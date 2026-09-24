"""AgentShield Web（本机 127.0.0.1:8787）

端点:
  GET  /                     首页（报告列表 + 体检 + 设置 + Agent 入口）
  GET  /report/<rid>         报告页（解释/帮我操作/导出 按钮）
  GET  /report/<rid>/files/<name>   原始报告文件（导出用）
  POST /api/scan             一键体检 {sys:1, lan:1}
  GET/POST /api/config       读/存 设置（config.json）
  POST /api/llm-test         SSE：测试 LLM 连通（流式回一段话）
  GET  /api/explain/<rid>/<fid>     SSE 流式：小白化解释该发现
  POST /api/fix/<rid>/<fid>          修复步骤（确定性知识库）
  POST /api/agent/new                {message} -> {agent_id}   (ReAct loop)
  GET  /api/agent/<id>/event         SSE 事件流 (think/tool/result/ask/final)
  POST /api/agent/<id>/answer        {text}  回答 Agent 的 Ask
  POST /api/agent/<id>/message       {message} 继续对话
  POST /api/agent/close              {agent_id}
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Queue, Empty
from urllib.parse import urlparse, unquote

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "02_scan"))
sys.path.insert(0, str(ROOT / "03_ai"))
sys.path.insert(0, str(ROOT / "08_arena"))
REPORTS = ROOT / "reports"
PY = sys.executable or "python3"

import llm as llm_mod   # noqa: E402
import agent as agent_mod  # noqa: E402
import simulator as arena_mod  # noqa: E402
from external_reports import external_html  # noqa: E402
import nvidia_scan  # noqa: E402

ARENA_REVIEW_LOCK = threading.Lock()
ARENA_STREAM_LOCK = threading.Lock()
NVIDIA_SCAN_LOCK = threading.Lock()


def nvidia_html():
    return '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NVIDIA Skill 审查 · AgentShield</title><link rel="stylesheet" href="/style.css"></head><body>
<div class="topbar"><a class="brand" href="/">AgentShield</a><a class="btn" href="/arena?scenario=malicious_skill">Skill 攻防演练</a></div>
<h1>NVIDIA Skill 安全审查</h1><p>使用 NVIDIA SkillSpector 的真实扫描结果，验证项目样本中的风险。保留原始报告、版本、输入内容哈希和覆盖边界。</p>
<div class="card"><label for="sample">选择项目样本</label><select id="sample" style="font:inherit;padding:8px;width:100%">
<option value="vulnerable-skill">植入漏洞样本</option><option value="hardened-skill">加固样本</option><option value="benign-skill">普通样本</option></select>
<label><input type="checkbox" id="use-model"> 添加私有 Qwen 语义分析</label>
<p class="tip">默认静态扫描不调用模型。启用语义分析会将所选合成样本交给配置的私有模型，约需数十秒至数分钟。扫描不执行样本脚本。</p>
<button class="btn primary" id="scan">开始官方引擎审查</button><p id="status" role="status" aria-live="polite"></p><a id="result" class="btn" hidden>查看完整报告</a></div>
<p class="tip">SkillSpector 风险分越高风险越大；AgentShield 规则健康分越高越好，两者分开展示。来源 commit 与内容哈希已记录；来源签名尚未验证。DGX Spark / OpenShell 未接入。</p>
<script>
const sampleHint=new URLSearchParams(location.search).get('sample');
if(['vulnerable-skill','hardened-skill','benign-skill'].includes(sampleHint)) document.getElementById('sample').value=sampleHint;
document.getElementById('scan').onclick=async()=>{
 const b=document.getElementById('scan'),s=document.getElementById('status'),a=document.getElementById('result');
 b.disabled=true;a.hidden=true;s.textContent='正在扫描并核验覆盖范围…';
 try{const r=await fetch('/api/nvidia/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sample:document.getElementById('sample').value,use_llm:document.getElementById('use-model').checked})});
 const j=await r.json();if(!r.ok||!j.ok)throw new Error(j.msg||'扫描失败');
 s.textContent='扫描结束：'+(j.status==='complete'?'已完成所选范围':'存在错误或覆盖缺口，请查看报告')+'；'+j.issues+' 项官方引擎线索。';
 a.href='/report/'+encodeURIComponent(j.report);a.hidden=false;
 }catch(e){s.textContent=e.message;}finally{b.disabled=false;}
};
</script></body></html>'''


def arena_review(result):
    """Two independent, read-only role contexts; the rule verdict is immutable."""
    c = llm_mod.cloud_cfg()
    if not c.get("base_url") or not c.get("api_key"):
        raise RuntimeError("请先配置私有模型。")
    evidence = json.dumps({"scenario": result["scenario"], "mode": result["mode"], "assumptions": result["assumptions"],
                           "before": result["before"]["outcomes"],
                           "after": result["after"]["outcomes"],
                           "repair": result["repair"],
                           "business": result["after"]["business_checks"]}, ensure_ascii=False)
    reviews = []
    for role, task in (("black", "你是黑方黑客的演练分析员。解释哪些预设目标成功、哪些前提受阻，以及未覆盖的场景假设。"),
                       ("red", "你是红方白帽分析员。解释修复为什么有效、谁能实施、业务副作用和复测局限。")):
        messages = [{"role": "system", "content": task + "这是合成的" + result.get("scenario_name", result["scenario"]) + "规则演练。用中文，先给普通用户两句结论，再给专业人士两条证据解读。总计不超过300字。不得声称进行了实网攻击或执行了工具，不生成命令，不修改规则裁判计数，不虚构日志。"},
                    {"role": "user", "content": evidence}]
        parts = []
        for kind, value in llm_mod._cloud_stream(messages, 0.2, timeout=35):
            if kind == "content":
                parts.append(value)
                if sum(map(len, parts)) >= 8000:
                    break
        content = "".join(parts).strip()
        if not content:
            raise RuntimeError("模型未返回解读。")
        reviews.append({"role": role, "text": content, "model": c["model"]})
    return {"ok": True, "run_id": result["run_id"], "reviews": reviews,
            "advisory_only": True, "execution": "independent_read_only_contexts"}

# ============================================================ UI（Hermes 风格：黑白灰 · 硬朗 · 0 圆角）

BASE_CSS = """
:root {
  --bg: #f5f5f5; --card: #ffffff; --fg: #111111; --muted: #787878;
  --line: #dcdcdc; --accent: #111111; --accent-soft: #ebebeb;
  --code: #f1f1f1; --ok: #444444; --warn: #333333; --bad: #111111;
  --r: 0px;
}
* { box-sizing: border-box; }
html { background: var(--bg); }
body { font: 15px/1.65 -apple-system, BlinkMacSystemFont, "PingFang SC", "Segoe UI", sans-serif;
       color: var(--fg); max-width: 920px; margin: 0 auto; padding: 28px 20px 80px; }
code, .mono { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: 12.5px; }
a { color: var(--fg); text-decoration: none; border-bottom: 1px solid var(--line); } a:hover { border-bottom-color: var(--fg); }
.topbar { display: flex; align-items: center; justify-content: space-between; margin-bottom: 18px;
          padding-bottom: 14px; border-bottom: 1px solid var(--fg); }
.brand { font-weight: 800; font-size: 18px; letter-spacing: .5px; text-transform: uppercase; }
.brand small { font-weight: 400; color: var(--muted); font-size: 12px; margin-left: 8px;
               text-transform: none; letter-spacing: 0; }
.hbtns { display: flex; gap: 8px; }
button { font: inherit; cursor: pointer; }
.btn { border: 1px solid #c8c8c8; background: #fff; color: var(--fg);
       padding: 7px 14px; border-radius: var(--r); font-size: 13px;
       transition: border-color .08s, background .08s; }
.btn:hover { border-color: var(--fg); background: #fff; }
.btn:active { transform: translateY(1px); }
.btn.primary { background: var(--fg); color: #fff; border-color: var(--fg); }
.btn.primary:hover { background: #000; border-color: #000; }
.btn.ghost { background: transparent; border-color: transparent; color: var(--muted); }
.btn.ghost:hover { color: var(--fg); border-color: var(--line); }
.btn.small { padding: 4px 10px; font-size: 12px; }
.btn.accent { background: #fff; color: var(--fg); border-color: var(--fg); }
.btn.accent:hover { background: var(--accent-soft); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: var(--r); padding: 16px 18px; }
.tip { font-size: 13px; color: var(--muted); }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 12px; margin: 18px 0; }
.report-card { display: block; color: inherit; }
.report-card:hover { border-color: var(--fg); text-decoration: none; }
.report-card .rid { font-size: 12px; color: var(--muted); }
.report-card .sc { font-size: 30px; font-weight: 800; letter-spacing: -1px; }
.report-card .sc span { font-size: 13px; font-weight: 400; color: var(--muted); }
.sev { display: inline-block; font-size: 11px; font-weight: 700; padding: 1px 8px; border-radius: 2px;
       letter-spacing: .5px; border: 1px solid transparent; }
.sev.critical { background: var(--fg); color: #fff; border-color: var(--fg); }
.sev.high { background: #3d3d3d; color: #fff; border-color: #3d3d3d; }
.sev.medium { background: #fff; color: var(--fg); border-color: var(--fg); }
.sev.low { background: var(--accent-soft); color: #444; border-color: #c9c9c9; }
.sev.info { background: var(--code); color: var(--muted); border-color: var(--line); }
.step { border-left: 2px solid var(--line); padding: 6px 0 6px 14px; margin: 8px 0; font-size: 13.5px; }
.step .lbl { font-size: 11px; font-weight: 700; letter-spacing: 1px; color: var(--muted); text-transform: uppercase; }
.step .lbl.tool { color: var(--fg); }
.think { color: var(--muted); font-style: italic; }
.obs { background: var(--code); border: 1px solid var(--line); border-radius: var(--r); padding: 8px 10px; margin-top: 4px;
       font-family: ui-monospace, "SF Mono", monospace; font-size: 12px; max-height: 140px;
       overflow: auto; white-space: pre-wrap; word-break: break-all; color: #333; }
.answer { background: var(--card); border: 1px solid var(--fg); border-left: 3px solid var(--fg);
          border-radius: var(--r); padding: 12px 16px; margin: 10px 0; }
.overlay { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex;
           align-items: center; justify-content: center; z-index: 50; }
.modal { background: var(--card); border: 1px solid var(--fg); border-radius: var(--r);
         width: min(680px, 92vw); max-height: 86vh; display: flex; flex-direction: column;
         box-shadow: 0 12px 48px rgba(0,0,0,.18); }
.modal .mhead { display: flex; justify-content: space-between; align-items: center; padding: 14px 18px;
                border-bottom: 1px solid var(--fg); }
.modal .mhead h3 { margin: 0; font-size: 15px; font-weight: 700; }
.modal .mbody { padding: 16px 18px; overflow: auto; }
.modal .mfoot { padding: 12px 18px; border-top: 1px solid var(--line); display: flex; justify-content: flex-end; gap: 8px; }
input[type=text], input[type=password], input[type=number], input:not([type]) {
  width: 100%; font: inherit; font-size: 13.5px; padding: 8px 10px; border: 1px solid #c8c8c8;
  border-radius: var(--r); background: #fff; }
input:focus, textarea:focus { outline: none; border-color: var(--fg); }
label { font-size: 12px; font-weight: 700; color: var(--muted); display: block; margin: 10px 0 4px;
        letter-spacing: .5px; text-transform: uppercase; }
.fieldrow { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.agentinput { display: flex; gap: 8px; padding: 12px 18px; border-top: 1px solid var(--fg); background: #fafafa; }
.agentinput input { flex: 1; }
.f-act { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.drawer { margin-top: 10px; background: var(--code); border-radius: var(--r); padding: 10px 12px; font-size: 13px;
          border: 1px solid var(--line); white-space: pre-wrap; }
.exportbar { display: flex; gap: 8px; align-items: center; margin: 8px 0 16px; flex-wrap: wrap; }
.scorehead { display: flex; gap: 22px; align-items: center; padding: 6px 4px 14px; }
.scorehead .big { font-size: 58px; font-weight: 800; letter-spacing: -2px; line-height: 1; }
.scorehead .big span { font-size: 16px; font-weight: 400; color: var(--muted); }
footer { margin-top: 44px; font-size: 12px; color: var(--muted); border-top: 1px solid var(--fg); padding-top: 12px; }
"""

def esc(s):
    return re.sub(r'[&<>"\']', lambda m: {"&": "&amp;", "<": "&lt;", ">": "&gt;",
                                           '"': "&quot;", "'": "&#39;"}[m.group(0)], str(s or ""))

def _report_list():
    out = []
    for p in REPORTS.glob("*/report.json"):
        try:
            d = json.loads(p.read_text())
            if d.get("integration_validation_status", "").startswith("superseded"):
                continue
            external = d.get("external_assessments", [])
            out.append({"rid": p.parent.name, "score": d.get("score"),
                        "n": len(d.get("findings", [])), "at": d.get("generated_at", ""),
                        "engine": d.get("engine", ""),
                        "external": " / ".join(f"{x.get('engine')}：{x.get('status')}" for x in external)})
        except Exception:
            continue
    return sorted(out, key=lambda x: x["rid"], reverse=True)


def home_html():
    cards = []
    for r in _report_list()[:24]:
        sc = r["score"] if r["score"] is not None else "–"
        cards.append(f"""
<a class="card report-card" href="/report/{r['rid']}">
  <div class="rid mono">{esc(r['rid'])}</div>
  <div class="sc">{sc}<span> /100</span></div>
  <div class="tip">{esc(r['at'])} · findings {r['n']} · {esc(r['engine'])}</div>
  <div class="tip">{esc(r.get('external'))}</div>
</a>""")
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentShield</title><style>{BASE_CSS}</style></head><body>
<div class="topbar">
  <div class="brand">🛡 AgentShield<small>规则评分 · LLM 解释 · 本地运行</small></div>
  <div class="hbtns">
    <a class="btn" href="/help">使用说明</a>
    <a class="btn" href="/nvidia">NVIDIA Skill 审查</a>
    <a class="btn" href="/arena">红黑攻防演练</a>
    <button class="btn" onclick="openSettings()">⚙ 设置</button>
    <button class="btn primary" onclick="startScan()">体检本机</button>
  </div>
</div>
<p class="tip">双评估域：Skill 静态评估 + 本机网络/系统。风险分由公式规则推导，LLM 只解释、不改分。右下角 🛡 或 <span class="mono">⌘⇧A</span> 呼出智能体。</p>
<div class="grid">{''.join(cards) or '<p class="tip">还没有报告——先点右上「体检本机」。</p>'}</div>
<div id="agent-host"></div>
<div id="modal-host"></div>
<footer>只监听 127.0.0.1（不出本机）。修复命令由你亲手确认执行。报告含密钥片段——分享前先看一眼。</footer>
<script src="/app.js"></script>
</body></html>"""


def report_html(rid: str):
    d = json.loads((REPORTS / rid / "report.json").read_text())
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    cards = []
    for f in sorted(d.get("findings", []), key=lambda x: (order.get(x["risk"]["level"], 9), -x["risk"]["raw_score"])):
        ev = f.get("evidence", {})
        loc = (f"{ev.get('file', '')}:{ev.get('line', '')}".rstrip(":")) or ev.get("cmd", "")
        snip = (ev.get("snippet") or ev.get("output_ref") or "").strip()[:160]
        gap = ' <span class="sev medium">证据不足·已降级</span>' if f.get("evidence_gap") else ""
        fid = re.sub(r'[^A-Za-z0-9_-]', '', f.get("id", "")) or "f0"
        cards.append(f"""
<div class="card" id="finding-{fid}">
  <h3 style="margin:0 0 4px;font-size:15.5px"><span class="sev {f['risk']['level']}">{f['risk']['level'].upper()}</span> {esc(f['title'])}{gap}</h3>
  <div class="mono" style="color:var(--muted);font-size:12px;margin:4px 0">
    risk <b style="color:var(--fg)">{f['risk']['raw_score']}</b> = {f['risk']['impact']}×{f['risk']['exploitability']}×{f['risk']['evidence_confidence']}×{f['risk']['exposure']}
    · {esc(f.get('owasp',''))}/{esc(f.get('nist',''))} · rule <code>{esc(f['rule_id'])}</code>
  </div>
  <div class="tip" style="margin:4px 0">证据 <code>{esc(loc)}</code> {esc(snip)}</div>
  <div style="font-size:13.5px;margin-top:8px">{esc(f.get('explain') or f.get('fix') or '')}</div>
  <div class="tip" style="margin-top:6px"><b>修复：</b>{esc(f.get('fix',''))}</div>
  <div class="f-act">
    <button class="btn small accent" onclick="explainFinding('{fid}', this)">💬 解释（大白话）</button>
    <button class="btn small" onclick="fixFinding('{fid}', this)">🔧 帮我操作</button>
  </div>
  <div class="drawer" id="drawer-{fid}" style="display:none"></div>
</div>""")
    tops = "".join(f"<li>{esc(a)}</li>" for a in d.get("narrative", {}).get("top_actions", []))
    sc = d.get("score", "–")
    findings_json = json.dumps(d.get("findings", []), ensure_ascii=False).replace("</", "<\\/")
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentShield · {esc(rid)}</title><style>{BASE_CSS}</style></head><body>
<div class="topbar">
  <a class="brand" href="/">🛡 AgentShield</a>
  <div class="hbtns"><button class="btn" onclick="openSettings()">⚙ 设置</button>
  <button class="btn primary" onclick="startScan()">体检本机</button></div>
</div>
<div class="scorehead">
  <div class="big">{sc}<span> /100 · 本地健康分</span></div>
  <div>
    <div class="mono tip">{esc(d.get('generated_at',''))} · 引擎 {esc(d.get('engine',''))}</div>
    <div style="font-size:13.5px;margin-top:4px" class="tip">本地健康分越高越好 · 外部风险分单独展示 · 证据先于结论</div>
  </div>
</div>
<div class="exportbar tip">
  <b style="color:var(--fg);margin-right:4px">导出</b>
  <a class="btn small" download href="/report/{rid}/files/report.html">HTML</a>
  <a class="btn small" download href="/report/{rid}/files/report.md">Markdown</a>
  <a class="btn small" download href="/report/{rid}/files/report.json">JSON</a>
  <a class="btn small ghost" href="/report/{rid}/files/results.json" target="_blank">原始数据</a>
</div>
<p style="margin:0 0 16px">{esc(d.get('narrative',{}).get('summary',''))}</p>
{external_html(d, '/report/' + rid + '/files/')}
{'<div class="card" style="margin-bottom:14px"><b style="font-size:12px;letter-spacing:1px;text-transform:uppercase;color:var(--muted)">最该先做</b><ol style="margin:8px 0 0;padding-left:20px;font-size:14px">' + tops + '</ol></div>' if tops else ''}
{''.join(cards) or '<p class="tip">无达到阈值的发现。</p>'}
<div id="agent-host"></div><div id="modal-host"></div>
<footer>边界：不证明绝对安全；不扫真实生产账号；高危结论均附证据；修复命令需人工确认。</footer>
<script>window.RID="{esc(rid)}"; window.FINDINGS={findings_json}</script>
<script src="/app.js"></script></body></html>"""


# ============================================================ Agent 会话

class AgentSession:
    def __init__(self):
        self.id = uuid.uuid4().hex[:10]
        self.q: Queue = Queue()
        self.history: list[dict] = []
        self.answer_q: Queue = Queue()
        self.running = False
        self.closed = False

    def close(self):
        self.closed = True


AGENT_SESSIONS: dict[str, AgentSession] = {}
SES_LOCK = threading.Lock()


def _agent_worker(sess: AgentSession, message: str):
    a = agent_mod.ReActAgent(sess.history)

    def answer_cb(question, choices):
        try:
            return sess.answer_q.get(timeout=300)
        except Empty:
            return "（用户未回答，请按最稳妥的方式继续）"

    def on_event(kind, payload):
        sess.q.put({"type": kind, **payload})

    try:
        a.run(message, on_event, answer_cb)
        sess.history = a.history
    except Exception as e:
        sess.q.put({"type": "error", "text": str(e)[:300]})
    finally:
        sess.running = False
        sess.q.put({"type": "done"})


def _run_agent_turn(sess: AgentSession, message: str):
    if sess.running:
        return {"ok": False, "msg": "上一轮还在跑，稍等"}
    sess.running = True
    threading.Thread(target=_agent_worker, args=(sess, message), daemon=True).start()
    return {"ok": True}


# ============================================================ 生成器

def iter_of_session(sess: AgentSession):
    while not sess.closed:
        try:
            ev = sess.q.get(timeout=15)
        except Empty:
            yield {"type": "ping"}
            continue
        yield ev
        if ev.get("type") == "done":
            break


def _explain_stream(finding: dict):
    ev = finding.get("evidence", {})
    prompt = (
        f"问题: {finding.get('title','')}\n规则: {finding.get('rule_id','')}\n"
        f"风险分: {finding['risk']['raw_score']} ({finding['risk']['level']})\n"
        f"证据: {ev.get('file','')}:{ev.get('line','')} {(ev.get('snippet') or '')[:120]}\n"
        f"修复建议(规则给出): {finding.get('fix','')}\n\n"
        "用完全外行能听懂的大白话解释：1) 这是什么事（打一个生活比喻）2) 为什么危险、谁会利用 "
        "3) 不处理会怎样 4) 普通人现在可以做的 1-2 步。180-260 字，不打术语堆砌。"
    )
    try:
        for kind, piece in llm_mod.chat_stream([
            {"role": "system", "content": "你是网络安全助手，把专业问题讲给非技术用户听。"},
            {"role": "user", "content": prompt},
        ], temperature=0.4):
            if kind == "content":
                yield {"type": "token", "text": piece}
        yield {"type": "done"}
    except Exception as e:
        yield {"type": "token", "text": f"（LLM 暂不可用：{e[:80]}）规则解释：{finding.get('fix','')}\n"}
        yield {"type": "done"}


def _llm_test_stream():
    try:
        for kind, piece in llm_mod.chat_stream([
            {"role": "system", "content": "测试连接。只输出一句话确认你在。"},
            {"role": "user", "content": "确认"},
        ], temperature=0.2):
            if kind == "content":
                yield {"type": "token", "text": piece}
        yield {"type": "done"}
    except Exception as e:
        yield {"type": "error", "text": str(e)[:200]}
        yield {"type": "done"}


def _fix_for(finding: dict) -> dict:
    rule = finding.get("rule_id", "")
    mapping = {
        "SYS-FW-OFF": ("firewall", "打开 macOS 系统防火墙"),
        "SYS-FV-OFF": ("filevault", "打开 FileVault 磁盘加密"),
        "SYS-AU-OFF": ("autoupdate", "打开系统自动更新"),
        "SK-KEY-LITERAL": ("key", "密钥明文放在源码里"),
        "SK-SHELL-DANGER": ("curlsh", "脚本里有危险 shell 模式"),
        "SK-NET-EXFIL": ("exfil", "代码里有网络外传调用"),
        "SK-PATH-TRAVER": ("curlsh", "路径拼接未限定目录"),
        "SK-OVERBROAD-TRIG": ("trigger", "Skill 触发范围过宽"),
        "NET-SMB": ("smb", "设备开放 SMB 共享"),
        "NET-REMOTE-DESKTOP": ("remotedesktop", "设备开放远程桌面"),
        "NET-PLAINTEXT": ("plaintext", "明文协议(Telnet/FTP)"),
    }
    key, desc = mapping.get(rule, (rule.lower().replace("-", ""), finding.get("title", "")))
    raw = agent_mod._fixer(key, desc)
    out = json.loads(raw) if isinstance(raw, str) else raw
    out["discovery_id"] = finding.get("id")
    out["rule"] = rule
    return out


# ============================================================ HTTP

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json; charset=utf-8")

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}

    def _sse(self, gen):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        for ev in gen:
            try:
                payload = {k: v for k, v in ev.items()}
                payload.setdefault("type", "msg")
                self.wfile.write(f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionError):
                return

    def _safe_report_dir(self, rid: str):
        base = (REPORTS / rid).resolve()
        if base.is_relative_to(REPORTS.resolve()) and base.is_dir():
            return base
        return None

    def _finding(self, rid, fid):
        d = self._safe_report_dir(rid)
        f = d and (d / "report.json")
        if not f or not f.is_file():
            return None
        rep = json.loads(f.read_text())
        return next((x for x in rep.get("findings", []) if x["id"] == fid), None)

    # ---- GET ----
    def do_GET(self):
        path = unquote(urlparse(self.path).path)
        try:
            if path == "/":
                return self._send(200, home_html())
            if path == "/arena":
                return self._send(200, (ROOT / "04_web" / "arena.html").read_text())
            if path == "/help":
                return self._send(200, (ROOT / "使用说明.html").read_text())
            if path in ("/01_specs/public-wifi-arena-2026-09-24.md",
                        "/01_specs/nvidia-integration-2026-09-24.md",
                        "/09_integrations/nvidia/README.md"):
                return self._send(200, (ROOT / path.lstrip("/")).read_text(), "text/plain; charset=utf-8")
            if path == "/nvidia":
                return self._send(200, nvidia_html())
            if path == "/arena.js":
                return self._send(200, (ROOT / "04_web" / "arena.js").read_text(), "text/javascript; charset=utf-8")
            if path == "/api/arena/catalog":
                return self._json(200, arena_mod.catalog())
            if path == "/api/arena/scenarios":
                return self._json(200, {"default": "public_wifi", "scenarios": {
                    key: arena_mod.catalog(key) for key in ("public_wifi", "malicious_skill")}})
            if path == "/app.js":
                return self._send(200, APP_JS, "text/javascript; charset=utf-8")
            if path == "/style.css":
                return self._send(200, BASE_CSS, "text/css")
            if path == "/api/config":
                cfg = json.loads(json.dumps(llm_mod.load_config()))
                key = cfg.get("cloud", {}).pop("api_key", "")
                if key:
                    cfg["cloud"]["api_key_masked"] = key[:6] + "…" + key[-4:]
                return self._json(200, cfg)
            m = re.fullmatch(r"/report/([^/]+)/files/(\w+\.html|\w+\.md|\w+\.json)", path)
            if m:
                d = self._safe_report_dir(m.group(1))
                f = d and (d / m.group(2))
                if f and f.is_file():
                    ct = {"json": "application/json; charset=utf-8",
                          "html": "text/html; charset=utf-8"}.get(f.suffix.lstrip("."),
                          "text/plain; charset=utf-8")
                    return self._send(200, f.read_bytes(), ct)
                return self._send(404, "not found", "text/plain")
            if path.startswith("/report/"):
                rid = path.split("/report/", 1)[1].strip("/")
                f = self._safe_report_dir(rid) and self._safe_report_dir(rid) / "report.json"
                if f and f.is_file():
                    return self._send(200, report_html(rid))
                return self._send(404, "报告不存在", "text/plain")
            m = re.fullmatch(r"/api/agent/([^/]+)/event", path)
            if m and AGENT_SESSIONS.get(m.group(1)):
                return self._sse(iter_of_session(AGENT_SESSIONS[m.group(1)]))
            m = re.fullmatch(r"/api/explain/([^/]+)/([A-Za-z0-9_-]+)", path)
            if m:
                finding = self._finding(m.group(1), m.group(2))
                if finding:
                    return self._sse(_explain_stream(finding))
            m = re.fullmatch(r"/api/llm-test", path)
            if m:
                return self._sse(_llm_test_stream())
            return self._json(404, {"ok": False, "msg": "not found"})
        except Exception as e:
            return self._json(500, {"ok": False, "msg": str(e)[:300]})

    # ---- POST ----
    def do_POST(self):
        path = unquote(urlparse(self.path).path)
        try:
            if path == "/api/nvidia/scan":
                try:
                    size = int(self.headers.get("Content-Length") or 0)
                    if not 0 <= size <= 1024:
                        raise ValueError()
                    body = self._body()
                    if not isinstance(body, dict) or set(body) - {"sample", "use_llm"}:
                        raise ValueError()
                    if body.get("sample") not in ("vulnerable-skill", "hardened-skill", "benign-skill") or type(body.get("use_llm", False)) is not bool:
                        raise ValueError()
                except (ValueError, TypeError):
                    return self._json(400, {"ok": False, "msg": "仅接受内置样本与语义分析开关。"})
                if not NVIDIA_SCAN_LOCK.acquire(blocking=False):
                    return self._json(429, {"ok": False, "msg": "官方引擎正在扫描，请稍后重试。"})
                try:
                    result = nvidia_scan.run_scan(ROOT / "06_samples" / body["sample"], body.get("use_llm", False))
                except Exception:
                    return self._json(502, {"ok": False, "msg": "扫描未完成，未生成通过结论。请检查组件安装与 reports 下的失败记录。"})
                finally:
                    NVIDIA_SCAN_LOCK.release()
                return self._json(200, result)
            if path in ("/api/arena/run", "/api/arena/review", "/api/arena/stream"):
                try:
                    size = int(self.headers.get("Content-Length") or 0)
                    if size < 0 or size > 8192:
                        return self._json(413, {"ok": False, "msg": "演练参数过大。"})
                    result = arena_mod.simulate(self._body())
                except (ValueError, TypeError):
                    return self._json(400, {"ok": False, "msg": "仅接受内置场景与该场景的布尔防护开关，不接受目标地址或命令。"})
                if path == "/api/arena/run":
                    return self._json(200, result)
                if path == "/api/arena/stream":
                    if not ARENA_STREAM_LOCK.acquire(blocking=False):
                        return self._json(429, {"ok": False, "msg": "另一场演练正在展示，请稍后重试。"})
                    try:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
                        self.send_header("Cache-Control", "no-store")
                        self.send_header("X-Accel-Buffering", "no")
                        self.send_header("Connection", "close")
                        self.end_headers()
                        self.close_connection = True
                        for event in arena_mod.presentation_events(result):
                            self.wfile.write((json.dumps(event, ensure_ascii=False) + "\n").encode())
                            self.wfile.flush()
                            if event["type"] in ("event", "repair"):
                                time.sleep(0.45)  # Display cadence, not measured attack latency.
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass  # Viewer cancelled; release the single-stream slot.
                    finally:
                        ARENA_STREAM_LOCK.release()
                    return
                if not ARENA_REVIEW_LOCK.acquire(blocking=False):
                    return self._json(429, {"ok": False, "msg": "模型正在复盘，请稍后重试。"})
                try:
                    review = arena_review(result)
                except Exception:
                    return self._json(502, {"ok": False, "msg": "模型复盘未完成；规则演练结果保留。请检查私有模型连接后重试。"})
                finally:
                    ARENA_REVIEW_LOCK.release()
                return self._json(200, review)
            body = self._body()
            if path == "/api/scan":
                return self._api_scan(body)
            if path == "/api/config":
                cur = json.loads(json.dumps(llm_mod.load_config()))
                for k in ("cloud", "ollama"):
                    if isinstance(body.get(k), dict):
                        updates = dict(body[k])
                        updates.pop("api_key_masked", None)
                        if k == "cloud" and not updates.get("api_key"):
                            updates.pop("api_key", None)
                        cur.setdefault(k, {}).update(updates)
                llm_mod.save_config(cur)
                return self._json(200, {"ok": True})
            m = re.fullmatch(r"/api/fix/([^/]+)/([A-Za-z0-9_-]+)", path)
            if m:
                finding = self._finding(m.group(1), m.group(2))
                if finding:
                    return self._json(200, {"ok": True, **_fix_for(finding)})
                return self._json(404, {"ok": False, "msg": "finding not found"})
            if path == "/api/agent/new":
                with SES_LOCK:
                    sess = AgentSession()
                    AGENT_SESSIONS[sess.id] = sess
                msg = (body.get("message") or "").strip() or "帮我看看最近一份报告，说说最该先做什么。"
                _run_agent_turn(sess, msg)
                return self._json(200, {"ok": True, "agent_id": sess.id})
            m = re.fullmatch(r"/api/agent/([^/]+)/(answer|message)", path)
            if m:
                sess = AGENT_SESSIONS.get(m.group(1))
                if not sess:
                    return self._json(404, {"ok": False})
                if m.group(2) == "answer":
                    t = (body.get("text") or "").strip()
                    sess.q.put({"type": "ask_answered", "answer": t})
                    sess.answer_q.put(t)
                    return self._json(200, {"ok": True})
                return self._json(200, _run_agent_turn(sess, (body.get("message") or "").strip()))
            if path == "/api/agent/close":
                sess = AGENT_SESSIONS.pop(body.get("agent_id", ""), None)
                if sess:
                    sess.close()
                return self._json(200, {"ok": True})
            return self._json(404, {"ok": False})
        except Exception as e:
            return self._json(500, {"ok": False, "msg": str(e)[:300]})

    def _api_scan(self, body):
        rid = time.strftime("scan-%Y%m%d-%H%M%S")
        outdir = REPORTS / rid
        cmd = [PY, str(ROOT / "02_scan" / "cmd_scan.py"), "--out", str(outdir / "results.json")]
        if body.get("sys") not in (0, "0", False):
            cmd.append("--sys")
        if body.get("lan"):
            cmd.append("--lan")
        log = []
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
            log += [p.stdout.strip(), p.stderr.strip()]
        except Exception as e:
            log.append(str(e))
        rep = None
        if (outdir / "results.json").exists():
            p2 = subprocess.run([PY, str(ROOT / "03_ai" / "report.py"),
                                 "--input", str(outdir / "results.json")],
                                capture_output=True, text=True, timeout=900)
            log.append(p2.stdout.strip())
            rep = rid if (outdir / "report.html").exists() else None
        self._json(200, {"ok": bool(rep), "report": rep, "log": " | ".join(v for v in log if v)[:1500]})
        return None


# ============================================================ 前端 JS

APP_JS = r"""
function escHtml(s) { return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function $(s) { return document.querySelector(s); }
function flash(msg) {
  const f = document.createElement('div');
  f.className='card'; f.style.cssText='position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:99;padding:8px 18px;font-size:13px';
  f.textContent = msg; document.body.appendChild(f);
  setTimeout(()=>f.remove(), 2600);
}
async function api(url, body) {
  const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{}) });
  return r.json();
}
function sse(url, onEvent, onDone) {
  const es = new EventSource(url);
  es.onmessage = e => {
    let d; try { d = JSON.parse(e.data); } catch { return; }
    if (d.type === 'ping') return;
    onEvent(d);
    if (['done','closed','error','end'].includes(d.type)) { es.close(); onDone && onDone(d); }
  };
  es.onerror = () => { es.close(); onDone && onDone({ type:'done' }); };
  return es;
}
// ---------- 体检 ----------
function startScan() {
  flash('体检中… 局域网扫描约 10-60 秒');
  api('/api/scan', { sys: 1, lan: 1 }).then(j => {
    if (j.report) location.href = '/report/' + j.report;
    else flash('完成但报告失败：' + (j.log||'').slice(-120));
  }).catch(e=>flash('失败: '+e));
}
// ---------- 设置 ----------
function openSettings() {
  fetch('/api/config').then(r=>r.json()).then(cfg => {
    const c = cfg.cloud || {}, o = cfg.ollama || {};
    $('#modal-host').innerHTML = `
    <div class="overlay" onclick="if(event.target===this)closeSettings()">
      <div class="modal">
        <div class="mhead"><h3>⚙ 设置 · LLM 后端</h3><button class="btn ghost small" onclick="closeSettings()">✕</button></div>
        <div class="mbody">
          <div class="tip">优先使用配置的私有或兼容 API；失败时尝试 Ollama。报告支持模板降级。保存即生效。</div>
          <label>API base_url（含 /v1）</label><input id="c-url" type="text" value="${escHtml(c.base_url)}">
          <label>API key${c.api_key_masked?'（当前 '+escHtml(c.api_key_masked)+'）':''}</label>
          <input id="c-key" type="password" placeholder="留空=不修改">
          <div class="fieldrow">
            <div><label>模型</label><input id="c-model" type="text" value="${escHtml(c.model)}"></div>
            <div><label>max_tokens</label><input id="c-tok" type="number" value="${c.max_tokens||2500}"></div>
          </div>
          <label>Ollama URL</label><input id="o-url" type="text" value="${escHtml(o.url||'')}" placeholder="留空=不用 Ollama">
          <label>Ollama 模型</label><input id="o-model" type="text" value="${escHtml(o.model||'')}">
        </div>
        <div class="mfoot">
          <button class="btn" id="btn-test" onclick="testLLM()">测试连接</button>
          <button class="btn primary" onclick="saveSettings()">保存</button>
        </div>
        <div class="tip" id="test-out" style="padding:0 18px 14px;white-space:pre-wrap;max-height:140px;overflow:auto"></div>
      </div>
    </div>`;
  });
}
function closeSettings() { $('#modal-host').innerHTML = ''; }
async function saveSettings() {
  const cfg = { cloud: { base_url: $('#c-url').value.trim(), api_key: $('#c-key').value.trim(),
    model: $('#c-model').value.trim(), max_tokens: Number($('#c-tok').value||2500) },
    ollama: { url: $('#o-url').value.trim(), model: $('#o-model').value.trim() } };
  const j = await api('/api/config', cfg);
  closeSettings(); flash(j.ok ? '设置已保存' : '保存失败');
}
function testLLM() {
  const out = $('#test-out'); out.textContent = '连接中…';
  const es = sse('/api/llm-test', ev => {
    if (ev.type === 'token') out.textContent += ev.text;
    if (ev.type === 'error') out.textContent += '\n⚠ ' + ev.text;
  }, () => { out.textContent += out.textContent.trim() ? '\n✓ 连接正常' : ''; });
}
// ---------- 发现：解释 / 帮我操作 ----------
function explainFinding(fid, btn) {
  const d = $('#drawer-'+fid);
  d.style.display='block'; d.innerHTML = '<span class="mono">正在用大白话解释（流式）…</span>';
  let got = '';
  sse(`/api/explain/${window.RID||''}/${fid}`, ev => {
    if (ev.type === 'token') {
      got += ev.text;
      d.innerHTML = '<div style="white-space:pre-wrap;font-size:13.5px">'+escHtml(got)+'</div><span class="mono tip">▍</span>';
      d.scrollTop = d.scrollHeight;
    }
  }, () => { if (got) d.innerHTML = '<div style="white-space:pre-wrap;font-size:13.5px">'+escHtml(got)+'</div>'; });
}
function fixFinding(fid, btn) {
  const d = $('#drawer-'+fid);
  d.style.display='block'; d.innerHTML = '<span class="mono">取修复步骤…</span>';
  fetch(`/api/fix/${window.RID||''}/${fid}`, { method:'POST' }).then(r=>r.json()).then(j => {
    if (!j.ok) { d.innerHTML = escHtml(j.msg||'失败'); return; }
    const steps = (j.steps||[]).map((s,i)=>`<div style="margin:4px 0">${i+1}. <code>${escHtml(s)}</code></div>`).join('');
    const f = (window.FINDINGS||[]).find(x=>x.id===fid);
    d.innerHTML = `<div style="margin-bottom:6px"><b>修复步骤</b> · <span class="mono">${escHtml(j.rule||'')}</span></div>${steps}
      <div class="tip" style="margin:8px 0">${escHtml(j.note||'')}</div>
      <div class="f-act" style="margin:0">
        <button class="btn small accent" onclick="agentAsk('帮我操作：${escHtml((f&&f.title)||'')}", true)">💬 交给 Agent 一步步带我</button>
        <button class="btn small ghost" onclick="copyFix('${fid}')">📋 复制全部</button>
      </div>`;
    d.dataset.fix = JSON.stringify(j.steps||[]);
  });
}
function copyFix(fid) {
  const d = $('#drawer-'+fid);
  navigator.clipboard.writeText(JSON.parse(d.dataset.fix||'[]').join('\n'));
  flash('已复制到剪贴板');
}
// ---------- Agent 对话框（中央弹出，ReAct） ----------
let agentId = null, agentOpenFlag = false;
function escAttr(s){ return escHtml(s).replace(/'/g, "\\'").replace(/\n/g,'\\n'); }
function openAgent(prefill) {
  if (agentOpenFlag) {
    if (prefill) { $('#agent-input').value = prefill; $('#agent-input').focus(); }
    document.querySelector('.overlay') && document.querySelector('.overlay').scrollIntoView();
    return;
  }
  $('#agent-host').innerHTML = `
  <div class="overlay" onclick="if(event.target===this)closeAgent()">
    <div class="modal" style="width:min(780px,94vw);height:min(660px,84vh)">
      <div class="mhead">
        <h3>🤖 AgentShield 智能体 <span class="tip mono" style="font-weight:400">ReAct · 本地工具 · 流式</span></h3>
        <div class="hbtns">
          <button class="btn ghost small" onclick="newAgent()">↺ 新会话</button>
          <button class="btn ghost small" onclick="closeAgent()">✕</button>
        </div>
      </div>
      <div class="mbody" id="agent-log"></div>
      <div class="agentinput">
        <input id="agent-input" type="text" placeholder="说人话就行，比如：这个密钥问题到底怎么修？" ${prefill?'value="'+escAttr(prefill)+'"':''}>
        <button class="btn primary" onclick="sendAgent()">发送</button>
      </div>
    </div>
  </div>`;
  agentOpenFlag = true;
  if (!agentId) newAgent(); else resumeStream();
  setTimeout(()=>{ const i=$('#agent-input'); i && i.focus(); }, 60);
  if (prefill && prefill === prefill) setTimeout(()=>{ if ($('#agent-input') && agentPrefill!==null) sendAgent(); }, 120);
  if (prefill) { agentPrefill = null; }
}
let agentPrefill = null;
function newAgent() {
  if (agentId) api('/api/agent/close', { agent_id: agentId });
  agentId = null;
  const log = $('#agent-log');
  if (log) log.innerHTML = '<div class="step"><span class="lbl">就绪</span><div class="tip">我能：看最近报告 · 评估任意 Skill · 本机系统体检 · 大白话解释 · 一步步带你修复。不确定时我会先问你。</div></div>';
  api('/api/agent/new', { message: '' }).then(j => {
    if (j.agent_id) { agentId = j.agent_id; resumeStream(); }
  });
}
function resumeStream() {
  if (!agentId) return;
  sse(`/api/agent/${agentId}/event`, handleAgentEvent, d => {});
}
function handleAgentEvent(ev) {
  const log = $('#agent-log'); if (!log) return;
  const push = h => { log.insertAdjacentHTML('beforeend', h); log.scrollTop = log.scrollHeight; };
  if (ev.type === 'thinking') {
    let el = document.getElementById('thinkp-'+ev.step);
    if (!el) {
      const b = document.createElement('div');
      b.id = 'thinkp-'+ev.step;
      b.className = 'tip'; b.style.cssText = 'font-size:12px;margin:2px 0 2px 14px;font-style:italic';
      b.textContent = '…';
      log.appendChild(b);
      el = b;
    }
    el.textContent = (el.textContent.length > 90 ? '…' : '') + ev.text.slice(-120);
    log.scrollTop = log.scrollHeight;
    return;
  }
  if (ev.type === 'think') {
    const p = document.getElementById('thinkp-'+ev.step);
    if (p) { p.style.opacity = .45; }
    push(`<div class="step"><span class="lbl">思考 · step${ev.step||''}</span><div class="think">${escHtml(ev.thought)}</div></div>`);
  }
  if (ev.type === 'tool_call') push(`<div class="step"><span class="lbl tool">⚙ 调 ${escHtml(ev.tool)}</span> <span class="mono tip">${escHtml(JSON.stringify(ev.input||{}))}</span><div class="obs" id="obs-${ev.step}">运行中…</div></div>`);
  if (ev.type === 'tool_result') { const o = document.getElementById('obs-'+ev.step); if (o) o.textContent = (ev.ok?'✓ ':'✗ ')+ (ev.obs||''); }
  if (ev.type === 'ask') {
    const opts = (ev.choices||[]).map(c=>`<button class="btn small accent" style="margin:3px 3px 0 0" onclick="answerAgent(this.dataset.t)" data-t="${escAttr(c)}">${escHtml(c)}</button>`).join('');
    push(`<div class="step" style="border-left-color:var(--accent)"><span class="lbl tool">❓ 问你一下</span>
      <div style="margin-top:4px">${escHtml(ev.question)}</div>
      <div style="margin-top:8px">${opts}
        <input id="ask-other" type="text" placeholder="或者自己打（回车发送）" onkeydown="if(event.key==='Enter'&&this.value.trim())answerAgent(this.value.trim())"></div></div>`);
  }
  if (ev.type === 'ask_answered') push(`<div class="step tip">你的回答：<b>${escHtml(ev.answer)}</b></div>`);
  if (ev.type === 'final') push(`<div class="answer">${renderMd(ev.text)}</div>`);
  if (ev.type === 'error') push(`<div class="step"><span class="lbl" style="color:var(--bad)">出错</span> ${escHtml(ev.text)}</div>`);
}
function renderMd(t) {
  // 极简：转义 + 换行 + 粗体
  return escHtml(t).replace(/\*\*(.+?)\*\*/g,'<b>$1</b>').replace(/\n/g,'<br>');
}
function sendAgent() {
  const inp = $('#agent-input'); if (!inp || !agentId) return;
  const t = inp.value.trim(); if (!t) return;
  inp.value = '';
  $('#agent-log').insertAdjacentHTML('beforeend', `<div class="answer"><b>你：</b>${escHtml(t)}</div>`);
  api(`/api/agent/${agentId}/message`, { message: t });
}
function answerAgent(text) {
  if (!agentId || !text) return;
  const o = $('#ask-other'); if (o) o.remove();
  document.querySelectorAll('[data-t]').forEach(b=>{ b.classList.add('btn'); b.style.opacity=.35; b.disabled=true; });
  api(`/api/agent/${agentId}/answer`, { text: text });
}
function agentAsk(t, auto) {
  openAgent(null);
  if (auto && t) setTimeout(()=>{ const i = $('#agent-input'); if (i) { i.value = t; sendAgent(); } }, 200);
}
function closeAgent() {
  $('#agent-host').innerHTML = '';
  agentOpenFlag = false;
  if (agentId) { api('/api/agent/close', { agent_id: agentId }); agentId = null; }
}
// 悬浮入口 + 快捷键
(function(){
  const b = document.createElement('button');
  b.textContent = '🛡'; b.title = 'AgentShield 智能体 (⌘⇧A)';
  b.style.cssText = 'position:fixed;right:22px;bottom:22px;z-index:40;width:54px;height:54px;border-radius:0;font-size:24px;border:1px solid var(--fg);background:var(--card);box-shadow:0 6px 20px rgba(0,0,0,.14)';
  b.onclick = () => { agentPrefill = null; openAgent(null); };
  document.body.appendChild(b);
  window.addEventListener('keydown', e => {
    if ((e.metaKey||e.ctrlKey) && e.shiftKey && e.key==='A') { e.preventDefault(); openAgent(null); }
    if (e.key==='Enter' && e.target && e.target.id==='agent-input') { e.preventDefault(); sendAgent(); }
    if (e.key==='Escape') closeAgent();
  });
})();
"""


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--open", action="store_true")
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    url = f"http://127.0.0.1:{args.port}"
    print(f"AgentShield web → {url}   (呼出智能体: 右下角 🛡 或 ⌘⇧A)")
    if args.open:
        __import__("webbrowser").open(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
