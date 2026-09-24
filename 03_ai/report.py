"""报告层（比赛纪律版）：
- 分数由规则推导（findings.py 公式），LLM 只产出 explain/narrative，不改分
- Ollama(本地) → 云 API → 模板降级；三种路径结论集一致
- 产出 report.json + report.md + report.html
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "02_scan"))
from findings import Finding, aggregate_score  # noqa: E402
from external_reports import external_html, external_markdown  # noqa: E402

HISTORY = ROOT / "reports" / "history.json"


def _load_config() -> dict:
    f = ROOT / "config.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            return {}
    return {}


_CFG = _load_config()
OLLAMA_URL = os.environ.get("OLLAMA_URL", _CFG.get("ollama", {}).get("url", "http://127.0.0.1:11434"))
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", _CFG.get("ollama", {}).get("model", "qwen2.5:3b"))
CLOUD_API_KEY = os.environ.get("OPENAI_API_KEY", _CFG.get("cloud", {}).get("api_key", ""))
CLOUD_BASE_URL = os.environ.get("OPENAI_BASE_URL", _CFG.get("cloud", {}).get("base_url", "https://api.openai.com/v1"))
CLOUD_MODEL = os.environ.get("OPENAI_MODEL", _CFG.get("cloud", {}).get("model", "gpt-4o-mini"))
CLOUD_MAX_TOKENS = _CFG.get("cloud", {}).get("max_tokens", 2500)


# ---------- LLM clients ----------

def _post(url: str, payload: dict, headers: dict | None = None, timeout: int = 120) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def ollama_available() -> bool:
    try:
        with urllib.request.urlopen(OLLAMA_URL + "/api/tags", timeout=3) as r:
            return bool(json.loads(r.read().decode()).get("models"))
    except Exception:
        return False


def _content_of(resp: dict) -> str:
    """兼容 reasoning 模型 content 可能为 null（需检查多个字段）。"""
    msg = resp["choices"][0].get("message") or {}
    for k in ("content", "reasoning", "reasoning_content"):
        v = msg.get(k)
        if v:
            return v
    return ""


def llm_chat(messages: list[dict]) -> tuple[str, str]:
    """云端优先（已配置则用），Ollama 兜底。返回 (engine, text)。都失败抛异常。"""
    errors = []
    if CLOUD_API_KEY:
        try:
            resp = _post(CLOUD_BASE_URL.rstrip("/") + "/chat/completions", {
                "model": CLOUD_MODEL, "temperature": 0.2,
                "max_tokens": CLOUD_MAX_TOKENS, "messages": messages,
            }, headers={"Authorization": f"Bearer {CLOUD_API_KEY}"}, timeout=180)
            text = _content_of(resp)
            if text:
                return "cloud", text
            errors.append("cloud: empty content")
        except Exception as e:
            errors.append(f"cloud: {e}")
    # Ollama 兜底
    try:
        resp = _post(OLLAMA_URL + "/api/chat", {
            "model": OLLAMA_MODEL, "stream": False,
            "options": {"temperature": 0.2, "num_predict": 2200},
            "messages": messages,
        }, timeout=600)
        text = resp.get("message", {}).get("content", "")
        if text:
            return "ollama", text
        errors.append("ollama: empty content")
    except Exception as e:
        errors.append(f"ollama: {e}")
    raise RuntimeError("; ".join(errors) or "no LLM backend available")


def extract_json(text: str) -> dict:
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    start = text.find("{")
    if start < 0:
        raise ValueError("no JSON")
    depth = 0
    for i, ch in enumerate(text[start:], start):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise ValueError("unbalanced")


# ---------- narrative generation ----------

SYSTEM_PROMPT = (
    "你是网络安全分析师，给非技术为主的用户解读体检/评估报告。中文、说人话，"
    "禁止 AI 腔词（赋能/闭环/抓手/三条腿）。你【不能改变】发现和分数——它们由规则算好。"
    "你只做三件事：1) 给每条发现一段 1-2 句的白话解释；2) 写 3 句最重要的行动建议；"
    "3) 写 2-3 句总体叙述。只输出 JSON。"
)

NARRATIVE_SCHEMA = """
输出 JSON：
{"summary": "总体叙述2-3句",
 "top_actions": ["行动1一句话","行动2","行动3"],
 "explains": {"<finding id>": "白话解释 1-2句"}}
有个别的 finding 证据不足（evidence_gap=true）就在它解释里明说“这条有待人工确认”。
"""


def build_narrative(results: dict) -> tuple[dict, str]:
    findings_brief = [
        {
            "id": f["id"], "title": f["title"], "level": f["risk"]["level"],
            "owasp": f.get("owasp"), "raw_score": f["risk"]["raw_score"],
            "evidence": f.get("evidence"), "evidence_gap": f.get("evidence_gap"),
            "fix": f.get("fix"),
        }
        for f in results.get("findings", [])
    ]
    user_prompt = (
        f"评分: {results.get('score')}/100\n"
        f"发现列表(JSON):\n{json.dumps(findings_brief, ensure_ascii=False)}\n\n"
        + NARRATIVE_SCHEMA
    )
    engine, raw = llm_chat([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ])
    parsed = extract_json(raw)
    return parsed, engine


def template_narrative(results: dict) -> dict:
    fs = results.get("findings", [])
    explains = {f["id"]: f.get("fix", "见修复建议。") for f in fs}
    tops = [f["title"] for f in sorted(
        fs, key=lambda x: -x["risk"]["raw_score"])][:3]
    n = len(fs)
    return {
        "summary": f"本地规则评估共 {n} 项发现，解释使用规则模板；外部引擎的分析状态与结果单独展示。",
        "top_actions": tops or ["未达阈值的发现，保持现状即可。"],
        "explains": explains,
    }


# ---------- assembly ----------

def assemble(results: dict, narrative: dict, engine: str) -> dict:
    merged = dict(results)
    for f in merged.get("findings", []):
        f["explain"] = narrative.get("explains", {}).get(f["id"], f.get("explain") or f.get("fix", ""))
    merged["score"] = aggregate_score([Finding.from_dict(f) for f in merged["findings"]])
    merged["narrative"] = {
        "summary": narrative.get("summary", ""),
        "top_actions": narrative.get("top_actions", []),
    }
    merged["engine"] = engine
    return merged


# ---------- markdown ----------

def to_markdown(rep: dict) -> str:
    lines = [
        f"# AgentShield 评估报告 — {rep.get('report_id','')}",
        "",
        f"**本地规则健康分: {rep['score']}/100（越高越好）**　引擎: 规则评分 + {rep.get('engine')} 叙述　"
        f"生成: {rep.get('generated_at','')}",
        "",
        "## 最该先做",
        *[f"{i+1}. {a}" for i, a in enumerate(rep["narrative"]["top_actions"])],
        "",
        "## 发现",
        "",
    ]
    if not rep["findings"]:
        lines.append("无达到阈值的发现。")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(rep["findings"], key=lambda x: (order.get(x["risk"]["level"], 9), -x["risk"]["raw_score"])):
        ev = f.get("evidence", {})
        loc = f"{ev.get('file','')}:{ev.get('line','')}".rstrip(":") or ev.get("cmd", "")
        lines += [
            f"### [{f['risk']['level'].upper()}] {f['title']}",
            f"- raw_score **{f['risk']['raw_score']}** = impact×exploit×conf×exposure "
            f"({f['risk']['impact']}×{f['risk']['exploitability']}×{f['risk']['evidence_confidence']}×{f['risk']['exposure']})"
            + ("　⚠️ 证据不足已降级" if f.get("evidence_gap") else ""),
            f"- 映射: {f.get('owasp','—')} / {f.get('nist','—')}　规则: `{f['rule_id']}`",
            f"- 证据: `{loc}`　{(ev.get('snippet') or '').strip()[:100]!r}",
            f"- 解释: {f.get('explain','')}",
            f"- 修复: {f.get('fix','')}",
            "",
        ]
    lines += ["## 边界声明", "",
              "不证明绝对安全；不扫描真实生产账号；高危结论均附证据；修复补丁需人工确认后应用。", ""]
    return "\n".join(lines) + "\n" + external_markdown(rep)


# ---------- html ----------

CSS = """
:root { --fg:#111; --muted:#666; --line:#ddd; }
* { box-sizing: border-box; }
body { font: 15px/1.6 -apple-system, "PingFang SC", "Helvetica Neue", sans-serif;
       color: var(--fg); max-width: 860px; margin: 40px auto; padding: 0 24px; }
.head { display: flex; align-items: baseline; gap: 24px; border-bottom: 3px solid #111; margin-bottom: 28px; }
.score { font-size: 64px; font-weight: 800; letter-spacing: -2px; }
.score small { font-size: 16px; font-weight: 400; color: var(--muted); }
.q { font-size: 14px; color: var(--muted); }
.decode { font: 12px ui-monospace, "SF Mono", monospace; color: var(--muted); }
.card { border: 1px solid var(--line); border-left: 5px solid #111; margin: 14px 0; padding: 14px 18px; }
.card.MEDIUM { border-left-color: #888; } .card.LOW { border-left-color: #bbb; } .card.INFO { border-left-color: #eee; }
.card h3 { margin: 0 0 6px; font-size: 16px; }
.meta { font: 12px ui-monospace, monospace; color: var(--muted); margin: 4px 0; }
.meta b { color: #111; }
.fix { margin-top: 6px; padding: 6px 10px; background: #f6f6f6; font-size: 13px; }
.top { background: #111; color: #fff; padding: 14px 18px; margin: 20px 0; }
.top h2 { margin: 0 0 8px; font-size: 14px; letter-spacing: 2px; color: #ccc; }
.top ol { margin: 0; padding-left: 20px; font-size: 14px; }
.bound { font-size: 12px; color: var(--muted); border-top: 1px solid var(--line); margin-top: 32px; padding-top: 12px; }
.gap { display:inline-block; background:#fff; border:1px solid #999; font-size:11px; padding:0 6px; margin-left:6px;}
"""


def to_html(rep: dict) -> str:
    external = external_html(rep)
    def escape_values(value):
        if isinstance(value, str):
            return html.escape(value, quote=True)
        if isinstance(value, list):
            return [escape_values(item) for item in value]
        if isinstance(value, dict):
            return {key: escape_values(item) for key, item in value.items()}
        return value
    rep = escape_values(rep)
    cards = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(rep["findings"], key=lambda x: (order.get(x["risk"]["level"], 9), -x["risk"]["raw_score"])):
        ev = f.get("evidence", {})
        loc = f"{ev.get('file','')}:{ev.get('line','')}".rstrip(":") or ev.get("cmd", "")
        snip = (ev.get("snippet") or ev.get("output_ref") or "").strip()[:120]
        gap = '<span class="gap">证据不足·降级</span>' if f.get("evidence_gap") else ""
        cards.append(f"""
<div class="card {f['risk']['level'].upper()}">
<h3>{f['risk']['level'].upper()} · {f['title']}{gap}</h3>
<div class="meta">risk <b>{f['risk']['raw_score']}</b> = {f['risk']['impact']}×{f['risk']['exploitability']}×{f['risk']['evidence_confidence']}×{f['risk']['exposure']}　·　{f.get('owasp','')} / {f.get('nist','')}　·　<code>{f['rule_id']}</code></div>
<div class="meta">证据 <code>{loc}</code>　{snip}</div>
<div>{f.get('explain','')}</div>
<div class="fix"><b>修复：</b>{f.get('fix','')}</div>
</div>""")
    tops = "".join(f"<li>{a}</li>" for a in rep["narrative"]["top_actions"])
    return f"""<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>AgentShield {rep.get('report_id','')}</title><style>{CSS}</style></head><body>
<div class="head">
<div class="score">{rep['score']}<small> /100 · 本地健康分</small></div>
<div class="q">AgentShield 评估报告<br>{rep.get('generated_at','')}<br>
<span class="decode">规则评分 · {rep.get('engine')} 叙述 · 证据先于结论</span></div>
</div>
<p>{rep['narrative']['summary']}</p>
{external}
<div class="top"><h2>最该先做</h2><ol>{tops or '<li>无</li>'}</ol></div>
{''.join(cards) or '<p>无达到阈值的发现。</p>'}
<div class="bound">边界：不证明绝对安全；不扫真实生产账号；高危结论均附可复核证据；修复补丁需人工确认后应用。
公式 Risk = Impact(1-5)×Exploitability(1-5)×EvidenceConfidence(0.5/0.75/1.0)×Exposure(0.5/1/1.5)。</div>
</body></html>"""


# ---------- main ----------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="cmd_scan 产出的 results.json")
    ap.add_argument("--no-narrative", action="store_true", help="跳过 LLM，直接模板")
    ap.add_argument("--out", help="输出目录（默认与输入同目录）")
    args = ap.parse_args()

    results = json.loads(Path(args.input).read_text())
    outdir = Path(args.out) if args.out else Path(args.input).parent
    outdir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()

    narrative, engine = template_narrative(results), "template"
    if not args.no_narrative and results.get("findings"):
        try:
            narrative, engine = build_narrative(results)
        except Exception as e:
            print(f"[report] narrative LLM failed: {e} → template", file=sys.stderr)

    rep = assemble(results, narrative, engine)
    rep["ai_elapse_s"] = round(time.time() - t0, 1)

    rep_json = outdir / "report.json"
    rep_json.write_text(json.dumps(rep, ensure_ascii=False, indent=2))
    (outdir / "report.md").write_text(to_markdown(rep))
    (outdir / "report.html").write_text(to_html(rep))

    # history（同配置一致率 + 前后对照的数据源）
    entries = json.loads(HISTORY.read_text()) if HISTORY.exists() else []
    entries.append({
        "report_id": results.get("report_id"), "at": results.get("generated_at"),
        "score": rep["score"],
        "finding_ids": sorted(f["id"] for f in rep["findings"]),
        "inputs": [{"k": k, "v": results.get(k, {}).get("manifest")} for k in ("skill",) if k in results],
    })
    HISTORY.parent.mkdir(parents=True, exist_ok=True)
    HISTORY.write_text(json.dumps(entries[-60:], ensure_ascii=False))

    print(f"[report] score={rep['score']} engine={engine} "
          f"→ {rep_json.name}, report.md, report.html ({rep['ai_elapse_s']}s)")


if __name__ == "__main__":
    main()
