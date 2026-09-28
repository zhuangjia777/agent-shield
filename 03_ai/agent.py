"""Agent 对话框核心：文本 ReAct 循环（Thought → Action → Observation → ... → Final）。

工具全部确定性、本地执行；LLM 只负责下一步决策与措辞。
不确定时输出 Ask，附 choices，前端渲染为可点选项。
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "02_scan"))
sys.path.insert(0, str(ROOT / "05_skill_eval"))
sys.path.insert(0, str(ROOT / "03_ai"))

from llm import chat_stream, load_config  # noqa: E402
from skillcheck import check_skill, SkillBundle  # noqa: E402
from findings import aggregate_score  # noqa: E402
import cmd_scan  # noqa: E402

MAX_STEPS = 6
REPORTS = ROOT / "reports"
SAMPLES = ROOT / "06_samples"

TOOLS = [
    ("list_reports", "列出最近体检/评估报告（含评分、发现数）"),
    ("read_report", "读某份报告的发现明细。参数: report_id"),
    ("scan_skill", "静态评估一个 Skill 目录。参数: dir（可给样本名如 vulnerable-skill）"),
    ("check_system", "快速本机系统体检（防火墙/加密/自动更新/端口）"),
    ("learn", "用大白话解释某个安全问题。参数: topic"),
    ("run_fix", "执行/给出修复。参数: action + detail（返回建议命令；破坏性命令只给不执行）"),
    ("delete_report", "删除某份体检报告（report_id 传 all 表示全部）。破坏性操作：第一次调用不带 confirmed 只会收到确认提示；"
                      "必须先 Ask 用户确认，用户同意后再带 confirmed=true 重新调用"),
]


def _observations():
    reports = []
    for p in sorted(REPORTS.glob("*/report.json"), reverse=True)[:8]:
        try:
            d = json.loads(p.read_text())
            reports.append({"id": p.parent.name, "score": d.get("score"),
                            "at": d.get("generated_at", ""), "n": len(d.get("findings", []))})
        except Exception:
            continue
    skills = [s.name for s in SAMPLES.iterdir() if s.is_dir()]
    return json.dumps({"recent_reports": reports, "available_skill_samples": skills},
                      ensure_ascii=False)


SYSTEM = """你是 AgentShield 智能体——一个本地网络安全评估工具里的小助手。
协议（必须遵守，每步只输出一个动作）:
1) 先写 Thought: <你的判断，一句话>
2) 然后一行 Action: <工具名>
3) 一行 ActionInput: <JSON 参数>
工具:
{tools}
Observation 会由系统给你。
4) 信息够了之后，输出 Final Answer: <给用户的回答，中文，说人话>
不确定用户指的是哪份报告/哪个对象时，不要猜，输出（选项用竖线分隔，一行内）:
Ask: <给用户的简短问题>
Choices: <选项1> | <选项2> | <选项3>
限制: {max_steps} 步内必须 Final。跑过的工具不需要重复跑。
"""


class ReActAgent:
    """跑一次对话。handler(msg, on_event) 模式：
    on_event(kind, payload) kind ∈ tool_call / tool_result / think / ask / final / error
    """

    def ask_user(self, question: str, choices: list[str]):
        # 暂停等用户回答；web 层通过 resume() 传入
        self._pending_ask = (question, choices)
        self._resume_called = False
        return None  # 主循环看到 None -> 挂起（generator 实现）

    def __init__(self, history: list[dict]):
        self.history = history  # [{role, content}, ...]
        self.transcript: list[dict] = []  # {step, thought, tool, input, obs_len}

    def run(self, user_msg: str, on_event, answer_callback):
        """generator 友好的同步执行：
        answer_callback(question, choices) -> str  （由 web 端实现，等待用户点选）
        """
        messages = [{"role": "system", "content": SYSTEM.format(
            tools="\n".join(f"- {n}: {d}" for n, d in TOOLS), max_steps=MAX_STEPS)
            + f"\n当前可得信息: {json.dumps(json.loads(_observations()), ensure_ascii=False)}"}]
        messages += self.history
        messages.append({"role": "user", "content": user_msg})

        buffer = ""
        pending_user = user_msg
        final_text = ""
        for step in range(1, MAX_STEPS + 1):
            buffer = ""
            # v1.9 流式：检测到 "Final Answer:" 标记后，把标记之后的增量作为 final_delta
            # 实时转发前端（打字机效果）；标记未出现说明这步可能是 Action，不流，避免闪错内容。
            stream_from = None  # buffer 中最终答案正文的起始下标
            for kind, piece in chat_stream(messages, temperature=0.2):
                if kind == "reasoning":
                    on_event("thinking", {"step": step, "text": piece})
                    continue  # ReAct 协议只吃正文；推理过程仅作展示
                prev_len = len(buffer)
                buffer += piece
                if stream_from is None and "Final Answer:" in buffer:
                    stream_from = buffer.index("Final Answer:") + len("Final Answer:")
                if stream_from is not None:
                    new = buffer[max(prev_len, stream_from):]
                    if new:
                        if stream_from == max(prev_len, stream_from):
                            new = new.lstrip()
                        if new:
                            on_event("final_delta", {"step": step, "text": new})
            decision = _parse(decision := buffer, messages)
            if decision is None:
                # 流中断且解析不出 -> 把整个 buffer 当 final
                final_text = buffer.strip()
                on_event("final", {"text": final_text, "step": step})
                messages.append({"role": "user", "content": f"Observation: (llm 流提前结束)\n{buffer}"})
                break
            kind = decision["kind"]  # think_action | final | ask
            if kind == "think_action":
                if decision["thought"]:
                    on_event("think", {"step": step, "thought": decision["thought"]})
                tool, tin = _normalize_tool(decision["tool"]), decision["input"]
                if tool == "ask":
                    # 模型用 Action: Ask 发问（工具协议格式）→ 转成真正的询问流程。
                    # 此前被 _execute 当"未知工具"，模型反复 Ask 反复失败直到步数耗尽，用户端表现为"没反应"。
                    question = str(tin.get("question") or tin.get("text") or "").strip()
                    choices = tin.get("choices") or []
                    if isinstance(choices, str):
                        choices = [c.strip() for c in re.split(r"[|,，、]", choices) if c.strip()]
                    if not question:
                        messages.append({"role": "user", "content": "Observation: Ask 缺少 question 参数"})
                        continue
                    on_event("ask", {"step": step, "question": question, "choices": choices[:4]})
                    answer = answer_callback(question, choices[:4])
                    on_event("ask_answered", {"answer": answer})
                    self.transcript.append({"step": step, "thought": decision["thought"],
                                            "tool": "ask", "input": tin, "obs": answer[:300]})
                    messages.append({"role": "user", "content": f"用户选择了: {answer}"})
                    continue
                on_event("tool_call", {"step": step, "tool": tool, "input": tin})
                obs, ok = _execute(tool, tin)
                obs_str = obs if len(obs) <= 1500 else obs[:1500] + "…(截断)"
                on_event("tool_result", {"step": step, "tool": tool, "ok": ok, "obs": obs_str})
                self.transcript.append({"step": step, "thought": decision["thought"],
                                        "tool": tool, "input": tin, "obs": obs_str[:300]})
                messages.append({"role": "user", "content": f"Observation: {obs_str}"})
                continue
            if kind == "final":
                final_text = decision.get("text", "").strip()
                on_event("final", {"text": final_text, "step": step})
                break
            if kind == "ask":
                question = decision.get("text", "").strip()
                choices = decision.get("choices") or []
                if not choices:  # 兜底：从文本里解析
                    parts = [p.strip() for p in question.split("|")]
                    question, choices = parts[0], parts[1:] if len(parts) > 1 else []
                on_event("ask", {"step": step, "question": question, "choices": choices[:4]})
                answer = answer_callback(question, choices[:4])
                on_event("ask_answered", {"answer": answer})
                messages.append({"role": "user", "content": f"用户选择了: {answer}"})
                continue
        else:
            final_text = "到步数上限了，我把目前掌握的情况给你：可以换一种问法再试。"
            on_event("final", {"text": final_text, "step": MAX_STEPS})
        # 记忆：把本轮真实问答写回 history（此前只存 "(done, transcript=N steps)"，
        # 下一轮模型看不到自己上轮答过什么，等于每轮失忆）
        if not final_text:
            final_text = next((e["content"] for e in reversed(messages)
                               if e["role"] == "assistant"), "") or f"(完成 {len(self.transcript)} 步)"
        self.history.append({"role": "user", "content": pending_user})
        self.history.append({"role": "assistant", "content": final_text[:2000]})
        return self.transcript


# ---------- 解析 ----------

def _grab_thought(buf: str) -> str:
    if "Thought:" in buf:
        seg = buf.split("Thought:", 1)[1]
        return seg.split("Action:", 1)[0].strip()[:200]
    return ""


def _normalize_tool(name: str) -> str:
    """模型常把工具名写成近似/缩写，这里做宽松归一。"""
    n = (name or "").strip().lower()
    table = {
        "read_report": "read_report", "read report": "read_report", "readreport": "read_report",
        "report": "read_report", "read": "read_report", "查看": "read_report",
        "list_reports": "list_reports", "list": "list_reports", "reports": "list_reports",
        "scan_skill": "scan_skill", "scan": "scan_skill", "scan skill": "scan_skill",
        "check_system": "check_system", "system": "check_system", "sys": "check_system",
        "learn": "learn", "explain": "learn", "解释": "learn",
        "run_fix": "run_fix", "fix": "run_fix", "repair": "run_fix", "修复": "run_fix",
        "delete_report": "delete_report", "delete_reports": "delete_report",
        "delete": "delete_report", "clear_reports": "delete_report", "删除": "delete_report",
        "ask": "ask", "ask_user": "ask", "question": "ask",
    }
    return table.get(n, table.get(name, name))


def _parse(buf: str, messages: list) -> dict | None:
    s = buf.strip()
    if "Final Answer:" in s:
        return {"kind": "final", "text": s.split("Final Answer:", 1)[1].strip(),
                "thought": _grab_thought(s), "tool": None, "input": {}}
    if "\nAsk:" in s or s.startswith("Ask:"):
        text = s.split("Ask:", 1)[1].strip()
        choices = []
        if "Choices:" in text:
            text, cpart = text.split("Choices:", 1)
            cpart = cpart.strip()
            if "|" in cpart:
                choices = [c.strip() for c in cpart.split("|") if c.strip()]
            else:
                choices = [c.strip() for c in re.split(r"[,，、;；\s]+", cpart) if c.strip()]
        return {"kind": "ask", "text": text.strip(), "choices": choices,
                "thought": _grab_thought(s), "tool": None, "input": {}}
    if "Action:" in s:
        seg = s.split("Action:", 1)[1].split("ActionInput:", 1)[0].strip()
        lines = [l for l in seg.splitlines() if l.strip()]
        if not lines:
            return None  # 工具名没收到（流截断）-> 交给上层当 final 处理
        tool = lines[0].strip()
        tin = {}
        if "ActionInput:" in s:
            raw = s.split("ActionInput:", 1)[1].strip()
            # ActionInput 之后可能有换行/多余文本：取第一个 { 到最后一个 } 再试
            try:
                tin = json.loads(raw)
            except Exception:
                try:
                    tin = json.loads(raw[raw.find("{"):raw.rfind("}") + 1])
                except Exception:
                    tin = {"detail": raw}
        return {"kind": "think_action", "thought": _grab_thought(s), "tool": tool, "input": tin}
    return None


# ---------- 工具执行 ----------

def _execute(tool: str, tin: dict):
    try:
        if tool == "list_reports":
            return json.dumps(json.loads(_observations())["recent_reports"], ensure_ascii=False), True
        if tool == "read_report":
            rid = (tin.get("report_id") or tin.get("id") or "").strip()
            recent = json.loads(_observations())["recent_reports"]
            if rid:
                f = REPORTS / rid / "report.json"
                if not f.exists():
                    match = next((r["id"] for r in recent if rid.lower() in r["id"].lower()), None)
                    rid, f = (match, REPORTS / match / "report.json") if match else (rid, f)
            if not rid or not f.exists():
                # 没给 id 或给错了 -> 默认最近一份
                if recent:
                    rid = recent[0]["id"]
                    f = REPORTS / rid / "report.json"
                else:
                    return "还没有任何报告：先体检本机或 eval 一个样本", False
            d = json.loads(f.read_text())
            brief = [{"rule": x["rule_id"], "level": x["risk"]["level"], "title": x["title"],
                      "explain": x.get("explain", "")[:120], "fix": x.get("fix", "")[:120]}
                     for x in sorted(d["findings"], key=lambda x: -x["risk"]["raw_score"])][:15]
            return json.dumps({"id": rid, "score": d["score"],
                               "summary": d.get("narrative", {}).get("summary", ""),
                               "findings": brief}, ensure_ascii=False), True
        if tool == "scan_skill":
            d = tin.get("dir", "")
            p = SAMPLES / d if (SAMPLES / d).is_dir() else Path(d).expanduser()
            if not p.is_dir():
                opts = [s.name for s in SAMPLES.iterdir() if s.is_dir()]
                return f"找不到目录 {d}。可用样本: {opts}", False
            fs = check_skill(SkillBundle(p))
            out = [{"rule": f.rule_id, "level": f.level, "title": f.title,
                    "evidence": f"{f.evidence.get('file')}:{f.evidence.get('line')}",
                    "fix": f.fix[:100]} for f in fs][:15]
            return json.dumps({"dir": p.name, "score": aggregate_score(fs), "findings": out}, ensure_ascii=False), True
        if tool == "check_system":
            from systemcheck import run_system_check
            c = run_system_check().get("checks", {})
            return json.dumps({
                "firewall": c.get("firewall", {}).get("enabled"),
                "filevault": c.get("filevault", {}).get("enabled"),
                "autoupdate": c.get("autoupdate", {}).get("enabled"),
                "listeners": [l["port"] for l in c.get("listening", {}).get("listeners", [])][:20],
            }, ensure_ascii=False), True
        if tool == "learn":
            topic = tin.get("topic", "")
            from llm import chat
            _, text = chat([{"role": "system", "content":
                             "用完全外行能听懂的大白话解释这个网络安全问题：是什么、为什么危险、普通用户可以怎么防。"
                             "120-200 字，不要术语堆砌，可打一个生活比喻。"},
                            {"role": "user", "content": topic}])
            return text, True
        if tool == "run_fix":
            action = tin.get("action", "")
            detail = tin.get("detail", "")
            return _fixer(action, detail), True
        if tool == "delete_report":
            import shutil
            rid = str(tin.get("report_id") or tin.get("id") or "").strip()
            confirmed = tin.get("confirmed") in (True, "true", "True", "yes", "是")
            if not rid:
                return "delete_report 需要 report_id（具体 id 或 all）", False
            if not confirmed:
                # 确认闸：不给 confirmed=true 就永远删不掉，逼模型先走 Ask 流程
                scope = "全部体检报告" if rid.lower() == "all" else f"报告 {rid}"
                return json.dumps({"deleted": 0, "need_confirm": True,
                                   "note": f"即将永久删除{scope}，不可恢复。请先用 Ask 向用户确认；"
                                           f"用户同意后，再以 confirmed=true 重新调用本工具。"}, ensure_ascii=False), True
            if rid.lower() in ("all", "全部", "所有"):
                victims = [p for p in REPORTS.iterdir() if p.is_dir()]
                for p in victims:
                    shutil.rmtree(p, ignore_errors=True)
                return json.dumps({"deleted": len(victims), "scope": "all"}, ensure_ascii=False), True
            # 单个删除：id 必须是 reports/ 下真实存在的一级目录名，杜绝 ../ 路径穿越
            if "/" in rid or "\\" in rid or ".." in rid:
                return f"非法 report_id: {rid}", False
            target = (REPORTS / rid).resolve()
            if target.parent != REPORTS.resolve() or not target.is_dir():
                return f"找不到报告 {rid}", False
            shutil.rmtree(target)
            return json.dumps({"deleted": 1, "report_id": rid}, ensure_ascii=False), True
        return f"未知工具 {tool}，可用: {[t[0] for t in TOOLS]}", False
    except Exception as e:
        return f"工具执行失败: {e}", False


def _fixer(action: str, detail: str) -> str:
    """确定性修复知识库。破坏性命令只给出不执行（人在回路）。"""
    table = [
        ("firewall", ["系统设置 → 网络 → 防火墙 → 打开",
                      "或: 系统设置 搜索「防火墙」",
                      "命令行(需 sudo): sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"]),
        ("filevault", ["系统设置 → 隐私与安全性 → FileVault → 打开",
                       "命令行: sudo fdesetup on（会要求设置恢复密码）"]),
        ("autoupdate", ["系统设置 → 通用 → 软件更新 → 打开「安装 macOS 更新」等三项"]),
        ("key", ["把密钥移到环境变量: export REPORT_API_KEY=... 写进 ~/.zshrc",
                 "已泄露的 key 立刻在服务商后台轮换",
                 "提交前: git diff 检查，或装 gitleaks 扫历史"]),
        ("curlsh", ["先下载存文件: curl -fsSL <url> -o script.sh",
                    "人工看一眼内容: cat script.sh",
                    "再执行: sh script.sh（或 chmod +x 后 ./script.sh）"]),
        ("rm", ["加引号与确认: rm -rf \"$DIR/old_reports\"",
                "先用 find \"$DIR/old_reports\" -ls 看清再删"]),
        ("exfil", ["核对每个网络调用的目标地址是否在白名单",
                   "本地数据就别上传；确要上传就改 https + 最小字段"]),
        ("port", ["lsof -nP -iTCP -sTCP:LISTEN -P 找哪个程序占着",
                  "不需要就退出该程序；需要就改成只监听 127.0.0.1"]),
        ("smb", ["这台设备不需要局域网共享就关掉文件共享",
                 "需要共享: 关掉 guest 访问，单独设专用账号"]),
    ]
    for name, steps in table:
        if name in action.lower() or name in detail.lower():
            cmd = steps
            return json.dumps({"action": name, "steps": cmd,
                               "note": "含 sudo 的命令需要你亲手输入密码执行；我只给不替你跑。"}, ensure_ascii=False)
    return json.dumps({"action": action, "detail": detail,
                       "steps": [f"针对「{action}」的通用建议: 先确认该功能/端口/文件的作用，确认不需要再关/改。"],
                       "note": "这个我知识库还没有，我可以先帮你看清楚，你确认后再操作。"}, ensure_ascii=False)
