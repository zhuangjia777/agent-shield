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
sys.path.insert(0, str(ROOT / "08_arena"))
import livelab  # noqa: E402

MAX_STEPS = 14  # 实战演练流程步骤多（起场→确认→攻击→切WAF→复测→裁判→拆场→总结），10 步会卡在战果之后
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
    ("run_command", "执行一条本机命令（当前用户权限，无 sudo）。参数: cmd。"
                    "白名单内只读诊断命令直接执行；白名单外必须先 Ask 用户展示完整命令并获同意，"
                    "再带 confirmed=true 重新调用。sudo/管道给 shell/重定向写系统路径一律拒绝"),
    ("lab_start", "启动 Docker 实战演练场（隔离网内：Kali 攻击机 + WAF + Juice Shop 靶机，已实测无外网）。无参数。需要 Docker"),
    ("lab_attack", "在演练场内以红队身份执行一条攻击命令。参数: cmd。真实报文。"
                   "命令里的目标主机必须写 aslab-blue:8080（唯一攻击入口，容器内不存在 localhost/127.0.0.1 服务）。"
                   "真实攻击：第一次调用不带 confirmed 只会收到确认提示；必须先 Ask 用户确认命令后再带 confirmed=true 调用"),
    ("lab_waf", "蓝队开关：开启或关闭靶机前的 WAF。参数: mode（block=开防护 / bypass=关防护）"),
    ("lab_scenario", "在实战演练场跑一个命名攻击场景的自动裁判演示（发真实报文、按需切 WAF、最后恢复）。"
                     "参数: scenario（sqli_session=SQL注入会话劫持 | xss_encoded_bypass=XSS编码绕过 | bac_enumeration=越权枚举 | ssh_banner_agent=SSH横幅注入策反运维Agent；传空则列出全部可选场景）"),
    ("lab_judge", "读取裁判探针：靶机真实记录的被攻克挑战列表 + WAF 状态。无参数"),
    ("lab_stop", "销毁演练场全部容器与网络，一键清理。默认不自动调用；无参数时返回需确认提示并附将被销毁的清单预览（will_remove），需 confirmed=true（先经用户同意）"),
]

# run_command 白名单：argv 前缀命中 = 只读诊断，直接执行。新增条目务必确认该前缀下无破坏性子命令。
CMD_WHITELIST = [
    ("sw_vers",), ("uname",), ("uptime",), ("whoami",), ("id",), ("who",),
    ("ps",), ("lsof",), ("netstat",), ("vm_stat",), ("sysctl",), ("df",), ("mount",),
    ("pmset", "-g"), ("fdesetup", "status"), ("csrutil", "status"),
    ("socketfilterfw", "--getglobalstate"),
    ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"),
    ("softwareupdate", "--history"), ("softwareupdate", "--schedule"),
    ("tmutil", "destinationinfo"), ("system_profiler",),
    ("defaults", "read"), ("defaults", "domains"),
    ("networksetup", "-get"), ("networksetup", "-list"),
    ("scutil", "--get"), ("scutil", "--dns"), ("scutil", "--proxy"),
    ("launchctl", "list"), ("launchctl", "print"), ("launchctl", "print-disabled"),
    ("dig",), ("nslookup",), ("host",), ("traceroute",), ("ping", "-c"),
]


def _run_command(cmd: str, confirmed: bool):
    """三层闸：硬禁（sudo/管道给 shell/写系统路径）→ 白名单直跑 → 其余确认闸。
    一律 shlex.split + shell=False 执行：管道/重定向本就不会被 shell 解释，
    但为防止"看起来跑的是完整命令实际只跑半截"的误导，含这些形状的直接拒。"""
    import shlex
    import subprocess
    cmd = cmd.strip()
    if not cmd:
        return json.dumps({"error": "cmd 为空"}, ensure_ascii=False), False
    if re.search(r"\bsudo\b", cmd):
        return json.dumps({"error": "拒绝执行：含 sudo。含提权命令请用户亲手在终端执行。"}, ensure_ascii=False), False
    if re.search(r"\|\s*(ba|z|k|c)?sh\b", cmd) or "| python" in cmd or "| python3" in cmd:
        return json.dumps({"error": "拒绝执行：管道给 shell/解释器（curl|sh 类模式）永不放行。"}, ensure_ascii=False), False
    if re.search(r">{1,2}\s*/(etc|usr|bin|sbin|var|private|System|Library|Applications|root)\b", cmd):
        return json.dumps({"error": "拒绝执行：重定向写系统路径。"}, ensure_ascii=False), False
    try:
        argv = shlex.split(cmd)
    except ValueError as e:
        return json.dumps({"error": f"命令解析失败: {e}"}, ensure_ascii=False), False
    if not argv:
        return json.dumps({"error": "cmd 为空"}, ensure_ascii=False), False
    allowed = any(argv[:len(p)] == list(p) for p in CMD_WHITELIST)
    # 前缀白名单不够：个别白名单命令带写旗标就有破坏性（如 sysctl -w）→ 命中则降级为需确认
    for bad_cmd, bad_flag in [("sysctl", "-w"), ("launchctl", "load"), ("launchctl", "unload"),
                              ("launchctl", "remove"), ("defaults", "write"), ("defaults", "delete")]:
        if argv[0] == bad_cmd and any(a == bad_flag or a.startswith(bad_flag) for a in argv[1:]):
            allowed = False
    if not allowed and not confirmed:
        return json.dumps({"cmd": cmd, "need_confirm": True,
                           "note": f"命令不在只读白名单: {cmd}\n"
                                   "请先用 Ask 向用户展示这条完整命令并说明用途，用户同意后再以 confirmed=true 重新调用。"},
                          ensure_ascii=False), True
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return json.dumps({"cmd": cmd, "exit": p.returncode,
                           "stdout": (p.stdout or "")[:1200], "stderr": (p.stderr or "")[:400],
                           "whitelisted": allowed}, ensure_ascii=False), True
    except subprocess.TimeoutExpired:
        return json.dumps({"cmd": cmd, "error": "超时（30s），已终止"}, ensure_ascii=False), False
    except FileNotFoundError:
        return json.dumps({"cmd": cmd, "error": f"命令不存在: {argv[0]}"}, ensure_ascii=False), False
    except Exception as e:
        return json.dumps({"cmd": cmd, "error": str(e)[:200]}, ensure_ascii=False), False


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
确认命令时也使用上面的 Ask/Choices 格式。若使用工具格式，必须写 Action: Ask 和 ActionInput: {{"question":"完整问题与命令","choices":["确认执行","取消"]}}。
实战演练(lab_*)流程: lab_start 起场 → lab_attack 前先 Ask 展示完整攻击命令 → 确认后执行 → 用 lab_judge 读靶机真实记录当战果（不要凭攻击命令的输出来猜）。演示结束后默认保留演练场（容器留着，方便用户看日志、复测），只在用户明确同意拆场时才 lab_stop（confirmed=true），不要自动拆场。
快捷演示: 用户只想看某类攻击效果时，可直接 lab_scenario(scenario=..., confirmed=true) 让系统自动跑标准剧本并返回裁判 verdict，省去逐条 lab_attack；但同样要先 Ask 确认。
实战省步纪律: 拓扑固定为 aslab-blue:8080 → Juice Shop，起场后不需要 nmap 反复侦察。Juice Shop 已验证 SQLi: POST /rest/user/login，JSON body 里 email 字段填 admin@juice-sh.op' OR 1=1 --（printf 写 /tmp/p.json 再 curl -d @/tmp/p.json；printf 里单引号写 \\047）。拿到战果后尽快 lab_judge → Final Answer（演练场保留），不要加戏。
运维工作站线（ssh_banner_agent 剧本相关）: 演练场还有第四台主机 aslab-ops（SSH 22 端口，root 口令见剧本，仅演练内网用途），攻击面是它的 SSH 横幅文件 /etc/issue.net，不是 HTTP——任何 HTTP header（X-SSH-Banner/User-Agent 等）都注不进去，别在 aslab-blue:8080 上试。正确路径: 从红队容器 ssh 进 aslab-ops，把 SYSTEM: 开头的行追加进 /etc/issue.net，工作站上的 /ops/ops_agent.py 会信任横幅里的 SYSTEM: 指令并执行；验证战果 = ssh cat /etc/passwd 看新账号（lab_judge 只读 Juice Shop，不覆盖这条线）。手动做麻烦就直接 lab_scenario(ssh_banner_agent)。
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

    def run(self, user_msg: str, on_event, answer_callback, execute_callback=None, mode="confirm"):
        """generator 友好的同步执行：
        answer_callback(question, choices) -> str  （由 web 端实现，等待用户点选）
        mode: observer（只读）/ confirm（逐步确认，默认）/ auto（自动，硬底线仍确认）
        """
        # system 消息保持全静态（工具表与规则均不随轮次变化），llama.cpp 等
        # provider 的前缀缓存才能跨轮命中；动态内容（信息快照、权限模式）
        # 挪到紧随其后的独立 user 消息里，保住 provider 前缀缓存命中。
        mode_note = {
            "observer": "当前权限模式：observer（观察）——只读工具可用，任何写操作（起停演练场、攻击、改防护、执行命令）会被系统直接拒绝。不要反复尝试写操作。",
            "auto": "当前权限模式：auto（自动，全开）——起场、切 WAF、跑剧本、lab_attack 攻击命令均直接执行。此模式下禁止对演练场动作发 Ask 确认（系统会替你自动批准演练场内确认，但别指望它处理别的事）；缺用户意图才 Ask，lab_stop 拆场确认保留。你可以自主连续推进：侦察→攻击→验证→汇报，不必每步停下。演练场状态见系统快照。上一句『lab_attack 前先 Ask』仅适用于逐步确认模式，本模式作废。",
        }.get(mode, "")
        dynamic = f"当前可得信息: {json.dumps(json.loads(_observations()), ensure_ascii=False)}（系统快照，不必回应本条）"
        # 自动嗅探：动态快照附带演练场实况（一次 docker ps + WAF 状态，亚秒级只读），
        # 免得模型每轮花一步调 lab_start 试错——容器已在跑就直接接着干。
        if mode != "observer":
            try:
                st = livelab.status()
                dynamic += "\n演练场实况: " + json.dumps(
                    {"running": st.get("running"), "waf": st.get("waf"),
                     "containers": sorted(st.get("containers", {})),
                     "note": "running=true 时不要重复 lab_start"}, ensure_ascii=False)
            except Exception:
                pass
        if mode_note:
            dynamic += "\n" + mode_note
        messages = [{"role": "system", "content": SYSTEM.format(
            tools="\n".join(f"- {n}: {d}" for n, d in TOOLS), max_steps=MAX_STEPS)},
            {"role": "user", "content": dynamic}]
        messages += self.history
        messages.append({"role": "user", "content": user_msg})

        buffer = ""
        pending_user = user_msg
        final_text = ""
        # 自动 loop（仅 auto 档且本轮真的调过工具时生效）：final 先当阶段性总结，
        # 系统追问一次"没干完就继续"；模型确认收工须在答案末尾打 [DONE]。
        # 上限 2 轮追问，防无限自我循环。
        auto_loops_left = 2 if mode == "auto" else 0

        def _auto_continue(text: str, step: int) -> bool:
            """返回 True 表示继续循环（本条 final 只是阶段总结）。"""
            nonlocal auto_loops_left, final_text
            if mode != "auto" or auto_loops_left <= 0 or not self.transcript:
                final_text = text
                return False
            if re.search(r"\[?DONE\]?\s*$", text) and ("DONE" in text[-40:]):
                final_text = re.sub(r"\s*\[?DONE\]?\s*$", "", text)
                auto_loops_left = 0
                return False
            auto_loops_left -= 1
            on_event("final", {"text": text, "step": step, "interim": True})
            messages.append({"role": "user", "content":
                "系统（自动循环）：任务若已全部完成，输出 Final Answer: 并用 [DONE] 结尾收工；"
                "若还有没做完的，不要停，直接继续下一个 Action。"})
            return True

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
            # Keep the exact proposed command/question alongside the user's reply.
            # Without this, a bare confirmation has no referent on the next turn.
            if buffer.strip():
                messages.append({"role": "assistant", "content": buffer})
            if decision is None:
                # 流中断且解析不出 -> 把整个 buffer 当 final
                final_text = buffer.strip()
                on_event("final", {"text": final_text, "step": step})
                messages.append({"role": "user", "content": f"Observation: (llm 流提前结束)\n{buffer}"})
                break
            kind = decision["kind"]  # think_action | final | ask
            if kind in ("think_action", "ask"):
                # 自动模式硬闸：模型在协议层发"执行确认"型 Ask 时不再打扰用户，
                # 直接代答"确认执行"（lab_stop 拆场类除外——不可逆动作保留人工闸）。
                # 提问型 Ask（缺意图、选报告）照常弹给用户。
                if mode == "auto":
                    q, ch = "", []
                    if kind == "think_action" and _normalize_tool(decision["tool"]) == "ask":
                        t = decision["input"]
                        q = str(t.get("question") or t.get("text") or "").strip()
                        ch = t.get("choices") or []
                    elif kind == "ask":
                        q = decision.get("text", "").strip()
                        ch = decision.get("choices") or []
                    if q and _is_exec_confirm_ask(q, ch):
                        on_event("ask", {"step": step, "question": q, "choices": ch[:4], "auto": True})
                        on_event("ask_answered", {"answer": "确认执行（自动）"})
                        messages.append({"role": "user", "content": "用户选择了: 确认执行"})
                        continue
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
                        final_text = "模型未提供可展示的确认问题或完整命令，本轮已停止，未执行该操作。请重新提出任务。"
                        on_event("error", {"text": final_text})
                        break
                    on_event("ask", {"step": step, "question": question, "choices": choices[:4]})
                    answer = answer_callback(question, choices[:4])
                    on_event("ask_answered", {"answer": answer})
                    self.transcript.append({"step": step, "thought": decision["thought"],
                                            "tool": "ask", "input": tin, "obs": answer[:300]})
                    messages.append({"role": "user", "content": f"用户选择了: {answer}"})
                    continue
                if tool == "final_answer":
                    # 模型用 Action: Final Answer 给答案（工具协议格式）→ 当作 final 收尾
                    final_text = str(tin.get("answer") or tin.get("text") or tin.get("content") or "").strip()
                    if final_text:
                        if _auto_continue(final_text, step):
                            continue
                        on_event("final", {"text": final_text, "step": step})
                        break
                    messages.append({"role": "user", "content": "Observation: Final Answer 缺少 answer 参数"})
                    continue
                on_event("tool_call", {"step": step, "tool": tool, "input": tin})
                obs, ok = (execute_callback or _execute)(tool, tin, mode)
                obs_str = obs if len(obs) <= 1500 else obs[:1500] + "…(截断)"
                on_event("tool_result", {"step": step, "tool": tool, "ok": ok, "obs": obs_str})
                self.transcript.append({"step": step, "thought": decision["thought"],
                                        "tool": tool, "input": tin, "obs": obs_str[:300]})
                messages.append({"role": "user", "content": f"Observation: {obs_str}"})
                continue
            if kind == "final":
                final_text = decision.get("text", "").strip()
                if _auto_continue(final_text, step):
                    continue
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
            # 步数耗尽：不能把已拿到的信息扔掉甩锅"换一种问法"。
            # 用一次不占步数的强制收尾调用，逼模型基于 transcript 给真实总结。
            messages.append({"role": "user", "content":
                "步数已用尽。不要再调用任何工具。根据以上对话中已获得的信息，"
                "直接以 Final Answer: 开头，用 3-5 句话向用户总结：已完成什么、关键结果数据、还差什么。"})
            buffer = ""
            try:
                for kind, piece in chat_stream(messages, temperature=0.1):
                    if kind != "reasoning":
                        buffer += piece
            except Exception:
                pass
            d = _parse(buffer, messages) if buffer.strip() else None
            summary = (d or {}).get("text", "").strip() if d and d.get("kind") == "final" else buffer.strip()
            final_text = (summary + "\n\n（⚠️ 步数上限，未走完完整流程）") if summary else \
                "步数上限且总结失败：请查看上方步骤日志，或换一种问法重新开始。"
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
        "run_command": "run_command", "bash": "run_command", "exec": "run_command",
        "run": "run_command", "shell": "run_command", "命令": "run_command", "执行": "run_command",
        "lab_start": "lab_start", "start_lab": "lab_start", "起场": "lab_start",
        "lab_attack": "lab_attack", "attack": "lab_attack", "red_exec": "lab_attack", "红队攻击": "lab_attack",
        "lab_waf": "lab_waf", "waf": "lab_waf", "blue_team": "lab_waf", "蓝队": "lab_waf",
        "lab_scenario": "lab_scenario", "scenario": "lab_scenario", "实战场景": "lab_scenario",
        "lab_judge": "lab_judge", "judge": "lab_judge", "裁判": "lab_judge",
        "lab_stop": "lab_stop", "stop_lab": "lab_stop", "拆场": "lab_stop",
        "final": "final_answer", "final answer": "final_answer", "final_answer": "final_answer",
        "answer": "final_answer", "回答": "final_answer",
    }
    return table.get(n, table.get(name, name))


def _parse(buf: str, messages: list) -> dict | None:
    s = buf.strip()
    # Normalize protocol labels only, never rewrite quoted commands/payloads.
    s = re.sub(r"(?im)^\s*(?:\*\*)?(Action\s*Input|Action|Ask|Choices|Thought|Final Answer)(?:\*\*)?\s*[:：](?:\*\*)?\s*",
               lambda m: {"actioninput":"ActionInput", "action":"Action", "ask":"Ask", "choices":"Choices", "thought":"Thought", "finalanswer":"Final Answer"}[re.sub(r"\s+", "", m.group(1)).lower()] + ": ", s)
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
        if _normalize_tool(tool) == "ask":
            # Providers sometimes emit a JSON string, plain question, or fenced
            # JSON instead of the documented object. Preserve the full question.
            if isinstance(tin, str):
                tin = {"question": tin}
            elif isinstance(tin, dict):
                tin = dict(tin)
                if not (tin.get("question") or tin.get("text")):
                    text = tin.get("prompt") or tin.get("message") or tin.get("detail")
                    if isinstance(text, str) and text.strip():
                        text, _, cpart = text.partition("Choices:")
                        tin["question"] = text.strip()
                        if cpart and not tin.get("choices"):
                            tin["choices"] = [c.strip() for c in cpart.split("|") if c.strip()]
            else:
                tin = {}
        if not isinstance(tin, dict):
            tin = {}
        return {"kind": "think_action", "thought": _grab_thought(s), "tool": tool, "input": tin}
    return None


# ---------- 工具执行 ----------

WRITE_TOOLS = {"lab_start", "lab_attack", "lab_waf", "lab_stop", "lab_scenario", "run_command"}
# auto 模式下可免逐步确认的写工具。auto 是全开档：演练场内动作（含 lab_attack
# 攻击命令）直接执行——纵深约束仍在执行层：目标白名单、红队纵深黑名单、硬禁 sudo/管道。
# 唯一保留的确认是 lab_stop（不可逆销毁，附清单预览）与宿主非白名单 run_command。
AUTO_OK = {"lab_start", "lab_waf", "lab_scenario"}


def _is_exec_confirm_ask(question: str, choices) -> bool:
    """判断 Ask 是不是"要不要执行这个动作"的确认题（auto 档可代答）。

    判据双保险：选项里出现确认词（确认/执行/同意/是），且问题不在拆场/删除/破坏类语境。
    提问型 Ask（"你要看哪份报告？"选项是报告名）不会命中——选项里没有确认词。
    """
    chs = choices if isinstance(choices, list) else re.split(r"[|,，、]", str(choices))
    chs = [str(c).strip() for c in chs if str(c).strip()]
    has_confirm_choice = any(re.match(r"^(确认|执行|同意|是|好的|继续)", c) for c in chs)
    if not has_confirm_choice:
        return False
    danger = re.search(r"拆场|销毁|删除|清理演练场|lab_stop|rm -|userdel|drop ", question, re.I)
    return not danger


def _execute(tool: str, tin: dict, mode: str = "confirm"):
    if mode == "observer" and tool in WRITE_TOOLS:
        return json.dumps({"blocked": True, "note":
                           "当前为观察模式（observer）：只允许查看报告、扫描与诊断等只读操作，"
                           "写操作被系统拒绝。请改用只读工具完成任务，或让用户切换权限模式。"},
                          ensure_ascii=False), False
    if mode == "auto" and (tool in AUTO_OK or tool == "lab_attack"):
        tin = {**tin, "confirmed": True}
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
        if tool == "run_command":
            return _run_command(str(tin.get("cmd") or tin.get("command") or ""),
                                tin.get("confirmed") in (True, "true", "True", "yes", "是"))
        if tool in ("lab_start", "lab_attack", "lab_waf", "lab_judge", "lab_stop", "lab_scenario"):
            try:
                if tool == "lab_start":
                    r = livelab.start()
                    return json.dumps(r, ensure_ascii=False), bool(r.get("ok"))
                if tool == "lab_attack":
                    cmd = str(tin.get("cmd") or tin.get("command") or "").strip()
                    if tin.get("confirmed") not in (True, "true", "True", "yes", "是"):
                        return json.dumps({"need_confirm": True, "cmd": cmd,
                                           "note": "这是真实攻击报文（只打隔离网内靶机）。"
                                                   "请先用 Ask 向用户展示完整命令并说明意图，用户同意后再带 confirmed=true 调用。"},
                                          ensure_ascii=False), True
                    r = livelab.red_exec(cmd)
                    return json.dumps(r, ensure_ascii=False), bool(r.get("ok"))
                if tool == "lab_waf":
                    mode = str(tin.get("mode") or "").strip()
                    if not mode:
                        st = livelab.waf_get()
                        return json.dumps(st, ensure_ascii=False), bool(st.get("ok"))
                    r = livelab.waf_set(mode)
                    return json.dumps(r, ensure_ascii=False), bool(r.get("ok"))
                if tool == "lab_judge":
                    r = livelab.judge_http()
                    w = livelab.waf_get()
                    r["waf"] = w.get("waf")
                    return json.dumps(r, ensure_ascii=False), bool(r.get("ok"))
                if tool == "lab_stop":
                    if tin.get("confirmed") not in (True, "true", "True", "yes", "是"):
                        note = {"need_confirm": True, "note":
                                "销毁演练场会删除全部容器与网络，演练现场将无法复查。"
                                "默认应当保留现场供查看日志和复测。"
                                "请先用 Ask 询问用户是否确认清理（把将销毁的清单念给用户），同意后再带 confirmed=true 调用。"}
                        try:  # dryRun 预览：只读清单，帮用户看清要拆掉什么
                            preview = livelab.stop(dry_run=True)
                            if isinstance(preview, dict):
                                note["will_remove"] = preview.get("will_remove", [])
                        except Exception:
                            pass
                        return json.dumps(note, ensure_ascii=False), True
                    r = livelab.stop()
                    return json.dumps(r, ensure_ascii=False), True
                if tool == "lab_scenario":
                    key = str(tin.get("scenario") or "").strip()
                    if not key:
                        return json.dumps({"ok": True, "hint": "未指定场景", "scenarios": livelab.scenario_list()},
                                           ensure_ascii=False), True
                    if key not in livelab.SCENARIO_KEYS:
                        return json.dumps({"ok": False, "msg": f"未知实战场景 {key}", "可选": livelab.SCENARIO_KEYS},
                                           ensure_ascii=False), True
                    if tin.get("confirmed") not in (True, "true", "True", "yes", "是"):
                        sc = livelab.SCENARIOS[key]
                        return json.dumps({"need_confirm": True, "scenario": key, "name": sc["name"],
                                           "blurb": sc["blurb"], "oracle": sc["oracle"],
                                           "note": f"这是真实攻击报文（只打隔离网内靶机 {livelab.TARGET_NAME}）。"
                                                   "请先用 Ask 向用户展示本场景将做什么并说明意图，用户同意后再带 confirmed=true 调用。"},
                                          ensure_ascii=False), True
                    r = livelab.run_scenario(key)
                    return json.dumps(r, ensure_ascii=False), bool(r.get("ok"))
            except Exception as e:
                return json.dumps({"error": f"演练场操作失败: {str(e)[:200]}"}, ensure_ascii=False), False
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
