#!/usr/bin/env python3
"""AgentShield 终端对话壳（CLI REPL）：不开浏览器，在 bash 里驱动 Agent。

用法:
  .venv/bin/python 03_ai/chat_cli.py                      # 交互模式（多轮，history 保留）
  .venv/bin/python 03_ai/chat_cli.py -m auto "跑一遍 sqli 剧本并汇报战果"   # 一次性
  .venv/bin/python 03_ai/chat_cli.py --objective sqli     # 一次性自主进攻（ReAct loop）
  .venv/bin/python 03_ai/chat_cli.py --objective ssh -m auto -- "banner 先读后写"
  .venv/bin/python 03_ai/chat_cli.py --help

交互命令: /quit /exit 退出；/mode observer|confirm|auto 切权限模式；
/objective sqli|xss|bac|ssh|recon|custom 开始一次自主进攻（下一个输入作为补充要求）。
/declare HOST:PORT 申报演练场外目标（配 custom 用；命令行申报即视为同意）。
Ask 确认直接在终端里选编号回答；auto 模式下执行确认会被系统代答（与网页行为一致）。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (ROOT / "02_scan", ROOT / "05_skill_eval", ROOT / "03_ai", ROOT / "08_arena"):
    sys.path.insert(0, str(p))

import agent as A  # noqa: E402

DIM, YEL, GRN, RED, CYA, RST = "\033[2m", "\033[33m", "\033[32m", "\033[31m", "\033[36m", "\033[0m"


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentShield Agent 终端对话壳")
    ap.add_argument("message", nargs="*", help="一次性消息（省略则进入交互模式）")
    ap.add_argument("-m", "--mode", choices=["observer", "confirm", "auto"],
                    default="confirm", help="权限模式（默认 confirm=逐步确认）")
    ap.add_argument("--objective", choices=sorted(A.VECTORS),
                    help="自主进攻方向（sqli/xss/bac/ssh/recon/custom）：交给 Agent 跑 ReAct loop，"
                         "本轮结束后退出")
    ap.add_argument("--declare", metavar="HOST:PORT",
                    help="M3 目标申报：命令行直接申报即视为用户显式同意，起红队中继通道"
                         "（常配 --objective custom；用完收工自动拆，或 lab_declare_clear）")
    args = ap.parse_args()
    mode = args.mode
    objective = {"vector": args.objective} if args.objective else None
    if args.declare:
        hp = args.declare.rsplit(":", 1)
        if len(hp) != 2:
            print("RED --declare 需要 HOST:PORT 格式，如 127.0.0.1:8799"); return 2
        d = A.livelab.declare_target(hp[0], hp[1])
        print((GRN if d.get("ok") else RED) + ("◆ " + d.get("msg", "")) + RST)
        if not d.get("ok"):
            return 1
        if not objective:
            objective = {"vector": "custom"}
    if args.objective:
        rest = " ".join(args.message).strip()
        msg = ("开始自主进攻：方向 " + args.objective
               + ("，补充要求：" + rest if rest else ""))
    else:
        msg = " ".join(args.message)

    a = A.ReActAgent([])
    streamed_final = False

    # on_event 收到 objective 事件时先打任务书（自主进攻场景）
    def on_event(kind, p):
        nonlocal streamed_final
        if kind == "objective":
            print(f"{CYA}◆ 任务书: {p.get('name')} → {p.get('target')}（步数上限 {p.get('max_steps')}）{RST}")
        elif kind == "think":
            print(f"{DIM}[思考] {(p.get('thought') or p.get('text') or '').strip()[:160]}{RST}")
        elif kind == "tool_call":
            print(f"{YEL}▶ {p['tool']}{RST} {str(p.get('input', ''))[:200]}")
        elif kind == "tool_result":
            mark = GRN if p.get("ok") else RED
            print(f"{mark}  ← {str(p.get('obs', ''))[:400]}{RST}")
        elif kind == "ask_answered" and "自动" in str(p.get("answer", "")):
            print(f"{DIM}  （自动批准）{RST}")
        elif kind == "final_delta":
            sys.stdout.write(p["text"]); sys.stdout.flush(); streamed_final = True
        elif kind == "final":
            if streamed_final:
                sys.stdout.write("\n")
            else:
                print(p.get("text", ""))
            streamed_final = False
            if p.get("interim"):
                print(f"{DIM}—（阶段小结，自动模式将继续）—{RST}")
        elif kind == "error":
            print(f"{RED}出错: {p.get('text', '')}{RST}")

    def answer_cb(question, choices):
        print(f"\n{YEL}Agent 问你:{RST} {question}")
        for i, c in enumerate(choices, 1):
            print(f"  {i}. {c}")
        hint = "选择编号或直接输入回答" if choices else "输入回答"
        try:
            s = input(f"{hint}: ").strip()
        except EOFError:
            return choices[0] if choices else ""
        if choices and s.isdigit() and 1 <= int(s) <= len(choices):
            return choices[int(s) - 1]
        return s or (choices[0] if choices else "")

    def turn(m, obj=None):
        try:
            a.run(m, on_event, answer_cb, mode=mode, objective=obj)
        except KeyboardInterrupt:
            print(f"\n{RED}（已中断本轮）{RST}")
        except Exception as e:
            print(f"{RED}出错: {type(e).__name__}: {e}{RST}")

    print(f"{DIM}AgentShield 终端壳 · 模式={mode} · /mode observer|confirm|auto 切换 · "
          f"/objective sqli|xss|bac|ssh|recon|custom 自主进攻 · /declare H:P 申报目标 · /quit 退出{RST}")

    if args.objective or (message := " ".join(args.message).strip()):
        turn(msg, objective)
        return 0

    pending_objective = None
    while True:
        try:
            line = input(f"\n你 > ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not line:
            continue
        if line in ("/quit", "/exit"):
            return 0
        if line.startswith("/mode"):
            parts = line.split()
            if len(parts) == 2 and parts[1] in ("observer", "confirm", "auto"):
                mode = parts[1]
                print(f"{DIM}模式已切换: {mode}{RST}")
            else:
                print(f"{DIM}用法: /mode observer|confirm|auto{RST}")
            continue
        if line.startswith("/declare"):
            parts = line.split(None, 1)
            arg = parts[1].strip() if len(parts) > 1 else "clear"
            if arg == "clear":
                d = A.livelab.clear_declared()
            elif ":" in arg:
                h, _, prt = arg.rpartition(":")
                d = A.livelab.declare_target(h, prt)
            else:
                d = {"ok": False, "msg": "用法: /declare HOST:PORT 或 /declare clear"}
            print((GRN if d.get("ok") else RED) + d.get("msg", "") + RST)
            continue
        if line.startswith("/objective"):
            parts = line.split(None, 1)
            if len(parts) < 2 or parts[1].strip() not in A.VECTORS:
                print(f"{DIM}用法: /objective sqli | xss | bac | ssh | recon | custom{RST}")
                continue
            pending_objective = parts[1].strip()
            print(f"{DIM}下一句话将作为补充要求开始自主进攻（空行=无要求）{RST}")
            continue
        if pending_objective:
            note = "" if line.startswith("/") else line
            turn("开始自主进攻：方向 " + pending_objective + (f"，补充要求：{note}" if note else ""),
                 {"vector": pending_objective, "note": note})
            pending_objective = None
            continue
        turn(line)


if __name__ == "__main__":
    sys.exit(main())
