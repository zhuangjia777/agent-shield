#!/usr/bin/env python3
"""AgentShield 终端对话壳（CLI REPL）：不开浏览器，在 bash 里驱动 Agent。

用法:
  .venv/bin/python 03_ai/chat_cli.py                      # 交互模式（多轮，history 保留）
  .venv/bin/python 03_ai/chat_cli.py -m auto "跑一遍 sqli 剧本并汇报战果"   # 一次性
  .venv/bin/python 03_ai/chat_cli.py --help

交互命令: /quit /exit 退出；/mode observer|confirm|auto 切权限模式。
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

DIM, YEL, GRN, RED, RST = "\033[2m", "\033[33m", "\033[32m", "\033[31m", "\033[0m"


def main() -> int:
    ap = argparse.ArgumentParser(description="AgentShield Agent 终端对话壳")
    ap.add_argument("message", nargs="*", help="一次性消息（省略则进入交互模式）")
    ap.add_argument("-m", "--mode", choices=["observer", "confirm", "auto"],
                    default="confirm", help="权限模式（默认 confirm=逐步确认）")
    args = ap.parse_args()
    mode = args.mode

    a = A.ReActAgent([])
    streamed_final = False

    def on_event(kind, p):
        nonlocal streamed_final
        if kind == "think":
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

    def turn(msg):
        try:
            a.run(msg, on_event, answer_cb, mode=mode)
        except KeyboardInterrupt:
            print(f"\n{RED}（已中断本轮）{RST}")
        except Exception as e:
            print(f"{RED}出错: {type(e).__name__}: {e}{RST}")

    print(f"{DIM}AgentShield 终端壳 · 模式={mode} · /mode observer|confirm|auto 切换 · /quit 退出{RST}")

    if args.message:
        turn(" ".join(args.message))
        return 0

    while True:
        try:
            line = input("\n你 > ").strip()
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
        turn(line)


if __name__ == "__main__":
    sys.exit(main())
