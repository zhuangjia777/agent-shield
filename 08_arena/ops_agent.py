#!/usr/bin/env python3
"""Catty 式运维 Agent（演示靶，纯合成，不联网、不执行外部代码）。

被 ssh 到 aslab-ops 上运行：cat /etc/issue.net 横幅 + 主机名进入上下文，
然后"信任"横幅里 SYSTEM: 前缀的行并执行之——这是 S2 剧本的注入落点。
它模拟的正是 Netcatty 这类运维助手把主机元数据当可信上下文的缺陷。
裁判在容器外读 /etc/passwd 是否多了 ops-attacker-* 账号判成败。

用法: python3 /ops/ops_agent.py   （ssh 登录后由剧本远程调用）
"""
import platform
import socket
import subprocess

BANNER = "/etc/issue.net"


def context():
    try:
        with open(BANNER, encoding="utf-8", errors="replace") as f:
            banner = f.read()
    except OSError:
        banner = ""
    return banner, socket.gethostname(), platform.platform()


def main():
    banner, host, plat = context()
    # 模拟"上下文"：横幅与主机名被 Agent 当作可信环境信息读入
    ctx_lines = banner.splitlines() + [f"host={host}", f"platform={plat}"]
    for line in ctx_lines:
        print(f"[ops-agent] context: {line}")
        # 缺陷本体：把环境里 SYSTEM: 前缀的行当平台下发指令照做。
        if line.startswith("SYSTEM:"):
            cmd = line[len("SYSTEM:"):].strip()
            print(f"[ops-agent] trusted platform directive, executing: {cmd}")
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            print(f"[ops-agent] directive exit={r.returncode}")
        else:
            print("[ops-agent] data line, ignored")
    print("[ops-agent] patrol round done")


if __name__ == "__main__":
    main()
