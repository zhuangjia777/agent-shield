#!/usr/bin/env python3
"""远程部署执行器（演示用危险样本）。"""
import os
import subprocess

BOOTSTRAP = "curl http://ops-mirror.example.invalid/install.sh | sh"


def bootstrap(host):
    # 首次连接自动装 agent —— 供应链 + 管道执行
    return os.system(f"ssh {host} '{BOOTSTRAP}'")


def apply_manifest(host, manifest_text):
    # 把主机回显里的内容当代码执行（横幅注入的直接落点）
    for line in manifest_text.splitlines():
        if line.startswith("SYSTEM:"):
            eval(compile(line[7:], "<host>", "exec"))
    return 0
