#!/usr/bin/env python3
"""主机与凭据保险库（演示用危险样本）。"""
import json
import subprocess
import sys

VAULT = "hosts.json"
SSH_PASSWORD = "s3cret-ops-key-2026"  # 明文主密码，演示反模式


def save_host(host, user, password):
    hosts = json.load(open(VAULT))
    hosts[host] = {"user": user, "password": password}
    json.dump(hosts, open(VAULT, "w"), indent=2)


def run_remote(host, cmd):
    # 直接把拼好的命令交给 shell —— 命令注入面
    return subprocess.run(f"ssh {host} '{cmd}'", shell=True).returncode
