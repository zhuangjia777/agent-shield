"""macOS 系统体检：确定性子检查，每项失败不中断整体。"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import time


def _run(cmd: list[str], timeout: int = 20) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"ok": p.returncode == 0, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except FileNotFoundError:
        return {"ok": False, "stdout": "", "stderr": f"missing: {cmd[0]}", "raw": cmd}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stdout": "", "stderr": "timeout", "raw": cmd}


def check_sip() -> dict:
    r = _run(["csrutil", "status"])
    return {"enabled": "enabled" in r["stdout"].lower() and "disabled" not in r["stdout"].lower(),
            "raw": r["stdout"], "ok": r["ok"]}


def check_firewall() -> dict:
    r = _run(["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"])
    val = r["stdout"]
    # 0=off, 1=block all incoming, 2=allow signed / installed
    enabled = val in ("1", "2")
    return {"enabled": enabled, "mode": val, "raw": r["stdout"]}


def check_autoupdate() -> dict:
    r = _run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
    if r["ok"]:
        return {"enabled": r["stdout"] == "1", "mode": "com.apple.SoftwareUpdate defaults"}
    # 新版 macOS 把设置移到别的偏好域，回退
    r2 = _run(["softwareupdate", "--schedule"])
    return {"enabled": "Automatically" in r2["stdout"], "mode": "softwareupdate --schedule", "raw": r2["stdout"]}


def check_filevault() -> dict:
    r = _run(["fdesetup", "status"])
    if "On" in r["stdout"]:
        return {"enabled": True, "raw": r["stdout"]}
    if "Off" in r["stdout"]:
        return {"enabled": False, "raw": r["stdout"]}
    return {"enabled": None, "raw": r["stdout"] + " | " + r["stderr"]}


def check_backup() -> dict:
    r = _run(["tmutil", "destinationinfo"], timeout=15)
    active = "Time Machine Disk" in r["stdout"] and "size" in r["stdout"].lower() or "Available" in r["stdout"]
    return {
        "timemachine": {
            "configured": r["ok"] and ("Time Machine" in r["stdout"] or "destination" in r["stdout"].lower()),
            "raw": (r["stdout"] + " | " + r["stderr"])[:400],
        }
    }


def check_listening() -> dict:
    r = _run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pPn"], timeout=20)
    listeners = []
    if r["ok"]:
        pid = None
        for line in r["stdout"].splitlines():
            if line.startswith("p"):
                pid = line[1:]
            elif line.startswith("n") and "LISTEN" in line:
                m = re.search(r":(\d+)", line)
                port = int(m.group(1)) if m else None
                if port:
                    listeners.append({"port": port, "pid": pid})
    # 去重（同端口多 pid 合并）
    by_port: dict[int, list[str]] = {}
    for l in listeners:
        by_port.setdefault(l["port"], []).append(l["pid"])
    # 进程名
    procs = {}
    for pid in {p for v in by_port.values() for p in v}:
        r2 = _run(["ps", "-p", pid, "-o", "comm=", "-n"], timeout=5)
        procs[pid] = r2["stdout"].strip().split("/")[-1] or pid
    out = []
    for port, pids in sorted(by_port.items()):
        out.append({
            "port": port,
            "pids": pids,
            "process": ", ".join({procs.get(p, "?") for p in pids}),
        })
    return {"listeners": out}


def check_logins() -> dict:
    items = {"login_items": [], "launchd_agents": []}
    r = _run(["osascript", "-e",
              'tell application "System Events" to get the name of every login item'], timeout=20)
    if r["ok"] and r["stdout"]:
        items["login_items"] = [s.strip() for s in r["stdout"].split(",") if s.strip()]
    r2 = _run(["launchctl", "list"], timeout=20)
    if r2["ok"]:
        lines = r2["stdout"].splitlines()[1:]
        services = []
        for line in lines:
            parts = line.split("\t")
            if len(parts) >= 3 and parts[2].startswith("com."):
                services.append(parts[2])
        items["launchd_agents"] = sorted(services)
    return items


def check_os() -> dict:
    r = _run(["sw_vers"])
    info = {}
    for line in r["stdout"].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    return {"platform": sys.platform, "macos": info.get("ProductVersion"), "build": info.get("BuildVersion")}


def run_system_check() -> dict:
    t0 = time.time()
    result = {"checks": {}, "elapse_s": 0}
    for name, fn in [
        ("os", check_os),
        ("sip", check_sip),
        ("firewall", check_firewall),
        ("autoupdate", check_autoupdate),
        ("filevault", check_filevault),
        ("backup", check_backup),
        ("listening", check_listening),
        ("logins", check_logins),
    ]:
        try:
            result["checks"][name] = fn()
        except Exception as e:  # 单项失败不影响整体
            result["checks"][name] = {"error": str(e)}
    result["elapse_s"] = round(time.time() - t0, 1)
    return result


if __name__ == "__main__":
    print(json.dumps(run_system_check(), ensure_ascii=False, indent=2))


# 允许 scanner.py 直接 import（同目录）
import os, sys as _s
if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(__file__))
