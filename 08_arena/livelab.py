"""实战演练场（Live Arena）：Docker 隔离网络内的真实红蓝对抗。

架构：
  aslab-net (internal, 禁止出网)  ← 红队容器( Kali 工具链 ) + 靶机容器
  aslab-lan (普通 bridge)         ← 靶机第二网卡，仅供宿裁判探针/宿主浏览器访问
    （--internal 网络不能 publish 端口，所以靶机双网卡；红队不在 aslab-lan 上）

安全硬约束（违反即拒绝启动，不静默降级）：
  1. 红队容器必须无外网：启动后实测 /dev/tcp 探测，能连通互联网就整体拆毁并报错
  2. 红队容器 --cap-drop ALL --security-opt no-new-privileges --read-only --memory/--cpus/--pids-limit
  3. 攻击目标只允许 aslab-net 内的靶机主机名；exec 层拒绝任何外部地址
  4. 全部命令与输出落盘 logs/arena_live/，stop 一键销毁容器与网络

依赖：本机 Docker（macOS OrbStack/Docker Desktop 均可），无需安装 Kali 系统。
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LOGDIR = ROOT / "logs" / "arena_live"

NET_ISOLATED = "aslab-net"
NET_LAN = "aslab-lan"
SUBNET_ISOLATED = "172.28.99.0/24"
SUBNET_LAN = "172.28.98.0/24"
TARGET_NAME = "aslab-target"
RED_NAME = "aslab-red"
BLUE_NAME = "aslab-blue"
TARGET_IMG = "bkimminich/juice-shop:latest"
RED_IMG = "aslab-red-tools:2"
BLUE_IMG = "python:3.12-alpine"
RED_DOCKERFILE_DIR = Path(__file__).resolve().parent / "red_image"
WAF_SCRIPT = Path(__file__).resolve().parent / "waf.py"
WAF_MODE_FILE = LOGDIR / "waf_mode.json"
HOST_PORT = 3999          # 127.0.0.1:3999 → 靶机:3000（裁判探针），只绑回环
WAF_HOST_PORT = 3998      # 127.0.0.1:3998 → WAF:8080（人浏览器体验攻防）
TARGET_HTTP = "http://127.0.0.1:3999"
WAF_HTTP = "http://127.0.0.1:3998"
RED_ENTRY = "http://aslab-blue:8080"   # 红队唯一的合法入口（WAF 后面才是靶机）

# 红队 exec 只允许打 WAF 主机名——绕过 WAF 直打靶机一律拒绝，蓝队开关才有意义
ALLOWED_TARGETS = (BLUE_NAME,)


def _sh(args: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, ((p.stdout or "") + (p.stderr or "")).strip()
    except FileNotFoundError:
        return 127, "docker 不可用：请先安装并启动 Docker"
    except subprocess.TimeoutExpired:
        return 124, f"docker 命令超时({timeout}s)"


def _log(entry: dict):
    LOGDIR.mkdir(parents=True, exist_ok=True)
    with open(LOGDIR / "events.jsonl", "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def status() -> dict:
    code, out = _sh(["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}",
                     "--filter", f"name={TARGET_NAME}", "--filter", f"name={RED_NAME}",
                     "--filter", f"name={BLUE_NAME}"])
    containers = {}
    for line in out.splitlines():
        if "\t" in line:
            n, s = line.split("\t", 1)
            containers[n] = s
    running = (containers.get(TARGET_NAME, "").startswith("Up") and
               containers.get(RED_NAME, "").startswith("Up") and
               containers.get(BLUE_NAME, "").startswith("Up"))
    return {"docker_ok": code == 0, "containers": containers, "running": running,
            "waf": waf_get().get("waf") if running else None,
            "target_url": TARGET_HTTP, "waf_url": WAF_HTTP}


def _isolation_check() -> tuple[bool, str]:
    """实测红队容器是否真上不了网。任何一条探测成功 = 隔离失效 = 失败。"""
    probes = [
        f"exec 3<>/dev/tcp/1.1.1.1/443 && echo LEAK",
        f"getent hosts example.com && echo DNS-LEAK",
    ]
    for cmd in probes:
        code, out = _sh(["docker", "exec", RED_NAME, "bash", "-c", cmd], timeout=15)
        if code == 0 and "LEAK" in out:
            return False, f"隔离探测失败: {cmd} -> {out[:80]}"
    return True, "红队容器无外网(实测)"


def start() -> dict:
    """拉起整套演练场；任何安全校验不过 → 拆毁回滚并报错。"""
    st = status()
    if st["running"]:
        return {"ok": True, "msg": "演练场已在运行", **st}

    code, out = _sh(["docker", "info", "-f", "{{.ServerVersion}}"], timeout=15)
    if code != 0:
        return {"ok": False, "msg": f"Docker 未就绪: {out[:120]}"}

    _sh(["docker", "network", "create", "--internal", "--subnet", SUBNET_ISOLATED, NET_ISOLATED])
    _sh(["docker", "network", "create", "--subnet", SUBNET_LAN, NET_LAN])

    # 攻击机镜像：没构建过就先构建（Kali + nmap/curl/sqlite3）
    code, _ = _sh(["docker", "image", "inspect", RED_IMG], timeout=15)
    if code != 0:
        RED_DOCKERFILE_DIR.mkdir(exist_ok=True)
        (RED_DOCKERFILE_DIR / "Dockerfile").write_text(
            "FROM kalilinux/kali-rolling:latest\n"
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "nmap curl sqlite3 whois sqlmap && rm -rf /var/lib/apt/lists/*\n")
        code, out = _sh(["docker", "build", "-q", "-t", RED_IMG, str(RED_DOCKERFILE_DIR)], timeout=900)
        if code != 0:
            return {"ok": False, "msg": f"攻击机镜像构建失败: {out[-200:]}"}

    # 靶机只在 aslab-lan（不接隔离网）：红队在物理上只能打到 WAF(aslab-blue)，
    # WAF 从 lan 转发给靶机。网络层强制攻防路径，exec 白名单只是第二道防线。
    _sh(["docker", "rm", "-f", TARGET_NAME])
    code, out = _sh(["docker", "run", "-d", "--name", TARGET_NAME,
                     "--network", NET_LAN, "-p", f"127.0.0.1:{HOST_PORT}:3000",
                     "--memory", "1g", "--cpus", "2", TARGET_IMG])
    if code != 0:
        return {"ok": False, "msg": f"靶机启动失败: {out[-200:]}"}

    # 蓝队 WAF：同样双网卡（lan 供人浏览器 3998，internal 供红队打）。默认 block 档。
    WAF_MODE_FILE.parent.mkdir(parents=True, exist_ok=True)
    WAF_MODE_FILE.write_text('{"mode": "block"}')
    _sh(["docker", "rm", "-f", BLUE_NAME])
    code, out = _sh(["docker", "run", "-d", "--name", BLUE_NAME,
                     "--network", NET_LAN, "-p", f"127.0.0.1:{WAF_HOST_PORT}:8080",
                     "-v", f"{WAF_SCRIPT}:/waf/waf.py:ro",
                     "-v", f"{WAF_MODE_FILE}:/waf/mode.json:ro",
                     "--memory", "256m", "--cpus", "1", "--read-only",
                     "--tmpfs", "/tmp:rw,size=64m",
                     BLUE_IMG, "python", "/waf/waf.py"])
    if code != 0:
        stop()
        return {"ok": False, "msg": f"蓝队 WAF 启动失败: {out[-200:]}"}
    code, out = _sh(["docker", "network", "connect", NET_ISOLATED, BLUE_NAME])
    if code != 0:
        stop()
        return {"ok": False, "msg": f"WAF 接入隔离网失败: {out[-200:]}"}

    _sh(["docker", "rm", "-f", RED_NAME])
    code, out = _sh(["docker", "run", "-d", "--name", RED_NAME,
                     "--network", NET_ISOLATED,
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                     "--memory", "1g", "--cpus", "2", "--pids-limit", "256",
                     "--read-only", "--tmpfs", "/tmp:rw,size=256m",
                     RED_IMG, "sleep", "infinity"])
    if code != 0:
        stop()
        return {"ok": False, "msg": f"攻击机启动失败: {out[-200:]}"}

    # 等靶机 HTTP 就绪（宿主侧轮询，最多 60s）
    ready = False
    for _ in range(30):
        code, out = _sh(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "4",
                         TARGET_HTTP + "/api/Challenges"], timeout=20)
        if out.startswith("2"):
            ready = True
            break
        time.sleep(2)
    if not ready:
        stop()
        return {"ok": False, "msg": f"靶机在 {TARGET_HTTP} 60s 内未就绪"}

    # 拓扑校验：红队必须能打通 WAF；必须打不通靶机 3000（只能经 WAF）
    code, _ = _sh(["docker", "exec", RED_NAME, "bash", "-c",
                   f"exec 3<>/dev/tcp/{BLUE_NAME}/8080 && echo ok"], timeout=15)
    if code != 0:
        stop()
        return {"ok": False, "msg": "红队容器无法连通 WAF，网络配置异常"}
    code, out = _sh(["docker", "exec", RED_NAME, "bash", "-c",
                     f"exec 3<>/dev/tcp/{TARGET_NAME}/3000 2>/dev/null && echo LEAK || echo blocked"], timeout=15)
    if "LEAK" in out:
        stop()
        return {"ok": False, "msg": "红队可直连靶机（绕过 WAF），拓扑异常，已回滚"}

    # 隔离实测（不过就拆）
    iso_ok, iso_msg = _isolation_check()
    if not iso_ok:
        stop()
        return {"ok": False, "msg": f"外网隔离校验失败，已回滚。{iso_msg}"}

    _log({"at": time.strftime("%F %T"), "evt": "lab_start", "iso": iso_msg})
    return {"ok": True, "msg": f"演练场就绪：攻击入口 {RED_ENTRY}（经 WAF），人视角 http://127.0.0.1:{WAF_HOST_PORT}，{iso_msg}，WAF=block",
            "target_url": TARGET_HTTP, "waf_url": WAF_HTTP, "red": RED_NAME, "blue": BLUE_NAME,
            "target": TARGET_NAME, "waf": "block"}


def waf_set(mode: str) -> dict:
    """蓝队开关：block=启用防护，bypass=关掉防护（红队直通靶机）。"""
    if mode not in ("block", "bypass"):
        return {"ok": False, "msg": "mode 只能是 block 或 bypass"}
    if not WAF_MODE_FILE.parent.exists():
        return {"ok": False, "msg": "演练场未启动"}
    WAF_MODE_FILE.write_text(json.dumps({"mode": mode}))
    _log({"at": time.strftime("%F %T"), "evt": "waf", "mode": mode})
    return {"ok": True, "msg": f"WAF 已切换为 {mode}（下一发请求即生效）", "waf": mode}


def waf_get() -> dict:
    try:
        return {"ok": True, "waf": json.loads(WAF_MODE_FILE.read_text()).get("mode", "block")}
    except Exception:
        return {"ok": False, "waf": None}


def stop() -> dict:
    _sh(["docker", "rm", "-f", RED_NAME, BLUE_NAME, TARGET_NAME], timeout=30)
    _sh(["docker", "network", "rm", NET_ISOLATED, NET_LAN], timeout=15)
    _log({"at": time.strftime("%F %T"), "evt": "lab_stop"})
    return {"ok": True, "msg": "演练场已销毁"}


def red_exec(cmd: str) -> dict:
    """在红队容器内执行一条命令。只允许打白名单靶机；全量落盘。"""
    cmd = cmd.strip()
    if not cmd:
        return {"ok": False, "msg": "空命令"}
    # 目标白名单：出现的 URL/主机必须是靶机或本机回环（容器内），禁止任意外部主机
    hosts = set(re.findall(r"(?:https?://|/dev/tcp/)([A-Za-z0-9_.\-]+)", cmd))
    hosts |= set(re.findall(r"\b(?:nmap|curl|wget|sqlmap|hydra|nc|ncat)\b[^|;&]*?\s+([a-zA-Z0-9][\w.\-]*\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})", cmd))
    external = [h for h in hosts if h not in ALLOWED_TARGETS and not h.startswith(("localhost", "127.", "::1"))]
    if external:
        return {"ok": False, "msg": f"目标白名单外，拒绝执行: {external}（红队只允许打 {BLUE_NAME}:8080，攻防必须过 WAF）"}
    if re.search(r"\bsudo\b", cmd):
        return {"ok": False, "msg": "容器内也不允许 sudo"}
    st = status()
    if not st["running"]:
        return {"ok": False, "msg": "演练场未启动，先 start"}
    t0 = time.time()
    code, out = _sh(["docker", "exec", RED_NAME, "bash", "-c", cmd], timeout=120)
    _log({"at": time.strftime("%F %T"), "evt": "red_exec", "cmd": cmd,
          "exit": code, "out": out[:2000], "secs": round(time.time() - t0, 1)})
    return {"ok": code == 0, "exit": code, "out": out[:4000]}


def judge_http(path: str = "/api/Challenges") -> dict:
    """宿裁判探针：真实 HTTP 读取靶机状态（挑战进度等），不经过模型自评。"""
    code, out = _sh(["curl", "-s", "-m", "8", f"{TARGET_HTTP}{path}"], timeout=20)
    if code != 0:
        return {"ok": False, "msg": f"探针失败: {out[:100]}"}
    try:
        d = json.loads(out)
        if isinstance(d, dict) and "data" in d:
            done = [c["key"] for c in d["data"] if c.get("solved")]
            return {"ok": True, "solved": done, "total": len(d["data"])}
        return {"ok": True, "raw": out[:400]}
    except Exception:
        return {"ok": True, "raw": out[:400]}


if __name__ == "__main__":
    import sys
    fn = sys.argv[1] if len(sys.argv) > 1 else "status"
    if fn == "waf":
        print(json.dumps(waf_set(sys.argv[2]), ensure_ascii=False, indent=1))
    else:
        print(json.dumps({"start": start, "stop": stop, "status": status,
                          "judge": judge_http}.get(fn, status)(), ensure_ascii=False, indent=1))
