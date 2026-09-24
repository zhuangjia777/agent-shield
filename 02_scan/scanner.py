"""网络扫描：存活发现 + 端口扫描。确定性引擎，不依赖 AI。

用法:
    .venv/bin/python 02_scan/scanner.py --lan --out /tmp/scan_result.json
"""
from __future__ import annotations

import argparse
import json
import shutil
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_TIMEOUT_S = 90


def _run(cmd: list[str], timeout: int = 60) -> dict:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"stdout": p.stdout, "stderr": p.stderr, "exit": p.returncode}
    except FileNotFoundError:
        return {"stdout": "", "stderr": f"missing: {cmd[0]}", "exit": 127}
    except subprocess.TimeoutExpired:
        return {"stdout": "", "stderr": "timeout", "exit": 124}


def find_active_interface() -> dict:
    """找有 IPv4 的接口，返回 {iface, ip, subnet}。"""
    for iface in ("en1", "en0", "en2", "en3", "en4", "en5"):
        out = _run(["ipconfig", "getifaddr", iface], timeout=5)
        ip = out["stdout"].strip()
        if ip:
            octets = ip.split(".")
            subnet = f".{octets[0]}.{octets[1]}.{octets[2]}."
            route = _run(["netstat", "-rn"], timeout=5)
            gw = ""
            for line in route["stdout"].splitlines():
                if line.startswith("default"):
                    gw = line.split()[1]
                    break
            return {"iface": iface, "ip": ip, "subnet": subnet, "gateway": gw}
    return {"iface": None, "ip": None, "subnet": None, "gateway": None, "error": "no IPv4 interface"}


def ping_sweep(ip_list: list[str], workers: int = 40) -> list[str]:
    """ICMP ping sweep。优先 scapy（可用时更快且不打扰路由器），回退系统 ping。"""
    def check(ip: str) -> bool:
        try:
            from scapy.all import Ether, ICMP, IP, sr1
            pkt = Ether() / IP(dst=ip) / ICMP()
            resp = sr1(pkt, timeout=0.4, verbose=0)
            return resp is not None
        except Exception:
            out = _run(["ping", "-c", "1", "-W", "400", ip], timeout=3)
            return out["exit"] == 0 and "1 packets received" in out["stdout"]

    alive = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check, ip): ip for ip in ip_list}
        for f in as_completed(futs):
            if f.result():
                alive.append(futs[f])
    alive.sort(key=lambda s: int(s.rsplit(".", 1)[1]))
    return alive


def tcp_probe(ip: str, port: int, timeout: float = 0.4) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


TOP_PORTS = [
    22, 25, 53, 80, 111, 135, 139, 143, 389, 443, 445, 465, 587, 631,
    873, 993, 1433, 1521, 3306, 3389, 5432, 5900, 5984, 5985, 5986,
    6379, 8080, 8443, 8888, 9100, 9200, 11211, 27017,
    8008, 8009, 14001, 5000, 9090,
]

# 高危端口：标签直接标注给 AI 看
HIGH_RISK = {
    139: "SMB 文件共享（guest 可进则风险高）",
    445: "SMB 文件共享",
    135: "RPC 远程过程调用",
    3389: "RDP 远程桌面",
    5985: "WinRM 远程管理 HTTP",
    5986: "WinRM 远程管理 HTTPS",
    23: "Telnet（明文）",
    21: "FTP（明文）",
    25: "SMTP（注意匿名收件）",
    5900: "VNC 远程控制",
    631: "CUPS 打印服务",
}


def nmap_scan(ip: str) -> list[dict]:
    nmap = shutil.which("nmap") or "/opt/homebrew/bin/nmap"
    out = _run(
        [nmap, "-sT", "-p", ",".join(map(str, TOP_PORTS)), "--open", "-oX", "-", ip],
        timeout=45,
    )
    return parse_nmap_xml(out["stdout"])


def parse_nmap_xml(xml: str) -> list[dict]:
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return []
    ports = []
    for port_el in root.iter("port"):
        ports.append({
            "port": int(port_el.get("portid")),
            "state": port_el.findtext("state/state"),
            "service": (port_el.find("service") or {}).get("name", ""),
            "product": (port_el.find("service") or {}).get("product", ""),
            "version": (port_el.find("service") or {}).get("version", ""),
        })
    return ports


def scan_host(ip: str, iface_ip: str) -> dict:
    result = {"ip": ip, "is_gateway_guess": False, "is_self": ip == iface_ip, "ports": []}
    nmap = shutil.which("nmap") or "/opt/homebrew/bin/nmap"
    if Path(nmap).exists():
        result["ports"] = nmap_scan(ip)
    else:
        # 回退：纯 Python TCP 探测
        with ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(tcp_probe, ip, p): p for p in TOP_PORTS}
            for f in as_completed(futs):
                if f.result():
                    result["ports"].append({"port": futs[f], "state": "open", "service": ""})
    for p in result["ports"]:
        if p["port"] in HIGH_RISK:
            p["risk_note"] = HIGH_RISK[p["port"]]
    return result


def run_network_scan(lan: bool = True) -> dict:
    started = time.time()
    meta = find_active_interface()
    report = {"meta": meta, "hosts": [], "elapse_s": 0}
    if not meta.get("ip"):
        report["error"] = "no active IPv4 interface"
        report["elapse_s"] = round(time.time() - started, 1)
        return report

    report["gateway"] = meta["gateway"]
    hosts: dict[str, dict] = {}
    hosts[meta["ip"]] = None  # self 占位

    if lan and meta["subnet"]:
        second, third = meta["subnet"].strip(".").split(".")[1:]
        candidates = [f"{second}.{third}.{i}" for i in range(1, 255)]
        if meta["ip"] not in candidates:
            candidates.append(meta["ip"])
        report["meta"]["scan_range"] = f"{second}.{third}.1-254"
        alive = ping_sweep(candidates)
        report["alive_count"] = len(alive)
    else:
        alive = [meta["ip"]]

    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(scan_host, ip, meta["ip"]): ip for ip in alive}
        for f in as_completed(futs):
            h = f.result()
            if h["ip"] == meta.get("gateway"):
                h["is_gateway_guess"] = True
            hosts[h["ip"]] = h

    # 排序: 网关 > 自己 > 其他
    def _host_key(h):
        cat = 0 if h.get("is_gateway_guess") else (1 if h.get("is_self") else 2)
        return (cat, int(h["ip"].rsplit(".", 1)[1]))

    report["hosts"] = sorted(
        [h or {"ip": ip, "is_self": True, "ports": [], "note": "self, not scanned"}
         for ip, h in hosts.items()],
        key=_host_key,
    )
    report["elapse_s"] = round(time.time() - started, 1)
    return report


def main() -> None:
    ap = argparse.ArgumentParser(description="AgentShield 网络扫描")
    ap.add_argument("--lan", action="store_true", help="扫描局域网（默认关）")
    ap.add_argument("--out", help="输出 JSON 路径（默认 stdout）")
    args = ap.parse_args()

    t0 = time.time()
    net = run_network_scan(lan=args.lan)
    from systemcheck import run_system_check

    sysinfo = run_system_check()
    full = {
        "report_id": time.strftime("%Y%m%d-%H%M%S"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "network": net,
        "system": sysinfo,
        "total_elapse_s": round(time.time() - t0, 1),
    }
    payload = json.dumps(full, ensure_ascii=False, indent=2, default=str)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(payload)
        print(f"wrote {args.out} ({full['total_elapse_s']}s)")
    else:
        print(payload)


if __name__ == "__main__":
    main()
