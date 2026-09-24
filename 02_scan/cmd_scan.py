"""AgentShield 统一扫描入口。

用法:
    python 02_scan/cmd_scan.py --skill 06_samples/vulnerable-skill          # 只评 Skill
    python 02_scan/cmd_scan.py --lan --skill <dir> --out reports/<id>/results.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import time
import traceback
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "02_scan"))
sys.path.insert(0, str(ROOT / "05_skill_eval"))

from findings import Finding, aggregate_score  # noqa: E402
from skillcheck import check_skill, SkillBundle  # noqa: E402
from bundle_manifest import manifest as skill_manifest  # noqa: E402


def run_skill_eval(skill_dir: str) -> dict:
    bundle = SkillBundle(Path(skill_dir))
    manifest = skill_manifest(bundle.root)
    findings = check_skill(bundle)
    return {"findings": findings, "manifest": manifest}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skill", help="Skill 目录")
    ap.add_argument("--lan", action="store_true", help="扫描局域网")
    ap.add_argument("--sys", dest="do_sys", action="store_true", help="本机系统体检")
    ap.add_argument("--no-ai", action="store_true", help="跳过 AI 层（纯规则）")
    ap.add_argument("--out", help="结果 JSON 输出路径")
    args = ap.parse_args()

    if not any([args.skill, args.lan, args.do_sys]):
        ap.error("至少给一个: --skill / --lan / --sys")

    t0 = time.time()
    result: dict = {
        "report_id": time.strftime("%Y%m%d-%H%M%S"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
        "env": {
            "python": sys.version.split()[0],
            "offline": True,  # 核心规则层不联网（LLM 层可选）
        },
    }

    all_findings: list[Finding] = []

    if args.skill:
        se = run_skill_eval(args.skill)
        all_findings += se["findings"]
        result["skill"] = {
            "manifest": se["manifest"],
            "findings": [f.to_dict() for f in se["findings"]],
        }

    if args.lan or args.do_sys:
        from scanner import run_network_scan
        from systemcheck import run_system_check
        if args.lan:
            net = run_network_scan(lan=True)
            result["network"] = net
        if args.do_sys:
            result["system"] = run_system_check()
        all_findings += _system_findings(result.get("system", {}))
        all_findings += _network_findings(result.get("network", {}))

    result["findings"] = [f.to_dict() for f in all_findings]
    result["score"] = aggregate_score(all_findings)
    result["total_elapse_s"] = round(time.time() - t0, 1)

    payload = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(payload)
        hi = [f for f in all_findings if f.level in ("high", "critical")]
        print(f"score={result['score']}  findings={len(all_findings)} (high+={len(hi)})  "
              f"→ {args.out}  ({result['total_elapse_s']}s)")
    else:
        print(payload)


def _system_findings(sysinfo: dict) -> list[Finding]:
    f = []
    c = sysinfo.get("checks", {})
    if c.get("firewall", {}).get("enabled") is False:
        f.append(Finding(id="SYS-001", source="system", rule_id="SYS-FW-OFF",
                         title="系统防火墙未开启", owasp="A04", nist="PR.IP-1",
                         impact=3, exploitability=3, confidence="static", exposure=1.0,
                         evidence={"cmd": "defaults read com.apple.alf globalstate",
                                   "output_ref": c["firewall"].get("raw", "")[:80]},
                         fix="系统设置 → 网络 → 防火墙 → 打开。"))
    if c.get("filevault", {}).get("enabled") is False:
        f.append(Finding(id="SYS-002", source="system", rule_id="SYS-FV-OFF",
                         title="FileVault 磁盘加密未开启", owasp="A03", nist="PR.DS-4",
                         impact=4, exploitability=2, confidence="static", exposure=1.0,
                         evidence={"cmd": "fdesetup status",
                                   "output_ref": c["filevault"].get("raw", "")[:80]},
                         fix="系统设置 → 隐私与安全性 → FileVault → 打开。"))
    if c.get("autoupdate", {}).get("enabled") is False:
        f.append(Finding(id="SYS-003", source="system", rule_id="SYS-AU-OFF",
                         title="系统自动更新未开启", owasp="A06", nist="PR.AT-2",
                         impact=3, exploitability=2, confidence="static", exposure=1.0,
                         evidence={"cmd": "softwareupdate --schedule",
                                   "output_ref": c["autoupdate"].get("raw", "")[:80]},
                         fix="系统设置 → 通用 → 软件更新 → 自动更新打开。"))
    return f


def _network_findings(net: dict) -> list[Finding]:
    f = []
    gw_meta = {}
    for h in net.get("hosts", []):
        if h.get("is_self"):
            continue
        for p in h.get("ports", []):
            if p.get("state") != "open":
                continue
            port = p["port"]
            svc = f"{p.get('service') or ''}{(' ' + p.get('version')) if p.get('version') else ''}".strip()
            if port in (3389, 5900, 5984):
                f.append(Finding(id=f"NET-{h['ip'].replace('.','-')}-{port}", source="network",
                                 rule_id="NET-REMOTE-DESKTOP",
                                 title=f"{h['ip']} 开放远程桌面 {port}/{svc}",
                                 owasp="A02", nist="PR.AC-1",
                                 impact=5, exploitability=3, confidence="static", exposure=1.5,
                                 evidence={"cmd": f"nmap -p {port} {h['ip']}",
                                           "output_ref": f"port {port} open ({svc})"},
                                 fix="关闭远程桌面，或 VPN 内 + 强密码。"))
            elif port in (139, 445):
                f.append(Finding(id=f"NET-{h['ip'].replace('.','-')}-{port}", source="network",
                                 rule_id="NET-SMB",
                                 title=f"{h['ip']} 开放 SMB {port}/{svc}",
                                 owasp="A03", nist="PR.DS-1",
                                 impact=3, exploitability=2, confidence="static", exposure=1.5,
                                 evidence={"cmd": f"nmap -p {port} {h['ip']}",
                                           "output_ref": f"port {port} open ({svc})"},
                                 fix="不需要共享就关闭；开了就禁 guest。"))
            elif port in (23, 21):
                f.append(Finding(id=f"NET-{h['ip'].replace('.','-')}-{port}", source="network",
                                 rule_id="NET-PLAINTEXT",
                                 title=f"{h['ip']} 明文协议 {port}/{svc}",
                                 owasp="A03", nist="PR.DS-1",
                                 impact=3, exploitability=2, confidence="static", exposure=1.0,
                                 evidence={"cmd": f"nmap -p {port} {h['ip']}",
                                           "output_ref": f"port {port} open ({svc})"},
                                 fix="换加密协议（SSH/SFTP）。"))
    return f


if __name__ == "__main__":
    main()
