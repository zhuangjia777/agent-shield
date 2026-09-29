#!/usr/bin/env python3
"""跑全部静态评测，对照 expected_findings / evals.json，输出 BENCHMARK 数字。"""
import json, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "02_scan")); sys.path.insert(0, str(ROOT / "05_skill_eval"))
from skillcheck import check_skill, SkillBundle


def run(name):
    t0 = time.time()
    fs = check_skill(SkillBundle(ROOT / "06_samples" / name))
    return fs, time.time() - t0


exp = json.loads((ROOT / "07_evals" / "expected_findings.json").read_text())
vuln, t_v = run("vulnerable-skill")
got = {f.rule_id for f in vuln}
need = set(exp["vulnerable-skill"]["mapping"].values())
det = len(need & got)
n_high_v = sum(1 for f in vuln if f.level in ("high", "critical"))
hard, t_h = run("hardened-skill")
ben, t_b = run("benign-skill")
n_high_h = sum(1 for f in hard if f.level in ("high", "critical"))
n_high_b = sum(1 for f in ben if f.level in ("high", "critical"))
evi = all(f.evidence for f in vuln if f.level in ("high", "critical"))

high = []
print(f"检出率 {det}/5 = {round(100 * det / 5)}%   (目标 >=80%)")
high.append(det >= 4)
print(f"高危证据覆盖率 {'100%' if evi else 'FAIL'}   (目标 100%)")
high.append(evi)
print(f"benign 高危误报 {n_high_b}   (目标 0)")
high.append(n_high_b == 0)
print(f"hardened 高危误报 {n_high_h}   (目标 0)")
high.append(n_high_h == 0)
print(f"耗时 vulnerable={t_v:.3f}s hardened={t_h:.3f}s benign={t_b:.3f}s   (目标 <=5min)")
print(f"vulnerable findings 总数 {len(vuln)}  high+ {n_high_v}")
ops, t_o = run("ops-agent-skill")
ops_rules = {f.rule_id for f in ops}
n_high_o = sum(1 for f in ops if f.level in ("high", "critical"))
ops_ok = "SK-INSTR-TRUST" in ops_rules and n_high_o >= 1
print(f"ops-agent-skill 指令注入面检出 {'PASS' if 'SK-INSTR-TRUST' in ops_rules else 'FAIL'}   高危 {n_high_o}（目标 >=1）")
high.append(ops_ok)
ok = all(high)
print("BENCHMARK static gate:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
