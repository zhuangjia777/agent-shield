"""统一 Finding Schema + 公式评分（比赛纪律：规则可算分，LLM 只解释）。

Risk = Impact(1-5) x Exploitability(1-5) x EvidenceConfidence(0.5|0.75|1.0) x Exposure(0.5|1.0|1.5)
  -> 原始分 0.125 .. 37.5
  -> 归一化 0-100（满分取 25 便于整除）
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Optional

# OWASP Agentic Top 10 (2026) 映射用常量
OWASP = {
    "A01": "A01 Prompt Injection / 指令劫持",
    "A02": "A02 Tool Misuse / 工具滥用与越权调用",
    "A03": "A03 Sensitive Data Exposure / 敏感信息泄露",
    "A04": "A04 Excessive Agency / 过度代理",
    "A05": "A05 Unsafe Code Execution / 危险代码执行",
    "A06": "A06 Supply Chain / 供应链",
    "A07": "A07 Trigger Abuse / 触发范围过宽",
    "A08": "A08 Memory & Context Poisoning",
    "A09": "A09 Insecure Output Handling",
    "A10": "A10 License & Documentation Gaps",
}

CONFIDENCE = {"inferred": 0.5, "static": 0.75, "dynamic": 1.0}


def risk_score(impact: int, exploitability: int, confidence: str, exposure: float) -> tuple[float, str]:
    """返回 (raw, level)。level: critical/high/medium/low/info"""
    raw = impact * exploitability * CONFIDENCE[confidence] * exposure
    pct = min(raw / 25.0 * 100.0, 100.0)
    if raw >= 20:
        level = "critical"
    elif raw >= 10:
        level = "high"
    elif raw >= 5:
        level = "medium"
    elif raw >= 2.5:
        level = "low"
    else:
        level = "info"
    return round(raw, 2), level


@dataclass
class Finding:
    id: str
    source: str                    # network | system | skill
    rule_id: str                   # 规则 ID，如 SK-KEY-LITERAL / SYS-FW-OFF / NET-SMB
    title: str
    owasp: str                     # e.g. "A03"
    nist: str                      # e.g. "PR.DS-1"（NIST AI RMF）
    impact: int = 3                # 1-5
    exploitability: int = 3        # 1-5
    confidence: str = "static"     # inferred | static | dynamic
    exposure: float = 1.0          # 0.5 | 1.0 | 1.5
    evidence: dict = field(default_factory=dict)   # {file, line, snippet} 或 {cmd, output_ref}
    repro: str = ""                # 可复现命令/步骤
    fix: str = ""
    explain: str = ""              # LLM 或模板白话解释
    retest_status: str = "open"    # open | fixed | n/a
    dynamic_evidence: Optional[dict] = None  # 沙箱轨迹引用

    def __post_init__(self):
        self.score, self.rule_level = risk_score(
            self.impact, self.exploitability, self.confidence, self.exposure
        )
        self.level = "medium" if self.rule_level in ("high", "critical") and not self.evidence else self.rule_level

    def to_dict(self) -> dict:
        d = asdict(self)
        d["risk"] = {
            "impact": self.impact,
            "exploitability": self.exploitability,
            "evidence_confidence": CONFIDENCE[self.confidence],
            "exposure": self.exposure,
            "raw_score": self.score,
            "normalized_100": min(self.score / 25 * 100, 100),
            "level": self.level,
        }
        # 证据纪律：high/critical 但 evidence 为空 -> 降级并标记
        if self.rule_level in ("high", "critical") and not self.evidence:
            d["evidence_gap"] = True
            d["risk"]["level"] = "medium"
            d["risk"]["evidence_note"] = "缺少证据，按纪律降为 medium"
        return d

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        d = dict(d)
        d.pop("risk", None)
        d.pop("evidence_gap", None)
        return Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})


def aggregate_score(findings: list[Finding]) -> int:
    """报告总分 0-100：从 100 起扣，critical-25 / high-12 / medium-5 / low-2。"""
    s = 100
    for f in findings:
        s -= {"critical": 25, "high": 12, "medium": 5, "low": 2, "info": 0}[f.level]
    return max(s, 0)


def to_json(findings: list[Finding], **meta) -> str:
    payload = {"findings": [f.to_dict() for f in findings], **meta}
    return json.dumps(payload, ensure_ascii=False, indent=2)
