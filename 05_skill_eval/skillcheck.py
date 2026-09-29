"""Agent Skill 静态评估器（规则优先，比赛要求：证据先于结论）。

输入：一个 Skill 目录（含 SKILL.md + scripts/ 等）。
输出：list[Finding]，每条带 rule_id / evidence(file,line,snippet) / OWASP+NIST 映射。

检查规则（v1）:
  SK-KEY-LITERAL    源码/配置中的明文密钥样 pattern（高置信：动态验证留给 Day5）
  SK-SHELL-DANGER   危险 shell：rm -rf $Var / eval / curl|sh / 写系统目录
  SK-UNICODE        隐藏 Unicode（零宽字符、双向控制符）
  SK-NET-EXFIL      网络外传调用（urllib/requests/socket.post / curl POST 出网）
  SK-PATH-TRAVER    路径拼接未 sanitize（用户输入字符串直接进入 open()）
  SK-OVERBROAD-TRIG description 触发词过宽（todo/报告/任意 等泛词占比高）
  SK-DOMAIN-MISS    SKILL.md 描述的能力 vs 脚本实际行为声明不一致（粗检：声明无 but 有 net/file 写）
  SK-NOLICENSE      缺 LICENSE
  SK-NODOC          缺 LICENSE / Owner 字段等 Skill Card 要素
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from findings import Finding, OWASP

KEY_PATTERNS = [
    ("OPENAI_API_KEY", r"OPENAI_API_KEY\s*=\s*[\"'][A-Za-z0-9_\-]{16,}[\"']", 0),
    ("api_key", r"api[_-]?key\s*=\s*[\"'][a-z0-9]{20,}[\"']", re.I),
    ("token-prefix", r"\b(sk|pk|ghp|xox[bap])-[A-Za-z0-9-]{16,}", 0),
    ("password", r"password\s*=\s*[\"'][^\"'\s]{8,}[\"']", re.I),
    ("JWT", r"AQAA[A-Za-z0-9+/=]{20,}", 0),
]

SHELL_DANGER = [
    (r"rm\s+-[rf]+\s+\$?", "rm -rf 带变量/递归"),
    (r"\beval\b", "eval 动态执行"),
    (r"curl\s+[^\n|]*\|\s*(ba|z)?sh", "curl 管道进 shell（供应链）"),
    (r"wget\s+[^\n|]*\|\s*(ba|z)?sh", "wget 管道进 shell（供应链）"),
    (r"(>|\btee\s+)\s*/usr/(local/)?(bin|etc)/", "写系统目录"),
    (r"chmod\s+\+x", "自加执行位"),
]

NET_PATTERNS = [
    (r"\brequests\.(post|put|patch)\s*\(", "requests 写出网调用", "active"),
    (r"\burllib\.request\.(urlopen|Request)\s*\(", "urllib 出网调用", "active"),
    (r"\bsocket\.(socket|create_connection)\s*\(", "socket 直连", "active"),
    (r"\bhttp\.client\.(\w*)?(HTTPConnection|HTTPSConnection)", "http.client 连接", "active"),
    (r"\bcurl\s+(-X\s*(POST|PUT)|--data|-d)\b", "curl POST（可能外传）", "active"),
    (r"\bwebbrowser\.open|aiohttp\.(get|post)", "web/aiohttp 出网", "active"),
]
# 硬编码公网 URL：仅当行内含访问动词时才报（排除 XML namespace 等静态 URL）
NAMESPACE_DOMAINS = (
    "schemas.", "w3.org", "oasis-open.org", "xmlsoap.org", "purl.org",
    "java.sun.com", "apache.org/xml", "opendata.net", "example.com",
)
URL_CONTEXT = re.compile(
    r"\b(urlopen|open|Request|get|fetch|download|post|read)\s*\(.*http://(?!127|localhost|0\.0\.0\.0)"
)

HIDDEN_UNICODE = [
    (re.compile(r"[\u200B-\u200F\u202A-\u202E\uFEFF]"), "零宽/双向控制字符"),
    (re.compile(r"[\u00AD]"), "软连字符"),
]

CODE_EXTS = {".py", ".sh", ".js", ".ts", ".rb", ".pl", ".php"}


@dataclass
class SkillBundle:
    root: Path

    @property
    def skill_md(self) -> Path:
        return self.root / "SKILL.md"

    def code_files(self) -> list[Path]:
        out = []
        for p in self.root.rglob("*"):
            if p.is_file() and p.suffix in CODE_EXTS and ".git" not in p.parts:
                out.append(p)
        # 非代码配置也看密钥
        for name in ("config.yaml", "config.json", ".env", "policy.yaml", "evals.json"):
            p = self.root / name
            if p.exists():
                out.append(p)
        return out


def _heuristic_read_input(arg_chain: str) -> bool:
    """粗糙：是否读用户输入（open(...input...), sys.argv, 参数名带 query/user/input/text/data）。"""
    return bool(re.search(r")(sys\.argv|input\(|args\.|user_?input|query|message|content)", arg_chain))


def check_skill(bundle: SkillBundle) -> list[Finding]:
    f: list[Finding] = []
    sid = 0

    def add(**kw):
        nonlocal sid
        kw.setdefault("source", "skill")
        kw["id"] = kw.get("id") or f"SK-{sid:03d}"
        sid += 1
        finding = Finding(**kw)
        if kw.get("confidence", "static") == "inferred":
            pass
        f.append(finding)
        return finding

    skill_md_text = bundle.skill_md.read_text(encoding="utf-8", errors="replace") \
        if bundle.skill_md.exists() else ""

    for path in bundle.code_files():
        rel = f"skill:{path.relative_to(bundle.root)}"
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        lines = text.splitlines()

        # --- 密钥 ---
        for i, line in enumerate(lines, 1):
            for entry in KEY_PATTERNS:
                name, pat = entry[0], entry[1]
                flags = entry[2] if len(entry) > 2 else 0
                m = re.search(pat, line, flags)
                if m and "honey" not in line.lower() and "example" not in line.lower():
                    add(
                        rule_id="SK-KEY-LITERAL",
                        title=f"疑似明文密钥: {name}",
                        owasp="A03", nist="PR.DS-1",
                        impact=5, exploitability=3, confidence="static", exposure=1.0,
                        evidence={"file": rel, "line": i, "snippet": line.strip()[:120]},
                        repro=f"grep -n '{name}' {rel}",
                        fix="移到环境变量或 Secret Manager；提交前用 secret-scanner 扫。",
                    )

        # --- 危险 shell ---
        for i, line in enumerate(lines, 1):
            for pat, desc in SHELL_DANGER:
                if re.search(pat, line):
                    add(
                        rule_id="SK-SHELL-DANGER",
                        title=f"危险 shell 模式: {desc}",
                        owasp="A05", nist="PR.AT-3",
                        impact=4, exploitability=3, confidence="static", exposure=1.0,
                        evidence={"file": rel, "line": i, "snippet": line.strip()[:120]},
                        repro=f"sed -n '{i}p' {rel}",
                        fix="固定路径、加 --dry-run、或移到显式 --confirm 后才执行。",
                    )
                    break  # 同规则同文件只报第一处，避免刷分

        # --- 隐藏 Unicode ---
        for i, line in enumerate(lines, 1):
            for rx, desc in HIDDEN_UNICODE:
                m = rx.search(line)
                if m:
                    add(
                        rule_id="SK-UNICODE",
                        title=f"隐藏 Unicode: {desc}（可能藏指令）",
                        owasp="A01", nist="PR.DS-3",
                        impact=3, exploitability=2, confidence="static", exposure=1.0,
                        evidence={"file": rel, "line": i,
                                  "snippet": line.strip()[:120] + f" [U+{ord(m.group()):04X}]"},
                        fix="从 file 里删掉；查 git diff 定位引入提交。",
                    )
                    break

        # --- 网络外传 ---
        for i, line in enumerate(lines, 1):
            for entry in NET_PATTERNS:
                pat, desc = entry[0], entry[1]
                if re.search(pat, line):
                    add(
                        rule_id="SK-NET-EXFIL",
                        title=f"网络外传调用: {desc}",
                        owasp="A03", nist="PR.DS-1",
                        impact=4, exploitability=2, confidence="static", exposure=1.0,
                        evidence={"file": rel, "line": i, "snippet": line.strip()[:120]},
                        fix="本地处理优先；必须出网时白名单域名并日志记录。",
                    )
                    break
            else:
                m = URL_CONTEXT.search(line)
                if m and not any(d in m.group(0) for d in NAMESPACE_DOMAINS):
                    add(
                        rule_id="SK-NET-EXFIL",
                        title="硬编码公网 URL 被访问",
                        owasp="A03", nist="PR.DS-1",
                        impact=3, exploitability=2, confidence="static", exposure=1.0,
                        evidence={"file": rel, "line": i, "snippet": line.strip()[:120]},
                        fix="改 https、白名单域名、记录日志。",
                    )

        # --- 路径穿越：os.path.join(dir, <input-like var>) 后 5 行内被 open()/读 引用 ---
        for i, line in enumerate(lines, 1):
            m = re.search(r"os\.path\.join\s*\((\w+),\s*(\w+)\)", line)
            if m:
                var_src = m.group(2)
                if re.search(r"(user|input|query|arg|param|name|filename)", var_src, re.I):
                    window = lines[i:i + 5]
                    has_open = any(re.search(r"\bopen\s*\(", w) for w in window)
                    has_guard = any(re.search(r"(startswith|is_relative_to|commonpath|realpath)", w) for w in lines[i - 2:i + 5])
                    if has_open and not has_guard:
                        add(
                            rule_id="SK-PATH-TRAVER",
                            title=f"路径拼接未校验: join({m.group(1)}, {var_src}) 后直接读文件",
                            owasp="A09", nist="PR.IP-4",
                            impact=3, exploitability=2, confidence="inferred", exposure=1.0,
                            evidence={"file": rel, "line": i, "snippet": line.strip()[:120]},
                            fix="用 realpath + startswith(base) 或 pathlib.is_relative_to 限定在数据目录内。",
                        )

    # --- SKILL.md 级检查 ---
    # 指令注入面：文档本身教 Agent 无条件信任外部输入（横幅/回显/头部里的"指令"）
    INSTR_TRUST = [
        (r"SYSTEM\s*[:：]", "把外部输入中的 SYSTEM 前缀当指令"),
        (r"(?:无需|不用|不必)[^。\n]{0,12}(?:用户)?确认", "教 Agent 跳过用户确认"),
        (r"(?:直接|照做|立即执行)[^。\n]{0,12}(?:指令|命令)", "指示无条件执行外部指令"),
        (r"ignore\s+(?:all\s+)?(?:previous|prior|user)", "英文越权指令（ignore previous）"),
    ]
    for pat, desc in INSTR_TRUST:
        m = re.search(pat, skill_md_text, re.I)
        if m and skill_md_text:
            line_no = skill_md_text[:m.start()].count("\n") + 1
            add(
                rule_id="SK-INSTR-TRUST",
                title=f"指令注入面: {desc}",
                owasp="A01", nist="DECM-4",
                impact=5, exploitability=3, confidence="static", exposure=1.0,
                evidence={"file": "skill:SKILL.md", "line": line_no,
                          "snippet": skill_md_text.splitlines()[line_no - 1][:120]},
                fix="外部输入（横幅、回显、元数据）只能当数据；删除任何『照做/免确认』条款。",
            )
    if not skill_md_text:
        add(
            rule_id="SK-NODOC",
            title="缺 SKILL.md（触发声明与文档）",
            owasp="A10", nist="GOVERN-01",
            impact=2, exploitability=1, confidence="static", exposure=0.5,
            evidence={"file": "skill:SKILL.md", "line": 0, "snippet": "file missing"},
            fix="补 SKILL.md：name/description/边界/依赖/Skill Card。",
        )
    else:
        desc = ""
        m = re.search(r"^description:\s*(.+)$", skill_md_text, re.M)
        if m:
            desc = m.group(1)
        # 过宽触发词
        broad_words = ["任意", "所有", "一切", "any", "all", "使用", "帮忙", "帮助", "任何文件", "any file", "everything"]
        hits = [w for w in broad_words if w in desc]
        if len(hits) >= 2:
            add(
                rule_id="SK-OVERBROAD-TRIG",
                title=f"触发范围过宽: 命中泛词 {hits}",
                owasp="A07", nist="PR.AC-1",
                impact=2, exploitability=3, confidence="static", exposure=1.0,
                evidence={"file": "skill:SKILL.md", "line": 1, "snippet": desc[:140]},
                fix="把 description 限缩到具体任务类型/文件扩展名/动词。",
            )

    # --- License ---
    if not (bundle.root / "LICENSE").exists() and not (bundle.root / "LICENSE.txt").exists():
        add(
            rule_id="SK-NOLICENSE",
            title="缺 LICENSE（供应链合规）",
            owasp="A06", nist="GOVERN-05",
            impact=2, exploitability=1, confidence="static", exposure=0.5,
            evidence={"file": "skill:LICENSE", "line": 0, "snippet": "file missing"},
            fix="加 LICENSE（建议 MIT 或 Apache-2.0）。",
        )

    return f
