"""红队入站命令黑名单（纵深防御，非安全边界）。

主边界仍然是目标白名单、人工确认闸与 Docker 网络隔离；本模块只挡
"白名单外但语义上越出演练场意图"的命令——挂载 docker.sock、写宿主目录、
反弹 shell 到外部、从外网拉脚本执行这类被注入后常见的逃逸动作。

规则正则先过 _redos_safe 再编译：嵌套量词（如 (a+)+ ）直接丢弃不编译，
宁可少一条规则，也不让裁判路径被一条恶意模式拖死。
"""
from __future__ import annotations

import re

# 先过 ReDoS 检查再入库的模式；命中即拒绝执行并写明理由。
BLACKLIST = [
    (r"(?:^|[\s;&|`(])docker\b[^|;&]*\b(?:run|exec|cp|build|compose)\b",
     "红队容器内不得再操作 Docker（防挂载 docker.sock 逃逸）"),
    (r"(?:^|[\s;&|`(])nsenter\b|/proc/\d+/ns/",
     "禁止进入其他容器的命名空间"),
    (r"(?:^|[\s;&|`(])(?:nc|ncat|netcat)\b[^|;&]*\s(?:-e|-c)\s",
     "禁止带 -e/-c 的反弹 shell"),
    (r"/dev/tcp/",
     "禁止 /dev/tcp 直连（绕过目标白名单的常见写法）"),
    (r"(?:curl|wget)[^|;&]*\|\s*(?:ba|z|da)?sh\b",
     "禁止从网络管道直接执行脚本"),
    (r"(?:^|[\s;&|`(])(?:crontab|systemctl|service)\b",
     "禁止持久化与系统服务操作"),
    (r"(?:^|[\s;&|`(])base64\s+(?:-d|--decode)\b[^|;&]*\|\s*(?:ba)?sh\b",
     "禁止解码后直接执行"),
]

def _group_content_has_quantifier(src: str, open_i: int, close_i: int) -> bool:
    """组内是否含量词（* + ? {n,m}），跳过转义与字符类。"""
    depth_class = 0
    i, esc = open_i + 1, False
    for i in range(open_i + 1, close_i):
        ch = src[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
        elif ch == "[" and depth_class == 0:
            depth_class = 1
        elif depth_class and ch == "]" and i > open_i + 2:
            depth_class = 0
        elif depth_class == 0 and ch in "*+?{":
            return True
    return False


def _strip_classes(inner: str) -> str:
    """去掉字符类 [..] 内容，避免把 [a(b] 里的括号当分组。"""
    out, in_class, esc = [], False, False
    for ch in inner:
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif not in_class:
            out.append(ch)
    return "".join(out)


def redos_safe(pattern: str) -> bool:
    """保守判定：含量词的分组再被量词修饰（(a+)+ / (\\w+\\s?)* 型）视为可疑。宁可丢规则。"""
    stack = []
    esc = in_class = False
    for i, ch in enumerate(pattern):
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if in_class:
            if ch == "]":
                in_class = False
            continue
        if ch == "[":
            in_class = True
        elif ch == "(":
            stack.append(i)
        elif ch == ")" and stack:
            open_i = stack.pop()
            nxt = pattern[i + 1] if i + 1 < len(pattern) else ""
            if nxt in "*+{":
                inner = _strip_classes(pattern[open_i + 1:i])
                if _group_content_has_quantifier(pattern, open_i, i) or "(" in inner:
                    return False
    try:
        re.compile(pattern)
    except re.error:
        return False
    return True


def compile_rules(rules=BLACKLIST):
    """只收 ReDoS 安全的模式；不安全的静默丢弃（有测试盯着条数）。"""
    return [(re.compile(p), why) for p, why in rules if redos_safe(p)]


_RULES = compile_rules()


def check(cmd: str):
    """命中黑名单返回理由字符串，干净命令返回 None。"""
    for rx, why in _RULES:
        if rx.search(cmd):
            return why
    return None
