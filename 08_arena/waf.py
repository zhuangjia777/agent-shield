#!/usr/bin/env python3
"""aslab WAF：真实反向代理 + 攻击特征拦截（SQLi/XSS）。

跑在隔离网的 aslab-blue 容器里：红队的流量先到这里，命中规则直接 403，
放行的才转发给靶机。纯 Python 标准库，演示用规则集——不是生产 WAF，
目标是让"开没开防护，攻击结果不同"这件事变成可实测的事实。
"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

UPSTREAM = "http://aslab-target:3000"
MODE_FILE = "/waf/mode.json"  # 宿主 logs/arena_live/waf_mode.json 挂进来：{"mode":"block"|"bypass"}


def _mode() -> str:
    try:
        return json.loads(open(MODE_FILE).read()).get("mode", "block")
    except Exception:
        return "block"  # 模式读不到按最安全档


# 规则收紧，避免误伤正常业务：只打典型攻击特征，不拦裸 -- 或裸 select
RULES = [
    ("sqli_logic",   re.compile(r"(?:'|%27)\s*(?:or|and)\s+[\d'\"]")),
    ("sqli_1eq1",    re.compile(r"\b(?:or|and)\s+1\s*=\s*1")),
    ("sqli_union",   re.compile(r"\bunion\b(?:\s+all)?\s+select\b")),
    ("sqli_quote_comment", re.compile(r"(?:'|%27)\s*(?:--|#)")),
    ("sqli_time",    re.compile(r"\b(?:sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(")),
    ("sqli_stacked", re.compile(r";\s*(?:drop|delete|update|insert|alter)\s")),
    ("xss_script",   re.compile(r"<\s*script")),
    ("xss_handler",  re.compile(r"\bon(?:error|load|mouseover)\s*=")),
]


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):  # 一行一条，进 docker logs
        pass

    def _blocked(self, rule):
        body = json.dumps({"waf": "blocked", "rule": rule,
                           "hint": "aslab WAF 拦截了攻击特征"}, ensure_ascii=False).encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print(f"BLOCK rule={rule} path={self.path[:80]}", flush=True)

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        if _mode() == "block":  # bypass 档：跳过全部规则，仅转发（蓝队关防护）
            hay = (self.path + "\n" + raw.decode("utf-8", "replace")).lower()
            for name, rx in RULES:
                if rx.search(hay):
                    return self._blocked(name)
        req = Request(UPSTREAM + self.path, data=raw or None, method=self.command)
        for h in ("Content-Type", "Accept", "Authorization"):
            if self.headers.get(h):
                req.add_header(h, self.headers[h])
        try:
            with urlopen(req, timeout=10) as r:
                data, code = r.read(), r.status
                ctype = r.headers.get("Content-Type", "application/json")
        except HTTPError as e:
            data, code = e.read(), e.code
            ctype = e.headers.get("Content-Type", "application/json")
        except (URLError, TimeoutError, OSError) as e:
            data = json.dumps({"waf": "upstream_unreachable", "err": str(e)[:120]}).encode()
            code, ctype = 502, "application/json"
        self.send_response(code)
        self.send_header("Content-Type", ctype or "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _proxy


if __name__ == "__main__":
    print(f"aslab WAF up, upstream={UPSTREAM}, rules={len(RULES)}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
