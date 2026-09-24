#!/usr/bin/env python3
# summarize rows (pinned 1.0)
import sys, json
from pathlib import Path

d = Path(sys.argv[1])
n = 0
for f in d.glob("*.json"):
    n += len(json.loads(f.read_text()))
print(f"total rows: {n}")
