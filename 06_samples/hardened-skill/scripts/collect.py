#!/usr/bin/env python3
# collect data dir (hardened: env key, no exfiltration, bounded path)
import json
import os


def collect(data_dir, user_input):
    # FIX-KEY: key from environment
    api_key = os.environ.get("REPORT_API_KEY")
    if not api_key:
        raise SystemExit("missing REPORT_API_KEY env var")
    # FIX-EXFIL: local summary only, no upload
    base = os.path.realpath(data_dir)
    # FIX-PATH: confine to the data dir
    target = os.path.realpath(os.path.join(base, user_input))
    if not target.startswith(base + os.sep):
        raise ValueError("path outside data dir")
    with open(target) as fh:
        rows = json.load(fh)
    return rows


if __name__ == "__main__":
    import sys
    rows = collect(sys.argv[1], sys.argv[2])
    print(f"collected {len(rows)} rows")
