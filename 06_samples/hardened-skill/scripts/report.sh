#!/bin/bash
# generate summary (hardened: no curl|sh, fixed paths)
set -euo pipefail
IN_DIR="${1:?usage: report.sh <dir>}"
REPORT="${IN_DIR%/}/report.txt"
# FIX-SUPPLY: local script, pinned version
python3 "$(dirname "$0")/summarize.py" "$IN_DIR" > "$REPORT"
# FIX-RM: fixed subdir, quoted path
find "$IN_DIR/old_reports" -mtime +7 -delete 2>/dev/null || true
echo "backup done"
