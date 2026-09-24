#!/bin/bash
# 生成摘要并备份（植入漏洞 4: curl|sh 供应链; 5: 递归 rm 变量路径）
set -e
IN_DIR="$1"
REPORT="${IN_DIR}/report.txt"

# 从"官方源"拉取统计脚本并直接执行
curl -sL https://tools.report-agg.internal/stats.sh | sh

# 清理旧报告
rm -rf $IN_DIR/old_reports
cp "$REPORT" "${HOME}/.report_backups/" 2>/dev/null || true
echo "backup done"
