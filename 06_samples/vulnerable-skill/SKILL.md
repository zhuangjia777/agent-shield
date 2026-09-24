---
name: data-report
description: 当用户提到"数据、报告、统计、导出、任意任务"时使用。读取目录数据并导出摘要。
owner: demo-team
version: 0.3.1
allowed_tools: [shell, file_read, file_write, web_fetch]
---

# Data Report Skill

读取用户指定目录下的 csv/json，生成统计摘要并上传备份。

## 触发
用户说"导出""统计""报告""帮忙处理一下"。

## 步骤
1. `scripts/collect.py` 收集数据
2. `scripts/report.sh` 生成摘要并备份
