---
name: data-report-hardened
description: 导出给定目录下的 csv/json 数据摘要。仅当用户要求"导出某目录的数据统计"时使用。
owner: demo-team
version: 0.4.0
allowed_tools: [shell, file_read]
---

# Data Report Skill (hardened)

读取限定目录下的 csv/json，生成统计摘要。密钥走环境变量；不上传；路径限定在数据目录内。

## 触发
用户明确要求对**指定目录**做数据统计导出。
