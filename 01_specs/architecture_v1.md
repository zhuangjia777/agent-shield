# AgentShield v1 架构规格

## 总体数据流
```
scan.py ──results.json──▶ report.py ──report.html──▶ web/app.py (浏览器)
   │                          │
   │ determinism              │ LLM (Ollama local → cloud fallback)
   │ (nmap/scapy/sysctl)      │
   └─ history appended to reports/history.json
```

## 模块划分

### 02_scan/scanner.py — 网络扫描
1. **接口探测**：`ipconfig getifaddr en0`，记下本机 IP + /24 网段
2. **存活发现**：scapy ping sweep（192.168.x.1-254，并发、只跑 ~5s），失败回退 ICMP
3. **端口扫描**：对每个存活主机跑 `nmap -sT -p TOP-40 --open -oX -`（TCP connect，非 root 可用）
4. **速率控制**：把整个 sweep 包裹进 10s-60s 超时，报告里保留每台机的 raw ports
- 输出：`network: {subnet, hosts: [{ip, mac, vendor?, ports: [{p, s, v}]}, ...]}`

### 02_scan/systemcheck.py — macOS 系统体检
| 检查项 | 命令/来源 | 输出字段 |
|---|---|---|
| 防火墙 | `defaults read /Library/Preferences/com.apple.alf globalstate` | firewall_enabled |
| 自动更新 | `defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled` | auto_update |
| FileVault | `fdesetup status` | disk_encryption |
| 监听端口 | `lsof -nP -iTCP -sTCP:LISTEN` | listening: [{port, pid, process}] |
| 登录项 | `osascript -e 'tell app "System Events" to get the name of every login item'` + `launchctl list` | logins |
| 备份 | `tmutil destinationinfo` | backup |
| 系统版本 | `sw_vers -productVersion` | os |
| SIP | `csrutil status` | sip |

- 输出：`system: {...}`

### 03_ai/report.py — AI 报告
- `llm.complete(jsonl)`：Ollama `/api/chat`（nomic 有文本模型时用 llama3.2 / qwen2.5）；失败 → 云 API（openai 兼容端点）→ 失败 → 模板降级
- prompt 结构：
  1. 系统角色：安全分析师，对中国用户，说人话，不要 AI 味
  2. user：`results.json`（太大则分块）+ 上一份 history
  3. 输出 JSON schema：
     ```json
     {
       "score": 0-100,
       "top3_actions": ["...", "...", "..."],
       "findings": [{"id","title","severity":"P0|P1|P2","explain","fix"}],
       "diff": {"new": [...], "fixed": [...]}
     }
     ```
- 写 `report.html`（黑白编辑感模板，评分大字 + 发现卡片流）

### 04_web/app.py — 网页端
- `flask` 起在 `127.0.0.1:8787`，只读本地
- `/`：最近一份报告 + "重新体检" 按钮（调 scan.py）
- `/reports/<ts>`：历史报告列表

## 错误处理
- nmap 不在：network 段标 `"skipped": "nmap not installed"`，系统检查照常
- Ollama 没起 / 云 API 没配：模板降级（手写规则 → severity，仍出报告）
- 所有 shell 调出 JSON 带 `stdout/stderr/exit_code`，保留 raw 到 reports 便于 debug

## MVP 验收标准
1. `./scan.py` 跑完 < 90s，产出合法 JSON
2. 本机 + 至少 1 台局域网设备被识别
3. 报告 HTML 可打开，评分 + ≥5 条 finding + 修复建议
4. 无网/Agent 场景：Ollama 挂 → 仍出模板报告
