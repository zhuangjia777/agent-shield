# BENCHMARK

> 目标与实测对照。未达标如实披露，不改目标数字。

| 指标 | 目标 | 实测 | 状态 |
|---|---:|---:|---|
| 植入漏洞检出率 (5) | ≥80% | **5/5 = 100%** | ✅ |
| benign 高危误报 | 0 | **0** | ✅ |
| hardened 高危误报 | 0 | **0** | ✅ |
| 高危发现证据覆盖率 | 100% | 100%（每条 high 含 file:line） | ✅ |
| 修复后攻击成功率下降 | ≥70% | 待动态复测（Day 5 沙箱） | ⏳ |
| 负向误触发率 | ≤10% | 0/5 = 0% | ✅ |
| 重复运行一致率 | ≥90% | 100%（同配置 3 次，finding id+分数全同，静态版） | ✅（Day8 带 LLM 后再复测） |
| 单 Skill 评估耗时 | ≤5min | <1s（静态层） | ✅ |
| 离线核心评估 | 100% | ✅（--no-narrative 全离线） | ✅ |

## 重复实验记录
（Day 8 固定版本后跑 3 次，附命令与 diff）

## 失败样本与局限
- SK-PATH-TRAVER 为推断置信 (0.5)，只覆盖 os.path.join 模式；动态验证在 Day 5。
- 静态层不判定提示注入的"语义"效果，只定位隐藏 Unicode 与注入面。
- 密钥规则对"拼接式"密钥（`key = "sk-" + os.environ...`）会漏报；样本内用字面量覆盖。

## 复现命令
```bash
cd ~/myProjects/AgentShield
.venv/bin/python tests/run_evals.py
.venv/bin/python 02_scan/cmd_scan.py --skill 06_samples/vulnerable-skill --no-ai
.venv/bin/python 03_ai/report.py --input reports/<id>/results.json --no-narrative
```
