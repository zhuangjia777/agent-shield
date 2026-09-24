# 参赛评分要求提炼 → AgentShield 契合改造清单

> **2026-09-24 方向更新：** 用户确认 NVIDIA 生态是核心评分方向，目前没有 DGX Spark，先使用私有 Qwen 模型开发。当前实施优先级以 [V3 NVIDIA 生态参赛方案](nvidia-hackathon-strategy-v3-2026-09-24.md) 为准。下文权重和状态保留为历史内部推算，尤其“NVIDIA/DGX 15%”不再用于分配资源，也不代表官方权重。

> 依据：《AI安全评估智能体_参赛实施计划.md》(2026-09-22)，预赛提交 2026-09-29。
> 说明：官方未公布评分表；权重为计划 §8 的内部推算，本文是"备赛用验收清单"。

## 一、评分维度（推算权重）

| 维度 | 权重 | AgentShield 当前状态 | 改造动作 |
|---|---:|---|---|
| 技术完成度 | 25% | 网络/系统扫描已能跑 | 补 Skill 静态评估器；跑通 3 样本 + 算法评分；报告三格式 |
| 创新性 & 问题价值 | 20% | 单薄（"给报告加 AI"） | 叙事改成：同一 Agent 覆盖「环境域 + Skill 域」双评估，规则判定 + LLM 解释分工 |
| Agent Skills 契合度 | 20% | ❌ 主要是弱点 | 产品本身做成可安装 Skill（SKILL.md + skill-card + LICENSE）；05_skill_eval 评估第三方 Skill |
| NVIDIA/DGX 价值 | 15% | Ollama 本地优先 ✅ | 默认本地模型 + 离线可跑 + 断网演示；DGX Spark 上同样命令可跑（架构无强依赖） |
| 可量化效果 | 10% | ❌ 没有基准 | BENCHMARK.md + 30 条 evals + 修复前后对照分 |
| 安全合规可信 | 10% | 部分（本地数据） | skill-card/权限边界/第三方清单/审计留痕/人在回路（补丁需确认） |

## 二、硬性量化指标（不达标就如实披露，不许改目标数字）

| 指标 | 目标 | 测量方式 |
|---|---:|---|
| 植入漏洞检出率 | ≥80% | vulnerable-skill 5 漏洞 vs expected_findings.json |
| 高危发现证据覆盖率 | 100% | 每条 high 级 finding 必须有 evidence.file+line 或命令输出引用 |
| benign 高危误报 | 0 | benign-skill 报告里无 high 级 findings |
| 修复后攻击成功率下降 | ≥70% | vulnerable vs hardened 同一 eval 集合跑分对照 |
| 负向场景误触发率 | ≤10% | negative 类 eval 用例 |
| 重复运行一致率 | ≥90% | 同配置跑 3 次，findings diff |
| 单 Skill 评估耗时 | ≤5min | 计时 |
| 离线核心评估 | 100% | 断网跑全量（Ollama 本地或不依赖模型） |

## 三、评分纪律（代码层强制，不是文档口号）

1. **公式评分**：`Risk = Impact(1-5) × Exploitability(1-5) × EvidenceConfidence(0.5|0.75|1.0) × Exposure(0.5|1.0|1.5)`
   → 实现在 `02_scan/findings.py::risk_score()`；report 的 0-100 总分 = 归一化，**全部由规则推导，LLM 只能解释不能改分**。
2. **证据先于结论**：finding 无 evidence（文件行号/命令输出/轨迹引用）不得标为高危。
3. **规则优先、模型辅助**：每条 finding 带 `rule_id`；LLM 输出只允许填 `explain/fix/narrative` 字段；LLM 挂了走模板降级，结论集不变。
4. **OWASP Agentic Top 10 + NIST AI RMF 映射**：每条 finding 必须带 category（见 `01_specs/risk_mapping.md`）。
5. **人在回路**：修复补丁只生成建议；`--apply` 需显式确认，且只作用于样本副本。
6. **可回放**：run manifest 记录模型、版本、策略、seed、时间、输入哈希。
7. **能力边界首页明示**：README 顶部列出"明确不做什么"（不证绝对安全、不扫真实生产账号等）。

## 四、演示与提交物清单（逐项勾对）

- [ ] 一条命令评估一个 Skill：`python3 -m agentshield scan samples/vulnerable-skill`
- [ ] 3 样本：vulnerable / hardened / benign（`06_samples/`）
- [ ] 30 条评测用例：10 正向 + 10 对抗 + 5 负向 + 5 故障（`07_evals/evals.json`）
- [ ] BENCHMARK.md：全部指标 + 失败样本披露（`BENCHMARK.md`）
- [ ] 报告：JSON + Markdown + 单页 HTML（评分大字/发现卡片/证据/映射/复测状态）
- [ ] 修复闭环：≥1 个漏洞"发现→补丁→复测 PASS + 分数下降"
- [ ] 三个证据帧：攻击前（声明 vs 实际权限差）/ 攻击中（轨迹+蜜罐命中）/ 修复后（同用例 FAIL→PASS）
- [ ] SKILL.md + skill-card.md + LICENSE + THIRD_PARTY_NOTICES.md
- [ ] 2-3 分钟演示视频 + 断网备战版
- [ ] 版本 tag + 文件哈希 + 复现说明

## 五、执行顺序（剩余 6 天，对齐原排期）

- **9/23（今天，= 原 Day2 静态分析）**：本题（需求+schema）✅ → skillcheck.py + 3 样本 → 报告重构（公式评分/映射/证据）→ 首版 BENCHMARK
- 9/24：威胁建模 + LLM 生成 30 条用例（evals.json 补齐、schema 校验）
- 9/25：沙箱动态执行（蜜罐 token + 文件/网络轨迹记录）
- 9/26：判定 + 补丁 + 自动复测闭环
- 9/27：HTML 仪表盘 + skill-card/BENCHMARK 终稿
- 9/28：跑 3 次基准、录视频、路演 PPT
- 9/29：打包提交（哈希/tag/清单），提前 ≥4h
