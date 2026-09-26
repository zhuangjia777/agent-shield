# AgentShield — AI 网络安全体检智能体

> **使用指南：** [中文使用说明](使用说明.md) · [浏览器阅读版](使用说明.html) · [应用内帮助](http://127.0.0.1:8787/help)

> **六种攻防场景：** 公共 Wi-Fi、恶意 Skill、办公内网横向移动、钓鱼与会话盗用、Web/API 越权、依赖供应链投毒。支持左右分屏、攻击前置条件、虚拟加固和业务复测。[打开演练](http://127.0.0.1:8787/arena?scenario=office_lateral) · [新增场景说明](01_specs/extended-arena-2026-09-26.md)。全部为规则推演，不执行真实攻击。

> **当前新增：** [公共 Wi-Fi 红黑演练](http://127.0.0.1:8787/arena) 采用左黑右红分屏，流式展示初始对攻、虚拟加固与同场景复测；支持停止、前后对照和专业证据。[实现与验证说明](01_specs/public-wifi-arena-2026-09-24.md)。私有 Qwen 已连通，DGX Spark 暂不可用。

> **NVIDIA 已接入：** [Skill 安全审查](http://127.0.0.1:8787/nvidia) 使用原版 SkillSpector 2.12.0，独立展示官方发现、覆盖范围与原始证据。[集成验收记录](01_specs/nvidia-integration-2026-09-24.md) · [安装与复现](09_integrations/nvidia/README.md)。
>
> **后续参赛设计：** [NVIDIA 生态参赛方案 V3](01_specs/nvidia-hackathon-strategy-v3-2026-09-24.md)。Spark 迁移、OpenShell、来源验签与 SkillEvaluator Tier 3 对照仍待实施。

> 比赛项目（预赛提交 2026-09-29）· 代号 AgentShield
> 双评估域：**Skill 域**（评估第三方 Agent Skill）+ **环境域**（本机网络/系统体检）
> 纪律：**本地健康分由确定性规则推导，LLM 不能改分**；NVIDIA 官方风险分独立展示，模型分析可以影响该官方结果，不与本地分相加。LLM 默认走 config.json 里的私有兼容 API（Qwen3.8-27B），本地报告解释在 API 不可用时尝试 Ollama→模板；演练规则无需模型。

## 能力边界（先说丑话）
- 不证明"绝对安全"——只在明确的模型/策略/测试集下报告被发现、复现和缓解的风险
- 不扫描真实生产账号/真实密钥/未授权的远程设备
- 不自动执行破坏性命令；动态测试在隔离目录（Day 5 沙箱）
- 断网可完整跑核心评估（`--no-narrative` 纯离线）

## 快速开始
```bash
cd ~/myProjects/agent-shield
# 首次: 配置 LLM（config.json 含 key, 已 gitignore）
test -f config.json || cp config.json.example config.json  # 已有配置不覆盖
# 一条命令评估一个 Skill
.venv/bin/python 02_scan/cmd_scan.py --skill 06_samples/vulnerable-skill --no-ai
# 生成报告（json/md/html，LLM 叙述：私有 Qwen3.8-27B 优先，Ollama→模板兜底）
.venv/bin/python 03_ai/report.py --input reports/eval_vulnerable-skill/results.json
# 离线模式（不联网，纯规则 + 模板叙述）
.venv/bin/python 03_ai/report.py --input ... --no-narrative
# 打开仪表盘
.venv/bin/python 04_web/app.py --open      # → http://127.0.0.1:8787
# 跑基准
.venv/bin/python tests/run_evals.py
```

## 目录
```
01_specs/   架构 + 参赛评分要求提炼
02_scan/    统一入口 cmd_scan.py；findings.py 统一 schema + 公式评分；network/system 引擎
03_ai/      报告层：规则评分 + LLM 叙述（兼容 API→Ollama→模板）
04_web/     本机仪表盘 http://127.0.0.1:8787
05_skill_eval/  Agent Skill 静态评估器（9 类规则）
06_samples/ vulnerable / hardened / benign 三样本
07_evals/   评测集 + 期望命中映射
08_arena/   六种确定性攻防演练（合成证据，无真实工具执行）
09_integrations/ NVIDIA 原版依赖锁定、子进程适配与来源记录
10_skills/  AgentShield 审计 Skill 草稿（依赖本项目，尚未 Tier 3 验证）
reports/    体检报告（每次一个子目录，results + report.*）
tests/      run_evals.py 基准门禁
config.json   运行时配置：私有/兼容 API 端点 + Ollama 兜底（改 key/模型在这）
BENCHMARK.md 指标实测 vs 目标（不达标如实披露）
```

## 评分公式（每条 finding）
`Risk = Impact(1-5) × Exploitability(1-5) × EvidenceConfidence(0.5/0.75/1.0) × Exposure(0.5/1.0/1.5)`
报告总分 = 100 − Σ(critical 25 / high 12 / medium 5 / low 2)，全部规则可复算。

## 当前基准
本地三样本门禁命中 5/5 映射规则，benign/hardened 高危误报为 0；这不是完整 30 条评测集的结果。NVIDIA 扫描耗时与覆盖范围见独立验收记录，不能沿用本地规则耗时。

## 进度（对齐 9/22 七天排期，详见 01_specs/competition-scoring-requirements.md）
- [x] 9/23 Domain：参赛要求提炼、统一 schema、Skill 静态评估器、3 样本、报告三格式、web 仪表盘、BENCHMARK 第一版
- [ ] 9/24：LLM 生成 30 条完整评测集（当前 25 条骨架）
- [ ] 9/25：沙箱动态执行（蜜罐 token、文件/网络轨迹）
- [ ] 9/26：修复补丁建议 + 同用例自动复测闭环
- [ ] 9/27：HTML 仪表盘打磨 + SKILL.md/skill-card/LICENSE 完善
- [ ] 9/28：3 次基准固化、视频、路演 PPT
- [ ] 9/29：打包提交（tag + 哈希 + 清单）
