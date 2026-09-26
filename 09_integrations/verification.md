# 集成验证记录（2026-09-26）

## 红黑智能体与模型设置

- 双方默认继承主模型，独立配置通过凭据隔离、空密钥保留、改接口重新确认密钥等 9 项回归测试。
- 智能体的角色权限、不同上下文、观察范围、前置条件、真实策略变化、轮次上限及失败处理通过 10 项回归测试。
- 使用本机已配置的私有 Qwen，通过真实 `/api/arena/agents` 完成 8 次模型决策：黑方观察并尝试目标，红方观察、检查业务并执行 1 项虚拟防护变更；双方均自主结束。
- 这是模型真实决策与工具调用的验证。工具环境仍为合成规则场景，没有发送攻击报文。
- 桌面和移动浏览器检查通过：品牌在左、操作在右，模型配置保存与失败提示正常，红黑双栏展示工具结果，证据可导出。

本机记录：`reports/agent-live-smoke/http-events.json`、`reports/agent-ui/agents.png`。这些文件不随 Git 发布。

## OMS 发布者签名

`model-signing 1.1.1` 的 8 项实际加密回归测试通过：未签名、有效签名、内容篡改、新增文件、删除文件、错误发布者、信任证书变化、符号链接输入。

还验证了 NVIDIA 官方样本，结果为 `verified`：

- 来源：`NVIDIA/skills` 的 `skills/mcore-linting-and-formatting`。
- 提交：`d8519c57da6db5d9bea274ec1724a4a7a56a3dee`。
- 5 个文件，严格检查新增与修改文件，不执行 Skill 内容。
- 签名文件 SHA-256：`d844681bf987952cc05bbe47ff25a7e17238734e0b3e83127d426d744ebb698f`。
- 信任证书 SHA-256：`fc15d9749a8933482b896e2b204fa59dc7bd86aac48e508d159a8c6dd14420fc`。

普通内置样本的完整静态扫描也已运行，报告包含 `unsigned`，不把未签名写成验签通过。

## OpenShell

CLI 0.1.0 发行包已按官方摘要核对。适配器的限定命令、无宿主回退、网络错误不算策略阻断等检查已通过。没有可用网关，尚未执行真正的隔离操作。

自动审批拒绝了需要 Docker socket 挂载及 Unconfined AppArmor 的本机网关配置。项目保留连接已有网关的适配方式，等待操作者选择网关；没有绕过该限制。

## SkillEvaluator Tier 3

使用官方 SkillEvaluator 0.3.0，源码锁定在 `4dcbe371f562a8ac4bca63fce81370228a7579c7`，Harbor 0.13.2。

四组人工编写任务通过官方 `tier3 validate --strict`。首次完整实验发生基础镜像下载/认证超时，导致加载 Skill 的一组任务失败，不能计算有效 Skill Lift；该轮已停止并保留失败记录，未将失败当作 0 分。

随后用 `explicit-review` 单任务重跑成对实验。加载 Skill 的智能体完成了任务，但官方评判器的 `accuracy` 与 `goal_accuracy` 请求达到固定 90 秒超时，评判状态为 `failed`。这属于评分未完成，不能把 Harbor 的占位 `overall: 0` 当作模型得分，也不能计算有效提升。

确认评分失败后已停止其余基线运行并清理本轮容器，诊断材料保留。

本机第二轮记录：`reports/tier3-20260926-115056-b5e71d/`。适配器按官方 `agents.*.conditions.with_skill/without_skill` 检查两组执行状态和评分覆盖，缺少基线、跳过基线或评分不全都不能标记完成；相关 6 项适配器测试已通过。

后续实验应从 `reports/tier3-*/agentshield-run.json` 和对应官方 `result.json` 核实双方是否全部成功，再引用结果。当前没有完整有效的对照结果，不宣称 Skill 已提高模型效果。
