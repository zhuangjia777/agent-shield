# 隔离执行、来源验签与效果评测

这三个流程分别回答：操作被允许了吗、内容来自谁、Skill 是否帮到了模型。结果分开记录，不合成一个“安全分”。

## OpenShell：在隔离环境里执行限定操作

`openshell/run.py` 连接操作者已配置的 OpenShell 0.1.0 网关。它不会在网关不可用时改为本机执行，也不会替你增加网关权限。

可用操作包括：读取合成样本、写入沙箱笔记、访问沙箱内临时 HTTP 服务，以及验证只读文件、受限目录和外部网络是否被阻止。`--agent` 让主模型从这些工具中选择；模型不能提供任意命令、路径或网址。网关由操作者配置，模型密钥留在宿主调用端，不随工具发进沙箱。

`openshell/policy.yaml` 只允许写入 `/sandbox`、`/tmp` 和 `/dev/null`，默认禁止外部网络，要求 Landlock 可用。隔离能力缺失时应拒绝启动。测试镜像中的文件均为合成数据，不挂载项目目录或真实用户文件。

准备可用网关及测试镜像后运行：

```sh
# 在所选网关使用的容器引擎上构建；远程网关需将镜像送至其镜像仓库。
docker build -t agentshield-lab:0.1 09_integrations/openshell/image

# 检查当前选中的网关，不执行测试
.venv/bin/python 09_integrations/openshell/run.py

# 固定探针验证 / 模型选择工具
.venv/bin/python 09_integrations/openshell/run.py --run
.venv/bin/python 09_integrations/openshell/run.py --run --agent
```

CLI 优先使用项目 `.vendor/openshell/openshell`。发行包版本和摘要见 `openshell/component-lock.json`。其他平台需安装对应的 0.1.0 CLI。网关安装请参阅 [官方安装说明](https://docs.nvidia.com/openshell/latest/about/installation)；此项目不自动部署需要 Docker socket 权限的网关。

结果保存在 `reports/openshell-*/result.json`，每个操作都有 `allowed`、`blocked` 或 `error`，原始日志单独保存。网络超时或 DNS 错误不是策略阻断，只有相应策略日志才能确认。测试结束会删除本次创建的沙箱，清理失败会记录沙箱名称。

目前适配器已完成离线回归检查，尚未在可用 OpenShell 网关中完成实测。网页里的红黑智能体暂时使用虚拟场景工具，与本流程分开。

## OMS：验证发布者签名

安装锁定的官方验签器：

```sh
uv venv --python 3.13 .venv-integrations
uv pip install --python .venv-integrations/bin/python -r 09_integrations/signatures/requirements.lock
.venv/bin/python 05_skill_eval/signature_verify.py --skill /你的/Skill目录
```

通过时退出码为 0；未签名或无法通过验证时为 1。扫描入口 `05_skill_eval/nvidia_scan.py` 会自动执行相同检查，并将状态写入报告。验签前创建完整快照，拒绝符号链接；验证签名覆盖的全部文件，新增、删除或修改文件都不能被忽略。

信任证书固定来自 NVIDIA 官方仓库，提交与 SHA-256 记在 `signatures/trust-lock.json`。不接受被审查 Skill 自带的证书作为信任根。更新信任证书需要维护者核对官方来源后同步更新锁文件。

| 状态 | 含义 |
| --- | --- |
| `verified` | 签名与已配置发布者信任根匹配，内容完整性检查通过；仍需安全审查 |
| `unsigned` | 没有 `skill.oms.sig`，无法确认签名来源 |
| `invalid` | 验签失败，可能是内容变化、签名损坏或不受信任的发布者 |
| `trust_error` | 本地信任证书与锁定摘要不一致 |
| `unavailable` / `error` | 验签器缺失、超时或执行错误，不算通过 |

本项目自己的审计 Skill 没有 NVIDIA 发布者签名，不能因此称为 NVIDIA Verified。格式依据 [NVIDIA 签名验证说明](https://docs.nvidia.com/skills/signing-agent-skills)，实际适配 `model-signing 1.1.1` 的 CLI 参数。

## Tier 3：同模型、有无 Skill 的对照

```sh
uv venv --python 3.13 .venv-evaluator
uv pip install --python .venv-evaluator/bin/python -r 09_integrations/tier3/requirements.lock

# 官方数据格式校验；不调用模型
.venv-evaluator/bin/skillevaluator tier3 validate 10_skills/agentshield-audit --strict

# 检查项目配置和数据；不启动模型实验
.venv/bin/python 09_integrations/tier3/run.py

# Docker 运行后执行完整成对实验
.venv/bin/python 09_integrations/tier3/run.py --run

# 先用核心任务做一组成对验证
.venv/bin/python 09_integrations/tier3/run.py --run --case explicit-review
```

实验使用主模型的私有兼容 API，通过官方 OpenCode 适配器执行任务，官方评判器使用同一模型。双方读取相同的数据快照，一组加载审计 Skill，一组不加载。默认 4 个任务 × 2 组 × 1 次，不跳过基线；想看重复性可以用 `--attempts 3`。密钥只通过子进程环境传递，不写进命令或任务数据。

四组任务分别检查：已有报告解读、分数与覆盖缺口判断、不可信输入中的指令注入、无关问题。它们不测真实漏洞利用，也不能用来宣称扫描召回率提升。评测材料位于 `10_skills/agentshield-audit/evals/`，只含合成输入。

官方结果、HTML 报告和运行记录保存在 `reports/tier3-*/`。模型、数据和运行方式由官方产物记录；AgentShield 的 `agentshield-run.json` 记录启动与结束状态。缺少完整的两组结果时，不发布 Skill Lift；基础设施失败不计为 0 分。

当前私有模型在官方评判器固定 90 秒请求时限内出现过评分超时。遇到 `evaluation_status: failed` 时，即使 Harbor 写出 `overall: 0` 也不能当作有效分数。完整记录见下方验证说明。

官方流程见 [Tier 3 文档](https://docs.nvidia.com/skills/skillevaluator/tier3-live-evaluation)。安装版本、源码提交和依赖见 `tier3/component-lock.json`、`tier3/requirements.lock`。

已完成的检查与实测范围见 [验证记录](verification.md)。
