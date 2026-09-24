# NVIDIA 集成验收 · 2026-09-24

当前接入原版 NVIDIA SkillSpector 2.12.0；静态及私有 Qwen 语义模式均已完成三类合成样本扫描。网页入口为 `/nvidia`。这是官方扫描组件的真实调用，不把 Qwen 或公共 Wi-Fi 规则仿真计作 NVIDIA 组件。

## 组件来源与各自贡献

- 上游：[NVIDIA/SkillSpector](https://github.com/NVIDIA/SkillSpector/tree/c7958a3268d9498644b22edb75d0f051bbc8cbfc)，Apache-2.0，commit `c7958a3268d9498644b22edb75d0f051bbc8cbfc`。
- 原版包 SHA-256：`bfbfa97934b8184b9079e3513a44b1310e19da0434d726cd2fc82a5a836f095d`。安装包与原版 `src/skillspector` 比较一致，每次扫描前重新核对。依赖锁定见 `09_integrations/nvidia/requirements.lock`。
- NVIDIA 负责官方规则与语义分析、覆盖判定、原始风险评估。AgentShield 负责输入快照、内容哈希、网络约束、模型传输适配、双引擎报告和分层用户界面。
- 上游源文件未修改。项目通过官方 provider 扩展接口适配私有 Qwen；设置保守请求预算、关闭 Qwen thinking，并显式创建不复用闲置连接、不读取系统代理的 HTTP 客户端。
- commit 和哈希仅用于内容追溯，来源签名尚未验证；不宣称 NVIDIA-Verified 或主办方背书。

## 本机实测

下表均为同日单次测量，不是重复稳定性基准。扫描完成仅表示所选范围完成，不表示样本安全。

| 样本 | 模式 | 状态 | 官方发现数 | 官方风险分（越高越大） | 模型节点成功/尝试 | 秒 | 报告目录 |
|---|---|---|---:|---:|---|---:|---|
| vulnerable | 静态 | complete | 4 | 89 | 0/0 | 1.23 | `nvidia-20260924-152956-f191e3` |
| benign | 静态 | complete | 1 | 7 | 0/0 | 1.20 | `nvidia-20260924-152958-3fbf06` |
| hardened | 静态 | complete | 1 | 7 | 0/0 | 1.22 | `nvidia-20260924-152957-0347ac` |
| vulnerable | 静态＋Qwen | complete | 14 | 100 | 5/5 | 81.30 | `nvidia-20260924-155254-205284` |
| benign | 静态＋Qwen | complete | 1 | 7 | 5/5 | 19.82 | `nvidia-20260924-155415-9bc694` |
| hardened | 静态＋Qwen | complete | 5 | 58 | 5/5 | 63.86 | `nvidia-20260924-155435-b624f4` |

报告目录都在 `reports/` 下。每次保存 `skillspector.json` 原文、`report.json/html/md`、`results.json`、`io-policy.json`；最新语义运行另有不含模型原文的 `model-calls.json` 与错误类别/调用栈位置 `model-errors.json`。三个成功语义运行的错误列表为空。

本地规则健康分分别为 64/100/100，独立于官方风险分。尤其 hardened 的语义风险分为 58，含 TP4、LP3、SDI-1 线索：不能因样本名叫“加固”就把它当成零误报真值，也不能把模型新增线索称作已复现漏洞。这些线索尚需人工核验，当前没有对官方引擎测得精确率/召回率。

## 失败记录与修复依据

- 初期误将 `source_local_only` 当作禁止递归读取开关；实际它禁止向模型发送源内容。这批报告标记 `superseded_adapter_flag_correction` 并在首页隐藏，原始记录保留，不纳入验收。
- 之后出现系统代理路由、一次 240 秒超时、模型节点 4/5 成功的失败运行。均保留失败状态，未修改为成功。
- `nvidia-20260924-155039-9e0afb/model-errors.json` 捕获 `RuntimeError: event loop is closed` 类别，定位为跨节点事件循环共用闲置 HTTP 连接。适配层显式配置独立客户端、禁用 keepalive 后，三类语义运行全部完成。
- 新增本地合成 HTTP 服务回归：同一模型跨三个独立事件循环调用、代理环境隔离、连接不复用与请求预算。原版 NVIDIA 源码没有打补丁。

## 输入与执行边界

只读扫描本地目录副本，要求 `SKILL.md`，拒绝符号链接，限制文件数与体积；网页仅允许三个合成样本。扫描不运行被测脚本，不遍历远程引用。

静态模式拒绝 Python 网络访问，语义模式只允许配置的私有模型地址与端口；密钥通过子进程 stdin 传递。剥离继承的云配置与代理，关闭 tracing。OSV 在线查询受限，覆盖缺口仍需以报告为准。审计钩子是可信扫描器的意外出网防护，不是针对恶意原生代码的操作系统沙箱。

原始报告可能包含被扫描文件的内容片段，输出目录权限为 0700、文件 0600；对外分享前仍需检查。自研 Skill 的静态扫描为 partial/AE1，因为它引用项目中的运行文件；语法验证通过不等于能独立安装或通过 Tier 3。

## 验证与未完成事项

- NVIDIA 适配、报告转义、版本/内容哈希、失败判定：10 项测试通过。
- 私有模型传输回归：2 项测试通过。
- 公共 Wi-Fi 规则语义、128 种防护组合及流式接口：15 项测试通过。
- 配置密钥处理：3 项测试通过；本地三样本静态门禁 PASS，5/5 映射规则命中。这不是完整 30 条基准。
- 自研 Skill 语法验证通过。机器可读验收清单见 `reports/nvidia-integration-20260924/verification.json`。

尚未完成：DGX Spark / Nemotron 实机迁移、OpenShell 动态执行沙箱、SkillEvaluator Tier 3 带/不带 Skill 对照、OMS 来源验签、官方治理卡生成、完整评测集与多次运行稳定性测量。当前不据此宣称满足所有赛事要求或具备获奖保证。
