# AgentShield Frontend — Design.md

> 前端设计规范 版本 1.1 · 2026-09-24（v1.1 新增 §6.6 深度厚重系统 + 全息设备）
> 单一事实来源：`04_web/app.py` 的 `BASE_CSS`（本文件与代码冲突时，以代码为准并更新本文件）
> 配套预览：`design_preview.html`（light/dark 双主题可视化 + 组件样例）

## 0. 一句话

黑白灰编辑感的技术报告界面：纯中性色、直角（radius=0）、1px 硬边框、**分层板材（v1.1）**、系统无衬线 + 等宽字体，**不靠颜色、靠墨色浓度和边框样式传达层级与语义**。界面层之上允许一层"全息设备"语言（扫描线 / 掠光 / reticle），但设备层永远是装饰，信息层永远是主角。

## 1. 原则（全部场景无例外）

1. **严格黑白灰。** 无彩色相（achromatic）、无彩色渐变；唯一"accent" 就是近黑（#111）／dark 下的近白（#ececec）。**灰阶功能性渐变（扫描线 / glow / reticle 弧）是 v1.1 允许的设备级例外**，常量表见 §6.6。语义等级用**墨色浓度 + 边框样式**表达，不用色相。
2. **Radius = 0。** 集中在一个 token `--r: 0px`，所有圆角走它；仅小徽章允许 ≤2px 硬编码例外。
3. **硬度 + 厚重。** 1px 边框；顶栏 / 弹窗头下方一条实心黑线；hover = 边框变黑（不上浮、不阴影渐隐）；**板材（plate）一律带分层阴影 + 硬肩（bevel），禁止裸描边卡片，分级见 §6.6；按钮 = #52 滑入填充板（静止 7px 错位，hover 滑归 + 文字反色，stable 主面不动）**。无玻璃拟态；glow 只允许出现在 holo 设备位（§6.6）。
4. **报告感。** 页面读起来像技术报告：evidence 行、`score = a×b×c` 公式行、密集但对齐。不营销、不 hero、无装饰性图标（功能 emoji 之外的彩色 emoji 是颜色泄漏点，纯单色场景换文字/SVG）。
5. **类型身份。** 系统无衬线正文；品牌名 / 表单 label / 状态 label 一律 **UPPERCASE + 字距**；ID、时间戳、公式、evidence 行用 **等宽**。

## 2. Tokens

### 2.1 Light（默认，代码现行值）

| Token | 值 | 用途 |
|---|---|---|
| `--bg` | `#f5f5f5` | 页面底色（fog） |
| `--card` | `#ffffff` | 卡片 / 弹窗表面 |
| `--fg` | `#111111` | 主墨色 / accent / 实心线条 |
| `--muted` | `#787878` | 次要文字（对比度下限，勿更深于灰的地域） |
| `--line` | `#dcdcdc` | 普通 1px 分隔线 |
| `--accent` | `#111111` | 语义 accent（= 近黑） |
| `--accent-soft` | `#ebebeb` | 浅填充（low 徽章、hover 底） |
| `--code` | `#f1f1f1` | 代码块 / evidence 观察区底 |
| `--fill` | `#ffffff` | 按钮 / 输入框底色（已统一 token） |
| `--overlay` | `rgba(0,0,0,.45)` | 弹窗遮罩 |
| `--sh-1` | `0 1px 2px rgba(0,0,0,.10), 0 2px 6px rgba(0,0,0,.08)` | 板材 L1：卡片 / 输入框 / 徽章组（薄） |
| `--sh-2` | `0 2px 4px rgba(0,0,0,.12), 0 10px 24px rgba(0,0,0,.14)` | 板材 L2：可点击卡 / 输入区 / toast（厚） |
| `--sh-3` | `0 4px 8px rgba(0,0,0,.16), 0 24px 64px rgba(0,0,0,.22)` | 板材 L3：modal / 悬浮窗（最厚） |
| `--bevel` | `inset 0 1px 0 #ffffff` | 板材硬肩（上缘受光边） |
| `--btn-ledge` | `0 2px 0 #c8c8c8` | 按钮底缘硬投影（机关件） |
| `--sweep` | `linear-gradient(115deg, transparent 30%, rgba(0,0,0,.05) 46%, rgba(0,0,0,.10) 50%, rgba(0,0,0,.05) 54%, transparent 70%)` | 卡片掠光（hover-only，light） |
| `--slab` / `--slab-ink` | `#ffe54c` / `#141414` | 按钮滑入填板（原版黄，唯一彩色豁免）/ 文字恒黑 |
| `--scanline` | `repeating-linear-gradient(0deg, rgba(0,0,0,.022) 0 1px, transparent 1px 3px)` | 全屏底纹扫描幕布 |
| `--r` | `0px` | 全局圆角 |

### 2.2 Dark（已并入代码）

推导规则：accent 反转（近白生效）；灰阶次序保持 bg < card < fill；文字次级不低于 `#8f8f8f`；遮罩更深。

| Token | 值 | 备注 |
|---|---|---|
| `--bg` | `#171717` | |
| `--card` | `#1e1e1e` | 与 bg 只拉开 1 级灰 |
| `--fg` | `#ececec` | accent 随之反转 |
| `--muted` | `#8f8f8f` | 对比度下限 |
| `--line` | `#333333` | |
| `--accent` | `#ececec` | 近白 |
| `--accent-soft` | `#2a2a2a` | 深填充 |
| `--code` | `#242424` | |
| `--fill` | `#1e1e1e` | 按钮 / 输入框底 |
| `--overlay` | `rgba(0,0,0,.60)` | |
| `--sh-1` | `0 1px 0 rgba(0,0,0,.6), 0 1px 2px rgba(0,0,0,.4), 0 2px 6px rgba(0,0,0,.35)` | 暗底阴影对比低，加深 + 上缘受光边改黑线 |
| `--sh-2` | `0 1px 0 rgba(0,0,0,.6), 0 2px 4px rgba(0,0,0,.45), 0 10px 28px rgba(0,0,0,.5)` | |
| `--sh-3` | `0 2px 0 rgba(0,0,0,.6), 0 4px 8px rgba(0,0,0,.5), 0 24px 72px rgba(0,0,0,.6)` | |
| `--bevel` | `inset 0 1px 0 rgba(255,255,255,.06)` | 暗底下受光边只有 6% 白，几乎隐形 → 厚重感改靠阴影 |
| `--btn-ledge` | `0 2px 0 #000000` | 暗底 ledge 用纯黑才看得见 |
| `--slab` / `--slab-ink` | `#ffe54c` / `#141414` | 按钮滑入填板（dark 同黄，原版一致）/ 文字恒黑 |
| `--sweep` | `linear-gradient(115deg, transparent 30%, rgba(255,255,255,.05) 46%, rgba(255,255,255,.10) 50%, rgba(255,255,255,.05) 54%, transparent 70%)` | 暗底掠光反转成白光 |
| `--scanline` | `repeating-linear-gradient(0deg, rgba(255,255,255,.018) 0 1px, transparent 1px 3px)` | 暗底幕布用白 |
| `--r` | `0px` | 不变 |

### 2.3 语义等级（severity）— 浓度分级，两主题共 5 档

| 等级 | Light | Dark | 表达手段 |
|---|---|---|---|
| critical | 黑底白字 `#111/#fff` | 白底黑字 `#ececec/#111` | 实心反白 |
| high | `#3d3d3d` 底白字 | `#6f6f6f` 底白字 | 深实心 |
| medium | 白底黑字 + 黑边框 | 透明底 + 白字白边框 | 描边 |
| low | `#ebebeb` 底 `#444` 字 | `#2a2a2a` 底 `#a8a8a8` 字 | 浅实心 |
| info | `#f1f1f1` 底灰字灰边框 | `#242424` 底 `#8f8f8f` 字 | 代码底色 + 线 |

⚠ 相邻灰阶不要靠太近——用 **填充 vs 描边 vs 字重** 拉开，而不是堆中间灰。

## 3. 字体

| 场景 | 值 |
|---|---|
| 正文 | `-apple-system, BlinkMacSystemFont, "PingFang SC", "Segoe UI", sans-serif`，`15px / 1.65` |
| 等宽 | `ui-monospace, "SF Mono", Menlo, monospace`，`12.5px`（code/ID/时间戳/公式） |
| 字阶 | 12 / 13 / 13.5 / 15 / 18（wordmark） / 30（卡片分） / 58（报告大分，`letter-spacing: -2px`） |
| wordmark | `font-weight: 800; text-transform: uppercase; letter-spacing: .5px` |
| label / 状态词 | `font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; color: var(--muted)` |
| 思考/doubt 文本 | `color: var(--muted); font-style: italic` |

不用 web font，不走 Inter 默认脸。

## 4. 间距与版式

- 内容列 `max-width: 920px` 居中，页面 padding `28px 20px 80px`。
- 栅格：`repeat(auto-fill, minmax(250px, 1fr))`，gap `12px`。
- 通用 gap：8 / 10 / 12 / 14 / 16 / 18 / 22（不随意造新值）。
- 线条：普通分隔 `var(--line)`；**结构性硬线**（顶栏下、弹窗头下、输入栏上、footer 上）一律 `var(--fg)` 实心 1px。
- 移动端 hit target ≥ 44px；print 文本 ≥ 12pt。

## 5. 组件规则

### Button（#52 滑入填充板，v1.1 定稿）
- **机制**（getcssscan #52 原版：`::after` 100%×100% 填板，`z-index:-1`，静止 `top/left` 错位 → hover `top:0 left:0` 滑归 + `transition .2s`）：底色从顶/左 6px 条透出 = 受光 bevel；底/右 6px 露出垫板。位移 = 原版 7px × 0.86 ≈ 6px（small: 5px），用户要求"稍微加大"后由 4px 调回（2026-09-25 定稿）。
- **灰阶映射**（v1.1.3 用户定稿）：**slab 用原版原色** `--slab: #ffe54c`（light/dark 均黄），文字恒黑 `--slab-ink #141414`。#52 的黄是本设计**唯一官方彩色豁免**（与"银灰全息"其余部分并存，字配色，色块只允许出现填板一处）；如需纯版，改回 `--slab: #dcdcdc`（其亮度等价灰）即整页回归 achromatic。
- **变体**：`.solid` 主操作钮 = slab 常驻原位（`top/left:0, transition:none`）无滑入；`.outline` 工具栏薄钮 = 无 slab（`::after:none`）+ bevel+ledge，hover 仅边框变 `--fg`。`[disabled]`：45% opacity，slab 冻结。
  - ⚠ **特异性坑**（v1.1.2 实测翻车）：变体规则 `.btn.small::after` 与hover规则 `.btn:hover::after` **特异性相同（0,1,2）但在源码中居后→覆盖 hover**，small 系按钮滑入全失效。凡"位移变体"+hover 滑归必须补 `.btn.small:hover::after, .btn.small.solid::after { top:0; left:0 }` 收尾，或把变体规则放到 hover 规则之前。
- 字规格取 #52 原值：`16px / 200 / 1px 字距`（light 下 wordmark 级细体，跟反色 fill 对比成立）。
- 与板材厚度的分工：按钮 = **滑入填板**（自带 bevel 幻觉，绝不加投影/ledge）；卡片 = **bevel+投影板材**；两者别再叠加第二层错位。

### Card / 报告卡（板材）
- **L2 板材**：`--card` 底 + `1px --line` 边框 + `box-shadow: var(--bevel), var(--sh-2)`。裸描边卡片禁止——板材必须带受光边和投影。
- 报告卡 hover：边框变 `--fg` + 掠光 `var(--sweep)` 以 `1.6s` 扫过（伪元素 translateX，hover-only，`prefers-reduced-motion` 下关闭）；仍不上浮。
- 静态信息卡（原则卡、表单卡）用 **L1**（`--sh-1`），比可点击卡薄一档 = 层级差。
- 大分数字 `58px / 800 / -2px`，`/100` 后缀降为 16px 灰色。

### Input
- `--fill` 底 + `1px --field-line` 边框 + `box-shadow: var(--sh-1)`（内嵌板材感）；focus 边框变 `--fg`（无外发光）。

### Step / Evidence（agent trace）
- `.step`：左 `2px --line` 竖线，段 label 小号大写。
- `.obs`：`--code` 底等宽 12px + **inset 硬阴影**（`inset 0 1px 3px rgba(0,0,0,.08)` light / `.45` dark = 凹槽凹进去，与凸出的板材方向相反），`max-height: 140px` 内滚。
- `.answer`：L2 板材 + `--fg` 全边框 + 左侧 3px 实线。
- 状态点（flicker dot）：只允许出现在"运行中/待命"状态标签，`@keyframes flicker` 阶梯式 opacity（step 而非 ease，像 CRT）；`prefers-reduced-motion` 下停住常亮。

### Modal
- **L3 板材**：遮罩 `--overlay`；`--card` 底 + `--fg` 边框 + `var(--sh-3)`（全页最厚投影）。
- 头部下 `1px --fg` 实线；底部操作区上 `1px --line`，右对齐，gap 8。
- 打开动效：`scale(.985)→1 + opacity .15s`（卡片从"投影态"定形，像全息成像凝固），仅此一个动效。

### Topbar / Footer / Agent 输入区
- Topbar：品牌在左（800 大写），右按钮组；下沿 `1px --fg` 实线 + `box-shadow: 0 1px 0 var(--fg)`（双线重影 = 顶栏比内容厚）。扫描幕布从顶栏下沿开始暗示"显示区"。
- Agent 输入区：L2 板材 + `border-top: 2px solid var(--fg)`；SEND 用 primary。
- Footer：上 `1px --fg` 实线，12px muted。

## 6. 深度厚重系统 + 全息设备（v1.1 新增）

### 6.1 升高栈（z-rhythm）
| 层 | 实体 | 投影 | 说明 |
|---|---|---|---|
| L0 | 页面 bg + 扫描幕布 + 底缘渐影 | — | 环境层 |
| L1 | 静态卡 / 输入槽 | `--sh-1` + bevel | 贴着地面 |
| L2 | 可点击卡 / agent 输入区 / toast | `--sh-2` + bevel | 抬起一档 |
| L3 | modal / 悬浮窗 | `--sh-3` + bevel | 最上浮 |
| 凹 | `.obs` / 代码槽 / severity 组 | inset 硬阴影 | 唯一"凹"的方向，与凸板永远成对出现 |

规则：**相邻不同层的板材之间垂直间距 ≥ 16px**（阴影要"落"得到）；L3 以下不允许叠 L2（modal 里放卡片 = 违和）。厚重 ≠ 全用最大投影，厚重 = 阴影层级差被看见。

### 6.2 硬肩（bevel）
每块板材上缘 1px 受光边（light 纯白 100% / dark 白 6%，另在 dark 用黑线补 1px 上缘轮廓）。这是"板材"与"上色矩形"的分界线——**只有带 bevel 的元素才算板材**。内凹元素（`.obs`）则只在**下缘**给受光边（凹面的光在底）。

### 6.3 全息设备层（holo eyewear，纯灰阶实现）
允许在 L0/L2/L3 上叠加的装饰语言，**全部 achromatic**，常量全在 §2：
1. **扫描幕布**：`--scanline` 作为 `html::before` 全屏 fixed 底纹（pointer-events:none），视口级呼吸（`opacity .5↔.8 / 9s`，reduced-motion 关闭）。暗示整个界面是一层显示介质。
2. **卡片掠光**：可点击卡 / L3 表面 hover 时 `--sweep` 斜掠一次（1.6s，translateX -60%→160%）。**只有"全息物体会响应"的东西才给掠光**（可点击卡、modal、输入区）。
3. **reticle 角标**：L3（modal）四角 10×10 的 L 形直角括号（2px 画中画边框），与 modal 边缘关系 6px——瞄准框语汇，代替花哨装饰。
4. **echo 双曝光标题**：仅三类位置——wordmark、报告大分、modal 标题：`text-shadow: 4px 0 0 var(--accent-soft)` 后立即反向 `text-shadow` 叠 `4px 0 0 var(--bg)` 制造双重残影；大分在 dark 下给 `0 0 18px rgba(236,236,236,.25)` 的窄光圈（**glow 全页只允许出现在这一处**）。halo 系数在 light 下压到几乎不见（0.08），因为 light 下白字在白底上、glow 无意义。
5. **flicker 状态点**：见 §5 Step，阶梯 opacity（`steps(2)`），CRT 质感，不用 ease 圆滑闪烁。
6. **错位入场**：首屏各 section 依次 `translateY(8px) + opacity / .4s`，stagger 80ms（只首屏一次，不是滚动监听）；load 时 modal 卡从"投影态"定形（见 §5 Modal）。

### 6.4 设备层纪律
- 装饰层**永远不允许**改变信息密度、对齐基线或文字可读性；关掉所有设备层（`[data-holo="off"]` 一条规则全灭）后页面必须仍然成立——这是验收标准。
- glow/掠光/幕布全部 `prefers-reduced-motion: reduce` 下停为静态。
- 不许用彩色的"全息蓝/紫"——本项目的全息是**银灰全息**，投影色永远从黑/白里取。
- 整页动效预算 ≤ 5 处（幕布呼吸、掠光、flicker 点、入场 stagger、modal 定形），加长即砍短。

## 7. Dark mode 规则

1. 只换 token 值，**不改组件结构**；切换入口 `:root[data-theme="dark"]`，默认值 = light，跟随 `prefers-color-scheme`，手动选择存 `localStorage`。
2. accent 反转；实心反白档（critical）随之反转，保证"最重的是最醒目的"。
3. 暗底下投影加重、遮罩加深（光线模型反过来了）。
4. 验证标准同 light：截图 + 目检，确认无彩色泄漏、无对比度掉到 `--muted` 之下。

## 8. Web 落地记录（2026-09-26）

- `app.py:BASE_CSS` 仍为全局样式单一来源，包含 light/dark、板材、黄色按钮填板、严重度、弹窗和设备层规则。
- `theme.js` 为首页、报告、NVIDIA 审查、演练和使用说明提供统一显示设置；沿用 `as-theme` / `as-holo` 存储键，存储不可用时当前页面仍可切换。
- `arena.css` 只负责演练布局与状态表现，引用共享 token。演练宽度上限 1440px，保持左右分屏；≤640px 改为上下分屏。黑方使用固定深灰面板，红方跟随主题，两者均保持无彩色相。
- 业务告警、成功、阻断、前置失败通过文字、填充、实线／虚线区分；删除原红绿蓝状态色。NVIDIA 报告边框也使用中性色。
- `build_help.py` 在生成时内嵌共享 CSS 与主题脚本，独立 HTML 不依赖网络资源。帮助页保留目录栏，宽度上限 1288px。
- toast 和 AGENT 悬浮入口已改用 CSS 类；表单、代码槽、等级标签全部使用 token。旧报告归档文件未重写，网页报告采用当前样式。
- HOLO OFF 关闭扫描线、掠光、角标、残影和入场效果；减少动态效果设置关闭动画及过渡。移动端按钮、选择器和折叠入口高度至少 44px。

## 9. Don't

- 彩色相 / 彩色渐变 / 玻璃拟态 / "全息蓝紫" 蹭科幻色
- 圆角 > 0（除 ≤2px 小徽章）、hover 上浮、ease 圆滑闪烁（状态只用 step 阶跃）
- 裸描边卡片（无 bevel 不算板材）、相邻同层板材硬贴、modal 里垫卡片
- 动效超预算（§6.4 的 5 处清单之外一律删掉）、彩色 emoji 当图标、营销化 hero

## Preview

`design_preview.html` — 顶栏可切 light/dark，含 token 色板、字阶、机械按钮、severity 五档、板材等级对照、报告卡、表单、trace、modal（reticle 角标）全组件样例 + 全息设备层实装（扫描幕布 / 掠光 / echo / flicker 点 / 入场 stagger）；顶栏 `HOLO OFF` 按钮一键关掉全部设备层做验收对照。

### 2026-09-26 交互细化

- HOLO ON：页面背景透出扫描纹理，视口有银灰定位角标，报告分数区／体检面板／攻防双栏有局部定位角标；OFF 关闭这些装饰。内容位置、板材阴影与正文不变。
- 体检入口使用 `.btn.primary.compact`：保留黄色填板，字号 13px、字重 400、padding 7px 14px，与普通 outline 按钮相同；手机端仍保持 44px 点击高度。
- `/checkup` 为独立体检入口，默认纯本机检查；运行中显示持续状态并防止当前页重复提交。体检报告增加首页／体检／报告面包屑和明确返回按钮。
