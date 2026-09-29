"""Declarative, synthetic security exercises; no external I/O or executable payloads."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

VERSION = "extended-tabletop-1.0"


def control(name, owner, description):
    return {"name": name, "owner": owner, "description": description}


def attack(key, name, goal, barriers, requires=()):
    return {"id": key, "name": name, "goal": goal,
            "barriers": list(barriers), "requires": list(requires)}


def business(key, name, barriers, allowed, denied):
    return {"id": key, "name": name, "barriers": list(barriers),
            "allowed": allowed, "denied": denied}


SCENARIOS = {
    "office_lateral": {
        "name": "办公内网横向移动", "eyebrow": "SCENARIO 03 / OFFICE LAN",
        "description": "从一台已失陷的虚拟办公终端出发，观察共享泄露、复用凭据、横向管理和外传之间的依赖。",
        "focus": "重点观察：阻止外传不能撤销已经发生的读取；限制远程登录可以切断后续横向管理。",
        "topology": ["失陷演示终端", "部门共享", "远程管理边界", "受管主机 / 演示接收端"],
        "setup": "红队已控制一台合成办公终端，并持有该终端的演示本地账号；不模拟最初入侵。",
        "assumptions": [
            "红队仅掌握演示本地凭据；凭据复用指其他主机恰好使用同一密码，不包含域管理员或有效授权账号失窃。",
            "分区策略拒绝失陷终端访问管理面，正常共享协作和获批管理通道仍在白名单内。",
            "外传只依赖本轮取得的演示共享文件；横向管理依赖前一步远程登录成功，没有其他路径。",
        ],
        "controls": {
            "share_auth": control("共享访问认证", "文件服务管理员", "取消匿名共享，保留已授权同事协作。"),
            "unique_credentials": control("各主机独立凭据", "终端管理员", "演示终端的本地密码不能用于其他受管主机。"),
            "management_segmentation": control("隔离远程管理面", "网络管理员", "只允许获批管理通道访问管理面，拒绝失陷演示终端。"),
            "least_privilege": control("远程账号最小权限", "终端管理员", "即使远程登录成功，该账号也不能修改受保护的服务。"),
            "egress_allowlist": control("外发目标白名单", "网络管理员", "拒绝向演示陌生接收端发送文件；不阻止已发生的共享读取。"),
            "detection": control("登录与文件行为审计", "白帽／管理员", "观察实际触发的合成尝试，只告警、不自动阻断。"),
            "disconnect_host": control("应急断开终端网络", "应急人员", "切断这台演示终端的网络，也中断正常协作和业务访问。"),
        },
        "everyday": ["share_auth", "detection"], "lockdown": "disconnect_host",
        "repair": ["share_auth", "unique_credentials", "management_segmentation", "least_privilege", "egress_allowlist", "detection"],
        "attacks": [
            attack("share_read", "匿名读取部门共享", "取得演示部门文件", ["share_auth", "disconnect_host"]),
            attack("remote_login", "尝试复用本地凭据", "登录另一台演示主机", ["unique_credentials", "management_segmentation", "disconnect_host"]),
            attack("lateral_admin", "尝试修改远程服务", "改变受保护服务的合成状态", ["least_privilege", "disconnect_host"], ["remote_login"]),
            attack("data_exfil", "尝试外传共享文件", "演示接收端获得已读取文件", ["egress_allowlist", "disconnect_host"], ["share_read"]),
        ],
        "business": [
            business("team_share", "授权同事共享协作", ["disconnect_host"], "授权账号可访问部门共享。", "终端断网，授权共享不可达。"),
            business("business_service", "访问正常办公业务", ["disconnect_host"], "正常办公站点仍在允许范围内。", "终端断网，办公业务不可达。"),
        ],
    },
    "phishing_identity": {
        "name": "钓鱼与会话盗用", "eyebrow": "SCENARIO 04 / IDENTITY & SESSION",
        "description": "比较诱导提交账号、密码登录和已有会话重放三条边界，观察多因素认证与会话保护各自的作用。",
        "focus": "重点观察：抗钓鱼认证保护本场景的密码登录，但不会自动撤销预先失窃的会话。",
        "topology": ["演示诱导链接", "用户 / 身份服务", "会话校验", "演示邮箱"],
        "setup": "红队提供一条合成诱导链接，并在独立分支持有一份预先失窃的演示会话。没有发送邮件或读取真实 Cookie。",
        "assumptions": [
            "链接核验假设用户拒绝当前未核验站点；不模拟误判或用户忽略提示。",
            "抗钓鱼认证假设已正确部署且授权用户拥有有效验证器，没有备用弱认证或账号找回绕过。",
            "会话重放独立于本轮密码采集；设备绑定和会话撤销假设在服务端逐次请求校验且无残留有效令牌。",
            "邮箱导出只建模密码登录分支；会话重放的目标仅为访问演示账户页，不覆盖全部后续权限。",
        ],
        "controls": {
            "verify_link": control("核验登录链接", "任务使用者", "在本用例中拒绝向未核验页面提交演示账号。"),
            "phishing_resistant_mfa": control("抗钓鱼多因素认证", "身份管理员", "仅持有演示密码不能完成新登录；不清除既有会话。"),
            "device_binding": control("会话设备绑定", "身份管理员", "服务端拒绝来自非绑定演示设备的会话请求。"),
            "revoke_sessions": control("撤销失窃会话", "应急人员", "使已知失窃会话失效；合法用户可以重新认证。"),
            "export_approval": control("敏感导出独立审批", "数据管理员", "拒绝本用例中的异常全量导出，保留正常读信与获批导出。"),
            "detection": control("身份行为审计", "白帽／管理员", "记录触发的合成身份行为；告警不自动使会话失效。"),
            "suspend_account": control("暂停演示账号", "应急人员", "拒绝账户访问，也中断合法登录与邮箱工作；不能阻止密码被提交到假页面。"),
        },
        "everyday": ["phishing_resistant_mfa", "detection"], "lockdown": "suspend_account",
        "repair": ["verify_link", "phishing_resistant_mfa", "device_binding", "revoke_sessions", "export_approval", "detection"],
        "attacks": [
            attack("password_capture", "诱导提交演示密码", "假页面获得用户提交的合成账号", ["verify_link"]),
            attack("account_login", "尝试使用已取得密码登录", "建立新的演示账户会话", ["phishing_resistant_mfa", "suspend_account"], ["password_capture"]),
            attack("session_replay", "重放预先失窃的演示会话", "从非绑定设备访问演示账户页", ["device_binding", "revoke_sessions", "suspend_account"]),
            attack("mailbox_export", "尝试全量导出演示邮箱", "新登录会话获得合成邮箱副本", ["export_approval", "suspend_account"], ["account_login"]),
        ],
        "business": [
            business("fresh_login", "合法用户重新认证", ["suspend_account"], "合法用户使用已配备的验证器建立新会话。", "账号暂停，合法认证后仍无法访问。"),
            business("normal_mail", "阅读与发送正常邮件", ["suspend_account"], "合法新会话可使用邮箱，不需要全量导出。", "账号暂停，正常邮箱工作不可用。"),
        ],
    },
    "api_authorization": {
        "name": "Web / API 越权访问", "eyebrow": "SCENARIO 05 / WEB & API",
        "description": "红队使用普通演示账号尝试读取他人对象、批量导出和管理操作，蓝队分别修复对象、功能与令牌边界。",
        "focus": "重点观察：登录成功不代表有权读取他人记录；对象权限和管理功能权限需要分别检查。",
        "topology": ["普通演示账号", "API 授权层", "对象 / 导出服务", "管理功能"],
        "setup": "红队具有自己的普通演示账号，并在独立用例中持有一份复制的演示令牌；不发送真实 HTTP 请求。",
        "assumptions": [
            "四个合成用例固定针对他人记录、同一批记录导出、管理写入和异设备令牌重放；不包含注入或真实漏洞利用。",
            "批量导出依赖前一步对象越权成功；导出范围校验不能替代单条对象鉴权。",
            "令牌发送方绑定在服务端验证；它不修复使用本人合法令牌进行的对象或功能越权。",
            "正常业务使用本人对象和授权操作；校验规则假设正确实现，无缓存、身份映射或旁路漏洞。",
        ],
        "controls": {
            "object_auth": control("逐对象权限校验", "后端开发者", "每次读取都核验请求者与对象的授权关系。"),
            "function_auth": control("管理功能权限校验", "后端开发者", "在服务端拒绝普通用户执行管理写入。"),
            "export_scope": control("导出范围二次校验", "数据服务维护者", "导出任务只接收当前账号被授权的记录。"),
            "token_binding": control("令牌发送方绑定", "身份管理员", "复制的演示令牌不能从未绑定设备重放。"),
            "detection": control("API 授权审计", "白帽／开发者", "记录触发的合成请求与判定；不替代服务端鉴权。"),
            "maintenance_mode": control("关闭业务 API", "应急人员", "暂停本场景全部 API，同时中断合法读取和提交。"),
        },
        "everyday": ["function_auth", "detection"], "lockdown": "maintenance_mode",
        "repair": ["object_auth", "function_auth", "export_scope", "token_binding", "detection"],
        "attacks": [
            attack("object_read", "尝试读取他人演示记录", "获得不属于当前账号的合成记录", ["object_auth", "maintenance_mode"]),
            attack("bulk_export", "尝试批量导出越权记录", "获得同一组未授权合成记录副本", ["export_scope", "maintenance_mode"], ["object_read"]),
            attack("admin_write", "普通账号尝试管理写入", "改变受保护的演示管理配置", ["function_auth", "maintenance_mode"]),
            attack("token_replay", "尝试异设备令牌重放", "复制的令牌被演示 API 接受", ["token_binding", "maintenance_mode"]),
        ],
        "business": [
            business("own_record", "读取本人授权记录", ["maintenance_mode"], "对象校验允许本人读取自己的演示记录。", "业务 API 已关闭，正常读取失败。"),
            business("normal_submit", "提交授权业务数据", ["maintenance_mode"], "普通账号可提交权限范围内的数据。", "业务 API 已关闭，正常提交失败。"),
        ],
    },
    "dependency_supply_chain": {
        "name": "依赖供应链投毒", "eyebrow": "SCENARIO 06 / DEPENDENCY SUPPLY CHAIN",
        "description": "沿着来源不符的依赖进入构建、安装钩子获得许可、合成资料外传及产物发布，逐层观察防护效果。",
        "focus": "重点观察：发布审批能挡住产物发布，但不能保护更早发生的构建资料外传。",
        "topology": ["演示依赖来源", "更新准入", "隔离构建边界", "演示发布仓库"],
        "setup": "红队提供一份来源与预先批准清单不符的合成依赖更新；没有下载软件包、运行安装钩子或发布产物。",
        "assumptions": [
            "来源校验绑定预先批准的发布身份、版本和内容哈希；不假定包自带签名就可信，也不覆盖受信发布者失陷。",
            "后续攻击均依赖本轮更新准入和钩子许可；禁用钩子不代表包在真实运行阶段必然安全。",
            "正常更新使用已批准、无需安装钩子的演示包，必要依赖可从允许的镜像取得。",
            "冻结更新阻断新版本安装，但已部署演示应用仍可提供服务；不模拟补丁积压的长期风险。",
        ],
        "controls": {
            "verify_provenance": control("校验批准来源与内容", "依赖维护者", "比对预先批准的身份、版本与哈希，拒绝当前不匹配更新。"),
            "disable_install_hooks": control("禁用安装钩子", "构建管理员", "拒绝演示依赖安装期间请求的额外进程动作。"),
            "build_egress": control("构建出网白名单", "构建管理员", "保留批准镜像，拒绝演示陌生接收端。"),
            "protected_release": control("发布产物独立审批", "发布管理员", "拒绝当前异常构建产物，允许批准的正常产物。"),
            "detection": control("构建与发布审计", "白帽／维护者", "记录触发的合成准入、钩子、外发与发布事件。"),
            "freeze_updates": control("冻结全部依赖更新", "应急人员", "阻止可疑与正常新版本安装；不停止已部署应用。"),
        },
        "everyday": ["protected_release", "detection"], "lockdown": "freeze_updates",
        "repair": ["verify_provenance", "disable_install_hooks", "build_egress", "protected_release", "detection"],
        "attacks": [
            attack("untrusted_install", "尝试引入来源不符的更新", "合成依赖通过更新准入", ["verify_provenance", "freeze_updates"]),
            attack("install_hook", "尝试申请安装钩子执行", "合成安装钩子获得策略许可", ["disable_install_hooks", "freeze_updates"], ["untrusted_install"]),
            attack("build_exfil", "尝试外传构建资料", "演示接收端获得合成构建标记", ["build_egress", "freeze_updates"], ["install_hook"]),
            attack("artifact_publish", "尝试发布受污染产物", "异常演示产物获得发布许可", ["protected_release", "freeze_updates"], ["install_hook"]),
        ],
        "business": [
            business("approved_update", "构建并发布正常依赖更新", ["freeze_updates"], "已批准的无钩子依赖可安装并完成正常发布审批。", "更新冻结，已批准的新版本也不能发布。"),
            business("existing_service", "已部署应用继续服务", [], "既有演示应用不依赖本轮更新，继续提供服务。", ""),
        ],
    },
    "agent_prompt_injection": {
        "name": "AI 智能体注入与数据外传", "eyebrow": "SCENARIO 07 / AI AGENT INJECTION",
        "description": "从一条被投毒的合成演示文件出发，观察注入指令、越权工具动作、沉默外传与回传控制点之间的依赖。",
        "focus": "重点观察：上下文归一化只能拦住本轮的输入注入，拦不住已经发生过的越权动作；出网白名单不阻止模型调用工具本身。",
        "topology": ["演示智能体", "被投毒演示文件", "敏感工具 / 工作区", "演示接收端"],
        "setup": "演示智能体在本用例中读取一份含有合成注入指令的演示文件；文件、工具调用与外发均为合成记录，不执行文件里的文字。",
        "assumptions": [
            "注入指本轮读取的文件里恰好含指向敏感工具的指令文本；不模拟模型权重、运行时自身失陷，也不覆盖图像或多模态注入。",
            "签名校验只保护工具结果回读；它不阻止输入侧注入，也不降低工具本身的权限。",
            "沉默外传依赖越权动作先取得资料；出网白名单只判定本轮的演示接收端，不代表生产环境的目标枚举。",
            "持续回传依赖注入成功且工具保留权限；撤销授权会让当轮已记录的动作仍保留告警。",
        ],
        "controls": {
            "context_sanitize": control("输入上下文归一化", "智能体平台管理员", "把演示文件内容标记为数据并剥离注入指令；不追溯历史轮次。"),
            "tool_allowlist": control("工具白名单与最小范围", "智能体平台管理员", "敏感资料工具只能访问授权工作区，拒绝本用例中的越权读取。"),
            "approval_gate": control("敏感动作人工确认", "任务使用者", "越权读取前弹窗确认；本用例假设演示操作者按预设拒绝。"),
            "response_signing": control("工具结果签名校验", "智能体平台管理员", "篡改后的工具结果回读不被接受；不改变输入侧注入。"),
            "egress_allowlist": control("外发目标白名单", "网络管理员", "拒绝向演示陌生接收端发送合成资料；不阻止已发生的读取。"),
            "detection": control("工具行为审计", "白帽／平台管理员", "记录触发的合成注入与工具行为；只告警、不自动阻断。"),
            "manual_review": control("停用演示智能体自动动作", "应急人员", "智能体只读模式，本轮与后续的工具动作全部暂停，也会暂停正常任务。"),
        },
        "everyday": ["context_sanitize", "detection"], "lockdown": "manual_review",
        "repair": ["context_sanitize", "tool_allowlist", "approval_gate", "response_signing", "egress_allowlist", "detection"],
        "attacks": [
            attack("injected_instruction", "注入指令进入上下文", "注入文本进入智能体上下文并被解读为指令", ["context_sanitize", "manual_review"]),
            attack("tool_overreach", "越权读取敏感工作区", "演示资料进入智能体上下文", ["tool_allowlist", "approval_gate", "manual_review"], ["injected_instruction"]),
            attack("silent_exfil", "尝试沉默外传资料", "演示接收端获得合成资料副本", ["egress_allowlist", "manual_review"], ["tool_overreach"]),
            attack("callback", "尝试建立持续回传", "演示接收端获得回传标记", ["response_signing", "manual_review"], ["injected_instruction", "tool_overreach"]),
        ],
        "business": [
            business("independent_task", "执行不读可疑文件的普通任务", ["manual_review"], "普通输入不含注入，工具在授权范围内正常完成。", "智能体只读，普通任务也无法执行工具。"),
            business("authorized_tools", "授权范围内的正常工作区工具", ["manual_review"], "白名单与确认不改变本人已授权工作区的正常读取。", "智能体只读，授权工具也暂停。"),
        ],
    },
    "device_guest_access": {
        "name": "访客设备与办公装置", "eyebrow": "SCENARIO 08 / DEVICE & GUEST ACCESS",
        "description": "一台未认证的演示访客设备进入访客网段，观察装置访问、段内互访、管理边界与内网外传之间的依赖。",
        "focus": "重点观察：隔离访客网段仍然开放段内互访；本地认证不替代段隔离。",
        "topology": ["演示访客设备", "访客网段", "演示打印机 / 段内装置", "内网资料区"],
        "setup": "演示访客设备已接入未部署逐设备认证的访客网段；访客网段默认允许段内互访但不直通内网。",
        "assumptions": [
            "访客网段不直通内网；内网外传依赖经段内装置与演示内网接收端，没有其他路径。",
            "设备访问认证拒绝未认证的演示设备；已认证设备仍可访问演示打印机。",
            "段内互访策略默认打开（访客设备互相可达）；关闭后访客设备之间不可达，也影响访客自带动机。",
            "装置仅打印不改变后端管理面；只有开放段内互访且装置在带内可管理时才可被控制。",
        ],
        "controls": {
            "segmentation": control("隔离访客网段", "网络管理员", "访客设备无法到达内网资料区与演示打印机；访客自带动机同时不可达。"),
            "device_auth": control("设备访问认证", "终端管理员", "拒绝本用例中未认证的演示设备访问装置。"),
            "guest_isolation": control("禁止访客段内互访", "网络管理员", "访客设备之间不可达；段内打印机为独立接入边界。"),
            "device_readonly": control("装置管理面只读", "终端管理员", "即使段内互访，也不能控制段内演示管理面。"),
            "internal_egress": control("内网外发白名单", "网络管理员", "拒绝向演示陌生内网接收端发送资料；不阻止已发生的打印与扫描。"),
            "detection": control("装置与接入审计", "白帽／管理员", "记录触发的合成接入与外发；只告警、不自动阻断。"),
            "disconnect_dev": control("应急断开演示设备", "应急人员", "切断这台演示设备的接入；授权同事从其他设备的工作不受影响。"),
        },
        "everyday": ["device_auth", "detection"], "lockdown": "disconnect_dev",
        "repair": ["segmentation", "device_auth", "guest_isolation", "device_readonly", "internal_egress", "detection"],
        "attacks": [
            attack("guest_printer", "未认证设备访问演示打印机", "演示打印机接受合成打印任务", ["segmentation", "device_auth", "disconnect_dev"]),
            attack("guest_peer", "访客设备互访段内装置", "段内装置对演示访客设备可达", ["guest_isolation", "disconnect_dev"], ["guest_printer"]),
            attack("segment_mgmt", "尝试取得段内管理面", "演示段内管理面状态被改变", ["device_readonly", "disconnect_dev"], ["guest_peer"]),
            attack("intranet_exfil", "尝试外传内网资料", "演示内网接收端获得合成资料", ["internal_egress", "disconnect_dev"], ["segment_mgmt"]),
        ],
        "business": [
            business("staff_print", "授权同事打印与扫描", [], "员工设备经内网独立通道访问打印服务，本场景策略不作用于内网通道。", ""),
            business("staff_office", "授权同事正常办公", [], "内网业务走独立内网通道，不受访客段互访与演示终端断开影响。", ""),
        ],
    },
    "cloud_bucket_key": {
        "name": "云配置密钥与存储桶", "eyebrow": "SCENARIO 09 / CLOUD & STORAGE",
        "description": "红队持有从一个泄露演示配置文件中读出的合成云密钥，观察桶列举、对象下载与跨区域恢复之间的依赖。",
        "focus": "重点观察：默认端点放行把最小权限凭证的作用范围放大到未授权对象；密钥泄露后凭证回收是唯一能同时切断两条分支的应急手段。",
        "topology": ["泄露演示配置文件", "云 API 端点", "演示存储桶", "跨区域恢复控制台"],
        "setup": "合成云密钥已从演示配置文件读出；本用例不发送真实云 API 请求，只推演凭证作用域的授权边界。",
        "assumptions": [
            "密钥泄露为合成前提，不模拟密码学破解；明文密钥一旦落入演示上下文即视为已抄走，依赖本机文件清空不会改变模型记忆。",
            "访问控制白名单只绑定已注册演示应用；新应用注册依赖审批，本用例中新应用尚未注册。",
            "下载白名单是对象级 ACL 检查；凭证曾成功列举不授予下载能力。",
            "跨区域恢复以桶列举成功为前置；恢复动作不依赖演示端点可达。",
        ],
        "controls": {
            "remove_plaintext": control("移除配置文件明文密钥", "平台运营者", "工作区不再保留可抄走的演示明文密钥；已抄走的副本不因此消失。"),
            "endpoint_binding": control("端点与客户端绑定", "平台运营者", "未注册演示客户端的默认端点请求被拒绝。"),
            "ram_policy": control("最小权限凭证", "平台运营者", "本用例凭证不能列举未授权对象。"),
            "download_allowlist": control("对象下载白名单", "数据管理员", "越权列举成功的对象也不能被下载，除非在授权列表内。"),
            "backup_scope": control("跨区域恢复访问控制", "平台运营者", "恢复操作需要演示恢复角色；普通凭证不能触发。"),
            "detection": control("云审计追踪", "白帽／平台管理员", "记录触发的合成 API 调用与判定；不自动中断 API。"),
            "revoke_key": control("回收全部演示凭证", "应急人员", "所有基于该演示密钥的调用被拒绝；依赖它们的正常同步任务同时中断。"),
        },
        "everyday": ["ram_policy", "detection"], "lockdown": "revoke_key",
        "repair": ["remove_plaintext", "endpoint_binding", "ram_policy", "download_allowlist", "backup_scope", "detection"],
        "attacks": [
            attack("key_read", "读取演示配置文件密钥", "合成密钥进入红队上下文", ["remove_plaintext", "revoke_key"]),
            attack("bucket_list", "尝试列举未授权存储桶", "获得未授权演示对象清单", ["endpoint_binding", "ram_policy", "revoke_key"], ["key_read"]),
            attack("object_download", "尝试下载越权对象", "获得未授权合成对象副本", ["download_allowlist", "revoke_key"], ["bucket_list"]),
            attack("cross_region", "尝试触发跨区域恢复", "演示恢复控制台接受合成恢复请求", ["backup_scope", "revoke_key"], ["bucket_list"]),
        ],
        "business": [
            business("sync_job", "正常云端同步任务", ["revoke_key"], "授权同步任务使用已注册客户端与授权凭证。", "凭证回收后授权同步任务同时中断，需要人工恢复操作。"),
            business("legal_download", "授权账号下载本人对象", ["revoke_key"], "白名单允许授权应用下载其对象清单内的实际对象。", "凭证回收后本人下载也暂不可用。"),
        ],
    },
    "ops_agent_broker": {
        "name": "运维智能体横幅策反", "eyebrow": "SCENARIO 10 / OPS AGENT COMPROMISE",
        "description": "一个有权限 SSH 与凭据库的演示运维智能体连上一台横幅被投毒的演示主机，观察注入指令、建号提权、凭据库读取与端口转发外泄之间的依赖。",
        "focus": "重点观察：命令白名单挡不住语义合法的组合动作（建号、读凭据、转发端口各自都在合法命令表里）；输出脱敏是唯一不依赖模型自律的出口闸。",
        "topology": ["演示运维智能体", "被投毒横幅的演示主机", "演示凭据库", "演示外部接收端"],
        "setup": "演示主机的登录横幅与命令回显里埋有合成注入指令；智能体的工具面覆盖远程执行、凭据库读写与端口转发，全部为合成记录，不建立真实连接。",
        "assumptions": [
            "横幅与命令输出注入为合成前提，不模拟模型权重或智能体运行时自身失陷。",
            "智能体把主机回显当作可信上下文是本用例的默认行为；工具白名单按命令名匹配，不检查参数语义。",
            "凭据库读取走的是智能体自身已授权的凭据接口；不模拟凭据库自身被爆破。",
            "端口转发外泄依赖前两步已成功；接收端为演示地址，不代表生产目标枚举。",
        ],
        "controls": {
            "output_quarantine": control("主机输出脱敏隔离", "平台运营者", "横幅与命令回显标记为数据并剥离指令文本；不追溯已执行的动作。"),
            "param_policy": control("命令参数级策略", "平台运营者", "useradd 不得进 sudo 组、凭据库读取限本人条目、转发目标须在允许清单；不改变命令名白名单本身。"),
            "session_confirm": control("写动作逐步人工确认", "运维负责人", "建号、写凭据、开转发前人工确认；本用例假设负责人按预设拒绝。"),
            "cred_vault_scope": control("凭据库分域授权", "数据管理员", "演示智能体凭据只覆盖运维域，读不到生产域条目；不阻止运维域内已授权读取。"),
            "egress_allowlist": control("转发与出网白名单", "网络管理员", "端口转发目标与出网目的地受限；不阻止已完成的建号与读取。"),
            "detection": control("会话行为审计", "白帽／平台运营者", "记录触发的合成注入与工具动作；只告警、不自动阻断。"),
            "kill_switch": control("吊销智能体凭据并停用", "应急人员", "智能体凭据全部吊销，任何新动作被拒绝；正在跑的例行巡检同时中断。"),
        },
        "everyday": ["param_policy", "detection"], "lockdown": "kill_switch",
        "repair": ["output_quarantine", "param_policy", "session_confirm", "cred_vault_scope", "egress_allowlist", "detection"],
        "attacks": [
            attack("banner_injection", "投毒横幅进入智能体上下文", "合成注入指令被智能体当作可执行任务", ["output_quarantine", "kill_switch"]),
            attack("rogue_account", "在被管主机创建后门账号", "演示主机出现带 sudo 组的合成账号", ["param_policy", "session_confirm", "kill_switch"], ["banner_injection"]),
            attack("vault_read", "批量读取演示凭据库", "智能体上下文获得越权合成凭据", ["cred_vault_scope", "session_confirm", "kill_switch"], ["banner_injection"]),
            attack("exfil_tunnel", "端口转发外泄合成凭据", "演示接收端获得合成凭据副本", ["egress_allowlist", "param_policy", "kill_switch"], ["vault_read"]),
        ],
        "business": [
            business("routine_check", "例行巡检与日志查看", ["kill_switch"], "只读巡检不触发参数限制，输出脱敏不影响阅读。", "凭据吊销后智能体连不上被管主机，巡检停摆。"),
            business("approved_change", "已批准的部署变更", ["kill_switch"], "已批准的变更天然通过人工确认环节，参数策略只限高危组合。", "吊销后变更全部中断。"),
        ],
    },
}


def catalog(scenario):
    spec = SCENARIOS[scenario]
    return deepcopy({
        "scenario": scenario, "version": VERSION, "name": spec["name"],
        "eyebrow": spec["eyebrow"], "description": spec["description"], "focus": spec["focus"],
        "controls_note": "所有开关仅改变虚拟策略。全面封锁包含应急停用措施；自动修复保留当前停用状态，不擅自恢复业务。",
        "hardened_label": "全面封锁", "controls": spec["controls"],
        "presets": {name: {key: name == "hardened" or (name == "everyday" and key in spec["everyday"])
                           for key in spec["controls"]} for name in ("exposed", "everyday", "hardened")},
        "attack_goals_total": len(spec["attacks"]), "business_total": len(spec["business"]),
        "topology": [{"name": name} for name in spec["topology"]],
        "attack_goals": [{"id": item["id"], "name": item["name"], "requires": item["requires"]} for item in spec["attacks"]],
        "assumptions": [
            "全部账号、主机、记录和事件均为合成数据；不读取真实凭据、不调用网络、文件或进程工具。",
            spec["setup"], *spec["assumptions"],
            "告警仅覆盖前置条件满足而实际触发的合成尝试；前置失败的下游目标标为未触发，不虚构请求或告警。",
            "策略均假设正确执行；计数只描述这四个固定用例，不代表真实攻击成功率或完整防护覆盖。",
        ],
    })


def _run(spec, controls):
    events, outcomes, resolved = [], [], {}

    def emit(side, action, result, detail, evidence):
        eid = f"E{len(events)+1:02d}"
        events.append({"id": eid, "tick": len(events)+1, "side": side, "action": action,
                       "result": result, "detail": detail, "evidence": evidence, "synthetic": True})
        return eid

    emit("black", "确认合成场景起点", "accepted", spec["setup"], {"setup_only": True, "actual_actions_executed": 0})
    for item in spec["attacks"]:
        unmet = [key for key in item["requires"] if not resolved[key]["success"]]
        barriers = [key for key in item["barriers"] if controls[key]]
        attempted = not unmet
        success = attempted and not barriers
        reasons = (["前置目标未达成：" + "、".join(resolved[key]["name"] for key in unmet)] if unmet else
                   ["生效防护：" + "、".join(spec["controls"][key]["name"] for key in barriers)] if barriers else [])
        eid = emit("black", item["name"], "skipped" if unmet else "success" if success else "blocked",
                   item["goal"] + ("：规则模型中达成。" if success else "：" + "；".join(reasons) + "。"),
                   {"goal": item["goal"], "goal_achieved": success, "attempted": attempted,
                    "requires": {key: resolved[key]["success"] for key in item["requires"]},
                    "prerequisite_events": [resolved[key]["evidence_id"] for key in item["requires"]],
                    "unmet_prerequisites": unmet, "active_barriers": barriers,
                    "rule": {"all_goals_succeeded": item["requires"], "no_active_controls": item["barriers"]},
                    "actual_actions_executed": 0})
        detected = controls["detection"] and attempted
        emit("red", "检测与核验 · " + item["name"], "skipped" if unmet else "alert" if detected else "unobserved",
             "前置目标未达成，无下游请求或告警；裁判保留依赖判定。" if unmet else
             "合成审计记录本次尝试；告警与阻断独立判定。" if detected else "未开启行为审计；裁判保留合成判定。",
             {"related_event": eid, "alert": detected, "attempt_observed": detected,
              "sensor": "synthetic policy audit" if detected else None})
        outcome = {"id": item["id"], "name": item["name"], "goal": item["goal"], "success": success,
                   "attempted": attempted, "detected": detected, "evidence_id": eid,
                   "blocked_by": barriers, "unmet_prerequisites": unmet,
                   "recommended_controls": list(item["barriers"])}
        outcomes.append(outcome)
        resolved[item["id"]] = outcome
    checks = []
    for item in spec["business"]:
        passed = not any(controls[key] for key in item["barriers"])
        check = {"id": item["id"], "name": item["name"], "pass": passed,
                 "evidence": item["allowed"] if passed else item["denied"]}
        checks.append(check)
        emit("judge", check["name"], "pass" if passed else "regression", check["evidence"],
             {"test_id": check["id"], "pass": passed, "attack_alert": False})
    return {"controls": dict(controls), "outcomes": outcomes, "events": events, "business_checks": checks,
            "metrics": {"attack_goals_achieved": sum(x["success"] for x in outcomes),
                        "attack_goals_total": len(outcomes), "detected_attempts": sum(x["detected"] for x in outcomes),
                        "business_passed": sum(x["pass"] for x in checks), "business_total": len(checks)}}


def simulate(scenario, controls):
    spec, selected = SCENARIOS[scenario], catalog(scenario)
    repaired = {**controls, **{key: True for key in spec["repair"]}}
    identity = json.dumps({"scenario": scenario, "version": VERSION, "controls": controls}, sort_keys=True)
    return {"ok": True, "scenario": scenario, "scenario_name": spec["name"], "version": VERSION,
            "run_id": hashlib.sha256(identity.encode()).hexdigest()[:16], "mode": "deterministic_simulation",
            "network_packets_sent": 0, "untrusted_code_executed": False,
            "roles": {"black": "黑客", "red": "白帽", "judge": "规则裁判"},
            "assumptions": selected["assumptions"], "before": _run(spec, controls), "after": _run(spec, repaired),
            "repair": [{"control": key, **spec["controls"][key]} for key in spec["controls"] if repaired[key] != controls[key]],
            "limitations": "预设攻击依赖与策略边界的确定性推演，不是实网攻击、动态漏洞复现或 NVIDIA 扫描结论。"}
