"""Pure, deterministic public-Wi-Fi tabletop simulation. No sockets or commands.

All hosts, artifacts, observations and time ticks are synthetic. The rule set
models declared preconditions, not a prediction of a real network's security.
"""
from __future__ import annotations

import hashlib
import json
import skill_scenario

VERSION = "wifi-tabletop-1.0"
CONTROLS = {
    "client_isolation": {"name": "访客设备隔离", "owner": "热点管理员", "description": "阻断本场景中同一热点的客户端互访；保留上网。"},
    "share_auth": {"name": "共享访问认证", "owner": "设备使用者", "description": "取消匿名读取；合法用户仍可用账号访问。"},
    "arp_guard": {"name": "ARP 欺骗防护", "owner": "网络管理员", "description": "假设网关绑定校验有效，拒绝本场景中的伪造绑定。"},
    "https_only": {"name": "严格 HTTPS", "owner": "设备使用者", "description": "业务仅用 HTTPS，证书校验失败即停止，不忽略警告。"},
    "vpn": {"name": "可信全隧道 VPN", "owner": "设备使用者", "description": "假设隧道已建立、含 DNS 且无旁路；不改变本地共享权限。"},
    "verify_portal": {"name": "核验认证页身份", "owner": "设备使用者", "description": "用户拒绝在未核验域名的认证页提交账号；HTTPS 本身不证明网站可信。"},
    "detection": {"name": "开启红方监测", "owner": "白帽／管理员", "description": "观察合成服务日志和终端遥测；只告警，不自动阻断。"},
}
PRESETS = {
    "exposed": {key: False for key in CONTROLS},
    "everyday": {key: key in ("https_only", "share_auth", "detection") for key in CONTROLS},
    "hardened": {key: True for key in CONTROLS},
}
ATTACKS = (
    ("share_read", "未授权共享访问", "读取演示共享文件", ("client_isolation", "share_auth")),
    ("http_intercept", "明文流量泄露", "取得演示 HTTP 会话标记", ("client_isolation", "arp_guard", "https_only", "vpn")),
    ("dns_redirect", "DNS 重定向", "业务请求到达伪造站点", ("client_isolation", "arp_guard", "https_only", "vpn")),
    ("portal_phish", "伪造认证页诱导", "取得用户主动提交的演示账号", ("verify_portal",)),
)


def catalog(scenario="public_wifi"):
    if scenario == "malicious_skill":
        return skill_scenario.catalog()
    if scenario != "public_wifi":
        raise ValueError("未知场景。")
    return {
        "scenario": "public_wifi", "version": VERSION,
        "name": "公共 Wi-Fi 同网攻防", "eyebrow": "SCENARIO 01 / PUBLIC WI-FI",
        "description": "同一个公共 Wi-Fi 下，黑方尝试四个预设攻击目标，红方监测并加固，再用相同场景复测。两侧随事件流同步更新。",
        "controls_note": "开关只修改虚拟场景。默认日常配置启用 HTTPS、共享认证与监测。",
        "attack_goals_total": 4, "business_total": 2,
        "controls": CONTROLS, "presets": PRESETS,
        "topology": [
            {"id": "black", "name": "黑方 · 同网访客", "address": "192.0.2.66"},
            {"id": "ap", "name": "咖啡店热点", "address": "192.0.2.1"},
            {"id": "client", "name": "普通用户笔记本", "address": "192.0.2.20"},
            {"id": "share", "name": "演示共享设备", "address": "192.0.2.30"},
            {"id": "service", "name": "正常业务站点", "address": "service.example"},
        ],
        "assumptions": [
            "这是规则推演，所有 IP、事件、文件与账号均为合成数据；不发送网络探测或攻击报文。",
            "黑方已接入同一热点，未控制网关、终端或证书颁发机构；共享服务与访客处于同一二层域。",
            "HTTP 窃听和 DNS 重定向都以伪造网关绑定成功为前提；不表示同 Wi-Fi 就能读取 HTTPS。",
            "伪造认证页通过用户可见的诱导链接呈现，域名为独立假站点；不要求局域网直连，模拟用户是否提交。",
            "全隧道 VPN 与网关校验均假定正确部署；未模拟无线破解、真实漏洞利用、恶意热点或管理员被攻陷。",
        ],
    }


def validate(body):
    if not isinstance(body, dict) or set(body) - {"scenario", "controls"}:
        raise ValueError("仅接受 scenario 和 controls；本演练不接受真实目标或命令。")
    scenario = body.get("scenario", "public_wifi")
    if not isinstance(scenario, str) or scenario not in ("public_wifi", "malicious_skill"):
        raise ValueError("未知场景。")
    selected = catalog(scenario)
    controls = body.get("controls", {})
    if not isinstance(controls, dict) or set(controls) - set(selected["controls"]):
        raise ValueError("未知防护设置。")
    if any(type(value) is not bool for value in controls.values()):
        raise ValueError("防护开关必须为布尔值。")
    return {**selected["presets"]["everyday"], **controls}


def _run(controls):
    events, outcomes = [], []

    def emit(side, action, result, detail, evidence):
        event = {"id": f"E{len(events)+1:02d}", "tick": len(events)+1,
                 "side": side, "action": action, "result": result,
                 "detail": detail, "evidence": evidence, "synthetic": True}
        events.append(event)
        return event["id"]

    peer = not controls["client_isolation"]
    mitm = peer and not controls["arp_guard"]
    emit("black", "观察同网设备", "reachable" if peer else "blocked",
         "可到达演示终端与共享设备。" if peer else "热点隔离阻断客户端互访。",
         {"peer_reachable": peer, "source": "192.0.2.66", "destination": "192.0.2.30"})
    emit("black", "尝试改变网关绑定", "accepted" if mitm else "blocked",
         "规则允许黑方成为模拟中间节点。" if mitm else "隔离或绑定校验阻断该路径。",
         {"gateway_binding_changed": mitm, "rule": "peer_reachable AND NOT arp_guard"})
    for action, title, goal, blockers in ATTACKS:
        prevented = [key for key in blockers if controls[key]]
        succeeded = not prevented
        evidence = {"goal": goal, "goal_achieved": succeeded, "active_barriers": prevented,
                    "rule": "NOT ANY(" + ", ".join(blockers) + ")"}
        if action == "share_read":
            evidence.update({"anonymous_read": succeeded, "artifact": "DEMO-SHARED-NOTE" if succeeded else None})
        elif action == "http_intercept":
            evidence.update({"on_path": mitm, "plaintext_observed": succeeded,
                             "artifact": "DEMO-SESSION-NOT-A-SECRET" if succeeded else None})
        elif action == "dns_redirect":
            evidence.update({"dns_answer_changed": mitm and not controls["vpn"],
                             "request_reached_fake_service": succeeded,
                             "certificate_checked": controls["https_only"]})
        else:
            evidence.update({"lure_presented": True, "site": "portal-login.example",
                             "user_submitted_demo_account": succeeded,
                             "independent_of_local_peer_reachability": True})
        attack_id = emit("black", title, "success" if succeeded else "blocked",
                         goal + ("：本轮达成。" if succeeded else "：本轮未达成。"), evidence)
        detected = controls["detection"]
        emit("red", "检测与核验 · " + title, "alert" if detected else "unobserved",
             "演示传感器记录尝试；告警不代表攻击已被阻止。" if detected else "本轮未启用监测；裁判仍保留合成事件。",
             {"related_event": attack_id, "alert": detected,
              "sensor": "synthetic service and endpoint telemetry" if detected else None})
        outcomes.append({"id": action, "name": title, "goal": goal, "success": succeeded,
                         "detected": detected, "evidence_id": attack_id,
                         "blocked_by": prevented, "recommended_controls": list(blockers)})
    business = [
        {"id": "normal_https", "name": "访问正常 HTTPS 业务", "pass": True,
         "evidence": "策略模型保留网关出口；可信证书业务成功，无攻击告警。"},
        {"id": "authorized_share", "name": "同网授权共享协作", "pass": peer,
         "evidence": "客户端隔离使本地协作不可达；需要独立受管协作网络。" if not peer else "授权用户可读取演示共享；匿名认证限制不影响其身份。"},
    ]
    for check in business:
        emit("judge", check["name"], "pass" if check["pass"] else "regression", check["evidence"],
             {"test_id": check["id"], "pass": check["pass"], "attack_alert": False})
    return {"controls": dict(controls), "outcomes": outcomes, "events": events, "business_checks": business,
            "metrics": {"attack_goals_achieved": sum(x["success"] for x in outcomes),
                        "attack_goals_total": len(outcomes),
                        "detected_attempts": sum(x["detected"] for x in outcomes),
                        "business_passed": sum(x["pass"] for x in business),
                        "business_total": len(business)}}


def simulate(body):
    controls = validate(body)
    if body.get("scenario", "public_wifi") == "malicious_skill":
        return skill_scenario.simulate(controls)
    # Preserve local collaboration: strengthen endpoints before blanket isolation.
    hardened = {**controls, "share_auth": True, "https_only": True,
                "verify_portal": True, "detection": True}
    before, after = _run(controls), _run(hardened)
    identity = json.dumps({"version": VERSION, "controls": controls}, sort_keys=True)
    return {"ok": True, "scenario": "public_wifi", "version": VERSION,
            "scenario_name": catalog()["name"],
            "run_id": hashlib.sha256(identity.encode()).hexdigest()[:16],
            "mode": "deterministic_simulation", "network_packets_sent": 0,
            "roles": {"black": "黑客", "red": "白帽", "judge": "规则裁判"},
            "assumptions": catalog()["assumptions"], "before": before, "after": after,
            "repair": [{"control": key, **CONTROLS[key]} for key in CONTROLS
                       if hardened[key] != controls[key]],
            "limitations": "计数只描述四个预设目标；不是实网攻防成功率、漏洞扫描结论或安全评分。"}


def presentation_events(result):
    """Ordered synthetic events for live display; no attack execution or clock.

    The deterministic result is computed first. The web transport paces these
    events for readability and sends the complete evidence only at the end.
    """
    sequence = 0

    def message(kind, **payload):
        nonlocal sequence
        sequence += 1
        return {"seq": sequence, "type": kind, "run_id": result["run_id"], "scenario": result["scenario"], **payload}

    yield message("start", mode=result["mode"], total_events=len(result["before"]["events"]) + len(result["after"]["events"]) + len(result["repair"]))
    for phase in ("before", "after"):
        if phase == "after":
            yield message("phase", phase="repair")
            for repair in result["repair"]:
                yield message("repair", phase="repair", repair=repair)
        yield message("phase", phase=phase)
        for event in result[phase]["events"]:
            yield message("event", phase=phase, event=event)
    yield message("complete", result=result)
