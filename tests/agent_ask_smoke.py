import json, time, urllib.request, threading

BASE = "http://127.0.0.1:8787"

def post(url, body):
    return json.loads(urllib.request.urlopen(urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}), timeout=120).read())

# 构造需要用户选择的场景：三份样本报告都在，问"哪个报告的问题最严重"需要选择
j = post(BASE + "/api/agent/new", {"message": "评估一下那个有漏洞的 demo skill，然后告诉我分数"})
aid = j["agent_id"]
print("agent:", aid, flush=True)
stream = urllib.request.urlopen(urllib.request.Request(BASE + f"/api/agent/{aid}/event"), timeout=600)
events = []

def reader():
    for raw in stream:
        line = raw.decode().strip()
        if not line.startswith("data:"):
            continue
        d = json.loads(line[5:])
        if d.get("type") == "ping":
            continue
        events.append(d)
        if d.get("type") in ("done", "error"):
            break
        if d.get("type") == "ask" and not asked_sent:
            asked_sent = True
            # 用户选第一个选项
            choice = (d.get("choices") or ["vulnerable-skill"])[0]
            time.sleep(0.5)
            post(BASE + f"/api/agent/{aid}/answer", {"text": choice})
            print(f"  [autouser] 选择: {choice}", flush=True)

asked_sent = False
t = threading.Thread(target=reader, daemon=True)
t.start()
t0 = time.time()
while t.is_alive() and len(events) < 50 and time.time() - t0 < 570:
    time.sleep(0.4)

for e in events:
    k = e["type"]
    if k == "think":
        print(f"  think[{e.get('step')}]: {e['thought'][:90]}", flush=True)
    elif k == "tool_call":
        print(f"  tool: {e['tool']} {json.dumps(e['input'], ensure_ascii=False)}", flush=True)
    elif k == "tool_result":
        print(f"    obs: {(e['obs'] or '')[:110].replace(chr(10), ' ')}", flush=True)
    elif k == "ask":
        print(f"  ASK: {e['question']} | {e['choices']}", flush=True)
    elif k == "ask_answered":
        print(f"  answered: {e['answer']}", flush=True)
    elif k == "final":
        print(f"  FINAL: {e['text'][:280]}", flush=True)
    elif k == "error":
        print("  ERR:", e["text"], flush=True)
print(f"total {time.time() - t0:.0f}s, events={len(events)}", flush=True)
post(BASE + "/api/agent/close", {"agent_id": aid})
