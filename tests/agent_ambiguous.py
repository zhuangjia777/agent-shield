import json, time, urllib.request, threading

BASE = "http://127.0.0.1:8787"

def post(url, body):
    return json.loads(urllib.request.urlopen(urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}), timeout=120).read())

# 没有明确指向哪个样本/报告 -> 期望 Agent Ask 用户选
q = "评估一下它，告诉我分数。"
j = post(BASE + "/api/agent/new", {"message": q})
aid = j["agent_id"]
print("agent:", aid, flush=True)
stream = urllib.request.urlopen(urllib.request.Request(BASE + f"/api/agent/{aid}/event"), timeout=600)
events = []
chose = {"done": False}

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
        if d.get("type") == "ask" and not chose["done"]:
            chose["done"] = True
            choice = (d.get("choices") or ["vulnerable-skill"])[0]
            print(f"  [autouser] 被问到「{d['question'][:40]}」-> 选 {choice}", flush=True)
            time.sleep(0.4)
            post(BASE + f"/api/agent/{aid}/answer", {"text": choice})

t = threading.Thread(target=reader, daemon=True)
t.start()
t0 = time.time()
while t.is_alive() and len(events) < 50 and time.time() - t0 < 570:
    time.sleep(0.4)

for e in events:
    k = e["type"]
    if k == "think":
        print(f"  think: {e['thought'][:90]}", flush=True)
    elif k == "tool_call":
        print(f"  tool: {e['tool']} {json.dumps(e['input'], ensure_ascii=False)}", flush=True)
    elif k == "ask":
        print(f"  ASK: {e['question']} | choices={e['choices']}", flush=True)
    elif k == "ask_answered":
        print(f"  answered: {e['answer']}", flush=True)
    elif k == "final":
        print(f"  FINAL: {e['text'][:240]}", flush=True)
    elif k == "error":
        print("  ERR:", e["text"], flush=True)
print(f"total {time.time() - t0:.0f}s, events={len(events)}", flush=True)
post(BASE + "/api/agent/close", {"agent_id": aid})
