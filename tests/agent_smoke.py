import json, time, urllib.request, threading

BASE = "http://127.0.0.1:8787"

def post(url, body):
    return json.loads(urllib.request.urlopen(urllib.request.Request(
        url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"}), timeout=90).read())

j = post(BASE + "/api/agent/new", {"message": "最近一份报告里最严重的问题是什么？一句话说清并给修复方向"})
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

t = threading.Thread(target=reader, daemon=True)
t.start()
t0 = time.time()
while t.is_alive() and len(events) < 40 and time.time() - t0 < 560:
    time.sleep(0.4)

for e in events:
    k = e["type"]
    if k == "think":
        print(f"  think[{e.get('step')}]: {e['thought'][:90]}", flush=True)
    elif k == "tool_call":
        print(f"  tool: {e['tool']} {json.dumps(e['input'], ensure_ascii=False)}", flush=True)
    elif k == "tool_result":
        print(f"    obs: {(e['obs'] or '')[:100].replace(chr(10), ' ')}", flush=True)
    elif k == "ask":
        print(f"  ASK: {e['question']} | {e['choices']}", flush=True)
    elif k == "final":
        print(f"  FINAL: {e['text'][:300]}", flush=True)
    elif k == "error":
        print("  ERR:", e["text"], flush=True)
print(f"total {time.time() - t0:.0f}s, events={len(events)}", flush=True)
post(BASE + "/api/agent/close", {"agent_id": aid})
