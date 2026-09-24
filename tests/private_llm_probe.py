"""Opt-in live compatibility probe. Sends synthetic prompts to config.json only.

No sample files, credentials, model answers, or raw HTTP errors enter the report.
Usage: python tests/private_llm_probe.py
"""
import json
from pathlib import Path
import time
import urllib.request

ROOT = Path(__file__).resolve().parent.parent


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    cfg = json.loads((ROOT / "config.json").read_text())["cloud"]
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    results = {"model_requested": cfg["model"], "synthetic_inputs_only": True, "checks": {}}

    def request(path, payload=None):
        req = urllib.request.Request(
            cfg["base_url"].rstrip("/") + path,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Authorization": "Bearer " + cfg["api_key"], "Content-Type": "application/json"},
        )
        return opener.open(req, timeout=25)

    def check(name, run):
        start = time.monotonic()
        try:
            result = run()
        except Exception as exc:
            result = {"pass": False, "error_type": type(exc).__name__,
                      "http_status": getattr(exc, "code", None),
                      "os_errno": getattr(getattr(exc, "reason", None), "errno", None)}
        result["elapsed_s"] = round(time.monotonic() - start, 2)
        results["checks"][name] = result
        print(json.dumps({name: result}), flush=True)
        return result["pass"]

    def models():
        with request("/models") as response:
            ids = [m.get("id") for m in json.load(response).get("data", [])]
        return {"pass": cfg["model"] in ids, "model_count": len(ids)}

    base = {"model": cfg["model"], "temperature": 0, "max_tokens": 256,
            "chat_template_kwargs": {"enable_thinking": False}}

    def json_chat():
        payload = {**base, "messages": [{"role": "user", "content":
                   'Reply with exactly this JSON and no markdown: {"status":"ok","value":7}'}]}
        with request("/chat/completions", payload) as response:
            data = json.load(response)
        content = data["choices"][0]["message"].get("content", "")
        parsed = json.loads(content)
        return {"pass": parsed == {"status": "ok", "value": 7},
                "served_model": data.get("model"), "finish_reason": data["choices"][0].get("finish_reason")}

    def stream():
        payload = {**base, "stream": True, "messages": [{"role": "user", "content": "Reply with exactly STREAM_OK."}]}
        chunks, text, done = 0, "", False
        with request("/chat/completions", payload) as response:
            for raw in response:
                line = raw.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                body = line[5:].strip()
                if body == "[DONE]":
                    done = True
                    break
                d = json.loads(body)
                for choice in d.get("choices", []):
                    piece = choice.get("delta", {}).get("content")
                    if piece:
                        text += piece
                        chunks += 1
        return {"pass": done and "STREAM_OK" in text, "content_chunks": chunks, "done_event": done}

    def tools():
        payload = {**base, "messages": [{"role": "user", "content": "Use lookup_demo_status for case_id demo-001. Do not invent a result."}],
                   "tools": [{"type": "function", "function": {"name": "lookup_demo_status",
                    "description": "Read the status of a synthetic test case.",
                    "parameters": {"type": "object", "properties": {"case_id": {"type": "string"}}, "required": ["case_id"]}}}],
                   "tool_choice": {"type": "function", "function": {"name": "lookup_demo_status"}}}
        with request("/chat/completions", payload) as response:
            data = json.load(response)
        calls = data["choices"][0]["message"].get("tool_calls") or []
        valid = any(c.get("function", {}).get("name") == "lookup_demo_status" and
                    json.loads(c["function"]["arguments"]) == {"case_id": "demo-001"} for c in calls)
        return {"pass": valid, "tool_call_count": len(calls), "tool_executed": False}

    if check("models", models):
        check("json_chat", json_chat)
        check("sse_stream", stream)
        check("native_tool_call_response", tools)
    out = ROOT / "reports" / "private-llm-check-20260924"
    out.mkdir(parents=True, exist_ok=True)
    (out / "compatibility.json").write_text(json.dumps(results, ensure_ascii=False, indent=2))
    return 0 if len(results["checks"]) == 4 and all(c["pass"] for c in results["checks"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
