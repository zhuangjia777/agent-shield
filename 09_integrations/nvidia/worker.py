"""Run unmodified NVIDIA SkillSpector in its separate Python environment.

The audit hook limits trusted scanner I/O; it is not an OS sandbox for malware.
Input files are only read by the upstream static/semantic analyzers.
"""
import json
import os
from pathlib import Path
import socket
import sys
import traceback
from urllib.parse import urlsplit


def main():
    request = json.load(sys.stdin)
    use_llm = request["use_llm"]
    config = request.get("model", {})
    allowed_addresses, allowed_host, allowed_port = set(), None, None
    if use_llm:
        endpoint = urlsplit(config["base_url"])
        if endpoint.scheme not in ("http", "https") or not endpoint.hostname or endpoint.username or endpoint.password:
            raise ValueError("Invalid model endpoint")
        allowed_host = endpoint.hostname
        allowed_port = endpoint.port or (443 if endpoint.scheme == "https" else 80)
        allowed_addresses = {item[4][0] for item in socket.getaddrinfo(allowed_host, allowed_port, type=socket.SOCK_STREAM)}
        os.environ.update({"SKILLSPECTOR_PROVIDER": "openai_compatible",
                           "SKILLSPECTOR_COMPAT_API_KEY": config["api_key"],
                           "SKILLSPECTOR_COMPAT_BASE_URL": config["base_url"],
                           "SKILLSPECTOR_MODEL": config["model"],
                           "SKILLSPECTOR_TEMPERATURE": "0"})
    else:
        os.environ["SKILLSPECTOR_PROVIDER"] = "openai_compatible"
    os.environ.update({"SKILLSPECTOR_BUILD_REVISION": request["revision"],
                       "LANGSMITH_TRACING": "false", "LANGCHAIN_TRACING_V2": "false",
                       "SKILLSPECTOR_OSV_TIMEOUT": "1", "NO_PROXY": "*", "no_proxy": "*"})
    counters = {"allowed_connects": 0, "denied_network_events": 0, "denied_processes": 0,
                "denied_event_shapes": []}

    def denied_shape(event, args):
        shape = {"event": event, "argument_types": [type(x).__name__ for x in args]}
        if event == "socket.getaddrinfo":
            shape["host_matches"] = args[0] in (allowed_host, (allowed_host or "").encode())
            shape["port_matches"] = str(args[1]) == str(allowed_port)
        if shape not in counters["denied_event_shapes"]:
            counters["denied_event_shapes"].append(shape)

    def audit(event, args):
        if event in ("subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"):
            counters["denied_processes"] += 1
            denied_shape(event, args)
            raise PermissionError("Child processes disabled for Skill analysis")
        if event == "socket.getaddrinfo":
            host = args[0].decode("ascii", "replace") if isinstance(args[0], bytes) else args[0]
            if use_llm and host in allowed_addresses | {allowed_host} and args[1] in (None, allowed_port, str(allowed_port)):
                return
            counters["denied_network_events"] += 1
            denied_shape(event, args)
            raise PermissionError("Name lookup outside model endpoint disabled")
        if event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
            address = args[1] if event == "socket.connect" else None
            if event == "socket.connect" and isinstance(address, tuple) and address[:2] in {(ip, allowed_port) for ip in allowed_addresses}:
                counters["allowed_connects"] += 1
                return
            counters["denied_network_events"] += 1
            denied_shape(event, args)
            raise PermissionError("Network outside model endpoint disabled")

    sys.addaudithook(audit)
    model_errors = []
    if use_llm:
        from langchain_core.callbacks import BaseCallbackHandler
        from skillspector.providers import use_provider
        from compatible_provider import AgentShieldCompatibleProvider

        class ModelDiagnostics(BaseCallbackHandler):
            def on_llm_error(self, error, **kwargs):
                # Do not persist exception messages: SDK errors may embed inputs.
                message = str(error).lower()
                category = next((text for text in ("event loop is closed", "different event loop",
                                                   "maximum context length", "length limit", "timed out")
                                 if text in message), "other")
                model_errors.append({"exception": type(error).__name__, "category": category,
                                     "frames": [{"file": Path(frame.filename).name, "function": frame.name,
                                                 "line": frame.lineno}
                                                for frame in traceback.extract_tb(error.__traceback__)[-6:]]})

        provider = AgentShieldCompatibleProvider(config, [ModelDiagnostics()])
        use_provider(provider)
    from skillspector.graph import graph
    result = graph.invoke({"input_path": request["input"], "output_format": "json",
                           "use_llm": use_llm, "llm_requested": use_llm,
                           # This upstream flag means "do not submit source to
                           # providers", not "do not fetch remote references".
                           # Input locality is enforced by our snapshot runner.
                           "source_local_only": False}, config={"max_concurrency": 2})
    if use_llm:
        provider.close()
    raw = result.get("report_body")
    if not raw:
        raise RuntimeError("Upstream returned no report")
    json.loads(raw)
    Path(request["raw_output"]).write_text(raw)
    Path(request["io_output"]).write_text(json.dumps(counters))
    calls = []
    for record in result.get("llm_call_log", []):
        message = str(record.get("error") or "")
        if config.get("api_key"):
            message = message.replace(config["api_key"], "[REDACTED]")
        calls.append({"node": record.get("node"), "ok": record.get("ok"),
                      "error": message[:300] or None})
    Path(request["raw_output"]).with_name("model-calls.json").write_text(json.dumps(calls, ensure_ascii=False, indent=2))
    Path(request["raw_output"]).with_name("model-errors.json").write_text(json.dumps(model_errors, indent=2))


if __name__ == "__main__":
    main()
