"""Transport regression: separate event loops must not share stale sockets.

Run using .venv-skillspector/bin/python; only a local synthetic HTTP server is used.
"""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "09_integrations/nvidia"))
from compatible_provider import AgentShieldCompatibleProvider


class ProviderTransportTests(unittest.TestCase):
    def test_model_requests_across_closed_event_loops(self):
        requests, clients = [], []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                clients.append(self.client_address)
                body = json.dumps({"id": "synthetic", "object": "chat.completion", "created": 0,
                                   "model": "Qwen-test", "choices": [{"index": 0, "finish_reason": "stop",
                                   "message": {"role": "assistant", "content": "ok"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        provider = AgentShieldCompatibleProvider({"max_tokens": 900})
        try:
            with patch.dict(os.environ, {"SKILLSPECTOR_COMPAT_API_KEY": "synthetic-test-key",
                                         "SKILLSPECTOR_COMPAT_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
                                         "HTTPS_PROXY": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1"}):
                first = provider.create_chat_model("Qwen-test", max_tokens=1000)
                second = provider.create_chat_model("Qwen-test", max_tokens=1000)
                self.assertIsNot(first.http_async_client, second.http_async_client)
                for model in (first, first, second):
                    self.assertEqual(asyncio.run(model.ainvoke("synthetic test")).content, "ok")
                self.assertEqual(len(set(clients)), 3)
                self.assertTrue(all(r["chat_template_kwargs"] == {"enable_thinking": False} for r in requests))
                self.assertTrue(all(r["max_completion_tokens"] == 900 for r in requests))
        finally:
            provider.close()
            server.shutdown()
            server.server_close()
            thread.join()

    def test_request_budget_is_bounded(self):
        for configured, expected in ((1, 512), (2500, 2500), (99999, 4096)):
            provider = AgentShieldCompatibleProvider({"max_tokens": configured})
            self.assertEqual(provider.get_max_output_tokens("test"), expected)
            self.assertEqual(provider.get_context_length("test"), 8192)


if __name__ == "__main__":
    unittest.main()
