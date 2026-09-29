"""Security semantics, boundary validation and web integration for the arena."""
import itertools
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "04_web"))
import app
sim = app.arena_mod


class ArenaTests(unittest.TestCase):
    def run_case(self, **controls):
        return sim.simulate({"controls": {**sim.PRESETS["exposed"], **controls}})

    def goals(self, result):
        return {x["id"]: x["success"] for x in result["before"]["outcomes"]}

    def test_known_scenarios_and_repair_business(self):
        for name, expected in (("exposed", 4), ("everyday", 1), ("hardened", 0)):
            result = sim.simulate({"controls": sim.PRESETS[name]})
            self.assertEqual(result["before"]["metrics"]["attack_goals_achieved"], expected)
            self.assertEqual(result["after"]["metrics"]["attack_goals_achieved"], 0)
            self.assertEqual(result["after"]["metrics"]["business_passed"], 1 if name == "hardened" else 2)

    def test_https_does_not_protect_shares_or_phishing(self):
        self.assertEqual(self.goals(self.run_case(https_only=True)), {
            "share_read": True, "http_intercept": False,
            "dns_redirect": False, "portal_phish": True})

    def test_vpn_does_not_change_local_share_permissions(self):
        self.assertEqual(self.goals(self.run_case(vpn=True)), {
            "share_read": True, "http_intercept": False,
            "dns_redirect": False, "portal_phish": True})

    def test_isolation_blocks_lateral_paths_but_costs_collaboration(self):
        result = self.run_case(client_isolation=True)
        self.assertEqual(sum(self.goals(result).values()), 1)
        self.assertTrue(self.goals(result)["portal_phish"])
        self.assertFalse(result["after"]["business_checks"][1]["pass"])

    def test_detection_is_not_prevention(self):
        quiet, observed = self.run_case(), self.run_case(detection=True)
        self.assertEqual(self.goals(quiet), self.goals(observed))
        self.assertEqual(observed["before"]["metrics"]["detected_attempts"], 4)
        self.assertEqual(quiet["before"]["metrics"]["detected_attempts"], 0)

    def test_all_128_policies_reproducible_and_repair_does_not_regress(self):
        for values in itertools.product((False, True), repeat=len(sim.CONTROLS)):
            policy = dict(zip(sim.CONTROLS, values))
            body = {"controls": policy}
            result = sim.simulate(body)
            self.assertEqual(result, sim.simulate(body))
            self.assertEqual(policy, body["controls"])
            self.assertEqual(result["after"]["metrics"]["attack_goals_achieved"], 0)
            self.assertGreaterEqual(result["after"]["metrics"]["business_passed"], result["before"]["metrics"]["business_passed"])
            for phase in ("before", "after"):
                events = {event["id"]: event for event in result[phase]["events"]}
                for goal in result[phase]["outcomes"]:
                    self.assertEqual(events[goal["evidence_id"]]["evidence"]["goal_achieved"], goal["success"])

    def test_malformed_policies_and_real_targets_are_rejected(self):
        for body in (None, [], {"target": "192.0.2.200"}, {"command": "anything"},
                     {"scenario": "real_lan"}, {"controls": []},
                     {"controls": {"vpn": 1}}, {"controls": {"vpn": "false"}},
                     {"controls": {"unknown": True}}):
            with self.assertRaises(ValueError):
                sim.simulate(body)

    def test_simulation_does_not_use_network_or_subprocess(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")), \
             patch("subprocess.Popen", side_effect=AssertionError("process forbidden")):
            self.assertEqual(self.run_case()["network_packets_sent"], 0)

    def handler(self, path, body):
        handler = object.__new__(app.Handler)
        handler.path = path
        handler.headers = {"Content-Length": str(len(json.dumps(body).encode()))}
        handler._body = lambda: body
        handler._json = lambda code, value: (code, value)
        return handler

    def test_http_validation_and_success(self):
        self.assertEqual(self.handler("/api/arena/run", {"target": "example"}).do_POST()[0], 400)
        status, body = self.handler("/api/arena/run", {}).do_POST()
        self.assertEqual(status, 200)
        self.assertEqual(body["before"]["metrics"]["attack_goals_achieved"], 1)
        handler = self.handler("/api/arena/run", {})
        handler.headers["Content-Length"] = "10000"
        self.assertEqual(handler.do_POST()[0], 413)

    def test_model_separate_contexts_and_immutable_results(self):
        result = self.run_case()
        before = json.dumps(result)
        with patch.object(app.llm_mod, "cloud_cfg", return_value={"api_key": "FAKE", "base_url": "http://test.invalid", "model": "test"}), \
             patch.object(app.llm_mod, "_cloud_stream", side_effect=[iter([("content", "红队复盘")]), iter([("content", "蓝队复盘")])]) as stream:
            review = app.arena_review(result)
        self.assertEqual([r["role"] for r in review["reviews"]], ["black", "red"])
        self.assertEqual(len(stream.call_args_list[1].args[0]), 2)
        self.assertNotIn("红队复盘", json.dumps(stream.call_args_list[1].args[0]))
        self.assertEqual(before, json.dumps(result))
        self.assertTrue(review["advisory_only"])

    def test_model_errors_do_not_leak_provider_details(self):
        with patch.object(app, "arena_review", side_effect=RuntimeError("SECRET_CONNECTION_DETAILS")):
            status, body = self.handler("/api/arena/review", {}).do_POST()
        self.assertEqual(status, 502)
        self.assertNotIn("SECRET", json.dumps(body))
        self.assertFalse(app.ARENA_REVIEW_LOCK.locked())

    def test_stream_preserves_same_case_evidence_and_final_result(self):
        for name in sim.PRESETS:
            result = sim.simulate({"controls": sim.PRESETS[name]})
            messages = list(sim.presentation_events(result))
            self.assertEqual([m["seq"] for m in messages], list(range(1, len(messages)+1)))
            self.assertNotIn("result", messages[0])
            self.assertEqual(messages[-1]["result"], result)
            for phase in ("before", "after"):
                self.assertEqual([m["event"] for m in messages if m["type"] == "event" and m["phase"] == phase], result[phase]["events"])
            repairs = [m for m in messages if m["type"] == "repair"]
            self.assertEqual(len(repairs), len(result["repair"]))
            self.assertEqual(messages[0]["total_events"], 24 + len(repairs))

    def test_stream_http_flushes_and_releases_slot(self):
        handler = self.handler("/api/arena/stream", {})
        handler.send_response = lambda code: self.assertEqual(code, 200)
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        handler.wfile = io.BytesIO()
        with patch.object(app.time, "sleep"):
            handler.do_POST()
        messages = [json.loads(line) for line in handler.wfile.getvalue().splitlines()]
        self.assertEqual(messages[-1]["type"], "complete")
        self.assertFalse(app.ARENA_STREAM_LOCK.locked())

    def test_stream_disconnect_releases_slot(self):
        handler = self.handler("/api/arena/stream", {})
        handler.send_response = lambda code: None
        handler.send_header = lambda *args: None
        handler.end_headers = lambda: None
        class Disconnected:
            def write(self, data): raise BrokenPipeError()
        handler.wfile = Disconnected()
        handler.do_POST()
        self.assertFalse(app.ARENA_STREAM_LOCK.locked())

    def test_stream_rejects_targets_and_parallel_runs(self):
        self.assertEqual(self.handler("/api/arena/stream", {"target": "example"}).do_POST()[0], 400)
        with app.ARENA_STREAM_LOCK:
            self.assertEqual(self.handler("/api/arena/stream", {}).do_POST()[0], 429)


if __name__ == "__main__":
    unittest.main()
