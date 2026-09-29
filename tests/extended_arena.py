"""Exercise causal boundaries and shared transports for the additional scenarios."""
import io
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "04_web"))
import app

sim = app.arena_mod
NEW_SCENARIOS = ("office_lateral", "phishing_identity", "api_authorization", "dependency_supply_chain",
                 "agent_prompt_injection", "device_guest_access", "cloud_bucket_key", "ops_agent_broker")


class ExtendedArenaTests(unittest.TestCase):
    def run_case(self, scenario, **controls):
        defaults = sim.catalog(scenario)["presets"]["exposed"]
        return sim.simulate({"scenario": scenario, "controls": {**defaults, **controls}})

    def goals(self, result):
        return {item["id"]: item["success"] for item in result["before"]["outcomes"]}

    def test_presets_and_lockdown_business_cost(self):
        for scenario, daily, locked_business in (("office_lateral", 2, 0), ("phishing_identity", 2, 0),
                                                 ("api_authorization", 3, 0), ("dependency_supply_chain", 3, 1),
                                                 ("agent_prompt_injection", 0, 0), ("device_guest_access", 0, 2),
                                                 ("cloud_bucket_key", 1, 0), ("ops_agent_broker", 2, 0)):
            for preset, before, business in (("exposed", 4, 2), ("everyday", daily, 2), ("hardened", 0, locked_business)):
                with self.subTest(scenario=scenario, preset=preset):
                    result = sim.simulate({"scenario": scenario, "controls": sim.catalog(scenario)["presets"][preset]})
                    self.assertEqual(result["before"]["metrics"]["attack_goals_achieved"], before)
                    self.assertEqual(result["after"]["metrics"]["attack_goals_achieved"], 0)
                    self.assertEqual(result["after"]["metrics"]["business_passed"], business)

    def test_office_egress_and_login_are_separate_boundaries(self):
        self.assertEqual(self.goals(self.run_case("office_lateral", egress_allowlist=True)),
                         {"share_read": True, "remote_login": True, "lateral_admin": True, "data_exfil": False})
        result = self.run_case("office_lateral", unique_credentials=True, detection=True)
        self.assertEqual(self.goals(result),
                         {"share_read": True, "remote_login": False, "lateral_admin": False, "data_exfil": True})
        lateral = result["before"]["outcomes"][2]
        self.assertFalse(lateral["attempted"])
        self.assertFalse(lateral["detected"])
        self.assertEqual(lateral["unmet_prerequisites"], ["remote_login"])

    def test_identity_mfa_does_not_revoke_stolen_sessions_or_hide_password(self):
        self.assertEqual(self.goals(self.run_case("phishing_identity", phishing_resistant_mfa=True)),
                         {"password_capture": True, "account_login": False, "session_replay": True, "mailbox_export": False})
        self.assertEqual(self.goals(self.run_case("phishing_identity", revoke_sessions=True)),
                         {"password_capture": True, "account_login": True, "session_replay": False, "mailbox_export": True})

    def test_suspension_cannot_prevent_submission_to_fake_page(self):
        result = self.run_case("phishing_identity", suspend_account=True)
        self.assertEqual(self.goals(result),
                         {"password_capture": True, "account_login": False, "session_replay": False, "mailbox_export": False})
        self.assertEqual(result["before"]["metrics"]["business_passed"], 0)

    def test_api_object_function_and_token_permissions_are_independent(self):
        self.assertEqual(self.goals(self.run_case("api_authorization", object_auth=True)),
                         {"object_read": False, "bulk_export": False, "admin_write": True, "token_replay": True})
        self.assertEqual(self.goals(self.run_case("api_authorization", export_scope=True, token_binding=True)),
                         {"object_read": True, "bulk_export": False, "admin_write": True, "token_replay": False})

    def test_supply_chain_release_gate_does_not_prevent_earlier_exfil(self):
        self.assertEqual(self.goals(self.run_case("dependency_supply_chain", protected_release=True)),
                         {"untrusted_install": True, "install_hook": True, "build_exfil": True, "artifact_publish": False})
        self.assertEqual(self.goals(self.run_case("dependency_supply_chain", disable_install_hooks=True)),
                         {"untrusted_install": True, "install_hook": False, "build_exfil": False, "artifact_publish": False})
        result = self.run_case("dependency_supply_chain", verify_provenance=True, detection=True)
        self.assertEqual(result["before"]["metrics"]["detected_attempts"], 1)
        self.assertTrue(all(not x["attempted"] for x in result["before"]["outcomes"][1:]))

    def test_agent_injection_context_gate_and_tool_scope_are_separate(self):
        self.assertEqual(self.goals(self.run_case("agent_prompt_injection", context_sanitize=True)),
                         {"injected_instruction": False, "tool_overreach": False, "silent_exfil": False, "callback": False})
        overreach = self.run_case("agent_prompt_injection", context_sanitize=True)["before"]["outcomes"][1]
        self.assertFalse(overreach["attempted"])
        self.assertEqual(overreach["unmet_prerequisites"], ["injected_instruction"])
        # limit/confirmation only stop tool actions; input injection still requires normalization, and callback additionally requires signature verification.
        self.assertEqual(
            self.goals(self.run_case("agent_prompt_injection", egress_allowlist=False)),
            {"injected_instruction": True, "tool_overreach": True, "silent_exfil": True, "callback": True})
        self.assertEqual(
            self.goals(self.run_case("agent_prompt_injection",
                                     tool_allowlist=True, approval_gate=True, response_signing=True)),
            {"injected_instruction": True, "tool_overreach": False, "silent_exfil": False, "callback": False})
        block_exfil = self.run_case("agent_prompt_injection", egress_allowlist=True)
        self.assertEqual(self.goals(block_exfil),
                         {"injected_instruction": True, "tool_overreach": True, "silent_exfil": False, "callback": True})
        freeze = self.run_case("agent_prompt_injection", manual_review=True)
        self.assertEqual(self.goals(freeze),
                         {"injected_instruction": False, "tool_overreach": False, "silent_exfil": False, "callback": False})
        self.assertEqual(freeze["before"]["metrics"]["business_passed"], 0)

    def test_device_guest_segmentation_does_not_match_local_authentication(self):
        self.assertEqual(self.goals(self.run_case("device_guest_access", guest_isolation=True)),
                         {"guest_printer": True, "guest_peer": False, "segment_mgmt": False, "intranet_exfil": False})
        segment = self.run_case("device_guest_access", segmentation=True)
        self.assertEqual(self.goals(segment),
                         {"guest_printer": False, "guest_peer": False, "segment_mgmt": False, "intranet_exfil": False})
        # The employee-side business goes through an independent internal network channel, and the visitor segment strategy does not affect it.
        self.assertEqual(segment["before"]["metrics"]["business_passed"], 2)
        unplugged = self.run_case("device_guest_access", disconnect_dev=True)
        self.assertEqual(unplugged["before"]["metrics"]["business_passed"], 2)
        self.assertFalse(any(self.goals(unplugged).values()))

    def test_cloud_key_scope_download_and_recovery_are_independent(self):
        self.assertEqual(self.goals(self.run_case("cloud_bucket_key", endpoint_binding=True)),
                         {"key_read": True, "bucket_list": False, "object_download": False, "cross_region": False})
        self.assertEqual(
            self.goals(self.run_case("cloud_bucket_key", download_allowlist=True, backup_scope=True)),
            {"key_read": True, "bucket_list": True, "object_download": False, "cross_region": False})
        revoked = self.run_case("cloud_bucket_key", revoke_key=True)
        self.assertFalse(any(self.goals(revoked).values()))
        self.assertEqual(revoked["before"]["metrics"]["business_passed"], 0)

    def test_audit_alone_never_changes_goals(self):
        for scenario in NEW_SCENARIOS:
            quiet, observed = self.run_case(scenario), self.run_case(scenario, detection=True)
            self.assertEqual(self.goals(quiet), self.goals(observed))
            self.assertEqual(observed["before"]["metrics"]["detected_attempts"], 4)

    def test_all_policies_causal_evidence_reproducible_and_non_regressing(self):
        count = 0
        for scenario in NEW_SCENARIOS:
            for bits in itertools.product((False, True), repeat=len(sim.catalog(scenario)["controls"])):
                controls = dict(zip(sim.catalog(scenario)["controls"], bits))
                body = {"scenario": scenario, "controls": controls}
                original = json.dumps(body)
                result = sim.simulate(body)
                self.assertEqual(result, sim.simulate(body))
                self.assertEqual(json.dumps(body), original)
                self.assertEqual(result["after"]["metrics"]["attack_goals_achieved"], 0)
                self.assertGreaterEqual(result["after"]["metrics"]["business_passed"], result["before"]["metrics"]["business_passed"])
                for phase in ("before", "after"):
                    events = {e["id"]: e for e in result[phase]["events"]}
                    for outcome in result[phase]["outcomes"]:
                        event = events[outcome["evidence_id"]]
                        self.assertEqual(outcome["success"], event["evidence"]["goal_achieved"])
                        if outcome["success"]:
                            self.assertTrue(all(event["evidence"]["requires"].values()))
                        if outcome["unmet_prerequisites"]:
                            self.assertEqual(event["result"], "skipped")
                            self.assertFalse(outcome["detected"])
                        for eid in event["evidence"]["prerequisite_events"]:
                            self.assertLess(events[eid]["tick"], event["tick"])
                    for event in events.values():
                        if event["side"] == "red":
                            self.assertEqual(events[event["evidence"]["related_event"]]["side"], "black")
                count += 1
        self.assertEqual(count, 896)

    def test_catalog_copies_cannot_change_policy_and_run_identity_is_scenario_specific(self):
        selected = sim.catalog("office_lateral")
        selected["controls"]["share_auth"]["name"] = "changed"
        selected["attack_goals"][2]["requires"].clear()
        self.assertNotEqual(sim.catalog("office_lateral")["controls"]["share_auth"]["name"], "changed")
        self.assertEqual(sim.catalog("office_lateral")["attack_goals"][2]["requires"], ["remote_login"])
        self.assertEqual(len({self.run_case(key)["run_id"] for key in NEW_SCENARIOS}), 8)

    def test_no_files_network_or_subprocess_execution(self):
        with patch("socket.socket", side_effect=AssertionError("network")), \
             patch("subprocess.Popen", side_effect=AssertionError("process")), \
             patch("builtins.open", side_effect=AssertionError("file")), \
             patch("pathlib.Path.open", side_effect=AssertionError("path")):
            for scenario in NEW_SCENARIOS:
                result = self.run_case(scenario)
                self.assertEqual(result["network_packets_sent"], 0)
                self.assertFalse(result["untrusted_code_executed"])

    def handler(self, path, body):
        handler = object.__new__(app.Handler)
        handler.path, handler.headers = path, {"Content-Length": str(len(json.dumps(body).encode()))}
        handler._body = lambda: body
        handler._json = lambda code, value: (code, value)
        return handler

    def test_http_stream_complete_and_invalid_requests(self):
        for scenario in NEW_SCENARIOS:
            body = {"scenario": scenario}
            code, result = self.handler("/api/arena/run", body).do_POST()
            self.assertEqual(code, 200)
            handler = self.handler("/api/arena/stream", body)
            handler.send_response = lambda code: self.assertEqual(code, 200)
            handler.send_header = lambda *args: None
            handler.end_headers = lambda: None
            handler.wfile = io.BytesIO()
            with patch.object(app.time, "sleep"):
                handler.do_POST()
            packets = [json.loads(line) for line in handler.wfile.getvalue().splitlines()]
            self.assertEqual(packets[-1]["result"], result)
            self.assertEqual([p["seq"] for p in packets], list(range(1, len(packets)+1)))
            self.assertTrue(all(p["scenario"] == scenario and p["run_id"] == result["run_id"] for p in packets))
            self.assertEqual(packets[0]["total_events"], sum(p["type"] in ("event", "repair") for p in packets))
            self.assertFalse(app.ARENA_STREAM_LOCK.locked())
            for extras in ({"target": "192.0.2.10"}, {"command": "demo"},
                           {"controls": {"vpn": True}}, {"controls": {"detection": "false"}}):
                self.assertEqual(self.handler("/api/arena/run", {**body, **extras}).do_POST()[0], 400)

    def test_model_review_uses_selected_evidence_and_separate_contexts(self):
        for scenario in NEW_SCENARIOS:
            result = self.run_case(scenario)
            original = json.dumps(result)
            with patch.object(app.llm_mod, "cloud_cfg", return_value={"api_key": "FAKE", "base_url": "http://test.invalid", "model": "test"}), \
                 patch.object(app.llm_mod, "_cloud_stream", side_effect=[iter([("content", "black-only-marker")]), iter([("content", "red review")])]) as stream:
                review = app.arena_review(result)
            for call in stream.call_args_list:
                self.assertIn(result["scenario_name"], call.args[0][0]["content"])
                self.assertEqual(json.loads(call.args[0][1]["content"])["scenario"], scenario)
            self.assertNotIn("black-only-marker", json.dumps(stream.call_args_list[1].args[0]))
            self.assertTrue(review["advisory_only"])
            self.assertEqual(json.dumps(result), original)


if __name__ == "__main__":
    unittest.main()
