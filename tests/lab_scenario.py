"""Unit tests for the live-drill named scenarios (agent tool + HTTP endpoints)."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / '04_web'))
import app

lab = app.lab_mod
agent = app.agent_mod
KEYS = lab.SCENARIO_KEYS


class LabScenarioToolTests(unittest.TestCase):
    def test_list_when_scenario_empty(self):
        out, ok = agent._execute("lab_scenario", {"scenario": ""})
        self.assertTrue(ok)
        self.assertEqual(json.loads(out)["scenarios"][0]["id"], KEYS[0])

    def test_unknown_scenario_does_not_fire(self):
        with patch.object(lab, "run_scenario") as rs:
            out, ok = agent._execute("lab_scenario", {"scenario": "nope", "confirmed": True})
        self.assertIn("未知实战场景", out)
        rs.assert_not_called()

    def test_confirmation_gate_blocks_until_confirmed(self):
        with patch.object(lab, "run_scenario") as rs:
            first, ok = agent._execute("lab_scenario", {"scenario": "sqli_session"})
        self.assertTrue(ok)
        self.assertTrue(json.loads(first)["need_confirm"])
        rs.assert_not_called()

    def test_confirmed_runs_and_reports_verdict(self):
        with patch.object(lab, "run_scenario", return_value={"ok": True, "scenario": "sqli_session",
                                                             "verdict": "pass"}) as rs:
            out, ok = agent._execute("lab_scenario", {"scenario": "sqli_session", "confirmed": True})
        self.assertTrue(ok)
        self.assertEqual(json.loads(out)["verdict"], "pass")
        rs.assert_called_once_with("sqli_session")

    def test_still_blocked_when_explicit_confirmed_false(self):
        with patch.object(lab, "run_scenario") as rs:
            out, _ = agent._execute("lab_scenario", {"scenario": "bac_enumeration", "confirmed": False})
        self.assertTrue(json.loads(out)["need_confirm"])
        rs.assert_not_called()


class LabScenarioEndpointTests(unittest.TestCase):
    def handler(self, path, body):
        h = object.__new__(app.Handler)
        h.path = path
        h.headers = {"Content-Length": str(len(json.dumps(body).encode()))}
        h._body = lambda: body
        h._json = lambda code, value: (code, value)
        return h

    def test_scenarios_catalog_endpoint(self):
        h = self.handler("/api/lab/scenarios", {})
        code, value = h.do_GET()
        self.assertEqual(code, 200)
        self.assertEqual(set(value["scenarios"]), set(KEYS))
        self.assertIn("entry", value["range"])

    def test_run_endpoint_ok(self):
        with patch.object(lab, "start", return_value={"ok": True}) as start, \
             patch.object(lab, "run_scenario", return_value={"ok": True, "scenario": "x", "verdict": "pass"}):
            code, value = self.handler("/api/lab/scenario/run", {"scenario": "sqli_session"}).do_POST()
        self.assertEqual(code, 200)
        self.assertEqual(value["verdict"], "pass")
        start.assert_called_once()

    def test_start_failure_is_returned_without_running(self):
        with patch.object(lab, "start", return_value={"ok": False, "msg": "Docker 未就绪"}), \
             patch.object(lab, "run_scenario") as run:
            code, value = self.handler("/api/lab/scenario/run", {"scenario": "sqli_session"}).do_POST()
        self.assertEqual(code, 503)
        self.assertEqual(value["msg"], "Docker 未就绪")
        run.assert_not_called()

    def test_busy_range_rejects_duplicate_run(self):
        with app.LAB_ACTION_LOCK, patch.object(lab, "start") as start:
            code, _ = self.handler("/api/lab/scenario/run", {"scenario": "sqli_session"}).do_POST()
        self.assertEqual(code, 409)
        start.assert_not_called()

    def test_stop_during_start_prevents_attack(self):
        def stopped():
            app.LAB_GENERATION += 1
            return {"ok": True}
        with patch.object(app, "LAB_GENERATION", 0), \
             patch.object(lab, "start", side_effect=stopped), \
             patch.object(lab, "run_scenario") as run:
            code, value = self.handler("/api/lab/scenario/run", {"scenario": "sqli_session"}).do_POST()
        self.assertEqual(code, 503)
        self.assertIn("停止", value["msg"])
        run.assert_not_called()

    def test_run_endpoint_rejects_unknown(self):
        with patch.object(lab, "run_scenario") as rs:
            code, value = self.handler("/api/lab/scenario/run", {"scenario": "ghost"}).do_POST()
        self.assertEqual(code, 400)
        rs.assert_not_called()

    def test_judge_endpoint_rejects_unknown(self):
        with patch.object(lab, "judge_scenario") as js:
            code, value = self.handler("/api/lab/scenario/judge", {"scenario": "ghost"}).do_POST()
        self.assertEqual(code, 400)
        js.assert_not_called()


class LiveOracleShapeTests(unittest.TestCase):
    def test_catalog_shape_is_stable(self):
        cat = lab.scenario_catalog()
        for key in KEYS:
            s = cat["scenarios"][key]
            self.assertTrue(s["name"], "name missing for %s" % key)
            self.assertIn("oracle", cat["scenarios"][key])
            self.assertIn("boundary", cat["scenarios"][key])
            self.assertIn(cat["scenarios"][key]["waf"], ("depends", "independent"))

    def test_scenario_list_ids_match_registry(self):
        self.assertEqual([s["id"] for s in lab.scenario_list()], list(KEYS))


if __name__ == "__main__":
    unittest.main()
