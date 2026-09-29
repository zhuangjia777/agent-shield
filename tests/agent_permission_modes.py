"""Permission modes: observer blocks writes, auto skips scripted confirmation, hardlines never skip."""
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '03_ai'))
import agent


class ObserverModeTests(unittest.TestCase):
    def test_write_tools_blocked_without_touching_livelab(self):
        for tool, tin in [("lab_start", {}), ("lab_attack", {"confirmed": True}),
                          ("lab_stop", {"confirmed": True}), ("run_command", {"cmd": "ls", "confirmed": True})]:
            with self.subTest(tool=tool):
                obs, ok = agent._execute(tool, tin, "observer")
                data = json.loads(obs)
                self.assertFalse(ok)
                self.assertTrue(data.get("blocked"))

    def test_read_tools_still_work_in_observer(self):
        with patch.object(agent, '_observations', return_value='{"recent_reports": [], "available_skill_samples": []}'):
            obs, ok = agent._execute("list_reports", {}, "observer")
            self.assertTrue(ok)


class AutoModeTests(unittest.TestCase):
    def test_scripted_scenario_confirmation_auto_satisfied(self):
        with patch.object(agent, "livelab") as lab:
            lab.SCENARIO_KEYS = ("sqli_session",)
            lab.run_scenario.return_value = {"ok": True}
            obs, ok = agent._execute("lab_scenario", {"scenario": "sqli_session"}, "auto")
            self.assertTrue(ok)
            lab.run_scenario.assert_called_once()

    def test_hardlines_still_need_confirmation_in_auto(self):
        with patch.object(agent, "livelab"):
            for tool, tin in [("lab_attack", {"cmd": "curl evil"}), ("lab_stop", {})]:
                with self.subTest(tool=tool):
                    obs, ok = agent._execute(tool, tin, "auto")
                    self.assertTrue(json.loads(obs).get("need_confirm"))

    def test_confirm_mode_unchanged(self):
        with patch.object(agent, "livelab") as lab:
            lab.SCENARIO_KEYS = ("sqli_session",)
            lab.SCENARIOS = {"sqli_session": {"name": "n", "blurb": "b", "oracle": "o"}}
            obs, ok = agent._execute("lab_scenario", {"scenario": "sqli_session"}, "confirm")
            self.assertTrue(json.loads(obs).get("need_confirm"))
            lab.run_scenario.assert_not_called()

    def test_observer_beats_auto_hardline_shortcut(self):
        # run_command whitelist path is allowed in every mode (read-only anyway)
        with patch.object(agent, "livelab"):
            obs, ok = agent._execute("run_command", {"cmd": "sudo rm -rf /"}, "auto")
            self.assertFalse(ok)


class PromptPrefixTests(unittest.TestCase):
    def test_system_message_is_static_and_dynamic_snapshot_is_separate(self):
        seen = []
        def stream(messages, **kwargs):
            seen.append(list(messages))
            yield 'token', 'Final Answer: done'
        for _ in range(2):
            with patch.object(agent, 'chat_stream', stream), \
                 patch.object(agent, '_observations', return_value='{"recent_reports": [], "available_skill_samples": []}'):
                agent.ReActAgent([]).run('hi', lambda k, v: None, lambda q, c: '')
        self.assertEqual(seen[0][0]['content'], seen[1][0]['content'])
        self.assertNotIn('当前可得信息', seen[0][0]['content'])
        self.assertIn('当前可得信息', seen[0][1]['content'])
        self.assertEqual(seen[0][1]['role'], 'user')

    def test_mode_note_reaches_dynamic_message_not_system(self):
        seen = []
        def stream(messages, **kwargs):
            seen.append(list(messages))
            yield 'token', 'Final Answer: done'
        with patch.object(agent, 'chat_stream', stream), \
             patch.object(agent, '_observations', return_value='{"recent_reports": [], "available_skill_samples": []}'):
            agent.ReActAgent([]).run('hi', lambda k, v: None, lambda q, c: '', mode='observer')
        self.assertIn('observer', seen[0][1]['content'])
        self.assertNotIn('observer', seen[0][0]['content'])


if __name__ == "__main__":
    unittest.main()
