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
        # auto 全开后仍保留的两道确认：不可逆拆场、宿主非白名单命令
        with patch.object(agent, "livelab"):
            obs, ok = agent._execute("lab_stop", {}, "auto")
            self.assertTrue(json.loads(obs).get("need_confirm"))

    def test_lab_attack_auto_executes_without_ask(self):
        # auto 档攻击命令直接执行（confirmed 由执行层注入），不再弹确认
        with patch.object(agent, "livelab") as lab:
            lab.red_exec.return_value = {"ok": True, "exit": 0, "out": ""}
            obs, ok = agent._execute("lab_attack", {"cmd": "curl -s http://aslab-blue:8080/"}, "auto")
            self.assertTrue(ok)
            self.assertFalse(json.loads(obs).get("need_confirm"))
            lab.red_exec.assert_called_once()

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


class ExecConfirmAutoAnswerTests(unittest.TestCase):
    """auto 档的 Ask 硬闸：执行确认型代答，提问型照弹，拆场确认保留。"""

    def test_classify(self):
        self.assertTrue(agent._is_exec_confirm_ask("确认执行这条 SQLi 攻击命令？", ["确认执行", "取消"]))
        self.assertTrue(agent._is_exec_confirm_ask("是否同意起场？", ["同意", "不同意"]))
        self.assertFalse(agent._is_exec_confirm_ask("你要看哪份报告？", ["报告A", "报告B"]))
        # 拆场/销毁类确认必须留给真人
        self.assertFalse(agent._is_exec_confirm_ask("确认销毁演练场全部容器？", ["确认", "取消"]))

    def _run_with_ask(self, mode):
        replies = ["Thought: 先问\nAction: Ask\nActionInput: {\"question\":\"确认执行攻击命令？\",\"choices\":[\"确认执行\",\"取消\"]}",
                   "Final Answer: 完成 [DONE]" if mode == "auto" else "Final Answer: 完成"]
        it = iter(replies)
        def stream(messages, **kwargs):
            yield 'token', next(it)
        asked = []
        with patch.object(agent, '_observations',
                          return_value='{"recent_reports": [], "available_skill_samples": []}'), \
             patch.object(agent, 'livelab') as lab, \
             patch.object(agent, 'chat_stream', stream):
            lab.status.return_value = {"running": True, "waf": "block", "containers": {}}
            agent.ReActAgent([]).run("打一发", lambda k, v: asked.append((k, v)),
                                     lambda q, c: (_ for _ in ()).throw(AssertionError("不该打扰用户"))
                                     if mode == "auto" else "确认执行", mode=mode)
        return asked

    def test_auto_mode_never_bothers_user_for_exec_confirm(self):
        asked = self._run_with_ask("auto")
        asks = [ev for k, ev in asked if k == "ask"]
        self.assertTrue(asks and all(ev.get("auto") for ev in asks))
        self.assertTrue(any(k == "ask_answered" and "自动" in ev.get("answer", "") for k, ev in asked))

    def test_confirm_mode_still_asks(self):
        asked = self._run_with_ask("confirm")
        self.assertTrue(any(k == "ask" and not ev.get("auto") for k, ev in asked))


class AutoLoopTests(unittest.TestCase):
    def _scripted_stream(self, replies):
        it = iter(replies)
        def stream(messages, **kwargs):
            text = next(it)
            yield 'token', text
        return stream

    def _patched_obs(self):
        return patch.object(agent, '_observations',
                            return_value='{"recent_reports": [], "available_skill_samples": []}')

    def test_auto_loops_until_done_sentinel(self):
        # 调过工具后第一次 final 没打 [DONE] → 系统追问 → 第二次带 [DONE] 收工
        replies = ["Thought: 先看战果\nAction: lab_judge\nActionInput: {}",
                   "Final Answer: 第一幕", "Final Answer: 第二幕 [DONE]"]
        seen = []
        with self._patched_obs(), \
             patch.object(agent, 'livelab') as lab, \
             patch.object(agent, 'chat_stream', self._scripted_stream(replies)):
            lab.status.return_value = {"running": True, "waf": "block", "containers": {}}
            lab.judge_http.return_value = {"ok": True, "solved": []}
            lab.waf_get.return_value = {"waf": "block"}
            a = agent.ReActAgent([])
            a.run("做任务", lambda k, v: seen.append((k, v)), lambda q, c: '', mode="auto")
        finals = [ev for k, ev in seen if k == "final"]
        self.assertEqual(len(finals), 2)
        self.assertTrue(finals[0].get("interim"))
        self.assertNotIn("interim", finals[1])
        self.assertIn("第二幕", a.history[-1]["content"])
        self.assertNotIn("DONE", a.history[-1]["content"])

    def test_confirm_mode_final_ends_immediately(self):
        replies = ["Final Answer: 一步收工"]
        seen = []
        with self._patched_obs(), \
             patch.object(agent, 'livelab') as lab, \
             patch.object(agent, 'chat_stream', self._scripted_stream(replies)):
            lab.status.return_value = {"running": False, "waf": None, "containers": {}}
            agent.ReActAgent([]).run("hi", lambda k, v: seen.append((k, v)), lambda q, c: '', mode="confirm")
        finals = [ev for k, ev in seen if k == "final"]
        self.assertEqual(len(finals), 1)
        self.assertNotIn("interim", finals[0])


if __name__ == "__main__":
    unittest.main()
