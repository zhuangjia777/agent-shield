"""Stop lifecycle regression tests; no real Docker resources are changed."""
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / '04_web'))
import app

class LabStopTests(unittest.TestCase):
    def test_cleanup_success_and_missing_resources(self):
        for response in ((0, ''), (1, 'Error: No such container: gone'),
                         (1, 'Error: No such network: gone')):
            with patch.object(app.lab_mod, '_sh', return_value=response) as sh, patch.object(app.lab_mod, '_log'):
                self.assertTrue(app.lab_mod.stop()['ok'])
                self.assertEqual(sh.call_count, 5)

    def test_cleanup_failure_is_reported_and_other_resources_attempted(self):
        with patch.object(app.lab_mod, '_sh', return_value=(1, 'Cannot connect to Docker daemon')) as sh, patch.object(app.lab_mod, '_log'):
            result = app.lab_mod.stop()
            self.assertFalse(result['ok'])
            self.assertIn('Cannot connect', result['msg'])
            self.assertEqual(sh.call_count, 5)

    def test_endpoint_reports_failure(self):
        h = object.__new__(app.Handler)
        h.path = '/api/lab/stop'
        h._body = lambda: {}
        h._json = lambda code, body: (code, body)
        with patch.object(app, '_stop_lab', return_value={'ok': False, 'msg': 'failed'}):
            self.assertEqual(h.do_POST()[0], 503)

    def test_old_agent_turn_cannot_restart_range(self):
        old = app.LAB_GENERATION
        with patch.object(app.lab_mod, 'stop', return_value={'ok': True}):
            app._stop_lab()
        def run(agent, message, on_event, answer, execute_callback):
            execute_callback('lab_start', {})
        sess = app.AgentSession()
        with patch.object(app.agent_mod.ReActAgent, 'run', run), patch.object(app.agent_mod, '_execute') as execute:
            app._agent_worker(sess, 'start', old)
            execute.assert_not_called()
        self.assertEqual(sess.q.get()['type'], 'error')

    def test_waiting_agent_exits_after_stop(self):
        waiting = threading.Event()
        sess = app.AgentSession()
        def run(agent, message, on_event, answer, execute_callback):
            execute_callback('lab_start', {})
            waiting.set()
            answer('Continue?', [])
            execute_callback('lab_attack', {})
        with patch.object(app.agent_mod.ReActAgent, 'run', run), patch.object(app.agent_mod, '_execute', return_value=('ok', True)) as execute, patch.object(app.lab_mod, 'stop', return_value={'ok': True}):
            worker = threading.Thread(target=app._agent_worker, args=(sess, 'start'))
            worker.start()
            self.assertTrue(waiting.wait(2))
            app._stop_lab()
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(execute.call_count, 1)

    def test_stop_waits_for_inflight_action_and_invalidates_turns(self):
        finished = threading.Event()
        old = app.LAB_GENERATION
        with patch.object(app.lab_mod, 'stop', side_effect=lambda: finished.set() or {'ok': True}):
            with app.LAB_ACTION_LOCK:
                worker = threading.Thread(target=app._stop_lab)
                worker.start()
                # Acquiring SES_LOCK after the worker is not guaranteed to order it;
                # the event wait verifies cleanup cannot enter while the action owns the lock.
                self.assertFalse(finished.wait(0.05))
            worker.join(2)
        self.assertTrue(finished.is_set())
        self.assertGreater(app.LAB_GENERATION, old)

if __name__ == '__main__':
    unittest.main()
