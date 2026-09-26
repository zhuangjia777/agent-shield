"""Adapter failure boundaries; no Docker or model requests."""
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def module(name,path):
 s=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
shell=module('openshell_adapter','09_integrations/openshell/run.py')
evalrun=module('tier3_adapter','09_integrations/tier3/run.py')
class AdapterTests(unittest.TestCase):
    def test_openshell_rejects_arbitrary_commands(self):
        with self.assertRaises(ValueError):shell.command('agentshield-test','curl http://target')
        with self.assertRaises(ValueError):shell.command('bad;command','read_fixture')
        self.assertIn('--no-login-shell',shell.command('agentshield-test','read_fixture'))
    def test_no_host_fallback(self):
        with patch.object(shell,'readiness',return_value={'ready':False}),patch.object(shell,'model_tools') as model,patch.object(shell,'invoke') as invoke:
            self.assertEqual(shell.run(True)['status'],'unavailable');model.assert_not_called();invoke.assert_not_called()
    def test_network_error_not_counted_as_policy_block(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'reports').mkdir()
            def invoke(args,timeout=45):
                if args[:2]==['sandbox','exec']:return SimpleNamespace(returncode=1,stdout='',stderr='DNS error')
                return SimpleNamespace(returncode=0,stdout='',stderr='')
            with patch.object(shell,'ROOT',root),patch.object(shell,'readiness',return_value={'ready':True}),patch.object(shell,'invoke',side_effect=invoke):r=shell.run()
            self.assertEqual(r['status'],'partial');self.assertEqual(r['cleanup'],'deleted');self.assertTrue(all(e['decision']=='error' for e in r['events']))
    def test_tier3_keeps_baseline_and_same_agent_model(self):
        cmd=evalrun.command('/tmp/test-output','test-model',2)
        self.assertNotIn('--skip-baseline',cmd);self.assertIn('opencode=openai/test-model',cmd);self.assertIn('docker',cmd);self.assertNotIn('--copy-repo',cmd)
    def test_tier3_requires_two_fully_scored_conditions(self):
        import copy
        arm={'execution_status':'succeeded','expected_attempts':1,'scored_attempts':1,'execution_errors':[]}
        report={'execution_status':'succeeded','agents':{'opencode':{'execution_status':'succeeded',
                'conditions':{'with_skill':dict(arm),'without_skill':dict(arm)}}}}
        self.assertTrue(evalrun.paired_complete(report))
        for replacement in ({},dict(arm,execution_status='skipped'),dict(arm,scored_attempts=0),
                            dict(arm,expected_attempts=0,scored_attempts=0),dict(arm,execution_errors=['missing'])):
            broken=copy.deepcopy(report);broken['agents']['opencode']['conditions']['without_skill']=replacement
            self.assertFalse(evalrun.paired_complete(broken))
        self.assertFalse(evalrun.paired_complete({'execution_status':'succeeded','agents':{}}))
    def test_credentials_not_in_command_or_foreign_environment(self):
        cfg={'base_url':'http://private.invalid/v1','api_key':'FAKE_PRIVATE','model':'qwen'}
        with patch.dict('os.environ',{'ANTHROPIC_API_KEY':'FOREIGN','HTTPS_PROXY':'http://foreign.invalid','SKILL_EVAL_LLM_BASE_URL':'http://foreign.invalid'},clear=True):env=evalrun.model_environment(cfg)
        self.assertNotIn('ANTHROPIC_API_KEY',env);self.assertNotIn('HTTPS_PROXY',env)
        self.assertEqual(env['SKILL_EVAL_LLM_BASE_URL'],cfg['base_url']);self.assertNotIn('FAKE_PRIVATE',' '.join(evalrun.command('/tmp/test-output','qwen')))
if __name__=='__main__':unittest.main()
