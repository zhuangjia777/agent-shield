"""Behavioral invariants for the synthetic Skill attack/defense scenario."""
import itertools
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / '04_web'))
import app
sim = app.arena_mod
skill = sim.skill_scenario


class SkillArenaTests(unittest.TestCase):
    def run_case(self, **controls):
        return sim.simulate({'scenario':'malicious_skill','controls':{**skill.PRESETS['exposed'],**controls}})

    def goals(self, result):
        return {x['id']:x['success'] for x in result['before']['outcomes']}

    def test_three_presets_include_business_cost(self):
        for name, expected, business in [('exposed',4,2),('everyday',2,2),('hardened',0,0)]:
            result=sim.simulate({'scenario':'malicious_skill','controls':skill.PRESETS[name]})
            self.assertEqual(result['before']['metrics']['attack_goals_achieved'],expected)
            self.assertEqual(result['after']['metrics']['attack_goals_achieved'],0)
            self.assertEqual(result['after']['metrics']['business_passed'],business)

    def test_egress_restriction_does_not_stop_local_read_or_tools(self):
        self.assertEqual(self.goals(self.run_case(egress_allowlist=True)),{
            'secret_read':True,'secret_exfil':False,'tool_abuse':True,'artifact_tamper':True})

    def test_exfil_requires_obtaining_demo_secret(self):
        result=self.run_case(workspace_only=True)
        goals=self.goals(result)
        self.assertFalse(goals['secret_read']);self.assertFalse(goals['secret_exfil'])
        self.assertTrue(goals['tool_abuse']);self.assertTrue(goals['artifact_tamper'])
        event=next(e for e in result['before']['events'] if e['action']=='诱导数据外传')
        self.assertFalse(event['evidence']['credential_available'])

    def test_audit_only_is_not_prevention(self):
        quiet,observed=self.run_case(),self.run_case(detection=True)
        self.assertEqual(self.goals(quiet),self.goals(observed))
        self.assertEqual(observed['before']['metrics']['detected_attempts'],4)

    def test_tool_allowlist_still_needs_file_scope(self):
        self.assertEqual(self.goals(self.run_case(tool_allowlist=True)),{
            'secret_read':True,'secret_exfil':False,'tool_abuse':False,'artifact_tamper':False})

    def test_all_128_policies_same_case_evidence_and_repair(self):
        for values in itertools.product((False,True),repeat=len(skill.CONTROLS)):
            controls=dict(zip(skill.CONTROLS,values));body={'scenario':'malicious_skill','controls':controls}
            original=json.dumps(body);result=sim.simulate(body)
            self.assertEqual(json.dumps(body),original);self.assertEqual(result,sim.simulate(body))
            self.assertEqual(result['after']['metrics']['attack_goals_achieved'],0)
            self.assertGreaterEqual(result['after']['metrics']['business_passed'],result['before']['metrics']['business_passed'])
            for phase in ('before','after'):
                events={e['id']:e for e in result[phase]['events']}
                for goal in result[phase]['outcomes']:
                    self.assertEqual(events[goal['evidence_id']]['evidence']['goal_achieved'],goal['success'])
            packets=list(sim.presentation_events(result))
            self.assertTrue(all(p['scenario']=='malicious_skill' for p in packets))
            self.assertEqual(packets[-1]['result'],result)

    def test_invalid_targets_and_cross_scenario_controls_rejected(self):
        for body in ({'scenario':[]},{'scenario':{}},{'scenario':'malicious_skill','target':'example'},
                     {'scenario':'malicious_skill','controls':{'vpn':True}},
                     {'scenario':'public_wifi','controls':{'tool_allowlist':True}},
                     {'scenario':'malicious_skill','controls':{'detection':1}}):
            with self.assertRaises(ValueError):sim.simulate(body)

    def test_no_files_network_or_process_execution(self):
        with patch('socket.socket',side_effect=AssertionError('network')), \
             patch('subprocess.Popen',side_effect=AssertionError('process')), \
             patch('pathlib.Path.read_text',side_effect=AssertionError('files')):
            result=self.run_case()
        self.assertEqual(result['network_packets_sent'],0)
        self.assertFalse(result['untrusted_code_executed'])

    def test_review_uses_selected_scenario_without_role_context_leak(self):
        with patch.object(app.llm_mod,'cloud_cfg',return_value={'api_key':'FAKE','base_url':'http://test.invalid','model':'test'}), \
             patch.object(app.llm_mod,'_cloud_stream',side_effect=[iter([('content','black review')]),iter([('content','red review')])]) as stream:
            app.arena_review(self.run_case())
        for call in stream.call_args_list:
            self.assertIn('恶意 Skill',call.args[0][0]['content'])
            self.assertNotIn('公共 Wi-Fi',call.args[0][0]['content'])
        self.assertNotIn('black review',json.dumps(stream.call_args_list[1].args[0]))

    def test_catalog_and_http_scenario_identity(self):
        handler=object.__new__(app.Handler);handler.path='/api/arena/scenarios'
        handler._json=lambda code,body:(code,body)
        code,data=handler.do_GET();self.assertEqual(code,200)
        self.assertEqual(set(data['scenarios']),{'public_wifi','malicious_skill','office_lateral',
                                               'phishing_identity','api_authorization','dependency_supply_chain',
                                               'agent_prompt_injection','device_guest_access','cloud_bucket_key'})
        handler.path='/api/arena/run';handler.headers={'Content-Length':'30'}
        handler._body=lambda:{'scenario':'malicious_skill'}
        code,result=handler.do_POST();self.assertEqual(code,200)
        self.assertEqual(result['scenario'],'malicious_skill')
        self.assertEqual(result['before']['metrics']['attack_goals_achieved'],2)


if __name__=='__main__':unittest.main()
