"""Agent choice, observation isolation, tool enforcement, and honest failures."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'03_ai'),str(ROOT/'08_arena')]
import agents
import llm
CFG={'cloud':{'base_url':'https://main.invalid/v1','api_key':'MAIN_TEST','model':'main','max_tokens':900},'arena_models':{'black':{'inherit_main':False,'base_url':'https://black.invalid/v1','api_key':'BLACK_TEST','model':'black','max_tokens':900}}}
def response(name,args):
    return {'choices':[{'message':{'tool_calls':[{'id':'test-call','function':{'name':name,'arguments':json.dumps(args)}}]}}]}
def chosen(name,**args):
    args={'reason':'Synthetic decision',**args}
    return name,args,{'role':'assistant','content':None,'tool_calls':[{'id':'t','type':'function','function':{'name':name,'arguments':json.dumps(args)}}]}
class AgentTests(unittest.TestCase):
    def test_role_cannot_change_other_capabilities(self):
        w=agents.World({})
        for role,name,args in [('black','set_control',{'control':'vpn'}),('red','attempt_goal',{'goal':'share_read'}),('black','shell',{'command':'anything'})]:
            with self.assertRaises(agents.AgentError):w.execute(role,name,args)
    def test_unobserved_black_attempt_not_visible_to_red(self):
        w=agents.World({'controls':{'detection':False}});w.execute('black','attempt_goal',{'goal':'portal_phish'})
        self.assertEqual(w.observation('red')['alerts'],[])
        self.assertEqual(len(w.observation('black')['own_attempts']),1)
    def test_red_change_affects_next_black_action(self):
        w=agents.World({});a=w.execute('black','attempt_goal',{'goal':'portal_phish'})
        self.assertTrue(a['success']);w.execute('red','set_control',{'control':'verify_portal'})
        self.assertFalse(w.execute('black','attempt_goal',{'goal':'portal_phish'})['success'])
        self.assertEqual([r['control'] for r in w.repairs],['verify_portal'])
    def test_no_automatic_repair_and_business_cost_visible(self):
        w=agents.World({'controls':{'client_isolation':False}})
        self.assertFalse(w.controls['verify_portal'])
        w.execute('red','set_control',{'control':'client_isolation'})
        self.assertFalse(w.controls['verify_portal'])
        self.assertTrue(any(not c['pass'] for c in w.execute('red','check_business',{})['checks']))
    def test_missing_prerequisite_is_not_auto_executed(self):
        import simulator
        for scenario in simulator.SCENARIO_IDS:
            w=agents.World({'scenario':scenario,'controls':simulator.catalog(scenario)['presets']['exposed']})
            for goal in w.catalog['attack_goals']:
                if goal.get('requires'):
                    self.assertEqual(w.execute('black','attempt_goal',{'goal':goal['id']})['status'],'skipped')
    def test_decision_rejects_invented_targets_and_extra_fields(self):
        tools=agents.tools_for('black',agents.simulator.catalog())
        for name,args in [('shell',{'reason':'x','command':'x'}),('attempt_goal',{'reason':'x','goal':'http://real-target'}),('observe',{'reason':'x','key':'x'})]:
            with patch.object(llm,'_post',return_value=response(name,args)):
                with self.assertRaises(agents.AgentError):agents.decide([],tools,CFG['cloud'])
    def test_bounded_loop_uses_role_models_and_separate_memory(self):
        history=[]
        def decide(messages,tools,cfg):
            history.append((copy.deepcopy(messages),cfg))
            role='black' if cfg['model']=='black' else 'red'
            return chosen('attempt_goal',goal='portal_phish') if role=='black' else chosen('set_control',control='verify_portal')
        with patch.object(llm,'load_config',return_value=CFG),patch.dict('os.environ',{},clear=True):packets=list(agents.run({},rounds=2,decision=decide))
        result=packets[-1]['result'];self.assertEqual(len(result['agent_events']),4)
        self.assertTrue(result['attempts'][0]['success']);self.assertFalse(result['attempts'][1]['success'])
        self.assertEqual([c['api_key'] for _,c in history],['BLACK_TEST','MAIN_TEST']*2)
        self.assertEqual(len(history[0][0]),2);self.assertEqual(len(history[1][0]),2)
        self.assertEqual(result['stop_reason'],'turn_budget')
        self.assertEqual([p['seq'] for p in packets],list(range(1,len(packets)+1)))
    def test_failure_never_becomes_scripted_success(self):
        with patch.object(llm,'load_config',return_value=CFG):packets=list(agents.run({},decision=lambda *a:(_ for _ in ()).throw(agents.AgentError('failed'))))
        self.assertEqual(packets[-1]['type'],'error');self.assertFalse(any(p['type']=='complete' for p in packets))
    def test_close_stops_next_model_call(self):
        calls=[]
        def decision(*a):calls.append(1);return chosen('observe')
        with patch.object(llm,'load_config',return_value=CFG):
            stream=agents.run({},decision=decision);next(stream);next(stream);next(stream);stream.close()
        self.assertEqual(len(calls),1)
    def test_both_finish_ends_early(self):
        with patch.object(llm,'load_config',return_value=CFG):packets=list(agents.run({},decision=lambda *a:chosen('finish')))
        self.assertEqual(packets[-1]['result']['model_api_calls'],2)
        self.assertEqual(packets[-1]['result']['stop_reason'],'both_finished')
if __name__=='__main__':unittest.main()
