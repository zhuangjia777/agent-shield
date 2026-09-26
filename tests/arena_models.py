"""Role routing and credential isolation regressions; no live model calls."""
import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'04_web'))
import app
llm=app.llm_mod
MAIN={'base_url':'https://main.invalid/v1','api_key':'FAKE_MAIN','model':'main','max_tokens':900}
OWN={'inherit_main':False,'base_url':'https://red.invalid/v1','api_key':'FAKE_RED','model':'red','max_tokens':800}
class RoleModels(unittest.TestCase):
    def test_defaults_follow_main_changes(self):
        for model in ['one','two']:
            with patch.dict('os.environ',{},clear=True):
                self.assertEqual(llm.role_cloud_cfg('black',{'cloud':{**MAIN,'model':model}})['model'],model)
    def test_independent_never_inherits_key(self):
        cfg={'cloud':MAIN,'arena_models':{'red':{**OWN,'api_key':''}}}
        self.assertEqual(llm.role_cloud_cfg('red',cfg)['api_key'],'')
    def test_get_masks_every_key(self):
        cfg={'cloud':MAIN,'arena_models':{'red':OWN,'black':{**OWN,'api_key':'FAKE_BLACK'}}};before=copy.deepcopy(cfg)
        data=json.dumps(llm.public_config(cfg))
        self.assertNotIn('FAKE_',data);self.assertEqual(before,cfg)
    def test_blank_key_and_inheritance_preserve_own(self):
        cfg={'arena_models':{'red':OWN}}
        updated=llm.merge_config(cfg,{'arena_models':{'red':{'api_key':'','inherit_main':True}}})
        self.assertEqual(updated['arena_models']['red']['api_key'],'FAKE_RED')
        self.assertEqual(cfg['arena_models']['red'],OWN)
    def test_new_endpoint_requires_key_decision(self):
        cfg={'arena_models':{'red':OWN}}
        update={'arena_models':{'red':{'base_url':'https://other.invalid/v1'}}}
        with self.assertRaises(ValueError):llm.merge_config(cfg,update)
        update['arena_models']['red']['clear_api_key']=True
        self.assertEqual(llm.merge_config(cfg,update)['arena_models']['red']['api_key'],'')
    def test_invalid_config_rejected(self):
        for change in [{'model':''},{'base_url':'file:///tmp/x'},{'base_url':'https://user:password@example.com'},{'max_tokens':True},{'max_tokens':0},{'inherit_main':'false'}]:
            with self.assertRaises(ValueError):llm.merge_config({'arena_models':{'red':OWN}},{'arena_models':{'red':change}})
    def test_http_payload_and_key_are_role_specific(self):
        class Response(io.BytesIO): pass
        for key in ['FAKE_RED','']:
            with patch.object(llm.urllib.request,'urlopen',return_value=Response(b'data: {"choices":[{"delta":{"content":"ok"}}]}\n')) as send:
                self.assertEqual(list(llm._cloud_stream([],0,config={**OWN,'api_key':key})),[('content','ok')])
                req=send.call_args.args[0]
                self.assertEqual(req.full_url,OWN['base_url']+'/chat/completions')
                self.assertEqual(req.get_header('Authorization'),('Bearer '+key) if key else None)
                self.assertEqual(json.loads(req.data)['model'],'red')
    def test_review_routes_snapshot_and_keeps_context_separate(self):
        cfg={'cloud':MAIN,'arena_models':{'red':OWN}}
        result={'scenario':'test','mode':'rules','assumptions':[], 'before':{'outcomes':[]},'after':{'outcomes':[],'business_checks':[]},'repair':{},'run_id':'test'}
        with patch.object(llm,'load_config',return_value=cfg),patch.dict('os.environ',{},clear=True),patch.object(llm,'_cloud_stream',return_value=iter([('content','ok')])) as stream:
            stream.side_effect=lambda *a,**k:iter([('content','ok')])
            out=app.arena_review(result)
        self.assertEqual([v['model'] for v in out['reviews']],['main','red'])
        self.assertEqual([v['config_source'] for v in out['reviews']],['main','independent'])
        self.assertEqual([c.kwargs['config']['api_key'] for c in stream.call_args_list],['FAKE_MAIN','FAKE_RED'])
        self.assertIsNot(stream.call_args_list[0].args[0],stream.call_args_list[1].args[0])
    def test_failed_connection_not_success(self):
        with patch.object(llm,'role_cloud_cfg',return_value=OWN),patch.object(llm,'_cloud_stream',side_effect=RuntimeError('FAKE_SECRET')):
            events=list(app._llm_test_stream('red'))
        self.assertFalse(events[-1]['ok']);self.assertNotIn('FAKE_SECRET',str(events))
if __name__=='__main__':unittest.main()
