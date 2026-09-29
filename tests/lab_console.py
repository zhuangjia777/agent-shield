import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'04_web'))
import app
lab=app.lab_mod

class ConsoleTests(unittest.TestCase):
    def test_fixed_container_sources(self):
        for source,name in [('waf',lab.BLUE_NAME),('target',lab.TARGET_NAME)]:
            with patch.object(lab,'_sh',return_value=(0,'<script>not html</script>')) as sh:
                self.assertTrue(lab.console_logs(source)['ok'])
                self.assertEqual(sh.call_args.args[0],['docker','logs','--timestamps','--tail','200',name])
    def test_unknown_source_never_calls_docker(self):
        with patch.object(lab,'_sh') as sh:
            self.assertFalse(lab.console_logs('../other-container')['ok'])
            sh.assert_not_called()
    def test_missing_container_reports_failure(self):
        with patch.object(lab,'_sh',return_value=(1,'No such container')):
            self.assertFalse(lab.console_logs('waf')['ok'])
    def test_bounded_service_output(self):
        with patch.object(lab,'_sh',return_value=(0,'x'*100000)):
            self.assertEqual(len(lab.console_logs('waf')['text']),65536)
    def test_agent_log_tolerates_partial_records_and_missing_file(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(lab,'LOGDIR',Path(directory)):
            self.assertEqual(lab.console_logs('agent')['text'],'')
            event={'evt':'red_exec','cmd':'echo test','out':'test','exit':0,'secs':1}
            (Path(directory)/'events.jsonl').write_text('[]\n'+json.dumps(event)+'\n{"partial":')
            text=lab.console_logs('agent')['text']
            self.assertIn('$ echo test',text);self.assertIn('exit=0',text)
    def test_http_rejects_arbitrary_source(self):
        h=object.__new__(app.Handler);h.path='/api/lab/logs?source=other'
        h._json=lambda code,value:(code,value)
        with patch.object(lab,'console_logs') as logs:
            self.assertEqual(h.do_GET()[0],400);logs.assert_not_called()
