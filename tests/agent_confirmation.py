"""Confirmation must retain the proposed action across model turns."""
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / '03_ai'))
import agent

class ConfirmationContextTests(unittest.TestCase):
    def test_question_and_action_remain_in_context(self):
        for ask in ('Ask: Run demo command?\nChoices: Yes|No',
                    'Action: Ask\nActionInput: {"question":"Run demo command?","choices":["Yes","No"]}'):
            with self.subTest(ask=ask):
                seen=[]
                action='Action: lab_attack\nActionInput: {"cmd":"demo-command","confirmed":true}'
                responses=iter([ask,action,'Final Answer: Completed'])
                def stream(messages, **kwargs):
                    seen.append([dict(m) for m in messages])
                    yield 'token',next(responses)
                events=[]
                with patch.object(agent,'chat_stream',stream), patch.object(agent,'_observations',return_value='{}'):
                    agent.ReActAgent([]).run('Test',lambda k,v:events.append(k),lambda q,c:'Yes',
                                             execute_callback=lambda t,i,m='confirm':('demo-result',True))
                self.assertIn({'role':'assistant','content':ask},seen[1])
                self.assertIn({'role':'assistant','content':action},seen[2])
                self.assertEqual(events.count('ask'),1)
                self.assertEqual(events.count('tool_call'),1)

class AskFormatTests(unittest.TestCase):
    def test_supported_formats_preserve_command(self):
        question = '确认执行 curl http://aslab-blue:8080/?q=%3Cscript%3E？'
        import json
        for raw in (
            'Action: Ask\nAction Input: '+json.dumps({'question':question}),
            '**Action:** Ask\n**Action Input:** '+json.dumps({'question':question}),
            'Action: Ask\nActionInput: '+json.dumps(question),
            'Action: Ask\nActionInput: '+question+'\nChoices: 确认执行|取消',
            'Action: Ask\nActionInput: ```json\n'+json.dumps({'question':question})+'\n```',
            'Action: Ask\nActionInput: '+json.dumps({'prompt':question}),
        ):
            with self.subTest(raw=raw):
                parsed=agent._parse(raw,[])
                self.assertEqual(parsed['input']['question'],question)

    def test_empty_ask_stops_without_executing_or_retrying(self):
        from unittest.mock import Mock
        stream=Mock(return_value=iter([('token','Thought: Need consent\nAction: Ask\nActionInput: {}')]))
        execute=Mock(); answer=Mock(); events=[]
        with patch.object(agent,'chat_stream',stream), patch.object(agent,'_observations',return_value='{}'):
            agent.ReActAgent([]).run('Test',lambda k,v:events.append(k),answer,execute_callback=execute)
        self.assertEqual(stream.call_count,1)
        self.assertIn('error',events)
        answer.assert_not_called();execute.assert_not_called()
