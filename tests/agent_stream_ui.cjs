const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('04_web/app.py','utf8');
const resume=source.slice(source.indexOf('function resumeStream()'),source.indexOf('function handleAgentEvent'));
const answer=source.slice(source.indexOf('async function answerAgent(text)'),source.indexOf('function agentAsk(t, auto)'));
let streams=0,done,answers=0;
const ctx={agentId:'demo',agentEs:null,handleAgentEvent(){},$:()=>null,
 document:{querySelectorAll:()=>[]},sse:(url,onEvent,onDone)=>{streams++;done=onDone;return {};},
 api:async()=>{answers++;return {ok:true};}};
vm.createContext(ctx);vm.runInContext(resume+answer,ctx);
(async()=>{
 ctx.resumeStream();await ctx.answerAgent('Yes');await ctx.answerAgent('No');
 assert.equal(streams,1);assert.equal(answers,2);
 done();ctx.resumeStream();assert.equal(streams,2);
 console.log('Agent stream: confirmations reuse subscriber, next turn reconnects after done');
})().catch(e=>{console.error(e);process.exitCode=1;});
const choices=source.slice(source.indexOf('function agentQuestionChoices'),source.indexOf('function resumeStream'));
vm.runInContext(choices,ctx);
assert.equal(JSON.stringify(ctx.agentQuestionChoices({question:'确认执行以下命令？',choices:[]})),JSON.stringify(['确认执行','取消']));
assert.equal(JSON.stringify(ctx.agentQuestionChoices({question:'请选择报告',choices:['A','B']})),JSON.stringify(['A','B']));
assert.equal(ctx.agentQuestionChoices({question:'目标是什么？'}).length,0);
assert.equal(JSON.stringify(ctx.agentQuestionChoices({choices:'是|否'})),JSON.stringify(['是','否']));
console.log('Agent questions: missing choices, supplied choices and free-text questions passed');
