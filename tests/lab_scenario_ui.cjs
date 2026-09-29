const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync('04_web/arena.js','utf8').split('// ── Docker 实战演练状态卡')[1].replace(/^[^\n]*\n/,'').replace(/\}\)\(\);\s*$/,'');
const elements={};
for(const id of ['lab-message','lab-scenario','lab-scenario-note','lab-guide','scenario']){
  elements['#'+id]={value:'',listeners:{},addEventListener(type,fn){this.listeners[type]=fn;}};
}
Object.defineProperty(elements['#lab-scenario'],'innerHTML',{set(html){this.value=(html.match(/value="([^"]*)"/)||[])[1]||'';}});
const scenarios={bac_enumeration:{name:'越权',blurb:'越权',oracle:'证据'},sqli_session:{name:'SQL',blurb:'SQL',oracle:'证据'}};
let prompt;
const ctx={window:{},$:s=>elements[s],catalogs:null,running:false,escapeHTML:s=>String(s),
  location:{search:''},URLSearchParams,console,agentAsk:text=>{prompt=text;},
  fetch:async(url,options)=>{
    if(url==='/api/lab/scenarios') return {ok:true,json:async()=>({scenarios})};
    throw new Error("Unexpected request: "+url);
  }};
vm.createContext(ctx);vm.runInContext(source,ctx);
(async()=>{
  await new Promise(resolve=>setImmediate(resolve));
  ctx.catalogs={};
  elements['#scenario'].value='agent_prompt_injection';
  vm.runInContext('labSyncScenario()',ctx);
  assert(elements['#lab-guide'].disabled);
  ctx.window.labGuide(); assert.equal(prompt,undefined);
  assert.match(elements['#lab-scenario-note'].textContent,/仅支持/);
  elements['#scenario'].value='api_authorization';
  vm.runInContext('labSyncScenario()',ctx);
  assert.equal(elements['#lab-scenario'].value,'bac_enumeration');
  assert(!elements['#lab-guide'].disabled);
  ctx.window.labGuide();
  assert.match(prompt,/scenario=bac_enumeration/);
  elements['#scenario'].value='live:sqli_session';
  vm.runInContext('labSyncScenario()',ctx);
  assert.equal(elements['#lab-scenario'].value,'sqli_session');
  assert.equal(elements['#lab-message'].textContent,'');
  ctx.window.labGuide();
  assert.match(prompt,/scenario=sqli_session/);
  assert.match(prompt,/完整命令并等待用户确认/);
  assert.match(prompt,/不要调用 lab_scenario/);
  console.log('Lab scenario UI: matching, unsupported scenarios and stepwise Agent guidance passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
