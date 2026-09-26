const fs=require('fs'),vm=require('vm'),assert=require('assert');
// Test the UI state machine with synthetic responses; no real scans or model calls.
const appSource=fs.readFileSync(require('path').join(__dirname,'../04_web/app.py'),'utf8');
const src=appSource.slice(appSource.indexOf('let scanInFlight = false;'),appSource.indexOf('// ---------- 设置 ----------'));
assert(src.includes('async function startScan()'));
function setup(fetch){const els={}; for(const id of ['scan-start','scan-system','scan-network','checkup-status','scan-message','scan-result','scan-running-note'])els[id]={checked:id==='scan-system',hidden:true,disabled:false,textContent:''}; const context={fetch,location:{},$:s=>els[s.slice(1)]};vm.createContext(context);vm.runInContext(src,context);return {els,run:()=>vm.runInContext('startScan()',context)};}
(async()=>{
let calls=[],resolve; const t=setup((url,args)=>{calls.push([url,JSON.parse(args.body)]);return new Promise(r=>resolve=r)});
const pending=t.run(); await t.run();assert.equal(calls.length,1);assert.deepEqual(calls[0][1],{sys:1,lan:0});assert(t.els['scan-start'].disabled);assert(!t.els['scan-running-note'].hidden);
resolve({ok:true,json:async()=>({ok:true,report:'scan-demo'})});await pending;assert.equal(t.els['scan-result'].href,'/report/scan-demo');assert(!t.els['scan-result'].hidden);assert(!t.els['scan-start'].disabled);
t.els['scan-system'].checked=false;await t.run();assert.equal(calls.length,1);assert(t.els['scan-message'].textContent.includes('至少'));assert(t.els['scan-result'].hidden);
let payload;const fail=setup(async(_,a)=>{payload=JSON.parse(a.body);throw Error('private internal diagnostic')});fail.els['scan-system'].checked=false;fail.els['scan-network'].checked=true;await fail.run();assert.deepEqual(payload,{sys:0,lan:1});assert(fail.els['scan-result'].hidden);assert(!fail.els['scan-start'].disabled);assert(!fail.els['scan-message'].textContent.includes('private'));
console.log('PASS: system-only default, duplicate submission guard, success report link, empty selection, network-only selection, failure recovery.');
})();
