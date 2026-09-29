// Exercise the range controls without touching a real Docker range.
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync('04_web/arena.js','utf8').split('// ── Docker 实战演练状态卡')[1].replace(/^[^\n]*\n/, '').replace(/\}\)\(\);\s*$/, '');
const buttons=[{},{},{}];
const elements={'#lab-state':{},'#lab-message':{},'#live-lab-card':{querySelectorAll:()=>buttons}};
let calls=0, finish;
const ctx={window:{}, $:s=>elements[s], fetch:async(url)=>{
 if(url==='/api/lab/status') return {ok:true,json:async()=>({running:false,docker_ok:true})};
 calls++;return await new Promise(resolve=>finish=resolve);
}};
vm.createContext(ctx);vm.runInContext(source,ctx);
(async()=>{
 const pending=ctx.window.labStop();
 assert(buttons.every(b=>b.disabled));
 await ctx.window.labStop(); assert.equal(calls,1);
 finish({ok:true,json:async()=>({ok:true})}); await pending;
 assert(buttons.every(b=>!b.disabled));assert.match(elements['#lab-message'].textContent,/已停止/);
 const failed=ctx.window.labStop();finish({ok:false,json:async()=>({ok:false,msg:'Docker unavailable'})});await failed;
 assert.match(elements['#lab-message'].textContent,/清理未完成/);
 assert(buttons.every(b=>!b.disabled));
 ctx.fetch=async()=>{throw new Error('offline')};await ctx.window.labStop();
 assert.match(elements['#lab-message'].textContent,/请求失败/);
 assert(buttons.every(b=>!b.disabled));
 console.log('Lab stop UI: success, duplicate click, backend failure, network failure passed');
})().catch(e=>{console.error(e);process.exitCode=1});
