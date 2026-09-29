// 实时控制台：WAF / 靶机 / Agent 三个日志窗口平铺，各自独立轮询，只读。
(() => {
  'use strict';
  const panel=document.getElementById('lab-console');
  if(!panel) return;
  const status=document.getElementById('lab-log-status');
  const pause=document.getElementById('lab-log-pause');
  const copy=document.getElementById('lab-log-copy');
  const follow=document.getElementById('lab-log-follow');
  const panes=[...panel.querySelectorAll('.lab-log-output')];
  let paused=false, timer=null, version=0;
  const state=panes.map(()=>({request:null, text:''}));
  function cancel(){ version++; clearTimeout(timer); state.forEach(s=>{s.request?.abort(); s.request=null;}); }
  function say(msg){ const parts=[]; panes.forEach((el,i)=>{ if(state[i].error) parts.push(el.previousElementSibling.textContent+'：'+state[i].error); });
    status.textContent = msg || (parts.length ? parts.join('　') : '已更新 · '+new Date().toLocaleTimeString()); }
  async function fetchPane(i){
    const el=panes[i], s=state[i];
    if(s.request) return;
    const token=version, controller=new AbortController(); s.request=controller;
    const timeout=setTimeout(()=>controller.abort(),10000);
    try{
      const response=await fetch('/api/lab/logs?source='+encodeURIComponent(el.dataset.source),{signal:controller.signal,cache:'no-store'});
      const data=await response.json();
      if(token!==version) return;
      if(!response.ok || !data.ok) throw new Error(data.msg || '日志读取失败');
      s.text=data.text || ''; s.error=null;
      el.textContent=s.text || '暂无日志。';
      if(follow.checked) el.scrollTop=el.scrollHeight;
    }catch(error){
      if(token===version){
        s.error=error.name==='AbortError'?'读取超时，稍后自动重试':error.message;
        if(!s.text) el.textContent='暂无可用日志，请查看下方状态提示。';
      }
    }finally{
      clearTimeout(timeout);
      if(token===version) s.request=null;
    }
  }
  async function tick(){
    if(paused || !panel.open || document.hidden) return;
    await Promise.all(panes.map((_,i)=>fetchPane(i)));
    say();
  }
  function loop(){ clearTimeout(timer); timer=setTimeout(async()=>{ await tick(); loop(); },2000); }
  pause.addEventListener('click',()=>{
    paused=!paused; cancel(); pause.textContent=paused?'恢复刷新':'暂停刷新';
    pause.setAttribute('aria-pressed',String(paused));
    say(paused?'已暂停刷新，容器继续运行。':'正在恢复刷新…');
    if(!paused){ tick().then(loop); }
  });
  copy.addEventListener('click',async()=>{
    const all=panes.map((el,i)=>'【'+el.previousElementSibling.textContent+'】\n'+(state[i].text||'')).join('\n\n');
    try{await navigator.clipboard.writeText(all);status.textContent='全部日志已复制。';}
    catch{status.textContent='复制失败，请选中日志手动复制。';}
  });
  panel.addEventListener('toggle',()=>{cancel(); tick().then(loop);});
  document.addEventListener('visibilitychange',()=>{cancel(); tick().then(loop);});
  window.addEventListener('pagehide',cancel);
  tick().then(loop);
})();
