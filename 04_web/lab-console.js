(() => {
  'use strict';
  const panel=document.getElementById('lab-console');
  if(!panel) return;
  const source=document.getElementById('lab-log-source');
  const output=document.getElementById('lab-log-output');
  const status=document.getElementById('lab-log-status');
  const pause=document.getElementById('lab-log-pause');
  const follow=document.getElementById('lab-log-follow');
  let paused=false, request=null, timer=null, version=0;
  function cancel(){ version++; clearTimeout(timer); request?.abort(); request=null; }
  async function refresh(){
    if(paused || !panel.open || document.hidden || request) return;
    const token=version, controller=new AbortController(); request=controller;
    const timeout=setTimeout(()=>controller.abort(),10000);
    try{
      const response=await fetch('/api/lab/logs?source='+encodeURIComponent(source.value),{signal:controller.signal,cache:'no-store'});
      const data=await response.json();
      if(token!==version) return;
      if(!response.ok || !data.ok) throw new Error(data.msg || '日志读取失败');
      output.textContent=data.text || '暂无日志。';
      status.textContent='已更新 · '+new Date().toLocaleTimeString();
      if(follow.checked) output.scrollTop=output.scrollHeight;
    }catch(error){
      if(token===version){
        status.textContent=error.name==='AbortError'?'日志读取超时，稍后自动重试。':error.message;
        if(output.textContent==='正在读取日志…') output.textContent='暂无可用日志，请查看下方状态提示。';
      }
    }finally{
      clearTimeout(timeout);
      if(token===version){ request=null; timer=setTimeout(refresh,2000); }
    }
  }
  source.addEventListener('change',()=>{cancel(); output.textContent='正在读取日志…'; status.textContent=paused?'已暂停，恢复后读取所选来源。':''; refresh();});
  pause.addEventListener('click',()=>{
    paused=!paused; cancel(); pause.textContent=paused?'恢复刷新':'暂停刷新';
    pause.setAttribute('aria-pressed',String(paused)); status.textContent=paused?'已暂停刷新，容器继续运行。':'正在恢复刷新…'; refresh();
  });
  document.getElementById('lab-log-copy').addEventListener('click',async()=>{
    try{await navigator.clipboard.writeText(output.textContent);status.textContent='日志已复制。';}
    catch{status.textContent='复制失败，请选中日志手动复制。';}
  });
  panel.addEventListener('toggle',()=>{cancel();refresh();});
  document.addEventListener('visibilitychange',()=>{cancel();refresh();});
  window.addEventListener('pagehide',cancel);
  refresh();
})();
