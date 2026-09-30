/* aslab-wrap */ (function(){
'use strict';
const $ = s => document.querySelector(s);
const escapeHTML = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
let catalogs, catalog, result, generation = 0, reviewing = false, lastReview = null;
let controller = null, running = false, packets = [], shown = 0, total = 0;
let counters, currentPhase = 'before';
const names = {black:'红队 · 攻击', red:'蓝队 · 防守', judge:'规则裁判'};
const stages = {agents:'智能体对攻',before:'初始对攻', repair:'蓝队加固', after:'同场景复测', complete:'结果复盘'};
const verdicts = {applied:'已应用',observed:'已观察',finished:'本方结束',success:'目标达成', blocked:'已阻断', skipped:'前置未满足', alert:'已检测', unobserved:'未监测', reachable:'可达', accepted:'生效', pass:'通过', regression:'业务受影响'};
const status = text => { $('#status').textContent = text; };
async function post(url, body) {
  const response = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body)});
  const data = await response.json();
  if (!response.ok || !data.ok) throw new Error(data.msg || '请求失败');
  return data;
}
function controls() { return Object.fromEntries(Object.keys(catalog.controls).map(k => [k, $('#c-'+k).checked])); }
function setRunning(value) {
  running = value; document.body.classList.toggle('running', value);
  $('#run').disabled = value || !catalog; $('#scenario').disabled = value || !catalog; $('#arena-mode').disabled=value; $('#stop').classList.toggle('hidden', !value);
  document.querySelectorAll('#controls input,[data-preset]').forEach(b => b.disabled = value || !catalog);
  document.querySelectorAll('[data-phase]').forEach(b => b.disabled = value || !packets.length);
  $('#review').disabled = value || !result || reviewing || result.mode==='llm_agents'; $('#export').disabled = value || !result;
}
function emptyFeeds() { $('#black-feed').innerHTML = ''; $('#red-feed').innerHTML = ''; }
function reset() {
  result = null; lastReview = null; packets = []; shown = 0; total = 0;
  counters = {before:{achieved:0,checked:0},after:{achieved:0,checked:0},repair:0,business:0};
  $('#reviews').classList.add('hidden');
  $('#before-count').textContent = '— / '+catalog.attack_goals_total; $('#after-count').textContent = '— / '+catalog.attack_goals_total;
  $('#business-count').textContent = '— / '+catalog.business_total; $('#repair-count').textContent = '—';
  $('#progress-fill').style.width = '0%'; $('#progress-text').textContent = '等待事件';
  $('#evidence').textContent = '等待服务器事件…'; $('#run-label').textContent = '尚未完成';
  document.querySelectorAll('[data-stage]').forEach(s => s.classList.remove('active','done'));
  document.querySelectorAll('[data-phase]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.phase === 'all')));
  emptyFeeds();
}
function invalidate() {
  if (running) return;
  generation++; reset(); setRunning(false);
  $('#black-state').textContent = '等待演练'; $('#red-state').textContent = '等待演练';
  $('#black-feed').innerHTML = '<div class="empty"><b>进攻视角已就绪</b>开始后显示红队路径与目标结果</div>';
  $('#red-feed').innerHTML = '<div class="empty"><b>防守视角已就绪</b>开始后显示对应检测、加固与复测</div>';
  status('配置已就绪，点击开始实时演练。');
}
function preset(key) {
  if (running) return;
  for (const [k, value] of Object.entries(catalog.presets[key])) $('#c-'+k).checked = value;
  invalidate();
}
function append(side, html) {
  const feed = $(side === 'black' ? '#black-feed' : '#red-feed');
  feed.insertAdjacentHTML('beforeend', html);
  if ($('#autoscroll').checked) feed.scrollTop = feed.scrollHeight;
}
function setStage(phase) {
  currentPhase = phase;
  const index = ['before','repair','after','complete'].indexOf(phase);
  document.querySelectorAll('[data-stage]').forEach((s,i) => {s.classList.toggle('active', i === index);s.classList.toggle('done', i < index);});
  $('#black-state').textContent = phase === 'repair' ? '等待复测' : stages[phase];
  $('#red-state').textContent = stages[phase];
}
function toolSummary(e) {
  const o=e.evidence.output||{};
  if(e.action==='observe')return '观察到 '+(o.topology||[]).length+' 个虚拟节点；本方已有 '+(o.own_attempts||[]).length+' 次尝试。';
  if(e.action==='inspect_alerts')return '当前有 '+(o.alerts||[]).length+' 条告警，'+Object.values(o.controls||{}).filter(Boolean).length+' 项防护已开启。';
  if(e.action==='set_control')return (catalog.controls[o.control]?.name||o.control)+'：'+(o.changed?'已开启':'原本已开启')+'。';
  if(e.action==='check_business')return '业务检查 '+(o.checks||[]).filter(c=>c.pass).length+' / '+(o.checks||[]).length+' 通过。'+(o.checks||[]).filter(c=>!c.pass).map(c=>c.name+'受影响').join('；');
  if(e.action==='attempt_goal')return (catalog.attack_goals.find(g=>g.id===o.id)?.name||o.id)+'：'+(verdicts[o.status]||o.status)+(o.blocked_by?.length?'，防护措施：'+o.blocked_by.map(k=>catalog.controls[k]?.name||k).join('、'):'')+'。';
  return '本方已结束本轮行动。';
}
function syncMode() {
  const labels=$('#arena-mode').value==='agents'?['01 观察环境','02 自主决策','03 调用工具','04 裁判复测']:['01 初始对攻','02 蓝队加固','03 同场景复测','04 结果复盘'];
  document.querySelectorAll('[data-stage]').forEach((e,i)=>e.textContent=labels[i]);
  document.querySelectorAll('[data-phase]').forEach(e=>e.hidden=$('#arena-mode').value==='agents'&&e.dataset.phase!=='all');
}
function showPacket(packet) {
  if (packet.type === 'phase') {
    for (const side of ['black','red']) append(side, `<div class="divider">${escapeHTML(stages[packet.phase])}</div>`);
  } else if (packet.type === 'repair') {
    const r = packet.repair;
    append('red', `<article class="event"><div class="event-meta"><span>虚拟策略变更</span><span class="verdict">已应用</span></div><b>${escapeHTML(r.name)}</b><p>${escapeHTML(r.description)}</p><div class="correlation">实施角色：${escapeHTML(r.owner)}</div><pre class="expert-only">${escapeHTML(JSON.stringify(r,null,2))}</pre></article>`);
  } else if (packet.type === 'event') {
    const e = packet.event;
    append(e.side, `<article class="event ${escapeHTML(e.side)}"><div class="event-meta"><span>${escapeHTML(stages[packet.phase])} / ${escapeHTML(e.id)} / 步 ${e.tick}</span><span class="verdict ${escapeHTML(e.result)}">${escapeHTML(verdicts[e.result] || e.result)}</span></div><b>${e.side === 'judge' ? '业务裁判 · ' : ''}${escapeHTML(({observe:'观察环境',attempt_goal:'尝试目标',inspect_alerts:'核对告警',set_control:'应用防护',check_business:'检查业务',finish:'结束行动'})[e.action]||e.action)}</b><p>${escapeHTML(e.detail)}</p>${e.model_selected?`<div class="correlation">模型 ${escapeHTML(e.evidence.model)} · 第 ${e.evidence.round} 轮 · ${escapeHTML(toolSummary(e))}</div>`:''}${e.evidence.related_event ? `<div class="correlation">↳ 对应红队 ${escapeHTML(stages[packet.phase])} / ${escapeHTML(e.evidence.related_event)}</div>` : ''}<pre class="expert-only">${escapeHTML(JSON.stringify(e.evidence,null,2))}</pre></article>`);
  }
}
function receive(packet) {
  if(packet.type==='error')throw new Error(packet.msg||'智能体执行未完成');
  if(packet.type==='agent_state'){
    document.querySelectorAll('[data-stage]').forEach((e,i)=>e.classList.toggle('active',i===1));
    $('#'+packet.side+'-state').textContent='第 '+packet.round+' 轮 · 决策中';
    status(names[packet.side]+' · '+packet.model+' 正在选择工具…');return;
  }

  if (packet.type === 'start') { total = packet.total_events; $('#run-label').textContent = 'RUN / '+packet.run_id; if(packet.mode==='llm_agents'){setStage('agents');status('红蓝智能体已连接，等待首个决策…');} return; }
  if (packet.type === 'complete') {
    result = packet.result; setStage('complete');
    $('#progress-text').textContent = '已完成 · '+shown+' 条事件';
    $('#progress-fill').style.width = '100%'; $('#evidence').textContent = JSON.stringify(result,null,2);
    $('#repair-count').textContent = result.repair.length+' 项';
    $('#before-count').textContent=result.before.metrics.attack_goals_achieved+' / '+catalog.attack_goals_total;
    $('#after-count').textContent=result.after.metrics.attack_goals_achieved+' / '+catalog.attack_goals_total;
    $('#business-count').textContent=result.after.metrics.business_passed+' / '+catalog.business_total;
    if(result.mode==='llm_agents'){
      status('智能体本轮结束 · '+result.model_api_calls+' 次模型决策 · '+(result.stop_reason==='turn_budget'?'达到轮次上限':'双方结束')+' · 可导出工具记录');return;
    }

    status('演练完成 · 可比较前后结果、复盘或导出证据'); return;
  }
  packets.push(packet); showPacket(packet);
  if (packet.type === 'phase') {
    setStage(packet.phase); status(stages[packet.phase]+' · 正在接收合成事件');
    if (packet.phase === 'before' || packet.phase === 'after') $('#'+packet.phase+'-count').textContent = '0 / '+catalog.attack_goals_total;
  } else {
    shown++;
    if (packet.type === 'repair') $('#repair-count').textContent = (++counters.repair)+' 项';
    if (packet.type === 'event') {
      const e = packet.event;
      if(packet.phase==='agents')document.querySelectorAll('[data-stage]').forEach((e,i)=>e.classList.toggle('active',i===2));
      if (packet.phase!=='agents' && Object.hasOwn(e.evidence, 'goal_achieved')) {
        const c = counters[packet.phase]; c.checked++; c.achieved += Number(e.evidence.goal_achieved);
        $('#'+packet.phase+'-count').textContent = c.achieved+' / '+catalog.attack_goals_total;
      }
      if (packet.phase === 'after' && e.side === 'judge') { counters.business += Number(e.evidence.pass); $('#business-count').textContent = counters.business+' / '+catalog.business_total; }
      status(stages[packet.phase]+' · '+names[e.side]+'：'+e.action);
    }
    $('#progress-text').textContent = shown+' / '+total+' 条事件';
    $('#progress-fill').style.width = (total ? shown/total*100 : 0)+'%';
  }
  if ($('#expert-toggle').open) $('#evidence').textContent = JSON.stringify({status:'in_progress',events:packets},null,2);
}
$('#run').onclick = async () => {
  if (running) return;
  const current = ++generation, input = controls(), selectedScenario = catalog.scenario; reset(); setRunning(true);
  $('.toolbar').scrollIntoView({block:'start',behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'});
  controller = new AbortController(); status('正在连接演练事件流…');
  try {
    const response = await fetch($('#arena-mode').value==='agents'?'/api/arena/agents':'/api/arena/stream', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scenario:selectedScenario,controls:input}),signal:controller.signal});
    if (!response.ok) {const e = await response.json(); throw new Error(e.msg || '事件流不可用');}
    if (!response.body) throw new Error('当前浏览器不支持流式响应');
    const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '', sequence = 0;
    while (true) {
      const {done,value} = await reader.read(); if (current !== generation) return;
      buffer += done ? decoder.decode() : decoder.decode(value,{stream:true});
      let newline;
      while ((newline=buffer.indexOf('\n')) !== -1) {
        const line=buffer.slice(0,newline); buffer=buffer.slice(newline+1); if (!line.trim()) continue;
        const packet=JSON.parse(line); if (packet.scenario !== selectedScenario) throw new Error('事件场景不匹配，请重新演练'); if (packet.seq !== ++sequence) throw new Error('事件顺序异常，请重新演练');
        receive(packet);
      }
      if (done) break;
    }
    if (!result || buffer.trim()) throw new Error('事件流中断，未收到完整结果');
  } catch (e) {
    if (current === generation && e.name !== 'AbortError') { controller.abort(); result=null; status('演练未完成：'+e.message); $('#progress-text').textContent='未完成'; }
  } finally { if (current === generation) {controller=null;setRunning(false);} }
};
$('#stop').onclick = () => {
  generation++; if (controller) controller.abort(); controller=null; result=null; setRunning(false);
  $('#black-state').textContent='已停止'; $('#red-state').textContent='已停止';
  $('#progress-text').textContent='已停止 · '+shown+' 条事件'; status('已停止接收新动作；正在进行的模型请求返回或超时后结束。保留已收到记录，本轮未完成。');
  $('#evidence').textContent=JSON.stringify({status:'cancelled',events:packets},null,2);
};
$('#depth').onchange = () => document.body.classList.toggle('expert', $('#depth').value === 'expert');
$('#expert-toggle').ontoggle = () => {
  if ($('#expert-toggle').open) { $('#depth').value='expert'; document.body.classList.add('expert'); $('#evidence').textContent=JSON.stringify(result || {status:running?'in_progress':'incomplete',events:packets},null,2); }
};
document.querySelectorAll('[data-phase]').forEach(b => b.onclick = () => {
  if (running) return; emptyFeeds();
  packets.filter(p => b.dataset.phase === 'all' || p.phase === b.dataset.phase).forEach(showPacket);
  document.querySelectorAll('[data-phase]').forEach(x => x.setAttribute('aria-pressed', String(x === b)));
});
document.querySelectorAll('[data-preset]').forEach(b => { b.disabled=true; b.onclick=()=>preset(b.dataset.preset); });
$('#review').onclick = async () => {
  if (!result || reviewing || running) return;
  const current=generation; reviewing=true; $('#review').disabled=true;
  $('#reviews').classList.remove('hidden'); $('#reviews').textContent='私有模型正在分别复盘红队与蓝队行为…';
  try {
    const review=await post('/api/arena/review', {scenario:result.scenario,controls:result.before.controls});
    if (current !== generation) return; lastReview=review;
    $('#reviews').innerHTML='<p class="tip">模型解读 · 仅供参考，裁判结果不变</p><div class="review-grid">'+review.reviews.map(r=>`<section><h3>${escapeHTML(names[r.role])}</h3><span class="tip">${escapeHTML(r.model)} · ${r.config_source==='independent'?'独立配置':'沿用主模型'}</span><p class="review">${escapeHTML(r.text)}</p></section>`).join('')+'</div>';
  } catch(e) { if (current === generation) $('#reviews').textContent=e.message; }
  finally { reviewing=false; $('#review').disabled=running || !result || result.mode==='llm_agents'; }
};
$('#export').onclick = () => {
  if (!result || running) return;
  const url=URL.createObjectURL(new Blob([JSON.stringify({...result,model_review:lastReview},null,2)],{type:'application/json'}));
  const a=document.createElement('a');a.href=url;a.download='arena-'+result.scenario+'-'+result.run_id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
};
function selectScenario(key) {
  if (running || labStopping) return;
  if (key.startsWith('live:')) {
    const id=key.slice(5), spec=labScenarios[id];
    if(!spec) return;
    catalog=null; $('#scenario').value=key;
    document.title=spec.name+' · AgentShield';
    $('#scenario-eyebrow').textContent='DOCKER / LIVE ARENA';
    $('#scenario-intro').textContent=spec.blurb;
    $('#arena-kind').textContent='Docker / 本机隔离实战';
    $('#virtual-arena').hidden=true;
    history.replaceState(history.state,'',location.pathname+'?scenario='+encodeURIComponent(key));
    labSyncScenario();
    return;
  }
  if (!catalogs[key]) return;
  $('#virtual-arena').hidden=false;
  $('#arena-kind').textContent='模型智能体 / 虚拟环境';
  catalog=catalogs[key]; $('#scenario').value=key;
  document.title=catalog.name+' · AgentShield';
  $('#scenario-eyebrow').textContent=catalog.eyebrow; $('#scenario-intro').textContent=catalog.description;
  $('#controls-note').textContent=catalog.controls_note;
  $('#scenario-focus').textContent=catalog.focus || '先比较薄弱与日常配置，再查看哪些措施阻断攻击、是否影响正常业务。';
  const goals=catalog.attack_goals || [], goalNames=Object.fromEntries(goals.map(g=>[g.id,g.name]));
  $('#case-list').innerHTML=goals.map(g=>`<li>${escapeHTML(g.name)}${g.requires.length ? `<small>前置：${escapeHTML(g.requires.map(k=>goalNames[k] || k).join('、'))}</small>` : ''}</li>`).join('');
  $('#skill-workflow').classList.toggle('hidden',key !== 'malicious_skill');
  $('#topology').innerHTML=catalog.topology.map(n=>'<b>'+escapeHTML(n.name)+'</b>').join('<span class="line"></span>');
  $('#controls').innerHTML=Object.entries(catalog.controls).map(([name,c])=>`<label><input type="checkbox" id="c-${escapeHTML(name)}"><span>${escapeHTML(c.name)}<small>${escapeHTML(c.description)}</small></span></label>`).join('');
  $('#assumptions').innerHTML=catalog.assumptions.map(x=>'<li>'+escapeHTML(x)+'</li>').join('');
  document.querySelector('[data-preset="hardened"]').textContent=catalog.hardened_label || '全面加固';
  history.replaceState(history.state,'',location.pathname+'?scenario='+encodeURIComponent(key));
  preset('everyday'); setRunning(false); labSyncScenario();
  document.dispatchEvent(new Event('agentshield:scenario-ready'));
}
$('#arena-mode').onchange=()=>{syncMode();invalidate();};
syncMode();
$('#scenario').onchange=()=>selectScenario($('#scenario').value);
$('#controls').addEventListener('change',invalidate);
fetch('/api/arena/scenarios').then(r=>{if(!r.ok)throw new Error('场景不可用');return r.json();}).then(data=>{
  catalogs=data.scenarios;
  $('#scenario').innerHTML=Object.entries(catalogs).map(([key,c])=>`<option value="${escapeHTML(key)}">${escapeHTML(c.name)}</option>`).join('');
  labAddOptions();
  const requested=new URLSearchParams(location.search).get('scenario');
  selectScenario(Object.hasOwn(catalogs,requested) || (requested || '').startsWith('live:') ? requested : data.default);
}).catch(e=>status('加载失败：'+e.message));

// ── Docker 实战演练状态卡 ──────────────────────────────
let labStopping = false;
async function labStatus(){
  const el=$('#lab-state'); if(!el) return;
  try{
    const r=await fetch('/api/lab/status'); if(!r.ok) throw new Error(); const j=await r.json();
    if(labStopping) return;
    el.innerHTML = j.running
      ? `<span class="dot"></span> 运行中 · WAF ${j.waf==='block'?'已开启':'已关闭'} · 人视角 <a href="${j.waf_url}" target="_blank" rel="noopener">${j.waf_url}</a>`
      : j.docker_ok ? '<span class="dot"></span> 就绪（未起场）' : '<span class="dot"></span> Docker 不可用';
  }catch(e){ el.innerHTML='<span class="dot"></span> 状态查询失败'; }
}
if($('#lab-check')){ labStatus(); }

async function labStop(){
  if(labStopping) return;
  labStopping=true;
  const buttons=Array.from($('#live-lab-card').querySelectorAll('button'));
  buttons.forEach(b=>b.disabled=true);
  const message=$('#lab-message');
  message.textContent='正在停止并清理演练场…';
  try{
    const r=await fetch('/api/lab/stop',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
    const j=await r.json();
    message.textContent=r.ok && j.ok ? '演练场已停止，容器与网络已清理。' : '清理未完成，请检查 Docker 后重试。';
    if(!j.ok && j.msg) message.textContent+=' '+j.msg;
  }catch(e){message.textContent='停止请求失败，请刷新状态后重试。';}
  finally{
    labStopping=false;
    buttons.forEach(b=>b.disabled=false);
    labScenarioUpdate();
    await labStatus();
  }
}
window.labStop = labStop;
window.labStatus = labStatus;

// ── Docker 场景与 Agent 引导 ───────────────
const labScenarios = {};
async function labScenariosLoad(){
  const sel = $('#lab-scenario'); if(!sel) return;
  try{
    const r = await fetch('/api/lab/scenarios'); if(!r.ok) throw new Error();
    const j = await r.json();
    Object.assign(labScenarios, j.scenarios || {});
    labAddOptions();
    const requested=new URLSearchParams(location.search).get('scenario');
    if(catalogs && (requested || '').startsWith('live:')) selectScenario(requested);
    labSyncScenario();
  }catch(e){ sel.innerHTML='<option>场景加载失败</option>'; }
}
function labAddOptions(){
  const select=$('#scenario'); if(!select || !catalogs) return;
  const selected=select.value;
  for(const [id,s] of Object.entries(labScenarios).reverse()){
    if(id==='bac_enumeration' || select.querySelector(`option[value="live:${id}"]`)) continue;
    const option=document.createElement('option'); option.value='live:'+id;
    option.textContent=s.name+' · Docker 实战'; select.prepend(option);
  }
  select.value=selected;
}
function labSyncScenario(){
  const sel=$('#lab-scenario'); if(!sel) return;
  const key=$('#scenario').value;
  $('#lab-message').textContent='';
  const id=key==='api_authorization' ? 'bac_enumeration' : key==='ops_agent_broker' ? 'ssh_banner_agent' : key.startsWith('live:') ? key.slice(5) : '';
  const spec=labScenarios[id];
  sel.innerHTML=spec ? `<option value="${escapeHTML(id)}">${escapeHTML(spec.name)}</option>` : '<option value="">当前场景暂无 Docker 实战</option>';
  sel.disabled=true;
  $('#lab-scenario-note').textContent=spec
    ? spec.blurb+'  裁判判据：'+spec.oracle+(key==='api_authorization'?'（实战仅覆盖跨用户枚举，其他用例仍为合成推演。）':'')
    : '当前场景仅支持下方合成环境推演。要运行 Docker，请在上方选择 Web / API 越权访问、SQL 注入或 XSS 编码绕过。';
  labScenarioUpdate();
}
function labScenarioUpdate(){
  const sel=$('#lab-scenario'); if(!sel) return;
  const busy=labStopping;
  const unavailable=!labScenarios[sel.value];
  for(const id of ['#lab-guide']){
    if($(id)) $(id).disabled=busy || unavailable;
  }
  if($('#scenario')) $('#scenario').disabled=busy || running || !catalogs;
}
function labGuide(){
  const key=$('#lab-scenario').value, spec=labScenarios[key];
  if(!spec || labStopping) return;
  agentAsk(`在 Docker 实战演练场里一步步引导用户验证「${spec.name}」（scenario=${key}）。验证目标：${spec.oracle}。覆盖边界：${spec.boundary || spec.blurb}。先检查并按需启动隔离演练场，再根据工具反馈规划每一步；攻击前展示完整命令并等待用户确认，确认后通过 lab_attack 执行，结合工具返回与靶机记录解释结果；如切换 WAF，结束后恢复原状态。不要调用 lab_scenario 一键固定剧本。`, true);
}
window.labGuide=labGuide;
if($('#lab-scenario')){
  labScenariosLoad().then(labScenarioUpdate);
  $('#lab-scenario').addEventListener('change', labScenarioUpdate);

}

// ── 红方控制台：在页面里激活红方 Agent 自主进攻 ─────────────
// 走现成后端：POST /api/agent/new {message, objective} + SSE /api/agent/<id>/event
const RC_VECTORS = {sqli:'SQL 注入 / 会话劫持', xss:'XSS 编码绕过', bac:'越权 / 跨用户枚举', ssh:'SSH 横幅注入 / 策反运维 Agent', recon:'自由侦察'};
const rc = {id:null, es:null, log:null};
function rcLogEl(){
  if(!rc.log) rc.log = $('#rc-log');
  return rc.log;
}
function rcPush(html){
  const log = rcLogEl(); if(!log) return;
  log.insertAdjacentHTML('beforeend', html);
  log.scrollTop = log.scrollHeight;
}
function rcState(text, on=false){
  const el=$('#rc-state'); if(!el) return;
  el.innerHTML=(on?'<span class="dot"></span> ':'')+text;
}
function rcNote(text){
  const el=$('#rc-step'); if(el) el.textContent=text;
}
function rcBusy(v){
  rcStartBtn().disabled = v; $('#rc-vector').disabled = v; $('#rc-mode').disabled = v; $('#rc-note').disabled = v;
  $('#rc-stop').classList.toggle('hidden', !v);
}
function rcStartBtn(){ return $('#rc-start'); }
function rcAskRender(q, choices){
  const box=$('#rc-ask'); if(!box) return;
  box.classList.remove('hidden');
  box.innerHTML='<div class="ask" style="margin-top:10px;padding:10px 12px;border:1px solid var(--accent);border-radius:8px;background:var(--card);font-size:13px"><p style="white-space:pre-wrap;margin:0 0 8px">'+escapeHTML(q)+'</p>'+
    (choices||[]).slice(0,4).map((c,i)=>`<button class="btn outline compact" style="margin:2px 4px 2px 0" data-rc-choice="${i}">${escapeHTML(c)}</button>`).join('')+'</div>';
  box.querySelectorAll('[data-rc-choice]').forEach(b=>b.onclick=()=>rcAnswer((choices||[])[Number(b.dataset.rcChoice)] || '确认执行'));
}
function rcAnswer(text){
  if(!rc.id) return;
  boxGone();
  rcPush('<div style="margin:6px 0"><b>你（指挥官）:</b> '+escapeHTML(text)+'</div>');
  fetch(`/api/agent/${rc.id}/answer`, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({text})})
    .then(r=>r.json()).then(()=>{ /* 后续事件经 SSE 回流 */ })
    .catch(e=>rcPush('<div class="tip">回答发送失败：'+escapeHTML(e.message)+'</div>'));
}
function boxGone(){ const b=$('#rc-ask'); if(b){ b.classList.add('hidden'); b.innerHTML=''; } }
function rcEvent(ev){
  if(ev.type==='objective'){
    rcPush('<div style="border-left:3px solid var(--accent);padding:6px 10px;margin:8px 0;background:var(--card);border-radius:4px"><b>◆ 任务书</b> '+escapeHTML(ev.name)+' → '+escapeHTML(ev.target)+'（步数上限 '+ev.max_steps+'）</div>');
  } else if(ev.type==='thinking'){
    rcPush('<div class="tip" style="margin:2px 0 2px 10px;font-style:italic;opacity:.75">…'+escapeHTML(String(ev.text||'').slice(-80))+'</div>');
  } else if(ev.type==='think'){
    rcPush('<div style="margin:6px 0"><b>思考 #'+ev.step+'</b> <span style="opacity:.85">'+escapeHTML(ev.thought)+'</span></div>');
  } else if(ev.type==='tool_call'){
    const raw=JSON.stringify(ev.input);
    const short=raw.length>240 ? raw.slice(0,240)+' …' : raw;
    rcPush('<div style="margin:6px 0"><span class="badge" style="margin-right:6px">⚔ '+escapeHTML(ev.tool)+'</span><code style="font-size:12px;word-break:break-all;display:inline-block;max-width:100%">'+escapeHTML(short)+'</code></div>');
  } else if(ev.type==='tool_result'){
    const obs=String(ev.obs||'').trim();
    const head=obs.length>260 ? obs.slice(0,260)+' …（共 '+obs.length+' 字）' : obs;
    rcPush('<div class="tip" style="margin:2px 0 2px 12px;white-space:pre-wrap;max-height:120px;overflow:auto;font-size:12px">'+escapeHTML(head)+'</div>');
  } else if(ev.type==='ask'){
    rcState('等你确认', true);
    rcAskRender(ev.question, ev.choices);
  } else if(ev.type==='ask_answered'){
    rcPush('<div class="tip" style="margin:2px 0 2px 12px">↳ 指挥官选择了：'+escapeHTML(ev.answer)+'</div>');
    rcState('行动中', true);
  } else if(ev.type==='final_delta'){
    // 累积到同一个 div
    let el=document.getElementById('rc-final');
    if(!el){ el=document.createElement('div'); el.id='rc-final'; el.style.cssText='white-space:pre-wrap;margin:8px 0;padding:8px 10px;border-left:3px solid var(--accent);background:var(--card)'; rcPush(''); rcLogEl().appendChild(el); }
    el.textContent += ev.text;
    rcLogEl().scrollTop=rcLogEl().scrollHeight;
  } else if(ev.type==='final' && !ev.interim){
    const el=document.getElementById('rc-final');
    if(!el){ rcPush('<div id="rc-final" style="white-space:pre-wrap;margin:8px 0;padding:8px 10px;border-left:3px solid var(--accent);background:var(--card)">'+escapeHTML(ev.text)+'</div>'); }
    rcPush('<div class="tip">— 红方 Agent 收工 —</div>');
    // 本轮自主进攻结束：解锁按钮、收尾会话（想续聊可在新会话里继续）
    setTimeout(()=>{ rcState('已收工', false); window.rcStop(true); }, 600);
  } else if(ev.type==='error'){
    rcPush('<div style="margin:6px 0;color:var(--accent)"><b>⚠</b> '+escapeHTML(ev.text)+'</div>');
  }
}
async function rcStart(){
  rcStopRound(true); // 先清掉上一轮（若有）
  const vector=$('#rc-vector').value, mode=$('#rc-mode').value, note=$('#rc-note').value.trim();
  const msg='开始自主进攻：方向 '+vector+(note?'，补充要求：'+note:'');
  rcLogEl().innerHTML=''; boxGone();
  $('#rc-log-wrap').classList.remove('hidden');
  rcPush('<div class="tip">目标已锁定（方向带目标，白名单内），权限档：<b>'+escapeHTML(mode)+'</b>。Agent 现在开始选工具…</div>');
  rcBusy(true); rcState('连接中', true);
  try{
    const j=await post('/api/agent/new', {message:msg, objective:vector, objective_note:note, mode});
    rc.id=j.agent_id;
    rcState('行动中', true);
    // app.js 里的 sse() 依赖 agent 窗的 DOM。 arena 页对红方控制台用独立轻量 EventSource
    rc.es=new EventSource(`/api/agent/${rc.id}/event`);
    rc.es.onmessage=m=>{ try{ rcEvent(JSON.parse(m.data)); }catch(e){} };
    rc.es.onerror=()=>{ rcState('断线', false); };
  }catch(e){
    rcState('失败', false); rcPush('<div style="margin:6px 0;color:var(--accent)"><b>启动失败</b> '+escapeHTML(e.message)+'</div>');
    rcBusy(false);
  }
}
async function rcStopRound(silent){
  if(rc.id){ try{ await fetch('/api/agent/close',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({agent_id:rc.id})}); }catch(e){} }
  if(rc.es){ rc.es.close(); rc.es=null; }
  rc.id=null;
  if(!silent){ rcState('已停止', false); rcNote(''); }
  rcBusy(false); boxGone();
}
window.rcStart=rcStart;
window.rcStop=rcStopRound;
})();
