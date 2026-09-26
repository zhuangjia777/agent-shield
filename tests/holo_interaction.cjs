// Browser regression: run the app, then launch an isolated Chrome with
// --headless=new --remote-debugging-port=9337 --user-data-dir=/tmp/agent-shield-holo-test
// Run: node tests/holo_interaction.cjs. Only local UI is exercised; all API POSTs are blocked.
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const base = process.env.HOLO_TEST_URL || 'http://127.0.0.1:8787';
const debug = process.env.HOLO_CDP_URL || 'http://127.0.0.1:9337';
if (![base, debug].every(url => ['127.0.0.1','localhost'].includes(new URL(url).hostname))) throw Error('Tests require loopback servers.');
(async () => {
  const pages = await (await fetch(debug + '/json/list')).json();
  const page = pages.find(p => p.type === 'page');
  assert(page, 'Launch an isolated test browser first.');
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen=resolve; ws.onerror=reject; });
  let id = 0; const pending = new Map(), errors = [], results = [];
  const send = (method, params={}) => new Promise((resolve,reject) => {
    const key=++id;
    const timeout=setTimeout(() => { pending.delete(key); reject(Error('CDP timeout: '+method)); },10000);
    pending.set(key,{resolve,reject,timeout}); ws.send(JSON.stringify({id:key,method,params}));
  });
  ws.onmessage = event => {
    const msg=JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const p=pending.get(msg.id); pending.delete(msg.id); clearTimeout(p.timeout);
      msg.error ? p.reject(Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    }
    if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
    if (msg.method === 'Fetch.requestPaused') {
      const {requestId,request}=msg.params;
      send(request.method === 'GET' ? 'Fetch.continueRequest' : 'Fetch.failRequest',
        request.method === 'GET' ? {requestId} : {requestId,errorReason:'BlockedByClient'}).catch(()=>{});
    }
  };
  const evaluate = async expression => {
    const r = await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if (r.exceptionDetails) throw Error(r.exceptionDetails.exception?.description || 'Evaluation failed');
    return r.result.value;
  };
  const waitFor = async (expression) => {
    for(let n=0;n<40;n++){ if(await evaluate(expression)) return; await delay(75); }
    throw Error('Timed out: '+expression);
  };
  const mark = title => {results.push(title); console.log('PASS: '+title);};
  const move = async (selector, fx=.75, fy=.3) => {
    await evaluate(`document.querySelector(${JSON.stringify(selector)}).scrollIntoView({block:'start'})`);
    await delay(150); // Wait for sticky-header layout and restored scrolling before measuring.
    const point=await evaluate(`(()=>{const e=document.querySelector(${JSON.stringify(selector)}),r=e.getBoundingClientRect();const left=Math.max(0,r.left),top=Math.max(e.closest('.site-header')?0:(document.querySelector('.site-header')?.getBoundingClientRect().bottom||0),r.top);return{x:left+(Math.min(innerWidth,r.right)-left)*${fx},y:top+(Math.min(innerHeight,r.bottom)-top)*${fy}}})()`);
    await send('Input.dispatchMouseEvent',{type:'mouseMoved',...point}); await delay(200);
  };
  const click = async selector => {
    await move(selector,.5,.5);
    const p=await evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await send('Input.dispatchMouseEvent',{type:'mousePressed',...p,button:'left',clickCount:1});
    await send('Input.dispatchMouseEvent',{type:'mouseReleased',...p,button:'left',clickCount:1}); await delay(100);
  };
  const navigate = async route => {
    await send('Page.navigate',{url:route.startsWith('file:') ? route : base+route});
    await waitFor(`document.readyState==='complete' && !!document.querySelector('.holo-fx')`);
  };
  const artifacts=path.join(__dirname,'../reports/holo-ui-20260926'); await fs.mkdir(artifacts,{recursive:true});
  const screenshot = async name => {
    const r=await send('Page.captureScreenshot',{format:'png'});
    await fs.writeFile(path.join(artifacts,name+'.png'),Buffer.from(r.data,'base64'));
  };
  try {
    await send('Page.enable'); await send('Runtime.enable');
    await send('Fetch.enable',{patterns:[{urlPattern:'*/api/*'}]});
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
    await send('Page.addScriptToEvaluateOnNewDocument',{source:`window.__holoFrames=0;const request=window.requestAnimationFrame.bind(window);window.requestAnimationFrame=cb=>{window.__holoFrames++;return request(cb)};`});
    await navigate('/help');
    await evaluate(`localStorage.setItem('as-holo','on');localStorage.setItem('as-theme','light')`);
    await navigate('/help');
    assert.equal(await evaluate(`document.documentElement.dataset.holoMotion`),'on');
    await move('.guide-main',.7,.01);
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.guide-main')).transform`),'none');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.guide-main')).transform`),'none');
    assert.equal(await evaluate(`document.querySelector('.holo-light')`),null);
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.guide-main')).backgroundImage`),'none');
    await screenshot('help-light'); mark('Long guide stays still without a pointer spotlight');
    const frames=await evaluate('window.__holoFrames'); await delay(250);
    assert.equal(await evaluate('window.__holoFrames'),frames); mark('No continuous animation-frame loop when the pointer stops');
    await click('.display-controls .btn:first-child');
    assert.equal(await evaluate('document.documentElement.dataset.theme'),'dark');
    await move('.guide-main',.55,.01); await screenshot('help-dark');
    await click('.display-controls .btn:last-child');
    assert.equal(await evaluate('document.documentElement.dataset.holoMotion'),'off');
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),0);
    assert.equal(await evaluate(`document.querySelector('.holo-fx').hidden`),true);
    await screenshot('help-off');
    await navigate('/help');
    assert.equal(await evaluate('document.documentElement.dataset.holoMotion'),'off');
    mark('Theme switch works and HOLO OFF clears all motion immediately');
    await click('.display-controls .btn:last-child');
    await navigate('/');
    await evaluate(`(()=>{if(!document.querySelector('.report-card')){const e=document.createElement('a');e.className='card report-card';e.href='#';e.textContent='Synthetic report card';document.body.appendChild(e)}})()`);
    await move('.report-card');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.holo-active')).transform`),'none');

    const hoverShadow=await evaluate(`getComputedStyle(document.querySelector('.holo-active')).boxShadow`);
    const restingShadow=await evaluate(`(()=>{const e=document.querySelector('.holo-active');e.classList.remove('holo-active');e.style.transition='none';const shadow=getComputedStyle(e).boxShadow;e.classList.add('holo-active');e.style.removeProperty('transition');return shadow})()`);
    assert.notEqual(hoverShadow,restingShadow);
    assert.equal(await evaluate(`getComputedStyle(document.documentElement,'::before').animationName`),'none');
    assert((await evaluate(`getComputedStyle(document.documentElement,'::before').backgroundImage`)).includes('data:image/svg+xml'));
    await screenshot('home-hover');
    const beforeBurst=await evaluate('window.__holoFrames');
    await evaluate(`(()=>{const e=document.querySelector('.report-card'),r=e.getBoundingClientRect();for(let i=0;i<25;i++)e.dispatchEvent(new PointerEvent('pointermove',{bubbles:true,pointerType:'mouse',clientX:r.x+20+i,clientY:r.y+30}))})()`);
    await delay(100);
    assert.equal(await evaluate('window.__holoFrames'),beforeBurst+1);
    mark('Rapid pointer events are coalesced into one render frame');
    await move('.display-controls .btn:first-child');
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),0); mark('Cards deepen shadows without moving; navigation controls remain still');
    await navigate('/checkup'); await move('.checkup-options label');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.holo-active')).transform`),'none');
    await move('#scan-start');
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),1);
    assert.equal(await evaluate(`document.querySelector('.holo-active').id`),'scan-start');
    await evaluate(`document.querySelector('#scan-start').disabled=true`);
    await move('#scan-start');
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),0); mark('Forms stay still, nested buttons activate alone, disabled buttons do not lift');
    await navigate('/arena');
    await waitFor(`!document.querySelector('#run').disabled`);
    await move('.metric'); assert.equal(await evaluate(`getComputedStyle(document.querySelector('.holo-active')).transform`),'none');
    await move('.lane'); assert.equal(await evaluate(`getComputedStyle(document.querySelector('.holo-active')).transform`),'none');
    await screenshot('arena-hover');
    await evaluate(`(()=>{const e=document.createElement('div');e.className='event';e.id='holo-test-event';e.textContent='Synthetic UI test event';document.querySelector('.feed').prepend(e)})()`);
    await move('#holo-test-event');
    assert.equal(await evaluate(`document.querySelector('.holo-active').id`),'holo-test-event');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.holo-active')).transform`),'none'); mark('Arena metrics, lanes and newly inserted log events stay still');
    await evaluate(`document.dispatchEvent(new Event('scroll'))`);
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),0);
    await evaluate(`(()=>{for(let i=0;i<8;i++)document.body.dispatchEvent(new PointerEvent('pointerdown',{bubbles:true,pointerType:'mouse',button:0,clientX:30,clientY:280}))})()`);
    assert.equal(await evaluate(`document.querySelectorAll('.holo-ripple').length`),3);
    await screenshot('background-ripple'); await delay(750);
    assert.equal(await evaluate(`document.querySelectorAll('.holo-ripple').length`),0); mark('Scroll resets motion; background ripples are capped and cleaned up');
    await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'reduce'}]});
    await waitFor(`document.documentElement.dataset.holoMotion==='off'`);
    await move('.metric'); assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),0);
    assert.equal(await evaluate(`document.querySelector('.holo-fx').hidden`),true); mark('Reduced motion disables following, tilt and ripples');
    await send('Emulation.setEmulatedMedia',{features:[{name:'prefers-reduced-motion',value:'no-preference'}]});
    await send('Emulation.setTouchEmulationEnabled',{enabled:true,maxTouchPoints:1});
    await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    await navigate('/arena');
    assert.equal(await evaluate(`document.documentElement.dataset.holoMotion`),'off');
    assert.equal(await evaluate(`document.documentElement.scrollWidth<=innerWidth`),true);
    await screenshot('arena-mobile'); mark('Touch layout has no mouse-follow effect or horizontal overflow');
    await send('Emulation.setTouchEmulationEnabled',{enabled:false});
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
    await navigate('file://'+path.resolve(__dirname,'../使用说明.html'));
    assert.equal(await evaluate(`!!document.querySelector('.display-controls')`),true);
    await move('.guide-main',.6,.01);
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),1); mark('Standalone offline guide includes shared HOLO behavior');
    assert.deepEqual(errors,[]); mark('No uncaught JavaScript errors');
    await fs.writeFile(path.join(artifacts,'verification.json'),JSON.stringify({results,errors},null,2)+'\n');
  } catch (err) {
    await screenshot('failure');
    console.error(await evaluate(`JSON.stringify({url:location.href,motion:document.documentElement.dataset.holoMotion,active:document.querySelector('.holo-active')?.className,hover:[...document.querySelectorAll(':hover')].map(e=>e.className),scrollY,metric:document.querySelector('.metric')?.getBoundingClientRect()})`));
    throw err;
  } finally {
    ws.close();
    for(const p of pending.values())clearTimeout(p.timeout);
  }
})().catch(err=>{console.error(err);process.exitCode=1});
