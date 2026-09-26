// Navigation regression with temporary synthetic reports: run the app, then launch an isolated Chrome with
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
      if(new URL(request.url).pathname==='/api/config' && request.method==='GET'){send('Fetch.fulfillRequest',{requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:'application/json'}],body:Buffer.from(JSON.stringify({cloud:{base_url:'http://localhost:8000/v1',model:'test-model'}})).toString('base64')}).catch(()=>{});return;}
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
  const artifacts=path.join(__dirname,'../reports/navigation-ui-20260926'); await fs.mkdir(artifacts,{recursive:true});
  const screenshot = async name => {
    await delay(450);
    const r=await send('Page.captureScreenshot',{format:'png'});
    await fs.writeFile(path.join(artifacts,name+'.png'),Buffer.from(r.data,'base64'));
  };
  const fixtures=[];
  const fixture=async kind=>{const dir=await fs.mkdtemp(path.join(__dirname,'../reports/nav-test-'));fixtures.push(dir);await fs.writeFile(path.join(dir,'report.json'),JSON.stringify({score:100,findings:[],generated_at:'Synthetic navigation test',engine:'template',[kind]:{}}));return '/report/'+path.basename(dir);};
  try {
    const systemReport=await fixture('system'), skillReport=await fixture('skill');
    await send('Page.enable'); await send('Runtime.enable');
    await send('Fetch.enable',{patterns:[{urlPattern:'*/api/*'}]});
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
    await send('Page.addScriptToEvaluateOnNewDocument',{source:`window.__holoFrames=0;const request=window.requestAnimationFrame.bind(window);window.requestAnimationFrame=cb=>{window.__holoFrames++;return request(cb)};`});
    await navigate(systemReport);
    assert.equal(await evaluate(`document.querySelector('[data-nav-back]').getAttribute('href')`),'/checkup');
    assert.equal(await evaluate(`document.querySelector('.breadcrumbs').textContent`),'首页/体检本机/检查报告');
    assert.equal(await evaluate(`document.querySelector('.report-actions a').textContent`),'重新体检');
    assert.equal(await evaluate(`document.querySelectorAll('.site-header').length`),1);
    await screenshot('report-desktop'); mark('Legacy report content determines checkup breadcrumb and direct-open fallback');
    for(const route of ['/','/checkup','/arena','/nvidia','/help']){
      await navigate(route);
      assert.deepEqual(await evaluate(`[...document.querySelectorAll('.site-navigation a')].map(a=>a.textContent)`),['首页','体检本机','攻防演练','Skill 审查','使用说明']);
      assert.equal(await evaluate(`document.querySelector('.site-navigation [aria-current]').getAttribute('href')`),route);
    }
    mark('All five pages share the same navigation with the correct active section');
    await navigate('/checkup');
    await evaluate(`document.querySelector('#scan-system').checked=false;document.querySelector('#scan-network').checked=true`);
    await click('.site-navigation a[href="/arena"]');
    await waitFor(`location.pathname==='/arena'&&!document.querySelector('#run').disabled`);
    await evaluate(`document.querySelector('#scenario').value='api_authorization';document.querySelector('#scenario').dispatchEvent(new Event('change'))`);
    const control=await evaluate(`(()=>{const e=document.querySelector('#controls input');e.checked=!e.checked;document.querySelector('.config').open=true;return{id:e.id,checked:e.checked}})()`);
    await evaluate('scrollTo(0,300)'); await delay(200);
    await click('.site-navigation a[href="/help"]');
    await waitFor(`location.pathname==='/help'&&!!document.querySelector('.site-header')`);
    assert.equal(await evaluate(`document.querySelector('[data-nav-back]').getAttribute('href')`),'/arena?scenario=api_authorization');
    await click('[data-nav-back]');
    await waitFor(`location.pathname==='/arena'&&!document.querySelector('#run').disabled`);
    assert.equal(await evaluate(`document.querySelector('#scenario').value`),'api_authorization');
    assert.equal(await evaluate(`document.getElementById(${JSON.stringify(control.id)}).checked`),control.checked);
    assert.equal(await evaluate(`document.querySelector('[data-nav-back]').getAttribute('href')`),'/checkup');
    await click('[data-nav-back]');
    await waitFor(`location.pathname==='/checkup'&&!!document.querySelector('.site-header')`);
    assert.equal(await evaluate(`document.querySelector('#scan-system').checked`),false);
    assert.equal(await evaluate(`document.querySelector('#scan-network').checked`),true);
    assert.equal(await evaluate(`document.querySelector('[data-nav-back]').getAttribute('href')`),'/');
    mark('Repeated Back does not bounce; scenario policy and checkup selections are restored');
    await navigate('/help'); await evaluate('scrollTo(0,650)'); await delay(200);
    const scrollBefore=await evaluate('scrollY');
    // Click a sticky header link without scrollIntoView, preserving the current reading position.
    const navPoint=await evaluate(`(()=>{const r=document.querySelector('.site-navigation a[href="/nvidia"]').getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await send('Input.dispatchMouseEvent',{type:'mousePressed',...navPoint,button:'left',clickCount:1});
    await send('Input.dispatchMouseEvent',{type:'mouseReleased',...navPoint,button:'left',clickCount:1});
    await waitFor(`location.pathname==='/nvidia'&&!!document.querySelector('.site-header')`);
    await click('[data-nav-back]');
    await waitFor(`location.pathname==='/help'&&!!document.querySelector('.site-header')`); await delay(200);
    assert(Math.abs((await evaluate('scrollY'))-scrollBefore)<5);
    assert(Math.abs(await evaluate(`document.querySelector('.site-header').getBoundingClientRect().top`))<2);
    mark('Back restores reading position and the navigation stays pinned while scrolling');
    await click('.nav-utility a[href="/?settings=1"]');
    await waitFor(`!!document.querySelector('.modal')`);
    assert.equal(await evaluate(`document.querySelector('#c-model').value`),'test-model');
    await evaluate('closeSettings()'); mark('Settings opens from the shared link using a synthetic test configuration');
    await navigate(skillReport);
    assert.equal(await evaluate(`document.querySelector('[data-nav-back]').getAttribute('href')`),'/nvidia');
    assert.equal(await evaluate(`document.querySelector('.breadcrumbs').textContent`),'首页/Skill 审查/Skill 审查报告');
    await move('.nav-history a:last-child');
    assert.equal(await evaluate(`document.querySelectorAll('.holo-active').length`),0);
    const press=await evaluate(`(()=>{const r=document.querySelector('.nav-history a:last-child').getBoundingClientRect();return{x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await send('Input.dispatchMouseEvent',{type:'mousePressed',...press,button:'left',clickCount:1});
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.nav-history a:last-child')).transform`),'none');
    await send('Input.dispatchMouseEvent',{type:'mouseReleased',...press,button:'left',clickCount:1});
    await waitFor(`location.pathname==='/'&&!!document.querySelector('.site-header')`);
    mark('Skill reports return to Skill review; navigation never tilts or sinks');
    await send('Emulation.setTouchEmulationEnabled',{enabled:true,maxTouchPoints:1});
    await send('Emulation.setDeviceMetricsOverride',{width:390,height:844,deviceScaleFactor:1,mobile:true});
    await navigate('/checkup');
    assert.equal(await evaluate(`getComputedStyle(document.querySelector('.site-navigation')).display`),'none');
    assert.equal(await evaluate(`document.documentElement.scrollWidth<=innerWidth`),true);
    assert.equal(await evaluate(`document.querySelector('.nav-history').getBoundingClientRect().bottom<250`),true);
    await click('.nav-toggle');
    assert.equal(await evaluate(`document.querySelector('.nav-toggle').getAttribute('aria-expanded')`),'true');
    await screenshot('mobile-menu');
    await send('Input.dispatchKeyEvent',{type:'keyDown',key:'Escape',code:'Escape',windowsVirtualKeyCode:27});
    assert.equal(await evaluate(`document.querySelector('.nav-toggle').getAttribute('aria-expanded')`),'false');
    assert.equal(await evaluate(`document.activeElement.classList.contains('nav-toggle')`),true);
    await screenshot('mobile-checkup'); mark('Mobile menu fits, opens, closes with Escape and returns focus');
    await send('Emulation.setTouchEmulationEnabled',{enabled:false});
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
    await navigate('file://'+path.resolve(__dirname,'../使用说明.html'));
    assert.equal(await evaluate(`document.querySelector('.nav-history a:last-child').href`),base+'/');
    assert.equal(await evaluate(`document.querySelector('.site-navigation [aria-current]').textContent`),'使用说明');
    mark('Offline guide navigation points to the local application');
    assert.deepEqual(errors,[]); mark('No uncaught JavaScript errors');
    await fs.writeFile(path.join(artifacts,'verification.json'),JSON.stringify({results,errors},null,2)+'\n');
  } catch (err) {
    await screenshot('failure');
    console.error(await evaluate(`JSON.stringify({url:location.href,motion:document.documentElement.dataset.holoMotion,active:document.querySelector('.holo-active')?.className,hover:[...document.querySelectorAll(':hover')].map(e=>e.className),scrollY,metric:document.querySelector('.metric')?.getBoundingClientRect()})`));
    throw err;
  } finally {
    ws.close();
    for(const dir of fixtures)await fs.rm(dir,{recursive:true,force:true});
    for(const p of pending.values())clearTimeout(p.timeout);
  }
})().catch(err=>{console.error(err);process.exitCode=1});
