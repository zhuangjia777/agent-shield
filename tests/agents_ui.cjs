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
  let mock={cloud:{base_url:'http://localhost:8000/v1',model:'mock-main',max_tokens:900,api_key_set:true},arena_models:{black:{inherit_main:true},red:{inherit_main:true}}};const writes=[];
  const agentPackets=JSON.parse(await fs.readFile(path.join(__dirname,'fixtures/agent-stream.json'),'utf8'));
  ws.onmessage = event => {
    const msg=JSON.parse(event.data);
    if (msg.id && pending.has(msg.id)) {
      const p=pending.get(msg.id); pending.delete(msg.id); clearTimeout(p.timeout);
      msg.error ? p.reject(Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    }
    if (msg.method === 'Runtime.exceptionThrown') errors.push(msg.params.exceptionDetails.text);
    if (msg.method === 'Fetch.requestPaused') {
      const {requestId,request}=msg.params;
      const route=new URL(request.url).pathname;
      const reply=(body,type='application/json')=>send('Fetch.fulfillRequest',{requestId,responseCode:200,responseHeaders:[{name:'Content-Type',value:type}],body:Buffer.from(body).toString('base64')}).catch(()=>{});
      if(route==='/api/config'){if(request.method==='POST'){writes.push(JSON.parse(request.postData));mock={...mock,...writes.at(-1)};reply(JSON.stringify({ok:true}));}else reply(JSON.stringify(mock));return;}
      if(route==='/api/llm-test'){reply('data: '+JSON.stringify({type:'error',text:'Synthetic connection failure'})+'\n\n','text/event-stream');return;}
      if(route==='/api/arena/agents'){reply(agentPackets.map(p=>JSON.stringify(p)).join('\n')+'\n','application/x-ndjson');return;}
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
  try {
    await send('Page.enable');await send('Runtime.enable');await send('Fetch.enable',{patterns:[{urlPattern:'*/api/*'}]});
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
    await navigate('/?settings=1');await waitFor("!!document.querySelector('#black-inherit')");
    assert.equal(await evaluate("document.querySelector('#black-inherit').checked&&document.querySelector('#red-inherit').checked"),true);
    assert.equal(await evaluate("document.querySelector('#black-fields').hidden&&document.querySelector('#black-key').disabled"),true);
    await evaluate("document.querySelector('#red-inherit').click();document.querySelector('#red-url').value='http://red.invalid/v1';document.querySelector('#red-model').value='red-test';document.querySelector('#red-key').value='FAKE_ROLE_KEY';saveSettings()");
    await waitFor("document.querySelector('#red-model')?.value==='red-test'&&!document.querySelector('#red-key').value");
    assert.equal(writes.length,1);assert.deepEqual(writes[0].arena_models.black,{inherit_main:true});
    assert.equal(writes[0].arena_models.red.api_key,'FAKE_ROLE_KEY');assert.equal(writes[0].cloud.api_key,'');mark('Role inheritance and independent save payload are correct; password input is cleared');
    await evaluate("testLLM('red')");await waitFor("document.querySelector('#test-out').textContent.includes('连接未通过')");
    assert.equal(await evaluate("document.querySelector('#test-out').textContent.includes('连接正常')"),false);mark('Failed role connection never displays success');
    await evaluate('closeSettings()');
    for(const width of [1280,390]){
      await send('Emulation.setDeviceMetricsOverride',{width,height:900,deviceScaleFactor:1,mobile:false});await delay(150);
      assert.equal(await evaluate("document.querySelector('.topbar').firstElementChild.classList.contains('brand')"),true);
      assert.equal(await evaluate("document.querySelector('.brand').getBoundingClientRect().left < document.querySelector('.nav-history').getBoundingClientRect().left"),true);
      assert.equal(await evaluate('document.documentElement.scrollWidth<=innerWidth'),true);
    }mark('Brand is leftmost at desktop and mobile widths without horizontal overflow');
    await send('Emulation.setDeviceMetricsOverride',{width:1280,height:900,deviceScaleFactor:1,mobile:false});
    await navigate('/arena?scenario=public_wifi');await waitFor("!document.querySelector('#run').disabled");
    assert.equal(await evaluate("document.querySelector('#arena-mode').value"),'agents');
    await click('#run');await waitFor("document.querySelector('#status').textContent.includes('智能体本轮结束')");
    assert.equal(await evaluate("document.querySelectorAll('#black-feed .event').length"),2);
    assert.equal(await evaluate("document.querySelectorAll('#red-feed .event').length"),2);
    assert.equal(await evaluate("document.querySelector('#review').disabled"),true);
    assert.equal(await evaluate("document.querySelector('#export').disabled"),false);
    const artifacts=path.join(__dirname,'../reports/agent-ui');await fs.mkdir(artifacts,{recursive:true});
    const shot=await send('Page.captureScreenshot',{format:'png'});await fs.writeFile(path.join(artifacts,'agents.png'),Buffer.from(shot.data,'base64'));
    mark('Both live agent feeds render tools and results; evidence export is enabled');
    assert.deepEqual(errors,[]);console.log('All settings and agent UI checks passed.');
  } finally {ws.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
