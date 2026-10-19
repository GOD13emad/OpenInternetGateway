'use strict';
// Disposable Windows GitHub runner ONLY. This drives the real published v2.5.18
// installed Electron UI via loopback Chrome DevTools Protocol. NO mock updater.
// The PowerShell CI caller must independently verify the helper receipt, NSIS
// exit code, installed v2.5.19, preserved state, and offline network afterward.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { WebSocket } = globalThis;
if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.RUNNER_ENVIRONMENT !== 'github-hosted' ||
    process.env.GITHUB_REPOSITORY !== 'GOD13emad/OpenInternetGateway' ||
    !WebSocket) throw Error('DISPOSABLE_GITHUB_WINDOWS_NODE24_ONLY');
const [portStr, receiptPath] = process.argv.slice(2);
const port = Number(portStr);
if (!Number.isInteger(port) || port < 1025 || port > 65535 ||
    !receiptPath || fs.existsSync(receiptPath)) throw Error('UNSAFE_CDP_ARGUMENTS');
const loopback = 'http://127.0.0.1:' + port;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const deadline = Date.now() + 135000;
async function targets() {
  const r = await fetch(loopback + '/json/list', {signal:AbortSignal.timeout(2500)});
  if (!r.ok) throw Error('CDP_HTTP_' + r.status);
  return r.json();
}
async function connect() {
  let lastError = '';
  while (Date.now() < deadline) {
    try {
      const candidates = (await targets()).filter(x => x.type === 'page' &&
        /^file:\/\/\//.test(x.url || '') &&
        /index\.html/i.test(x.url || '') &&
        /^ws:\/\/(127\.0\.0\.1|localhost):/.test(x.webSocketDebuggerUrl || ''));
      if (candidates.length === 1) {
        return await new Promise((resolve, reject) => {
          const ws = new WebSocket(candidates[0].webSocketDebuggerUrl);
          const t = setTimeout(() => reject(Error('CDP_WEBSOCKET_TIMEOUT')), 4000);
          ws.addEventListener('open', () => {clearTimeout(t);resolve(ws)}, {once:true});
          ws.addEventListener('error', e => {clearTimeout(t);reject(Error('CDP_WEBSOCKET_ERROR'))}, {once:true});
        });
      }
    } catch(e) {lastError=String(e.message||e)}
    await sleep(350);
  }
  throw Error('INSTALLED_ELECTRON_DASHBOARD_CDP_UNAVAILABLE ' + lastError);
}
(async()=>{
const ws = await connect();
let seq=0;
const pending=new Map();
let closed=false;
ws.addEventListener('close', () => {
  closed=true;
  for (const p of pending.values()) p.reject(Error('CDP_CLOSED'));
  pending.clear();
});
ws.addEventListener('message', ev => {
  let msg;
  try { msg=JSON.parse(typeof ev.data === 'string' ? ev.data : String(ev.data)); } catch { return; }
  const p=pending.get(msg.id);
  if (!p) return;
  pending.delete(msg.id);
  if (msg.error) p.reject(Error('CDP_'+JSON.stringify(msg.error)));
  else p.resolve(msg.result);
});
function send(method, params={}) {
  if (closed) return Promise.reject(Error('CDP_CLOSED'));
  const id=++seq;
  return new Promise((resolve,reject)=>{
    pending.set(id,{resolve,reject});
    ws.send(JSON.stringify({id,method,params}));
    // Hosted Electron may momentarily pause its main renderer during the
    // genuine online release check. Allow a bounded CDP response window,
    // without ever retrying side-effectful Install clicks.
    setTimeout(()=>{if(pending.has(id)){pending.delete(id);reject(Error('CDP_TIMEOUT_'+method));}},12000);
  });
}
async function evalJs(js) {
  const r=await send('Runtime.evaluate',{expression:js,returnByValue:true,awaitPromise:true});
  if(r.exceptionDetails)throw Error('DASHBOARD_JS_EXCEPTION_'+r.exceptionDetails.text);
  return r.result?.value;
}
async function until(js,label,ms=55000) {
  const limit=Math.min(Date.now()+ms,deadline);
  while(Date.now()<limit){
    if(await evalJs(js)) return;
    await sleep(250);
  }
  throw Error('DASHBOARD_TIMEOUT_'+label);
}
await send('Runtime.enable');
await until("!!document.querySelector('.nav-item[data-page=\"updates\"]') && !!window.gateway", 'loaded');
await evalJs("document.querySelector('.nav-item[data-page=\"updates\"]').click();true");
await until("document.querySelector('#page-updates').classList.contains('active')", 'updates-page');
const releaseLookupTimeout=Date.now()+80000;
let nextForcedCheck=Date.now()+12000;
let lookupAttempts=0;
let before;
while(Date.now()<releaseLookupTimeout) {
  before=await evalJs("({current:document.querySelector('#updateCurrent').textContent,latest:document.querySelector('#updateLatest').textContent,sha:document.querySelector('#updateChecksum').textContent,enabled:!document.querySelector('#installUpdate').disabled,state:document.querySelector('#updateState').textContent,toast:document.querySelector('#toast').textContent})");
  if(before.enabled)break;
  if(Date.now()>=nextForcedCheck && lookupAttempts<4) {
    await evalJs("document.querySelector('#checkUpdates').click();true");
    lookupAttempts++;
    nextForcedCheck=Date.now()+15000;
  }
  await sleep(500);
}
if(!before?.enabled) {
  // GitHub release lookup may be temporarily unavailable on a public CI IP.
  // Record a distinct infrastructure failure; never accept old self-update.
  const inconclusive={
    schema:'oig-disposable-legacy-github-release-lookup-inconclusive-v1',
    result:'INCONCLUSIVE_GITHUB_RELEASE_LOOKUP_NOT_PRODUCT_PASS',
    oldInstalledVersion:'2.5.18',
    realUpdateButtonClicked:false,
    attemptedForcedReleaseChecks:lookupAttempts,
    lastState:before,
    at:new Date().toISOString()
  };
  fs.writeFileSync(require('node:path').join(require('node:path').dirname(receiptPath),'release-lookup-inconclusive-result.json'),JSON.stringify(inconclusive,null,2)+'\n',{flag:'wx'});
  throw Error('AUTHENTIC_PUBLISHED_RELEASE_LOOKUP_UNAVAILABLE');
}
assert.equal(before.current,'2.5.18');
assert.equal(before.latest,'2.5.19');
assert.equal(String(before.sha).toLowerCase(),'761637b5d49f37858973300ec2e9b1bb2b32c684ebabe86f1e8718b4480685db');
assert.equal(before.enabled,true);
// Install itself performs a mandatory fresh GitHub lookup; a second
// unconditional Check now would create a redundant external dependency.
await evalJs("document.querySelector('#installUpdate').click();true");
const clicked={schema:'oig-published-old-installed-ui-real-click-v1',
  osScope:'disposable-GitHub-Windows-Server-x64-not-Windows-11-x64',
  publishedInstalledVersion:'2.5.18',publicTarget:'2.5.19',publishedSha256:before.sha,
  actualDomInstallButtonClicked:true,mockedBackend:false,realDownloadRequested:true,
  resultingInstallVerifiedByThisReceipt:false,
  at:new Date().toISOString()};
fs.writeFileSync(receiptPath,JSON.stringify(clicked,null,2)+'\n',{flag:'wx'});
console.log('REAL_PUBLISHED_OLD_INSTALLED_UPDATE_BUTTON_CLICKED '+JSON.stringify(clicked));
const t=Date.now()+100000;
while(Date.now()<t){
  if(closed){console.log('OLD_APP_CDP_CLOSED_AFTER_UPDATE_CLICK');return;}
  try {
    const v=await evalJs("({toast:document.querySelector('#toast').textContent,busy:document.querySelector('#busyOverlay').classList.contains('show')})");
    if(/failed|unable|error/i.test(v.toast)){
      throw Error('OLD_PUBLISHED_UPDATER_UI_FAILED_'+String(v.toast).slice(0,350));
    }
    if(/Verified update is installing/i.test(v.toast)){
      console.log('OLD_PUBLISHED_UPDATER_UI_APPLYING_RETURNED');
      return;
    }
  } catch(e) {if(closed)return;throw e}
  await sleep(200);
}
throw Error('PUBLISHED_OLD_UPDATER_DID_NOT_EXIT_OR_SHOW_APPLYING');
})().catch(e=>{
  const reason=String(e?.stack||e);
  const clicked=fs.existsSync(receiptPath);
  const known=clicked && reason.includes('Windows update helper failed to start with the verified PowerShell runtime.');
  if (known) {
    const negative={
      schema:'oig-published-2518-real-update-known-failure-v1',
      actualPublic2518Installed:true,
      realInstalledRendererUpdateButtonClicked:true,
      mockedBackend:false,
      actualPublishedOldUpdaterSucceeded:false,
      classification:'LEGACY_WINDOWS_DETACHED_PWSH_HELPER_START_FAILURE',
      nativeWindows11X64:false,
      sourceHead:process.env.GITHUB_SHA,
      at:new Date().toISOString()
    };
    try {fs.writeFileSync(require('node:path').join(require('node:path').dirname(receiptPath),'legacy-updater-failure-result.json'),JSON.stringify(negative,null,2)+'\n',{flag:'wx'});}
    catch(err) {fs.writeSync(2,'LEGACY_DIAGNOSTIC_RECEIPT_WRITE_FAIL '+String(err)+'\n');}
  }
  fs.writeSync(2,'REAL_INSTALLED_OLD_UI_DRIVER_FAILED '+reason.slice(0,650)+'\n');
  // Close the remote-debugging WebSocket by terminating the diagnostic
  // Node process; the prior test leaked an open WS and hit the job timeout.
  process.exit(known?42:1);
});