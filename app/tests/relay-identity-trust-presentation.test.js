const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const root = path.resolve(__dirname, '..');

test('disconnected, unverified connected, and verified connected states never conflate protection', () => {
  const ui = fs.readFileSync(path.join(root, 'src/renderer/app.js'), 'utf8');
  const m = ui.match(/function protectionStatusLabel\(connected, identityVerified, score\) \{[\s\S]*?\n\}/);
  assert.ok(m, 'pure security display policy exists');
  const policy = vm.runInNewContext('(' + m[0] + ')');
  assert.equal(policy(false, false, 4), '0%');
  assert.equal(policy(false, true, 4), '0%');
  assert.equal(policy(true, false, 4), 'Unverified');
  assert.equal(policy(true, false, 0), 'Unverified');
  assert.equal(policy(true, true, 4), '100%');
  assert.equal(policy(true, true, 3), '75%');
  assert.match(ui, /const identityVerified = s\.serverIdentityVerified === true/);
  assert.match(ui, /Server certificate identity not independently verified/);
  assert.match(ui, /Tunnel active · relay unverified/);
  assert.match(ui, /IPv4 uses VPN; relay identity unverified/);
  assert.match(ui, /setText\('healthScore', protectionStatusLabel\(connected, identityVerified, score\)\)/);
});
test('backend cannot infer public relay identity from transport, geography or cached data', () => {
  const backend = fs.readFileSync(path.join(root, 'src/main/platform-backend.js'), 'utf8');
  assert.match(backend, /return \{ \.\.\.base, activeSha, configPool, serverIdentityVerified: false \}/);
  assert.match(backend, /serverIdentityVerified: false,\s*error: error\.message/);
  assert.doesNotMatch(backend, /serverIdentityVerified:\s*!!base\./);
});


test('unverified connection renders route and DNS as warnings rather than green checks',()=>{
  const ui=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'src/renderer/styles.css'),'utf8');
  assert.match(ui,/routeOk && !identityVerified\);/);
  assert.match(ui,/dnsOk && !identityVerified\);/);
  assert.match(css,/\.health-icon\.warn\{[^}]*var\(--warn\)/);
  const m=ui.match(/function markHealth\(iconId, textId, ok, label, caution = false\) \{[\s\S]*?\n\}/);
  assert.ok(m);
  const icons={icon:{className:'',textContent:''}};
  const ctx={$:()=>icons.icon,setText:()=>{}};
  const mark=vm.runInNewContext('('+m[0]+')',ctx);
  mark('icon','label',true,'route alive',true);
  assert.equal(icons.icon.className,'health-icon warn');
  assert.equal(icons.icon.textContent,'!');
  mark('icon','label',true,'verified route',false);
  assert.equal(icons.icon.className,'health-icon ok');
  assert.equal(icons.icon.textContent,'✓');
  mark('icon','label',false,'route missing',false);
  assert.equal(icons.icon.className,'health-icon bad');
});


test('static Dashboard never promises Secure DNS or Protected routes for an unverified relay',()=>{
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(html,/VPN TUNNEL/);
  assert.match(html,/DNS responses/);
  assert.match(html,/IPv4 VPN routes/);
  assert.match(html,/Relay identity unverified/);
  assert.doesNotMatch(html,/>SECURE TUNNEL<|>Secure DNS<|>Protected routes<|Dynamic validated endpoint/);
  assert.match(html,/Relay identity may remain unverified/);
});

test('startup recovery labels unverified, verified, and missing VPN tunnels accurately',async()=>{
  const js=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const m=js.match(/async function reconcileStartupTunnel\(initialStatus\) \{[\s\S]*?\n\}/);
  assert.ok(m,'actual production startup reconciliation exists');
  for(const [finalStatus,want] of [
    [{connected:true,serverIdentityVerified:false},'VPN tunnel restored; relay identity remains unverified.'],
    [{connected:true,serverIdentityVerified:true},'Verified VPN tunnel restored.'],
    [{connected:false,serverIdentityVerified:false},null],
  ]){
    const toast=[],busy=[],rendered=[],actions=[];
    const fn=vm.runInNewContext('('+m[0]+')',{
      setBusy:(...args)=>busy.push(args),
      showToast:(text)=>toast.push(text),
      renderStatus:(s)=>rendered.push(s),
      window:{gateway:{action:async(action)=>{actions.push(action);return {status:finalStatus};},status:async()=>finalStatus}},
      refreshStatus:async()=>finalStatus
    });
    const result=await fn({connected:false,desiredState:'on',autoRecovery:true});
    assert.equal(result,finalStatus);
    assert.equal(actions.join(','),'ensure');
    assert.equal(busy[0][0],true);
    assert.equal(busy[busy.length-1][0],false);
    assert.equal(rendered.length,1);
    assert.equal(toast.length,want?1:0);
    if(want)assert.equal(toast[0],want);
    assert.doesNotMatch(busy[0][2],/protected/i,'pre-handshake restore cannot claim protection');
  }
});
