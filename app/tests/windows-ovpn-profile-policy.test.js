const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..', 'backend', 'windows', 'scripts');
const policy = fs.readFileSync(path.join(root, 'Profile-Policy.ps1'), 'utf8');
const factory = fs.readFileSync(path.join(root, 'Build-VpnGateUdpCache.ps1'), 'utf8');
const connector = fs.readFileSync(path.join(root, 'Headless-Control.ps1'), 'utf8');

test('Windows source profile policy is fail-closed and has no control-byte regex anchor', () => {
  for (const [label, src] of Object.entries({policy, factory, connector})) {
    assert.equal(src.includes('\x08'), false, label + ' must never carry a backspace instead of regex word boundary');
  }
  assert.match(policy, /function Test-OigVpnProfile/);
  for (const token of ["'dev'", "'proto'", "'remote'", "'cipher'", "'data-ciphers'", "'auth'",
                       "'resolv-retry'", "'nobind'", "'persist-key'", "'persist-tun'", "'client'", "'verb'"]) {
    assert.ok(policy.includes(token), 'missing explicit safe directive: ' + token);
  }
  assert.match(policy, /\$found\.Count -ne \$allowed\.Count/);
  assert.match(policy, /TryParse/); // IPv4 parse rather than trusting CSV metadata
  assert.match(policy, /AddressFamily.*InterNetwork/);
  assert.match(policy, /ExpectedIP/);
  assert.match(policy, /ExpectedPort/);
  assert.match(policy, /ExpectedProtocol/);
  assert.match(policy, /\[regex\]::Replace/);
  assert.doesNotMatch(policy, /Invoke-Expression|ScriptBlock::Create|Start-Process/);
});

test('Windows generation, LKG preservation, and elevated connector apply the same profile policy', () => {
  assert.match(factory, /Join-Path \$PSScriptRoot 'Profile-Policy\.ps1'/);
  assert.match(connector, /Join-Path \$PSScriptRoot 'Profile-Policy\.ps1'/);
  const generation = factory.indexOf('Test-OigVpnProfile -Text $text -ExpectedIP $ip');
  const preserve = factory.indexOf('Test-OigVpnProfile -Text $text -ExpectedIP ([string]$o.IP)');
  const preserveCopy = factory.indexOf('Copy-Item -LiteralPath $oldPath');
  assert.ok(generation >= 0, 'newly fetched profiles require policy');
  assert.ok(preserve >= 0 && preserve < preserveCopy, 'LKG profiles must be revalidated before copying');
  const connectorCheck = connector.indexOf("PROFILE_POLICY_OR_CA_INVALID");
  const connectorStop = connector.indexOf(' Stop-Connector', connector.indexOf('function Try-Candidate'));
  assert.ok(connectorCheck >= 0 && connectorCheck < connectorStop, 'deny before privileged connector service actions');
});


test('Windows public relay CA continuity remains fail-closed without claiming independent identity',()=>{
  assert.match(policy,/function Get-OigVpnProfileCaSha256/);
  assert.match(policy,/function Test-OigKnownRelayCaContinuity/);
  assert.match(connector,/PREVIOUSLY_SEEN_ENDPOINT_CA_CHANGED/);
  assert.match(connector,/Record-Success \$c \$h \$caSha256/);
  assert.match(connector,/caSha256=\$CaSha256/);
  const before=connector.indexOf('Test-OigKnownRelayCaContinuity -IP');
  const sideEffect=connector.indexOf(' Stop-Connector',connector.indexOf('function Try-Candidate'));
  assert.ok(before>0 && before<sideEffect,'CA continuity checked before service or route mutation');
  const backend=fs.readFileSync(path.join(__dirname,'..','src','main','platform-backend.js'),'utf8');
  assert.match(backend,/serverIdentityVerified: false/);
});

test('native Windows in-memory CA continuity regression', {skip:process.platform!=='win32'},()=>{
  const {spawnSync}=require('node:child_process');
  const script=path.join(__dirname,'windows-relay-ca-continuity-smoke.ps1');
  const r=spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',script],
    {cwd:path.join(__dirname,'..'),encoding:'utf8',timeout:30000,windowsHide:true});
  assert.equal(r.status,0, (r.stderr||'')+'\n'+(r.stdout||''));
  assert.match(r.stdout,/CA_CONTINUITY_PASS 18/);
});
