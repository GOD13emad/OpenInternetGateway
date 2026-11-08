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
  const connectorCheck = connector.indexOf("PROFILE_POLICY_DENIED");
  const connectorStop = connector.indexOf(' Stop-Connector', connector.indexOf('function Try-Candidate'));
  assert.ok(connectorCheck >= 0 && connectorCheck < connectorStop, 'deny before privileged connector service actions');
});
