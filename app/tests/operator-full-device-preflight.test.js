const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

test('Linux full-device preflight is read-only, pinned and fail-closed across realistic host states',
  { skip: process.platform !== 'linux' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-full-device-preflight-'));
  try {
    const root = path.join(dir, 'backend');
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    fs.mkdirSync(path.join(root, 'linux'), {recursive:true});
    fs.mkdirSync(path.join(root, 'state'), {recursive:true});
    const profileScript = path.join(__dirname, '../backend/linux/operator_profile.py');
    const preflightScript = path.join(__dirname, '../backend/linux/operator_full_device.py');
    for (const script of ['operator_profile.py','operator_full_device.py']) {
      fs.copyFileSync(path.join(__dirname, '../backend/linux', script), path.join(root,'linux',script));
    }
    const cert = path.join(dir, 'cert.pem');
    const key = path.join(dir, 'key.pem');
    const made = spawnSync('openssl', [
      'req','-x509','-newkey','rsa:2048','-nodes','-days','1',
      '-subj','/CN=synthetic-test-only','-out',cert,'-keyout',key
    ],{encoding:'utf8',timeout:8000});
    assert.equal(made.status,0,made.stderr);
    const ca = fs.readFileSync(cert,'utf8').trim();
    const fingerprint = crypto.createHash('sha256')
      .update(new crypto.X509Certificate(ca).raw).digest('hex');
    const peerCN='server.vpnbook.com';
    const profile=path.join(dir,'synthetic.ovpn');
    fs.writeFileSync(profile, [
      'client','dev tun1','proto tcp','remote uk205.vpnbook.com 443',
      'auth-user-pass','pull','redirect-gateway def1',
      '<ca>',ca,'</ca>','<cert>',ca,'</cert>',
      '<key>',fs.readFileSync(key,'utf8').trim(),'</key>',''
    ].join('\n'),{mode:0o600});
    const stage=spawnSync('python3',['-B',profileScript,'stage','--profile',profile,
      '--ca-sha256',fingerprint,'--peer-cn',peerCN,
      '--common',path.join(root,'common')],{encoding:'utf8',timeout:8000});
    assert.equal(stage.status,0,stage.stderr);
    const metadataPath=path.join(root,'common','operator-profiles','current.json');
    const metadata=JSON.parse(fs.readFileSync(metadataPath,'utf8'));
    const pinned=path.join(root,'common','operator-profiles',metadata.profile);
    const desired=path.join(root,'state','desired-state');
    fs.writeFileSync(desired,'off\n',{mode:0o600});

    // Exactly three read-only command shapes are supported by this fixture.
    const fake = [
      '#!/usr/bin/env python3',
      'import os,sys,pathlib',
      'tool=pathlib.Path(sys.argv[0]).name; a=sys.argv[1:]',
      'case=os.environ.get("OIG_PREFLIGHT_CASE","clean")',
      'with open(os.environ["OIG_PREFLIGHT_LOG"],"a") as f:f.write(tool+" "+ " ".join(a)+"\\n")',
      'if tool=="nmcli" and a==["-t","-f","NAME,TYPE","connection","show","--active"]:',
      '  if case=="unknown-nm":sys.exit(3)',
      '  print("Home Ethernet:802-3-ethernet")',
      '  if case=="external-vpn":print("IPbaz:vpn")',
      '  if case=="external-tun":print("tailscale0:tun")',
      '  sys.exit(0)',
      'if tool=="ip" and a==["-4","route","show","table","main"]:',
      '  print("default via 192.0.2.1 dev enp1s0")',
      '  if case=="manual-tun-route":print("0.0.0.0/1 dev tun1")',
      '  sys.exit(0)',
      'if tool=="ip" and a[:3]==["-6","route","get"] and len(a)==4:',
      '  if case=="ipv6-route":print(a[3]+" via fe80::1 dev enp1s0 src 2001:db8::2");sys.exit(0)',
      '  if case=="ipv6-error":print("Operation not permitted",file=sys.stderr);sys.exit(1)',
      '  print("RTNETLINK answers: Network is unreachable",file=sys.stderr);sys.exit(2)',
      'print("FORBIDDEN COMMAND",file=sys.stderr);sys.exit(70)',
      ''
    ].join('\n');
    for (const name of ['nmcli','ip']) fs.writeFileSync(path.join(bin,name),fake,{mode:0o700});
    const log=path.join(dir,'commands.log');
    const env={...process.env, PATH:bin+path.delimiter+process.env.PATH,
      OIG_PREFLIGHT_LOG:log,PYTHONDONTWRITEBYTECODE:'1'};
    const args=['-B',preflightScript,'preflight','--profile',pinned,
      '--ca-sha256',fingerprint,'--peer-cn',peerCN,'--desired-state',desired];
    const profileBefore=fs.readFileSync(pinned);
    const metadataBefore=fs.readFileSync(metadataPath);

    function run(caseName='clean', overrides={}) {
      fs.writeFileSync(log,'');
      const result=spawnSync('python3',args,{encoding:'utf8',timeout:6000,
        env:{...env,OIG_PREFLIGHT_CASE:caseName}});
      if (overrides.expectedExit !== undefined) assert.equal(result.status,overrides.expectedExit,result.stderr);
      else assert.equal(result.status,0,result.stderr);
      const events=fs.readFileSync(log,'utf8');
      assert.doesNotMatch(events, /connection (?:up|down|modify|import|delete)|systemd-run|iptables|nft|sudo|pkexec/);
      assert.ok(profileBefore.equals(fs.readFileSync(pinned)));
      assert.ok(metadataBefore.equals(fs.readFileSync(metadataPath)));
      return {data: result.status===0 ? JSON.parse(result.stdout) : null, events, result};
    }

    const clean=run('clean').data;
    assert.equal(clean.ok,true);
    assert.equal(clean.candidateHostIsolation,true);
    assert.equal(clean.noIndependentTunnelObserved,true);
    assert.equal(clean.publicIpv6AbsenceRepresentativelyChecked,true);
    assert.deepEqual(clean.blockers,[]);
    for(const key of ['activationRequested','independentRollbackArmed',
      'fullDevicePathEnabled','fullDeviceTunnelVerified','readyForAutomaticConnection']) {
      assert.equal(clean[key],false,key);
    }
    const cases={
      'external-vpn':'INDEPENDENT_TUNNEL_ACTIVE',
      'external-tun':'INDEPENDENT_TUNNEL_ACTIVE',
      'manual-tun-route':'INDEPENDENT_TUNNEL_ACTIVE',
      'unknown-nm':'ACTIVE_TUNNEL_INVENTORY_UNKNOWN',
      'ipv6-route':'PUBLIC_IPV6_ROUTE_PRESENT',
      'ipv6-error':'IPV6_ROUTE_STATUS_UNKNOWN'
    };
    for (const [name,reason] of Object.entries(cases)) {
      const r=run(name).data;
      assert.equal(r.candidateHostIsolation,false,name);
      assert.ok(r.blockers.includes(reason),name);
      assert.equal(r.fullDevicePathEnabled,false,name);
    }
    fs.writeFileSync(desired,'on\n',{mode:0o600});
    assert.ok(run('clean').data.blockers.includes('DESIRED_STATE_NOT_VERIFIED_OFF'));
    fs.writeFileSync(desired,'off\n',{mode:0o600});
    args[args.indexOf('--ca-sha256')+1] = '0'.repeat(64);
    assert.equal(run('clean',{expectedExit:2}).data,null,'wrong trust pin must fail before any network probe');
    args[args.indexOf('--ca-sha256')+1] = fingerprint;

    const Backend=require('../src/main/platform-backend');
    const backend=new Backend({version:'2.5.20',appPath:dir,resourcesPath:dir,userData:dir});
    backend.platform='linux';backend.backendRoot=root;
    assert.equal(backend.operatorProfileStatus().staged,true);
    fs.writeFileSync(log,'');
    const oldPath=process.env.PATH,oldLog=process.env.OIG_PREFLIGHT_LOG,oldCase=process.env.OIG_PREFLIGHT_CASE;
    try {
      process.env.PATH=env.PATH;
      process.env.OIG_PREFLIGHT_LOG=log;
      process.env.OIG_PREFLIGHT_CASE='external-vpn';
      const response=await backend.checkOperatorFullDevicePreflight();
      assert.equal(response.ok,true);
      assert.ok(response.blockers.includes('INDEPENDENT_TUNNEL_ACTIVE'));
      assert.equal(response.fullDevicePathEnabled,false);
      assert.equal(response.activationRequested,false);
      assert.equal(backend.operatorProfileTaskBusy,false);
      backend.operatorTrialBusy=true;
      await assert.rejects(backend.checkOperatorFullDevicePreflight(),/Wait for current gateway tasks/);
      backend.operatorTrialBusy=false;
      backend.gatewayActionCount=1;
      await assert.rejects(backend.checkOperatorFullDevicePreflight(),/Wait for current gateway tasks/);
      backend.gatewayActionCount=0;
    } finally {
      if (oldPath===undefined) delete process.env.PATH; else process.env.PATH=oldPath;
      if (oldLog===undefined) delete process.env.OIG_PREFLIGHT_LOG; else process.env.OIG_PREFLIGHT_LOG=oldLog;
      if (oldCase===undefined) delete process.env.OIG_PREFLIGHT_CASE; else process.env.OIG_PREFLIGHT_CASE=oldCase;
    }
    assert.equal(fs.readFileSync(desired,'utf8'),'off\n');
    assert.ok(profileBefore.equals(fs.readFileSync(pinned)));
    assert.ok(metadataBefore.equals(fs.readFileSync(metadataPath)));
  } finally {
    fs.rmSync(dir,{recursive:true,force:true});
  }
});

test('hosted Windows regression scope permits only the explicit new Linux preflight files', () => {
  const content = fs.readFileSync(path.join(__dirname,
    '../../.github/workflows/hosted-first-connect-acceptance.yml'),'utf8');
  const start = content.indexOf('$allowed=@(');
  const end = content.indexOf('$actual=@(',start);
  assert.ok(start >= 0 && end > start, 'Existing exact-scope gate must remain present');
  const allowed = content.slice(start,end);
  assert.ok(allowed.includes("'app/backend/linux/operator_full_device.py'"));
  assert.ok(allowed.includes("'app/tests/operator-full-device-preflight.test.js'"));
  assert.match(content, /UNEXPECTED_PRODUCT_SCOPE/);
});

test('read-only full-device button and IPC are separate from the consented transport trial', () => {
  const html = fs.readFileSync(path.join(__dirname, '../src/renderer/index.html'),'utf8');
  const renderer = fs.readFileSync(path.join(__dirname, '../src/renderer/app.js'),'utf8');
  const preload = fs.readFileSync(path.join(__dirname, '../src/preload/preload.js'),'utf8');
  const main = fs.readFileSync(path.join(__dirname, '../src/main/main.js'),'utf8');
  assert.match(html, /id="operatorFullDevicePreflightButton" disabled/);
  assert.match(html, /id="operatorFullDevicePreflightStatus"/);
  assert.match(renderer, /window\.gateway\.operatorFullDevicePreflight\(\)/);
  assert.match(preload, /operatorFullDevicePreflight: \(\) => ipcRenderer\.invoke\('gateway:operatorFullDevicePreflight'\)/);
  assert.match(main, /ipcMain\.handle\('gateway:operatorFullDevicePreflight', \(\) => backend\.checkOperatorFullDevicePreflight\(\)\)/);
  assert.match(renderer, /full-device activation and independent active-tunnel rollback are NOT enabled or verified/);
});
