const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawnSync} = require('node:child_process');

test('opt-in QA trial passes provider password only in memfd, arms timer before activation and rolls back',
  {skip: process.platform !== 'linux'}, async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-memory-secrets-'));
    const uuid = 'd1234567-1234-4234-8234-123456789abc';
    const script = path.join(__dirname, '../backend/linux/operator_trial.py');
    try {
      const cert = path.join(root, 'synthetic.crt');
      const key = path.join(root, 'synthetic.key');
      const crt = spawnSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048',
        '-nodes','-days','1','-subj','/CN=synthetic-only',
        '-out',cert,'-keyout',key], {encoding:'utf8',timeout:5000});
      assert.equal(crt.status,0,crt.stderr);
      const ca = fs.readFileSync(cert,'utf8').trim();
      const fingerprint = crypto.createHash('sha256')
        .update(new crypto.X509Certificate(ca).raw).digest('hex');
      const profile = path.join(root,'source.ovpn');
      fs.writeFileSync(profile, [
        'client','dev tun','proto tcp-client','remote uk205.vpnbook.com 443',
        'auth-user-pass','<ca>',ca,'</ca>',
        '<cert>',ca,'</cert>','<key>',fs.readFileSync(key,'utf8').trim(),'</key>',''
      ].join('\n'),{mode:0o600});
      const state = path.join(root, 'state.json');
      const log = path.join(root,'events.log');
      const shim = [
        '#!/usr/bin/env python3',
        'import os,sys,json,pathlib,re',
        'a=sys.argv[1:]; tool=pathlib.Path(sys.argv[0]).name',
        'p=pathlib.Path(os.environ["OIG_SECRET_STUB_STATE"])',
        's=json.loads(p.read_text())',
        'u="'+uuid+'"',
        'with open(os.environ["OIG_SECRET_STUB_LOG"],"a") as f:',
        '    f.write(tool+" "+("UP" if "passwd-file" in a else " ".join(a[:8]))+"\\n")',
        'def done(code=0):',
        '    p.write_text(json.dumps(s));sys.exit(code)',
        'if tool=="systemd-run":',
        '    if os.environ.get("OIG_SECRET_STUB_FAIL_ARM")=="1":done(7)',
        '    s["timerEnv"]=[x for x in a if x.startswith("--setenv=") ]',
        '    s["rollbackHelper"]=a[11];s["rollbackArgs"]=a[12:]',
        '    s["armed"]=True;done()',
        'if tool=="systemctl":',
        '    if "is-active" in a and s.get("armed"):print("active")',
        '    done(0 if s.get("armed") else 5)',
        'if a==["-t","-f","NAME,TYPE","connection","show","--active"]:',
        '    if os.environ.get("OIG_SECRET_STUB_ACTIVE_OIG")=="1":print("OIG-VPN-LIVE:vpn")',
        '    if os.environ.get("OIG_SECRET_STUB_ACTIVE_EXTERNAL_VPN")=="1":print("IPbaz:vpn")',
        '    if os.environ.get("OIG_SECRET_STUB_ACTIVE_EXTERNAL_TUN")=="1":print("tailscale0:tun")',
        '    if s.get("externalVpn"):print("IPbaz:vpn")',
        '    if s.get("active"):print(s.get("name", "OIG-Operator-QA-test")+":vpn")',
        '    done()',
        'if a[:5]==["--wait","5","-t","-f","UUID"] and a[5:]==["connection","show"]:',
        '    print(u if s.get("exists") else "aaaaaaaa-1234-4234-8234-123456789abc");done()',
        'if a[:3]==["-t","-f","UUID"] and a[3:]==["connection","show","--active"]:',
        '    if s.get("active"):print(u)',
        '    done()',
        'if a[:4]==["--wait","5","connection","import"]:',
        '    assert a[4:8]==["--temporary","type","openvpn","file"]',
        '    source=pathlib.Path(a[8]);assert source.exists();stem=source.stem;content=source.read_text()',
        '    certdir=pathlib.Path(os.environ["XDG_DATA_HOME"])/"networkmanagement/certificates/nm-openvpn";certdir.mkdir(parents=True,exist_ok=True)',
        '    files={}',
        '    for name in ("ca","cert","key"):',
        '        match=re.search(r"<"+name+r">\\s*(.*?)\\s*</"+name+r">",content,re.S);assert match,name',
        '        target=certdir/(stem+"-"+name+".pem");target.write_text(match.group(1).strip()+"\\n");target.chmod(0o600);files[name]=str(target)',
        '    s["exists"]=True;s["name"]=stem;s["certs"]=files',
        '    s["vpnData"]="auth=SHA256, ca="+files["ca"]+", cert="+files["cert"]+", key="+files["key"]+", proto-tcp=yes, remote=uk205.vpnbook.com:443, remote-cert-tls=server, verify-x509-name=name:server.vpnbook.com"',
        '    if os.environ.get("OIG_SECRET_STUB_FAIL_IMPORT_AFTER")=="1":done(12)',
        '    print("Connection imported ("+u+")");done()',
        'if a[:5]==["--wait","5","connection","modify","--temporary"]:',
        '    assert "connection.id" in a and "vpn.user-name" in a',
        '    assert "ipv4.ignore-auto-routes" in a and a[a.index("ipv4.ignore-auto-routes")+1]=="yes"',
        '    assert "ipv6.ignore-auto-routes" in a and a[a.index("ipv6.ignore-auto-routes")+1]=="yes"',
        '    s["name"]=a[a.index("connection.id")+1]',
        '    s["username"]=a[a.index("vpn.user-name")+1]',
        '    s["scoped"]=True',
        '    if os.environ.get("OIG_SECRET_STUB_EXTERNAL_VPN_AFTER_MODIFY")=="1":s["externalVpn"]=True',
        '    if os.environ.get("OIG_SECRET_STUB_FAIL_MODIFY_AFTER")=="1":done(14)',
        '    done()',
        'if a[:2]==["-g","connection.autoconnect,ipv4.never-default,ipv6.never-default,ipv4.ignore-auto-dns,ipv6.ignore-auto-dns,ipv4.ignore-auto-routes,ipv6.ignore-auto-routes,vpn.user-name"]:',
        '    assert s.get("scoped")',
        '    print("no\\nyes\\nyes\\nyes\\nyes\\nyes\\nyes\\n"+s["username"]);done()',
        'if a[:4]==["--wait","5","-g","connection.id"]:',
        '    if s.get("exists"):print(s["name"]);done()',
        '    done(10)',
        'if a[:2]==["-g","connection.id"]:',
        '    if s.get("exists"):print(s["name"]);done()',
        '    done(10)',
        'if a[:4]==["--wait","5","-g","connection.type"]:',
        '    print("vpn" if s.get("exists") else "ethernet");done()',
        'if a[:4]==["--wait","5","-g","vpn.data"]:',
        '    print(s.get("vpnData","") if s.get("exists") else "");done()',
        'if a[:2]==["-g","connection.type"]:',
        '    print("vpn");done()',
        'if a[:2]==["-g","vpn.data"]:',
        '    print(s.get("vpnData",""));done()',
        'if a[:3]==["--wait","5","-t"] and a[3:]==["-f","UUID","connection","show","--active"]:',
        '    if s.get("active"):print(u)',
        '    done()',
        'if a[:4]==["--wait","25","connection","up"]:',
        '    assert s.get("armed"),"timer not armed before activation"',
        '    assert a[4:6]==["uuid",u]',
        '    assert a[6]=="passwd-file"',
        '    secret=pathlib.Path(a[7]).read_text()',
        '    assert secret=="vpn.secrets.password:fake-test-only-pass\\n"',
        '    s["memfdPass"]=True',
        '    if os.environ.get("OIG_SECRET_STUB_FAIL_UP")=="1":done(11)',
        '    s["active"]=True',
        '    if os.environ.get("OIG_SECRET_STUB_EXTERNAL_VPN_AFTER_UP")=="1":s["externalVpn"]=True',
        '    done()',
        'if a[:3]==["--wait","5","connection"] and a[3:5]==["down","uuid"]:',
        '    if not s.get("active"):done(10)',
        '    s["active"]=False;done()',
        'if a[:3]==["--wait","5","connection"] and a[3:5]==["delete","uuid"]:',
        '    s["exists"]=False;s["active"]=False;done()',
        'done(19)',
        ''
      ].join('\n');
      for (const tool of ['nmcli','systemd-run','systemctl']) {
        fs.writeFileSync(path.join(root,tool),shim,{mode:0o700});
      }
      const base = {
        ...process.env, PATH: root + path.delimiter + process.env.PATH,
        OIG_SECRET_STUB_STATE: state, OIG_SECRET_STUB_LOG: log,
        PYTHONDONTWRITEBYTECODE:'1', XDG_DATA_HOME: path.join(root, 'xdg-data')
      };
      function run(opts = {}, pin = fingerprint, pass = 'fake-test-only-pass') {
        fs.writeFileSync(state,JSON.stringify({exists:false,active:false,armed:false}));
        fs.writeFileSync(log,'');
        return spawnSync('python3',[
          '-B',script,'trial','--profile',profile,'--ca-sha256',pin,
          '--peer-cn','server.vpnbook.com','--timer-seconds','45'
        ],{env:{...base,...opts},encoding:'utf8',timeout:7500,
          input:JSON.stringify({username:'vpnbook',password:pass})});
      }
      const good = run();
      assert.equal(good.status,0,good.stderr);
      const parsed = JSON.parse(good.stdout);
      assert.equal(parsed.tempProfileRemoved,true);
      assert.equal(parsed.independentTimerArmedBeforeActivation,true);
      assert.equal(parsed.identityVerifiedByApp,true);
      assert.equal(parsed.liveTlsVerified,true);
      assert.equal(parsed.trustConstraintsPreserved,true);
      assert.equal(parsed.certificateArtifactsRemoved,true);
      assert.equal(parsed.peerCN,'server.vpnbook.com');
      assert.equal(parsed.fullDeviceTunnelVerified,false);
      const current = JSON.parse(fs.readFileSync(state,'utf8'));
      assert.equal(current.exists,false);
      assert.equal(current.memfdPass,true);
      const certdir = path.join(base.XDG_DATA_HOME,'networkmanagement','certificates','nm-openvpn');
      assert.deepEqual(fs.readdirSync(certdir),[]);
      const events = fs.readFileSync(log,'utf8');
      assert.ok(events.indexOf('systemd-run') < events.indexOf('connection modify'));
      assert.ok(events.indexOf('systemd-run') < events.indexOf('UP'));
      for (const secret of ['fake-test-only-pass','vpn.secrets.password:']) {
        assert.doesNotMatch(good.stdout+good.stderr+events,new RegExp(secret));
      }
      const failUp = run({OIG_SECRET_STUB_FAIL_UP:'1'});
      assert.equal(failUp.status,2);
      assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).exists,false);
      assert.doesNotMatch(failUp.stderr,/fake-test-only-pass/);
      const failTimer = run({OIG_SECRET_STUB_FAIL_ARM:'1'});
      assert.equal(failTimer.status,2);
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/UP/);
      assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).exists,false);
      const concurrent = run({OIG_SECRET_STUB_ACTIVE_OIG:'1'});
      assert.equal(concurrent.status,2);
      assert.match(concurrent.stderr,/still active/);
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/connection import|UP/);
      const externalVpn = run({OIG_SECRET_STUB_ACTIVE_EXTERNAL_VPN:'1'});
      assert.equal(externalVpn.status,2);
      assert.match(externalVpn.stderr,/independent VPN or tunnel is active/);
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/connection import|UP/);
      const externalTun = run({OIG_SECRET_STUB_ACTIVE_EXTERNAL_TUN:'1'});
      assert.equal(externalTun.status,2);
      assert.match(externalTun.stderr,/independent VPN or tunnel is active/);
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/connection import|UP/);
      const externalAfterModify = run({OIG_SECRET_STUB_EXTERNAL_VPN_AFTER_MODIFY:'1'});
      assert.equal(externalAfterModify.status,2);
      assert.match(externalAfterModify.stderr,/independent VPN or tunnel is active/);
      assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).exists,false,
        'A VPN started during import must block activation and still clean up the QA profile');
      assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).externalVpn,true,
        'The external VPN must remain active and untouched');
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/UP/);
      const externalAfterUp = run({OIG_SECRET_STUB_EXTERNAL_VPN_AFTER_UP:'1'});
      assert.equal(externalAfterUp.status,2);
      assert.match(externalAfterUp.stderr,/independent VPN or tunnel is active/);
      const externalAfterUpState = JSON.parse(fs.readFileSync(state,'utf8'));
      assert.equal(externalAfterUpState.exists,false,
        'The QA profile must be rolled back when an external VPN appears during activation');
      assert.equal(externalAfterUpState.active,false,
        'The QA VPN must be down after the race is detected');
      assert.equal(externalAfterUpState.externalVpn,true,
        'Rollback must leave the independently started VPN active');
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/IPbaz/,
        'Rollback must never issue a down/delete operation for the external VPN');
      const failedImport = run({OIG_SECRET_STUB_FAIL_IMPORT_AFTER:'1'});
      assert.equal(failedImport.status,2);
      assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).exists,false,
        'A rejected import which created a profile must still be removed');
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/UP/);
      const failedModify = run({OIG_SECRET_STUB_FAIL_MODIFY_AFTER:'1'});
      assert.equal(failedModify.status,2);
      assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).exists,false,
        'A partially applied temporary profile name must be recovered');
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/UP/);
      const badPin = run({},'0'.repeat(64));
      assert.equal(badPin.status,2);
      assert.doesNotMatch(fs.readFileSync(log,'utf8'),/connection import|connection up|UP/);
      assert.equal(run({},fingerprint,'invalid\npassword').status,2);
      // Verify the actual Electron Backend -> Python stdin transport without
      // invoking NetworkManager: all external tools resolve to our stubs.
      const baseBackend = require('../src/main/platform-backend');
      const backend = new baseBackend({
        version:'2.5.20',appPath:root,resourcesPath:root,userData:root
      });
      backend.platform = 'linux';
      backend.backendRoot = root;
      fs.mkdirSync(path.join(root,'linux'));
      fs.mkdirSync(path.join(root,'state'));
      for (const file of ['operator_profile.py','operator_rollback.py','operator_trial.py']) {
        fs.copyFileSync(path.join(__dirname,'../backend/linux',file),
          path.join(root,'linux',file));
      }
      fs.writeFileSync(path.join(root,'state','desired-state'),'off\n');
      const staged = spawnSync('python3',[
        path.join(root,'linux','operator_profile.py'),'stage',
        '--profile',profile,'--ca-sha256',fingerprint,
        '--peer-cn','server.vpnbook.com','--common',path.join(root,'common')
      ],{encoding:'utf8',timeout:5000});
      assert.equal(staged.status,0,staged.stderr);
      const previousEnv = Object.fromEntries(
        ['PATH','OIG_SECRET_STUB_STATE','OIG_SECRET_STUB_LOG','XDG_DATA_HOME'].map(k=>[k,process.env[k]])
      );
      try {
        for (const [k,val] of Object.entries(base)) {
          if (['PATH','OIG_SECRET_STUB_STATE','OIG_SECRET_STUB_LOG','XDG_DATA_HOME'].includes(k)) process.env[k]=val;
        }
        fs.writeFileSync(state,JSON.stringify({exists:false,active:false,armed:false}));
        fs.writeFileSync(log,'');
        const result = await backend.operatorConnectionTrial('vpnbook','fake-test-only-pass');
        assert.equal(result.ok,true);
        assert.equal(result.tempProfileRemoved,true);
        assert.equal(result.fullDeviceTunnelVerified,false);
        assert.equal(result.identityVerifiedByApp,true);
        assert.equal(result.liveTlsVerified,true);
        assert.equal(result.trustConstraintsPreserved,true);
        assert.equal(result.certificateArtifactsRemoved,true);
        assert.equal(JSON.parse(fs.readFileSync(state,'utf8')).exists,false);
        assert.deepEqual(fs.readdirSync(certdir),[]);
        assert.doesNotMatch(JSON.stringify(result),/fake-test-only-pass/);
        fs.writeFileSync(path.join(root,'state','desired-state'),'on\n');
        await assert.rejects(backend.operatorConnectionTrial('vpnbook','fake-test-only-pass'),
          /Disconnect the regular OIG gateway/);
        fs.writeFileSync(path.join(root,'state','desired-state'),'off\n');
        backend.gatewayActionCount = 1;
        await assert.rejects(
          backend.operatorConnectionTrial('vpnbook','fake-test-only-pass'),
          /Wait for the regular gateway operation/);
        backend.gatewayActionCount = 0;
        backend.operatorTrialBusy = true;
        for (const action of ['connect','connect-profile','refresh','factory-refresh','benchmark-all-fast']) {
          await assert.rejects(backend.action(action), /isolated provider trial is active/);
        }
        assert.equal(backend.gatewayActionCount, 0);
        await assert.rejects(backend.stageOperatorProfile(profile, fingerprint, 'server.vpnbook.com'),
          /Cannot replace the operator profile/);
        await assert.rejects(backend.checkOperatorNativeCompatibility(),
          /Cannot import the operator profile/);
        backend.operatorTrialBusy = false;
        backend.operatorUpdateBusy = true;
        await assert.rejects(backend.operatorConnectionTrial('vpnbook','fake-test-only-pass'),
          /Wait for the pending update/);
        await assert.rejects(
          backend.stageOperatorProfile(profile, fingerprint, 'server.vpnbook.com'),
          /Cannot operate on profiles while an update is pending/);
        await assert.rejects(backend.checkOperatorNativeCompatibility(),
          /Cannot operate on profiles while an update is pending/);
        backend.operatorUpdateBusy = false;
        backend.operatorProfileTaskBusy = true;
        await assert.rejects(
          backend.operatorConnectionTrial('vpnbook', 'fake-test-only-pass'),
          /Wait for operator-profile import\/check/);
        await assert.rejects(
          backend.stageOperatorProfile(profile, fingerprint, 'server.vpnbook.com'),
          /Another operator-profile task is still running/);
        await assert.rejects(backend.checkOperatorNativeCompatibility(),
          /Another operator-profile task is still running/);
        backend.operatorProfileTaskBusy = false;
        const originalLinux = backend._linux;
        backend._linux = async () => ({ ok: true });
        backend.status = async () => ({ connected: false });
        const ordinary = await backend.action('disconnect');
        assert.equal(ordinary.ok, true, 'Emergency gateway disconnect remains available');
        assert.equal(backend.gatewayActionCount, 0, 'The regular action lock is always released');
        backend._linux = originalLinux;
        backend.platform='win32';
        await assert.rejects(backend.operatorConnectionTrial('vpnbook','fake-test-only-pass'),
          /only on Linux/);
        backend.platform='linux';

        // Simulate the app process disappearing after the independent timer
        // was armed. Execute the durable copied helper exactly as systemd-run
        // would, and verify it removes the active UUID and its three PEM copies.
        const rollbackScript = path.join(__dirname,'../backend/linux/operator_rollback.py');
        const timerName = 'OIG-Operator-QA-a1b2c3d4e5f6';
        const timerCertDir = path.join(base.XDG_DATA_HOME,'networkmanagement','certificates','nm-openvpn');
        fs.mkdirSync(timerCertDir,{recursive:true,mode:0o700});
        const pem = { ca, cert: ca, key: fs.readFileSync(key,'utf8').trim() };
        const files = {};
        for (const name of ['ca','cert','key']) {
          const target = path.join(timerCertDir,timerName+'-'+name+'.pem');
          fs.writeFileSync(target,pem[name],{mode:0o600});
          fs.chmodSync(target,0o600);
          files[name]=target;
        }
        fs.writeFileSync(state,JSON.stringify({
          exists:true,active:false,armed:false,name:timerName,
          vpnData:'ca='+files.ca+', cert='+files.cert+', key='+files.key+
            ', remote=uk205.vpnbook.com:443, remote-cert-tls=server, verify-x509-name=name:server.vpnbook.com'
        }));
        const artifactHashes = Object.fromEntries(
          Object.entries(pem).map(([name,value])=>[
            name,crypto.createHash('sha256').update(value).digest('hex')
          ])
        );
        const armed = spawnSync('python3',[
          '-B',rollbackScript,'arm','--uuid',uuid,'--name',timerName,
          '--artifact-stem',timerName,'--certificate-directory',timerCertDir,
          '--ca-sha256',artifactHashes.ca,'--cert-sha256',artifactHashes.cert,
          '--key-sha256',artifactHashes.key,'--seconds','45'
        ],{env:base,encoding:'utf8',timeout:5000});
        assert.equal(armed.status,0,armed.stderr);
        const armedState=JSON.parse(fs.readFileSync(state,'utf8'));
        assert.equal(armedState.armed,true);
        assert.ok(fs.existsSync(armedState.rollbackHelper));
        assert.equal(fs.statSync(armedState.rollbackHelper).mode & 0o777,0o600);
        assert.equal(armedState.rollbackArgs[0],'cleanup');
        const afterActivation = JSON.parse(fs.readFileSync(state,'utf8'));
        afterActivation.active = true;
        fs.writeFileSync(state,JSON.stringify(afterActivation));
        assert.equal(armedState.timerEnv.length,1);
        assert.match(armedState.timerEnv[0],/^--setenv=XDG_DATA_HOME=/);
        const timerEnv={...base};
        delete timerEnv.XDG_DATA_HOME;
        timerEnv.XDG_DATA_HOME=armedState.timerEnv[0].slice('--setenv=XDG_DATA_HOME='.length);
        const timerRun=spawnSync('python3',[
          '-B',armedState.rollbackHelper,...armedState.rollbackArgs
        ],{env:timerEnv,encoding:'utf8',timeout:8000});
        assert.equal(timerRun.status,0,timerRun.stderr);
        const timerResult=JSON.parse(timerRun.stdout);
        assert.equal(timerResult.profileRemoved,true);
        assert.equal(timerResult.certificateArtifactsRemoved,true);
        const timerFinal=JSON.parse(fs.readFileSync(state,'utf8'));
        assert.equal(timerFinal.exists,false);
        assert.equal(timerFinal.active,false);
        assert.deepEqual(fs.readdirSync(certdir),[]);

        // A file with the expected name but different content is not ours to
        // delete, even when the timer runs after the profile has disappeared.
        const tampered = path.join(timerCertDir,timerName+'-ca.pem');
        fs.writeFileSync(tampered,'-----BEGIN CERTIFICATE-----\\nnot-the-pinned-ca\\n',{mode:0o600});
        const refused = spawnSync('python3',[
          '-B',armedState.rollbackHelper,...armedState.rollbackArgs
        ],{env:timerEnv,encoding:'utf8',timeout:8000});
        assert.equal(refused.status,2);
        assert.match(refused.stderr,/SHA-256 pin/);
        assert.equal(fs.existsSync(tampered),true);
        fs.unlinkSync(tampered);

        const wrongDir = path.join(root,'other','networkmanagement','certificates','nm-openvpn');
        const wrongArgs = [...armedState.rollbackArgs];
        const certificateDirIndex = wrongArgs.indexOf('--certificate-directory');
        assert.ok(certificateDirIndex >= 0);
        wrongArgs[certificateDirIndex+1] = wrongDir;
        const wrongPath = spawnSync('python3',[
          '-B',armedState.rollbackHelper,...wrongArgs
        ],{env:timerEnv,encoding:'utf8',timeout:8000});
        assert.equal(wrongPath.status,2);
        assert.match(wrongPath.stderr,/configured XDG NetworkManager path/);
      } finally {
        for (const [key,val] of Object.entries(previousEnv)) {
          if (val===undefined) delete process.env[key];
          else process.env[key]=val;
        }
      }
      const main = fs.readFileSync(path.join(__dirname,'../src/main/main.js'),'utf8');
      const preload = fs.readFileSync(path.join(__dirname,'../src/preload/preload.js'),'utf8');
      const renderer = fs.readFileSync(path.join(__dirname,'../src/renderer/app.js'),'utf8');
      assert.match(main,/gateway:operatorTrial/);
      assert.match(main,/Wait for isolated VPN trial cleanup before updating/);
      assert.match(main,/Wait for operator-profile import\/check to complete before updating/);
      assert.match(main,/backend\?\.operatorTrialBusy \|\| backend\?\.operatorProfileTaskBusy/);
      assert.match(main,/backend\.operatorUpdateBusy = true/);
      assert.match(main,/if \(!handedOff\) backend\.operatorUpdateBusy = false/);
      assert.match(main,/a provider trial is active; Quit waits for cleanup/);
      assert.match(main,/cannot exit during provider trial cleanup/);
      assert.match(preload,/gateway:operatorTrial/);
      assert.match(renderer,/operatorTrialConsent/);
      assert.match(renderer,/operatorPassword'\)\.value = ''/);

    } finally {
      fs.rmSync(root,{recursive:true,force:true});
    }
  });
