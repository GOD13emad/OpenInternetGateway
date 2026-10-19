const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

test('operator QA rollback is name/UUID scoped, independent and never activates network',
  { skip: process.platform !== 'linux' }, () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-qa-rollback-'));
    const uuid = 'c1234567-1234-4234-8234-123456789abc';
    const name = 'OIG-Operator-QA-aabbccddeeff';
    const statePath = path.join(root, 'state.json');
    const events = path.join(root, 'events.txt');
    const sourceScript = path.join(__dirname, '..', 'backend', 'linux', 'operator_rollback.py');
    const fakeMount = path.join(root, 'ephemeral-appimage-mount');
    fs.mkdirSync(fakeMount);
    let script = path.join(fakeMount, 'operator_rollback.py');
    fs.copyFileSync(sourceScript, script);
    const state = s => fs.writeFileSync(statePath, JSON.stringify(s), {mode: 0o600});
    const shim = [
      '#!/usr/bin/env python3',
      'import os,json,sys,pathlib',
      'p=pathlib.Path(os.environ["OIG_STUB_ROLLBACK_STATE"])',
      'a=sys.argv[1:]',
      's=json.loads(p.read_text())',
      'with open(os.environ["OIG_STUB_ROLLBACK_EVENTS"],"a") as f:f.write(" ".join(a)+"\\n")',
      'uuid="'+uuid+'"',
      'if os.path.basename(sys.argv[0])=="systemd-run":',
      '    if not any(x.startswith("--on-active=") for x in a):sys.exit(9)',
      '    s["scheduled"]=True',
      'elif os.path.basename(sys.argv[0])=="systemctl":',
      '    if s.get("scheduled"):print("active")',
      '    else:sys.exit(3)',
      'elif a[:2]==["--wait","5"]:',
      '    args=a[2:]',
      '    if args==["-t","-f","UUID","connection","show"]:',
      '        if s.get("exists"):print(uuid)',
      '    elif args==["-g","connection.id","connection","show","uuid",uuid]:',
      '        if s.get("exists"):print(s.get("name"))',
      '        else:sys.exit(10)',
      '    elif args==["-t","-f","UUID","connection","show","--active"]:',
      '        if s.get("exists") and s.get("active"):print(uuid)',
      '    elif args==["connection","down","uuid",uuid]:',
      '        if s.get("exists") and s.get("active"):s["active"]=False',
      '        else:sys.exit(10)',
      '    elif args==["connection","delete","uuid",uuid]:',
      '        if s.get("failDelete"):sys.exit(12)',
      '        s["exists"]=False;s["active"]=False',
      '    else:sys.exit(15)',
      'else:sys.exit(20)',
      'p.write_text(json.dumps(s))',
      ''
    ].join('\n');
    try {
      for (const program of ['nmcli', 'systemd-run', 'systemctl']) {
        fs.writeFileSync(path.join(root, program), shim, {mode: 0o700});
      }
      const env = {
        ...process.env, PATH: root + path.delimiter + process.env.PATH,
        OIG_STUB_ROLLBACK_STATE: statePath,
        OIG_STUB_ROLLBACK_EVENTS: events, PYTHONDONTWRITEBYTECODE: '1',
        XDG_DATA_HOME: path.join(root, 'xdg-data')
      };
      function invoke(action, extra = [], id = uuid, label = name) {
        return spawnSync('python3', [script, action, '--uuid', id,
          '--name', label, ...extra], {encoding: 'utf8', timeout: 6000, env});
      }
      state({exists:true,active:false,name,scheduled:false});
      const armed = invoke('arm', ['--seconds','30']);
      assert.equal(armed.status, 0, armed.stderr);
      assert.equal(JSON.parse(armed.stdout).timerArmed, true);
      assert.match(fs.readFileSync(events, 'utf8'), /is-active/);
      assert.match(fs.readFileSync(events, 'utf8'), /AccuracySec=1s/);
      const stableDir = path.join(root, 'xdg-data', 'OpenInternetGateway', 'qa-rollback');
      const names = fs.readdirSync(stableDir);
      assert.equal(names.length, 1);
      const stableRunner = path.join(stableDir, names[0]);
      assert.ok(fs.readFileSync(stableRunner).equals(fs.readFileSync(sourceScript)),
        'Timer runner is an exact independent copy of the packaged Python helper');
      assert.equal(fs.statSync(stableDir).mode & 0o777, 0o700);
      assert.equal(fs.statSync(stableRunner).mode & 0o777, 0o600);
      assert.match(fs.readFileSync(events, 'utf8'), new RegExp(
        stableRunner.replace(/[.*+?^\${}()|[\]\\]/g, '\\$&')));
      assert.doesNotMatch(fs.readFileSync(events, 'utf8'), /ephemeral-appimage-mount/);
      // Simulate the AppImage mount disappearing before rollback executes.
      fs.unlinkSync(script);
      script = stableRunner;
      assert.equal(fs.existsSync(path.join(fakeMount, 'operator_rollback.py')), false);
      assert.equal(invoke('arm', ['--seconds','9']).status, 2);
      assert.equal(invoke('arm', ['--seconds','301']).status, 2);
      assert.equal(invoke('arm', ['--seconds','30'],uuid,'User-WiFi').status, 2);
      assert.equal(invoke('arm', ['--seconds','30'],
        '00000000-0000-0000-0000-000000000000').status, 2);

      state({exists:true,active:true,name});
      const cleaned = invoke('cleanup');
      assert.equal(cleaned.status, 0, cleaned.stderr);
      assert.equal(JSON.parse(cleaned.stdout).profileRemoved, true);
      assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).exists, false);
      const alreadyAbsent = invoke('cleanup');
      assert.equal(alreadyAbsent.status, 0);
      assert.equal(JSON.parse(alreadyAbsent.stdout).alreadyAbsent, true);

      state({exists:true,active:true,name:'Other-Connection'});
      const unrelated = invoke('cleanup');
      assert.equal(unrelated.status, 2);
      assert.equal(JSON.parse(fs.readFileSync(statePath, 'utf8')).active, true);
      state({exists:true,active:true,name,failDelete:true});
      const failed = invoke('cleanup');
      assert.equal(failed.status, 2);
      assert.doesNotMatch(failed.stdout, /profileRemoved/);
      const log = fs.readFileSync(events, 'utf8');
      assert.doesNotMatch(log, /connection up|networking off|device disconnect|route /);
      assert.match(log, /connection delete uuid/);
    } finally {
      fs.rmSync(root, {recursive:true,force:true});
    }
  });
