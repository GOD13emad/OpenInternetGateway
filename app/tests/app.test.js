const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const root = path.resolve(__dirname,'..');

test('renderer exposes all primary product workflows',()=>{
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  for(const text of ['Refresh configs','Repair now','Automatic recovery','Console Gateway','Self-Healing Config Factory','Refresh configs','Diagnostics','Activity','Settings']) assert.match(html,new RegExp(text,'i'));
});

test('secure Electron boundary is configured',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/contextIsolation:\s*true/);
  assert.match(main,/nodeIntegration:\s*false/);
  assert.match(main,/sandbox:\s*true/);
});

test('Windows backend rejects inherited prototype action keys before launching PowerShell',async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const os=require('node:os');
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-action-map-'));
  try{
    const backend=new Backend({version:'2.5.19',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
    backend.backendRoot=tmp;
    // Nonexistent executable: no privileged process, VPN, or network action can run.
    backend._requireWindowsPwsh=()=>path.join(tmp,'no-powershell-runtime.exe');
    for(const action of ['constructor','toString','__proto__','hasOwnProperty','not-an-action']){
      await assert.rejects(backend._windows(action),/Unsupported action:/,
        'reject inherited/unlisted action before attempting shell command: '+action);
    }
  }finally{fs.rmSync(tmp,{recursive:true,force:true});}
});

test('dashboard explicitly separates VPN route health from relay certificate identity',()=>{
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  const styles=fs.readFileSync(path.join(root,'src/renderer/styles.css'),'utf8');
  const ui=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const overview=html.slice(html.indexOf('id="page-overview"'),html.indexOf('id="page-connections"'));
  const connections=html.slice(html.indexOf('id="page-connections"'),html.indexOf('id="page-diagnostics"'));
  assert.match(overview,/VPN TUNNEL/);
  assert.match(overview,/class="relay-identity-note" role="note"/);
  assert.match(overview,/healthy VPN route does not verify the server certificate/i);
  assert.match(connections,/class="relay-identity-note" role="note"/);
  assert.match(connections,/share a CA and omit server-identity checks/i);
  assert.match(styles,/\.connection-copy \.relay-identity-note\{/);
  assert.match(ui,/connected \? 'VPN active' : 'Direct connection'/);
  assert.doesNotMatch(ui,/Internet protected|Validated endpoint/);
  assert.doesNotMatch(html,/SECURE TUNNEL/);
});

test('Config Factory exposes last-fetch transport without pretending provider profiles are authenticated',()=>{
  const py=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const ps=fs.readFileSync(path.join(root,'backend/windows/scripts/Config-Factory.ps1'),'utf8');
  const ui=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  for(const source of [py,ps]) {
    assert.match(source,/lastFetchTransport/);
    assert.match(source,/profileOriginAuthenticated/);
    assert.match(source,/usedMirrors/);
  }
  assert.match(py,/last_fetch_transport=="https"/);
  assert.match(ps,/lastFetchTransport -eq 'https'/);
  assert.match(html,/id="poolFetchTransport" class="relay-identity-note" role="note"/);
  assert.match(backend,/hasOwnProperty.call\(cached, 'lastFetchTransport'\)/);
  assert.match(ui,/fetchTransport === 'http'/);
  assert.match(ui,/Last feed fetch: plaintext HTTP/);
  assert.match(ui,/HTTPS transport\. Imported relay profiles/);
  assert.match(ui,/mixed or unknown transports/);
  assert.match(ui,/cached or unknown/);
});

test('Linux source transport provenance handles HTTP, HTTPS, mixed, cached and unknown in isolated factory status',()=>{
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const source=[
    'import sys,importlib.util,collections,json,tempfile',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("oig_factory",sys.argv[1])',
    'factory=importlib.util.module_from_spec(spec);spec.loader.exec_module(factory)',
    'cases=[("http",["http://relay.invalid"]),("https",["https://relay.invalid"]),("mixed",["http://relay.invalid","https://relay.invalid"]),("cached",[]),("unknown",None)]',
    'for expected,urls in cases:',
    '  with tempfile.TemporaryDirectory(prefix="oig-provenance-") as path:',
    '    common=Path(path)/"common";evidence=common/"evidence";evidence.mkdir(parents=True)',
    '    if urls is not None:',
    '      (evidence/"mirror-refresh-last.json").write_text(json.dumps({"usedMirrors":urls,"refresh":bool(urls)}))',
    '    s=factory.status(common,evidence)',
    '    assert s["lastFetchTransport"]==expected,(expected,s["lastFetchTransport"])',
    '    assert s["lastFetchTransportTlsOnly"]==(expected=="https")',
    '    assert s["profileOriginAuthenticated"] is False',
    'print("PASS five isolated source-transport fixtures")'
  ].join('\n');
  const r=cp.spawnSync('python3',['-c',source,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:15000});
  assert.equal(r.status,0,r.stderr||r.stdout);
  assert.match(r.stdout,/PASS five isolated source-transport fixtures/);
});

test('HTTPS relay feed redirects cannot silently downgrade to plaintext HTTP',()=>{
  const py=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const win=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  assert.match(py,/--proto-redir/);
  assert.match(py,/class NoHttpsDowngrade/);
  assert.match(win,/--proto-redir/);
  assert.match(win,/StartsWith\('https:\/\//);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const fixture=[
    'import importlib.util,sys,urllib.request',
    'spec=importlib.util.spec_from_file_location("factory",sys.argv[1])',
    'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'seen=[]',
    'm.shutil.which=lambda name: "/usr/bin/curl"',
    'def fake_run(args,**kwargs):',
    '  seen.append(args)',
    '  return type("Result",(),{"stdout":b"test","returncode":0})()',
    'm.subprocess.run=fake_run',
    'm.fetch("https://provider.invalid/api/iphone/")',
    'm.fetch("http://mirror.invalid/api/iphone/")',
    'assert seen[0][seen[0].index("--proto-redir")+1]=="=https",seen',
    'assert seen[1][seen[1].index("--proto-redir")+1]=="=http,https",seen',
    'handler=m.NoHttpsDowngrade()',
    'req=urllib.request.Request("https://provider.invalid/api/iphone/")',
    'try:',
    '  handler.redirect_request(req,None,302,"Found",{},"http://mirror.invalid/api/iphone/")',
    'except ValueError: pass',
    'else: raise AssertionError("HTTPS-to-HTTP redirect accepted")',
    'assert handler.redirect_request(req,None,302,"Found",{},"https://mirror.invalid/api/iphone/").full_url.startswith("https://")',
    'print("PASS curl and urllib HTTPS downgrade guard; HTTP fallback retained")'
  ].join('\n');
  const result=cp.spawnSync('python3',['-c',fixture,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:12000});
  assert.equal(result.status,0,result.stderr||result.stdout);
  assert.match(result.stdout,/PASS curl and urllib HTTPS downgrade guard/);
});

test('valid HTTPS VPN Gate feeds outrank faster HTTP mirrors with fallback intact',()=>{
  const win=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  assert.match(win,/HttpsPriority/);
  assert.match(win,/'HttpsPriority';Descending=\$true/);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const fixture=[
    'import sys,importlib.util,tempfile,base64,time,json',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("factory",sys.argv[1])',
    'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'def csvrows(offset):',
    '  lines=[]',
    '  for n in range(8):',
    '    ip="203.0.113.%d"%(offset+n)',
    '    ovpn="client\\ndev tun\\nproto udp\\nremote "+ip+" 1194\\n<ca>\\na\\n</ca>\\n<cert>\\nb\\n</cert>\\n<key>\\nc\\n</key>\\n"',
    '    line=["relay"+str(n),ip,"100","12","1000000","Japan","JP","4","0","0","0","0","0","0",base64.b64encode(ovpn.encode()).decode()]',
    '    lines.append(",".join(line))',
    '  return ("\\n".join(lines)+"\\n").encode()',
    'https=csvrows(10);http=csvrows(70)',
    'def slow_https(url,timeout=6,allow_partial=True):',
    '  if url.startswith("https://"): time.sleep(0.2);return https,False',
    '  return http,False',
    'm.fetch=slow_https',
    'with tempfile.TemporaryDirectory(prefix="oig-https-preference-") as td:',
    '  evidence=Path(td);m.refresh_snapshot(evidence,max_sources=3)',
    '  report=json.loads((evidence/"mirror-refresh-last.json").read_text())',
    '  assert report["usedMirrors"][0].startswith("https://"),report["usedMirrors"]',
    '  assert report["usedMirrors"]==["https://www.vpngate.net"],report',
    '  assert len(evidence.joinpath("vpngate-mirror-api.csv").read_text().splitlines())==8',
    '  assert all(line.split(",")[1].startswith("203.0.113.1") for line in evidence.joinpath("vpngate-mirror-api.csv").read_text().splitlines())',
    '  def unavailable_https(url,timeout=6,allow_partial=True):',
    '    if url.startswith("https://"): raise RuntimeError("offline HTTPS")',
    '    return http,False',
    '  m.fetch=unavailable_https',
    '  m.refresh_snapshot(evidence,max_sources=3)',
    '  fallback=json.loads((evidence/"mirror-refresh-last.json").read_text())',
    '  assert fallback["usedMirrors"] and all(u.startswith("http://") for u in fallback["usedMirrors"]),fallback',
    'print("PASS HTTPS priority with HTTP fallback")'
  ].join('\n');
  const res=cp.spawnSync('python3',['-c',fixture,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:15000});
  assert.equal(res.status,0,res.stderr||res.stdout);
  assert.match(res.stdout,/PASS HTTPS priority with HTTP fallback/);
});

test('Imported OpenVPN profiles fail closed on unknown executable directives and unsafe extra remote, including retained LKG',()=>{
  const factory=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const win=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(factory,/def profile_is_data_only\(text\):/);
  assert.match(factory,/if not profile_is_data_only\(text\): continue/);
  assert.match(win,/function Test-SafePublicVpnProfile\(\[string\]\$text\)/);
  assert.equal((win.match(/Test-SafePublicVpnProfile \$text/g)||[]).length,2,'must guard both fresh and LKG imports');
  assert.match(factory,/inline_allowed = \{"ca", "cert", "key"/);
  assert.match(win,/\$allowedBlocks=@\('ca','cert','key'/);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const script=[
    'import sys,importlib.util,tempfile,base64',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("oig_safe",sys.argv[1])',
    'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'def config(i,extra):',
    '  return "client\\ndev tun\\nproto udp\\nremote 203.0.113.%d 1194\\ncipher AES-128-CBC\\nauth SHA1\\nresolv-retry infinite\\nnobind\\npersist-key\\npersist-tun\\nverb 3\\n<ca>\\nCA\\n</ca>\\n<cert>\\nCERT\\n</cert>\\n<key>\\nKEY\\n</key>\\n%s\\n"%(i,extra)',
    'cases=[("safe1",""),("safe2",""),("safe3",""),("management","management 127.0.0.1 7654"),("config","config /etc/sensitive.conf"),("tls_verify","tls-verify /bin/sh"),("extra_remote","remote 203.0.113.252 9999"),("file_log","log /tmp/untrusted.log"),("inline_script","<connection>\\nup /bin/sh\\n</connection>")]',
    'with tempfile.TemporaryDirectory(prefix="oig-relay-allowlist-") as tmp:',
    '  lines=[]',
    '  for i,(name,extra) in enumerate(cases,1):',
    '    fields=[name,"203.0.113.%d"%i,"100","12","1000000","Japan","JP","4","","","","","","",base64.b64encode(config(i,extra).encode()).decode()]',
    '    lines.append(",".join(fields))',
    '  csv=Path(tmp)/"relay.csv";csv.write_text("\\n".join(lines)+"\\n")',
    '  kept=m.parse_candidates(csv,count=20,per_country=20)',
    '  names={x["Host"] for x in kept}',
    '  assert names=={"safe1","safe2","safe3"},names',
    '  print("PASS safe=3 malicious_rejected=6")'
  ].join('\n');
  const result=cp.spawnSync('python3',['-c',script,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:15000});
  assert.equal(result.status,0,result.stderr||result.stdout);
  assert.match(result.stdout,/PASS safe=3 malicious_rejected=6/);
});

test('untrusted duplicate endpoint cannot suppress a later valid relay profile',()=>{
  const factory=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  const pyScope=factory.slice(factory.indexOf('def parse_candidates('),factory.indexOf('def preserve_old('));
  assert.ok(pyScope.indexOf('if not profile_is_data_only(text): continue') < pyScope.indexOf('seen.add(key)'));
  assert.ok(windows.indexOf('if(-not(Test-SafePublicVpnProfile $text)){continue}') < windows.indexOf('$seen[$key]=$true'));
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const script=[
    'import importlib.util,sys,tempfile,base64',
    'from pathlib import Path',
    'sp=importlib.util.spec_from_file_location("oig_factory",sys.argv[1]);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)',
    'def text(ip,extra):',
    '  return "client\\ndev tun\\nproto udp\\nremote %s 1194\\n<ca>\\nCA\\n</ca>\\n<cert>\\nCERT\\n</cert>\\n<key>\\nKEY\\n</key>\\n%s\\n"%(ip,extra)',
    'values=[("poison","203.0.113.10","management 127.0.0.1 7777"),("valid-same","203.0.113.10",""),("valid-other","203.0.113.11","")]',
    'with tempfile.TemporaryDirectory(prefix="oig-duplicate-safe-") as d:',
    '  rows=[]',
    '  for host,ip,extra in values:',
    '    parts=[host,ip,"100","12","1000000","Japan","JP","4","","","","","","",base64.b64encode(text(ip,extra).encode()).decode()]',
    '    rows.append(",".join(parts))',
    '  csv=Path(d)/"relays.csv";csv.write_text("\\n".join(rows)+"\\n")',
    '  hosts={x["Host"] for x in m.parse_candidates(csv,count=10,per_country=10)}',
    '  assert hosts=={"valid-same","valid-other"},hosts',
    'print("PASS duplicate malicious-first does not suppress valid same-IP relay")'
  ].join('\n');
  const x=cp.spawnSync('python3',['-c',script,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:12000});
  assert.equal(x.status,0,x.stderr||x.stdout);
  assert.match(x.stdout,/PASS duplicate malicious-first/);
});

test('VPN Gate CSV and Base64 input stay bounded and oversized rows fail closed',()=>{
  const py=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const winFetch=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  const winBuild=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(py,/MAX_SOURCE_CSV_BYTES = 24 \* 1024 \* 1024/);
  assert.match(py,/MAX_CSV_LINE_BYTES = 256 \* 1024/);
  assert.match(py,/--max-filesize/);
  assert.match(py,/def bounded_csv_rows/);
  assert.doesNotMatch(py,/for line in csv_path\.read_text\(/);
  assert.match(winFetch,/--max-filesize/);
  assert.match(winFetch,/\$MaxSourceCsvBytes=24\*1024\*1024/);
  assert.match(winFetch,/\$MaxCsvLineBytes=256\*1024/);
  assert.match(winFetch,/\$mergedBytes\+/);
  assert.match(winBuild,/\$MaxCachedCsvBytes=72\*1024\*1024/);
  assert.match(winBuild,/\$MaxCsvLineBytes=256\*1024/);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const code=[
    'import sys,importlib.util,tempfile,base64,types,unittest.mock',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("oig_bounded",sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'def config(ip):',
    '  return "client\\ndev tun\\nproto udp\\nremote %s 1194\\n<ca>\\nCA\\n</ca>\\n<cert>\\nCERT\\n</cert>\\n<key>\\nKEY\\n</key>\\n"%ip',
    'with tempfile.TemporaryDirectory(prefix="oig-csv-bound-") as t:',
    '  p=Path(t)/"cache.csv"',
    '  rows=["bad,203.0.113.15,100,12,1000000,Japan,JP,4,,,,,,,"+"A"*(m.MAX_CSV_LINE_BYTES+1)]',
    '  for i in range(1,4):',
    '    ip="203.0.113.%d"%i',
    '    row=["valid%d"%i,ip,"100","12","1000000","Japan","JP","4","","","","","","",base64.b64encode(config(ip).encode()).decode()]',
    '    rows.append(",".join(row))',
    '  p.write_text("\\n".join(rows)+"\\n")',
    '  hosts={x["Host"] for x in m.parse_candidates(p,count=10,per_country=10)}',
    '  assert hosts=={"valid1","valid2","valid3"},hosts',
    '  with p.open("wb") as file:file.truncate(m.MAX_CACHED_CSV_BYTES+1)',
    '  try:list(m.bounded_csv_rows(p));raise AssertionError("oversized cached file accepted")',
    '  except RuntimeError:pass',
    '  huge=b"x"*(m.MAX_SOURCE_CSV_BYTES+1)',
    '  fake=types.SimpleNamespace(returncode=0,stdout=huge)',
    '  with unittest.mock.patch.object(m.shutil,"which",return_value="/usr/bin/curl"),unittest.mock.patch.object(m.subprocess,"run",return_value=fake) as run:',
    '    try:m.fetch("https://example.invalid/api/iphone/");raise AssertionError("oversized response accepted")',
    '    except RuntimeError:pass',
    '    argv=run.call_args.args[0]',
    '    assert "--max-filesize" in argv and str(m.MAX_SOURCE_CSV_BYTES) in argv',
    'print("PASS oversized response, row and cache all fail closed; 3 safe rows accepted")'
  ].join('\n');
  const r=cp.spawnSync('python3',['-c',code,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:20000});
  assert.equal(r.status,0,r.stderr||r.stdout);
  assert.match(r.stdout,/PASS oversized response, row and cache/);
});


test('Mirror refresh never clobbers healthy cached CSV with unsafe profiles or lets short source poison dedupe',()=>{
  const python=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const win=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  assert.match(python,/source_seen = set\(\)/);
  assert.match(python,/seen\.update\(source_seen\)/);
  assert.match(python,/len\(parse_candidates\(tmp, count=48, per_country=6\)\) < 3/);
  assert.match(win,/\$priorCsv=Join-Path \$tmpRoot "prior-complete\.csv"/);
  assert.match(win,/Copy-Item -LiteralPath \$priorCsv -Destination \$csv -Force/);
  assert.match(win,/Remove-Item -LiteralPath \$csv -Force -ErrorAction SilentlyContinue/);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const src=[
    'import sys,importlib.util,tempfile,base64,time,json',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("oig",sys.argv[1])',
    'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'def data(n,unsafe=False):',
    '  rows=[]',
    '  for i in range(1,n+1):',
    '    cfg="client\\ndev tun\\nproto udp\\nremote 203.0.113.%d 1194\\n<ca>\\nCA\\n</ca>\\n<cert>\\nCERT\\n</cert>\\n<key>\\nKEY\\n</key>\\n"%i',
    '    if unsafe:cfg+="management 127.0.0.1 7654\\n"',
    '    fields=["relay%d"%i,"203.0.113.%d"%i,"100","12","1000000","Japan","JP","4","","","","","","",base64.b64encode(cfg.encode()).decode()]',
    '    rows.append(",".join(fields))',
    '  return ("\\n".join(rows)+"\\n").encode()',
    'with tempfile.TemporaryDirectory(prefix="oig-atomic-mirror-") as d:',
    '  p=Path(d);old=data(9);(p/"vpngate-mirror-api.csv").write_bytes(old)',
    '  m.SEEDS=["http://bad.invalid"];m.fetch=lambda url,**kw:(data(9,True),False)',
    '  m.refresh_snapshot(p,max_sources=1)',
    '  assert (p/"vpngate-mirror-api.csv").read_bytes()==old',
    '  receipt=json.loads((p/"mirror-refresh-last.json").read_text())',
    '  assert not receipt["refresh"] and receipt["sourceCount"]==0',
    'with tempfile.TemporaryDirectory(prefix="oig-short-source-") as d:',
    '  p=Path(d);m.SEEDS=["http://short.invalid","http://healthy.invalid"]',
    '  def mock(url,**kw):',
    '    if "short.invalid" in url:return data(7),False',
    '    time.sleep(0.07);return data(9),False',
    '  m.fetch=mock',
    '  m.refresh_snapshot(p,max_sources=2)',
    '  assert len((p/"vpngate-mirror-api.csv").read_text().splitlines())==9',
    '  assert len(m.parse_candidates(p/"vpngate-mirror-api.csv",count=48,per_country=6))>=3',
    'print("PASS unsafe body cannot replace cache; seven-row source cannot suppress healthy mirror")'
  ].join('\n');
  const r=cp.spawnSync('python3',['-c',src,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:15000});
  assert.equal(r.status,0,r.stderr||r.stdout);
  assert.match(r.stdout,/PASS unsafe body cannot replace cache/);
});

test('Config Factory restores the previous active generation when new stage activation fails',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(linux,/archive = None[\s\S]*?try:\s*\n\s*stage\.rename\(active\)[\s\S]*?except Exception:[\s\S]*?archive\.rename\(active\)/);
  assert.match(windows,/\$archivedPrevious=\$null[\s\S]*?try\s*\{\s*Move-Item -LiteralPath \$stage -Destination \$active[\s\S]*?catch\s*\{[\s\S]*?Move-Item -LiteralPath \$archivedPrevious -Destination \$active/);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const code=[
    'import sys,tempfile,importlib.util,base64,hashlib,json',
    'from pathlib import Path',
    'from unittest import mock',
    's=importlib.util.spec_from_file_location("cf",sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)',
    'def config(i):',
    '  return "client\\ndev tun\\nproto udp\\nremote 203.0.113.%d 1194\\n<ca>\\nCA\\n</ca>\\n<cert>\\nCERT\\n</cert>\\n<key>\\nKEY\\n</key>\\n"%i',
    'with tempfile.TemporaryDirectory(prefix="oig-activate-rollback-") as d:',
    '  common=Path(d)/"common";ev=common/"evidence";ev.mkdir(parents=True)',
    '  active=common/"runtime/udp-cache";active.mkdir(parents=True)',
    '  old=config(77).encode();(active/"old.ovpn").write_bytes(old)',
    '  metadata=[{"Rank":1,"Host":"previous","IP":"203.0.113.77","Port":1194,"Protocol":"udp","Profile":"runtime/udp-cache/old.ovpn","SHA256":hashlib.sha256(old).hexdigest()}]',
    '  (active/"index.json").write_text(json.dumps(metadata))',
    '  index_before=(active/"index.json").read_bytes()',
    '  lines=[]',
    '  for i in range(1,5):',
    '    cols=["relay%d"%i,"203.0.113.%d"%i,"100","12","1000000","Japan","JP","4","","","","","","",base64.b64encode(config(i).encode()).decode()]',
    '    lines.append(",".join(cols))',
    '  (ev/"vpngate-mirror-api.csv").write_text("\\n".join(lines)+"\\n")',
    '  original=Path.rename',
    '  def rename(path,destination):',
    '    if path.name.startswith("pool-") and destination==active:',
    '      raise OSError("OFFLINE_ACTIVATION_FAILURE_INJECTED")',
    '    return original(path,destination)',
    '  with mock.patch.object(Path,"rename",rename):',
    '    try:m.promote(common,ev,count=4,preserve_count=0);raise AssertionError("fault not triggered")',
    '    except OSError as exc:assert "OFFLINE_ACTIVATION_FAILURE" in str(exc),exc',
    '  assert (active/"index.json").read_bytes()==index_before',
    '  assert (active/"old.ovpn").read_bytes()==old',
    '  assert not list((common/"runtime/config-factory/generations").iterdir())',
    'print("PASS stage rename failure restored previous index and profile without losing active pool")'
  ].join('\n');
  const result=cp.spawnSync('python3',['-c',code,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:20000});
  assert.equal(result.status,0,result.stderr||result.stdout);
  assert.match(result.stdout,/PASS stage rename failure restored previous index/);
});

test('Config Factory health verifies indexed OpenVPN files and SHA256, not only index row count',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Config-Factory.ps1'),'utf8');
  assert.match(linux,/def indexed_usable_profiles\(active, idx\):/);
  assert.match(linux,/hashlib\.sha256\(file\.read_bytes\(\)\)/);
  assert.match(linux,/"integrityInvalid":len\(idx\)-len\(usable\)/);
  assert.match(linux,/"healthy":len\(usable\)>=min_pool/);
  assert.match(windows,/function Test-UsableIndexedProfile\(\$Item\)/);
  assert.match(windows,/Get-FileHash -LiteralPath \$file -Algorithm SHA256/);
  assert.match(windows,/integrityInvalid=\(\$items\.Count-\$usable\.Count\)/);
  assert.match(windows,/healthy=\(\$usable\.Count -ge \$MinPool\)/);
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const fixture=[
    'import importlib.util,sys,tempfile,json,hashlib',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("factory",sys.argv[1])',
    'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'with tempfile.TemporaryDirectory(prefix="oig-verified-health-") as d:',
    '  base=Path(d)/"common";active=base/"runtime/udp-cache";ev=base/"evidence";active.mkdir(parents=True);ev.mkdir()',
    '  records=[]',
    '  for i in range(1,7):',
    '    name="profile%d.ovpn"%i',
    '    records.append({"Rank":i,"Host":"relay%d"%i,"IP":"203.0.113.%d"%i,"Port":1194,"Protocol":"udp","Country":"JP","Profile":"runtime/udp-cache/"+name,"SHA256":hashlib.sha256(("profile %d"%i).encode()).hexdigest()})',
    '  (active/"index.json").write_text(json.dumps(records))',
    '  report=m.status(base,ev)',
    '  assert report["pool"]==6 and report["usable"]==0 and report["integrityInvalid"]==6 and not report["healthy"],report',
    '  for i in range(1,7):(active/("profile%d.ovpn"%i)).write_bytes(("profile %d"%i).encode())',
    '  report=m.status(base,ev)',
    '  assert report["usable"]==6 and report["healthy"] and report["integrityInvalid"]==0,report',
    '  (active/"profile6.ovpn").write_bytes(b"tampered")',
    '  report=m.status(base,ev)',
    '  assert report["usable"]==5 and report["integrityInvalid"]==1 and not report["healthy"],report',
    '  records[5]["Profile"]="runtime/udp-cache/../outside.ovpn"',
    '  (active/"index.json").write_text(json.dumps(records))',
    '  report=m.status(base,ev)',
    '  assert report["usable"]==5 and not report["healthy"],report',
    'print("PASS missing / valid / tampered / traversal indexed profile cases")'
  ].join('\n');
  const result=cp.spawnSync('python3',['-c',fixture,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:15000});
  assert.equal(result.status,0,result.stderr||result.stdout);
  assert.match(result.stdout,/PASS missing \/ valid \/ tampered \/ traversal/);
});

test('Linux profile dedupe does not let an incomplete candidate reserve a valid endpoint',()=>{
  if(process.platform!=='linux') return;
  const cp=require('node:child_process');
  const fixture=[
    'import base64,importlib.util,sys,tempfile',
    'from pathlib import Path',
    'spec=importlib.util.spec_from_file_location("factory",sys.argv[1])',
    'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
    'def row(dev):',
    '  profile="client\\ndev "+dev+"\\nproto udp\\nremote 203.0.113.5 1194\\n<ca>\\na\\n</ca>\\n<cert>\\nb\\n</cert>\\n<key>\\nc\\n</key>\\n"',
    '  parts=["example","203.0.113.5","10","10","1000","Japan","JP","5","0","0","0","0","0","0",base64.b64encode(profile.encode()).decode()]',
    '  return ",".join(parts)',
    'with tempfile.TemporaryDirectory(prefix="oig-endpoint-dedupe-") as td:',
    '  cache=Path(td)/"provider.csv"',
    '  cache.write_text(row("tap")+"\\n"+row("tun")+"\\n"+row("tun")+"\\n")',
    '  selected=m.parse_candidates(cache)',
    '  assert len(selected)==1 and "dev tun" in selected[0]["Text"],selected',
    'print("PASS invalid prior duplicate cannot shadow valid endpoint")'
  ].join('\n');
  const result=cp.spawnSync('python3',['-c',fixture,path.join(root,'backend/linux/config_factory.py')],{encoding:'utf8',timeout:12000});
  assert.equal(result.status,0,result.stderr||result.stdout);
  assert.match(result.stdout,/PASS invalid prior duplicate/);
});

test('LastKnownGood deduplicates the final normalized server-role profile hash',()=>{
  const cp=require('node:child_process'),os=require('node:os'),crypto=require('node:crypto');
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-role-dedup-'));
  const profile=ip=>['client','dev tun','proto udp','remote '+ip+' 1194',
    'cipher AES-128-CBC','auth SHA1','<ca>','a','</ca>',
    '<cert>','b','</cert>','<key>','c','</key>',''].join('\n');
  const row=(host,ip)=>[host,ip,'100','12','100000','Japan','JP','4',
    '0','0','0','0','0','0',Buffer.from(profile(ip)).toString('base64')].join(',');
  const csv=[row('new-0','203.0.113.80'),row('new-1','203.0.113.81'),
    row('new-2','203.0.113.82')].join('\n')+'\n';
  const setup=base=>{
    const evidence=path.join(base,'evidence'),active=path.join(base,'runtime','udp-cache');
    fs.mkdirSync(evidence,{recursive:true});fs.mkdirSync(active,{recursive:true});
    fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),csv);
    const old=[['prior-duplicate','203.0.113.80',0],['prior-distinct','203.0.113.83',0],
      ['prior-normalized-duplicate','203.0.113.83',1],['prior-next','203.0.113.84',0]].map(([Host,IP,extra],i)=>{
      const value=profile(IP)+'\n'.repeat(extra),name='prior-'+i+'.ovpn';
      fs.writeFileSync(path.join(active,name),value);
      return {Rank:i+1,Host,IP,Port:1194,Protocol:'udp',Country:'JP',
        Profile:'runtime/udp-cache/'+name,SHA256:crypto.createHash('sha256').update(value).digest('hex')};
    });
    fs.writeFileSync(path.join(active,'index.json'),JSON.stringify(old));
    return active;
  };
  try{
    if(process.platform==='linux'){
      const active=setup(temp);
      const script=[
        'import importlib.util,sys,hashlib,json,re',
        'from pathlib import Path',
        'spec=importlib.util.spec_from_file_location("m",sys.argv[1])',
        'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
        'base=Path(sys.argv[2]);meta,kept=m.promote(base,base/"evidence",count=3,preserve_count=2)',
        'assert kept==2 and len(meta)==5,(kept,meta)',
        'assert [r["Host"] for r in meta]==["new-0","new-1","new-2","prior-distinct","prior-next"],meta',
        'assert len(set(r["SHA256"] for r in meta))==5,meta',
        'for r in meta:',
        '  contents=(base/"runtime"/"udp-cache"/Path(r["Profile"]).name).read_bytes()',
        '  assert hashlib.sha256(contents).hexdigest()==r["SHA256"]',
        '  assert len(re.findall(r"(?mi)^remote-cert-tls\\s+server\\s*$",contents.decode()))==1',
        'print("PASS normalized SHA dedup + LKG quota")'
      ].join('\n');
      const result=cp.spawnSync('python3',['-c',script,path.join(root,'backend/linux/config_factory.py'),temp],{encoding:'utf8',timeout:12000});
      assert.equal(result.status,0,result.stderr||result.stdout);
    }else if(process.platform==='win32'){
      const base=path.join(temp,'windows'),active=setup(base);
      const scripts=path.join(base,'scripts');fs.mkdirSync(scripts,{recursive:true});
      for(const file of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
        fs.copyFileSync(path.join(root,'backend/windows/scripts',file),path.join(scripts,file));
      }
      const result=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',
        path.join(scripts,'Build-VpnGateUdpCache.ps1'),'-Count','3','-PerCountry','3',
        '-PreserveOld','2'],{encoding:'utf8',timeout:20000});
      assert.equal(result.status,0,result.stderr||result.stdout);
      const index=JSON.parse(fs.readFileSync(path.join(active,'index.json'),'utf8'));
      assert.deepEqual(index.map(x=>x.Host),['new-0','new-1','new-2','prior-distinct','prior-next']);
      assert.equal(new Set(index.map(x=>x.SHA256)).size,5);
      for(const item of index){
        const body=fs.readFileSync(path.join(active,path.basename(item.Profile)));
        assert.equal(crypto.createHash('sha256').update(body).digest('hex'),item.SHA256);
        assert.equal((body.toString('utf8').match(/^remote-cert-tls\s+server\s*$/gmi)||[]).length,1);
      }
    }
  }finally{fs.rmSync(temp,{recursive:true,force:true});}
});

test('OpenVPN staged profiles enforce server certificate role including retained cache',()=>{
  const cp=require('node:child_process'),os=require('node:os'),crypto=require('node:crypto');
  const base=fs.mkdtempSync(path.join(os.tmpdir(),'oig-server-role-'));
  const build=(ip,role='')=>[
    'client','dev tun','proto udp','remote '+ip+' 1194',
    'cipher AES-128-CBC','auth SHA1',role,
    '<ca>','a','</ca>','<cert>','b','</cert>','<key>','c','</key>',''
  ].filter(Boolean).join('\n');
  const row=(name,ip,role='')=>[
    name,ip,'100','12','100000','Japan','JP','4',
    '0','0','0','0','0','0',Buffer.from(build(ip,role)).toString('base64')
  ].join(',');
  const csv=[
    row('bad-role','203.0.113.40','remote-cert-tls client'),
    row('duplicate-role','203.0.113.41','remote-cert-tls server\nremote-cert-tls server'),
    row('valid-0','203.0.113.50'),
    row('valid-1','203.0.113.51','remote-cert-tls server'),
    row('valid-2','203.0.113.52')
  ].join('\n')+'\n';
  try{
    const evidence=path.join(base,'evidence');
    const active=path.join(base,'runtime','udp-cache');
    fs.mkdirSync(evidence,{recursive:true});
    fs.mkdirSync(active,{recursive:true});
    fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),csv);
    const prior=build('203.0.113.80');
    fs.writeFileSync(path.join(active,'prior.ovpn'),prior);
    const priorHash=crypto.createHash('sha256').update(prior).digest('hex');
    fs.writeFileSync(path.join(active,'index.json'),JSON.stringify([{
      Rank:1,Host:'prior',IP:'203.0.113.80',Port:1194,Protocol:'udp',Country:'JP',
      CountryName:'Japan',Profile:'runtime/udp-cache/prior.ovpn',SHA256:priorHash
    }]));
    if(process.platform==='linux'){
      const snippet=[
        'import importlib.util,sys,json,hashlib,re',
        'from pathlib import Path',
        'mod=importlib.util.spec_from_file_location("f",sys.argv[1])',
        'f=importlib.util.module_from_spec(mod);mod.loader.exec_module(f)',
        'base=Path(sys.argv[2]);meta,kept=f.promote(base,base/"evidence",count=3,preserve_count=1)',
        'assert kept==1 and len(meta)==4,(kept,len(meta))',
        'assert sorted(x["Host"] for x in meta)==["prior","valid-0","valid-1","valid-2"]',
        'for item in meta:',
        '  target=base/"runtime"/"udp-cache"/Path(item["Profile"]).name',
        '  blob=target.read_bytes()',
        '  assert hashlib.sha256(blob).hexdigest()==item["SHA256"],item',
        '  text=blob.decode("utf8")',
        '  assert len(re.findall(r"(?mi)^remote-cert-tls\\s+server\\s*$",text))==1,item',
        '  assert f.profile_is_data_only(text),item',
        'print("PASS staged role and LKG digest")'
      ].join('\n');
      const result=cp.spawnSync('python3',['-c',snippet,path.join(root,'backend/linux/config_factory.py'),base],{encoding:'utf8',timeout:15000});
      assert.equal(result.status,0,result.stderr||result.stdout);
    }else if(process.platform==='win32'){
      const target=path.join(base,'windows');
      const scripts=path.join(target,'scripts'),wevidence=path.join(target,'evidence');
      const wactive=path.join(target,'runtime','udp-cache');
      for(const dir of [scripts,wevidence,wactive])fs.mkdirSync(dir,{recursive:true});
      for(const name of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
        fs.copyFileSync(path.join(root,'backend/windows/scripts',name),path.join(scripts,name));
      }
      fs.writeFileSync(path.join(wevidence,'vpngate-mirror-api.csv'),csv);
      fs.writeFileSync(path.join(wactive,'prior.ovpn'),prior);
      fs.writeFileSync(path.join(wactive,'index.json'),JSON.stringify([{
        Rank:1,Host:'prior',IP:'203.0.113.80',Port:1194,Protocol:'udp',Country:'JP',
        CountryName:'Japan',Profile:'runtime/udp-cache/prior.ovpn',SHA256:priorHash
      }]));
      const result=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',
        path.join(scripts,'Build-VpnGateUdpCache.ps1'),'-Count','3','-PerCountry','3','-PreserveOld','1'],{encoding:'utf8',timeout:20000});
      assert.equal(result.status,0,result.stderr||result.stdout);
      const idx=JSON.parse(fs.readFileSync(path.join(wactive,'index.json'),'utf8'));
      assert.deepEqual(idx.map(x=>x.Host).sort(),['prior','valid-0','valid-1','valid-2']);
      for(const item of idx){
        const blob=fs.readFileSync(path.join(wactive,path.basename(item.Profile)));
        assert.equal(crypto.createHash('sha256').update(blob).digest('hex'),item.SHA256);
        assert.equal((blob.toString('utf8').match(/^remote-cert-tls\s+server\s*$/gmi)||[]).length,1);
      }
    }
  }finally{fs.rmSync(base,{recursive:true,force:true});}
});

test('OpenVPN imported profiles cannot disable cipher or authentication',()=>{
  const sourcePy=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const sourceWin=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(sourcePy,/directive in \{"cipher", "auth", "data-ciphers", "data-ciphers-fallback"\}/);
  assert.match(sourceWin,/\$opt -in @\('cipher','auth','data-ciphers','data-ciphers-fallback'\)/);
  const cp=require('node:child_process'),os=require('node:os'),crypto=require('node:crypto');
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-crypto-guard-'));
  const bad=['cipher none','auth none','data-ciphers AES-128-GCM:none','data-ciphers-fallback NONE'];
  const profile=(ip,override='')=>[
    'client','dev tun','proto udp','remote '+ip+' 1194',
    'cipher AES-128-CBC','auth SHA1',override,
    '<ca>','a','</ca>','<cert>','b','</cert>','<key>','c','</key>',''
  ].filter(Boolean).join('\n');
  const row=(host,ip,override='')=>[host,ip,'100','12','100000','Japan','JP','4',
    '0','0','0','0','0','0',Buffer.from(profile(ip,override)).toString('base64')].join(',');
  const csv=[
    ...bad.map((directive,i)=>row('bad-'+i,'203.0.113.'+(40+i),directive)),
    row('good-0','203.0.113.60'),row('good-1','203.0.113.61'),
    row('good-2','203.0.113.62')
  ].join('\n')+'\n';
  try{
    if(process.platform==='linux'){
      const script=[
        'import importlib.util,sys,json,hashlib',
        'from pathlib import Path',
        'spec=importlib.util.spec_from_file_location("factory",sys.argv[1])',
        'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
        'base=Path(sys.argv[2]);rows=m.parse_candidates(base/"feed.csv",count=30,per_country=30)',
        'assert [r["Host"] for r in rows]==["good-0","good-1","good-2"],rows',
        'active=base/"active";stage=base/"stage";active.mkdir();stage.mkdir()',
        'old=[]',
        'for i,flag in enumerate(["cipher none","auth none",""]):',
        '  ip="203.0.113."+str(80+i)',
        '  p="client\\ndev tun\\nproto udp\\nremote "+ip+" 1194\\ncipher AES-128-CBC\\nauth SHA1\\n"+flag+"\\n<ca>\\na\\n</ca>\\n<cert>\\nb\\n</cert>\\n<key>\\nc\\n</key>\\n"',
        '  fname="prior-"+str(i)+".ovpn";(active/fname).write_text(p)',
        '  old.append({"Rank":i+1,"Host":"prior-"+str(i),"IP":ip,"Port":1194,"Protocol":"udp","Country":"JP","Profile":"runtime/udp-cache/"+fname,"SHA256":hashlib.sha256(p.encode()).hexdigest()})',
        '(active/"index.json").write_text(json.dumps(old))',
        'meta=[];n=m.preserve_old(active,stage,meta,{},4)',
        'assert n==1 and meta[0]["Host"]=="prior-2",(n,meta)',
        'print("PASS crypto disable rejected in new and retained profiles")'
      ].join('\n');
      fs.writeFileSync(path.join(temp,'feed.csv'),csv);
      const result=cp.spawnSync('python3',['-c',script,path.join(root,'backend/linux/config_factory.py'),temp],{encoding:'utf8',timeout:12000});
      assert.equal(result.status,0,result.stderr||result.stdout);
    }else if(process.platform==='win32'){
      const base=path.join(temp,'windows');
      const scripts=path.join(base,'scripts'),evidence=path.join(base,'evidence'),active=path.join(base,'runtime','udp-cache');
      for(const dir of [scripts,evidence,active]) fs.mkdirSync(dir,{recursive:true});
      for(const name of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
        fs.copyFileSync(path.join(root,'backend/windows/scripts',name),path.join(scripts,name));
      }
      fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),csv);
      const old=[];
      for(const [i,flag] of ['cipher none','auth none',''].entries()){
        const ip='203.0.113.'+(80+i),name='prior-'+i+'.ovpn',text=profile(ip,flag);
        fs.writeFileSync(path.join(active,name),text);
        old.push({Rank:i+1,Host:'prior-'+i,IP:ip,Port:1194,Protocol:'udp',Country:'JP',
          Profile:'runtime/udp-cache/'+name,SHA256:crypto.createHash('sha256').update(text).digest('hex')});
      }
      fs.writeFileSync(path.join(active,'index.json'),JSON.stringify(old));
      const result=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',path.join(scripts,'Build-VpnGateUdpCache.ps1'),
        '-Count','3','-PerCountry','3','-PreserveOld','4'],{encoding:'utf8',timeout:20000});
      assert.equal(result.status,0,result.stderr||result.stdout);
      const resultIndex=JSON.parse(fs.readFileSync(path.join(active,'index.json'),'utf8'));
      assert.deepEqual(resultIndex.filter(x=>x.Source==='VPNGate').map(x=>x.Host),['good-0','good-1','good-2']);
      assert.deepEqual(resultIndex.filter(x=>x.Source==='LastKnownGood').map(x=>x.Host),['prior-2']);
    }
  }finally{fs.rmSync(temp,{recursive:true,force:true});}
});

test('Public relay pool never imports local, private, link-local or reserved tunnel endpoints',()=>{
  const python=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(python,/def relay_ip_allowed\(value\):/);
  assert.match(windows,/function Test-AllowedRelayIp\(/);
  assert.match(python,/if not relay_ip_allowed\(ip\): continue/);
  assert.match(windows,/not\(Test-AllowedRelayIp \$remoteIp\)/);
  const cp=require('node:child_process');
  const os=require('node:os');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'oig-local-relay-block-'));
  const config=ip=>[
    'client','dev tun','proto udp','remote '+ip+' 1194',
    '<ca>','a','</ca>','<cert>','b','</cert>','<key>','c','</key>',''
  ].join('\n');
  const hash=t=>require('node:crypto').createHash('sha256').update(t).digest('hex');
  const row=(host,ip)=>[host,ip,'100','10','100000','Japan','JP','4',
    '0','0','0','0','0','0',Buffer.from(config(ip)).toString('base64')].join(',');
  const denied=['0.1.2.3','10.0.0.1','100.64.0.1','127.0.0.1','169.254.169.254',
    '172.16.0.1','192.0.0.2','192.168.0.1','198.18.0.1','224.0.0.1','255.255.255.255'];
  const allowed=['203.0.113.80','203.0.113.81','203.0.113.82','192.0.3.10'];
  const csv=[...denied.map((ip,i)=>row('blocked-'+i,ip)),
    ...allowed.map((ip,i)=>row('relay-'+i,ip))].join('\n')+'\n';
  try {
    if(process.platform==='linux'){
      const source=[
        'import importlib.util,sys,json,hashlib',
        'from pathlib import Path',
        'sp=importlib.util.spec_from_file_location("f",sys.argv[1])',
        'm=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)',
        'base=Path(sys.argv[2]);csv=base/"feed.csv"',
        'rows=m.parse_candidates(csv,count=30,per_country=30)',
        'assert [r["Host"] for r in rows]==["relay-0","relay-1","relay-2","relay-3"],rows',
        'stage=base/"stage";stage.mkdir();active=base/"active";active.mkdir()',
        'prior=[]',
        'for n,ip in enumerate(["127.0.0.1","203.0.113.83"]):',
        '  name="legacy-%d.ovpn"%n',
        '  profile="client\\ndev tun\\nproto udp\\nremote "+ip+" 1194\\n<ca>\\na\\n</ca>\\n<cert>\\nb\\n</cert>\\n<key>\\nc\\n</key>\\n"',
        '  (active/name).write_text(profile)',
        '  prior.append({"Rank":n+1,"Host":"prior-"+str(n),"IP":ip,"Port":1194,"Protocol":"udp","Country":"JP","Profile":"runtime/udp-cache/"+name,"SHA256":hashlib.sha256(profile.encode()).hexdigest()})',
        '  assert m.relay_ip_allowed(ip)==(n==1)',
        '(active/"index.json").write_text(json.dumps(prior))',
        'meta=[];count=m.preserve_old(active,stage,meta,{},4)',
        'assert count==1 and meta[0]["Host"]=="prior-1",(count,meta)',
        'print("PASS fresh and retained unsafe relay rejection")'
      ].join('\n');
      fs.writeFileSync(path.join(dir,'feed.csv'),csv);
      const r=cp.spawnSync('python3',['-c',source,path.join(root,'backend/linux/config_factory.py'),dir],{encoding:'utf8',timeout:12000});
      assert.equal(r.status,0,r.stderr||r.stdout);
      assert.match(r.stdout,/PASS fresh and retained unsafe relay rejection/);
    }else if(process.platform==='win32'){
      const base=path.join(dir,'windows');
      const scripts=path.join(base,'scripts'),evidence=path.join(base,'evidence');
      const active=path.join(base,'runtime','udp-cache');
      fs.mkdirSync(scripts,{recursive:true});
      fs.mkdirSync(evidence,{recursive:true});
      fs.mkdirSync(active,{recursive:true});
      for(const name of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
        fs.copyFileSync(path.join(root,'backend/windows/scripts',name),path.join(scripts,name));
      }
      fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),csv);
      const prior=[];
      for(const [i,ip] of ['127.0.0.1','203.0.113.83'].entries()){
        const name='legacy-'+i+'.ovpn',profile=config(ip);
        fs.writeFileSync(path.join(active,name),profile);
        prior.push({Rank:i+1,Host:'prior-'+i,IP:ip,Port:1194,Protocol:'udp',
          Country:'JP',Profile:'runtime/udp-cache/'+name,SHA256:hash(profile)});
      }
      fs.writeFileSync(path.join(active,'index.json'),JSON.stringify(prior));
      const r=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',path.join(scripts,'Build-VpnGateUdpCache.ps1'),
        '-Count','4','-PerCountry','4','-PreserveOld','4'],{encoding:'utf8',timeout:20000});
      assert.equal(r.status,0,r.stderr||r.stdout);
      const index=JSON.parse(fs.readFileSync(path.join(active,'index.json'),'utf8'));
      assert.deepEqual(index.filter(x=>x.Source==='VPNGate').map(x=>x.Host),['relay-0','relay-1','relay-2','relay-3']);
      assert.deepEqual(index.filter(x=>x.Source==='LastKnownGood').map(x=>x.Host),['prior-1']);
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('VPN Gate CSV IP must match the OpenVPN remote before endpoint deduplication',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(linux,/ipaddress\.IPv4Address\(p\[1\]\.strip\(\)\) != ipaddress\.IPv4Address\(ip\)/);
  assert.match(windows,/\$csvIp\.Equals\(\$remoteIp\)/);
  const parseScope=linux.slice(linux.indexOf('def parse_candidates('),linux.indexOf('def preserve_old('));
  assert.ok(parseScope.indexOf('ipaddress.IPv4Address(p[1].strip()) !=')<parseScope.indexOf('seen.add(key)'));
  assert.ok(windows.indexOf('$csvIp.Equals($remoteIp)')<windows.indexOf('$seen[$key]=$true'));
  const cp=require('node:child_process');
  const os=require('node:os');
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'oig-csv-remote-consistency-'));
  const data=ip=>[
    'client','dev tun','proto udp','remote '+ip+' 1194',
    '<ca>','a','</ca>','<cert>','b','</cert>','<key>','c','</key>',''
  ].join('\n');
  const row=(name,listed,remote)=>[
    name,listed,'100','12','100000','Japan','JP','4',
    '0','0','0','0','0','0',Buffer.from(data(remote)).toString('base64')
  ].join(',');
  try{
    const csv=[
      row('spoofed','203.0.113.50','203.0.113.51'),
      row('invalid-ip','not-an-ip','203.0.113.51'),
      row('valid-51','203.0.113.51','203.0.113.51'),
      row('valid-52','203.0.113.52','203.0.113.52'),
      row('valid-53','203.0.113.53','203.0.113.53')
    ].join('\n')+'\n';
    if(process.platform==='linux'){
      const csvPath=path.join(dir,'vpngate.csv');
      fs.writeFileSync(csvPath,csv);
      const script=[
        'import importlib.util,sys',
        'from pathlib import Path',
        'spec=importlib.util.spec_from_file_location("factory",sys.argv[1])',
        'module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)',
        'rows=module.parse_candidates(Path(sys.argv[2]),count=3,per_country=3)',
        'names=[r["Host"] for r in rows]',
        'assert names==["valid-51","valid-52","valid-53"],names',
        'print("PASS csv/remote IP identity and same-endpoint recovery")'
      ].join('\n');
      const result=cp.spawnSync('python3',['-c',script,path.join(root,'backend/linux/config_factory.py'),csvPath],{encoding:'utf8',timeout:12000});
      assert.equal(result.status,0,result.stderr||result.stdout);
      assert.match(result.stdout,/PASS csv\/remote IP identity/);
    }else if(process.platform==='win32'){
      const project=path.join(dir,'windows');
      const scripts=path.join(project,'scripts');
      const evidence=path.join(project,'evidence');
      fs.mkdirSync(scripts,{recursive:true});
      fs.mkdirSync(evidence,{recursive:true});
      for(const name of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
        fs.copyFileSync(path.join(root,'backend/windows/scripts',name),path.join(scripts,name));
      }
      fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),csv);
      const result=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',
        path.join(scripts,'Build-VpnGateUdpCache.ps1'),'-Count','3',
        '-PerCountry','3','-PreserveOld','0'],{encoding:'utf8',timeout:20000});
      assert.equal(result.status,0,result.stderr||result.stdout);
      const profiles=JSON.parse(fs.readFileSync(path.join(project,'runtime','udp-cache','index.json'),'utf8'));
      assert.deepEqual(profiles.map(x=>x.Host),['valid-51','valid-52','valid-53']);
    }
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
});

test('Windows malformed VPN Gate metrics cannot abort or poison a valid relay',()=>{
  const ps=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(ps,/\[long\]::TryParse/);
  assert.match(ps,/\[int\]::TryParse/);
  assert.ok(ps.indexOf('TryParse(([string]$p[7])') < ps.indexOf('$seen[$key]=$true'));
  if(process.platform!=='win32') return;
  const cp=require('node:child_process');
  const os=require('node:os');
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-metric-row-'));
  try{
    const base=path.join(temp,'windows');
    const scripts=path.join(base,'scripts');
    const evidence=path.join(base,'evidence');
    fs.mkdirSync(scripts,{recursive:true});
    fs.mkdirSync(evidence,{recursive:true});
    for(const file of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
      fs.copyFileSync(path.join(root,'backend/windows/scripts',file),path.join(scripts,file));
    }
    const data=(ip)=>[
      'client','dev tun','proto udp','remote '+ip+' 1194',
      '<ca>','a','</ca>','<cert>','b','</cert>','<key>','c','</key>',''
    ].join('\n');
    const row=(name,n,score='100',speed='100000',sessions='4')=>{
      const ip='203.0.113.'+n;
      return [name,ip,score,'12',speed,'Japan','JP',sessions,
        '0','0','0','0','0','0',Buffer.from(data(ip)).toString('base64')].join(',');
    };
    const rows=[
      row('bad-score',20,'invalid'),
      row('bad-speed',20,'100','overflow'),
      row('bad-sessions',20,'100','100000','invalid'),
      row('good-20',20),row('good-21',21),row('good-22',22)
    ];
    fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),rows.join('\n')+'\n');
    const exec=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',
      path.join(scripts,'Build-VpnGateUdpCache.ps1'),'-Count','3','-PerCountry','3',
      '-PreserveOld','0'],{encoding:'utf8',timeout:20000});
    assert.equal(exec.status,0,exec.stderr||exec.stdout);
    const index=JSON.parse(fs.readFileSync(path.join(base,'runtime','udp-cache','index.json'),'utf8'));
    assert.deepEqual(index.map(x=>x.Host),['good-20','good-21','good-22']);
  }finally{fs.rmSync(temp,{force:true,recursive:true});}
});

test('LKG restore accepts only bounded local hash-verified profiles, never outside paths or symlinks',()=>{
  const cp=require('node:child_process');
  const os=require('node:os');
  const base=fs.mkdtempSync(path.join(os.tmpdir(),'oig-lkg-containment-'));
  const active=path.join(base,'windows','runtime','udp-cache');
  const profile=(ip,proto='udp')=>[
    'client','dev tun','proto '+proto,'remote '+ip+' 1194',
    '<ca>','a','</ca>','<cert>','b','</cert>','<key>','c','</key>',''
  ].join('\n');
  const hash=value=>require('node:crypto').createHash('sha256').update(value).digest('hex');
  try{
    fs.mkdirSync(active,{recursive:true});
    const outside=path.join(base,'outside.ovpn');
    const outsideData=profile('203.0.113.77','tcp');
    const localData=profile('203.0.113.88');
    fs.writeFileSync(outside,outsideData);
    fs.writeFileSync(path.join(active,'local.ovpn'),localData);
    const prior=[
      {Rank:1,Profile:outside,SHA256:hash(outsideData),Country:'JP',Host:'outside',IP:'203.0.113.77',Port:1194,Protocol:'tcp',Score:100,Ping:'20',Speed:20,Sessions:0},
      {Rank:3,Profile:'runtime/udp-cache/local.ovpn',SHA256:hash(localData),Country:'JP',Host:'local',IP:'203.0.113.88',Port:1194,Protocol:'udp',Score:100,Ping:'20',Speed:20,Sessions:0}
    ];
    if(process.platform==='linux'){
      fs.symlinkSync(outside,path.join(active,'alias.ovpn'));
      prior.splice(1,0,{...prior[0],Rank:2,Profile:'runtime/udp-cache/alias.ovpn',Host:'alias'});
    }
    fs.writeFileSync(path.join(active,'index.json'),JSON.stringify(prior));
    if(process.platform==='linux'){
      const source=[
        'import importlib.util,sys,json',
        'from pathlib import Path',
        'spec=importlib.util.spec_from_file_location("oig_factory",sys.argv[1])',
        'm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)',
        'active=Path(sys.argv[2]);stage=Path(sys.argv[3]);stage.mkdir()',
        'meta=[]',
        'kept=m.preserve_old(active,stage,meta,{},4)',
        'assert kept==1 and len(meta)==1 and meta[0]["Host"]=="local",(kept,meta)',
        'print("PASS LKG local-only")'
      ].join('\n');
      const res=cp.spawnSync('python3',['-c',source,path.join(root,'backend/linux/config_factory.py'),active,path.join(base,'staged')],{encoding:'utf8',timeout:15000});
      assert.equal(res.status,0,res.stderr||res.stdout);
      assert.match(res.stdout,/PASS LKG local-only/);
    }else if(process.platform==='win32'){
      const scripts=path.join(base,'windows','scripts');
      const evidence=path.join(base,'windows','evidence');
      fs.mkdirSync(scripts,{recursive:true});
      fs.mkdirSync(evidence,{recursive:true});
      for(const file of ['Build-VpnGateUdpCache.ps1','Config-Factory.ps1']){
        fs.copyFileSync(path.join(root,'backend/windows/scripts',file),path.join(scripts,file));
      }
      const row=n=>{
        const ip='203.0.113.'+n;
        return ['host'+n,ip,'100','20','200000','Japan','JP','5','0','0','0','0','0','0',Buffer.from(profile(ip)).toString('base64')].join(',');
      };
      fs.writeFileSync(path.join(evidence,'vpngate-mirror-api.csv'),[20,21,22].map(row).join('\n')+'\n');
      const res=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',path.join(scripts,'Build-VpnGateUdpCache.ps1'),'-Count','3','-PerCountry','3','-PreserveOld','4'],{encoding:'utf8',timeout:20000});
      assert.equal(res.status,0,res.stderr||res.stdout);
      const idx=JSON.parse(fs.readFileSync(path.join(active,'index.json'),'utf8'));
      const retained=idx.filter(x=>x.Source==='LastKnownGood');
      assert.deepEqual(retained.map(x=>x.Host),['local']);
      assert.equal(idx.filter(x=>x.Source==='VPNGate').length,3);
    }
  }finally{
    fs.rmSync(base,{recursive:true,force:true});
  }
});

test('Linux backend implements required actions',()=>{
  const sh=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  for(const action of ['connect','disconnect','refresh','ensure','auto-install','auto-remove','console-status','console-enable','console-disable']) assert.ok(sh.includes(action));
});

test('package includes no-admin Windows installer and Linux update formats',()=>{
  const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
  assert.equal(pkg.build.win.target[0].target,'nsis');
  assert.equal(pkg.build.win.requestedExecutionLevel,'asInvoker');
  assert.equal(pkg.build.nsis.oneClick,true);
  assert.equal(pkg.build.nsis.perMachine,false);
  assert.equal(pkg.build.nsis.allowElevation,false);
  assert.equal(pkg.build.nsis.packElevateHelper,false);
  assert.ok(pkg.build.linux.target.includes('AppImage'));
  assert.ok(pkg.build.linux.target.includes('deb'));
});


test('Config Factory is wired through platform and renderer',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(backend,/factory-refresh/);
  assert.match(backend,/configPool/);
  assert.match(renderer,/poolValidated/);
  assert.match(renderer,/factoryRefresh/);
});


test('desktop app enforces single-instance tray UX',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/requestSingleInstanceLock\(\{ intent: launchIntent \}\)/);
  assert.match(main,/if \(gotSingleInstanceLock\) \{/);
  assert.match(main,/second-instance/);
  assert.match(main,/additionalData\?\.intent/);
  assert.match(main,/function showDashboard\(\)/);
  const guarded=main.slice(main.indexOf('if (gotSingleInstanceLock) {'));
  assert.match(guarded,/app\.whenReady\(\)/);
  assert.match(guarded,/startLinuxExitWatchdog\(\)/);
});


test('Windows backend is fully headless, self-healing, and independent from OpenVPN UI', { skip: !fs.existsSync(path.resolve(root,'backend/windows/scripts')) }, ()=>{
  const base=path.resolve(root,'backend/windows/scripts');
  const connect=fs.readFileSync(path.join(base,'Connect-OpenInternet.ps1'),'utf8');
  const disconnect=fs.readFileSync(path.join(base,'Disconnect-OpenInternet.ps1'),'utf8');
  const ensure=fs.readFileSync(path.join(base,'Ensure-OpenInternet.ps1'),'utf8');
  const factory=fs.readFileSync(path.join(base,'Config-Factory.ps1'),'utf8');
  const headless=fs.readFileSync(path.join(base,'Headless-Control.ps1'),'utf8');
  const bootstrap=fs.readFileSync(path.join(base,'Bootstrap-HeadlessConnector.ps1'),'utf8');
  const auto=fs.readFileSync(path.join(base,'Install-AutoRecovery.ps1'),'utf8');
  const production=connect+'\n'+disconnect+'\n'+ensure+'\n'+headless+'\n'+bootstrap;

  assert.match(headless,/ovpnconnector\.exe/i);
  assert.match(headless,/OVPNConnectorService/i);
  assert.match(headless,/ProgramData\\OpenInternetGateway/i);
  assert.match(headless,/function Stop-ServiceForConfig/);
  assert.match(headless,/Connector service must be stopped before configuration changes/);
  const ensureInstalled=headless.slice(headless.indexOf('function Ensure-ServiceInstalled'),headless.indexOf('function Schedule-ManualServiceMode'));
  assert.match(ensureInstalled,/Stop-ServiceForConfig[\s\S]*set-config','profile'/);
  assert.match(factory,/successes\.json/i);
  assert.match(factory,/quarantine\.json/i);
  assert.match(auto,/OpenInternetGateway-AutoRecovery/i);
  assert.match(headless,/Get-Process -Name 'OpenVPNConnect'/);
  assert.doesNotMatch(production,/--connect-shortcut|Start-Process\s+.*OpenVPNConnect\.exe/i);
  assert.doesNotMatch(production,/--connect-shortcut/i);
  assert.ok(fs.existsSync(path.join(base,'Headless-Control.ps1')));
  assert.ok(fs.existsSync(path.join(base,'Bootstrap-HeadlessConnector.ps1')));
});


test('Windows disconnect cancels queued reconnect requests before Auto-Recovery',()=>{
  const disconnect=fs.readFileSync(path.join(root,'backend/windows/scripts/Disconnect-OpenInternet.ps1'),'utf8');
  const desired=disconnect.indexOf("desired='off'");
  const exact=disconnect.indexOf('exact-profile.request');
  const known=disconnect.indexOf('headless-known-recover.request');
  const pool=disconnect.indexOf('headless-pool-probe.request');
  const probe=disconnect.indexOf('connector-probe.request');
  const run=disconnect.indexOf('schtasks.exe /Run');
  assert.ok(desired >= 0 && exact > desired && known > desired && pool > desired && probe > desired);
  assert.ok(run > exact && run > known && run > pool && run > probe);
});

test('desktop app owns a dynamic OIG tray and background startup',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/function renderTray/);
  assert.match(main,/OpenInternetGateway —/);
  assert.match(main,/setLoginItemSettings/);
  assert.match(main,/--background/);
  assert.match(main,/setInterval\(refreshTrayStatus/);
});


test('version is runtime-derived and quit disconnects the managed tunnel',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  assert.match(main,/version:\s*app\.getVersion\(\)/);
  assert.match(main,/backend\.action\('disconnect'\)/);
  assert.match(main,/SIGTERM/);
  assert.match(main,/watch-parent\.sh/);
  assert.match(main,/app-process\.lease/);
  assert.match(main,/detached:\s*true/);
  assert.match(backend,/version:\s*this\.version/);
  assert.doesNotMatch(html,/R2\.2\.1/);
  assert.match(html,/id="appVersion"/);
  assert.match(renderer,/state\.platform\.version/);
  assert.match(linux,/DESIRED=.*desired-state/);
  assert.match(linux,/set_desired off/);
  assert.match(linux,/DESIRED OFF/);
});

test('Windows upgrade shutdown preserves tunnel intent while explicit Quit disconnects',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/function requestProcessExitPreservingTunnel/);
  assert.match(main,/process\.platform === 'win32'\) requestProcessExitPreservingTunnel/);
  assert.match(main,/else requestQuit\(\)/);
  assert.match(main,/click: \(\) => requestQuit\(\)/);
  assert.match(main,/await disconnectBeforeQuit\(\)/);
  const explicitQuit=main.slice(main.indexOf('async function disconnectBeforeQuit'),main.indexOf('async function requestQuit'));
  assert.match(explicitQuit,/await backend\.action\('disconnect'\)/);
  assert.doesNotMatch(explicitQuit,/backend\.status\(\)/);
  const preserve=main.slice(main.indexOf('function requestProcessExitPreservingTunnel'),main.indexOf('if (gotSingleInstanceLock)'));
  assert.doesNotMatch(preserve,/backend\.action\('disconnect'\)/);
});

test('shutdown event emission tolerates destroyed renderer',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/!mainWindow\.isDestroyed\(\)/);
  assert.match(main,/!mainWindow\.webContents\.isDestroyed\(\)/);
});

test('Linux close-to-dock and desktop Quit lifecycle are explicit',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const afterInstall=fs.readFileSync(path.join(root,'build/linux-after-install.sh'),'utf8');
  assert.match(main,/win\.on\('close'/);
  assert.match(main,/win\.hide\(\)/);
  assert.match(main,/argv\.includes\('--quit'\)/);
  assert.match(main,/quitRequestedAtLaunch/);
  assert.doesNotMatch(main,/process\.platform === 'linux'\) requestQuit/);
  assert.match(afterInstall,/Actions=Quit/);
  assert.match(afterInstall,/Desktop Action Quit/);
  assert.match(afterInstall,/--quit/);
  assert.match(backend,/OpenInternetGateway\.desktop/);
  assert.match(backend,/Desktop Action Quit/);
  assert.match(backend,/copyFileSync\(systemDesktop, userDesktop\)/);
});

test('tray app survives last window destruction until explicit Quit',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  assert.match(main,/app\.on\('window-all-closed', \(\) => \{\}\)/);
  assert.match(main,/win\.on\('closed'/);
  assert.match(main,/if \(mainWindow === win\) mainWindow = null/);
  assert.match(main,/function isLiveWindow/);
});

test('Linux independent exit watchdog enforces disconnect safely',()=>{
  const watchdog=fs.readFileSync(path.join(root,'backend/linux/watch-parent.sh'),'utf8');
  assert.match(watchdog,/\/proc\/\$pid\/stat/);
  assert.match(watchdog,/app-process\.lease/);
  assert.match(watchdog,/replacement-active/);
  assert.match(watchdog,/oig-linux\.sh" disconnect/);
});

test('multi-country config factories retain country metadata and no JP-only gate',()=>{
  const linuxFactory=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  const linuxBackend=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const winFactory=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  const winControl=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const winStatus=fs.readFileSync(path.join(root,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const platform=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(linuxFactory,/COUNTRY_PRIORITY/);
  assert.match(linuxFactory,/CountryName/);
  assert.doesNotMatch(linuxFactory,/p\[6\] != "JP"/);
  assert.match(linuxBackend,/OIG-VPN-LIVE/);
  assert.match(winFactory,/PerCountry=6/);
  assert.match(winFactory,/CountryName/);
  assert.doesNotMatch(winFactory,/\$p\[6\] -ne 'JP'/);
  assert.match(winControl,/ExpectedCountry/);
  assert.doesNotMatch(winControl,/\$loc -eq 'JP'/);
  assert.doesNotMatch(winStatus,/\$loc -eq 'JP'/);
  assert.match(winStatus,/\$loc -ne 'IR'/);
  assert.match(winStatus,/Get-Service OVPNConnectorService/);
  assert.match(winStatus,/\$svc\.Status -eq 'Running'/);
  assert.match(platform,/\$loc -ne 'IR'/);
});

test('Linux status tolerates a transient geo probe failure only for a real managed tunnel',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const statusBlock=linux.slice(linux.indexOf('json_status()'),linux.indexOf('\nhealthy()'));
  assert.match(statusBlock,/managed_active=false/);
  assert.match(statusBlock,/connection show --active/);
  assert.match(statusBlock,/\$1==n && \$2=="vpn"/);
  assert.doesNotMatch(statusBlock,/\$3 ~ \/\^\(tun\|tap\)\//);
  assert.match(statusBlock,/probe_degraded=false/);
  assert.match(statusBlock,/\[\[ -z "\$loc" && "\$managed_active" == true && "\$routes" -ge 2/);
  assert.match(statusBlock,/healthProbeDegraded/);
  assert.match(statusBlock,/connected=\(r>=2 and managed=="true"/);
});

test('Windows status tolerates a transient geo probe failure only for a real managed tunnel',()=>{
  const winStatus=fs.readFileSync(path.join(root,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const platform=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const winBlock=platform.slice(platform.indexOf("if (action === 'status')"),platform.indexOf('const mapped = map[action]'));
  assert.match(winStatus,/\$managedActive=\(\$svc -and \$svc\.Status -eq 'Running'\)/);
  assert.match(winStatus,/\$probeDegraded=\$false/);
  assert.match(winStatus,/if\(-not \$loc -and \$managedActive -and \$routes\.Count -ge 2/);
  assert.match(winStatus,/HealthProbeDegraded=\[bool\]\$probeDegraded/);
  assert.match(winBlock,/\$managedActive=\(\$svc -and \$svc\.Status -eq 'Running'\)/);
  assert.match(winBlock,/\$probeDegraded=\$false/);
  assert.match(winBlock,/healthProbeDegraded=\[bool\]\$probeDegraded/);
  assert.match(winBlock,/connected=\(\$desired -eq 'on' -and \$routes\.Count -ge 2 -and \$managedActive/);
});

test('Linux failed exact relay does not turn desired gateway intent off',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const failure=linux.slice(linux.indexOf('rm -f "$KEEP"',linux.indexOf('connect_gateway()')),linux.indexOf('\n}\n\ndisconnect_gateway()',linux.indexOf('connect_gateway()')));
  assert.match(failure,/Selected relay failed validation/);
  assert.doesNotMatch(failure,/set_desired off/);
});

test('Linux foreground actions wait for the operation lock while periodic Ensure yields safely',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const block=linux.slice(linux.indexOf('action="${1:-status}"'),linux.indexOf('case "$action" in'));
  assert.match(block,/if \[\[ "\$action" == "ensure" \]\]/);
  assert.match(block,/flock -n 9/);
  assert.match(block,/periodic recovery skipped/);
  assert.match(block,/flock -w 90 9/);
  assert.match(block,/exit 75/);
});

test('Linux connection watchdog is fully detached and reaps its sleeper on cancellation',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const block=linux.slice(linux.indexOf('start_watchdog()'),linux.indexOf('profile_lines()'));
  assert.match(block,/exec 9>&-/);
  assert.match(block,/sleeper=''/);
  assert.match(block,/trap '[^']*kill "\$sleeper"[^']*wait "\$sleeper"[^']*' TERM INT/);
  assert.match(block,/sleep 180 &/);
  assert.match(block,/wait "\$sleeper" \|\| exit 0/);
  assert.match(block,/<\/dev\/null >\/dev\/null 2>&1 &/);
});

test('Windows exact relay switch is atomic, bounded and SHA verified',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const connect=fs.readFileSync(path.join(root,'backend/windows/scripts/Connect-OpenInternet.ps1'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const block=backend.slice(backend.indexOf('async connectProfile'),backend.indexOf('async _directInternetPath'));
  assert.doesNotMatch(block,/this\._windows\('disconnect'\)[\s\S]*this\._windows\('connect'\)/);
  assert.match(block,/const request = path\.join\(this\.backendRoot, 'state', 'exact-profile\.request'\)/);
  assert.match(block,/try \{ fs\.unlinkSync\(request\); \} catch \{\}/);
  assert.doesNotMatch(block,/this\._writeJson\(request/);
  assert.match(block,/_windows\('connect', \['-ProfileSha', sha\]\)/);
  assert.match(block,/actualSha[\s\S]*actualSha !== wanted/);
  assert.match(block,/type: 'progress'[\s\S]*stage: 'switching'/);
  assert.match(connect,/\$expectedSha/);
  assert.match(connect,/\$idleUntil=\(Get-Date\)\.AddSeconds\(90\)/);
  assert.match(connect,/\$waitSeconds=\$\(if\(\$expectedSha\)\{150\}else\{150\}\)/);
  assert.match(connect,/Gateway intent remains on/);
  assert.match(connect,/CONNECTED EXACT/);
  assert.match(connect,/Selected relay failed validation\. Gateway intent remains on so the previous preferred relay can be restored/);
  assert.match(renderer,/payload\.type === 'progress'/);
  assert.match(block,/restorePrevious/);
  assert.match(block,/Previous working relay was restored/);
  assert.match(block,/const savePreferred = \(\) => this\._writeJson\(preferredPath/);
  assert.match(block,/if \(profile\.active\)[\s\S]*savePreferred\(\)/);
  assert.match(block,/neither exact rollback nor general recovery[\s\S]*savePreferred\(\);[\s\S]*return \{ ok: true/);
  assert.match(block,/catch \{[\s\S]*fs\.unlinkSync\(request\)[\s\S]*return false/);
  assert.match(renderer,/Connecting .* speed is measured only after that exact tunnel is validated/);
});

test('failed exact relay attempt preserves preferred metadata and clears stale request',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-exact-fail-'));
  const stateDir=path.join(tmp,'state');
  fs.mkdirSync(stateDir,{recursive:true});
  const previous={sha256:'a'.repeat(64),country:'TH',host:'working',at:'before'};
  const target={sha256:'b'.repeat(64),country:'HK',host:'dead',ip:'198.51.100.7',active:false,quarantined:false};
  fs.writeFileSync(path.join(stateDir,'preferred-profile.json'),JSON.stringify(previous));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='win32';
  backend.backendRoot=tmp;
  backend.profiles=async()=>({profiles:[{...previous,active:true,quarantined:false},target]});
  backend._windows=async()=>{throw new Error('SIMULATED_EXACT_FAIL')};
  await assert.rejects(backend.connectProfile(target.sha256),/neither exact rollback nor general recovery could restore protection/i);
  const after=JSON.parse(fs.readFileSync(path.join(stateDir,'preferred-profile.json'),'utf8'));
  assert.equal(after.sha256,previous.sha256);
  assert.equal(fs.existsSync(path.join(stateDir,'exact-profile.request')),false);
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('Windows foreground exact connect owns its request and preserves gateway intent on failure',()=>{
  const connect=fs.readFileSync(path.join(root,'backend/windows/scripts/Connect-OpenInternet.ps1'),'utf8');
  const main=fs.readFileSync(path.join(root,'backend/windows/OpenInternetGateway.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  assert.match(connect,/param\(\[string\]\$ProfileSha=''/);
  assert.match(connect,/Remove-Item -LiteralPath \$exact[\s\S]*\$idleUntil=\(Get-Date\)\.AddSeconds\(90\)/);
  assert.match(connect,/requestId=\$requestId/);
  assert.match(connect,/State -ne 'Running'[\s\S]*Selected relay failed validation\. Gateway intent remains on/);
  assert.match(main,/\[string\]\$ProfileSha=''/);
  assert.match(main,/Connect-OpenInternet\.ps1" -ProfileSha \$ProfileSha/);
  assert.match(backend,/async _windows\(action, extraArgs = \[\]\)/);
  assert.match(backend,/_windows\('connect', \['-ProfileSha', sha\]\)/);
  const failure=headless.slice(headless.indexOf('if(-not $connected)'),headless.indexOf('& (Join-Path $PSScriptRoot',headless.indexOf('if(-not $connected)')));
  assert.doesNotMatch(failure,/Save-Desired 'off'/);
  assert.doesNotMatch(failure,/Stop-Connector/);
});

test('selected relay connection is exact rather than fallback',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(linux,/connect-profile\)/);
  assert.match(linux,/connect_gateway "\$2"/);
  assert.match(linux,/profile_lines "\$exact_sha"/);
  assert.match(linux,/set_desired off/);
  assert.match(windows,/\$ProfileSha/);
  const exactFailure=windows.slice(windows.indexOf('if(-not $connected)'),windows.indexOf('& (Join-Path $PSScriptRoot',windows.indexOf('if(-not $connected)')));
  assert.doesNotMatch(exactFailure,/Save-Desired 'off'/);
  assert.match(windows,/Get-Candidates \$ProfileSha/);
  assert.match(ensure,/exact-profile\.request/);
  assert.match(ensure,/-ProfileSha \$sha/);
  assert.match(backend,/exact-profile\.request/);
  assert.match(backend,/_linux\('connect-profile', \[sha\]\)/);
});

test('Linux exact relay selection preserves the visible pool and rejects missing relay before VPN intent changes',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('connect_gateway() {');
  const end=linux.indexOf('\nteardown_gateway()',start);
  const gateway=linux.slice(start,end);
  assert.ok(start>=0 && end>start);
  assert.match(gateway,/if \[\[ -z "\$exact_sha" \]\]; then\s+python3 "\$FACTORY_PY" ensure --common "\$OIG_COMMON"/,
    'an exact selected relay must not disappear during factory ensure');
  const selectedStart=linux.indexOf('  connect-profile)');
  const selectedEnd=linux.indexOf('    ;;',selectedStart);
  const selected=linux.slice(selectedStart,selectedEnd);
  const inventory=selected.indexOf('candidate="$(profile_lines "$2" | head -n1 || true)"');
  assert.ok(inventory>=0 && inventory<selected.indexOf('if healthy; then') && inventory<selected.indexOf('set_desired on "connect-profile"'),
    'reject invalid exact SHA before preflight, desired-state or teardown');
  if(process.platform!=='linux') return;
  const os=require('node:os'),cp=require('node:child_process');
  const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-missing-exact-linux-'));
  try{
    fs.mkdirSync(path.join(temp,'state'),{recursive:true});
    fs.mkdirSync(path.join(temp,'common/runtime/udp-cache'),{recursive:true});
    fs.writeFileSync(path.join(temp,'state/desired-state'),'off\n');
    fs.writeFileSync(path.join(temp,'common/runtime/udp-cache/index.json'),'[]\n');
    fs.mkdirSync(path.join(temp,'bin'));
    for(const command of ['nmcli','curl','getent']){
      const stub=path.join(temp,'bin',command);
      fs.writeFileSync(stub,'#!/bin/sh\nprintf "CALLED '+command+'\\n" >> "$OIG_HOME/external-command-attempts"\nexit 87\n',{mode:0o700});
    }
    const res=cp.spawnSync('bash',[path.join(root,'backend/linux/oig-linux.sh'),'connect-profile','a'.repeat(64)],{
      env:{...process.env,OIG_HOME:temp,OIG_COMMON:path.join(temp,'common'),
        PATH:path.join(temp,'bin')+':'+process.env.PATH},
      timeout:15000,encoding:'utf8'
    });
    assert.equal(res.status,21,'expected missing-selection rejection: '+res.stderr);
    assert.match(res.stderr,/Selected relay is missing or quarantined/);
    assert.equal(fs.readFileSync(path.join(temp,'state/desired-state'),'utf8').trim(),'off');
    assert.equal(fs.existsSync(path.join(temp,'external-command-attempts')),false,
      'missing exact selection must not launch nmcli, curl or DNS probes');
  }finally{fs.rmSync(temp,{recursive:true,force:true});}
});

test('explicit Windows disconnect cancels queued recovery and exact requests before running recovery task',()=>{
  const disconnect=fs.readFileSync(path.join(root,'backend/windows/scripts/Disconnect-OpenInternet.ps1'),'utf8');
  assert.match(disconnect,/exact-profile\.request/);
  assert.match(disconnect,/headless-known-recover\.request/);
  assert.match(disconnect,/headless-pool-probe\.request/);
  assert.match(disconnect,/connector-probe\.request/);
  assert.match(disconnect,/Remove-Item -LiteralPath/);
  const off=disconnect.indexOf("desired='off'");
  const cleanup=disconnect.indexOf("exact-profile.request");
  const runTask=disconnect.indexOf("schtasks.exe /Run");
  assert.ok(off >= 0 && cleanup > off && runTask > cleanup);
});

test('disabled Windows Auto-Recovery task is reported unhealthy and self-reenabled by Repair',()=>{
  const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8');
  const status=fs.readFileSync(path.join(root,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(ensure,/Enable-ScheduledTask -TaskName \$taskName/);
  assert.match(ensure,/task is disabled and could not be re-enabled/);
  assert.match(status,/AutoRecovery=.*Disabled/);
  assert.match(backend,/autoRecoveryState=.*Disabled/);
  assert.match(renderer,/\['inactive','failed','missing','disabled'\]/);
});

test('Windows non-admin Ensure delegates to the elevated recovery task and startup reconciles desired-on state',()=>{
  const ensure=fs.readFileSync(path.join(root,'backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(ensure,/if\(-not\(Test-Admin\)\)/);
  assert.match(ensure,/schtasks\.exe \/Run \/TN \$taskName/);
  assert.match(ensure,/ELEVATED ENSURE PASS/);
  assert.match(ensure,/AddSeconds\(150\)/);
  assert.match(renderer,/async function reconcileStartupTunnel/);
  assert.match(renderer,/s\.desiredState !== 'on'/);
  assert.match(renderer,/window\.gateway\.action\('ensure'\)/);
  assert.match(renderer,/const startupStatus = await refreshStatus\(false\)/);
  assert.match(renderer,/await reconcileStartupTunnel\(startupStatus\)/);
});

test('Linux direct ISP path rejects tunnel defaults and stale exact request files are removed',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const block=backend.slice(backend.indexOf("if (this.platform === 'linux')",backend.indexOf('async _directInternetPath')),backend.indexOf("throw new Error('Direct Internet test is supported",backend.indexOf('async _directInternetPath')));
  assert.match(block,/nmcli -t -f DEVICE,TYPE,STATE/);
  assert.match(block,/ethernet/);
  assert.match(block,/wifi/);
  assert.match(backend,/tun\|tap\|wg\|tailscale\|ppp\|zt\|vpn/);
  assert.match(backend,/fs\.unlinkSync\(path\.join\(stable, 'state', 'exact-profile\.request'\)\)/);
  const connect=backend.slice(backend.indexOf('async connectProfile'),backend.indexOf('async _directInternetPath'));
  assert.doesNotMatch(connect,/this\._writeJson\(request/);
  assert.match(connect,/fs\.unlinkSync\(request\)/);
});

test('native UI typography applies to form controls and select sizing is valid',()=>{
  const css=fs.readFileSync(path.join(root,'src/renderer/styles.css'),'utf8');
  assert.match(css,/body\{[^}]*font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif/);
  assert.match(css,/button,input,select,textarea\{font:inherit\}/);
  assert.match(css,/\.select-control\{[^}]*font-size:11px/);
  assert.doesNotMatch(css,/font:11px inherit/);
});

test('TCP socket responsiveness receives bounded ranking credit, not TLS validation credit',()=>{
  const cp=require('node:child_process');
  if(process.platform==='linux'){
    const program=[
      'from pathlib import Path',
      'import datetime as dt,math',
      'src=Path(__import__("sys").argv[1]).read_text()',
      'code=src.split("def quality(c):",1)[1].split("\\nif only_sha:",1)[0]',
      'def num(v,default=None):',
      '  try:',
      '    x=float(v);return x if math.isfinite(x) else default',
      '  except Exception:return default',
      'def fresh_iso(value,hours=48):',
      '  return value is not None',
      'ns={"bench":{},"success":{},"failures":{},"pref":"","num":num,"fresh_iso":fresh_iso,"math":math}',
      'exec("def quality(c):"+code,ns)',
      'item={"SHA256":"fixture","Protocol":"tcp","Port":443,"Ping":90,"Speed":0,"Score":0}',
      'base=ns["quality"](item)',
      'def delta(b):',
      '  ns["bench"]={"fixture":dict(b,fastAt="2026-10-19T00:00:00Z")}',
      '  return ns["quality"](item)-base',
      'tcp=delta({"fastPingMs":1,"tcpConnectMs":1,"fastMethod":"tcp-direct","fastReachable":True})',
      'icmp=delta({"fastPingMs":50,"icmpPingMs":50,"fastMethod":"icmp-direct","fastReachable":True})',
      'legacy=delta({"fastPingMs":50,"fastReachable":True})',
      'assert 0<tcp<=25,(tcp,base)',
      'assert icmp>100,(icmp,base)',
      'assert legacy>100,(legacy,base)',
      'print("PASS real Linux quality: TCP-only lower than ICMP and backward-compatible")'
    ].join('\n');
    const r=cp.spawnSync('python3',['-c',program,path.join(root,'backend/linux/oig-linux.sh')],{encoding:'utf8',timeout:6000});
    assert.equal(r.status,0,r.stderr||r.stdout);
  }else if(process.platform==='win32'){
    const script=[
      '$ErrorActionPreference="Stop"',
      '$text=[IO.File]::ReadAllText($env:OIG_RANKING_SOURCE)',
      '$start=$text.IndexOf("function Get-Number(")',
      '$end=$text.IndexOf("function Get-Candidates(",$start)',
      'if($start -lt 0 -or $end -lt 0){throw "Windows quality functions missing"}',
      'Invoke-Expression $text.Substring($start,$end-$start)',
      '$c=@{SHA256="fixture";Protocol="tcp";Port=443;Ping=90;Speed=0;Score=0}',
      '$base=Get-QualityScore $c "fixture" @{} @{} @{} ""',
      'function Delta($b){(Get-QualityScore $c "fixture" @{} @{} @{fixture=$b} "")-$base}',
      '$stamp=(Get-Date).ToString("o")',
      '$tcp=Delta @{fastAt=$stamp;fastPingMs=1;tcpConnectMs=1;fastMethod="tcp-direct";fastReachable=$true}',
      '$icmp=Delta @{fastAt=$stamp;fastPingMs=50;icmpPingMs=50;fastMethod="icmp-direct";fastReachable=$true}',
      '$legacy=Delta @{fastAt=$stamp;fastPingMs=50;fastReachable=$true}',
      'if($tcp -le 0 -or $tcp -gt 25 -or $icmp -le 100 -or $legacy -le 100){throw ("Quality mismatch: "+$tcp+","+ $icmp+","+$legacy)}',
      '"PASS native Windows quality: TCP-only reduced and legacy preserved"'
    ].join(';');
    const r=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
      encoding:'utf8',timeout:15000,
      env:{...process.env,OIG_RANKING_SOURCE:path.join(root,'backend/windows/scripts/Headless-Control.ps1')}
    });
    assert.equal(r.status,0,r.stderr||r.stdout);
  }
});

test('active tunnel summary never labels TCP-port latency as live ICMP ping',()=>{
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const summary=renderer.slice(renderer.indexOf('function renderBenchmarkSummary()'),renderer.indexOf('function connectionStatusRank('));
  assert.match(summary,/b\?\.fastMethod === 'icmp-direct'/);
  assert.match(summary,/liveIcmpMs == null/);
  assert.doesNotMatch(summary,/b\?\.icmpPingMs \?\? b\?\.fastPingMs/);
});

test('direct relay reachability separates ICMP from TCP-open without claiming VPN TLS',async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const backend=Object.create(Backend.prototype);
  const cache=[
    {SHA256:'a',IP:'203.0.113.11',Port:443,Protocol:'tcp'},
    {SHA256:'b',IP:'203.0.113.12',Port:443,Protocol:'tcp'},
    {SHA256:'c',IP:'203.0.113.13',Port:443,Protocol:'tcp'},
    {SHA256:'d',IP:'203.0.113.14',Port:1194,Protocol:'udp'}
  ];
  const mock={
    a:{fastPingMs:25,icmpPingMs:25,tcpConnectMs:null,fastReachable:true,fastAt:'2026-10-19T00:00:00Z',fastMethod:'icmp-direct'},
    b:{fastPingMs:40,icmpPingMs:null,tcpConnectMs:40,fastReachable:true,fastAt:'2026-10-19T00:00:00Z',fastMethod:'tcp-direct'},
    c:{fastPingMs:10,icmpPingMs:16,tcpConnectMs:10,fastReachable:true,fastAt:'2026-10-19T00:00:00Z',fastMethod:'tcp-direct'},
    d:{fastPingMs:null,icmpPingMs:null,tcpConnectMs:null,fastReachable:false,fastAt:'2026-10-19T00:00:00Z',fastMethod:'none'}
  };
  let updated;
  backend.backendRoot='/synthetic-no-network';
  backend._profileIndexPath=()=>'/synthetic-no-network/index.json';
  backend._directInternetPath=async()=>({interface:'eth0',localIP:'198.51.100.2',gateway:'198.51.100.1'});
  backend._readJson=(file,fallback)=>file.endsWith('index.json')?cache:(file.endsWith('connection-benchmarks.json')?{}:fallback);
  backend._quickProbeProfile=async(profile)=>mock[profile.sha256];
  backend._writeJson=(_file,value)=>{updated=value;};
  const result=await backend.benchmarkAllFast();
  assert.equal(result.tested,4);
  assert.equal(result.reachable,3);
  assert.equal(result.noReply,1);
  assert.equal(result.icmpReplies,2);
  assert.equal(result.tcpPortsOpen,2);
  assert.equal(Object.keys(updated).length,4);
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const windows=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  assert.match(renderer,/result\?\.tcpPortsOpen/);
  assert.match(renderer,/result\?\.icmpReplies/);
  assert.match(renderer,/TCP port .*TLS not verified/);
  assert.match(html,/Direct probe <span>/);
  assert.match(linux,/tcp_only_bonus/);
  assert.match(windows,/\$tcpOnlyBonus/);
});

test('all-relay probe covers the full pool and UI explains missing live replies',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const css=fs.readFileSync(path.join(root,'src/renderer/styles.css'),'utf8');
  const block=backend.slice(backend.indexOf('async benchmarkAllFast()'),backend.indexOf('async _httpsLatencyMs'));
  assert.match(block,/\.filter\(p => p\.sha256 && p\.ip\)/);
  assert.doesNotMatch(block,/!quarantine\[p\.sha256\]/);
  assert.match(block,/noReply: results\.filter/);
  assert.match(renderer,/wasFastTested \? 'No reply' : 'Not tested'/);
  assert.match(renderer,/result\?\.noReply/);
  assert.match(css,/font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif/);
  assert.match(css,/ui-monospace,"Cascadia Mono"/);
});

test('connection inventory exposes honest source-vs-live metrics and selectable profiles',()=>{
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const preload=fs.readFileSync(path.join(root,'src/preload/preload.js'),'utf8');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const win=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  assert.match(html,/data-page="connections"/);
  assert.match(html,/Source ping/);
  assert.match(html,/Actual download/);
  assert.match(html,/Actual upload/);
  assert.match(html,/Some relays block ICMP/);
  assert.match(renderer,/benchmark-active/);
  assert.match(renderer,/connect-profile/);
  assert.match(preload,/gateway:profiles/);
  assert.match(main,/gateway:profiles/);
  assert.match(backend,/async profiles\(liveStatusOverride = null\)/);
  assert.match(backend,/connection-benchmarks\.json/);
  assert.match(backend,/preferred-profile\.json/);
  assert.match(backend,/speed\.cloudflare\.com\/__down/);
  assert.match(backend,/speed\.cloudflare\.com\/__up/);
  assert.match(linux,/preferred-profile\.json/);
  assert.match(linux,/configuredCountry/);
  assert.match(win,/preferred-profile\.json/);
  assert.match(win,/Preferred/);
});

test('Linux packaged payload stays readable to desktop user',()=>{
  const afterPack=fs.readFileSync(path.join(root,'tools/afterPack.js'),'utf8');
  const afterInstall=fs.readFileSync(path.join(root,'build/linux-after-install.sh'),'utf8');
  assert.match(afterPack,/mode \| 0o044/);
  assert.match(afterPack,/normalizeLinuxPayload/);
  assert.match(afterInstall,/find "\$APPDIR" -type f -exec chmod a\+r/);
});

test('Connections stays synchronized with externally recovered active tunnel',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(backend,/const activeSha = base\?\.connected \? String\(current\.sha256/);
  assert.match(backend,/syntheticActive: true/);
  assert.match(backend,/!profiles\.some\(p => p\.active\)/);
  assert.match(renderer,/function syncConnectionInventoryToStatus/);
  assert.match(renderer,/String\(s\?\.activeSha/);
  assert.match(renderer,/if \(state\.page === 'connections'\)/);
  assert.match(renderer,/if \(connected && !matched\)[\s\S]*loadConnections\(\)/);
  assert.match(renderer,/syncConnectionInventoryToStatus\(s\)/);
});

test('connection inventory active state requires live tunnel',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(backend,/const liveStatus = liveStatusOverride \|\| await this\.status\(\)/);
  assert.match(backend,/active: !!liveStatus\.connected && !!sha && sha === activeSha/);
});

test('fast Test all probes relays in parallel and table sorting is explicit',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(backend,/async benchmarkAllFast\(\)/);
  assert.match(backend,/Math\.min\(16/);
  assert.match(backend,/benchmark-all-fast/);
  assert.match(backend,/fastPingMs/);
  assert.match(backend,/action === 'benchmark-all-fast'[\s\S]*type: 'busy'[\s\S]*return result/);
  assert.match(renderer,/connectionSortValue/);
  assert.match(renderer,/compareConnections/);
  assert.match(renderer,/benchmark-all-fast/);
  assert.match(renderer,/new Map\(\(result\?\.results \|\| \[\]\)/);
  assert.doesNotMatch(renderer.slice(renderer.indexOf('async function benchmarkCurrent'),renderer.indexOf('async function loadDiagnostics')),/loadConnections\(\)/);
  assert.match(renderer,/test\.textContent = 'Speed'/);
  assert.match(html,/>Test all relays</);
  for(const key of ['country','relay','protocol','sourcePing','livePing','download','upload','status']) assert.match(html,new RegExp('data-sort="'+key+'"'));
});

test('Linux direct ISP selects a connected physical NIC with a usable best-metric default route',()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const backend=new Backend({version:'2.5.19'});
  const wired={name:'enp1s0',type:'ethernet',state:'connected',hardware:true};
  const wifi={name:'wlp2s0',type:'wifi',state:'connected',hardware:true};
  const routes=[
    {dst:'default',gateway:'192.168.20.1',dev:'wlp2s0',metric:600},
    {dst:'default',gateway:'192.168.20.1',dev:'enp1s0',metric:100},
    {dst:'default',gateway:'100.64.0.1',dev:'tun0',metric:1}
  ];
  const route=backend._selectLinuxPhysicalDefaultRoute(routes,[wifi,wired]);
  assert.equal(route.interface,'enp1s0','lowest-metric physical default, not first enumerated connected NIC');
  assert.equal(route.gateway,'192.168.20.1');
  assert.equal(route.curlInterface,'if!enp1s0');
  assert.equal(backend._selectLinuxPhysicalDefaultRoute(routes.filter(r=>r.dev!=='enp1s0'),[wired,wifi]).interface,'wlp2s0',
    'fallback to secondary Wi-Fi default when first Ethernet has no default');
  const rogue={dst:'default',gateway:'192.168.20.1',dev:'evil;touch /tmp/oig',metric:0};
  assert.equal(backend._selectLinuxPhysicalDefaultRoute([rogue,...routes],[wired,wifi]).interface,'enp1s0',
    'never parse/shell interpolate device names from route results');
  for(const bad of [
    [{...wired,hardware:false},wifi],
    [{...wired,state:'disconnected'},wifi],
    [{...wired,type:'tun'},wifi]
  ]) assert.equal(backend._selectLinuxPhysicalDefaultRoute(routes,bad).interface,'wlp2s0');
  assert.throws(()=>backend._selectLinuxPhysicalDefaultRoute(routes,[{...wired,hardware:false}]),/physical|default|route/i);
  assert.throws(()=>backend._selectLinuxPhysicalDefaultRoute(
    [{dst:'default',dev:'tun0',gateway:'100.64.0.1',metric:0}],[wired,wifi]),/physical|default|route/i);
  assert.throws(()=>backend._selectLinuxPhysicalDefaultRoute(
    [{dst:'default',dev:'enp1s0',gateway:'not-an-ip',metric:0}],[wired]),/physical|default|route/i);
});
test('Windows direct ISP route selection rejects split-tunnel VPN, nonphysical default and spoofed source',()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const backend=new Backend({version:'2.5.19'});
  const physical={prefix:'0.0.0.0/0',alias:'Ethernet',index:18,
    gateway:'192.168.20.1',ip:'192.168.20.6',hardware:true,
    status:'Up',routeMetric:0,interfaceMetric:25};
  const selected=backend._selectWindowsPhysicalRoute([physical]);
  assert.equal(selected.interface,'Ethernet');
  assert.equal(selected.gateway,'192.168.20.1');
  assert.equal(selected.curlInterface,'host!192.168.20.6');
  const secondary={...physical,alias:'Wi-Fi',index:30,interfaceMetric:35};
  assert.equal(backend._selectWindowsPhysicalRoute([secondary,physical]).index,18,
    'effective route uses sum of route and interface metrics');
  const vpnSplit={...physical,prefix:'0.0.0.0/1',alias:'VPN',hardware:false};
  assert.throws(()=>backend._selectWindowsPhysicalRoute([physical,vpnSplit]),/VPN|split|tunnel/i);
  const vpn128={...vpnSplit,prefix:'128.0.0.0/1'};
  assert.throws(()=>backend._selectWindowsPhysicalRoute([physical,vpn128]),/VPN|split|tunnel/i);
  const virtualDefault={...physical,alias:'OIG tunnel',hardware:false,routeMetric:0,interfaceMetric:5};
  assert.throws(()=>backend._selectWindowsPhysicalRoute([physical,virtualDefault]),/physical|VPN|route/i,
    'do not switch to a secondary physical route when effective default is VPN');
  for(const route of [
    {...physical,hardware:false}, {...physical,status:'Disabled'},
    {...physical,alias:'OpenVPN renamable'},
    {...physical,ip:'0.0.0.0'}, {...physical,ip:'169.254.1.2'},
    {...physical,ip:'1000.1.1.1'}, {...physical,gateway:'0.0.0.0'},
    {...physical,index:0}
  ]) assert.throws(()=>backend._selectWindowsPhysicalRoute([route]),/physical|safe|VPN|route/i);
  assert.throws(()=>backend._selectWindowsPhysicalRoute([]),/route|physical/i);
});
test('direct ISP benchmark binds physical Internet and bypasses proxies',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(backend,/async _directInternetPath\(\)/);
  assert.match(backend,/--noproxy','\*','--interface/);
  assert.match(backend,/curlInterface: 'host!' \+ localIP/);
  assert.match(backend,/curlInterface: 'if!' \+ selected\.dev/);
  assert.match(backend,/async benchmarkDirectInternet\(\)/);
  assert.match(backend,/mode: 'direct-physical-internet'/);
  assert.match(backend,/downloadMbps/);
  assert.match(backend,/uploadMbps/);
  assert.match(backend,/bypassObserved/);
  assert.match(backend,/icmp-direct/);
  assert.match(backend,/tcp-direct/);
  assert.match(backend,/benchmark-direct-internet/);
  assert.match(renderer,/benchmarkDirectInternet/);
  assert.match(renderer,/renderDirectInternet/);
  assert.match(html,/id="benchmarkDirect"/);
  assert.match(html,/DIRECT INTERNET \/ ISP BASELINE/);
  assert.match(html,/id="directDownload"/);
  assert.match(html,/id="directUpload"/);
  assert.match(html,/Test all relays/);
});

test('GitHub updater checks latest release and verifies published SHA-256',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const preload=fs.readFileSync(path.join(root,'src/preload/preload.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
  assert.match(backend,/releases\/latest/);
  assert.match(backend,/SHA256SUMS/);
  assert.match(backend,/GitHub digest and SHA256SUMS disagree/);
  assert.match(backend,/Downloaded update SHA-256 does not match/);
  assert.match(backend,/async _curlText/);
  assert.match(backend,/--max-time','300/);
  assert.match(backend,/--retry','2/);
  assert.match(backend,/async updateInfo\(force = false\)/);
  assert.match(backend,/async downloadUpdate\(\)/);
  assert.match(main,/gateway:updateInfo/);
  assert.match(main,/gateway:installUpdate/);
  assert.match(main,/launchDownloadedUpdate/);
  assert.match(main,/requestProcessExitPreservingTunnel/);
  assert.doesNotMatch(main,/shell\.openPath\(result\.path\)/);
  assert.match(backend,/async launchDownloadedUpdate/);
  assert.match(backend,/installScope: 'current-user'/);
  assert.ok(backend.includes("Programs', 'open-internet-gateway', 'Open Internet Gateway.exe'"));
  assert.match(backend,/pwsh-helper/);
  assert.match(backend,/copyDir\(bundledPwshRoot, helperRuntime\)/);
  assert.match(backend,/spawn\(updatePwsh, launchArgs/);
  assert.match(backend,/resultFile \+ '\.started'/);
  assert.match(backend,/Windows update helper failed to start/);
  assert.doesNotMatch(backend,/spawn\('pwsh\.exe'/);
  assert.match(backend,/--appimage-extract/);
  assert.match(backend,/update-desktop-database/);
  assert.match(preload,/updateInfo/);
  assert.match(preload,/installUpdate/);
  assert.match(renderer,/renderUpdateInfo/);
  assert.match(renderer,/loadUpdates/);
  assert.match(html,/data-page="updates"/);
  assert.match(html,/GITHUB RELEASES/);
  assert.match(html,/Install verified update/);
});


test('Linux Chromium sandbox hardening is fail-safe and update-persistent',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const helper=fs.readFileSync(path.join(root,'backend/linux/harden_sandbox.py'),'utf8');
  assert.match(backend,/_hardenLinuxChromiumSandbox/);
  assert.match(backend,/linux-sandbox-hardening.json/);
  assert.match(backend,/path.join\(this.resourcesPath, 'backend', 'linux', 'harden_sandbox.py'\)/);
  assert.match(backend,/path.join\(this.appPath, 'backend', 'linux', 'harden_sandbox.py'\)/);
  assert.doesNotMatch(backend,/path.join\(this.backendRoot, 'linux', 'harden_sandbox.py'\)/);
  assert.match(backend,/path.isAbsolute\(candidate\) && fs.statSync\(candidate\).isFile\(\)/);
  assert.match(backend,/execFile\('python3', \['-I', helperScript, runtimeRoot\]/);
  assert.match(backend,/sandboxHardened/);
  assert.match(backend,/resources\/backend\/linux\/harden_sandbox\.py/);
  assert.match(main,/OIG_SANDBOX_RESTARTED/);
  assert.ok(main.includes('initialized?.sandboxHardening?.restartRequired'));
  assert.match(helper,/0o4755/);
  assert.match(helper,/hash-compatible root-owned setuid Chromium sandbox/);
  assert.match(helper,/OIG sandbox hardening: prefer a compatible root-owned setuid helper/);
  assert.match(helper,/CHROME_DEVEL_SANDBOX/);
  assert.match(helper,/readlink -f .*chrome-sandbox/);
  assert.match(helper,/LEGACY_REPLACEMENT/);
  assert.doesNotMatch(helper,/sysctl|apparmor_parser|sudo|pkexec/);
});

test('GitHub workflows use current hosted-runner actions and Node LTS',()=>{
  const build=fs.readFileSync(path.resolve(root,'..','.github','workflows','build.yml'),'utf8');
  const release=fs.readFileSync(path.resolve(root,'..','.github','workflows','release.yml'),'utf8');
  for(const wf of [build,release]) {
    assert.doesNotMatch(wf,/actions\/checkout@v4/);
    assert.doesNotMatch(wf,/actions\/setup-node@v4/);
    assert.doesNotMatch(wf,/node-version:\s*['"]22['"]/);
    assert.match(wf,/actions\/checkout@v7/);
    assert.match(wf,/npm audit --omit=dev --audit-level=high/);
    assert.match(wf,/npm audit --audit-level=critical/);
  }
  assert.match(build,/actions\/setup-node@v7/);
  assert.match(build,/actions\/upload-artifact@v7/);
  assert.match(build,/permissions:\s*\n\s*contents:\s*read/);
  assert.match(release,/actions\/setup-node@v7/);
  assert.match(release,/actions\/upload-artifact@v7/);
  assert.match(release,/actions\/download-artifact@v8/);
  assert.match(build,/node-version:\s*['"]24['"]/);
  assert.match(release,/node-version:\s*['"]24['"]/);
});

test('Linux Debian desktop entry is normalized to world-readable mode after packaging',()=>{
  const pkg=require(path.join(root,'package.json'));
  const hook=fs.readFileSync(path.join(root,'tools/afterAllArtifactBuild.js'),'utf8');
  assert.equal(pkg.build.afterAllArtifactBuild,'tools/afterAllArtifactBuild.js');
  assert.match(hook,/--raw-extract/);
  assert.match(hook,/fs\.chmodSync\(desktop, 0o644\)/);
  assert.match(hook,/fs\.chmodSync\(icon, 0o644\)/);
  assert.match(hook,/fs\.chmodSync\(controlDir, 0o755\)/);
  assert.match(hook,/--root-owner-group/);
  assert.match(hook,/desktop entry mode is not 0644/);
  assert.match(hook,/application icon mode is not 0644/);
  assert.ok(hook.includes('artifactPaths') && hook.includes('.deb$/i.test(file)'));
});

test('Linux Debian package path is sandbox-safe',()=>{
  const afterPack=fs.readFileSync(path.join(root,'tools/afterPack.js'),'utf8');
  const afterInstall=fs.readFileSync(path.join(root,'build/linux-after-install.sh'),'utf8');
  assert.match(afterPack,/sanitizedProductName\s*=\s*['"]open-internet-gateway['"]/);
  assert.match(afterInstall,/APPDIR="\/opt\/open-internet-gateway"/);
  assert.doesNotMatch(afterInstall,/\/opt\/Open Internet Gateway/);
});

test('disconnected exact relay failure restores saved preferred relay',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-preferred-restore-'));
  const stateDir=path.join(tmp,'state');
  fs.mkdirSync(stateDir,{recursive:true});
  const previous={sha256:'c'.repeat(64),country:'VN',host:'saved-working',ip:'203.0.113.9',active:false,quarantined:false};
  const target={sha256:'d'.repeat(64),country:'JP',host:'dead-target',ip:'198.51.100.7',active:false,quarantined:false};
  fs.writeFileSync(path.join(stateDir,'preferred-profile.json'),JSON.stringify(previous));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='win32';
  backend.backendRoot=tmp;
  backend.profiles=async()=>({profiles:[previous,target],preferredSha:previous.sha256});
  backend.status=async()=>({connected:true,country:'VN'});
  const calls=[];
  backend._windows=async(_action,args)=>{
    const sha=String(args?.[1]||'');
    calls.push(sha);
    if(sha===target.sha256) throw new Error('SIMULATED_EXACT_FAIL');
    fs.writeFileSync(path.join(stateDir,'current-openvpn-profile.json'),JSON.stringify({sha256:previous.sha256}));
    return {ok:true};
  };
  const result=await backend.connectProfile(target.sha256);
  assert.equal(result.ok,false);
  assert.equal(result.recovered,true);
  assert.equal(result.code,'SELECTED_RELAY_FAILED_RESTORED');
  assert.match(result.message,/Previous working relay was restored/);
  assert.deepEqual(calls,[target.sha256,previous.sha256]);
  const preferred=JSON.parse(fs.readFileSync(path.join(stateDir,'preferred-profile.json'),'utf8'));
  assert.equal(preferred.sha256,previous.sha256);
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('backend strips ANSI terminal formatting before surfacing command errors',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.match(backend,/function stripAnsi\(value\)/);
  assert.match(backend,/stdout: stripAnsi\(stdout\)\.trim\(\), stderr: stripAnsi\(stderr\)\.trim\(\)/);
  assert.match(backend,/new Error\(result\.stderr \|\| result\.stdout/);
});


test('renderer terminal backend events close only the matching busy overlay',()=>{
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(renderer,/busyAction:\s*''/);
  assert.match(renderer,/state\.busyAction = on \? action : ''/);
  assert.match(renderer,/payload\.type === 'status'[\s\S]*payload\.busy === false && state\.busyAction === payload\.action[\s\S]*setBusy\(false\)/);
  assert.match(renderer,/payload\.type === 'error'[\s\S]*payload\.busy === false && state\.busyAction === payload\.action[\s\S]*setBusy\(false\)/);
  assert.match(renderer,/payload\.type === 'busy'[\s\S]*payload\.busy \|\| !state\.busyAction \|\| state\.busyAction === payload\.action/);
});


test('recovered relay failure is a structured non-error outcome and Speed does not benchmark fallback',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(backend,/recovered:\s*true/);
  assert.match(backend,/SELECTED_RELAY_FAILED_RESTORED/);
  assert.match(backend,/if \(restored\) return recoveredResult/);
  assert.match(renderer,/if \(connected\?\.recovered\)[\s\S]*showToast\(connected\.message[\s\S]*await loadConnections\(\);[\s\S]*return;/);
  const connectBlock=renderer.slice(renderer.indexOf('async function connectOrTestProfile'),renderer.indexOf('async function benchmarkCurrent'));
  const recoveredPos=connectBlock.indexOf('if (connected?.recovered)');
  const benchmarkPos=connectBlock.indexOf("window.gateway.action('benchmark-active')");
  assert.ok(recoveredPos >= 0 && benchmarkPos > recoveredPos);
});

test('renderer strips Electron IPC and PowerShell framing from user-facing errors',()=>{
  const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
  assert.match(renderer,/function userErrorMessage\(error, fallback/);
  assert.match(renderer,/Error invoking remote method/);
  assert.match(renderer,/CategoryInfo\|FullyQualifiedErrorId/);
  assert.match(renderer,/showToast\(userErrorMessage\(e, 'Relay operation failed\.'\), true\)/);
  assert.match(renderer,/showToast\(userErrorMessage\(payload\.message, 'Action failed\.'\), true\)/);
});

test('profiles can reuse an already validated live status without a second transient probe',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-status-reuse-'));
  fs.mkdirSync(path.join(tmp,'runtime','udp-cache'),{recursive:true});
  fs.mkdirSync(path.join(tmp,'runtime','config-factory'),{recursive:true});
  fs.mkdirSync(path.join(tmp,'state'),{recursive:true});
  const sha='e'.repeat(64);
  fs.writeFileSync(path.join(tmp,'runtime','udp-cache','index.json'),JSON.stringify([{Rank:1,Host:'relay',IP:'203.0.113.10',Port:443,Protocol:'tcp',Country:'VN',SHA256:sha}]));
  fs.writeFileSync(path.join(tmp,'state','current-openvpn-profile.json'),JSON.stringify({sha256:sha,host:'relay',serverIP:'203.0.113.10',port:443,protocol:'tcp',configuredCountry:'VN'}));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='win32'; backend.backendRoot=tmp;
  let statusCalls=0; backend.status=async()=>{statusCalls++;return {connected:false};};
  const inventory=await backend.profiles({connected:true});
  assert.equal(statusCalls,0); assert.equal(inventory.profiles.length,1); assert.equal(inventory.profiles[0].active,true);
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('active throughput benchmark reuses its validated status for inventory mapping',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async benchmarkActive()');
  const block=backend.slice(start,backend.indexOf('async diagnostics()',start));
  assert.match(block,/const status = await this\.status\(\)/);
  assert.match(block,/const inventory = await this\.profiles\(status\)/);
});


test('active throughput upload tolerates one transient Cloudflare POST failure without accepting an unverified result',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async benchmarkActive()');
  const block=backend.slice(start,backend.indexOf('_githubHeaders()',start));
  assert.match(block,/let uploadAttempts = 0/);
  assert.match(block,/for \(let attempt = 0; attempt < 2; attempt\+\+\)/);
  assert.match(block,/--connect-timeout','8','--max-time','20'/);
  assert.match(block,/timeout: 24000, allowFailure: true/);
  assert.match(block,/code === '200' && Number\(speed\) > 0/);
  assert.match(block,/after a bounded retry/);
  assert.match(block,/uploadAttempts,/);
});


test('Linux exact relay switch preserves gateway intent atomically and records provenance',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('  connect-profile)');
  const end=linux.indexOf('    ;;',start);
  const block=linux.slice(start,end);
  assert.ok(start>=0 && end>start);
  assert.match(block,/set_desired on "connect-profile"/);
  assert.match(block,/teardown_gateway/);
  assert.match(block,/connect_gateway "\$2"/);
  assert.doesNotMatch(block,/disconnect_gateway/);
  assert.ok(block.indexOf('set_desired on') < block.indexOf('teardown_gateway'));
  assert.ok(block.indexOf('teardown_gateway') < block.indexOf('connect_gateway'));
  const intent=linux.slice(linux.indexOf('record_intent()'),linux.indexOf('\ndesired_state()'));
  assert.match(intent,/intent-history\.jsonl/);
  assert.match(intent,/\/proc\/\$PPID\/cmdline/);
  assert.match(intent,/parentCommand/);
  const disconnect=linux.slice(linux.indexOf('disconnect_gateway()'),linux.indexOf('\nrefresh_cache()'));
  assert.match(disconnect,/set_desired off/);
  assert.match(disconnect,/teardown_gateway/);
});


test('automatic updater prefers user-space assets and avoids elevation paths',()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(require('os').tmpdir(),'oig-update-select-'));
  const backend=new Backend({version:'2.5.13',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  const assets=[
    {name:'OpenInternetGateway-2.5.14-amd64.deb'},
    {name:'OpenInternetGateway-2.5.14-x86_64.AppImage'},
    {name:'OpenInternetGateway-Setup-2.5.14.exe'}
  ];
  backend.platform='linux';
  assert.equal(backend._selectUpdateAsset(assets,'2.5.14').name,'OpenInternetGateway-2.5.14-x86_64.AppImage');
  backend.platform='win32';
  assert.equal(backend._selectUpdateAsset(assets,'2.5.14').name,'OpenInternetGateway-Setup-2.5.14.exe');
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
  const source=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  assert.ok(source.includes("ArgumentList @('/S')"));
  const launchBlock=source.slice(source.indexOf('async launchDownloadedUpdate'),source.indexOf('async downloadUpdate'));
  assert.doesNotMatch(launchBlock,/-Verb RunAs/);
  assert.ok(main.includes('app-process.lease'));
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('updater ignores cached release results from a previous installed version', async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const os=require('node:os');
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-update-post-upgrade-'));
  try{
    const statePath=path.join(tmp,'state','github-update.json');
    fs.mkdirSync(path.dirname(statePath),{recursive:true});
    fs.writeFileSync(statePath,JSON.stringify({
      checkedAt:new Date().toISOString(),currentVersion:'2.5.18',
      latestVersion:'2.5.19',updateAvailable:true,upToDate:false,
      asset:{name:'OpenInternetGateway-Setup-2.5.19.exe'}
    }));
    const backend=new Backend({version:'2.5.19',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
    backend.platform='win32';
    backend.backendRoot=tmp;
    let requests=0;
    backend._githubJson=async()=>{
      requests++;
      return {
        tag_name:'v2.5.19',
        assets:[{name:'OpenInternetGateway-Setup-2.5.19.exe',
          digest:'sha256:'+'a'.repeat(64),browser_download_url:'https://github.com/example/asset'}]
      };
    };
    const refreshed=await backend.updateInfo(false);
    assert.equal(requests,1,'a newer installed app must not reuse an older currentVersion cache');
    assert.equal(refreshed.currentVersion,'2.5.19');
    assert.equal(refreshed.updateAvailable,false);
    assert.equal(refreshed.upToDate,true);
    const cached=await backend.updateInfo(false);
    assert.equal(requests,1,'matching-version cache must still avoid a redundant release fetch');
    assert.equal(cached.currentVersion,'2.5.19');
  }finally{
    fs.rmSync(tmp,{recursive:true,force:true});
  }
});

test('updater rejects assets named for a different release on Windows and Linux',()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const backend=new Backend({version:'2.5.18',resourcesPath:'',appPath:'',userData:'',emit:()=>{}});
  backend.platform='win32';
  assert.equal(backend._selectUpdateAsset([
    {name:'OpenInternetGateway-Setup-2.5.18.exe',digest:'sha256:'+'a'.repeat(64)}
  ],'2.5.19'),null,'do not install an older Windows EXE under a new version label');
  backend.platform='linux';
  assert.equal(backend._selectUpdateAsset([
    {name:'OpenInternetGateway-2.5.18-x86_64.AppImage',digest:'sha256:'+'a'.repeat(64)},
    {name:'OpenInternetGateway-2.5.18-amd64.deb'}
  ],'2.5.19'),null,'do not replace the installed AppImage with a different release');
});
test('up-to-date releases never require platform assets or try download', async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const os=require('node:os');
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-no-new-release-asset-'));
  try{
    const backend=new Backend({version:'2.5.19',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
    backend.backendRoot=tmp;
    let calls=0;
    backend._githubJson=async()=>{calls++;return {tag_name:'v2.5.19',assets:[],published_at:'2026-10-18T00:00:00Z'};};
    backend._curlText=async()=>{throw new Error('no checksum request for an already-current release');};
    backend._downloadWithSha256=async()=>{throw new Error('no installer download for an already-current release');};
    for(const platform of ['win32','linux']){
      backend.platform=platform;
      const result=await backend.downloadUpdate();
      assert.equal(result.ok,true);
      assert.equal(result.alreadyCurrent,true);
      assert.equal(result.info.upToDate,true);
      assert.equal(result.info.updateAvailable,false);
      assert.equal(result.info.asset,null);
      assert.equal(result.path,null);
    }
    assert.equal(calls,2,'a fresh version check should still occur for each platform');
    backend.platform='win32';
    backend._githubJson=async()=>({tag_name:'v2.5.20',assets:[]});
    await assert.rejects(backend.downloadUpdate(),/compatible update asset/i,
      'missing installer for an actual newer version must still fail closed');
  }finally{
    fs.rmSync(tmp,{recursive:true,force:true});
  }
});
test('updater rejects malformed latest release tags before caching or downloading',async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const os=require('node:os');
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-release-semver-'));
  try{
    const backend=new Backend({version:'2.5.19',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
    backend.backendRoot=tmp;
    let downloads=0;
    backend._downloadWithSha256=async()=>{downloads++;throw Error('INVALID_TAG_DOWNLOAD_ATTEMPTED');};
    for(const tag of ['v2.5.20junk','v2.5.20-rc.1','v2.5.20/../../escape','v02.5.20','v2.5.20\nanything','v2.5','2.5.20+build']){
      backend._githubJson=async()=>({tag_name:tag,assets:[]});
      await assert.rejects(backend.updateInfo(true),/invalid release version tag/i,
        'reject malformed latest release tag: '+JSON.stringify(tag));
      await assert.rejects(backend.downloadUpdate(),/invalid release version tag/i);
      assert.equal(downloads,0,'invalid release metadata must not reach installer download');
    }
    for(const tag of ['v2.5.20','2.5.20']){
      backend._githubJson=async()=>({tag_name:tag,assets:[]});
      const result=await backend.updateInfo(true);
      assert.equal(result.latestVersion,'2.5.20');
      assert.equal(result.updateAvailable,true);
    }
  }finally{fs.rmSync(tmp,{recursive:true,force:true});}
});

test('updater requires published SHA256SUMS before downloading a newer release on both platforms',async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const os=require('node:os');
  for(const platform of ['win32','linux']){
    const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-updater-required-sums-'));
    try{
      const backend=new Backend({version:'2.5.19',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
      backend.backendRoot=tmp;
      backend.platform=platform;
      const filename=platform==='win32'?'OpenInternetGateway-Setup-2.5.20.exe':'OpenInternetGateway-2.5.20-x86_64.AppImage';
      const hash='a'.repeat(64);
      const asset={name:filename,digest:'sha256:'+hash,browser_download_url:'https://github.com/GOD13emad/OpenInternetGateway/releases/download/v2.5.20/'+filename};
      const sumsAsset={name:'SHA256SUMS.txt',browser_download_url:'https://github.com/GOD13emad/OpenInternetGateway/releases/download/v2.5.20/SHA256SUMS.txt'};
      let checksumFetches=0, downloads=0;
      backend._curlText=async()=>{
        checksumFetches++;
        return hash+'  '+filename+'\n';
      };
      backend._downloadWithSha256=async()=>{
        downloads++;
        return {sha256:hash,bytes:3};
      };
      backend._githubJson=async()=>({tag_name:'v2.5.20',assets:[asset]});
      await assert.rejects(backend.downloadUpdate(),/SHA256SUMS/i,'missing manifest must stop actual update');
      assert.equal(downloads,0,'installer must not download before manifest verification');
      backend._githubJson=async()=>({tag_name:'v2.5.20',assets:[asset,{...sumsAsset,browser_download_url:''}]});
      await assert.rejects(backend.downloadUpdate(),/SHA256SUMS/i,'empty manifest URL must stop actual update');
      assert.equal(downloads,0);
      backend._githubJson=async()=>({tag_name:'v2.5.20',assets:[asset,sumsAsset]});
      backend._curlText=async()=>{ checksumFetches++; return 'b'.repeat(64)+'  '+filename+'\n'; };
      await assert.rejects(backend.downloadUpdate(),/GitHub digest and SHA256SUMS disagree/i);
      assert.equal(downloads,0,'mismatched manifest must not download installer');
      backend._curlText=async()=>{checksumFetches++;return hash+'  '+filename+'\n';};
      const good=await backend.downloadUpdate();
      assert.equal(good.ok,true);
      assert.equal(good.sha256,hash);
      assert.equal(downloads,1);
      assert.equal(checksumFetches,2,'checksum text fetched for mismatched and correct manifest only');
    }finally{fs.rmSync(tmp,{recursive:true,force:true});}
  }
});

test('updater streams checksum calculation and never promotes a hash-mismatched installer', {timeout:30000}, async()=>{
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const os=require('node:os');
  const crypto=require('node:crypto');
  const {pathToFileURL}=require('node:url');
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-update-hash-before-rename-'));
  try{
    const backend=new Backend({version:'2.5.18',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
    const source=path.join(tmp,'source installer with spaces.exe');
    const target=path.join(tmp,'verified','OpenInternetGateway-Setup-2.5.19.exe');
    // Real local-file curl exercises the downloaded .partial path without
    // external network access or touching an installed app.
    const payload=Buffer.alloc(8*1024*1024,0x6d);
    fs.writeFileSync(source,payload);
    const expected=crypto.createHash('sha256').update(payload).digest('hex');
    const url=pathToFileURL(source).href;
    await assert.rejects(backend._downloadWithSha256(url,target,'0'.repeat(64)),
      /SHA-256|digest|hash/i,
      'bad download must be rejected before the final filename exists');
    assert.equal(fs.existsSync(target),false);
    assert.equal(fs.existsSync(target+'.partial'),false);
    const result=await backend._downloadWithSha256(url,target,expected);
    assert.equal(result.sha256,expected);
    assert.equal(result.bytes,payload.length);
    assert.equal(fs.existsSync(target),true);
    assert.equal(fs.existsSync(target+'.partial'),false);
    assert.equal(await backend._fileSha256(target),expected);
    assert.equal(await backend._fileSha256(source),expected);
    const backendSource=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
    assert.doesNotMatch(backendSource,/fs\.readFileSync\((?:partial|destination)\)/);
  }finally{
    fs.rmSync(tmp,{recursive:true,force:true});
  }
});
test('Linux OpenVPN quality engine uses multi-source refresh and safe public-profile filtering',()=>{
  const factory=fs.readFileSync(path.join(root,'backend/linux/config_factory.py'),'utf8');
  assert.match(factory,/https:\/\/www\.vpngate\.net/);
  assert.match(factory,/ThreadPoolExecutor/);
  assert.match(factory,/max_sources=3/);
  assert.match(factory,/usedMirrors/);
  assert.match(factory,/sourceCount/);
  assert.match(factory,/allow_partial=True/);
  assert.match(factory,/proc\.returncode == 28/);
  assert.match(factory,/partialSourceCount/);
  assert.match(factory,/len\(rows\) >= 8/);
  assert.match(factory,/not data\.endswith/);
  assert.match(factory,/mergedRows/);
  assert.match(factory,/count=48/);
  assert.match(factory,/preserve_count=8/);
  for(const token of ['script-security','route-up','route-pre-down','ipchange','plugin','client-connect','client-disconnect','learn-address']) assert.ok(factory.includes(token));
});

test('Linux adaptive OpenVPN ranking consumes direct probes and persistent quality history',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('profile_lines()');
  const end=linux.indexOf('\nconnect_one()',start);
  const block=linux.slice(start,end);
  assert.match(block,/connection-benchmarks\.json/);
  assert.match(block,/successes\.json/);
  assert.match(block,/failures\.json/);
  assert.match(block,/fastPingMs/);
  assert.match(block,/downloadMbps/);
  assert.match(block,/uploadMbps/);
  assert.match(block,/httpsLatencyMs/);
  assert.match(block,/fresh_iso\(f\.get\("last"\),6\)/);
  assert.match(block,/score -= 320\.0/);
  assert.match(block,/proto=="udp"/);
  assert.match(block,/proto=="tcp" and b\.get\("fastReachable"\) is False/);
  assert.match(block,/if n >= \(1 if only_sha else 16\): break/);
});

test('Linux exact OpenVPN switch preflights beside the working tunnel before teardown',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const pre=linux.slice(linux.indexOf('preflight_one()'),linux.indexOf('\nconnect_one()'));
  assert.match(pre,/OIG-VPN-PREFLIGHT/);
  assert.match(pre,/ipv4\.never-default yes/);
  assert.match(pre,/ipv4\.ignore-auto-routes yes/);
  assert.match(pre,/ipv4\.ignore-auto-dns yes/);
  assert.match(pre,/nmcli -w 10 connection up/);
  assert.match(pre,/defaultRoutePreserved/);
  assert.match(pre,/dnsStatePreserved/);
  assert.match(linux,/dns_server_fingerprint/);
  assert.match(pre,/route_ok and dns_ok/);
  const start=linux.indexOf('  connect-profile)');
  const end=linux.indexOf('    ;;',start);
  const block=linux.slice(start,end);
  assert.ok(block.indexOf('preflight_one') >= 0);
  assert.ok(block.indexOf('preflight_one') < block.indexOf('teardown_gateway'));
  assert.match(block,/current tunnel preserved/);
  assert.match(block,/rc=\$\?/);
});

test('Linux foreground connect and refresh qualify the OpenVPN pool over physical Internet first',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async action(action, options = {})');
  const end=backend.indexOf('\n  async diagnostics()',start);
  const block=backend.slice(start,end);
  assert.match(block,/this\.platform === 'linux' && action === 'connect'[\s\S]*benchmarkAllFast\(\)[\s\S]*_linux\('connect'\)/);
  assert.match(block,/this\.platform === 'linux' && action === 'refresh'[\s\S]*_linux\('factory-refresh'\)[\s\S]*benchmarkAllFast\(\)[\s\S]*_linux\('connect'\)/);
  assert.match(block,/this\.platform === 'linux' && action === 'factory-refresh'[\s\S]*fastQualification/);
});


test('Linux interrupted OpenVPN activation records pending identity without trusting pending geo fallback',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  assert.match(linux,/validationPending/);
  assert.match(linux,/profile_ip="" if pending/);
  assert.match(linux,/profile_country="" if pending/);
  const start=linux.indexOf('connect_one()');
  const end=linux.indexOf('\nrecord_success()',start);
  const block=linux.slice(start,end);
  assert.ok(block.indexOf('write_profile_state') > block.indexOf('nmcli -w 30 connection up'));
  assert.ok(block.indexOf('write_profile_state') < block.indexOf('for _ in 1 2 3 4 5 6'));
  assert.match(block,/current-linux-profile\.before-connect\.json/);
  assert.match(block,/mv -f "\$previous_state" "\$state_file"/);
});

test('Linux teardown waits on observed NetworkManager state instead of fixed outage delay',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8').replace(/\r\n/g,'\n');
  const start=linux.indexOf('teardown_gateway()');
  const end=linux.indexOf('\ndisconnect_gateway()',start);
  const block=linux.slice(start,end);
  assert.doesNotMatch(block,/sleep 2/);
  assert.match(block,/connection show --active/);
  assert.match(block,/sleep 0\.1/);
});


test('Linux intent provenance tolerates a disappearing parent process',()=>{
  const linux=fs.readFileSync(path.join(root,'backend/linux/oig-linux.sh'),'utf8');
  const start=linux.indexOf('record_intent()');
  const end=linux.indexOf('\nset_desired()',start);
  const block=linux.slice(start,end);
  assert.match(block,/\[\[ -r "\/proc\/\$PPID\/cmdline" \]\]/);
  assert.match(block,/2>\/dev\/null \|\| true/);
});

test('Linux exact relay failure falls through to adaptive recovery when exact rollback is unavailable',async()=>{
  const os=require('os');
  const Backend=require(path.join(root,'src/main/platform-backend.js'));
  const tmp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-linux-general-recovery-'));
  const stateDir=path.join(tmp,'state');
  fs.mkdirSync(stateDir,{recursive:true});
  const previous={sha256:'e'.repeat(64),country:'JP',host:'previous',ip:'203.0.113.10',active:true,quarantined:false};
  const target={sha256:'f'.repeat(64),country:'JP',host:'target',ip:'198.51.100.20',active:false,quarantined:false};
  const recoveredSha='1'.repeat(64);
  fs.writeFileSync(path.join(stateDir,'preferred-profile.json'),JSON.stringify(previous));
  const backend=new Backend({version:'test',resourcesPath:tmp,appPath:tmp,userData:tmp,emit:()=>{}});
  backend.platform='linux';
  backend.backendRoot=tmp;
  backend.profiles=async()=>({profiles:[previous,target],preferredSha:previous.sha256});
  let connected=false;
  backend.status=async()=>({connected,country:connected?'TH':''});
  const calls=[];
  backend._linux=async(action,args)=>{
    calls.push([action,...(args||[])]);
    if(action==='connect-profile') throw new Error('SIMULATED_EXACT_FAILURE');
    if(action==='connect'){
      connected=true;
      fs.writeFileSync(path.join(stateDir,'current-linux-profile.json'),JSON.stringify({
        sha256:recoveredSha,country:'TH',host:'adaptive-recovery',serverIP:'203.0.113.77'
      }));
      return {ok:true};
    }
    throw new Error('UNEXPECTED_ACTION');
  };
  const result=await backend.connectProfile(target.sha256);
  assert.equal(result.ok,false);
  assert.equal(result.recovered,true);
  assert.equal(result.code,'SELECTED_RELAY_FAILED_GENERAL_RECOVERY');
  assert.equal(result.status.connected,true);
  assert.deepEqual(calls,[
    ['connect-profile',target.sha256],
    ['connect-profile',previous.sha256],
    ['connect']
  ]);
  const preferred=JSON.parse(fs.readFileSync(path.join(stateDir,'preferred-profile.json'),'utf8'));
  assert.equal(preferred.sha256,recoveredSha);
  assert.equal(preferred.country,'TH');
  fs.rmSync(tmp,{recursive:true,force:true});
});

test('Linux general recovery is present in every post-selection validation failure branch',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const block=backend.slice(backend.indexOf('async connectProfile'),backend.indexOf('async _directInternetPath'));
  assert.match(block,/const recoverAnyLinux = async/);
  assert.match(block,/this\.platform !== 'linux'/);
  assert.match(block,/await this\._linux\('connect'\)/);
  assert.match(block,/SELECTED_RELAY_FAILED_GENERAL_RECOVERY/);
  assert.match(block,/SELECTED_RELAY_NOT_ACTIVE_GENERAL_RECOVERY/);
  assert.match(block,/SELECTED_RELAY_COUNTRY_MISMATCH_GENERAL_RECOVERY/);
});


test('Windows OpenVPN quality engine mirrors evidence-backed pool and profile safety controls',()=>{
  const build=fs.readFileSync(path.join(root,'backend/windows/scripts/Build-VpnGateUdpCache.ps1'),'utf8');
  assert.match(build,/Count=48/);
  assert.match(build,/PerCountry=6/);
  assert.match(build,/PreserveOld=8/);
  for(const token of ['script-security','route-up','route-pre-down','ipchange','plugin','client-connect','client-disconnect','learn-address']) assert.ok(build.includes(token));
});

test('Windows native HTTPS-only source selection never includes plaintext mirror rows',()=>{
  if(process.platform!=='win32') return;
  const cp=require('node:child_process');
  const source=path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1');
  const script=[
    '$ErrorActionPreference="Stop"',
    '$text=[IO.File]::ReadAllText($env:OIG_HTTPS_SELECTION_SOURCE)',
    '$start=$text.IndexOf(" $httpsOnlyLive=")',
    '$stop=$text.IndexOf(" $seen=",$start)',
    'if($start -lt 0 -or $stop -lt 0){throw "Selection code not found"}',
    '$code=$text.Substring($start,$stop-$start)',
    '$MaxSources=3',
    '$usable=@([pscustomobject]@{Base="https://provider";HttpsPriority=$true;Complete=$true;Rows=8},[pscustomobject]@{Base="http://mirror";HttpsPriority=$false;Complete=$true;Rows=20})',
    'Invoke-Expression $code',
    'if(-not $httpsOnlyLive -or @($chosen).Count -ne 1 -or $chosen[0].Base -ne "https://provider"){throw "HTTP mixed with HTTPS"}',
    '$usable=@([pscustomobject]@{Base="http://mirror-a";HttpsPriority=$false;Complete=$true;Rows=8},[pscustomobject]@{Base="http://mirror-b";HttpsPriority=$false;Complete=$true;Rows=9})',
    'Invoke-Expression $code',
    'if($httpsOnlyLive -or @($chosen).Count -ne 2){throw "HTTP fallback lost"}',
    '"PASS HTTPS-only and HTTP-only fallback under native Windows PowerShell"'
  ].join(';');
  const r=cp.spawnSync('pwsh',['-NoProfile','-NonInteractive','-EncodedCommand',Buffer.from(script,'utf16le').toString('base64')],{
    encoding:'utf8',timeout:12000,env:{...process.env,OIG_HTTPS_SELECTION_SOURCE:source}
  });
  assert.equal(r.status,0,r.stderr||r.stdout);
});

test('Windows VPN Gate refresh is bounded, parallel, HTTPS-first and merges multiple snapshots',()=>{
  const refresh=fs.readFileSync(path.join(root,'backend/windows/scripts/Refresh-VpnGateCache.ps1'),'utf8');
  assert.match(refresh,/https:\/\/www\.vpngate\.net/);
  assert.match(refresh,/--connect-timeout','2'/);
  assert.match(refresh,/--max-time','8'/);
  assert.match(refresh,/Diagnostics\.ProcessStartInfo/);
  assert.match(refresh,/sourceCount/);
  assert.match(refresh,/usedMirrors/);
  assert.match(refresh,/mergedRows/);
  assert.match(refresh,/cachedMergedRows/);
  assert.match(refresh,/liveMergedRows/);
  assert.match(refresh,/cachedSnapshotExisted/);
  assert.match(refresh,/\$httpsOnlyLive=\@\(\$usable\|Where-Object HttpsPriority\)/);
  assert.match(refresh,/\$candidateSources=if\(\$httpsOnlyLive\)/);
  assert.match(refresh,/\-not \$httpsOnlyLive \-and \$liveMergedRows \-gt 0/);
  assert.match(refresh,/liveMergedRows -ge 8/);
  assert.match(refresh,/MaxSources=3/);
});

test('Windows headless OpenVPN ranking consumes benchmark history and recent failure evidence',()=>{
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const start=headless.indexOf('function Get-QualityScore');
  const end=headless.indexOf('function Resolve-ProfilePath',start);
  const block=headless.slice(start,end);
  assert.match(headless,/connection-benchmarks\.json/);
  for(const token of ['fastPingMs','downloadMbps','uploadMbps','httpsLatencyMs']) assert.ok(block.includes(token));
  assert.match(block,/Test-Fresh \$Failures\[\$Key\]\.last 6/);
  assert.match(block,/score-=320/);
  assert.match(block,/score\+=45/);
  assert.match(block,/\$limit=if\(\$OnlySha\)\{1\}else\{8\}/);
  assert.match(block,/Select-Object -First \$limit/);
  assert.match(headless,/first=\$first;count=\$count/);
});

test('Windows foreground connect qualifies before connector mutation while refresh preserves connect semantics',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const start=backend.indexOf('async action(action, options = {})');
  const end=backend.indexOf('\n  async diagnostics()',start);
  const block=backend.slice(start,end);
  assert.match(block,/this\.platform === 'win32' && action === 'connect'[\s\S]*benchmarkAllFast\(\)[\s\S]*_windows\('connect'\)/);
  assert.match(block,/this\.platform === 'win32' && \(action === 'refresh' \|\| action === 'factory-refresh'\)[\s\S]*_windows\(action\)[\s\S]*benchmarkAllFast\(\)/);
  assert.doesNotMatch(block,/this\.platform === 'win32'[\s\S]{0,220}action === 'refresh'[\s\S]{0,220}_windows\('connect'\)/);
});
test('Windows native handover keeps a physical shadow until isolated TAP data-plane readiness',()=>{
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');
  assert.match(headless,/windows-physical-shadow\.json/);
  assert.match(headless,/shadow-handover-last\.json/);
  const physical=headless.slice(headless.indexOf('function Get-PhysicalDefaultPath'),headless.indexOf('function Add-PhysicalShadows'));
  assert.match(physical,/Refusing shadow path on tunnel-like default interface/);
  const add=headless.slice(headless.indexOf('function Add-PhysicalShadows'),headless.indexOf('function Get-ShadowState'));
  assert.match(add,/0\.0\.0\.0\/1/);
  assert.match(add,/128\.0\.0\.0\/1/);
  assert.match(add,/RouteMetric 1 -PolicyStore ActiveStore/);
  assert.match(add,/Refusing to add physical shadows while \/1 routes already exist/);
  const ready=headless.slice(headless.indexOf('function Wait-NativeReady'),headless.indexOf('function Stop-Connector'));
  assert.match(ready,/EVENT: CONNECTED/);
  assert.match(ready,/allow IPv4 traffic from TAP/);
  assert.match(ready,/NativeRoutes=\$native\.Count/);
  const data=headless.slice(headless.indexOf('function Wait-NativeDataPlane'),headless.indexOf('function Remove-PhysicalShadows'));
  assert.match(data,/1\.0\.0\.1\/32/);
  assert.match(data,/PolicyStore ActiveStore/);
  assert.match(data,/Test-TcpDataPlane '1\.0\.0\.1' 443 900/);
  assert.match(data,/finally/);
  assert.match(data,/Remove-NetRoute/);
});

test('Windows shadow takeover preserves native profile bytes and fails closed under physical cover',()=>{
  const headless=fs.readFileSync(path.join(root,'backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');
  const ts=headless.indexOf('function Try-Candidate');
  const te=headless.indexOf('\n$mutex=',ts);
  const block=headless.slice(ts,te);
  assert.match(block,/Copy-Item -LiteralPath \$profile -Destination \$serviceProfile -Force/);
  assert.match(block,/ProgramData profile copy hash mismatch/);
  assert.doesNotMatch(block,/route-nopull|route-delay/);
  const addAt=block.indexOf('$shadow=Add-PhysicalShadows');
  const startAt=block.indexOf("Invoke-Connector @('start')");
  const nativeAt=block.indexOf('Wait-NativeReady');
  const dataAt=block.indexOf('Wait-NativeDataPlane');
  const removeAt=block.indexOf('Remove-PhysicalShadows');
  assert.ok(addAt >= 0 && addAt < startAt && startAt < nativeAt && nativeAt < dataAt && dataAt < removeAt);
  assert.match(block,/DATAPLANE_READY_FAIL.*Stop-Connector/);
  assert.match(block,/NATIVE_READY_FAIL.*Stop-Connector/);
  assert.match(block,/POST_TAKEOVER_HEALTH_FAIL/);
  const stop=headless.slice(headless.indexOf('function Stop-Connector'),headless.indexOf('function Stop-ServiceForConfig'));
  assert.match(stop,/Get-ShadowState/);
  assert.ok(stop.indexOf("Invoke-Connector @('stop')") < stop.indexOf('Remove-PhysicalShadows'));
});

test('Tray dashboard lifecycle never dereferences a destroyed or null BrowserWindow',()=>{
  const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8').replace(/\r\n/g,'\n');
  const show=main.slice(main.indexOf('function showDashboard'),main.indexOf('function renderTray'));
  assert.match(show,/quitInProgress \|\| allowQuit \|\| app\.isQuitting/);
  assert.match(show,/!isLiveWindow\(mainWindow\)[\s\S]*createWindow\(\{ showWhenReady: true \}\)/);
  assert.match(show,/mainWindow\.isMinimized\(\)[\s\S]*mainWindow\.show\(\)[\s\S]*mainWindow\.focus\(\)/);
  assert.match(main,/Open Dashboard', click: showDashboard/);
  assert.match(main,/tray\.on\('double-click', showDashboard\)/);
  assert.doesNotMatch(main,/click: \(\) => \{ mainWindow\.show\(\)/);
  assert.doesNotMatch(main,/double-click', \(\) => \{ mainWindow\.show\(\)/);
  assert.match(main,/win\.on\('closed',[\s\S]*if \(mainWindow === win\) mainWindow = null/);
});

test('Windows clean-machine disconnect treats missing connector service as already off and does not require recovery task',()=>{
  const disconnect=fs.readFileSync(path.join(root,'backend/windows/scripts/Disconnect-OpenInternet.ps1'),'utf8').replace(/\r\n/g,'\n');
  const routeAt=disconnect.indexOf("$routes=@(Get-NetRoute");
  const alreadyAt=disconnect.indexOf("if($routes.Count -eq 0 -and (-not $svc -or $svc.Status -eq 'Stopped'))",routeAt);
  const taskAt=disconnect.indexOf("Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery'",alreadyAt);
  const runAt=disconnect.indexOf('schtasks.exe /Run',taskAt);
  assert.ok(routeAt >= 0 && alreadyAt > routeAt && taskAt > alreadyAt && runAt > taskAt);
  assert.match(disconnect.slice(alreadyAt,taskAt),/DISCONNECTED - ALREADY OFF[\s\S]*exit 0/);
  assert.match(disconnect,/recovery task is missing while a managed tunnel may still be active/);
});

test('Windows first Connect bootstraps verified prerequisites before desired-state mutation',()=>{
  const connect=fs.readFileSync(path.join(root,'backend/windows/scripts/Connect-OpenInternet.ps1'),'utf8').replace(/\r\n/g,'\n');
  const connectorAt=connect.indexOf("$connector='C:\\Program Files\\OpenVPN Connect\\ovpnconnector.exe'");
  const taskAt=connect.indexOf("$taskName='OpenInternetGateway-AutoRecovery'");
  const installAt=connect.indexOf("Install-AutoRecovery.ps1",taskAt);
  const desiredAt=connect.indexOf("desired='on'");
  assert.ok(connectorAt >= 0 && taskAt > connectorAt && installAt > taskAt && desiredAt > installAt);
  assert.match(connect,/Administrator approval is required once for first-time setup/);
  const installer=fs.readFileSync(path.join(root,'backend/windows/scripts/Install-AutoRecovery.ps1'),'utf8');
  assert.match(installer,/Join-Path \$PSHOME 'pwsh\.exe'/);
  assert.match(installer,/Start-Process -FilePath \$pwsh -Verb RunAs -Wait -PassThru/);
  assert.match(installer,/Elevated Auto-Recovery setup returned without creating the recovery task/);
});

test('Windows backend installer has no dead Install-Launcher reference',()=>{
  const install=fs.readFileSync(path.join(root,'backend/windows/Install.ps1'),'utf8');
  assert.doesNotMatch(install,/Install-Launcher\.ps1/);
  assert.match(install,/Install-AutoRecovery\.ps1/);
  assert.ok(fs.existsSync(path.join(root,'backend/windows/scripts/Install-AutoRecovery.ps1')));
});

test('Windows package bundles verified portable PowerShell 7',()=>{
  const pkg=JSON.parse(fs.readFileSync(path.join(root,'package.json'),'utf8'));
  assert.match(pkg.scripts['dist:win'],/prepareWindowsPwsh\.js/);
  assert.ok(pkg.build.win.extraResources.some(x=>x.from==='vendor/pwsh'&&x.to==='pwsh'));
  const prep=fs.readFileSync(path.join(root,'tools/prepareWindowsPwsh.js'),'utf8');
  assert.match(prep,/const VERSION = '7\.5\.4'/);
  assert.match(prep,/PowerShell-\$\{VERSION\}-win-x64\.zip/);
  assert.match(prep,/b40d192ae95ba6ccc4cc362ff4e1b18ca6fb5055bebbcd3920684e12701fa8f6/);
  assert.match(prep,/const PWSH_URL = `https:\/\/github\.com\/PowerShell\/PowerShell\/releases\/download\/v\$\{VERSION\}/);
  assert.doesNotMatch(prep,/const URL =/);
  assert.match(prep,/SHA-256 mismatch/);
  assert.match(prep,/pwsh\.exe/);
});

test('Windows first-connect OpenVPN prerequisite is pinned, verified and installed through Windows Installer',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8').replace(/\r\n/g,'\n');
  assert.match(backend,/openvpn-connect-3\.9\.0\.5008_signed\.msi/);
  assert.match(backend,/31347812dd37dbbb69bc47de842eb179827266e9dfb45e7f6ce10c5d71a5bad6/);
  assert.match(backend,/https:\/\/swupdate\.openvpn\.net\/downloads\/connect\/openvpn-connect-3\.9\.0\.5008_signed\.msi/);
  const ensure=backend.slice(backend.indexOf('async _ensureWindowsConnector'),backend.indexOf('async _ensureWindowsRuntimePrerequisites'));
  assert.match(ensure,/downloaded\.sha256/);
  assert.match(ensure,/WINDOWS_OPENVPN_CONNECT\.sha256/);
  assert.ok(ensure.includes("$systemMsi=Join-Path ([Environment]::SystemDirectory) 'msiexec.exe'"));
  assert.ok(ensure.includes('Test-Path -LiteralPath $systemMsi -PathType Leaf'));
  assert.ok(ensure.includes('Start-Process -FilePath $systemMsi -Verb RunAs -Wait -PassThru'));
  assert.ok(!ensure.includes("Start-Process -FilePath 'msiexec.exe'"));
  assert.match(ensure,/\$msi='" \+ escapedMsi \+ "'/);
  assert.match(ensure,/\/quiet \/norestart AUTOSTART=no/);
  assert.doesNotMatch(ensure,/\/passive/);
  assert.match(ensure,/ArgumentList \$msiArgs/);
  assert.match(ensure,/run\(pwsh, \['-NoProfile','-Command',elevate\]/);
  assert.match(ensure,/administrator approval was cancelled/);
  assert.match(ensure,/ovpnconnector\.exe is still missing/);
  const actionStart=backend.indexOf('async action(action, options = {})');
  const action=backend.slice(actionStart,backend.indexOf('\n  async diagnostics()',actionStart));
  const pre=action.indexOf('await this._ensureWindowsRuntimePrerequisites()');
  const bench=action.indexOf('await this.benchmarkAllFast()');
  assert.ok(pre >= 0 && bench > pre);
  assert.match(action,/action === 'connect' \|\| action === 'connect-profile'/);
});


test('official 2.5.18 Windows recovery guidance preserves integrity and security boundaries',()=>{
  const readme=fs.readFileSync(path.resolve(root,'../README.md'),'utf8');
  assert.match(readme,/Latest published release \(checked 2026-10-18\): 2\.5\.19/);
  const section=readme.split('### Windows v2.5.18: recovery when in-app update fails')[1]?.split('### Windows')[0];
  assert.ok(section,'missing bounded recovery section');
  assert.match(section,/confirmed failure/i);
  assert.match(section,/releases\/tag\/v2\.5\.19/);
  assert.match(section,/Get-FileHash -LiteralPath/);
  assert.match(section,/761637b5d49f37858973300ec2e9b1bb2b32c684ebabe86f1e8718b4480685db/);
  assert.match(section,/SHA256SUMS\.txt/);
  assert.match(section,/Quit.*disconnects the managed tunnel/);
  assert.match(section,/do not expect uninterrupted VPN access/i);
  assert.match(section,/Do not request elevation, disable Windows App Control\/SmartScreen/);
  assert.match(section,/does.*not.*prove live-tunnel continuity/);
});

test('public 2.5.18 failed updater has separate verified per-user recovery evidence',()=>{
  const script=fs.readFileSync(path.join(root,'tests/hosted-published-updater-ci.ps1'),'utf8');
  const start=script.indexOf('if($driverExit -eq 42){');
  const end=script.indexOf('if($driverExit -ne 0)',start);
  assert.ok(start>0 && end>start,'negative-only recovery must stay within classified old-client failure');
  const negative=script.slice(start,end);
  assert.match(negative,/FAIL_REAL_PUBLISHED_2518_AUTOMATIC_UPDATE/);
  assert.match(negative,/legacy-updater-failure-result\.json/);
  assert.match(negative,/Assert-Offline/);
  assert.match(negative,/RECOVERY_REFUSES_UNRECOGNIZED_APP_PROCESS/);
  assert.match(negative,/gh release download v2\.5\.19/);
  assert.match(negative,/Get-FileHash -LiteralPath \$recoveryInstaller -Algorithm SHA256/);
  assert.match(negative,/Start-Process -FilePath \$recoveryInstaller -ArgumentList '\/S' -PassThru -Wait/);
  assert.match(negative,/RECOVERY_USER_DATA_OR_OLD_HELPER_STATE_CHANGED/);
  assert.match(negative,/oldPublicInAppAutomaticUpdateSucceeded=\$false/);
  assert.match(negative,/recoveryRequiresOutOfAppAction=\$true/);
  assert.match(negative,/verified-manual-recovery-result\.json/);
  assert.match(negative,/DISPOSABLE_WINDOWS_SERVER_X64_ONLY|Assert-Offline/);
});

test('Windows update helper rejects ProductVersion prefix collisions after NSIS',()=>{
  const source=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
  const match=source.match(/^\s*(if\(\$installed -not(?:match|like) .+Installed version mismatch:.+)$/m);
  assert.ok(match,'Windows installed-version verification missing');
  const check=match[1].trim();
  assert.match(check,/\$installed -notmatch /,'prefix or wildcard-only acceptance is unsafe');
  assert.match(check,/\[regex\]::Escape\(\$Version\)/);
  assert.match(check,/\\d\+/,'allow a numeric fourth ProductVersion component only');
  const accepted=['2.5.19','2.5.19.0','2.5.19.12'];
  const rejected=['2.5.190','2.5.19evil','2.5.19-rc1','2.5.19.0evil','2.5.19.0.extra','2.5.1'];
  if(process.platform==='win32'){
    const {spawnSync}=require('node:child_process');
    const powershell=[
      "$ErrorActionPreference='Stop'",
      "$Version='2.5.19'",
      "$cases=@("+[...accepted,...rejected].map(v=>"'"+v+"'").join(',')+")",
      '$results=@()',
      'foreach($installed in $cases){',
      '  $allowed=$true',
      '  try { '+check+' } catch { $allowed=$false }',
      '  $results+=@{version=$installed;allowed=$allowed}',
      '}',
      'ConvertTo-Json -InputObject $results -Compress -Depth 3'
    ].join('\n');
    const result=spawnSync('pwsh',['-NoProfile','-NonInteractive','-Command',powershell],
      {encoding:'utf8',timeout:10000,windowsHide:true});
    assert.equal(result.status,0,result.stderr||result.error?.message);
    const outcomes=JSON.parse(result.stdout);
    for(const v of accepted)assert.equal(outcomes.find(x=>x.version===v)?.allowed,true,'must accept '+v);
    for(const v of rejected)assert.equal(outcomes.find(x=>x.version===v)?.allowed,false,'must reject '+v);
  }else{
    assert.match(check,/\\\.\s*\\d/,'numeric component must be dot-delimited');
  }
});

test('Windows update helper uses an isolated copy of bundled PowerShell instead of PATH lookup',()=>{
  const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8').replace(/\r\n/g,'\n');
  const start=backend.indexOf('async launchDownloadedUpdate');
  const end=backend.indexOf("if (this.platform === 'linux')",start);
  const block=backend.slice(start,end);
  assert.match(block,/const bundledPwshRoot = path\.join\(this\.resourcesPath \|\| '', 'pwsh'\)/);
  assert.match(block,/copyDir\(bundledPwshRoot, helperRuntime\)/);
  assert.match(block,/updatePwsh = path\.join\(helperRuntime, 'pwsh\.exe'\)/);
  assert.match(block,/spawn\(updatePwsh, launchArgs/);
  assert.match(block,/detached: false/);
  assert.match(block,/const launchScript = String\.raw/);
  assert.match(block,/Start-Process -FilePath \$Runtime -ArgumentList \$line -WindowStyle Hidden -PassThru/);
  assert.match(block,/child\.once\('close', code =>/);
  assert.match(block,/const startedDeadline = Date\.now\(\) \+ 15000/);
  assert.doesNotMatch(block,/where\.exe pwsh\.exe|process\.env\.ComSpec|apply-update\.cmd/);
});

test('Linux sandbox helper executes packaged Python in isolated mode without shell interpretation', async () => {
  const vm = require('node:vm');
  const os = require('node:os');
  const {EventEmitter} = require('node:events');
  const {PassThrough} = require('node:stream');
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'oig-helper-argv-'));
  try {
    const runtime = path.join(workspace, 'AppDir ; path with spaces');
    const packages = path.join(workspace, 'packaged resources');
    const dev = path.join(workspace, 'development');
    const stable = path.join(workspace, 'writable state');
    const pkgHelper = path.join(packages, 'backend', 'linux', 'harden_sandbox.py');
    const devHelper = path.join(dev, 'backend', 'linux', 'harden_sandbox.py');
    const replaced = path.join(stable, 'linux', 'harden_sandbox.py');
    for (const item of [runtime, path.dirname(pkgHelper), path.dirname(devHelper), path.dirname(replaced)]) {
      fs.mkdirSync(item, {recursive:true});
    }
    fs.writeFileSync(path.join(runtime, 'AppRun'), '#!/bin/sh\n', 'utf8');
    fs.writeFileSync(pkgHelper, 'print("packaged")\n', 'utf8');
    fs.writeFileSync(devHelper, 'print("development")\n', 'utf8');
    fs.writeFileSync(replaced, 'print("UNTRUSTED")\n', 'utf8');
    const calls=[];
    const fakeSpawn=()=>{throw new Error('unexpected spawned process');};
    const fakeExecFile=(file,args,options,callback)=>{
      calls.push({file,args,options});
      process.nextTick(()=>callback(null,'{"supported":true,"hardened":false,"reason":"test"}\n',''));
      return {kill:()=>true};
    };
    const module={exports:{}};
    const source=fs.readFileSync(path.join(root, 'src/main/platform-backend.js'),'utf8');
    vm.runInNewContext(source,{
      module,exports:module.exports,
      require:(name)=>name==='child_process'?{spawn:fakeSpawn,execFile:fakeExecFile}:require(name),
      process:{platform:'linux',execPath:path.join(runtime,'open-internet-gateway'),pid:process.pid,env:{}},
      setTimeout,clearTimeout,Buffer,console
    },{filename:'platform-backend.js',timeout:1000});
    const Backend=module.exports;
    const backend=new Backend({version:'test',resourcesPath:packages,appPath:dev,userData:workspace});
    backend.backendRoot=stable;
    backend._writeJson=()=>{};
    const result=await backend._hardenLinuxChromiumSandbox();
    assert.equal(result.supported,true);
    assert.equal(calls.length,1);
    assert.equal(calls[0].file,'python3');
    assert.deepEqual(Array.from(calls[0].args),['-I',pkgHelper,runtime]);
    assert.equal(calls[0].options.shell,false);
    assert.ok(!calls[0].args.includes(replaced));
    fs.unlinkSync(pkgHelper);
    await backend._hardenLinuxChromiumSandbox();
    assert.equal(calls.length,2);
    assert.deepEqual(Array.from(calls[1].args),['-I',devHelper,runtime]);
    fs.unlinkSync(devHelper);
    const failClosed=await backend._hardenLinuxChromiumSandbox();
    assert.equal(calls.length,2);
    assert.equal(failClosed.supported,false);
  } finally {
    fs.rmSync(workspace,{recursive:true,force:true});
  }
});
