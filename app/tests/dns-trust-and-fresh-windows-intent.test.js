const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const base=path.join(__dirname,'..');

test('Linux dns.google unexpected A and unavailable response fail closed', {skip:process.platform!=='linux'},()=>{
  const script=path.join(base,'backend/linux/oig-linux.sh');
  const run=value=>{
    const cmd="source <(sed -n '/^dns_google_answer_state() {/,/^}/p' \"$OIG_TEST_SH\"); dns_google_answer_state \"$1\"";
    const r=spawnSync('bash',['-c',cmd,'-',value],{encoding:'utf8',timeout:3500,env:{...process.env,OIG_TEST_SH:script}});
    assert.equal(r.status,0,r.stderr);return r.stdout.trim();
  };
  for(const [value,expected] of [
    ['', 'unknown'],['8.8.8.8','false'],['8.8.4.4,8.8.8.8','false'],
    ['10.10.34.35','true'],['10.10.34.36','true'],
    ['8.8.8.8,10.10.34.36','true']])assert.equal(run(value),expected,value);
  assert.match(fs.readFileSync(script,'utf8'),/"poison":None if poison=="unknown" else poison=="true"/);
});

test('Windows status defaults explicit intent off and DNS unknown must fail closed',()=>{
  const status=fs.readFileSync(path.join(base,'backend/windows/scripts/Status-OpenInternet.ps1'),'utf8');
  const health=fs.readFileSync(path.join(base,'backend/windows/scripts/Headless-Control.ps1'),'utf8');
  const backend=fs.readFileSync(path.join(base,'src/main/platform-backend.js'),'utf8');
  for(const s of [status,health,backend]){
    assert.match(s,/8\.8\.8\.8/);
    assert.match(s,/8\.8\.4\.4/);
    assert.match(s,/\$poison -eq \$false/);
    assert.doesNotMatch(s,/10\.10\.34\.35/);
  }
  assert.match(backend,/\$desired='off';if\(Test-Path \$desiredPath\)/);
  assert.match(status,/\$desired='off'/);
});

test('Disconnected Dashboard shows no claimed protection and no green DNS icon',()=>{
  const s=fs.readFileSync(path.join(base,'src/renderer/app.js'),'utf8');
  assert.match(s,/const dnsOk = connected && s\.poison === false/);
  assert.match(s,/const routeOk = connected && Number\(s\.fullRoutes/);
  assert.match(s,/connected \? Math\.round\(score \/ 4 \* 100\) : 0/);
  assert.match(s,/Requires active VPN tunnel/);
  assert.match(s,/not authenticated/);
});
