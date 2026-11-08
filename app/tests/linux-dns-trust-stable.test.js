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
