const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const os=require('node:os');
const path=require('node:path');
const {spawnSync}=require('node:child_process');

test('Linux first run does not interpret missing desired-state as permission to connect', {skip:process.platform!=='linux'},()=>{
  const scratch=fs.mkdtempSync(path.join(os.tmpdir(),'oig-desired-first-run-'));
  const script=path.join(__dirname,'../backend/linux/oig-linux.sh');
  const desired=path.join(scratch,'state','desired-state');
  const read=()=>spawnSync('bash',['-c',
    'source <(awk \'/^delete_connection_name\\(\\) \\{/ {exit} {print}\' "$OIG_TEST_SCRIPT"); desired_state'
  ],{encoding:'utf8',timeout:5000,env:{...process.env,OIG_HOME:scratch,OIG_COMMON:path.join(scratch,'common'),OIG_TEST_SCRIPT:script}});
  try{
    const missing=read();
    assert.equal(missing.status,0,missing.stderr);
    assert.equal(missing.stdout.trim(),'off');
    assert.equal(fs.existsSync(desired),false,'status must not implicitly persist intent');
    fs.writeFileSync(desired,'on\n');
    const on=read();
    assert.equal(on.status,0,on.stderr);
    assert.equal(on.stdout.trim(),'on','explicit on must be preserved');
    fs.writeFileSync(desired,'off\n');
    const off=read();
    assert.equal(off.status,0,off.stderr);
    assert.equal(off.stdout.trim(),'off','explicit off must be preserved');
    const sh=fs.readFileSync(script,'utf8');
    assert.match(sh,/if \[\[ "\$\(desired_state\)" != "on" \]\];/);
    assert.match(sh,/if \[\[ "\$action" == "connect"/);
    assert.match(sh,/connect\) set_desired on; connect_gateway/);
  }finally{fs.rmSync(scratch,{recursive:true,force:true});}
});
