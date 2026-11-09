const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../backend/windows/scripts/Headless-Control.ps1'),'utf8').replace(/\r\n/g,'\n');

test('connector start rejection produces a bounded sanitized diagnostic before cleanup',()=>{
  const start=source.indexOf("try{[void](Invoke-Connector @('start') 20000)}catch{");
  const end=source.indexOf(" $native=Wait-NativeReady",start);
  assert.ok(start>=0&&end>start,'exact start catch block must be found');
  const handler=source.slice(start,end);
  assert.match(handler,/result='START_REJECTED'/);
  assert.match(handler,/startError\.Length -gt 400/);
  assert.match(handler,/password\|token\|secret\|key/);
  assert.match(handler,/Record-Failure \$c 'START_FAIL'/);
  assert.match(handler,/Stop-Connector;return \$null/);
  assert.ok(handler.indexOf("Write-ShadowEvidence")<handler.indexOf("Record-Failure"));
});
