const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');

const script=fs.readFileSync(path.join(__dirname,'../backend/windows/scripts/Ensure-OpenInternet.ps1'),'utf8').replace(/\r\n/g,'\n');

test('fresh elevated Ensure bootstraps once and immediately proceeds to headless Ensure',()=>{
 const exact=script.indexOf("if(Test-Path $exactRequest){");
 const regular=script.lastIndexOf(" $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue",script.indexOf("-Action Ensure",exact));
 const bootstrap=script.indexOf("& (Join-Path $PSScriptRoot 'Bootstrap-HeadlessConnector.ps1')",regular);
 const ensure=script.indexOf("& (Join-Path $PSScriptRoot 'Headless-Control.ps1') -Action Ensure",bootstrap);
 assert.ok(exact>=0 && regular>exact && bootstrap>regular && ensure>bootstrap);
 const section=script.slice(bootstrap,ensure);
 assert.doesNotMatch(section,/\bexit\b|\breturn\b/, 'first bootstrapping must not defer to ten-minute recovery');
 assert.match(script.slice(exact,regular),/Headless-Control\.ps1'\) -Action Connect -ProfileSha \$sha/, 'exact relay remains separate');
 assert.match(script,/\[ordered\]@\{at=.*error=\$_.Exception.Message/,'elevated failures remain observable');
});
