const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {spawnSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');
const src=fs.readFileSync(path.join(root,'backend/windows/scripts/Operator-PinnedProfile.ps1'),'utf8');
test('Windows pinned certificate-only AUTLOGIN policy is offline and fail-closed',()=>{
 assert.match(src,/function Test-OigPinnedAutologinProfile/);
 assert.match(src,/PinnedCaSha256/);
 assert.match(src,/ExpectedPeerCN/);
 assert.match(src,/remote-cert-tls/);
 assert.match(src,/verify-x509-name/);
 assert.match(src,/serverIdentityVerified=\$false/);
 assert.match(src,/transportAttempted=\$false/);
 assert.match(src,/readyForAutomaticConnection=\$false/);
 assert.doesNotMatch(src,/Start-Process|Invoke-Expression|New-NetRoute|Start-Service|Set-Service|Invoke-WebRequest|Set-Content/);
});
test('Windows native offline pinned AUTLOGIN positive and rejection cases', {skip:process.platform!=='win32'},()=>{
 const r=spawnSync('pwsh',['-NoProfile','-NonInteractive','-File',path.join(__dirname,'windows-pinned-autologin-offline-smoke.ps1')],{
  cwd:root,encoding:'utf8',timeout:20000,windowsHide:true
 });
 assert.equal(r.status,0,(r.stderr||'')+'\n'+(r.stdout||''));
 assert.match(r.stdout,/WIN_PINNED_OFFLINE_29_PASS/);
});
