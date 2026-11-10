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


test('Windows owner-pinned AUTLOGIN inspection is only a native picker and never a connection action',()=>{
 const backend=fs.readFileSync(path.join(root,'src/main/platform-backend.js'),'utf8');
 const main=fs.readFileSync(path.join(root,'src/main/main.js'),'utf8');
 const preload=fs.readFileSync(path.join(root,'src/preload/preload.js'),'utf8');
 const renderer=fs.readFileSync(path.join(root,'src/renderer/app.js'),'utf8');
 const html=fs.readFileSync(path.join(root,'src/renderer/index.html'),'utf8');
 assert.match(backend,/async inspectWindowsPinnedAutologinProfile\(profilePath, options = \{\}\)/);
 assert.match(backend,/input: payload, env: \{ OIG_PINNED_POLICY_PATH: source \}/);
 assert.match(backend,/readyForAutomaticConnection: false, profilePersisted: false/);
 assert.match(main,/ipcMain\.handle\('gateway:inspectWindowsPinnedAutologin'/);
 assert.match(main,/dialog\.showOpenDialog\(mainWindow/);
 assert.match(main,/backend\.inspectWindowsPinnedAutologinProfile\(selected\.filePaths\[0\]/);
 assert.match(preload,/inspectWindowsPinnedAutologin: \(input\) => ipcRenderer\.invoke\('gateway:inspectWindowsPinnedAutologin', input\)/);
 assert.match(renderer,/async function inspectWindowsPinnedAutologin\(\)/);
 assert.match(renderer,/\$\('windowsPinnedProfileCard'\)\.hidden = state\.platform\.platform !== 'win32'/);
 assert.match(html,/id="windowsPinnedProfileCard" hidden/);
 for(const id of ['windowsPinnedCa','windowsPinnedCN','windowsPinnedHost','windowsPinnedPort','windowsPinnedProtocol','windowsPinnedInspectButton','windowsPinnedStatus']){
  assert.match(html,new RegExp('id="'+id+'"'));
 }
 assert.match(html,/An offline match is not a real TLS handshake/);
 assert.match(renderer,/NO VPN connection or live server identity verified/);
});

test('Windows Electron backend privately inspects a synthetic pinned AUTLOGIN .ovpn without persisting the key', {
 skip:process.platform!=='win32'
},async()=>{
 const os=require('node:os');
 const Backend=require('../src/main/platform-backend');
 const temp=fs.mkdtempSync(path.join(os.tmpdir(),'oig-windows-operator-inspect-'));
 try{
  const script=[
   "$ErrorActionPreference='Stop'",
   "$rsa=[Security.Cryptography.RSA]::Create(2048)",
   "try {",
   " $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=QA-only',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,[Security.Cryptography.RSASignaturePadding]::Pkcs1)",
   " $now=[DateTimeOffset]::UtcNow",
   " $cert=$req.CreateSelfSigned($now.AddMinutes(-1),$now.AddMinutes(20))",
   " try {",
   "  $pem=$cert.ExportCertificatePem().Trim()",
   "  $key=$rsa.ExportPkcs8PrivateKeyPem().Trim()",
   "  $der=$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)",
   "  $sha=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($der)).ToLowerInvariant()",
   "  $lines=@('client','dev tun','proto tcp-client','remote vpn.example.test 443','nobind','remote-cert-tls server','verify-x509-name tls.vpn.example.test name','cipher AES-256-GCM','data-ciphers AES-256-GCM:AES-128-GCM','auth SHA256','<ca>',$pem,'</ca>','<cert>',$pem,'</cert>','<key>',$key,'</key>')",
   "  [IO.File]::WriteAllText((Join-Path $env:OIG_SYNTH_DIR 'synthetic.ovpn'),($lines -join [char]10),[Text.UTF8Encoding]::new($false))",
   "  [pscustomobject]@{caSha256=$sha;peerCN='tls.vpn.example.test';host='vpn.example.test';port=443;protocol='tcp'} | ConvertTo-Json -Compress",
   " } finally {$cert.Dispose()}",
   "} finally {$rsa.Dispose()}"
  ].join('\n');
  const made=spawnSync('pwsh',['-NoProfile','-NonInteractive','-Command',script],{
   env:{...process.env,OIG_SYNTH_DIR:temp},encoding:'utf8',timeout:15000,windowsHide:true
  });
  assert.equal(made.status,0,made.stderr);
  assert.doesNotMatch(made.stdout,/PRIVATE KEY/);
  const pins=JSON.parse(made.stdout.trim());
  const profile=path.join(temp,'synthetic.ovpn');
  const b=new Backend({version:'offline-QA',resourcesPath:temp,appPath:root,userData:temp});
  b.backendRoot=path.join(root,'backend','windows');
  const previous=fs.readdirSync(temp).sort();
  const originalBytes=fs.readFileSync(profile);
  const result=await b.inspectWindowsPinnedAutologinProfile(profile,pins);
  assert.equal(result.inspectedOffline,true);
  assert.equal(result.valid,true);
  assert.equal(result.pinnedConstraintsMatch,true);
  assert.equal(result.serverIdentityVerified,false);
  assert.equal(result.transportAttempted,false);
  assert.equal(result.readyForAutomaticConnection,false);
  assert.equal(result.profilePersisted,false);
  assert.equal(result.profileSha256,require('node:crypto').createHash('sha256').update(fs.readFileSync(profile)).digest('hex'));
  assert.deepEqual(fs.readdirSync(temp).sort(),previous,'no private key or profile copied to disk');
  assert.equal(b.operatorProfileTaskBusy,false);
  assert.doesNotMatch(JSON.stringify(result),/PRIVATE KEY/);
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(profile,{...pins,caSha256:'f'.repeat(64)}),
   /Profile rejected/);
  assert.equal(b.operatorProfileTaskBusy,false);
  fs.writeFileSync(profile,fs.readFileSync(profile,'utf8').replace('client\n','client\nauth-user-pass\n'));
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(profile,pins),/Profile rejected/);
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(profile,{...pins,port:0}),/Independently authenticated/);
  fs.writeFileSync(profile,'x'.repeat(131073));
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(profile,pins),/bounded regular file/);
  // No network/device paths should reach lstat/open at all.
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(
    '\\\\remote.example.test\\share\\profile.ovpn',pins),/Select a local/);
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(
    '\\\\?\\C:\\Temp\\profile.ovpn',pins),/Select a local/);
  // Reject invalid UTF-8 bytes instead of silently replacing them.
  fs.writeFileSync(profile,Buffer.concat([
    Buffer.from('client\n'),Buffer.from([0xff]),originalBytes.subarray(7)
  ]));
  await assert.rejects(b.inspectWindowsPinnedAutologinProfile(profile,pins),/valid UTF-8/);
  fs.writeFileSync(profile,originalBytes);
  // Deterministically replace the chosen file after lstat but just before
  // open: this must fail by file identity, without running PowerShell.
  const savedOpen=fs.openSync;
  const backup=profile+'.previous';
  let swapped=false;
  fs.openSync=function(file,...args){
    if(!swapped && file===profile){
      swapped=true;
      fs.renameSync(profile,backup);
      fs.writeFileSync(profile,originalBytes);
    }
    return savedOpen.call(fs,file,...args);
  };
  try{
    await assert.rejects(b.inspectWindowsPinnedAutologinProfile(profile,pins),
      /file identity or size changed before inspection/);
  }finally{
    fs.openSync=savedOpen;
    if(swapped){
      fs.unlinkSync(profile);
      fs.renameSync(backup,profile);
    }
  }
  assert.equal(swapped,true);
  assert.equal(b.operatorProfileTaskBusy,false);
  assert.deepEqual(fs.readdirSync(temp).sort(),previous);
 }finally{fs.rmSync(temp,{recursive:true,force:true});}
});
