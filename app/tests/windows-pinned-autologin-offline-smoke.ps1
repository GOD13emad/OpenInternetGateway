# Native offline-only ephemeral certificate tests, no VPN/route/service or disk writes.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\backend\windows\scripts\Operator-PinnedProfile.ps1')
$rsa=[Security.Cryptography.RSA]::Create(2048)
try{
 $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
  'CN=Unit-Test-OffLine-CA',$rsa,[Security.Cryptography.HashAlgorithmName]::SHA256,
  [Security.Cryptography.RSASignaturePadding]::Pkcs1)
 $now=[DateTimeOffset]::UtcNow
 $cert=$req.CreateSelfSigned($now.AddMinutes(-1),$now.AddMinutes(25))
 try{
  $pem=$cert.ExportCertificatePem().Trim()
  $key=$rsa.ExportPkcs8PrivateKeyPem().Trim()
  $der=$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  $caHash=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($der)).ToLowerInvariant()
  $remoteHost='vpn.example.test';$peer='tls.vpn.example.test';$port=443
  $profile=@(
   'client','dev tun','proto tcp-client','remote vpn.example.test 443','nobind',
   'remote-cert-tls server',('verify-x509-name '+$peer+' name'),
   'cipher AES-256-GCM','data-ciphers AES-256-GCM:AES-128-GCM','auth SHA256',
   '<ca>',$pem,'</ca>','<cert>',$pem,'</cert>','<key>',$key,'</key>'
  ) -join [char]10
  $n=0
  function Check($label,[bool]$valid,[string]$profileText,$sha=$caHash,$name=$peer,$server=$remoteHost,$portNumber=$port,$proto='tcp') {
   $r=Test-OigPinnedAutologinProfile -Text $profileText -ExpectedHost $server -ExpectedPort $portNumber -ExpectedProtocol $proto -PinnedCaSha256 $sha -ExpectedPeerCN $name
   if($null -eq $r -or [bool]$r.valid -ne $valid){throw ('PINNED_PROFILE_CASE_FAILED '+$label)}
   if($r.serverIdentityVerified -ne $false -or $r.transportAttempted -ne $false -or $r.readyForAutomaticConnection -ne $false){throw ('FALSE_TRUST_CLAIM '+$label)}
   if($valid -and (-not $r.pinnedConstraintsMatch -or $r.caDerSha256 -cne $sha -or $r.expectedPeerCN -cne $name)){throw ('PIN_MISMATCH '+$label)}
   $script:n++
   Write-Output ('OFFLINE_PINNED_PROFILE_CASE '+$label+' PASS')
  }
  Check 'exact-pinned-cert-autologin' $true $profile
  Check 'CRLF-line-endings' $true ($profile.Replace([string][char]10,([string][char]13+[string][char]10)))
  Check 'unpinned-ca' $false $profile ('a'*64)
  Check 'peer-CN-changed' $false $profile $caHash 'attacker.example.test'
  Check 'remote-host-changed' $false $profile $caHash $peer 'other.example.test'
  Check 'remote-port-changed' $false $profile $caHash $peer $remoteHost 1194
  Check 'remote-protocol-changed' $false $profile $caHash $peer $remoteHost 443 'udp'
  Check 'username-password-interactive' $false ($profile.Replace('client','client'+[char]10+'auth-user-pass'))
  Check 'credentials-file' $false ($profile.Replace('client','client'+[char]10+'auth-user-pass creds.txt'))
  Check 'script-hook' $false ($profile.Replace('client','client'+[char]10+'script-security 2'))
  Check 'route-push' $false ($profile.Replace('client','client'+[char]10+'redirect-gateway def1'))
  Check 'shell-hook' $false ($profile.Replace('client','client'+[char]10+'up command.exe'))
  Check 'duplicate-remote' $false ($profile.Replace('nobind','remote vpn.example.test 443'+[char]10+'nobind'))
  Check 'wrong-server-cert-role' $false ($profile.Replace('remote-cert-tls server','remote-cert-tls client'))
  Check 'missing-exact-name' $false ($profile.Replace('verify-x509-name '+$peer+' name',''))
  Check 'weak-HMAC' $false ($profile.Replace('auth SHA256','auth SHA1'))
  Check 'weak-cipher' $false ($profile.Replace('cipher AES-256-GCM','cipher AES-128-CBC'))
  Check 'missing-inline-key' $false ($profile.Substring(0,$profile.IndexOf('<key>')))
  Check 'duplicate-ca-block' $false ($profile + [char]10 + '<ca>' + [char]10 + $pem + [char]10 + '</ca>')
  Check 'NUL-byte' $false ($profile+[char]0)
  Check 'control-character' $false ($profile+[char]7)
  Check 'oversize' $false ($profile+('x'*131072))
  Check 'malformed-CA' $false ($profile.Replace($pem,'-----BEGIN CERTIFICATE-----'+[char]10+'!!!!!'+[char]10+'-----END CERTIFICATE-----'))
  Check 'raw-CR' $false ($profile+[char]13+'extra')
  Check 'inline-PowerShell-expression' $false ($profile.Replace('client','client'+[char]10+'$(Get-Process)'))
  Check 'missing-client-block' $false ($profile.Replace('<cert>','<ignored>'))
  $otherRsa=[Security.Cryptography.RSA]::Create(2048)
  try{
   $unpairedKey=$otherRsa.ExportPkcs8PrivateKeyPem().Trim()
   Check 'client-key-does-not-match-cert' $false ($profile.Replace($key,$unpairedKey))
  }finally{$otherRsa.Dispose()}
  $badKey=$key.Replace('-----END PRIVATE KEY-----','-----END RSA PRIVATE KEY-----')
  Check 'private-key-marker-mismatch' $false ($profile.Replace($key,$badKey))
  Check 'private-key-invalid-base64' $false ($profile.Replace($key, '-----BEGIN PRIVATE KEY-----'+[char]10+'****'+[char]10+'-----END PRIVATE KEY-----'))
  if($script:n -ne 29){throw ('BAD_TEST_COUNT '+$script:n)}
  Write-Output 'WIN_PINNED_OFFLINE_29_PASS'
 }finally{$cert.Dispose()}
}finally{$rsa.Dispose()}
