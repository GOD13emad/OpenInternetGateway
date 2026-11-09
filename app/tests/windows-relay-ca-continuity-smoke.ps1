# Isolated PowerShell 7 regression; no route, VPN, admin, disk or network writes.
param([switch]$ValidateSeededPool)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\backend\windows\scripts\Profile-Policy.ps1')
$script:passed=0
function Check([bool]$Ok,[string]$Label){
 if(-not $Ok){throw ('CA_CONTINUITY_FAIL '+$Label)}
 $script:passed++
 Write-Output ('CA_CONTINUITY_CASE '+$Label+' PASS')
}
function New-TestCa {
 $rsa=[Security.Cryptography.RSA]::Create(2048)
 try{
   $req=[Security.Cryptography.X509Certificates.CertificateRequest]::new(
      'CN=Offline-CA-For-Unit-Test',$rsa,
      [Security.Cryptography.HashAlgorithmName]::SHA256,
      [Security.Cryptography.RSASignaturePadding]::Pkcs1)
   $now=[DateTimeOffset]::UtcNow
   $cert=$req.CreateSelfSigned($now.AddMinutes(-1),$now.AddMinutes(30))
   try{
     $der=$cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
     $nl=[string][char]10
     $pem="-----BEGIN CERTIFICATE-----"+$nl+[Convert]::ToBase64String($der,[Base64FormattingOptions]::InsertLineBreaks)+$nl+"-----END CERTIFICATE-----"
     return "<ca>"+$nl+$pem+$nl+"</ca>"
   }finally{$cert.Dispose()}
 }finally{$rsa.Dispose()}
}
$a=New-TestCa;$b=New-TestCa
$caA=[string](Get-OigVpnProfileCaSha256 -Text $a)
$caB=[string](Get-OigVpnProfileCaSha256 -Text $b)
Check ($caA -match '^[0-9a-f]{64}$') 'parsed-CA-DER-SHA256'
Check ($caA -eq (Get-OigVpnProfileCaSha256 -Text $a)) 'stable-same-CA'
$crlf=[regex]::Replace($a,'\r?\n',([string][char]13+[string][char]10))
Check ($caA -eq (Get-OigVpnProfileCaSha256 -Text $crlf)) 'real-VPNGate-CRLF-CA'
$withBlank=$crlf.Replace('</ca>',([string][char]13+[string][char]10)+'</ca>')
Check ($caA -eq (Get-OigVpnProfileCaSha256 -Text $withBlank)) 'real-VPNGate-CRLF-and-blank-CA'
Check ($caA -ne $caB) 'different-CAs-have-distinct-pins'
Check ('' -eq (Get-OigVpnProfileCaSha256 -Text 'not-a-profile')) 'missing-CA-denied'
Check ('' -eq (Get-OigVpnProfileCaSha256 -Text '<ca>invalid</ca>')) 'malformed-CA-denied'
Check ('' -eq (Get-OigVpnProfileCaSha256 -Text ($a+[char]10+$a))) 'duplicate-CA-denied'
$shaA=('a'*64);$shaB=('b'*64)
$none=@{}
$prior=@{};$prior[$shaA]=@{ip='192.0.2.10';port=1194;caSha256=$caA}
$legacy=@{};$legacy[$shaA]=@{ip='192.0.2.10';port=1194}
function Allow([hashtable]$Map,[string]$IP,[int]$Port,[string]$Sha,[string]$Pin){
 return [bool](Test-OigKnownRelayCaContinuity -IP $IP -Port $Port -ProfileSha256 $Sha -CaSha256 $Pin -KnownSuccesses $Map)
}
Check (Allow $none '192.0.2.10' 1194 $shaB $caB) 'first-contact-is-allowed-not-trusted'
Check (Allow $prior '192.0.2.10' 1194 $shaB $caA) 'same-known-CA-allowed'
Check (-not (Allow $prior '192.0.2.10' 1194 $shaB $caB)) 'changed-CA-denied'
Check (Allow $legacy '192.0.2.10' 1194 $shaA $caA) 'legacy-exact-profile-reconnects'
Check (-not (Allow $legacy '192.0.2.10' 1194 $shaB $caA)) 'legacy-profile-change-without-pin-denied'
Check (Allow $prior '192.0.2.11' 1194 $shaB $caB) 'independent-new-endpoint-allowed'
Check (Allow $prior '192.0.2.10' 1195 $shaB $caB) 'different-port-is-different-endpoint'
Check (-not (Allow $none '192.0.2.10' 1194 $shaB 'bad')) 'missing-fingerprint-fail-closed'
Check (-not (Allow $none '192.0.2.10' 1194 'bad' $caA)) 'invalid-profile-sha-fail-closed'
$contradictory=@{};$contradictory[$shaA]=@{ip='192.0.2.10';port=1194;caSha256=$caA}
$contradictory[$shaB]=@{ip='192.0.2.10';port=1194;caSha256=$caB}
Check (-not (Allow $contradictory '192.0.2.10' 1194 ('c'*64) $caA)) 'conflicting-history-denied'
if($script:passed -ne 18){throw 'Unexpected offline case count'}
Write-Output ('CA_CONTINUITY_PASS '+$script:passed)

if($ValidateSeededPool){
  # Validate the real public cache fed to this disposable Windows CI run.
  # Read-only: never invoke Connect, OpenVPN service or update owner network.
  $backendRoot=Join-Path $PSScriptRoot '..\backend\windows'
  $cache=Join-Path $backendRoot 'runtime\udp-cache'
  $idx=Join-Path $cache 'index.json'
  if(-not(Test-Path -LiteralPath $idx)){throw 'SEEDED_CA_INDEX_MISSING'}
  $entries=@(Get-Content -LiteralPath $idx -Raw | ConvertFrom-Json)
  if($entries.Count -lt 3){throw 'SEEDED_CA_POOL_TOO_SMALL'}
  $passedSeed=0
  foreach($item in $entries){
    $full=Join-Path $backendRoot ([string]$item.Profile)
    if([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($full)).TrimEnd('\') -ne [IO.Path]::GetFullPath($cache).TrimEnd('\')){
      throw 'SEEDED_CA_PROFILE_PATH_ESCAPE'
    }
    if(-not(Test-Path -LiteralPath $full -PathType Leaf)){throw 'SEEDED_CA_PROFILE_MISSING'}
    if((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string]$item.SHA256).ToLowerInvariant()){
      throw 'SEEDED_CA_PROFILE_SHA_MISMATCH'
    }
    $profile=[IO.File]::ReadAllText($full)
    if(-not(Test-OigVpnProfile -Text $profile -ExpectedIP ([string]$item.IP) -ExpectedPort ([int]$item.Port) -ExpectedProtocol ([string]$item.Protocol))){
      throw 'SEEDED_CA_PROFILE_POLICY_DENIED'
    }
    if((Get-OigVpnProfileCaSha256 -Text $profile) -notmatch '^[a-f0-9]{64}$'){
      throw 'SEEDED_CA_PROFILE_CERT_INVALID'
    }
    $passedSeed++
  }
  Write-Output ('SEEDED_CA_PROFILES_PASS '+$passedSeed)
}
