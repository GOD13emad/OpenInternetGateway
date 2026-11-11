# Disposable runner only: verify pinned native Community OpenVPN 2.7.9,
# synthetic local TLS/password challenge, and QA app-owned process/management
# lifecycle. No VPN, TUN, system service, privilege or owner-network change.
[CmdletBinding()]
param([string]$Receipt = '')
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($item in @(
  @('GITHUB_ACTIONS','true'),
  @('RUNNER_OS','Windows'),
  @('RUNNER_ENVIRONMENT','github-hosted'),
  @('GITHUB_REPOSITORY','GOD13emad/OpenInternetGateway')
)){
  if([Environment]::GetEnvironmentVariable($item[0]) -ne $item[1]){
    throw ('DISPOSABLE_WINDOWS_RUNNER_REQUIRED_'+$item[0])
  }
}
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){
  throw 'DOMAIN_JOINED_HOST_REFUSED'
}
if(-not $env:RUNNER_TEMP){throw 'RUNNER_TEMP_MISSING'}
if(-not $Receipt){
  $Receipt=Join-Path $env:RUNNER_TEMP 'oig-community-engine-feasibility.json'
}
$expectedHash='47abc38a15c217b848fe099332a8523500fcbf2ebf8a1eaa7d5648c6e75079aa'
$expectedExe='0b9b5ad60279b912ae826da5e13a57750fdc918d9ec28b73f031aaffef8dd485'
$release='2.7.9-I001'
$vendorPrimaryFingerprint='F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7'
$download='https://build.openvpn.net/downloads/releases/OpenVPN-2.7.9-I001-amd64.msi'
$archive=Join-Path $env:RUNNER_TEMP ('oig-community-offline-'+$env:GITHUB_RUN_ID)
if(Test-Path -LiteralPath $archive){throw 'SCRATCH_EXISTS'}
if(Test-Path -LiteralPath $Receipt){throw 'RECEIPT_EXISTS'}
New-Item -ItemType Directory -Path $archive -Force|Out-Null
$routesBefore=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')} |
  Sort-Object DestinationPrefix,InterfaceIndex |
  Select-Object DestinationPrefix,InterfaceIndex,NextHop | ConvertTo-Json -Compress)
$preExistingService=@(Get-Service 'OpenVPNService','OpenVPNServiceInteractive' -ErrorAction SilentlyContinue |
  Select-Object Name,Status | ConvertTo-Json -Compress)
try{
  $msi=Join-Path $archive 'OpenVPN-2.7.9-I001-amd64.msi'
  $iwr=@{Uri=$download;OutFile=$msi;TimeoutSec=80;MaximumRedirection=0;ErrorAction='Stop'}
  Invoke-WebRequest @iwr | Out-Null
  if((Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash){
    throw 'OPENVPN_RELEASE_MSI_SHA_MISMATCH'
  }
  if((Get-Item -LiteralPath $msi).Length -ne 5906432){
    throw 'OPENVPN_RELEASE_MSI_SIZE_MISMATCH'
  }
  $seven=if(Test-Path 'C:\Program Files\7-Zip\7z.exe'){
    'C:\Program Files\7-Zip\7z.exe'
  }else{
    $cmd=Get-Command 7z.exe -ErrorAction SilentlyContinue
    if(-not $cmd){throw '7ZIP_NOT_AVAILABLE_ON_DISPOSABLE_RUNNER'}
    $cmd.Source
  }
  $payload=Join-Path $archive 'payload'
  New-Item -ItemType Directory -Path $payload -Force|Out-Null
  & $seven x -y -bd ('-o'+$payload) $msi 'bin.openvpn.exe' '*.dll' | Out-Null
  if($LASTEXITCODE){throw 'MSI_PORTABLE_EXTRACTION_FAILED'}
  $binary=Join-Path $payload 'bin.openvpn.exe'
  if(-not(Test-Path -LiteralPath $binary)){
    throw 'COMMUNITY_OPENVPN_PE_MISSING'
  }
  if((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedExe){
    throw 'VERIFIED_MSI_OPENVPN_EXE_MISMATCH'
  }
  # 7-Zip exports MSI logical file IDs with underscores, but the authenticated
  # PE import table explicitly requires these exact hyphenated DLL names.
  # Reconstruct only this known vendor layout; no OS installation or PATH edit.
  $dllNames=[ordered]@{
    'libcrypto_3_x64.dll'='libcrypto-3-x64.dll'
    'libssl_3_x64.dll'='libssl-3-x64.dll'
    'libpkcs11_helper_1.dll'='libpkcs11-helper-1.dll'
  }
  foreach($key in $dllNames.Keys){
    $source=Join-Path $payload $key
    $target=Join-Path $payload $dllNames[$key]
    if(-not(Test-Path -LiteralPath $source -PathType Leaf) -or
       (Test-Path -LiteralPath $target)){throw ('SIGNED_MSI_DLL_LAYOUT_INVALID_'+$key)}
    Move-Item -LiteralPath $source -Destination $target
  }
  $exe=Join-Path $payload 'openvpn.exe'
  Move-Item -LiteralPath $binary -Destination $exe
  $version=(& $exe --version 2>&1 | Out-String)
  if($version -notmatch 'OpenVPN 2\.7\.9'){
    throw ('OPENVPN_VERSION_NOT_EXECUTABLE_EXIT_'+$LASTEXITCODE+'_OUTPUT_'+$version.Substring(0,[Math]::Min(160,$version.Length)))
  }
  $help=(& $exe --help 2>&1 | Out-String)
  $required=@('auth-user-pass','management-query-passwords','verify-x509-name','remote-cert-tls','route-noexec')
  $matched=[ordered]@{}
  foreach($flag in $required){
    $matched[$flag]=($help.Contains($flag))
    if(-not $matched[$flag]){throw ('WINDOWS_COMMUNITY_CLI_FLAG_MISSING_'+$flag)}
  }
  # Exercise verified native 2.7.9 as an actual localhost TLS client and
  # server. Synthetic password challenge is answered over management TCP;
  # both negative cases must fail closed. dev null prevents tunnel creation.
  $python=(Get-Command python.exe -ErrorAction Stop).Source
  $opensslCandidates=@(
    (Get-Command openssl.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source),
    'C:\Program Files\Git\usr\bin\openssl.exe',
    'C:\Program Files\Git\mingw64\bin\openssl.exe'
  )
  $openssl=@($opensslCandidates | Where-Object {$_ -and (Test-Path -LiteralPath $_ -PathType Leaf)} | Select-Object -First 1)
  if($openssl.Count -ne 1){throw 'OPENSSL_UNAVAILABLE_IN_DISPOSABLE_WINDOWS_RUNNER'}
  $localReceipt=Join-Path $env:RUNNER_TEMP 'oig-community-loopback-receipt.json'
  if(Test-Path -LiteralPath $localReceipt){throw 'LOCAL_LOOPBACK_RECEIPT_ALREADY_EXISTS'}
  $localSmoke=Join-Path (Get-Location) 'tests/windows-community-engine-loopback.py'
  if(!(Test-Path -LiteralPath $localSmoke -PathType Leaf)){throw 'LOCAL_LOOPBACK_SCRIPT_MISSING'}
  & $python -B $localSmoke --openvpn $exe --openssl $openssl[0] --receipt $localReceipt
  if($LASTEXITCODE -ne 0){throw 'LOCAL_TLS_PASSWORD_MANAGEMENT_SMOKE_FAILED'}
  $proof=Get-Content -LiteralPath $localReceipt -Raw | ConvertFrom-Json
  if($proof.schema -cne 'oig-community-windows-loopback-v1' -or -not $proof.pass -or
     @($proof.cases).Count -ne 3 -or
     @($proof.cases|Where-Object { $_.mode -ne 'bad-cn' -and -not $_.managementPromptObserved }).Count -ne 0 -or
     @($proof.cases|Where-Object {$_.mode -eq 'valid' -and $_.tlsAccepted}).Count -ne 1 -or
     @($proof.cases|Where-Object {$_.mode -eq 'bad-cn' -and $_.identityRejected -and -not $_.tlsAccepted}).Count -ne 1 -or
     @($proof.cases|Where-Object {$_.mode -eq 'bad-password' -and $_.authRejected -and -not $_.tlsAccepted}).Count -ne 1){
    throw 'LOCAL_LOOPBACK_RECEIPT_NEGATIVE_CASE_NOT_ACCEPTED'
  }
  # Integration gate: own only the newly spawned portable OpenVPN process
  # and password-protected localhost management channel. The synthetic VPN
  # credentials arrive by stdin; only a throwaway management token is filed
  # in private QA scratch, then removed during rollback.
  $node=(Get-Command node.exe -ErrorAction Stop).Source
  $controllerReceipt=Join-Path $env:RUNNER_TEMP 'oig-community-controller-loopback-receipt.json'
  if(Test-Path -LiteralPath $controllerReceipt){throw 'OWNED_CONTROLLER_RECEIPT_EXISTS'}
  & $python -B $localSmoke --openvpn $exe --openssl $openssl[0] --receipt $controllerReceipt --controller-node --node-bin $node
  if($LASTEXITCODE -ne 0){throw 'OWNED_COMMUNITY_CONTROLLER_LOCAL_TLS_FAILED'}
  $control=Get-Content -LiteralPath $controllerReceipt -Raw | ConvertFrom-Json
  if($control.schema -cne 'oig-community-controller-loopback-v1' -or
     -not $control.pass -or -not $control.appOwnedManagementClientTested -or
     @($control.cases).Count -ne 3 -or
     @($control.cases | Where-Object {
       $_.schema -cne 'oig-community-controller-qa-v1' -or
       -not $_.managementConnected -or -not $_.managementHoldObserved -or
       -not $_.managementPromptObserved -or
       -not $_.ownedProcessStopped -or
       -not $_.closedManagementListener -or
       -not $_.managementPasswordProtected -or
       -not $_.managementTokenErased -or
       -not $_.devNull -or -not $_.routesNotExecuted -or
       $_.productionEngineChanged -or $_.independentPublicServerVerified
     }).Count -ne 0 -or
     @($control.cases | Where-Object {$_.mode -eq 'valid' -and $_.tlsAccepted -and -not $_.identityRejected -and -not $_.authRejected}).Count -ne 1 -or
     @($control.cases | Where-Object {$_.mode -eq 'bad-cn' -and $_.identityRejected -and -not $_.tlsAccepted}).Count -ne 1 -or
     @($control.cases | Where-Object {$_.mode -eq 'bad-password' -and $_.authRejected -and -not $_.tlsAccepted}).Count -ne 1){
    throw 'OWNED_COMMUNITY_CONTROLLER_RECEIPT_INVALID'
  }
  $routesAfter=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')} |
    Sort-Object DestinationPrefix,InterfaceIndex |
    Select-Object DestinationPrefix,InterfaceIndex,NextHop | ConvertTo-Json -Compress)
  $postService=@(Get-Service 'OpenVPNService','OpenVPNServiceInteractive' -ErrorAction SilentlyContinue |
    Select-Object Name,Status | ConvertTo-Json -Compress)
  if([string]$routesBefore -cne [string]$routesAfter){throw 'DISPOSABLE_WINDOWS_ROUTES_CHANGED'}
  if([string]$preExistingService -cne [string]$postService){throw 'OPENVPN_SERVICE_CHANGED_BY_READONLY_PROBE'}
  $result=[ordered]@{
    schema='oig-windows-community-engine-offline-feasibility-v3'
    sourceSha=$env:GITHUB_SHA;version=$release
    msiSHA256=$expectedHash;openvpnExeSHA256=$expectedExe
    primarySigningKeyFingerprint=$vendorPrimaryFingerprint
    sourceReleaseHashVerifiedAgainstGpgSignedMSI=$true
    binaryExecutedVersionAndHelpOnly=$false
    availableOptions=$matched
    passwordManagementFeatureProbedLive=$true
    serverTlsHandshakeAttempted=$true
    userVpnConnected=$false
    networkRoutesUnchanged=$true
    serviceOrDriverInstalled=$false
    productEngineSwitched=$false
    loopbackReceiptSHA256=(Get-FileHash -LiteralPath $localReceipt -Algorithm SHA256).Hash.ToLowerInvariant()
    localSyntheticTlsAndManagementOnly=$true
    applicationOwnedManagementClientSyntheticOnly=$true
    controllerReceiptSHA256=(Get-FileHash -LiteralPath $controllerReceipt -Algorithm SHA256).Hash.ToLowerInvariant()
    ownerNetworkUntouched=$true
    independentlyTrustedRemoteServer=$false
    result='PASS_LOCAL_SYNTHETIC_TLS_AND_APP_OWNED_MANAGEMENT_ONLY'
  }
  [IO.File]::WriteAllText($Receipt,($result|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
  Write-Output 'PASS_PINNED_OPENVPN_2_7_9_APP_OWNED_LOCAL_TLS_MANAGEMENT'
}finally{
  Remove-Item -LiteralPath $archive -Recurse -Force -ErrorAction SilentlyContinue
}
# OpenVPN's --help can return 1 even when all required flags were correctly
# displayed. A verified success receipt, not the native help exit code, decides
# whether this disposable feasibility step succeeded.
exit 0
