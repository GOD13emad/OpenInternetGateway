# Disposable runner only: prove that verified OpenVPN Community 2.7.9 for
# Windows can be invoked headlessly and exposes password-management options.
# This DOES NOT connect a VPN, install a service, or change owner networks.
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
  $routesAfter=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')} |
    Sort-Object DestinationPrefix,InterfaceIndex |
    Select-Object DestinationPrefix,InterfaceIndex,NextHop | ConvertTo-Json -Compress)
  $postService=@(Get-Service 'OpenVPNService','OpenVPNServiceInteractive' -ErrorAction SilentlyContinue |
    Select-Object Name,Status | ConvertTo-Json -Compress)
  if([string]$routesBefore -cne [string]$routesAfter){throw 'DISPOSABLE_WINDOWS_ROUTES_CHANGED'}
  if([string]$preExistingService -cne [string]$postService){throw 'OPENVPN_SERVICE_CHANGED_BY_READONLY_PROBE'}
  $result=[ordered]@{
    schema='oig-windows-community-engine-offline-feasibility-v1'
    sourceSha=$env:GITHUB_SHA;version=$release
    msiSHA256=$expectedHash;openvpnExeSHA256=$expectedExe
    primarySigningKeyFingerprint=$vendorPrimaryFingerprint
    sourceReleaseHashVerifiedAgainstGpgSignedMSI=$true
    binaryExecutedVersionAndHelpOnly=$true
    availableOptions=$matched
    passwordManagementFeatureProbedLive=$false
    serverTlsHandshakeAttempted=$false
    userVpnConnected=$false
    networkRoutesUnchanged=$true
    serviceOrDriverInstalled=$false
    productEngineSwitched=$false
    result='PASS_OFFLINE_FEASIBILITY_ONLY'
  }
  [IO.File]::WriteAllText($Receipt,($result|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
  Write-Output 'VERIFIED_OFFICIAL_OPENVPN_2_7_9_WINDOWS_PASSWORD_OPTIONS_PRESENT'
}finally{
  Remove-Item -LiteralPath $archive -Recurse -Force -ErrorAction SilentlyContinue
}
# OpenVPN's --help can return 1 even when all required flags were correctly
# displayed. A verified success receipt, not the native help exit code, decides
# whether this disposable feasibility step succeeded.
exit 0
