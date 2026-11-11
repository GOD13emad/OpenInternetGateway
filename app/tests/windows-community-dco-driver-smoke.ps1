# Hosted Windows ONLY: pinned vendor MSI, ovpn-dco adapter, owned teardown.
# No VPN connect, default route, DNS, user credential or product-engine change.
[CmdletBinding()]
param([string]$Receipt='', [switch]$ProbeTun, [switch]$ProbeFullIpv4, [switch]$ProbeLeakPolicy)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
foreach($pair in @(
 @('GITHUB_ACTIONS','true'), @('RUNNER_OS','Windows'),
 @('RUNNER_ENVIRONMENT','github-hosted'),
 @('GITHUB_REPOSITORY','GOD13emad/OpenInternetGateway'),
 @('GITHUB_HEAD_REF','qa/v2.5.20-operator-safety-20261019')
)){
 if([Environment]::GetEnvironmentVariable($pair[0]) -cne $pair[1]){
  throw ('HOSTED_WINDOWS_ONLY_'+$pair[0])
 }
}
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'DOMAIN_JOINED_HOST_REFUSED'}
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){
 throw 'DISPOSABLE_RUNNER_ADMIN_REQUIRED'
}
if(-not $env:RUNNER_TEMP){throw 'RUNNER_TEMP_NOT_SET'}
$selectedQaModes=0
if($ProbeTun){$selectedQaModes+=1}
if($ProbeFullIpv4){$selectedQaModes+=1}
if($ProbeLeakPolicy){$selectedQaModes+=1}
if($selectedQaModes -gt 1){throw 'CANNOT_COMBINE_DISPOSABLE_DCO_QA_MODES'}
if(-not $Receipt){$Receipt=Join-Path $env:RUNNER_TEMP 'oig-dco-driver-lifecycle.json'}
if((Split-Path -Parent $Receipt) -cne $env:RUNNER_TEMP -or (Test-Path -LiteralPath $Receipt)){
 throw 'RECEIPT_NOT_PRIVATE_OR_EXISTS'
}
$expectedMsi='47abc38a15c217b848fe099332a8523500fcbf2ebf8a1eaa7d5648c6e75079aa'
$expectedExe='0b9b5ad60279b912ae826da5e13a57750fdc918d9ec28b73f031aaffef8dd485'
$msiUrl='https://build.openvpn.net/downloads/releases/OpenVPN-2.7.9-I001-amd64.msi'
$services=@('OpenVPNService','OpenVPNServiceInteractive','OpenVPNServiceLegacy','OpenVPNServiceUser')
$installedExe='C:\Program Files\OpenVPN\bin\openvpn.exe'
$tapctl='C:\Program Files\OpenVPN\bin\tapctl.exe'
$alias='OIG-QA-DCO-'+$env:GITHUB_RUN_ID
if($alias -notmatch '^OIG-QA-DCO-[0-9]{7,16}$'){throw 'UNEXPECTED_RUN_ID'}
if(@(Get-Service -Name $services -ErrorAction SilentlyContinue).Count -gt 0 -or
   (Test-Path -LiteralPath $installedExe) -or
   @(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
     $_.InterfaceDescription -match 'OpenVPN|Data Channel Offload|TAP-Windows' -or
     $_.Name -like 'OIG-QA-DCO-*'
   }).Count -gt 0){
 throw 'PREEXISTING_VPN_INSTALL_REFUSED'
}
$hostAdapters=@(Get-NetAdapter -ErrorAction Stop | Where-Object {$_.Status -eq 'Up'})
if($hostAdapters.Count -lt 1){throw 'NO_ACTIVE_HOST_NETWORK'}
$hostIndices=@($hostAdapters | ForEach-Object {[int]$_.ifIndex})
function Read-HostNetwork {
 $routes=@(Get-NetRoute -ErrorAction Stop | Where-Object {
   $_.DestinationPrefix -in @('0.0.0.0/0','::/0','0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')
 } | Sort-Object AddressFamily,DestinationPrefix,InterfaceIndex,NextHop |
 ForEach-Object {"$($_.AddressFamily)|$($_.DestinationPrefix)|$($_.InterfaceIndex)|$($_.NextHop)"})
 $dns=@(Get-DnsClientServerAddress -ErrorAction Stop |
  Where-Object {$_.InterfaceIndex -in $hostIndices} |
  Sort-Object InterfaceIndex,AddressFamily |
  ForEach-Object {"$($_.InterfaceIndex)|$($_.AddressFamily)|$($_.ServerAddresses -join ',')"})
 return @{routes=$routes;dns=$dns}
}
function Same-List($a,$b) {
 return ((@($a) | ConvertTo-Json -Compress) -ceq (@($b) | ConvertTo-Json -Compress))
}
function Run-Msi([string]$verb,[string]$package) {
 $args=@($verb,('"' + $package + '"'),'/qn','/norestart')
 $proc=Start-Process -FilePath msiexec.exe -ArgumentList $args -PassThru -ErrorAction Stop
 if(-not $proc.WaitForExit(210000)){try{$proc.Kill()}catch{};throw ('MSI_'+$verb+'_TIMEOUT')}
 if($proc.ExitCode -ne 0){throw ('MSI_'+$verb+'_EXIT_'+$proc.ExitCode)}
}
function Read-DcoDriverStore {
 return @(Get-WindowsDriver -Online -All -ErrorAction Stop |
  Where-Object {$_.OriginalFileName -match 'ovpn-dco\.inf'} |
  Sort-Object Driver |
  ForEach-Object {"$($_.Driver)|$($_.Version)|$($_.OriginalFileName)"})
}
$driverStoreBefore=@(Read-DcoDriverStore)
$before=Read-HostNetwork
$work=Join-Path $env:RUNNER_TEMP ('oig-dco-driver-'+$env:GITHUB_RUN_ID)
if(Test-Path -LiteralPath $work){throw 'DCO_SCRATCH_EXISTS'}
New-Item -ItemType Directory -Path $work -ErrorAction Stop | Out-Null
$msi=Join-Path $work 'OpenVPN-2.7.9-I001-amd64.msi'
$installAttempted=$false;$installed=$false;$ownedGuid='';$ownedCreated=$false
$adapterCreateAttempted=$false
$driverSigned=$false;$adapterVerified=$false;$removed=$false;$uninstalled=$false
$tunAccepted=$false
$fullIpv4Accepted=$false
$leakPolicyAccepted=$false
$leakPolicyReceipt=Join-Path $env:RUNNER_TEMP 'oig-dco-leak-policy.json'
$tunReceipt=Join-Path $env:RUNNER_TEMP 'oig-dco-scoped-tunnel.json'
$fullIpv4Receipt=Join-Path $env:RUNNER_TEMP 'oig-dco-fullroute-ipv4.json'
$networkRestored=$false;$servicesRestored=$false;$driverStoreRestored=$false;$failure=''
try {
 Invoke-WebRequest -Uri $msiUrl -OutFile $msi -TimeoutSec 90 -MaximumRedirection 0 -ErrorAction Stop | Out-Null
 if((Get-FileHash $msi -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedMsi){
  throw 'VENDOR_MSI_SHA256_MISMATCH'
 }
 if((Get-Item $msi).Length -ne 5906432){throw 'VENDOR_MSI_SIZE_MISMATCH'}
 $installAttempted=$true
 Run-Msi '/i' $msi
 $installed=$true
 if(-not(Test-Path -LiteralPath $installedExe -PathType Leaf) -or
    (Get-FileHash $installedExe -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedExe){
  throw 'INSTALLED_BINARY_PIN_MISMATCH'
 }
 if(-not(Test-Path -LiteralPath $tapctl -PathType Leaf)){throw 'TAPCTL_MISSING'}
 $adapterCreateAttempted=$true
 $created=@(& $tapctl create --hwid ovpn-dco --name $alias 2>&1)
 if($LASTEXITCODE -ne 0){throw 'TAPCTL_CREATE_FAILED'}
 $lineText=[string]::Join(' ',@($created | ForEach-Object {[string]$_}))
 if($lineText -notmatch '(\{[0-9a-fA-F-]{36}\})'){throw 'OWNED_GUID_MISSING'}
 $ownedGuid=$Matches[1]
 $ownedCreated=$true
 $lines=@(& $tapctl list --hwid ovpn-dco 2>&1)
 if($LASTEXITCODE -ne 0){throw 'TAPCTL_LIST_FAILED'}
 $matching=@($lines | ForEach-Object {[string]$_} | Where-Object {
  $_ -match [regex]::Escape($ownedGuid) -and
  $_ -match [regex]::Escape($alias) -and $_ -match 'ovpn-dco'
 })
 if($matching.Count -ne 1){throw 'OWNED_ADAPTER_NOT_LISTED'}
 $net=@(Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | Where-Object {
  $_.InterfaceGuid.ToString().Trim('{}') -ieq $ownedGuid.Trim('{}')
 })
 if($net.Count -ne 1){throw 'OWNED_ADAPTER_NOT_VISIBLE_TO_OS'}
 if($net[0].InterfaceDescription -notmatch 'OpenVPN|Data Channel Offload'){
  throw 'UNEXPECTED_ADAPTER_DRIVER'
 }
 # Win32_PnPSignedDriver.DeviceName is often NOT the adapter description.
 # Join actual InterfaceGuid -> Win32_NetworkAdapter.GUID -> PNPDeviceID,
 # then require the corresponding signed PnP driver, not a loosely named one.
 $nic=@(Get-CimInstance Win32_NetworkAdapter -ErrorAction Stop |
  Where-Object {$_.GUID -and $_.GUID.ToString().Trim('{}') -ieq $ownedGuid.Trim('{}')})
 if($nic.Count -ne 1){throw ('DCO_NETADAPTER_PNP_LINK_COUNT_'+$nic.Count)}
 if(-not $nic[0].PNPDeviceID){throw 'DCO_NETADAPTER_PNP_ID_MISSING'}
 $signed=@(Get-CimInstance Win32_PnPSignedDriver -ErrorAction Stop |
  Where-Object {$_.DeviceID -ieq $nic[0].PNPDeviceID})
 if($signed.Count -ne 1){throw ('DCO_PNP_SIGNED_DRIVER_LINK_COUNT_'+$signed.Count)}
 if(([string]$signed[0].IsSigned) -ine 'True'){
  throw 'DCO_PNP_DRIVER_SIGNATURE_FALSE'
 }
 # The ovpn-dco hardware ID was established by the exact GUID-matched
 # tapctl --hwid ovpn-dco listing. PnP InstanceId may have a generic name;
 # require the SAME NetAdapter PNPDeviceID and its verified signature.
 $driverSigned=$true;$adapterVerified=$true
 Write-Output 'HOSTED_VENDOR_DCO_ADAPTER_SIGNED_AND_VISIBLE'
 if($ProbeTun){
  if(Test-Path -LiteralPath $tunReceipt){throw 'DCO_TUN_RECEIPT_EXISTS'}
  $python=(Get-Command python.exe -ErrorAction Stop).Source
  $probe=Join-Path $PSScriptRoot 'windows-community-dco-tunnel-qa.py'
  if(-not(Test-Path -LiteralPath $probe -PathType Leaf)){
   throw 'DCO_TUN_SCRIPT_MISSING'
  }
  try {
   $env:OIG_HOSTED_DCO_DATA_QA='1'
   & $python -B $probe --root $work --openvpn $installedExe --adapter $alias --receipt $tunReceipt
   if($LASTEXITCODE -ne 0){throw 'DCO_TUN_NATIVE_PROBE_FAILED'}
  }finally{
   Remove-Item Env:\OIG_HOSTED_DCO_DATA_QA -ErrorAction SilentlyContinue
  }
  $e=Get-Content -LiteralPath $tunReceipt -Raw | ConvertFrom-Json
  if($e.schema -cne 'oig-hosted-windows-community-dco-scoped-dataplane-v1' -or
     -not $e.pass -or -not $e.peerIdentityVerified -or
     -not $e.tunnelIpAssigned -or -not $e.sourceBoundHttpsOverVpn -or
     -not $e.routeRemoved -or -not $e.vpnProcessStopped -or
     -not $e.defaultRoutesUnchanged -or -not $e.hostDnsUnchanged -or
     $e.productionEngineChanged -or $e.fullDeviceOrKillSwitchProven){
   throw 'DCO_SCOPED_TUN_RECEIPT_NOT_ACCEPTED'
  }
  $tunAccepted=$true
 }
 if($ProbeFullIpv4){
  if(Test-Path -LiteralPath $fullIpv4Receipt){throw 'FULL_IPV4_RECEIPT_EXISTS'}
  $python=(Get-Command python.exe -ErrorAction Stop).Source
  $probe=Join-Path $PSScriptRoot 'windows-community-dco-fullroute-qa.py'
  if(-not(Test-Path -LiteralPath $probe -PathType Leaf)){
   throw 'FULL_IPV4_QA_SCRIPT_MISSING'
  }
  try {
   $env:OIG_HOSTED_DCO_DATA_QA='1'
   $env:OIG_HOSTED_DCO_FULL_IPV4_QA='1'
   & $python -B $probe --root $work --openvpn $installedExe --adapter $alias --receipt $fullIpv4Receipt
   if($LASTEXITCODE -ne 0){throw 'FULL_IPV4_NATIVE_PROBE_FAILED'}
  }finally{
   Remove-Item Env:\OIG_HOSTED_DCO_FULL_IPV4_QA -ErrorAction SilentlyContinue
   Remove-Item Env:\OIG_HOSTED_DCO_DATA_QA -ErrorAction SilentlyContinue
  }
  $e=Get-Content -LiteralPath $fullIpv4Receipt -Raw | ConvertFrom-Json
  if($e.schema -cne 'oig-hosted-windows-community-dco-ipv4-fullroute-v1' -or
     -not $e.pass -or -not $e.pinnedPeerVerified -or
     -not $e.dcoRoutePairActive -or -not $e.publicIpv4ViaVpnVerified -or
     -not $e.ownedRoutesRemoved -or -not $e.vpnProcessStopped -or
     -not $e.hostRoutesRestored -or -not $e.hostDnsRestored -or
     $e.ipv6LeakProtectionProven -or $e.dnsLeakProtectionProven -or
     $e.killSwitchProven -or $e.fullDeviceAccepted -or
     $e.productionEngineChanged -or $e.ownerHostTouched){
   throw 'FULL_IPV4_QA_RECEIPT_NOT_ACCEPTED'
  }
  $fullIpv4Accepted=$true
 }
 if($ProbeLeakPolicy){
  if(Test-Path -LiteralPath $leakPolicyReceipt){throw 'DCO_LEAK_POLICY_RECEIPT_EXISTS'}
  $python=(Get-Command python.exe -ErrorAction Stop).Source
  $probe=Join-Path $PSScriptRoot 'windows-community-dco-dualstack-dns-policy-qa.py'
  if(-not(Test-Path -LiteralPath $probe -PathType Leaf)){throw 'DCO_LEAK_POLICY_SCRIPT_MISSING'}
  try{
   $env:OIG_HOSTED_DCO_DATA_QA='1'
   $env:OIG_HOSTED_DCO_LEAK_POLICY_QA='1'
   & $python -B $probe --root $work --openvpn $installedExe --adapter $alias --receipt $leakPolicyReceipt
   if($LASTEXITCODE -ne 0){throw 'DCO_LEAK_POLICY_NATIVE_PROBE_FAILED'}
  }finally{
   Remove-Item Env:\OIG_HOSTED_DCO_LEAK_POLICY_QA -ErrorAction SilentlyContinue
   Remove-Item Env:\OIG_HOSTED_DCO_DATA_QA -ErrorAction SilentlyContinue
  }
  $e=Get-Content -LiteralPath $leakPolicyReceipt -Raw | ConvertFrom-Json
  if($e.schema -cne 'oig-hosted-windows-community-dco-dualstack-dns-policy-v1' -or
     -not $e.pass -or -not $e.pinnedPeerVerified -or
     -not $e.ipv4RoutePairActive -or -not $e.ipv6GlobalRoutePairOnDco -or
     -not $e.sourceBoundHttpsOverVpn -or -not $e.dnsResponseOverTun -or
     -not $e.ownedRoutesRemoved -or -not $e.vpnProcessStopped -or
     -not $e.hostRoutesRestored -or -not $e.hostDnsRestored -or
     ($e.dnsPhysicalBaselineEligible -and -not $e.dnsLeakProtectionProven) -or
     ($e.ipv6PublicBaselineEligible -and -not $e.ipv6LeakProtectionProven) -or
     $e.killSwitchProven -or $e.fullDeviceAccepted -or
     $e.ownerHostTouched -or $e.productionBackendChanged){
   throw 'DCO_LEAK_POLICY_RECEIPT_NOT_ACCEPTED'
  }
  $leakPolicyAccepted=$true
 }

}catch{
 $failure=[string]$_.Exception.Message
}finally{
 if($adapterCreateAttempted -and (Test-Path -LiteralPath $tapctl)){
  try {
   $listed=@(& $tapctl list --hwid ovpn-dco 2>&1)
   if($LASTEXITCODE -ne 0){throw 'OWNED_ADAPTER_ROLLBACK_LIST_FAILED'}
   $matchesOwned=@($listed | ForEach-Object {[string]$_} |
     Where-Object {$_ -match [regex]::Escape($alias) -and $_ -match 'ovpn-dco'})
   if($matchesOwned.Count -gt 1){throw 'AMBIGUOUS_OWNED_ADAPTER_ROLLBACK'}
   if($matchesOwned.Count -eq 1){
    $entry=[string]$matchesOwned[0]
    if($entry -notmatch '(\{[0-9a-fA-F-]{36}\})'){throw 'OWNED_GUID_UNRESOLVED'}
    $rollbackGuid=$Matches[1]
    if($ownedCreated -and $rollbackGuid -ine $ownedGuid){
     throw 'OWNED_ADAPTER_GUID_MISMATCH'
    }
    & $tapctl delete $rollbackGuid | Out-Null
    if($LASTEXITCODE -ne 0){throw 'OWNED_ADAPTER_DELETE_FAILED'}
   }
   $afterListing=@(& $tapctl list --hwid ovpn-dco 2>&1)
   if($LASTEXITCODE -ne 0){throw 'OWNED_ADAPTER_REMOVAL_UNVERIFIABLE'}
   $left=@($afterListing | Where-Object {[string]$_ -match [regex]::Escape($alias)})
   $removed=($left.Count -eq 0)
   if(-not $removed){throw 'OWNED_ADAPTER_STILL_PRESENT'}
  }catch{$failure+=(';'+[string]$_.Exception.Message)}
 }
 if($installAttempted -and (Test-Path -LiteralPath $msi)){
  try{Run-Msi '/x' $msi; $uninstalled=$true}
  catch{$failure+=(';'+[string]$_.Exception.Message)}
 }
 Start-Sleep -Seconds 2
 $after=Read-HostNetwork
 $networkRestored=(Same-List $before.routes $after.routes) -and
                  (Same-List $before.dns $after.dns)
 $servicesRestored=(@(Get-Service -Name $services -ErrorAction SilentlyContinue).Count -eq 0)
 $driverStoreAfter=@(Read-DcoDriverStore)
 $driverStoreRestored=Same-List $driverStoreBefore $driverStoreAfter
 if(-not $ownedCreated){
  $removed=(@(Get-NetAdapter -Name $alias -IncludeHidden -ErrorAction SilentlyContinue).Count -eq 0)
 }
 Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
$failureShort=''
if($failure){$failureShort=$failure.Substring(0,[Math]::Min($failure.Length,300))}
$pass=($installed -and $adapterVerified -and $driverSigned -and $removed -and
       $uninstalled -and $networkRestored -and $servicesRestored -and
       $driverStoreRestored -and -not $failure)
$tunSha=''
$fullIpv4Sha=''
$leakPolicySha=''
if($ProbeLeakPolicy -and (Test-Path -LiteralPath $leakPolicyReceipt)){
 $leakPolicySha=(Get-FileHash -LiteralPath $leakPolicyReceipt -Algorithm SHA256).Hash.ToLowerInvariant()
}
if($ProbeFullIpv4 -and (Test-Path -LiteralPath $fullIpv4Receipt)){
 $fullIpv4Sha=(Get-FileHash -LiteralPath $fullIpv4Receipt -Algorithm SHA256).Hash.ToLowerInvariant()
}
if($ProbeTun -and (Test-Path -LiteralPath $tunReceipt)){
 $tunSha=(Get-FileHash -LiteralPath $tunReceipt -Algorithm SHA256).Hash.ToLowerInvariant()
}
$report=[ordered]@{
 schema='oig-disposable-windows-dco-driver-lifecycle-v1'
 sourceSha=$env:GITHUB_SHA
 pinnedMsiSHA256=$expectedMsi
 pinnedOpenvpnExeSHA256=$expectedExe
 driver='ovpn-dco'
 installedOriginalVendorMsi=$installed
 createdDedicatedDriverAdapter=$adapterVerified
 signedDriverVerified=$driverSigned
 ownedAdapterRemoved=$removed
 vendorUninstallSucceeded=$uninstalled
 hostRoutesAndDnsRestored=$networkRestored
 vendorServicesRemoved=$servicesRestored
 driverStorePackagesRestored=$driverStoreRestored
 fullDeviceVpnTested=$false
 scopedDcoTunReceiptSHA256=$tunSha
 fullIpv4RouteProbeAccepted=$fullIpv4Accepted
 fullIpv4RouteReceiptSHA256=$fullIpv4Sha
 dualstackDnsPolicyQaAccepted=$leakPolicyAccepted
 dualstackDnsPolicyReceiptSHA256=$leakPolicySha
 externalVpnConnected=($tunAccepted -or $fullIpv4Accepted -or $leakPolicyAccepted)
 externalVpnConnectionAttempted=([bool]$ProbeTun -or [bool]$ProbeFullIpv4 -or [bool]$ProbeLeakPolicy)
 scopedDcoTunHttpsVerified=$tunAccepted
 ownerHostTouched=$false
 productionBackendChanged=$false
 failure=$failureShort
 pass=$pass
}
[IO.File]::WriteAllText($Receipt,($report | ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
if(-not $pass){throw ('DISPOSABLE_DCO_DRIVER_QA_NOT_ACCEPTED_'+$report.failure)}
Write-Output 'PASS_PINNED_DCO_DRIVER_ADAPTER_INSTALL_AND_ROLLBACK'
