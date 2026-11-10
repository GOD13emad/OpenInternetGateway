$ErrorActionPreference='Stop'
$script:root=Join-Path $PSScriptRoot '..\backend\windows\scripts'
. (Join-Path $script:root 'Route-Pair.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $script:root 'Headless-Control.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw ('Headless PowerShell parser failed: '+$errors[0].Message)}
$matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-Health'},$true))
if($matches.Count -ne 1){throw 'Cannot uniquely extract the real Get-Health function'}
Invoke-Expression $matches[0].Extent.Text

# Mock EVERY external dependency used by Get-Health; this test cannot alter
# connection, routing, service, DNS, process state or credential files.
$script:routes=@()
$script:driver='OpenVPN Data Channel Offload'
$script:serviceStatus='Running'
$script:country='US'
function DnsRecord([string]$name,[string]$type,[string]$section,[string]$ip) {
 return [pscustomobject]@{Name=$name;Type=$type;Section=$section;IPAddress=$ip}
}
$script:dnsRecords=@((DnsRecord 'dns.google' 'A' 'Answer' '8.8.8.8'))
$script:winnerMode='matching'
$script:v6Mode='none'
function Get-NetRoute {
 param([string]$AddressFamily,[string]$ErrorAction)
 if($AddressFamily -eq 'IPv6'){
   if($script:v6Mode -in @('foreign','owned','unverified')){
     return [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=19}
   }
   return
 }
 return $script:routes
}
function Get-NetAdapter {param([int]$InterfaceIndex,[string]$ErrorAction)
 return [pscustomobject]@{InterfaceDescription=$script:driver;InterfaceIndex=$InterfaceIndex}
}
function Get-Service {param([string]$Name,[string]$ErrorAction)
 return [pscustomobject]@{Status=$script:serviceStatus}
}
function Find-NetRoute {
 param([string]$RemoteIPAddress,[string]$ErrorAction)
 if($RemoteIPAddress -match ':'){
   if($script:v6Mode -eq 'foreign'){
     return [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=19}
   }
   if($script:v6Mode -eq 'owned'){
     return [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=20}
   }
   return
 }
 $prefix=$(if($RemoteIPAddress -eq '1.1.1.1'){'0.0.0.0/1'}else{'128.0.0.0/1'})
 [pscustomobject]@{IPAddress='10.8.0.9'}
 if($script:winnerMode -eq 'foreign-upper' -and $prefix -eq '128.0.0.0/1'){
   Row '128.0.0.0/1' 37 'Foreign VPN'
   return
 }
 $candidate=@($script:routes|Where-Object{$_.DestinationPrefix -eq $prefix})
 if($candidate.Count -eq 1){$candidate[0]}
}
function curl.exe {return @('ip=198.51.100.10',('loc='+$script:country))}
function Resolve-DnsName {
 param([string]$Name,[string]$Type,[switch]$DnsOnly,[string]$ErrorAction)
 return @($script:dnsRecords)
}
function Row([string]$p,[int]$i,[string]$alias) {
 return [pscustomobject]@{DestinationPrefix=$p;InterfaceIndex=$i;InterfaceAlias=$alias}
}
function Expect([bool]$healthy,[int]$fullRoutes,[string]$scenario,[string]$expectedCountry='US'){
 $s=Get-Health $expectedCountry
 if([bool]$s.Healthy -ne $healthy -or [int]$s.FullRoutes -ne $fullRoutes){
    throw ('Headless health '+$scenario+' wrong: '+($s|ConvertTo-Json -Compress))}
}
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
Expect $true 2 'valid managed OpenVPN service and route pair'
$script:serviceStatus='Stopped'
Expect $false 2 'stopped connector cannot claim health; residual routes must remain visible for cleanup'
$script:serviceStatus='Running'
$script:winnerMode='foreign-upper'
Expect $false 0 'OpenVPN routes present but effective upper route belongs to different VPN'
$script:winnerMode='matching'
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 37 'Another VPN'))
Expect $false 0 'foreign upper route cannot create healthy managed VPN'
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
Expect $false 0 'only one route'
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
$script:driver='Intel Ethernet Controller'
Expect $false 0 'physical shadow routes'
$script:driver='OpenVPN Data Channel Offload'
$script:country='IR'
Expect $false 2 'foreign-country requirement'
$script:country='US'
$script:dnsRecords=@(
 (DnsRecord 'dns.google' 'A' 'Answer' '8.8.8.8'),
 (DnsRecord 'dns.google' 'A' 'Answer' '8.8.4.4'),
 (DnsRecord 'ns1.google.com' 'A' 'Additional' '216.239.32.114'),
 (DnsRecord 'ns1.google.com' 'AAAA' 'Additional' '2001:4860:4802:32::72')
)
Expect $true 2 'additional-section glue is not DNS answer poisoning'
$script:dnsRecords=@((DnsRecord 'dns.google' 'A' 'Answer' '10.10.34.35'))
Expect $false 2 'DNS poisoning in answer section'
$script:dnsRecords=@((DnsRecord 'ns1.google.com' 'A' 'Additional' '8.8.8.8'))
Expect $false 2 'additional-only DNS records leave answer unknown'
$script:dnsRecords=@([pscustomobject]@{IPAddress='8.8.8.8'})
Expect $false 2 'unclassified DNS record fails closed'
$script:dnsRecords=@()
Expect $false 2 'DNS unknown must not be healthy'
$script:dnsRecords=@((DnsRecord 'dns.google' 'A' 'Answer' '8.8.8.8'))
Expect $false 2 'expected-country mismatch' 'JP'
$script:v6Mode='foreign'
Expect $false 2 'foreign IPv6 default despite owned IPv4'
$script:v6Mode='unverified'
Expect $false 2 'IPv6 default but no verified selected route'
$script:v6Mode='owned'
Expect $true 2 'IPv6 egress selected on managed OpenVPN adapter'
$script:v6Mode='none'
# Exercise the actual post-takeover branch *inside the single handover
# transaction's actual finally block*. All connector and route calls below
# are mocked; no user VPN, DNS, service, firewall or route is modified.
$actual=Join-Path $script:root 'Headless-Control.ps1'
$headlessAst=[Management.Automation.Language.Parser]::ParseFile($actual,[ref]$null,[ref]$null)
$branches=@($headlessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.IfStatementAst] -and
  $node.Extent.Text.TrimStart().StartsWith('if(-not $h.Healthy){')
},$true))
$transactions=@($headlessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.TryStatementAst] -and
  $node.Extent.Text.Contains('$shadow=Add-PhysicalShadows') -and
  $null -ne $node.Finally -and
  $node.Finally.Extent.Text.Contains('if(-not $handoverCommitted){Stop-Connector}')
},$true))
if($branches.Count -ne 1 -or $transactions.Count -ne 1){
  throw "Nonunique real rollback branch: health=$($branches.Count) transaction=$($transactions.Count)"
}
$cleanupText=$transactions[0].Finally.Extent.Text
$wrapper=[scriptblock]::Create('try {'+$branches[0].Extent.Text+'} finally '+$cleanupText)
$cleanupOnly=[scriptblock]::Create($cleanupText.Substring(1,$cleanupText.Length-2))
$script:events=@();$script:evidenceFails=$false;$script:lastHealthReceipt=$null
function Write-ShadowEvidence($Data){
  $script:events+=,'evidence'
  $script:lastHealthReceipt=$Data
  if($script:evidenceFails){throw 'SYNTHETIC_EVIDENCE_WRITE_FAILURE'}
}
function Record-Failure($Candidate,[string]$Reason){$script:events+=,'record-failure'}
function Stop-Connector {$script:events+=,'stop-connector'}
$h=[pscustomobject]@{Healthy=$false;FullRoutes=0;Poison=$null}
$c=[pscustomobject]@{SHA256=('a'*64)}
$native=[pscustomobject]@{Ready=$true;NativeRoutes=2}
$handoverCommitted=$false
& $wrapper | Out-Null
if(($script:events -join ',') -cne 'evidence,record-failure,stop-connector'){throw 'Post-health rollback ordering failed'}
if($script:lastHealthReceipt.result -ne 'POST_TAKEOVER_HEALTH_FAIL' -or
   $script:lastHealthReceipt.recovery -ne 'stop-owned-connector'){
  throw 'Health failure evidence or policy not preserved'
}
$script:events=@();$script:evidenceFails=$true;$threw=$false
try{& $wrapper | Out-Null}catch{
  if($_.Exception.Message -like '*SYNTHETIC_EVIDENCE_WRITE_FAILURE*'){$threw=$true}else{throw}
}
if(-not $threw -or ($script:events -join ',') -cne 'evidence,stop-connector'){
  throw 'Cleanup must run when diagnostic evidence cannot be written'
}
$script:events=@();$handoverCommitted=$true
& $cleanupOnly | Out-Null
if($script:events.Count){throw 'A committed healthy tunnel must not be stopped by finally'}
$script:events=@();$handoverCommitted=$false
& $cleanupOnly | Out-Null
if(($script:events -join ',') -cne 'stop-connector'){throw 'Uncommitted tunnel must always stop in finally'}

# Execute the actual Add-PhysicalShadows source function with a mock route
# table, fake interface and a PRIVATE temporary journal file. No NetTCPIP
# commands reach the operating system (both Get/ New-NetRoute are mocked).
$shadowMatches=@($headlessAst.FindAll({
  param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
  $node.Name -eq 'Add-PhysicalShadows'
},$true))
if($shadowMatches.Count -ne 1){throw 'Cannot extract actual shadow creator'}
Invoke-Expression $shadowMatches[0].Extent.Text
# Also execute the real source cleanup and journal parser. Only NetTCPIP route
# commands are mocked; tests must not merely assert that a cleanup stub ran.
foreach($funcName in @('Get-ShadowState','Remove-PhysicalShadows')){
  $items=@($headlessAst.FindAll({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $funcName
  },$true))
  if($items.Count -ne 1){throw ('Cannot extract source function: '+$funcName)}
  Invoke-Expression $items[0].Extent.Text
}
$shadowFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-shadow-journal-unit-'+[guid]::NewGuid().ToString('N')+'.json')
$script:fakeRoutes=@();$script:routeCalls=0;$script:failSecond=$false
$script:events=@();$script:evidenceFails=$false
function Get-PhysicalDefaultPath {
  return [pscustomobject]@{InterfaceIndex=41;InterfaceAlias='MOCK-PHYSICAL-ONLY';NextHop='192.0.2.1';InterfaceMetric=20;RouteMetric=15;EffectiveMetric=35}
}
function Get-NetRoute {
  [CmdletBinding()]
  param([string]$AddressFamily,[string]$DestinationPrefix)
  if($DestinationPrefix){return @($script:fakeRoutes|Where-Object DestinationPrefix -eq $DestinationPrefix)}
  return @($script:fakeRoutes)
}
function New-NetRoute {
  [CmdletBinding()]
  param([string]$DestinationPrefix,[int]$InterfaceIndex,[string]$NextHop,
        [int]$RouteMetric,[string]$PolicyStore)
  if(-not(Test-Path -LiteralPath $shadowFile)){throw 'JOURNAL_WAS_NOT_DURABLY_WRITTEN_BEFORE_ROUTE'}
  $script:routeCalls++
  if($script:failSecond -and $script:routeCalls -eq 2){throw 'SYNTHETIC_SECOND_SHADOW_ROUTE_FAILURE'}
  $row=[pscustomobject]@{DestinationPrefix=$DestinationPrefix;InterfaceIndex=$InterfaceIndex;NextHop=$NextHop}
  $script:fakeRoutes+=,$row
  return $row
}
# Only mock the NetTCPIP cmdlet: actual Remove-PhysicalShadows consumes the
# fake objects and must preserve the journal when a removal is denied.
$script:failRouteRemoval=$false
function Remove-NetRoute {
  [CmdletBinding(SupportsShouldProcess=$true)]
  param([Parameter(ValueFromPipeline=$true)][object]$InputObject)
  process {
    if($null -eq $InputObject){return}
    if(-not(Test-Path -LiteralPath $shadowFile)){throw 'JOURNAL_MISSING_BEFORE_ROUTE_REMOVAL'}
    $script:events+=,'journalled-cleanup'
    if($script:failRouteRemoval){throw 'SYNTHETIC_REMOVE_DENIED'}
    $script:fakeRoutes=@($script:fakeRoutes|Where-Object {
      $_.DestinationPrefix -ne $InputObject.DestinationPrefix -or
      $_.InterfaceIndex -ne $InputObject.InterfaceIndex -or
      $_.NextHop -ne $InputObject.NextHop
    })
  }
}
try{
  $script:routeCalls=0;$script:fakeRoutes=@();$script:events=@()
  $script:failSecond=$true;$script:evidenceFails=$false;$threw=$false
  try{[void](Add-PhysicalShadows)}catch{
    if($_.Exception.Message -like '*SYNTHETIC_SECOND_SHADOW_ROUTE_FAILURE*'){$threw=$true}else{throw}
  }
  if(-not $threw -or $script:routeCalls -ne 2 -or $script:fakeRoutes.Count -ne 0 -or
     (Test-Path -LiteralPath $shadowFile) -or
     -not ('journalled-cleanup' -in $script:events)){
    throw 'Partial /1 route insertion was not safely rolled back'
  }
  $script:routeCalls=0;$script:fakeRoutes=@();$script:events=@()
  $script:failSecond=$false;$script:evidenceFails=$true;$threw=$false
  try{[void](Add-PhysicalShadows)}catch{
    if($_.Exception.Message -like '*SYNTHETIC_EVIDENCE_WRITE_FAILURE*'){$threw=$true}else{throw}
  }
  if(-not $threw -or $script:fakeRoutes.Count -ne 0 -or
     (Test-Path -LiteralPath $shadowFile) -or
     -not ('journalled-cleanup' -in $script:events)){
    throw 'Evidence-write failure stranded route or cleanup journal'
  }
  $script:routeCalls=0;$script:fakeRoutes=@();$script:events=@()
  $script:evidenceFails=$false
  $result=Add-PhysicalShadows
  if($script:routeCalls -ne 2 -or $script:fakeRoutes.Count -ne 2 -or
     $result.status -ne 'cleanup-armed' -or
     -not(Test-Path -LiteralPath $shadowFile) -or
     -not ('evidence' -in $script:events)){
    throw 'Successful /1 pair missing durable cleanup journal'
  }
  # The actual remover must leave the on-disk journal intact when even one
  # mock OS route deletion fails; a later retry can still recover the route.
  $script:failRouteRemoval=$true;$threw=$false
  try{Remove-PhysicalShadows}catch{
    if($_.Exception.Message -like '*SYNTHETIC_REMOVE_DENIED*'){$threw=$true}else{throw}
  }
  if(-not $threw -or -not(Test-Path -LiteralPath $shadowFile) -or $script:fakeRoutes.Count -ne 2){
    throw 'Route removal error lost the cleanup journal or fake routes'
  }
  $script:failRouteRemoval=$false
  Remove-PhysicalShadows
  if($script:fakeRoutes.Count -ne 0 -or (Test-Path -LiteralPath $shadowFile)){
    throw 'Actual source shadow remover did not clean up'
  }
  $script:routeCalls=0;$script:fakeRoutes=@()
  $shadowFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-shadow-malformed-'+[guid]::NewGuid().ToString('N')+'.json')
  Set-Content -LiteralPath $shadowFile -Value '{malformed' -Encoding UTF8
  $threw=$false
  try{Remove-PhysicalShadows}catch{
    if($_.Exception.Message -like '*cannot be parsed*'){$threw=$true}else{throw}
  }
  if(-not $threw -or -not(Test-Path -LiteralPath $shadowFile)){
    throw 'Malformed journal must be retained for recovery'
  }
  Remove-Item -LiteralPath $shadowFile -Force
  $shadowFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-shadow-nonexistent-'+[guid]::NewGuid().ToString('N')) 'no-file.json'
  $threw=$false
  try{[void](Add-PhysicalShadows)}catch{$threw=$true}
  if(-not $threw -or $script:routeCalls -ne 0){
    throw 'Journal write failure MUST abort before any route insertion'
  }
}finally{
  # Only the private test journal is touched. All host routes were mocks.
  if($shadowFile -and (Test-Path -LiteralPath $shadowFile)){
    Remove-Item -LiteralPath $shadowFile -Force
  }
}
Write-Output 'PASS: Windows native mocked health, universal rollback, actual owned route removal, and durable recovery journal (offline, no network mutation)'
