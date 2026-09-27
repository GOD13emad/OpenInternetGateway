[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$evidence=Join-Path $Root 'evidence\ensure-last-error.json'
try{
 $knownRecoverRequest=Join-Path $Root 'state\headless-known-recover.request'
 if(Test-Path $knownRecoverRequest){
   Remove-Item $knownRecoverRequest -Force -ErrorAction SilentlyContinue
   & (Join-Path $PSScriptRoot 'Recover-HeadlessKnownWinners.ps1')
   exit 0
 }
 $poolProbeRequest=Join-Path $Root 'state\headless-pool-probe.request'
 if(Test-Path $poolProbeRequest){
   Remove-Item $poolProbeRequest -Force -ErrorAction SilentlyContinue
   & (Join-Path $PSScriptRoot 'Probe-HeadlessPool.ps1')
   exit 0
 }
 $probeRequest=Join-Path $Root 'state\connector-probe.request'
 if(Test-Path $probeRequest){
   Remove-Item $probeRequest -Force -ErrorAction SilentlyContinue
   & (Join-Path $PSScriptRoot 'Probe-HeadlessConnector.ps1')
   exit 0
 }
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 $ready=Test-Path (Join-Path $Root 'state\headless-bootstrap.ready')
 if(-not $svc -or -not $ready){
   & (Join-Path $PSScriptRoot 'Bootstrap-HeadlessConnector.ps1')
   exit 0
 }
 & (Join-Path $PSScriptRoot 'Headless-Control.ps1') -Action Ensure
}catch{
 [ordered]@{at=(Get-Date).ToString('o');error=$_.Exception.Message;stack=$_.ScriptStackTrace}|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 $evidence
 throw
}
