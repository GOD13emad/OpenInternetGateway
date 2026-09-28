[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$evidence=Join-Path $Root 'evidence\ensure-last-error.json'
function Test-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# UI and ordinary-user callers must never invoke the privileged connector
# control path directly. Delegate to the already-installed Highest-runlevel
# recovery task, then wait for the real service/routes outcome.
if(-not(Test-Admin)){
 $taskName='OpenInternetGateway-AutoRecovery'
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if(-not $task){throw 'Open Internet Gateway Auto-Recovery task is not installed.'}
 if([string]$task.State -ne 'Running'){
   schtasks.exe /Run /TN $taskName | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Could not start the elevated Open Internet Gateway recovery task.'}
 }
 $until=(Get-Date).AddSeconds(150)
 do{
   Start-Sleep -Seconds 1
   $desired='on'
   $desiredFile=Join-Path $Root 'state\desired-state.json'
   if(Test-Path $desiredFile){try{$desired=[string](Get-Content -Raw $desiredFile|ConvertFrom-Json).desired}catch{}}
   $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
   $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
   $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
   if($desired -eq 'on' -and $svc -and $svc.Status -eq 'Running' -and $routes.Count -ge 2){
     Write-Host 'ELEVATED ENSURE PASS'
     exit 0
   }
   if($desired -ne 'on' -and $routes.Count -eq 0 -and $task -and [string]$task.State -ne 'Running'){
     Write-Host 'ELEVATED ENSURE PASS - DESIRED OFF'
     exit 0
   }
 }while((Get-Date)-lt $until)
 throw 'Elevated recovery task did not reach the requested gateway state within 150 seconds.'
}

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
 $exactRequest=Join-Path $Root 'state\exact-profile.request'
 if(Test-Path $exactRequest){
   $req=$null
   try{$req=Get-Content -Raw $exactRequest|ConvertFrom-Json}catch{}
   $sha=if($req){[string]$req.sha256}else{''}
   if([string]::IsNullOrWhiteSpace($sha)){Remove-Item $exactRequest -Force -ErrorAction SilentlyContinue;throw 'Exact profile request is invalid.'}
   $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
   $ready=Test-Path (Join-Path $Root 'state\headless-bootstrap.ready')
   if(-not $svc -or -not $ready){& (Join-Path $PSScriptRoot 'Bootstrap-HeadlessConnector.ps1')}
   Remove-Item $exactRequest -Force -ErrorAction SilentlyContinue
   & (Join-Path $PSScriptRoot 'Headless-Control.ps1') -Action Connect -ProfileSha $sha
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
