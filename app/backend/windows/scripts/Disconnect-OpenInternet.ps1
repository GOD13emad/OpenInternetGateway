[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$desired=Join-Path $Root 'state\desired-state.json'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'state')|Out-Null
[ordered]@{desired='off';at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -Encoding UTF8 $desired
# Disconnect owns cancellation of any queued operation that could re-enable
# the tunnel after desired=off. A future explicit Connect writes desired=on
# again before creating a new exact request.
foreach($name in @('exact-profile.request','headless-known-recover.request','headless-pool-probe.request','connector-probe.request')){
 Remove-Item -LiteralPath (Join-Path $Root ('state\'+$name)) -Force -ErrorAction SilentlyContinue
}
$routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
$svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
if($routes.Count -eq 0 -and (-not $svc -or $svc.Status -eq 'Stopped')){
 Write-Host 'DISCONNECTED - ALREADY OFF'
 exit 0
}
$task=Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery' -ErrorAction SilentlyContinue
if(-not $task){throw 'Open Internet Gateway recovery task is missing while a managed tunnel may still be active.'}
schtasks.exe /Run /TN OpenInternetGateway-AutoRecovery | Out-Null
if($LASTEXITCODE -ne 0){throw 'Could not start the elevated Open Internet Gateway recovery task for disconnect.'}
# Task Scheduler is configured IgnoreNew. If a pre-existing elevated Ensure is
# still running, /Run succeeds but the disconnect run may be discarded. Keep
# the explicit desired=off intent, observe the actual service/routes, and
# re-trigger only after the old task has exited. Do not spawn a second writer,
# kill somebody else's VPN, or require another UAC prompt.
$queuedAt=Get-Date
$requeued=0
$until=(Get-Date).AddSeconds(180)
do{
 Start-Sleep -Seconds 2
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 if($routes.Count -eq 0 -and (-not $svc -or $svc.Status -eq 'Stopped')){
   Write-Host 'DISCONNECTED'
   exit 0
 }
 if($requeued -lt 6 -and ((Get-Date)-$queuedAt).TotalSeconds -ge 10){
   $current=Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery' -ErrorAction SilentlyContinue
   if(-not $current){throw 'Open Internet Gateway recovery task disappeared while disconnect was pending.'}
   if([string]$current.State -ne 'Running'){
     schtasks.exe /Run /TN OpenInternetGateway-AutoRecovery | Out-Null
     if($LASTEXITCODE -ne 0){throw 'Could not requeue elevated Open Internet Gateway disconnect.'}
     $queuedAt=Get-Date
     $requeued++
   }
 }
}while((Get-Date)-lt $until)
throw 'Headless disconnect task did not settle within 180 seconds; desired=off retained.'
