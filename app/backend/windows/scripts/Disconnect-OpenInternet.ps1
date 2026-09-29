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
schtasks.exe /Run /TN OpenInternetGateway-AutoRecovery | Out-Null
$until=(Get-Date).AddSeconds(45)
do{
 Start-Sleep -Seconds 2
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 if($routes.Count -eq 0 -and $svc -and $svc.Status -eq 'Stopped'){
   Write-Host 'DISCONNECTED'
   exit 0
 }
}while((Get-Date)-lt $until)
throw 'Headless disconnect task did not settle within 45 seconds.'
