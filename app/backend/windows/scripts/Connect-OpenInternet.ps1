[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$desired=Join-Path $Root 'state\desired-state.json'
$exact=Join-Path $Root 'state\exact-profile.request'
$current=Join-Path $Root 'state\current-openvpn-profile.json'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'state')|Out-Null

$expectedSha=''
if(Test-Path -LiteralPath $exact){
 try{$expectedSha=([string](Get-Content -LiteralPath $exact -Raw -Encoding UTF8|ConvertFrom-Json).sha256).ToLowerInvariant()}catch{}
}
[ordered]@{desired='on';at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -Encoding UTF8 $desired

# Wait briefly for a previous AutoRecovery instance to leave Running state. The
# task is configured IgnoreNew, so firing while it is still active can silently
# drop the exact-switch request.
$taskName='OpenInternetGateway-AutoRecovery'
$taskUntil=(Get-Date).AddSeconds(8)
do{
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if(-not $task -or [string]$task.State -ne 'Running'){break}
 Start-Sleep -Milliseconds 250
}while((Get-Date)-lt $taskUntil)

schtasks.exe /Run /TN $taskName | Out-Null
$waitSeconds=$(if($expectedSha){60}else{150})
$until=(Get-Date).AddSeconds($waitSeconds)
do{
 Start-Sleep -Seconds 1
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
 $loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 $activeSha=''
 if(Test-Path -LiteralPath $current){try{$activeSha=([string](Get-Content -LiteralPath $current -Raw -Encoding UTF8|ConvertFrom-Json).sha256).ToLowerInvariant()}catch{}}
 $exactOk=(-not $expectedSha -or ($activeSha -and $activeSha -eq $expectedSha))
 if($routes.Count -ge 2 -and $loc -and $loc -ne 'IR' -and $svc -and $svc.Status -eq 'Running' -and $exactOk){
   Write-Host $(if($expectedSha){'CONNECTED EXACT'}else{'CONNECTED'})
   exit 0
 }
 # Exact relay failure in Headless-Control deliberately turns desired state off.
 if($expectedSha -and -not(Test-Path -LiteralPath $exact)){
   try{$d=[string](Get-Content -LiteralPath $desired -Raw -Encoding UTF8|ConvertFrom-Json).desired}catch{$d=''}
   if($d -eq 'off'){throw 'Selected relay failed validation; no fallback relay was accepted.'}
 }
}while((Get-Date)-lt $until)
if($expectedSha){throw 'Selected relay did not become the validated active tunnel within 60 seconds.'}
throw 'Headless connect task did not reach a validated foreign tunnel within 150 seconds.'
