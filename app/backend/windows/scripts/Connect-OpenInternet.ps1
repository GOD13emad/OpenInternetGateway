[CmdletBinding()]
param([string]$ProfileSha='')
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$desired=Join-Path $Root 'state\desired-state.json'
$exact=Join-Path $Root 'state\exact-profile.request'
$current=Join-Path $Root 'state\current-openvpn-profile.json'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'state')|Out-Null

$expectedSha=([string]$ProfileSha).Trim().ToLowerInvariant()
if(-not $expectedSha -and (Test-Path -LiteralPath $exact)){
 try{$expectedSha=([string](Get-Content -LiteralPath $exact -Raw -Encoding UTF8|ConvertFrom-Json).sha256).Trim().ToLowerInvariant()}catch{}
}
if($expectedSha -and $expectedSha -notmatch '^[0-9a-f]{64}$'){throw 'Exact relay SHA-256 is invalid.'}

# Take ownership of any legacy exact request before waiting for the scheduled task.
# This prevents an already-running AutoRecovery instance from consuming a request
# that belongs to this foreground Connect/Speed operation.
if($expectedSha){Remove-Item -LiteralPath $exact -Force -ErrorAction SilentlyContinue}

[ordered]@{desired='on';at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -Encoding UTF8 $desired

$taskName='OpenInternetGateway-AutoRecovery'
$idleUntil=(Get-Date).AddSeconds(90)
do{
 $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 if(-not $task -or [string]$task.State -ne 'Running'){break}
 Start-Sleep -Milliseconds 250
}while((Get-Date)-lt $idleUntil)
$task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if($task -and [string]$task.State -eq 'Running'){throw 'Another gateway recovery operation is still active. Please retry after it finishes.'}

$requestId=''
if($expectedSha){
 $requestId=[guid]::NewGuid().ToString('N')
 [ordered]@{sha256=$expectedSha;requestId=$requestId;at=(Get-Date).ToUniversalTime().ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $exact -Encoding UTF8
}

schtasks.exe /Run /TN $taskName | Out-Null
if($LASTEXITCODE -ne 0){
 if($expectedSha){Remove-Item -LiteralPath $exact -Force -ErrorAction SilentlyContinue}
 throw 'Could not start the Open Internet Gateway recovery task.'
}

$waitSeconds=$(if($expectedSha){150}else{150})
$until=(Get-Date).AddSeconds($waitSeconds)
$minimumCompletionAt=(Get-Date).AddSeconds(2)
do{
 Start-Sleep -Seconds 1
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
 $loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 $activeSha=''
 if(Test-Path -LiteralPath $current){try{$activeSha=([string](Get-Content -LiteralPath $current -Raw -Encoding UTF8|ConvertFrom-Json).sha256).Trim().ToLowerInvariant()}catch{}}
 $exactOk=(-not $expectedSha -or ($activeSha -and $activeSha -eq $expectedSha))
 if($routes.Count -ge 2 -and $loc -and $loc -ne 'IR' -and $svc -and $svc.Status -eq 'Running' -and $exactOk){
   Remove-Item -LiteralPath $exact -Force -ErrorAction SilentlyContinue
   Write-Host $(if($expectedSha){'CONNECTED EXACT'}else{'CONNECTED'})
   exit 0
 }

 # Do not infer failure merely because Ensure consumed exact-profile.request.
 # Wait for the scheduled task itself to finish, then inspect final state.
 if($expectedSha -and (Get-Date) -ge $minimumCompletionAt){
   $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
   if($task -and [string]$task.State -ne 'Running' -and -not(Test-Path -LiteralPath $exact)){
     if($activeSha -ne $expectedSha -or -not $svc -or $svc.Status -ne 'Running' -or $routes.Count -lt 2){
       throw 'Selected relay failed validation. Gateway intent remains on so the previous preferred relay can be restored.'
     }
   }
 }
}while((Get-Date)-lt $until)

if($expectedSha){throw 'Selected relay did not become the validated active tunnel within 150 seconds.'}
throw 'Headless connect task did not reach a validated foreign tunnel within 150 seconds.'
