[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'Route-Pair.ps1')
$evidence=Join-Path $Root 'evidence\ensure-last-error.json'
function Test-OigOpenVpnGuiRunning {
 try{return (@(Get-Process -Name 'OpenVPNConnect' -ErrorAction Stop).Count -gt 0)}
 catch{if($_.FullyQualifiedErrorId -like 'NoProcessFoundForGivenName*'){return $false};throw 'Cannot confirm whether OpenVPN Connect GUI is running; refusing connector bootstrap.'}
}
function Assert-OigOpenVpnGuiClosed {
 if(Test-OigOpenVpnGuiRunning){
   $desiredFile=Join-Path $Root 'state\desired-state.json'
   $intent='off'
   if(Test-Path -LiteralPath $desiredFile){try{$intent=[string](Get-Content -LiteralPath $desiredFile -Raw|ConvertFrom-Json).desired}catch{}}
   if($intent -eq 'on'){
     [ordered]@{desired='off';at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -Encoding UTF8 $desiredFile
     Remove-Item -LiteralPath (Join-Path $Root 'state\exact-profile.request') -Force -ErrorAction SilentlyContinue
   }
   throw 'OpenVPN Connect GUI is already running; headless connector bootstrap was refused. Close the independent app and click Connect again.'
 }
}
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
 if(-not [bool]$task.Settings.Enabled){
   try{Enable-ScheduledTask -TaskName $taskName -ErrorAction Stop|Out-Null}catch{throw ('Auto-Recovery task is disabled and could not be re-enabled: '+$_.Exception.Message)}
   $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
 }
 if([string]$task.State -ne 'Running'){
   schtasks.exe /Run /TN $taskName | Out-Null
   if($LASTEXITCODE -ne 0){throw 'Could not start the elevated Open Internet Gateway recovery task.'}
 }
 $until=(Get-Date).AddSeconds(150)
 do{
   Start-Sleep -Seconds 1
   $desired='off'
   $desiredFile=Join-Path $Root 'state\desired-state.json'
   if(Test-Path $desiredFile){try{$desired=[string](Get-Content -Raw $desiredFile|ConvertFrom-Json).desired}catch{}}
   $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
   $routePairValid=Test-OigFullRoutePair -Routes $routes
   $ipv6Safe=if($routePairValid){Test-OigIpv6EgressSafe -InterfaceIndex ([int]$routes[0].InterfaceIndex)}else{$false}
   $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
   $task=Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
   $statePath=Join-Path $Root 'state\current-openvpn-profile.json'
   $activeSha='';$activeRelay='';$profileCountry=''
   if(Test-Path -LiteralPath $statePath){
     try{
       $profile=Get-Content -LiteralPath $statePath -Raw|ConvertFrom-Json
       $activeSha=([string]$profile.sha256).Trim().ToLowerInvariant()
       $activeRelay=([string]$profile.serverIP)+':'+([string]$profile.port)
       $profileCountry=[string]$profile.country
       if(-not $profileCountry){$profileCountry=[string]$profile.configuredCountry}
     }catch{}
   }
   $trace=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
   $observed=[string]((($trace|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''))
   $dns=@(Resolve-DnsName dns.google -Type A -DnsOnly -ErrorAction SilentlyContinue|Where-Object {$_.IPAddress -and $_.Section -eq 'Answer'}|Select-Object -ExpandProperty IPAddress)
   $poison=if($dns.Count -eq 0){$null}else{@($dns|Where-Object{$_ -notin @('8.8.8.8','8.8.4.4')}).Count -gt 0}
   if($desired -eq 'on' -and $svc -and $svc.Status -eq 'Running' -and $routePairValid -and $ipv6Safe -and
      $activeSha -match '^[a-fA-F0-9]{64}$' -and $activeRelay -and $activeRelay -ne ':' -and
      $profileCountry -and $observed.Trim() -eq $profileCountry -and $poison -eq $false){
     Write-Host 'ELEVATED ENSURE PASS'
     exit 0
   }
   if($desired -ne 'on' -and $routes.Count -eq 0 -and (-not $svc -or $svc.Status -eq 'Stopped') -and $task -and [string]$task.State -ne 'Running'){
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
   if(-not $svc -or -not $ready){
     Assert-OigOpenVpnGuiClosed
     & (Join-Path $PSScriptRoot 'Bootstrap-HeadlessConnector.ps1')
   }
   Remove-Item $exactRequest -Force -ErrorAction SilentlyContinue
   & (Join-Path $PSScriptRoot 'Headless-Control.ps1') -Action Connect -ProfileSha $sha
   exit 0
 }
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 $ready=Test-Path (Join-Path $Root 'state\headless-bootstrap.ready')
 if(-not $svc -or -not $ready){
   Assert-OigOpenVpnGuiClosed
   & (Join-Path $PSScriptRoot 'Bootstrap-HeadlessConnector.ps1')
   # Continue into Ensure immediately; the periodic recovery interval is too
   # long for the foreground first-Connect operation.
 }
 & (Join-Path $PSScriptRoot 'Headless-Control.ps1') -Action Ensure
}catch{
 [ordered]@{at=(Get-Date).ToString('o');error=$_.Exception.Message;stack=$_.ScriptStackTrace}|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 $evidence
 throw
}
