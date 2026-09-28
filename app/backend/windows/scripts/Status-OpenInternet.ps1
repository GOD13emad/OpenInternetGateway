[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
$Root=Split-Path -Parent $PSScriptRoot
$routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}|Select-Object DestinationPrefix,InterfaceAlias,NextHop)
$cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
$ip=[string]((($cf|Where-Object{$_ -like 'ip=*'}|Select-Object -First 1)-replace '^ip=',''));$ip=$ip.Trim()
$loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()
$dns=@(Resolve-DnsName dns.google -Type A -DnsOnly -ErrorAction SilentlyContinue|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)
$poison=($dns -contains '10.10.34.35')
$task=Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery' -ErrorAction SilentlyContinue
$desired='off'
$desiredFile=Join-Path $Root 'state\desired-state.json'
if(Test-Path $desiredFile){try{$desired=[string](Get-Content -Raw $desiredFile|ConvertFrom-Json).desired}catch{}}
$relay='';$protocol='';$engine='OVPNConnectorService'
$stateFile=Join-Path $Root 'state\current-openvpn-profile.json'
if(Test-Path $stateFile){try{$s=Get-Content -Raw $stateFile|ConvertFrom-Json;$relay=([string]$s.serverIP)+':'+([string]$s.port);$protocol=[string]$s.protocol;if($s.engine){$engine=[string]$s.engine}}catch{}}
$svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
$pool=$null
try{$pool=& (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Status|ConvertFrom-Json}catch{}
[pscustomobject]@{
 Connected=($routes.Count -ge 2 -and $loc -and $loc -ne 'IR' -and -not $poison -and $svc -and $svc.Status -eq 'Running')
 IP=$ip;Country=$loc;Dns=($dns -join ',');Poison=$poison;FullRoutes=$routes.Count
 Relay=$relay;Protocol=$protocol;Engine=$engine;DesiredState=$desired
 AutoRecovery=$(if(-not $task){'NotInstalled'}elseif(-not [bool]$task.Settings.Enabled){'Disabled'}else{'Installed'})
 AutoRecoveryTask=$(if(-not $task){'Missing'}elseif(-not [bool]$task.Settings.Enabled){'Disabled'}else{[string]$task.State})
 ConfigPool=$(if($pool){[int]$pool.pool}else{0})
 ConfigValidated=$(if($pool){[int]$pool.validated}else{0})
 ConfigStandby=$(if($pool){[int]$pool.standby}else{0})
 ConfigQuarantined=$(if($pool){[int]$pool.quarantined}else{0})
}|Format-List
