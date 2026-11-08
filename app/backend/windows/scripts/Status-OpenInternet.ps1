[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
. (Join-Path $PSScriptRoot 'Route-Pair.ps1')
$Root=Split-Path -Parent $PSScriptRoot
$routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}|Select-Object DestinationPrefix,InterfaceAlias,InterfaceIndex,NextHop)
$routePairValid=Test-OigFullRoutePair -Routes $routes
$ipv6Safe=if($routePairValid){Test-OigIpv6EgressSafe -InterfaceIndex ([int]$routes[0].InterfaceIndex)}else{$false}
$cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
$ip=[string]((($cf|Where-Object{$_ -like 'ip=*'}|Select-Object -First 1)-replace '^ip=',''));$ip=$ip.Trim()
$loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()
$dns=@(Resolve-DnsName dns.google -Type A -DnsOnly -ErrorAction SilentlyContinue|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)
$poison=if($dns.Count -eq 0){$null}else{@($dns|Where-Object{$_ -notin @('8.8.8.8','8.8.4.4')}).Count -gt 0}
$task=Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery' -ErrorAction SilentlyContinue
$desired='off'
$desiredFile=Join-Path $Root 'state\desired-state.json'
if(Test-Path $desiredFile){try{$desired=[string](Get-Content -Raw $desiredFile|ConvertFrom-Json).desired}catch{}}
$relay='';$protocol='';$engine='OVPNConnectorService';$profileIP='';$profileCountry=''
$stateFile=Join-Path $Root 'state\current-openvpn-profile.json'
if(Test-Path $stateFile){try{$s=Get-Content -Raw $stateFile|ConvertFrom-Json;$relay=([string]$s.serverIP)+':'+([string]$s.port);$protocol=[string]$s.protocol;if($s.engine){$engine=[string]$s.engine};$profileIP=[string]$s.observedIP;if(-not $profileIP){$profileIP=[string]$s.serverIP};$profileCountry=[string]$s.country;if(-not $profileCountry){$profileCountry=[string]$s.configuredCountry}}catch{}}
$svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
$managedActive=($svc -and $svc.Status -eq 'Running')
$probeDegraded=$false
if(-not $loc -and $managedActive -and $routes.Count -ge 2 -and $routePairValid -and $ipv6Safe -and $poison -eq $false -and $profileCountry){
  $loc=$profileCountry
  if(-not $ip){$ip=$profileIP}
  $probeDegraded=$true
}
$pool=$null
try{$pool=& (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Status|ConvertFrom-Json}catch{}
[pscustomobject]@{
 Connected=($routes.Count -ge 2 -and $routePairValid -and $ipv6Safe -and $managedActive -and $loc -and $loc -ne 'IR' -and $poison -eq $false)
 IP=$ip;Country=$loc;Dns=($dns -join ',');Poison=$poison;FullRoutes=$(if($routePairValid){2}else{0});Ipv6LeakRisk=[bool]($routePairValid -and -not $ipv6Safe)
 Relay=$relay;Protocol=$protocol;Engine=$engine;ManagedTunnelActive=[bool]$managedActive;HealthProbeDegraded=[bool]$probeDegraded;DesiredState=$desired
 AutoRecovery=$(if(-not $task){'NotInstalled'}elseif(-not [bool]$task.Settings.Enabled){'Disabled'}else{'Installed'})
 AutoRecoveryTask=$(if(-not $task){'Missing'}elseif(-not [bool]$task.Settings.Enabled){'Disabled'}else{[string]$task.State})
 ConfigPool=$(if($pool){[int]$pool.pool}else{0})
 ConfigValidated=$(if($pool){[int]$pool.validated}else{0})
 ConfigStandby=$(if($pool){[int]$pool.standby}else{0})
 ConfigQuarantined=$(if($pool){[int]$pool.quarantined}else{0})
}|Format-List
