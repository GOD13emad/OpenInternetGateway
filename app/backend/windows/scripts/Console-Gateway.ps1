[CmdletBinding()]
param([ValidateSet('Status','Enable','Disable')][string]$Action='Status',[string]$PrivateAdapter='Ethernet',[string]$PublicAdapter='Local Area Connection')
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$stateDir=Join-Path $Root 'state'
New-Item -ItemType Directory -Force -Path $stateDir|Out-Null
$stateFile=Join-Path $stateDir 'console-gateway-prestate.json'
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function Get-IcsRows {
 $share=New-Object -ComObject HNetCfg.HNetShare
 $cons=@($share.EnumEveryConnection())
 $rows=foreach($c in $cons){
   $p=$share.NetConnectionProps($c)
   $cfg=$share.INetSharingConfigurationForINetConnection($c)
   [pscustomobject]@{Name=$p.Name;Guid=[string]$p.Guid;SharingEnabled=[bool]$cfg.SharingEnabled;SharingType=$cfg.SharingConnectionType;Connection=$c}
 }
 [pscustomobject]@{Share=$share;Rows=$rows}
}
if($Action -eq 'Status'){
 Write-Host '=== OpenInternetGateway Console ==='
 Get-NetAdapter -Name $PublicAdapter,$PrivateAdapter -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,Status,MediaConnectionState,ifIndex,LinkSpeed | Format-Table -Auto
 if(-not $isAdmin){Write-Host 'ICS state: elevation required for exact HNetCfg sharing state.';exit 0}
 $ics=Get-IcsRows
 $ics.Rows|Where-Object{$_.Name -in @($PublicAdapter,$PrivateAdapter) -or $_.SharingEnabled}|Select-Object Name,SharingEnabled,SharingType|Format-Table -Auto
 exit 0
}
if(-not $isAdmin){throw 'Console Gateway Enable/Disable requires elevation.'}
$pub=Get-NetAdapter -Name $PublicAdapter -ErrorAction Stop
$priv=Get-NetAdapter -Name $PrivateAdapter -ErrorAction Stop
if($pub.Name -eq $priv.Name){throw 'Public and private adapters cannot be the same.'}
if($Action -eq 'Enable'){
 if($pub.Status -ne 'Up'){throw "OpenVPN public adapter is not Up: $PublicAdapter"}
 if($priv.Status -ne 'Up' -or $priv.MediaConnectionState -ne 'Connected'){throw "Console adapter is not physically connected: $PrivateAdapter"}
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') -and $_.InterfaceAlias -eq $PublicAdapter})
 if($routes.Count -lt 2){throw 'Validated OpenVPN full-route is not active; refusing console sharing.'}
 $cf=@(curl.exe -4 --max-time 5 -s https://www.cloudflare.com/cdn-cgi/trace)
 $loc=[string](($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=','');$loc=$loc.Trim()
 $dns=@(Resolve-DnsName dns.google -Type A -DnsOnly -ErrorAction SilentlyContinue|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)
 if($loc -eq 'IR' -or $dns -contains '10.10.34.35'){throw 'Tunnel validation failed; refusing console sharing.'}
 $ics=Get-IcsRows
 $existing=@($ics.Rows|Where-Object SharingEnabled)
 if($existing.Count){
   $ours=@($existing|Where-Object{$_.Name -in @($PublicAdapter,$PrivateAdapter)})
   if($ours.Count -eq 2){Write-Host 'Console Gateway already enabled.';exit 0}
   throw ('Existing Internet Connection Sharing detected on: '+(($existing.Name)-join ', ')+'. Refusing to overwrite.')
 }
 $pre=[ordered]@{at=(Get-Date).ToString('o');PublicAdapter=$PublicAdapter;PrivateAdapter=$PrivateAdapter;privateStatus=[string]$priv.Status;privateMac=$priv.MacAddress;privateIP=@(Get-NetIPAddress -InterfaceAlias $PrivateAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue|Select-Object IPAddress,PrefixLength,PrefixOrigin,SuffixOrigin);privateDns=@((Get-DnsClientServerAddress -InterfaceAlias $PrivateAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses);ics=@($ics.Rows|Select-Object Name,Guid,SharingEnabled,SharingType)}
 $pre|ConvertTo-Json -Depth 8|Set-Content -Encoding UTF8 $stateFile
 $pubRow=$ics.Rows|Where-Object Name -eq $PublicAdapter|Select-Object -First 1
 $privRow=$ics.Rows|Where-Object Name -eq $PrivateAdapter|Select-Object -First 1
 if(-not $pubRow -or -not $privRow){throw 'Unable to map adapters into Windows ICS connection list.'}
 $pubCfg=$ics.Share.INetSharingConfigurationForINetConnection($pubRow.Connection)
 $privCfg=$ics.Share.INetSharingConfigurationForINetConnection($privRow.Connection)
 try{
   $pubCfg.EnableSharing(0)
   $privCfg.EnableSharing(1)
   Start-Sleep -Seconds 3
   $after=Get-IcsRows
   $p2=$after.Rows|Where-Object Name -eq $PublicAdapter|Select-Object -First 1
   $r2=$after.Rows|Where-Object Name -eq $PrivateAdapter|Select-Object -First 1
   if(-not($p2.SharingEnabled -and $r2.SharingEnabled)){throw 'ICS post-check failed.'}
   [ordered]@{at=(Get-Date).ToString('o');status='ENABLED';public=$PublicAdapter;private=$PrivateAdapter;country=$loc;dns=$dns;privateIP=@(Get-NetIPAddress -InterfaceAlias $PrivateAdapter -AddressFamily IPv4 -ErrorAction SilentlyContinue|Select-Object IPAddress,PrefixLength)}|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 (Join-Path $Root 'evidence\console-gateway-live.json')
   Write-Host 'CONSOLE GATEWAY ENABLED'
 }catch{
   try{$pubCfg.DisableSharing()}catch{};try{$privCfg.DisableSharing()}catch{}
   throw
 }
}else{
 $ics=Get-IcsRows
 foreach($row in @($ics.Rows|Where-Object{$_.Name -in @($PublicAdapter,$PrivateAdapter) -and $_.SharingEnabled})){
   try{($ics.Share.INetSharingConfigurationForINetConnection($row.Connection)).DisableSharing()}catch{}
 }
 Start-Sleep -Seconds 2
 $after=Get-IcsRows
 $left=@($after.Rows|Where-Object{$_.Name -in @($PublicAdapter,$PrivateAdapter) -and $_.SharingEnabled})
 if($left.Count){throw 'Console Gateway sharing still active after disable.'}
 [ordered]@{at=(Get-Date).ToString('o');status='DISABLED';public=$PublicAdapter;private=$PrivateAdapter}|ConvertTo-Json|Set-Content -Encoding UTF8 (Join-Path $Root 'evidence\console-gateway-last-disable.json')
 Write-Host 'CONSOLE GATEWAY DISABLED'
}