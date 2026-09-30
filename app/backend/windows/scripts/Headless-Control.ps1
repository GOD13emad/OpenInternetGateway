[CmdletBinding()]
param([ValidateSet('Ensure','Connect','Disconnect','Status')][string]$Action='Ensure',[string]$ProfileSha='')
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$connector='C:\Program Files\OpenVPN Connect\ovpnconnector.exe'
$service='OVPNConnectorService'
$programData='C:\ProgramData\OpenInternetGateway'
$serviceProfile=Join-Path $programData 'connector-current.ovpn'
$serviceLog=Join-Path $programData 'ovpnconnector.log'
$desiredFile=Join-Path $Root 'state\desired-state.json'
$resultFile=Join-Path $Root 'evidence\headless-control-last.json'
$stateFile=Join-Path $Root 'state\current-openvpn-profile.json'
$preferredFile=Join-Path $Root 'state\preferred-profile.json'
$factory=Join-Path $Root 'runtime\config-factory'
$successFile=Join-Path $factory 'successes.json'
$failureFile=Join-Path $factory 'failures.json'
$benchmarkFile=Join-Path $Root 'state\connection-benchmarks.json'
$quarantineFile=Join-Path $factory 'quarantine.json'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'state'),(Join-Path $Root 'evidence'),$factory,$programData|Out-Null

function Test-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if(-not(Test-Admin)){throw 'Headless control requires the elevated OIG scheduled task.'}
if(-not(Test-Path $connector)){throw 'OpenVPN Connect connector backend is not installed.'}

function Invoke-Connector([string[]]$CommandArgs,[int]$TimeoutMs=20000,[switch]$IgnoreExit){
 $tag=[guid]::NewGuid().ToString('N')
 $outFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-connector-'+$tag+'.out')
 $errFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-connector-'+$tag+'.err')
 try{
   $psi=[Diagnostics.ProcessStartInfo]::new()
   $psi.FileName=$connector
   $psi.UseShellExecute=$false
   $psi.CreateNoWindow=$true
   $psi.RedirectStandardOutput=$true
   $psi.RedirectStandardError=$true
   foreach($a in $CommandArgs){[void]$psi.ArgumentList.Add([string]$a)}
   $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
   [void]$p.Start()
   $outTask=$p.StandardOutput.ReadToEndAsync()
   $errTask=$p.StandardError.ReadToEndAsync()
   if(-not $p.WaitForExit($TimeoutMs)){
     try{$p.Kill()}catch{}
     if($IgnoreExit){return ''}
     throw ('Connector timeout: '+($CommandArgs -join ' '))
   }
   $o=$outTask.GetAwaiter().GetResult()
   $e=$errTask.GetAwaiter().GetResult()
   if(([string]$o) -match 'Aborting|already running'){
     if($IgnoreExit){return ([string]$o).Trim()}
     throw ('Connector refused command: '+([string]$o).Trim())
   }
   if($p.ExitCode -ne 0 -and -not $IgnoreExit){
     $msg=([string]$e).Trim()
     if([string]::IsNullOrWhiteSpace($msg)){$msg=([string]$o).Trim()}
     if([string]::IsNullOrWhiteSpace($msg)){$msg='exit '+[string]$p.ExitCode}
     throw ('Connector '+($CommandArgs -join ' ')+' failed: '+$msg)
   }
   return ([string]$o).Trim()
 }finally{
   foreach($f in @($outFile,$errFile)){if($f -and(Test-Path $f)){Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue}}
 }
}
function Get-Health([string]$ExpectedCountry='') {
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
 $ip=[string]((($cf|Where-Object{$_ -like 'ip=*'}|Select-Object -First 1)-replace '^ip=',''));$ip=$ip.Trim()
 $loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()
 $dns=@(Resolve-DnsName dns.google -Type A -DnsOnly -ErrorAction SilentlyContinue|Where-Object IPAddress|Select-Object -ExpandProperty IPAddress)
 $foreign=($loc -and $loc -ne 'IR')
 $countryOk=([string]::IsNullOrWhiteSpace($ExpectedCountry) -or $loc -eq $ExpectedCountry)
 [pscustomobject]@{Healthy=($routes.Count -ge 2 -and $foreign -and $countryOk -and -not($dns -contains '10.10.34.35'));IP=$ip;Country=$loc;DNS=$dns;Poison=($dns -contains '10.10.34.35');FullRoutes=$routes.Count}
}
function Wait-Health([bool]$Want,[int]$Seconds,[string]$ExpectedCountry=''){
 $until=(Get-Date).AddSeconds($Seconds)
 do{
   $h=Get-Health $ExpectedCountry
   if($Want -and $h.Healthy){return $h}
   if((-not $Want) -and $h.FullRoutes -eq 0){return $h}
   Start-Sleep -Seconds 2
 }while((Get-Date)-lt $until)
 return (Get-Health $ExpectedCountry)
}
function Save-Desired([string]$Value){
 [ordered]@{desired=$Value;at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -Encoding UTF8 $desiredFile
}
function Read-Map([string]$Path){
 if(Test-Path $Path){try{return (Get-Content -Raw $Path|ConvertFrom-Json -AsHashtable)}catch{}}
 return @{}
}
function Write-Map([hashtable]$Map,[string]$Path){
 $Map|ConvertTo-Json -Depth 10|Set-Content -Encoding UTF8 $Path
}
function Config-Key($c){
 if($c.SHA256){return ([string]$c.SHA256).ToLowerInvariant()}
 return (([string]$c.IP)+':'+([string]$c.Port))
}
function Record-Failure($c,[string]$Reason){
 $fail=Read-Map $failureFile;$quar=Read-Map $quarantineFile
 $key=Config-Key $c
 $count=1
 if($fail.ContainsKey($key)){try{$count=[int]$fail[$key].count+1}catch{$count=1}}
 $fail[$key]=[ordered]@{count=$count;last=(Get-Date).ToString('o');reason=$Reason;host=[string]$c.Host;ip=[string]$c.IP;port=[int]$c.Port;sha256=[string]$c.SHA256}
 if($count -ge 3){$quar[$key]=[ordered]@{at=(Get-Date).ToString('o');reason=$Reason;failures=$count;host=[string]$c.Host;ip=[string]$c.IP;port=[int]$c.Port;sha256=[string]$c.SHA256}}
 Write-Map $fail $failureFile;Write-Map $quar $quarantineFile
}
function Record-Success($c,$h){
 $success=Read-Map $successFile;$fail=Read-Map $failureFile;$quar=Read-Map $quarantineFile
 $key=Config-Key $c
 $prior=@{}
 if($success.ContainsKey($key)){try{$prior=$success[$key]}catch{$prior=@{}}}
 $stamp=(Get-Date).ToString('o')
 $first=$stamp;$count=1
 try{if($prior.first){$first=[string]$prior.first}elseif($prior.at){$first=[string]$prior.at}}catch{}
 try{$count=[int]$prior.count+1}catch{$count=1}
 $success[$key]=[ordered]@{at=$stamp;first=$first;count=$count;host=[string]$c.Host;ip=[string]$c.IP;port=[int]$c.Port;sha256=[string]$c.SHA256;observedIP=[string]$h.IP;country=[string]$h.Country;engine='OVPNConnectorService'}
 if($fail.ContainsKey($key)){$fail.Remove($key)}
 if($quar.ContainsKey($key)){$quar.Remove($key)}
 Write-Map $success $successFile;Write-Map $fail $failureFile;Write-Map $quar $quarantineFile
}
function Get-Number($Value){
 if($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)){return $null}
 try{
  $n=[Convert]::ToDouble($Value,[Globalization.CultureInfo]::InvariantCulture)
  if([double]::IsNaN($n) -or [double]::IsInfinity($n)){return $null}
  return $n
 }catch{return $null}
}
function Test-Fresh($Value,[double]$Hours){
 if([string]::IsNullOrWhiteSpace([string]$Value)){return $false}
 try{
  $d=[DateTimeOffset]::Parse([string]$Value,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
  $age=([DateTimeOffset]::UtcNow-$d.ToUniversalTime()).TotalHours
  return ($age -ge -0.1 -and $age -le $Hours)
 }catch{return $false}
}
function Get-QualityScore($c,[string]$Key,[hashtable]$Success,[hashtable]$Failures,[hashtable]$Bench,[string]$Preferred){
 [double]$score=0
 $proto=([string]$c.Protocol).ToLowerInvariant()
 $port=0;try{$port=[int]$c.Port}catch{}
 if($proto -eq 'udp'){$score+=45}
 if($port -gt 0 -and $port -lt 2000){$score+=30}elseif($proto -eq 'tcp' -and $port -eq 443){$score+=20}
 $sp=Get-Number $c.Ping
 if($null -ne $sp){$score+=[Math]::Max(-30,110-$sp)}
 $srcSpeed=Get-Number $c.Speed
 if($null -ne $srcSpeed -and $srcSpeed -gt 0){$score+=[Math]::Min(120,[Math]::Log10($srcSpeed+1)*15)}
 $srcScore=Get-Number $c.Score
 if($null -ne $srcScore -and $srcScore -gt 0){$score+=[Math]::Min(80,[Math]::Log10($srcScore+1)*12)}
 if($Success.ContainsKey($Key)){
  $sc=1;try{$sc=[Math]::Max(1,[int]$Success[$Key].count)}catch{}
  $score+=90+[Math]::Min(60,15*$sc)
 }
 if($Failures.ContainsKey($Key)){
  $fc=0;try{$fc=[Math]::Max(0,[int]$Failures[$Key].count)}catch{}
  $score-=[Math]::Min(240,60*$fc)
  try{if(Test-Fresh $Failures[$Key].last 6){$score-=320}}catch{}
 }
 if($Preferred -and $Key -eq $Preferred){$score+=20}
 if($Bench.ContainsKey($Key)){
  $b=$Bench[$Key]
  try{
   if(Test-Fresh $b.fastAt 24){
    $fast=Get-Number $b.fastPingMs
    if($null -ne $fast){$score+=[Math]::Max(-80,140-$fast*0.45)}
    elseif($proto -eq 'tcp' -and $null -ne $b.fastReachable -and -not [bool]$b.fastReachable){$score-=180}
   }
   if(Test-Fresh $b.at 72){
    $down=Get-Number $b.downloadMbps;$up=Get-Number $b.uploadMbps;$lat=Get-Number $b.httpsLatencyMs
    if($null -ne $down){$score+=[Math]::Min(260,$down*12)}
    if($null -ne $up){$score+=[Math]::Min(120,$up*15)}
    if($null -ne $lat){$score-=[Math]::Min(220,$lat*0.25)}
   }
  }catch{}
 }
 return [Math]::Round($score,3)
}
function Get-Candidates([string]$OnlySha='') {
 $idx=Join-Path $Root 'runtime\udp-cache\index.json'
 if(-not(Test-Path $idx)){return @()}
 $success=Read-Map $successFile;$fail=Read-Map $failureFile;$quar=Read-Map $quarantineFile;$bench=Read-Map $benchmarkFile
 $preferred=''
 if(Test-Path $preferredFile){try{$preferred=[string](Get-Content -Raw $preferredFile|ConvertFrom-Json).sha256}catch{}}
 $preferred=$preferred.ToLowerInvariant()
 $rows=@()
 foreach($c in @(Get-Content -Raw $idx|ConvertFrom-Json)){
   $key=Config-Key $c
   if($OnlySha -and $key -ne $OnlySha.ToLowerInvariant()){continue}
   if($quar.ContainsKey($key)){continue}
   $quality=Get-QualityScore $c $key $success $fail $bench $preferred
   $rows += [pscustomobject]@{Item=$c;Quality=$quality;Rank=[int]$c.Rank}
 }
 $limit=if($OnlySha){1}else{8}
 return @($rows|Sort-Object @{Expression='Quality';Descending=$true},Rank|Select-Object -First $limit|ForEach-Object {$_.Item})
}
function Resolve-ProfilePath($c){
 $p=[string]$c.Profile
 if([IO.Path]::IsPathRooted($p)){return $p}
 return (Join-Path $Root $p)
}
function Stop-ServiceForConfig {
 $svc=Get-Service $service -ErrorAction SilentlyContinue
 if(-not $svc){return}
 try{[void](Invoke-Connector @('stop') 12000 -IgnoreExit)}catch{}
 $svc=Get-Service $service -ErrorAction SilentlyContinue
 if($svc -and $svc.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped){
   try{Stop-Service -Name $service -Force -ErrorAction Stop}catch{}
   $svc=Get-Service $service -ErrorAction SilentlyContinue
   if($svc){
     try{$svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped,[TimeSpan]::FromSeconds(8))}catch{}
   }
 }
 $svc=Get-Service $service -ErrorAction SilentlyContinue
 if($svc -and $svc.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped){
   throw 'Connector service must be stopped before configuration changes.'
 }
}

function Ensure-ServiceInstalled {
 $svc=Get-Service $service -ErrorAction SilentlyContinue
 if(-not $svc){
   [void](Invoke-Connector @('install') 20000)
   Start-Sleep -Seconds 1
   $svc=Get-Service $service -ErrorAction SilentlyContinue
   if(-not $svc){throw 'Connector service installation did not create OVPNConnectorService.'}
 }
 Stop-ServiceForConfig
 [void](Invoke-Connector @('set-config','profile',$serviceProfile) 12000)
 [void](Invoke-Connector @('set-config','log',$serviceLog) 12000)
 [void](Invoke-Connector @('set-config','dco','false') 12000)
 [void](Invoke-Connector @('set-config','security-level','legacy') 12000)
 [void](Invoke-Connector @('set-config','seamless-tunnel','false') 12000)
 [void](Invoke-Connector @('set-config','allow-local-dns','false') 12000)
 [void](Invoke-Connector @('set-config','google-dns-fallback','true') 12000)
}
function Stop-Connector {
 try{[void](Invoke-Connector @('stop') 20000 -IgnoreExit)}catch{}
 try{Stop-Service $service -Force -ErrorAction SilentlyContinue}catch{}
 [void](Wait-Health $false 20)
}
function Schedule-ManualServiceMode {
 $cmd = "Start-Sleep -Seconds 8; sc.exe config OVPNConnectorService start= demand | Out-Null"
 Start-Process -FilePath 'pwsh.exe' -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$cmd) | Out-Null
}

function Try-Candidate($c){
 $profile=Resolve-ProfilePath $c
 if(-not(Test-Path $profile)){Record-Failure $c 'PROFILE_MISSING';return $null}
 $sha=(Get-FileHash -Algorithm SHA256 $profile).Hash.ToLowerInvariant()
 if($c.SHA256 -and $sha -ne ([string]$c.SHA256).ToLowerInvariant()){Record-Failure $c 'HASH_MISMATCH';return $null}
 Stop-Connector
 Copy-Item -LiteralPath $profile -Destination $serviceProfile -Force
 if((Get-FileHash -Algorithm SHA256 $serviceProfile).Hash.ToLowerInvariant() -ne $sha){throw 'ProgramData profile copy hash mismatch.'}
 [void](Invoke-Connector @('set-config','profile',$serviceProfile) 12000)
 try{[void](Invoke-Connector @('start') 20000)}catch{
   Record-Failure $c 'START_FAIL';return $null
 }
 $h=Wait-Health $true 14 ([string]$c.Country)
 if(-not $h.Healthy){Record-Failure $c 'LIVE_FAIL';Stop-Connector;return $null}
 Record-Success $c $h
 Schedule-ManualServiceMode
 $state=[ordered]@{at=(Get-Date).ToString('o');engine='OVPNConnectorService';service=$service;host=$c.Host;serverIP=$c.IP;port=$c.Port;protocol=$c.Protocol;configuredCountry=[string]$c.Country;countryName=[string]$c.CountryName;profile=$profile;serviceProfile=$serviceProfile;sha256=$sha;observedIP=$h.IP;country=$h.Country;dns=$h.DNS}
 $state|ConvertTo-Json -Depth 7|Set-Content -Encoding UTF8 $stateFile
 $state|ConvertTo-Json -Depth 7|Set-Content -Encoding UTF8 (Join-Path $Root 'evidence\connect-last-success.json')
 return $h
}

$mutex=New-Object System.Threading.Mutex($false,'Global\OpenInternetGatewayHeadless')
if(-not $mutex.WaitOne(0)){Write-Host 'Another headless gateway operation is active.';exit 0}
try{
 if($Action -eq 'Status'){
   $svc=Get-Service $service -ErrorAction SilentlyContinue
   $h=Get-Health
   [pscustomobject]@{Service=$(if($svc){$svc.Status.ToString()}else{'Missing'});StartType=$(if($svc){$svc.StartType.ToString()}else{'Missing'});Health=$h;Engine='OVPNConnectorService'}|ConvertTo-Json -Depth 5
   exit 0
 }
 if($Action -eq 'Disconnect'){
   Save-Desired 'off'
   if(Get-Service $service -ErrorAction SilentlyContinue){Set-Service -Name $service -StartupType Manual}
   Stop-Connector
   $h=Get-Health
   if($h.FullRoutes -ne 0){throw 'Headless disconnect did not remove full-route.'}
   [ordered]@{at=(Get-Date).ToString('o');action='disconnect';result='PASS';health=$h;engine='OVPNConnectorService'}|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 $resultFile
   Write-Host 'DISCONNECTED HEADLESS'
   exit 0
 }

 if($Action -eq 'Connect'){Save-Desired 'on'}
 $desired='off'
 if(Test-Path $desiredFile){try{$desired=[string](Get-Content -Raw $desiredFile|ConvertFrom-Json).desired}catch{}}
 if($desired -ne 'on'){
   if(Get-Service $service -ErrorAction SilentlyContinue){Set-Service -Name $service -StartupType Manual}
   Stop-Connector
   Write-Host 'DESIRED OFF'
   exit 0
 }

 try{& (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Ensure -MaxAgeHours 8|Out-Null}catch{}
 $pre=Get-Health
 $currentEngine=''
 if(Test-Path $stateFile){try{$currentEngine=[string](Get-Content -Raw $stateFile|ConvertFrom-Json).engine}catch{}}
 if($pre.Healthy -and $currentEngine -eq 'OVPNConnectorService' -and [string]::IsNullOrWhiteSpace($ProfileSha)){
    Schedule-ManualServiceMode
   Write-Host ('HEALTHY HEADLESS '+$pre.IP+' '+$pre.Country)
   exit 0
 }

 Ensure-ServiceInstalled
 Set-Service -Name $service -StartupType Automatic

 $connected=$null
 $maxCycles=$(if([string]::IsNullOrWhiteSpace($ProfileSha)){2}else{1})
 for($cycle=0;$cycle -lt $maxCycles -and -not $connected;$cycle++){
   foreach($c in @(Get-Candidates $ProfileSha)){
     $connected=Try-Candidate $c
     if($connected){break}
   }
   if(-not $connected -and $cycle -eq 0 -and [string]::IsNullOrWhiteSpace($ProfileSha)){
     try{& (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Refresh|Out-Null}catch{}
   }
 }
 if(-not $connected){
   if($ProfileSha){
     # A failed foreground relay choice must not turn the whole gateway intent off.
     # connectProfile can now restore the previous preferred relay deterministically.
     throw 'Selected relay failed headless connector validation.'
   }
   throw 'No Config Factory profile passed headless connector validation.'
 }
 & (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Status|Out-Null
 [ordered]@{at=(Get-Date).ToString('o');action='connect';result='PASS';health=$connected;engine='OVPNConnectorService'}|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 $resultFile
 Write-Host ('CONNECTED HEADLESS '+$connected.IP+' '+$connected.Country)
}finally{
 try{$mutex.ReleaseMutex()}catch{}
 $mutex.Dispose()
}
