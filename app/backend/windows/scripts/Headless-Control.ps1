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
$shadowFile=Join-Path $Root 'state\windows-physical-shadow.json'
$shadowEvidence=Join-Path $Root 'evidence\shadow-handover-last.json'
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
function Write-ShadowEvidence($Object){$Object|ConvertTo-Json -Depth 10|Set-Content -Encoding UTF8 $shadowEvidence}
function Get-PhysicalDefaultPath {
 $defs=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue|Where-Object {$_.NextHop -and $_.NextHop -ne '0.0.0.0'})
 $rows=@()
 foreach($r in $defs){$im=99999;try{$im=[int](Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex -ErrorAction Stop).InterfaceMetric}catch{};$rows+=[pscustomobject]@{Route=$r;Effective=[int]$r.RouteMetric+$im}}
 $best=$rows|Sort-Object Effective|Select-Object -First 1
 if(-not $best){throw 'No physical IPv4 default route is available.'}
 $r=$best.Route
 if($r.InterfaceAlias -match 'OpenVPN|Local Area Connection|TAP|Wintun'){throw ('Refusing shadow path on tunnel-like default interface '+$r.InterfaceAlias+'.')}
 return [pscustomobject]@{InterfaceIndex=[int]$r.InterfaceIndex;InterfaceAlias=[string]$r.InterfaceAlias;NextHop=[string]$r.NextHop;RouteMetric=[int]$r.RouteMetric;InterfaceMetric=[int](Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex).InterfaceMetric;EffectiveMetric=[int]$best.Effective}
}
function Add-PhysicalShadows {
 if(Test-Path $shadowFile){throw 'Physical shadow state already exists.'}
 $existing=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 if($existing.Count -gt 0){throw 'Refusing to add physical shadows while /1 routes already exist.'}
 $p=Get-PhysicalDefaultPath
 foreach($prefix in @('0.0.0.0/1','128.0.0.0/1')){New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $p.InterfaceIndex -NextHop $p.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null}
 $owned=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') -and $_.InterfaceIndex -eq $p.InterfaceIndex -and $_.NextHop -eq $p.NextHop})
 if($owned.Count -ne 2){throw ('Physical shadow verification failed; expected 2 routes, found '+$owned.Count+'.')}
 $state=[ordered]@{at=(Get-Date).ToString('o');status='holding-physical';interfaceIndex=$p.InterfaceIndex;interfaceAlias=$p.InterfaceAlias;nextHop=$p.NextHop;routeMetric=1;interfaceMetric=$p.InterfaceMetric;effectiveMetric=(1+$p.InterfaceMetric);prefixes=@('0.0.0.0/1','128.0.0.0/1')}
 $state|ConvertTo-Json -Depth 7|Set-Content -Encoding UTF8 $shadowFile
 Write-ShadowEvidence ([ordered]@{at=(Get-Date).ToString('o');result='HOLDING';state=$state})
 return [pscustomobject]$state
}
function Get-ShadowState {if(Test-Path $shadowFile){try{return (Get-Content -Raw $shadowFile|ConvertFrom-Json)}catch{}};return $null}
function Test-TcpDataPlane([string]$Address,[int]$Port=443,[int]$TimeoutMs=900){
 $sw=[Diagnostics.Stopwatch]::StartNew();$client=[Net.Sockets.TcpClient]::new();$ok=$false
 try{$task=$client.ConnectAsync($Address,$Port);$ok=($task.Wait($TimeoutMs) -and $client.Connected)}catch{$ok=$false}finally{$sw.Stop();$client.Dispose()}
 return [pscustomobject]@{Ok=[bool]$ok;ElapsedMs=[int]$sw.ElapsedMilliseconds}
}
function Wait-NativeDataPlane([int]$Seconds=6){
 $shadow=Get-ShadowState;if(-not $shadow){throw 'Physical shadow is required for isolated tunnel data-plane validation.'}
 $native=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') -and $_.InterfaceIndex -ne [int]$shadow.interfaceIndex})
 if($native.Count -ne 2){return [pscustomobject]@{Ready=$false;Reason='NATIVE_ROUTE_PAIR_MISSING';Attempts=@()}}
 $tap=$native|Select-Object -First 1;$idx=[int]$tap.InterfaceIndex;$hop=[string]$tap.NextHop;$probe='1.0.0.1/32'
 if(@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $probe -ErrorAction SilentlyContinue).Count -gt 0){return [pscustomobject]@{Ready=$false;Reason='PROBE_ROUTE_ALREADY_EXISTS';Attempts=@()}}
 New-NetRoute -DestinationPrefix $probe -InterfaceIndex $idx -NextHop $hop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop|Out-Null
 $attempts=@();$ready=$false;$until=(Get-Date).AddSeconds($Seconds)
 try{
   do{
     $tcp=Test-TcpDataPlane '1.0.0.1' 443 900
     $attempts+=,[ordered]@{at=(Get-Date).ToString('o');ok=[bool]$tcp.Ok;elapsedMs=[int]$tcp.ElapsedMs}
     if($tcp.Ok){$ready=$true;break}
     Start-Sleep -Milliseconds 250
   }while((Get-Date)-lt $until)
 }finally{
   @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $probe -ErrorAction SilentlyContinue|Where-Object {$_.InterfaceIndex -eq $idx -and $_.NextHop -eq $hop})|Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
 }
 return [pscustomobject]@{Ready=[bool]$ready;Reason=$(if($ready){'PASS'}else{'TCP_PROBE_TIMEOUT'});Probe='1.0.0.1:443';InterfaceIndex=$idx;NextHop=$hop;Attempts=$attempts}
}

function Remove-PhysicalShadows {
 $s=Get-ShadowState;if(-not $s){return}
 $idx=[int]$s.interfaceIndex;$hop=[string]$s.nextHop
 foreach($prefix in @('0.0.0.0/1','128.0.0.0/1')){@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -ErrorAction SilentlyContinue|Where-Object {$_.InterfaceIndex -eq $idx -and $_.NextHop -eq $hop})|Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue}
 Remove-Item $shadowFile -Force -ErrorAction SilentlyContinue
}
function Read-ServiceLogDelta([long]$Offset){
 if(-not(Test-Path $serviceLog)){return ''}
 $fs=[IO.File]::Open($serviceLog,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{if($Offset -gt $fs.Length){$Offset=0};[void]$fs.Seek($Offset,[IO.SeekOrigin]::Begin);$sr=[IO.StreamReader]::new($fs);try{return $sr.ReadToEnd()}finally{$sr.Dispose()}}finally{$fs.Dispose()}
}
function Wait-NativeReady($c,[long]$LogOffset,[int]$Seconds=18){
 $until=(Get-Date).AddSeconds($Seconds);$connectedNeedle='EVENT: CONNECTED '+[string]$c.IP+':'+[string]$c.Port
 do{
   $shadow=Get-ShadowState;if(-not $shadow){throw 'Physical shadow disappeared before native readiness.'}
   $delta=Read-ServiceLogDelta $LogOffset
   $event=($delta.Contains($connectedNeedle));$wfp=($delta.Contains('allow IPv4 traffic from TAP'))
   $native=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') -and $_.InterfaceIndex -ne [int]$shadow.interfaceIndex})
   if($event -and $wfp -and $native.Count -eq 2){
     $routeEvidence=@();foreach($r in @(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})){try{$im=[int](Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $r.InterfaceIndex).InterfaceMetric}catch{$im=99999};$routeEvidence+=,[ordered]@{prefix=$r.DestinationPrefix;interface=$r.InterfaceAlias;interfaceIndex=[int]$r.InterfaceIndex;nextHop=$r.NextHop;routeMetric=[int]$r.RouteMetric;interfaceMetric=$im;effectiveMetric=([int]$r.RouteMetric+$im)}}
     return [pscustomobject]@{Ready=$true;Event=$event;Wfp=$wfp;NativeRoutes=$native.Count;Routes=$routeEvidence;LogDeltaTail=(($delta -split "`r?`n")|Select-Object -Last 80)}
   }
   $svc=Get-Service $service -ErrorAction SilentlyContinue;if($svc -and $svc.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped){return [pscustomobject]@{Ready=$false;Reason='SERVICE_STOPPED';Event=$event;Wfp=$wfp;NativeRoutes=$native.Count}}
   Start-Sleep -Milliseconds 150
 }while((Get-Date)-lt $until)
 return [pscustomobject]@{Ready=$false;Reason='NATIVE_READY_TIMEOUT';Event=$event;Wfp=$wfp;NativeRoutes=$native.Count}
}
function Stop-Connector {
 $shadow=Get-ShadowState
 try{[void](Invoke-Connector @('stop') 20000 -IgnoreExit)}catch{}
 try{Stop-Service $service -Force -ErrorAction SilentlyContinue}catch{}
 if($shadow){$until=(Get-Date).AddSeconds(6);do{$native=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1') -and $_.InterfaceIndex -ne [int]$shadow.interfaceIndex});if($native.Count -eq 0){break};Start-Sleep -Milliseconds 100}while((Get-Date)-lt $until);Remove-PhysicalShadows}
 [void](Wait-Health $false 20)
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
function Schedule-ManualServiceMode {
 $cmd = "Start-Sleep -Seconds 8; sc.exe config OVPNConnectorService start= demand | Out-Null"
 Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-Command',$cmd) | Out-Null
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
 $shadow=Add-PhysicalShadows
 $logOffset=0;if(Test-Path $serviceLog){$logOffset=(Get-Item $serviceLog).Length}
 try{[void](Invoke-Connector @('start') 20000)}catch{
   Record-Failure $c 'START_FAIL';Stop-Connector;return $null
 }
 $native=Wait-NativeReady $c $logOffset 18
 if(-not $native.Ready){Write-ShadowEvidence ([ordered]@{at=(Get-Date).ToString('o');result='NATIVE_NOT_READY';candidate=[string]$c.SHA256;native=$native;shadow=$shadow});Record-Failure $c 'NATIVE_READY_FAIL';Stop-Connector;return $null}
 $dataPlane=Wait-NativeDataPlane 6
 if(-not $dataPlane.Ready){Write-ShadowEvidence ([ordered]@{at=(Get-Date).ToString('o');result='DATAPLANE_NOT_READY';candidate=[string]$c.SHA256;native=$native;dataPlane=$dataPlane;shadow=$shadow});Record-Failure $c 'DATAPLANE_READY_FAIL';Stop-Connector;return $null}
 Write-ShadowEvidence ([ordered]@{at=(Get-Date).ToString('o');result='DATAPLANE_READY';candidate=[string]$c.SHA256;native=$native;dataPlane=$dataPlane;shadow=$shadow})
 Remove-PhysicalShadows
 $h=Wait-Health $true 14 ([string]$c.Country)
 if(-not $h.Healthy){$fallback=Add-PhysicalShadows;Write-ShadowEvidence ([ordered]@{at=(Get-Date).ToString('o');result='POST_TAKEOVER_HEALTH_FAIL';candidate=[string]$c.SHA256;health=$h;fallback=$fallback;native=$native});Record-Failure $c 'LIVE_FAIL';Stop-Connector;return $null}
 Write-ShadowEvidence ([ordered]@{at=(Get-Date).ToString('o');result='PASS';candidate=[string]$c.SHA256;health=$h;native=$native;dataPlane=$dataPlane})
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
