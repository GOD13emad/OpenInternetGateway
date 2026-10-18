[CmdletBinding()]
param([int]$Count=48,[int]$PerCountry=6,[int]$PreserveOld=8,[int]$KeepGenerations=4)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$csv=Join-Path $Root 'evidence\vpngate-mirror-api.csv'
if(-not(Test-Path $csv)){throw 'VPN Gate mirror API cache missing.'}
$MaxCachedCsvBytes=72*1024*1024
$MaxCsvLineBytes=256*1024
if((Get-Item -LiteralPath $csv).Length -gt $MaxCachedCsvBytes){throw 'VPN Gate mirror CSV exceeds size limit.'}

$factory=Join-Path $Root 'runtime\config-factory'
$stagingRoot=Join-Path $factory 'staging'
$generations=Join-Path $factory 'generations'
$active=Join-Path $Root 'runtime\udp-cache'
$successFile=Join-Path $factory 'successes.json'
New-Item -ItemType Directory -Force -Path $factory,$stagingRoot,$generations,(Join-Path $factory 'quarantine')|Out-Null

$oldIndex=@()
if(Test-Path (Join-Path $active 'index.json')){
 try{$oldIndex=@(Get-Content -Raw (Join-Path $active 'index.json')|ConvertFrom-Json)}catch{$oldIndex=@()}
}
$success=@{}
if(Test-Path $successFile){try{$success=Get-Content -Raw $successFile|ConvertFrom-Json -AsHashtable}catch{$success=@{}}}

$stage=Join-Path $stagingRoot ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage|Out-Null

function Test-AllowedRelayIp([Net.IPAddress]$Address){
 if($null -eq $Address -or $Address.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){return $false}
 $b=$Address.GetAddressBytes()
 $a=[int]$b[0];$c=[int]$b[1]
 if($a -eq 0 -or $a -eq 10 -or $a -eq 127 -or $a -ge 224){return $false}
 if($a -eq 100 -and $c -ge 64 -and $c -le 127){return $false}
 if($a -eq 169 -and $c -eq 254){return $false}
 if($a -eq 172 -and $c -ge 16 -and $c -le 31){return $false}
 if($a -eq 192 -and (($c -eq 0 -and [int]$b[2] -eq 0) -or $c -eq 168)){return $false}
 if($a -eq 198 -and $c -in @(18,19)){return $false}
 return $true
}

function Test-SafePublicVpnProfile([string]$text){
 $ls=$text -split '[\r\n]+'
 # Public OpenVPN profiles are data only: explicitly allow known client directives.
 # Unlisted directives may invoke local scripts, manage sockets or write files.
 if([Text.Encoding]::UTF8.GetByteCount($text) -gt 131072 -or $text.Contains([char]0)){return $false}
 $allowed=@('client','dev','proto','remote','cipher','data-ciphers','data-ciphers-fallback','auth','resolv-retry','nobind','persist-key','persist-tun','verb','mute','tun-mtu','mssfix','sndbuf','rcvbuf','reneg-sec','key-direction','auth-nocache','explicit-exit-notify','tls-client','remote-cert-tls','verify-x509-name','tls-version-min','tls-version-max','tls-cipher','tls-ciphersuites','ping','ping-restart','ping-exit','keepalive','connect-retry','connect-retry-max','connect-timeout','server-poll-timeout')
 $allowedBlocks=@('ca','cert','key','tls-auth','tls-crypt','tls-crypt-v2')
 $openBlock='';$seenOps=@{};$seenBlocks=@{};$unsafe=$false
 foreach($rawLine in $ls){
   $v=([string]$rawLine).Trim()
   if(-not $v -or $v.StartsWith('#') -or $v.StartsWith(';')){continue}
   if($openBlock){
     if($v.ToLowerInvariant() -eq ('</'+$openBlock+'>')){$openBlock=''}
     elseif($v -match '^</?[^>]+>$'){$unsafe=$true;break}
     continue
   }
   if($v -match '^<([A-Za-z][A-Za-z0-9-]*)>$'){
     $tag=$Matches[1].ToLowerInvariant()
     if($tag -notin $allowedBlocks -or $seenBlocks.ContainsKey($tag)){$unsafe=$true;break}
     $seenBlocks[$tag]=1;$openBlock=$tag;continue
   }
   if($v.StartsWith('<')){$unsafe=$true;break}
   $fields=@($v -split '\s+')
   $opt=$fields[0].ToLowerInvariant()
   if($opt -notin $allowed){$unsafe=$true;break}
   # Imported profiles cannot disable crypto, including a NONE cipher-list
   # member that would otherwise survive in a colon-delimited list.
   if($opt -in @('cipher','auth','data-ciphers','data-ciphers-fallback')){
     if($fields.Count -ne 2 -or 'none' -in ($fields[1].ToLowerInvariant() -split ':')){$unsafe=$true;break}
   }
   $seenOps[$opt]=[int]$seenOps[$opt]+1
   if($opt -in @('client','dev','proto','remote') -and $seenOps[$opt] -ne 1){$unsafe=$true;break}
   if($opt -eq 'remote'){
     if($fields.Count -ne 3){$unsafe=$true;break}
     $parsedIp=$null
     if(-not [Net.IPAddress]::TryParse($fields[1],[ref]$parsedIp) -or $parsedIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork){$unsafe=$true;break}
     $parsedPort=0
     if(-not [int]::TryParse($fields[2],[ref]$parsedPort) -or $parsedPort -lt 1 -or $parsedPort -gt 65535){$unsafe=$true;break}
   }
 }
 if($unsafe -or $openBlock){return $false}
 if(@('client','dev','proto','remote')|Where-Object {$seenOps[$_] -ne 1}){return $false}
 if(@('ca','cert','key')|Where-Object {$seenBlocks[$_] -ne 1}){return $false}
 return $true
}

$rows=@()
$seen=@{}
foreach($line in Get-Content -LiteralPath $csv){
 if($line.Length -gt $MaxCsvLineBytes){continue}
 if(-not $line -or $line.StartsWith('*') -or $line.StartsWith('#')){continue}
 $p=$line -split ','
 if($p.Count -lt 15){continue}
 $country=([string]$p[6]).Trim().ToUpperInvariant();$countryName=([string]$p[5]).Trim()
 if([string]::IsNullOrWhiteSpace($country)){continue}
 if(([string]$p[-1]).Length -gt $MaxCsvLineBytes){continue}
  try{$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p[-1].Trim()))}catch{continue}
 $ls=$text -split '[\r\n]+'
 if(-not(Test-SafePublicVpnProfile $text)){continue}
 $proto=($ls|Where-Object {$_ -match '^proto\s+'}|Select-Object -First 1)
 $remote=($ls|Where-Object {$_ -match '^remote\s+'}|Select-Object -First 1)
 $transport=$null;$transportRank=9
 if($proto -match '^proto\s+udp'){$transport='udp';$transportRank=0}
 elseif($proto -match '^proto\s+tcp'){$transport='tcp';$transportRank=1}
 else{continue}
 if($remote -notmatch '^remote\s+([0-9\.]+)\s+(\d+)'){continue}
 $ip=$Matches[1];$port=[int]$Matches[2]
 # Reject mismatched CSV metadata and OpenVPN destination before deduplication.
 $csvIp=$null;$remoteIp=$null
 if(-not([Net.IPAddress]::TryParse(([string]$p[1]).Trim(),[ref]$csvIp)) -or
    -not([Net.IPAddress]::TryParse($ip,[ref]$remoteIp)) -or
    $csvIp.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
    -not $csvIp.Equals($remoteIp) -or
    -not(Test-AllowedRelayIp $remoteIp)){continue}
 $key=($transport+':'+$ip+':'+$port)
 if($seen.ContainsKey($key)){continue}
 if($text -notmatch '(?m)^client\s*$'){continue}
 if($text -notmatch '(?m)^dev\s+tun\s*$'){continue}
 if($text -notmatch '(?s)<ca>.+?</ca>'){continue}
 if($text -notmatch '(?s)<cert>.+?</cert>'){continue}
 if($text -notmatch '(?s)<key>.+?</key>'){continue}
 # Treat public profiles as data, never executable local policy.
 if($text -match '(?mi)^\s*(?:script-security|up|down|route-up|route-pre-down|ipchange|plugin|client-connect|client-disconnect|learn-address)'){continue}
 # A malformed provider metric must reject this row, not abort pool refresh.
 # Parse before reserving the endpoint so a later valid duplicate survives.
 $scoreValue=[long]0;$speedValue=[long]0;$sessionValue=[int]0
 if(-not([long]::TryParse(([string]$p[2]).Trim(),[ref]$scoreValue)) -or
    -not([long]::TryParse(([string]$p[4]).Trim(),[ref]$speedValue)) -or
    -not([int]::TryParse(([string]$p[7]).Trim(),[ref]$sessionValue))){continue}
 # Only safe, complete profiles can reserve a deduplicated endpoint.
 $seen[$key]=$true
 $rows += [pscustomobject]@{
   Host=$p[0];IP=$ip;Score=$scoreValue;Ping=$p[3];Speed=$speedValue;
   Sessions=$sessionValue;Port=$port;Text=$text;Source='VPNGate';
   Protocol=$transport;TransportRank=$transportRank;Country=$country;CountryName=$countryName
 }
}
$countryPriority=@('JP','KR','US','SG','TH','VN','FR','DE','NL','GB','CA','AU','PT','RU')
$available=@($rows|Select-Object -ExpandProperty Country -Unique)
$order=@($countryPriority|Where-Object {$_ -in $available})
$order+=@($available|Where-Object {$_ -notin $countryPriority}|Sort-Object)
$selected=@()
foreach($cc in $order){
 if($selected.Count -ge $Count){break}
 $selected+=@($rows|Where-Object Country -eq $cc|Sort-Object TransportRank,@{Expression='Score';Descending=$true}|Select-Object -First $PerCountry)
}
if($selected.Count -lt $Count){
 $keys=@{};foreach($x in $selected){$keys[([string]$x.Protocol+':'+[string]$x.IP+':'+[string]$x.Port)]=$true}
 $rest=@($rows|Where-Object {-not $keys.ContainsKey(([string]$_.Protocol+':'+[string]$_.IP+':'+[string]$_.Port))}|Sort-Object TransportRank,@{Expression='Score';Descending=$true})
 $selected+=@($rest|Select-Object -First ($Count-$selected.Count))
}
$selected=@($selected|Select-Object -First $Count)
if($selected.Count -lt 3){
 Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
 throw "Only $($selected.Count) structurally valid OpenVPN profiles found."
}

$meta=@();$i=0
foreach($r in $selected){
 $i++
 $safe=($r.Host -replace '[^A-Za-z0-9_-]','_')
 $file=('{0:D2}-{1}-{2}-{3}-{4}.ovpn' -f $i,$r.Protocol,$safe,$r.IP,$r.Port)
 $path=Join-Path $stage $file
 [IO.File]::WriteAllText($path,$r.Text,[Text.UTF8Encoding]::new($false))
 $sha=(Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant()
 $relative='runtime\udp-cache\'+$file
 $meta += [pscustomobject]@{
   Rank=$i;Host=$r.Host;IP=$r.IP;Port=$r.Port;Protocol=$r.Protocol;Country=$r.Country;CountryName=$r.CountryName;Score=$r.Score;Ping=$r.Ping;
   Speed=$r.Speed;Sessions=$r.Sessions;Profile=$relative;SHA256=$sha;Source=$r.Source;
   GeneratedAt=(Get-Date).ToString('o')
 }
}

# Preserve several old profiles, prioritizing those with proven live success.
$oldSorted=@($oldIndex|ForEach-Object{
 $k=([string]$_.SHA256).ToLowerInvariant()
 [pscustomobject]@{Item=$_;Validated=$(if($success.ContainsKey($k)){1}else{0});Rank=[int]$_.Rank}
}|Sort-Object @{Expression='Validated';Descending=$true},Rank)
$kept=0
foreach($wrap in $oldSorted){
 if($kept -ge $PreserveOld){break}
 $o=$wrap.Item
 $sha=([string]$o.SHA256).ToLowerInvariant()
 if($meta|Where-Object {([string]$_.SHA256).ToLowerInvariant() -eq $sha}){continue}
 # Match Config Factory Status: an old index cannot import a file outside
 # the active cache, a reparse point, or an unbounded file.
 $relative=([string]$o.Profile).Replace([char]92,'/')
 if($relative -cnotmatch '^runtime/udp-cache/([A-Za-z0-9][A-Za-z0-9_.-]*\.ovpn)$'){continue}
 $leaf=$Matches[1]
 if($sha -cnotmatch '^[0-9a-f]{64}$'){continue}
 $oldPath=Join-Path $active $leaf
 try{
   if(-not(Test-Path -LiteralPath $oldPath -PathType Leaf)){continue}
   $entry=Get-Item -LiteralPath $oldPath -ErrorAction Stop
   if(($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $entry.Length -gt 131072){continue}
   if((Get-FileHash -LiteralPath $oldPath -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() -ne $sha){continue}
   $text=Get-Content -Raw -LiteralPath $oldPath -ErrorAction Stop
 }catch{continue}
 if(-not(Test-SafePublicVpnProfile $text)){continue}
 $lkgRemote=[regex]::Match($text,'(?m)^remote\s+([0-9.]+)\s+(\d+)\s*$')
 if(-not $lkgRemote.Success){continue}
 $lkgIp=$null
 if(-not([Net.IPAddress]::TryParse($lkgRemote.Groups[1].Value,[ref]$lkgIp)) -or
    -not(Test-AllowedRelayIp $lkgIp) -or
    $lkgRemote.Groups[1].Value -ne ([string]$o.IP).Trim()){continue}
 $protocol=if($text -match '(?m)^proto\s+udp'){'udp'}elseif($text -match '(?m)^proto\s+tcp'){'tcp'}else{'unknown'}
 $i++;$kept++
 $file=('LKG-{0:D2}-{1}' -f $kept,(Split-Path $oldPath -Leaf))
 Copy-Item -LiteralPath $oldPath -Destination (Join-Path $stage $file) -Force
 $country=[string]$o.Country
 if([string]::IsNullOrWhiteSpace($country) -and $success.ContainsKey($sha)){try{$country=[string]$success[$sha].country}catch{}}
 if([string]::IsNullOrWhiteSpace($country)){$country='JP'} # legacy pools before 2.3 were JP-only
 $meta += [pscustomobject]@{
   Rank=$i;Host=$o.Host;IP=$o.IP;Port=$o.Port;Protocol=$protocol;Country=$country;CountryName=$o.CountryName;Score=$o.Score;Ping=$o.Ping;
   Speed=$o.Speed;Sessions=$o.Sessions;Profile=('runtime\udp-cache\'+$file);SHA256=$sha;
   Source='LastKnownGood';GeneratedAt=(Get-Date).ToString('o')
 }
}

$meta|ConvertTo-Json -Depth 6|Set-Content -Encoding UTF8 (Join-Path $stage 'index.json')
foreach($c in $meta){
 $leaf=Split-Path $c.Profile -Leaf
 $p=Join-Path $stage $leaf
 if(-not(Test-Path $p)){throw "Staged profile missing: $leaf"}
 $sha=(Get-FileHash -Algorithm SHA256 $p).Hash.ToLowerInvariant()
 if($sha -ne $c.SHA256){throw "Staged hash mismatch: $leaf"}
}

$archivedPrevious=$null
if(Test-Path $active){
 $hasIndex=Test-Path (Join-Path $active 'index.json')
 if($hasIndex){
   $stamp=(Get-Date).ToString('yyyyMMdd-HHmmssfff')
   $archivedPrevious=Join-Path $generations $stamp
   Move-Item -LiteralPath $active -Destination $archivedPrevious
 }else{Remove-Item $active -Recurse -Force -ErrorAction SilentlyContinue}
}
try{
 Move-Item -LiteralPath $stage -Destination $active
}catch{
 # A failed stage activation must preserve the previous verified pool.
 if($archivedPrevious -and (Test-Path -LiteralPath $archivedPrevious) -and -not(Test-Path -LiteralPath $active)){
   Move-Item -LiteralPath $archivedPrevious -Destination $active
 }
 throw
}

$old=@(Get-ChildItem $generations -Directory -ErrorAction SilentlyContinue|Sort-Object Name -Descending)
if($old.Count -gt $KeepGenerations){
 $old|Select-Object -Skip $KeepGenerations|ForEach-Object{Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue}
}
Get-ChildItem $stagingRoot -Directory -ErrorAction SilentlyContinue|Where-Object LastWriteTime -lt (Get-Date).AddHours(-2)|Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

& (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Status | Out-Null
$udp=@($meta|Where-Object Protocol -eq 'udp').Count
$tcp=@($meta|Where-Object Protocol -eq 'tcp').Count
Write-Host ('Config Factory promoted '+$meta.Count+' profiles atomically (UDP='+$udp+', TCP='+$tcp+', LKG='+$kept+').')
