[CmdletBinding()]
param([int]$Count=12,[int]$PreserveOld=4,[int]$KeepGenerations=4)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$csv=Join-Path $Root 'evidence\vpngate-mirror-api.csv'
if(-not(Test-Path $csv)){throw 'VPN Gate mirror API cache missing.'}

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

$rows=@()
$seen=@{}
foreach($line in Get-Content -LiteralPath $csv){
 if(-not $line -or $line.StartsWith('*') -or $line.StartsWith('#')){continue}
 $p=$line -split ','
 if($p.Count -lt 15 -or $p[6] -ne 'JP'){continue}
 try{$text=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p[-1].Trim()))}catch{continue}
 $ls=$text -split '[\r\n]+'
 $proto=($ls|Where-Object {$_ -match '^proto\s+'}|Select-Object -First 1)
 $remote=($ls|Where-Object {$_ -match '^remote\s+'}|Select-Object -First 1)
 $transport=$null;$transportRank=9
 if($proto -match '^proto\s+udp'){$transport='udp';$transportRank=0}
 elseif($proto -match '^proto\s+tcp'){$transport='tcp';$transportRank=1}
 else{continue}
 if($remote -notmatch '^remote\s+([0-9\.]+)\s+(\d+)'){continue}
 $ip=$Matches[1];$port=[int]$Matches[2]
 $key=($transport+':'+$ip+':'+$port)
 if($seen.ContainsKey($key)){continue}
 $seen[$key]=$true
 if($text -notmatch '(?m)^client\s*$'){continue}
 if($text -notmatch '(?m)^dev\s+tun\s*$'){continue}
 if($text -notmatch '(?s)<ca>.+?</ca>'){continue}
 if($text -notmatch '(?s)<cert>.+?</cert>'){continue}
 if($text -notmatch '(?s)<key>.+?</key>'){continue}
 $rows += [pscustomobject]@{
   Host=$p[0];IP=$ip;Score=[int64]$p[2];Ping=$p[3];Speed=[int64]$p[4];
   Sessions=[int]$p[7];Port=$port;Text=$text;Source='VPNGate';
   Protocol=$transport;TransportRank=$transportRank
 }
}
$selected=@($rows|Sort-Object TransportRank,@{Expression='Score';Descending=$true}|Select-Object -First $Count)
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
   Rank=$i;Host=$r.Host;IP=$r.IP;Port=$r.Port;Protocol=$r.Protocol;Score=$r.Score;Ping=$r.Ping;
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
 $oldPath=if([IO.Path]::IsPathRooted([string]$o.Profile)){[string]$o.Profile}else{Join-Path $Root ([string]$o.Profile)}
 if(-not(Test-Path $oldPath)){continue}
 if((Get-FileHash -Algorithm SHA256 $oldPath).Hash.ToLowerInvariant() -ne $sha){continue}
 $text=Get-Content -Raw $oldPath
 $protocol=if($text -match '(?m)^proto\s+udp'){'udp'}elseif($text -match '(?m)^proto\s+tcp'){'tcp'}else{'unknown'}
 $i++;$kept++
 $file=('LKG-{0:D2}-{1}' -f $kept,(Split-Path $oldPath -Leaf))
 Copy-Item -LiteralPath $oldPath -Destination (Join-Path $stage $file) -Force
 $meta += [pscustomobject]@{
   Rank=$i;Host=$o.Host;IP=$o.IP;Port=$o.Port;Protocol=$protocol;Score=$o.Score;Ping=$o.Ping;
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

if(Test-Path $active){
 $hasIndex=Test-Path (Join-Path $active 'index.json')
 if($hasIndex){
   $stamp=(Get-Date).ToString('yyyyMMdd-HHmmssfff')
   Move-Item -LiteralPath $active -Destination (Join-Path $generations $stamp)
 }else{Remove-Item $active -Recurse -Force -ErrorAction SilentlyContinue}
}
Move-Item -LiteralPath $stage -Destination $active

$old=@(Get-ChildItem $generations -Directory -ErrorAction SilentlyContinue|Sort-Object Name -Descending)
if($old.Count -gt $KeepGenerations){
 $old|Select-Object -Skip $KeepGenerations|ForEach-Object{Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue}
}
Get-ChildItem $stagingRoot -Directory -ErrorAction SilentlyContinue|Where-Object LastWriteTime -lt (Get-Date).AddHours(-2)|Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

& (Join-Path $PSScriptRoot 'Config-Factory.ps1') -Action Status | Out-Null
$udp=@($meta|Where-Object Protocol -eq 'udp').Count
$tcp=@($meta|Where-Object Protocol -eq 'tcp').Count
Write-Host ('Config Factory promoted '+$meta.Count+' profiles atomically (UDP='+$udp+', TCP='+$tcp+', LKG='+$kept+').')
