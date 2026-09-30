[CmdletBinding()]
param([int]$MaxSources=3)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$csv=Join-Path $Root 'evidence\vpngate-mirror-api.csv'
$seedBases=@(
 'https://www.vpngate.net',
 'http://210.222.246.148:12814',
 'http://150.40.105.19:35399',
 'http://150.40.105.6:11803',
 'http://150.40.105.5:32536',
 'http://150.40.105.24:38827'
)
$bases=New-Object System.Collections.Generic.List[string]
foreach($s in $seedBases){if(-not $bases.Contains($s)){$bases.Add($s)}}
$tmpRoot=Join-Path ([IO.Path]::GetTempPath()) ('oig-vpngate-refresh-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmpRoot|Out-Null
$jobs=New-Object System.Collections.Generic.List[object]
$usable=@()
$used=@()
$attemptedSources=@()
$merged=New-Object System.Collections.Generic.List[string]
$cachedAdded=0
$cachedSnapshotExisted=Test-Path -LiteralPath $csv
try{
 $i=0
 foreach($base in $bases){
  $i++
  $out=Join-Path $tmpRoot ('source-'+$i+'.csv')
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName='curl.exe'
  $psi.UseShellExecute=$false
  $psi.CreateNoWindow=$true
  foreach($a in @('-4','-L','--fail','--noproxy','*','--connect-timeout','2','--max-time','8','-sS','-o',$out,($base+'/api/iphone/'))){[void]$psi.ArgumentList.Add([string]$a)}
  $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
  try{
   if($p.Start()){$jobs.Add([pscustomobject]@{Base=$base;Path=$out;Process=$p})}
  }catch{$p.Dispose()}
 }
 $deadline=(Get-Date).AddSeconds(9)
 do{
  $running=@($jobs|Where-Object {-not $_.Process.HasExited})
  if($running.Count -eq 0){break}
  Start-Sleep -Milliseconds 100
 }while((Get-Date)-lt $deadline)
 foreach($j in $jobs){
  if(-not $j.Process.HasExited){try{$j.Process.Kill($true)}catch{}}
  try{$j.Process.WaitForExit(1000)|Out-Null}catch{}
 }
 foreach($j in $jobs){
  if(-not(Test-Path -LiteralPath $j.Path)){continue}
  $size=(Get-Item -LiteralPath $j.Path).Length
  if($size -lt 100000){continue}
  $rows=0
  foreach($line in [IO.File]::ReadLines([string]$j.Path)){
   if([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('*') -or $line.StartsWith('#')){continue}
   if(($line -split ',').Count -ge 15){$rows++}
  }
  if($rows -ge 8){
   $complete=$false
   try{$complete=($j.Process.HasExited -and $j.Process.ExitCode -eq 0)}catch{}
   $usable+=,[pscustomobject]@{Base=$j.Base;Path=$j.Path;Rows=$rows;Size=$size;Complete=$complete}
  }
 }
 $chosen=@($usable|Sort-Object @{Expression='Complete';Descending=$true},@{Expression='Rows';Descending=$true}|Select-Object -First ([Math]::Max(1,$MaxSources)))
 $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
 foreach($j in $chosen){
  $attemptedSources+=,[string]$j.Base
  foreach($line in [IO.File]::ReadLines([string]$j.Path)){
   if([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('*') -or $line.StartsWith('#')){continue}
   if(($line -split ',').Count -lt 15){continue}
   if($seen.Add($line)){$merged.Add($line)}
  }
 }
 $liveMergedRows=$merged.Count
 # A bounded live fetch may time out after returning useful complete rows.
 # Keep those fresh rows first, then fill coverage/diversity from the last
 # complete cache rather than replacing a broad snapshot with a narrow prefix.
 if($liveMergedRows -gt 0 -and $cachedSnapshotExisted){
  foreach($line in [IO.File]::ReadLines($csv)){
   if([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('*') -or $line.StartsWith('#')){continue}
   if(($line -split ',').Count -lt 15){continue}
   if($seen.Add($line)){$merged.Add($line);$cachedAdded++}
  }
 }
 $promoted=$false
 if($liveMergedRows -ge 8){
  New-Item -ItemType Directory -Force -Path (Split-Path $csv -Parent)|Out-Null
  $partial=$csv+'.partial'
  [IO.File]::WriteAllLines($partial,$merged,[Text.UTF8Encoding]::new($false))
  Move-Item -LiteralPath $partial -Destination $csv -Force
  $used=@($attemptedSources)
  $promoted=$true
  Write-Host ('VPN Gate sources OK: '+($used -join ', ')+'; live rows='+$liveMergedRows+'; cached fill='+$cachedAdded+'; merged rows='+$merged.Count)
 }elseif($cachedSnapshotExisted){
  Write-Warning ('Live VPN Gate fetch produced only '+$liveMergedRows+' complete rows; preserving cached snapshot.')
 }else{throw ('No usable VPN Gate snapshot: only '+$liveMergedRows+' complete live rows and no cache.')}
}finally{
 foreach($j in $jobs){try{if(-not $j.Process.HasExited){$j.Process.Kill($true)}}catch{};try{$j.Process.Dispose()}catch{}}
 Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
}
$source=if($used.Count){$used -join ' + '}else{'cached VPN Gate mirror snapshot'}
$partialCount=@($chosen|Where-Object {-not $_.Complete}).Count
[ordered]@{
 at=(Get-Date).ToString('o');refresh=$promoted;usedMirror=$(if($used.Count){$used[0]}else{$null});
 usedMirrors=@($used);attemptedSources=@($attemptedSources);sourceCount=$used.Count;partialSourceCount=$partialCount;
 liveMergedRows=$liveMergedRows;cachedMergedRows=$cachedAdded;mergedRows=$merged.Count;discoveredMirrors=$bases.Count;source=$source
}|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 (Join-Path $Root 'evidence\mirror-refresh-last.json')
& (Join-Path $PSScriptRoot 'Build-VpnGateUdpCache.ps1')
