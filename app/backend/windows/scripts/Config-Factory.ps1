[CmdletBinding()]
param(
 [ValidateSet('Status','Ensure','Refresh')][string]$Action='Status',
 [int]$MinPool=6,
 [int]$MaxAgeHours=8
)
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$factory=Join-Path $Root 'runtime\config-factory'
$active=Join-Path $Root 'runtime\udp-cache'
$successFile=Join-Path $factory 'successes.json'
$failureFile=Join-Path $factory 'failures.json'
$quarantineFile=Join-Path $factory 'quarantine.json'
$statusFile=Join-Path $factory 'status.json'
New-Item -ItemType Directory -Force -Path $factory,(Join-Path $factory 'generations'),(Join-Path $factory 'quarantine')|Out-Null

function Read-Map([string]$Path){
 if(Test-Path $Path){try{return (Get-Content -Raw $Path|ConvertFrom-Json -AsHashtable)}catch{}}
 return @{}
}
function Restore-LatestGeneration {
 $genRoot=Join-Path $factory 'generations'
 $latest=Get-ChildItem $genRoot -Directory -ErrorAction SilentlyContinue|Sort-Object Name -Descending|Select-Object -First 1
 if(-not $latest){return $false}
 if(Test-Path $active){Remove-Item $active -Recurse -Force -ErrorAction SilentlyContinue}
 New-Item -ItemType Directory -Force -Path $active|Out-Null
 Copy-Item (Join-Path $latest.FullName '*') -Destination $active -Recurse -Force
 return (Test-Path (Join-Path $active 'index.json'))
}
function Write-Status {
 $idx=Join-Path $active 'index.json'
 $items=@()
 $generatedAt=$null
 if(Test-Path $idx){
   try{$items=@(Get-Content -Raw $idx|ConvertFrom-Json)}catch{$items=@()}
   if($items.Count){$generatedAt=[string]$items[0].GeneratedAt}
 }
 $success=Read-Map $successFile
 $quarantine=Read-Map $quarantineFile
 $validated=0
 foreach($c in $items){if($success.ContainsKey(([string]$c.SHA256).ToLowerInvariant())){$validated++}}
 $standby=[Math]::Max(0,$items.Count-$validated)
 $gens=@(Get-ChildItem (Join-Path $factory 'generations') -Directory -ErrorAction SilentlyContinue)
 $protocols=@{}
 $countries=@{}
 foreach($item in $items){
   $pr=if($item.Protocol){[string]$item.Protocol}else{'unknown'}
   if($protocols.ContainsKey($pr)){$protocols[$pr]=[int]$protocols[$pr]+1}else{$protocols[$pr]=1}
   $cc=if($item.Country){[string]$item.Country}else{'??'}
   if($countries.ContainsKey($cc)){$countries[$cc]=[int]$countries[$cc]+1}else{$countries[$cc]=1}
 }
 $source=''
 $mirror=Join-Path $Root 'evidence\mirror-refresh-last.json'
 $lastRefresh=$generatedAt
 if(Test-Path $mirror){
   try{
     $m=Get-Content -Raw $mirror|ConvertFrom-Json
     if($m.usedMirror){$source=[string]$m.usedMirror}else{$source='cached VPN Gate mirror snapshot'}
     if($m.at){$lastRefresh=[string]$m.at}
   }catch{}
 }
 $ageHours=$null
 if($lastRefresh){try{$ageHours=[Math]::Round(((Get-Date)-[DateTimeOffset]::Parse($lastRefresh).LocalDateTime).TotalHours,2)}catch{}}
 $metadataComplete=($items.Count -gt 0 -and @($items|Where-Object {[string]::IsNullOrWhiteSpace([string]$_.Country)}).Count -eq 0)
 $obj=[ordered]@{
   at=(Get-Date).ToString('o')
   schemaVersion=2
   pool=$items.Count
   validated=$validated
   standby=$standby
   quarantined=$quarantine.Count
   generations=$gens.Count
   lastRefresh=$lastRefresh
   ageHours=$ageHours
   source=$source
   healthy=($items.Count -ge $MinPool)
   metadataComplete=$metadataComplete
   protocols=$protocols
   countries=$countries
 }
 $obj|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 $statusFile
 return [pscustomobject]$obj
}

if($Action -eq 'Refresh'){
 & (Join-Path $PSScriptRoot 'Refresh-VpnGateCache.ps1')
 $s=Write-Status
 $s|ConvertTo-Json -Compress
 exit 0
}
if($Action -eq 'Ensure'){
 $s=Write-Status
 $stale=$false
 if($null -eq $s.ageHours){$stale=$true}elseif([double]$s.ageHours -gt $MaxAgeHours){$stale=$true}
 if($s.pool -lt $MinPool -or $stale -or -not [bool]$s.metadataComplete){
   try{& (Join-Path $PSScriptRoot 'Refresh-VpnGateCache.ps1')}catch{
     if(-not(Test-Path (Join-Path $active 'index.json'))){
       if(-not(Restore-LatestGeneration)){throw}
       Write-Warning ('Factory discovery failed; restored latest archived generation: '+$_.Exception.Message)
     }else{
       Write-Warning ('Factory refresh failed; retaining last-known-good pool: '+$_.Exception.Message)
     }
   }
 }
 $s=Write-Status
 $s|ConvertTo-Json -Compress
 exit 0
}
$s=Write-Status
$s|ConvertTo-Json -Compress
