[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
$Root=Split-Path -Parent $PSScriptRoot
$csv=Join-Path $Root 'evidence\vpngate-mirror-api.csv'
$seedBases=@(
 'http://210.222.246.148:12814',
 'http://150.40.105.19:35399',
 'http://150.40.105.6:11803',
 'http://150.40.105.5:32536',
 'http://150.40.105.24:38827'
)
$bases=New-Object System.Collections.Generic.List[string]
foreach($s in $seedBases){if(-not $bases.Contains($s)){$bases.Add($s)}}
$sitesTmp=Join-Path ([IO.Path]::GetTempPath()) 'oig-vpngate-sites.html'
foreach($s in $seedBases){
 if(Test-Path $sitesTmp){Remove-Item $sitesTmp -Force -ErrorAction SilentlyContinue}
 & curl.exe -4 -L --connect-timeout 2 --max-time 6 -sS -o $sitesTmp ($s+'/en/sites.aspx')
 if($LASTEXITCODE -eq 0 -and (Test-Path $sitesTmp) -and (Get-Item $sitesTmp).Length -gt 1000){
  $html=Get-Content -Raw -LiteralPath $sitesTmp
  $matches=[regex]::Matches($html,'http://[A-Za-z0-9\.\-]+:\d+/en/')
  foreach($m in $matches){$base=$m.Value.TrimEnd('/').Substring(0,$m.Value.TrimEnd('/').Length-3);$base=$base.TrimEnd('/');if(-not $bases.Contains($base)){$bases.Add($base)}}
  break
 }
}
$tmp=$csv+'.partial';$ok=$false;$used=$null
foreach($base in $bases){
 Remove-Item $tmp -Force -ErrorAction SilentlyContinue
 & curl.exe -4 -L --connect-timeout 2 --max-time 8 -sS -o $tmp ($base+'/api/iphone/')
 if($LASTEXITCODE -eq 0 -and (Test-Path $tmp) -and (Get-Item $tmp).Length -gt 100000){Move-Item $tmp $csv -Force;$ok=$true;$used=$base;break}
}
if(-not $ok){if(Test-Path $csv){Write-Warning 'Live mirror refresh failed; using cached API snapshot.'}else{throw 'No live mirror and no cache.'}}else{Write-Host ('Mirror OK: '+$used)}
[ordered]@{at=(Get-Date).ToString('o');refresh=$ok;usedMirror=$used;discoveredMirrors=$bases.Count}|ConvertTo-Json|Set-Content -Encoding UTF8 (Join-Path $Root 'evidence\mirror-refresh-last.json')
& (Join-Path $PSScriptRoot 'Build-VpnGateUdpCache.ps1')