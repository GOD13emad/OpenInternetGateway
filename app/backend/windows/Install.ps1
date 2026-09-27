[CmdletBinding()]
param([string]$InstallRoot=(Join-Path $env:LOCALAPPDATA 'OpenInternetGateway'))
$ErrorActionPreference='Stop'
$Source=$PSScriptRoot
$srcFull=[IO.Path]::GetFullPath($Source).TrimEnd('\')
$dstFull=[IO.Path]::GetFullPath($InstallRoot).TrimEnd('\')
if($srcFull -ieq $dstFull){
  & (Join-Path $InstallRoot 'scripts\Install-Launcher.ps1')
  if($LASTEXITCODE -ne 0){throw 'Launcher/Auto-Recovery setup failed.'}
  Write-Host ('INSTALLED '+$InstallRoot)
  exit 0
}
$tmp=$InstallRoot+'.new'
$previous=$InstallRoot+'.previous'
Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $tmp|Out-Null
Get-ChildItem -LiteralPath $Source -Force | ForEach-Object {
  Copy-Item -LiteralPath $_.FullName -Destination $tmp -Recurse -Force
}
# Verify staged copy before promotion.
$idx=Join-Path $tmp 'runtime\udp-cache\index.json'
if(-not(Test-Path $idx)){throw 'Installed payload is missing UDP cache index.'}
foreach($c in @(Get-Content -Raw $idx|ConvertFrom-Json)){
  $rel=[string]$c.Profile
  if([IO.Path]::IsPathRooted($rel)){throw "Non-portable profile path in installer payload: $rel"}
  $p=Join-Path $tmp $rel
  if(-not(Test-Path $p)){throw "Missing profile in installer payload: $rel"}
  if($c.SHA256){
    $sha=(Get-FileHash -Algorithm SHA256 $p).Hash.ToLowerInvariant()
    if($sha -ne ([string]$c.SHA256).ToLowerInvariant()){throw "Profile hash mismatch: $rel"}
  }
}
$bad=@()
Get-ChildItem $tmp -Recurse -Filter *.ps1 | ForEach-Object {
  $tokens=$null;$errors=$null
  [System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)|Out-Null
  if($errors.Count){$bad += $_.FullName}
}
if($bad){throw ('PowerShell parse failure in installed payload: '+($bad -join ', '))}
Remove-Item $previous -Recurse -Force -ErrorAction SilentlyContinue
if(Test-Path $InstallRoot){Move-Item -LiteralPath $InstallRoot -Destination $previous -Force}
Move-Item -LiteralPath $tmp -Destination $InstallRoot -Force

# Preserve machine-local runtime state during upgrades, but never require it on fresh installs.
$stateDst=Join-Path $InstallRoot 'state\current-openvpn-profile.json'
$stateSrc=Join-Path $Source 'state\current-openvpn-profile.json'
$prevState=Join-Path $previous 'state\current-openvpn-profile.json'
if(Test-Path $stateSrc){Copy-Item $stateSrc $stateDst -Force -ErrorAction SilentlyContinue}
elseif(Test-Path $prevState){Copy-Item $prevState $stateDst -Force -ErrorAction SilentlyContinue}

$ledgerNames=@('successes.json','failures.json','quarantine.json')
foreach($n in $ledgerNames){
 $prevLedger=Join-Path $previous ('runtime\config-factory\'+$n)
 $dstLedger=Join-Path $InstallRoot ('runtime\config-factory\'+$n)
 if(Test-Path $prevLedger){Copy-Item $prevLedger $dstLedger -Force -ErrorAction SilentlyContinue}
}
foreach($n in @('auto-recovery-last.json','connect-last-success.json')){
 $prevEvidence=Join-Path $previous ('evidence\'+$n)
 $dstEvidence=Join-Path $InstallRoot ('evidence\'+$n)
 if(Test-Path $prevEvidence){Copy-Item $prevEvidence $dstEvidence -Force -ErrorAction SilentlyContinue}
}

& (Join-Path $InstallRoot 'scripts\Config-Factory.ps1') -Action Status | Out-Null
& (Join-Path $InstallRoot 'scripts\Install-Launcher.ps1')
if($LASTEXITCODE -ne 0){throw 'Launcher/Auto-Recovery setup failed after install promotion.'}
[ordered]@{
 at=(Get-Date).ToString('o')
 source=$Source
 installRoot=$InstallRoot
 previous=$(if(Test-Path $previous){$previous}else{$null})
 files=(Get-ChildItem $InstallRoot -Recurse -File).Count
}|ConvertTo-Json|Set-Content -Encoding UTF8 (Join-Path $InstallRoot 'evidence\install-last.json')
& (Join-Path $InstallRoot 'OpenInternetGateway.ps1') -Action Status
Write-Host ('INSTALLED '+$InstallRoot)
