param(
  [Parameter(Mandatory=$true)][string]$StableDir,
  [Parameter(Mandatory=$true)][string]$CandidateDir,
  [Parameter(Mandatory=$true)][string]$ReceiptPath
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'DISPOSABLE_GITHUB_WINDOWS_RUNNER_REQUIRED'
}
if ($env:GITHUB_REPOSITORY -ne 'GOD13emad/OpenInternetGateway') { throw 'SOURCE_REPOSITORY_MISMATCH' }
$expectedCommit='05a15ba7f64c6ab570cad110a1af45c6f6a16fd1'
$stableExe=Join-Path $StableDir 'OpenInternetGateway-Setup-2.5.19.exe'
$sumsFile=Join-Path $StableDir 'SHA256SUMS.txt'
$candidates=@(Get-ChildItem -LiteralPath $CandidateDir -File -Filter '*.exe')
if ($candidates.Count -ne 1 -or $candidates[0].Name -ne 'OpenInternetGateway-Setup-2.5.19.exe') { throw 'AMBIGUOUS_CANDIDATE_INSTALLER' }
if (!(Test-Path -LiteralPath $stableExe) -or !(Test-Path -LiteralPath $sumsFile)) { throw 'STABLE_RELEASE_ASSET_MISSING' }
$stableRecord=@(Get-Content -LiteralPath $sumsFile -Encoding ascii | Where-Object { $_ -match '^[0-9a-fA-F]{64}  \*?OpenInternetGateway-Setup-2[.]5[.]19[.]exe$' })
if ($stableRecord.Count -ne 1) { throw 'STABLE_RELEASE_CHECKSUM_RECORD_INVALID' }
$stableSHA=(Get-FileHash -LiteralPath $stableExe -Algorithm SHA256).Hash.ToLowerInvariant()
$candidateSHA=(Get-FileHash -LiteralPath $candidates[0].FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($stableSHA -ne $stableRecord[0].Substring(0,64).ToLowerInvariant() -or $stableSHA -eq $candidateSHA) { throw 'INSTALLER_PROVENANCE_FAIL' }
$programRoot=Join-Path $env:LOCALAPPDATA 'Programs'
if (!(Test-Path -LiteralPath $programRoot)) { New-Item -ItemType Directory -Path $programRoot -Force | Out-Null }

function Find-OIG {
  $found=@(Get-ChildItem -LiteralPath $programRoot -Recurse -Depth 3 -File -Filter '*.exe' -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match '^Open[ ]?Internet[ ]?Gateway[.]exe$' } |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.DirectoryName 'resources\app.asar') })
  if ($found.Count -gt 1) { throw 'MULTIPLE_INSTALLS' }
  if ($found.Count -eq 0) { return $null }
  return [pscustomobject]@{Exe=$found[0].FullName;Root=$found[0].DirectoryName;Asar=(Join-Path $found[0].DirectoryName 'resources\app.asar')}
}
if ($null -ne (Find-OIG)) { throw 'RUNNER_IS_NOT_FRESH' }
function Run-Silent([string]$exe,[string]$stage) {
  $p=Start-Process -FilePath $exe -ArgumentList @('/S') -PassThru
  if (!$p.WaitForExit(180000)) { $p.Kill(); throw ('INSTALL_TIMEOUT_'+$stage) }
  if ($p.ExitCode -ne 0) { throw ('INSTALL_EXIT_'+$stage+'_'+$p.ExitCode) }
}
function Installed([string]$label) {
  $app=Find-OIG
  if ($null -eq $app) { throw ('APP_MISSING_'+$label) }
  $hash=(Get-FileHash -LiteralPath $app.Asar -Algorithm SHA256).Hash.ToLowerInvariant()
  return [pscustomobject]@{App=$app;AsarSHA=$hash}
}
function Check-Asar([string]$file,[bool]$expectedGuard) {
  $js="const a=require('@electron/asar');const inventory=a.listPackage(process.argv[1]).map(p=>p.replaceAll(String.fromCharCode(92),'/'));const hits=inventory.filter(p=>p.endsWith('src/main/platform-backend.js'));if(hits.length!==1){console.error('ASAR_SOURCE_PATH_AMBIGUOUS_OR_MISSING',JSON.stringify(hits),'RELATED',JSON.stringify(inventory.filter(p=>p.toLowerCase().includes('platform')).slice(0,12)),'SAMPLE',JSON.stringify(inventory.slice(0,8)));process.exit(18)}const asarPath=hits[0].startsWith('/')?hits[0].slice(1):hits[0];const s=a.extractFile(process.argv[1],asarPath).toString('utf8');const guard=s.includes('PATH can include user-writable directories');const risk=s.includes('for (const dir of String(process.env.PATH ||');if(guard!==Boolean(Number(process.argv[2]))||risk===guard)process.exit(17);console.log('PACKAGED_PWSH_RESOLVER_PASS');"
  Push-Location (Join-Path $PSScriptRoot '..\app')
  try {
    & node -e $js $file ([string][int]$expectedGuard)
    if ($LASTEXITCODE -ne 0) { throw 'PACKAGED_HELPER_GUARD_MISMATCH' }
  } finally { Pop-Location }
}
function Stop-Only-Owned-App([string]$exe) {
  Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
    try { if ($_.Path -and [string]::Equals($_.Path,$exe,[StringComparison]::OrdinalIgnoreCase)) {
      Stop-Process -Id $_.Id -Force -ErrorAction Stop
    } } catch {}
  }
}
# All mutations below take place ONLY inside one throwaway GitHub-hosted Windows VM.
Run-Silent $stableExe 'STABLE_FRESH'
$stable=Installed 'STABLE_FRESH'
Check-Asar $stable.App.Asar $false
Stop-Only-Owned-App $stable.App.Exe
Run-Silent $candidates[0].FullName 'CANDIDATE_UPGRADE'
$candidate=Installed 'CANDIDATE_UPGRADE'
Check-Asar $candidate.App.Asar $true
if ($candidate.AsarSHA -eq $stable.AsarSHA) { throw 'CANDIDATE_BINARY_NOT_DISTINCT' }
Stop-Only-Owned-App $candidate.App.Exe
Run-Silent $stableExe 'STABLE_ROLLBACK'
$rollback=Installed 'STABLE_ROLLBACK'
Check-Asar $rollback.App.Asar $false
if ($rollback.AsarSHA -ne $stable.AsarSHA) { throw 'ROLLBACK_NOT_BYTE_EXACT' }
$uninstaller=@(Get-ChildItem -LiteralPath $rollback.App.Root -File -Filter 'Uninstall*.exe' -ErrorAction SilentlyContinue)
if ($uninstaller.Count -ne 1) { throw 'UNINSTALLER_NOT_IDENTIFIED' }
Stop-Only-Owned-App $rollback.App.Exe
Run-Silent $uninstaller[0].FullName 'DISPOSABLE_CLEANUP'
if ($null -ne (Find-OIG)) { throw 'CLEANUP_FAILED' }
$receipt=[ordered]@{
  schema='oig-disposable-installer-acceptance-v1';status='PASS';sourceSHA=$expectedCommit
  sourceRun=38721014237;stableTag='v2.5.19'
  stableSetupSHA256=$stableSHA;candidateSetupSHA256=$candidateSHA
  stableAsarSHA256=$stable.AsarSHA;candidateAsarSHA256=$candidate.AsarSHA
  restoredAsarSHA256=$rollback.AsarSHA
  packagedPwshPathGuard=$true;stableRestoredByteExact=$true;uninstalled=$true
  host='github-hosted-windows';ownerMachineTouched=$false
  realGuiOrVpnAcceptance=$false
}
$receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReceiptPath -Encoding utf8
Write-Output 'OIG_DISPOSABLE_INSTALL_UPGRADE_ROLLBACK_PASS'
