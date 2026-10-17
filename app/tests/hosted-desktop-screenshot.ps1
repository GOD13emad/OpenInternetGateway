[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Receipt,[string]$Installer,[string]$ExpectedSha256)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Native, installed-dashboard smoke only on disposable GitHub-hosted Windows.
foreach($pair in @(@('GITHUB_ACTIONS','true'),@('RUNNER_OS','Windows'),@('RUNNER_ENVIRONMENT','github-hosted'),@('GITHUB_REPOSITORY','GOD13emad/OpenInternetGateway'))){
  if([Environment]::GetEnvironmentVariable($pair[0]) -ne $pair[1]){throw ('DISPOSABLE_WINDOWS_RUNNER_REQUIRED_'+$pair[0])}
}
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'DOMAIN_JOINED_MACHINE_REFUSED'}
$backend=Join-Path $env:LOCALAPPDATA 'OpenInternetGateway'
$program=Join-Path $env:LOCALAPPDATA 'Programs\open-internet-gateway'
$exe=Join-Path $program 'Open Internet Gateway.exe'
$desired=Join-Path $backend 'state\desired-state.json'

# A fresh installer is used by the standard Windows Build job, which must
# not depend on any OpenVPN relay or start a VPN service.
$installerHash=''
if($Installer) {
  $existingRoutes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
  if($existingRoutes.Count -ne 0 -or (Get-Service OVPNConnectorService -ErrorAction SilentlyContinue)){
    throw 'DESKTOP_INSTALL_REQUIRES_CLEAN_NO_TUNNEL_RUNNER'
  }
  if(Test-Path -LiteralPath $exe){throw 'DESKTOP_INSTALL_NOT_FRESH'}
  if(-not(Test-Path -LiteralPath $Installer -PathType Leaf)){throw 'DESKTOP_INSTALLER_MISSING'}
  if($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$'){throw 'DESKTOP_INSTALLER_DIGEST_INVALID'}
  $installerHash=(Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
  if($installerHash -ne $ExpectedSha256.ToLowerInvariant()){throw 'DESKTOP_INSTALLER_DIGEST_MISMATCH'}
  $setup=Start-Process -FilePath (Resolve-Path $Installer).Path -ArgumentList '/S' -PassThru
  if(-not $setup.WaitForExit(180000)){throw 'DESKTOP_INSTALLER_TIMEOUT'}
  if($setup.ExitCode -ne 0){throw ('DESKTOP_INSTALLER_EXIT_'+$setup.ExitCode)}
  if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){throw 'DESKTOP_INSTALLER_EXE_NOT_FOUND'}
  if(Test-Path -LiteralPath $desired){throw 'DESKTOP_INSTALL_EXPECTED_CLEAN_STATE'}
  New-Item -ItemType Directory -Force -Path (Split-Path $desired -Parent)|Out-Null
  [ordered]@{desired='off';at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath $desired -Encoding UTF8
}
if(-not(Test-Path -LiteralPath $exe -PathType Leaf)){throw 'INSTALLED_DESKTOP_EXE_MISSING'}

function Assert-Offline {
  $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
  $svc=Get-Service -Name OVPNConnectorService -ErrorAction SilentlyContinue
  $intent=''
  if(Test-Path -LiteralPath $desired){try{$intent=[string](Get-Content -LiteralPath $desired -Raw|ConvertFrom-Json).desired}catch{}}
  if($intent -ne 'off' -or $routes.Count -ne 0 -or ($svc -and $svc.Status -ne 'Stopped')){
    throw 'DESKTOP_CAPTURE_REQUIRES_VERIFIED_DISCONNECTED_BASELINE'
  }
}
Assert-Offline

$existing=@(Get-CimInstance Win32_Process -Filter "Name='Open Internet Gateway.exe'" -ErrorAction SilentlyContinue)
if($existing.Count -ne 0){throw 'DESKTOP_GUI_ALREADY_RUNNING'}
$png=Join-Path $env:RUNNER_TEMP 'oig-installed-dashboard.png'
$probePath=Join-Path $env:RUNNER_TEMP 'oig-desktop-navigation-probe.json'
if(Test-Path -LiteralPath $png){throw 'CAPTURE_DEST_ALREADY_EXISTS'}
if(Test-Path -LiteralPath $probePath){throw 'PROBE_DEST_ALREADY_EXISTS'}
$oldCapture=[Environment]::GetEnvironmentVariable('OIG_CAPTURE_PATH')
$oldOnly=[Environment]::GetEnvironmentVariable('OIG_CAPTURE_ONLY')
$oldProbe=[Environment]::GetEnvironmentVariable('OIG_DESKTOP_PROBE_RECEIPT')
$child=$null
try{
  $env:OIG_CAPTURE_PATH=$png
  $env:OIG_CAPTURE_ONLY='1'
  $env:OIG_DESKTOP_PROBE_RECEIPT=$probePath
  $child=Start-Process -FilePath $exe -WorkingDirectory $program -PassThru
  if(-not $child.WaitForExit(65000)){throw 'INSTALLED_DASHBOARD_RENDER_TIMEOUT'}
  if($child.ExitCode -ne 0){throw ('INSTALLED_DASHBOARD_EXIT_'+$child.ExitCode)}
  if(-not(Test-Path -LiteralPath $png)){throw 'INSTALLED_DASHBOARD_SCREENSHOT_MISSING'}
  $bytes=[IO.File]::ReadAllBytes($png)
  if($bytes.Length -lt 5000){throw 'INSTALLED_DASHBOARD_SCREENSHOT_TOO_SMALL'}
  $signature=[byte[]](137,80,78,71,13,10,26,10)
  for($i=0;$i -lt $signature.Length;$i++){
    if($bytes[$i] -ne $signature[$i]){throw 'INSTALLED_DASHBOARD_INVALID_PNG'}
  }
  $width=([int]$bytes[16]*16777216)+([int]$bytes[17]*65536)+([int]$bytes[18]*256)+[int]$bytes[19]
  $height=([int]$bytes[20]*16777216)+([int]$bytes[21]*65536)+([int]$bytes[22]*256)+[int]$bytes[23]
  if($width -lt 980 -or $height -lt 680){throw ('INSTALLED_DASHBOARD_SIZE_INVALID_'+$width+'x'+$height)}
  if(-not(Test-Path -LiteralPath $probePath -PathType Leaf)){throw 'INSTALLED_DESKTOP_NAVIGATION_PROBE_MISSING'}
  $probe=Get-Content -LiteralPath $probePath -Raw|ConvertFrom-Json
  if($probe.schema -ne 'oig-offline-installed-ui-navigation-tray-v1' -or
     $probe.pass -ne $true -or $probe.navigation.pass -ne $true -or
     $probe.navigation.navigationClicked -ne $true -or
     $probe.navigation.powerControlInvoked -ne $false -or
     @($probe.navigation.pagesVisited).Count -ne 2 -or
     $probe.navigation.pagesVisited[0] -ne 'settings' -or
     $probe.navigation.pagesVisited[1] -ne 'overview' -or
     $probe.closeToTray -ne $true -or $probe.windowStillAlive -ne $true -or
     $probe.vpnControlInvoked -ne $false){throw 'INSTALLED_DESKTOP_NAVIGATION_TRAY_PROBE_FAILED'}
  Assert-Offline
  $evidence=[ordered]@{
    schema='oig-installed-windows-dashboard-smoke-v2'
    scope='disposable-GitHub-hosted-Windows-Server-2025-packaged-dashboard-navigation-tray-render-only'
    navigationAndTrayProbe=$probe
    probeSha256=(Get-FileHash -LiteralPath $probePath -Algorithm SHA256).Hash.ToLowerInvariant()
    source=$env:GITHUB_SHA
    pass=$true
    imageWidth=$width
    imageHeight=$height
    pngBytes=$bytes.Length
    imageSha256=(Get-FileHash -LiteralPath $png -Algorithm SHA256).Hash.ToLowerInvariant()
    exeSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
    verifiedInstallerSha256=$installerHash
    disconnectedBeforeAndAfter=$true
    vpnConnectionsAttempted=$false
    endUserWindows10Or11GuiAcceptance=$false
  }
  [IO.File]::WriteAllText($Receipt,($evidence|ConvertTo-Json -Depth 6)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  Write-Host ('INSTALLED_WINDOWS_DASHBOARD_SCREENSHOT_PASS '+$width+'x'+$height)
}finally{
  [Environment]::SetEnvironmentVariable('OIG_CAPTURE_PATH',$oldCapture)
  [Environment]::SetEnvironmentVariable('OIG_CAPTURE_ONLY',$oldOnly)
  [Environment]::SetEnvironmentVariable('OIG_DESKTOP_PROBE_RECEIPT',$oldProbe)
  if($child -and -not $child.HasExited){try{Stop-Process -Id $child.Id -Force -ErrorAction Stop}catch{}}
}
