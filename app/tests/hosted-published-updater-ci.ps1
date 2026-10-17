[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
# All effects are confined to a new disposable GitHub-hosted Windows Server VM.
if($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or
   $env:GITHUB_REPOSITORY -ne 'GOD13emad/OpenInternetGateway' -or
   $env:GITHUB_EVENT_NAME -ne 'pull_request' -or
   [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne 'X64' -or
   (Get-CimInstance Win32_OperatingSystem).Caption -notmatch 'Windows Server 2025' -or
   (Get-CimInstance Win32_ComputerSystem).PartOfDomain) { throw 'DISPOSABLE_WINDOWS_SERVER_X64_ONLY' }
$root=Join-Path $env:LOCALAPPDATA 'OpenInternetGateway'
$state=Join-Path $root 'state'
$intent=Join-Path $state 'desired-state.json'
$exe=Join-Path $env:LOCALAPPDATA 'Programs\open-internet-gateway\Open Internet Gateway.exe'
$folder=Join-Path $env:RUNNER_TEMP 'oig-authentic-old-release-update-ui'
if(Test-Path -LiteralPath $folder){throw 'EVIDENCE_FOLDER_EXISTS'}
New-Item -ItemType Directory -Path $folder | Out-Null
$oldHash='ed93dcadde96efec14c8de12b3e0074f12b826b968f4146330c496d816ecdb3d'
$newHash='761637b5d49f37858973300ec2e9b1bb2b32c684ebabe86f1e8718b4480685db'
function Assert-Offline {
  if(@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}).Count){throw 'VPN_PROTECTED_ROUTE_PRESENT'}
  $service=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
  if($service -and $service.Status -ne 'Stopped'){throw 'VPN_SERVICE_ACTIVE'}
  if(Test-Path $intent){
    if((Get-Content -Raw $intent|ConvertFrom-Json).desired -ne 'off'){throw 'VPN_DESIRED_ON'}
  }
}
Assert-Offline
if((Get-Service OVPNConnectorService -ErrorAction SilentlyContinue) -or
   (Test-Path -LiteralPath $exe) -or
   @(Get-CimInstance Win32_Process -Filter "Name='Open Internet Gateway.exe'" -ErrorAction SilentlyContinue).Count){throw 'EXPECTED_FRESH_RUNNER'}
foreach($v in @(@('v2.5.18','OpenInternetGateway-Setup-2.5.18.exe',$oldHash,203778543),
                @('v2.5.19','OpenInternetGateway-Setup-2.5.19.exe',$newHash,203780968))){
  $release=gh api "repos/GOD13emad/OpenInternetGateway/releases/tags/$($v[0])"|ConvertFrom-Json
  if($LASTEXITCODE -ne 0 -or $release.tag_name -ne $v[0]){throw 'PUBLISHED_RELEASE_NOT_VERIFIED'}
  $asset=@($release.assets|Where-Object {$_.name -eq $v[1]})
  if($asset.Count -ne 1 -or $asset[0].digest -ne ('sha256:'+$v[2]) -or $asset[0].size -ne [long]$v[3]){throw 'PUBLISHED_ASSET_IDENTITY_CHANGED'}
}
gh release download v2.5.18 --repo GOD13emad/OpenInternetGateway --pattern 'OpenInternetGateway-Setup-2.5.18.exe' --dir $folder
if($LASTEXITCODE -ne 0){throw 'PUBLISHED_OLD_INSTALLER_DOWNLOAD_FAILED'}
$old=Join-Path $folder 'OpenInternetGateway-Setup-2.5.18.exe'
if((Get-FileHash -LiteralPath $old -Algorithm SHA256).Hash.ToLowerInvariant() -ne $oldHash){throw 'PUBLISHED_OLD_HASH_FAILED'}
$process=Start-Process -FilePath $old -ArgumentList '/S' -Wait -PassThru
if($process.ExitCode -ne 0 -or !(Test-Path $exe) -or (Get-Item $exe).VersionInfo.ProductVersion -notlike '2.5.18*'){throw 'PUBLISHED_OLD_2518_INSTALL_FAILED'}
New-Item -ItemType Directory -Force -Path $state|Out-Null
[IO.File]::WriteAllText($intent,'{"desired":"off"}',[Text.UTF8Encoding]::new($false))
$mark='{"scope":"published-2518-installed-update-disposable-server","preserve":true}'
$marker=Join-Path $state 'published-old-gui-update-marker.json'
if(Test-Path $marker){throw 'MARKER_ALREADY_PRESENT'}
[IO.File]::WriteAllText($marker,$mark,[Text.UTF8Encoding]::new($false))
Assert-Offline
$port=9383
if((Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)){throw 'CDP_PORT_OCCUPIED'}
$child=Start-Process -FilePath $exe -WorkingDirectory (Split-Path $exe -Parent) -ArgumentList @("--remote-debugging-port=$port",'--remote-debugging-address=127.0.0.1') -PassThru
if(!$child -or $child.Id -le 0){throw 'INSTALLED_OLD_ELECTRON_PROCESS_NOT_CREATED'}
Write-Host "AUTHENTIC_2518_INSTALLED_APP_GUI_LAUNCHED_PID=$($child.Id)"
node tests/hosted-published-updater-ui.cjs "$port" (Join-Path $folder 'real-ui-click-receipt.json')
$driverExit=$LASTEXITCODE
$receipt=Join-Path $root 'updates\v2.5.19\apply-result.json'
$started=$receipt+'.started'
if($driverExit -eq 42){
  $negFile=Join-Path $folder 'legacy-updater-failure-result.json'
  $click=Join-Path $folder 'real-ui-click-receipt.json'
  if(!(Test-Path $negFile -PathType Leaf) -or !(Test-Path $click -PathType Leaf)){throw 'EXPECTED_LEGACY_FAILURE_MISSING_PROVENANCE'}
  $neg=Get-Content -Raw $negFile|ConvertFrom-Json
  $clicked=Get-Content -Raw $click|ConvertFrom-Json
  if($neg.classification -ne 'LEGACY_WINDOWS_DETACHED_PWSH_HELPER_START_FAILURE' -or
     $neg.actualPublishedOldUpdaterSucceeded -ne $false -or
     $neg.realInstalledRendererUpdateButtonClicked -ne $true -or
     $clicked.mockedBackend -ne $false -or
     $clicked.publishedInstalledVersion -ne '2.5.18' -or
     $clicked.publicTarget -ne '2.5.19'){throw 'LEGACY_FAILURE_CLASSIFICATION_UNTRUSTED'}
  Start-Sleep -Seconds 8
  Assert-Offline
  if((Get-Item $exe).VersionInfo.ProductVersion -notlike '2.5.18*' -or
     (Get-Content -Raw $marker) -ne $mark -or
     (Test-Path $started -PathType Leaf) -or
     (Test-Path $receipt -PathType Leaf)){throw 'LEGACY_FAILED_CLOSED_INVARIANTS_NOT_PROVEN'}
  $proof=[ordered]@{
    schema='oig-real-published-2518-installed-legacy-update-compatibility-v1'
    status='FAIL_REAL_PUBLISHED_2518_AUTOMATIC_UPDATE'
    testDetector='PASS_REPRODUCED_AND_FAILED_CLOSED'
    installedOldPublic2518=$true
    originalOldReleaseUnmodified=$true
    realUiButtonClicked=$true
    mockedBackend=$false
    publishedUpdateTo2519Succeeded=$false
    errorClassification=$neg.classification
    initialVersion='2.5.18'
    stillInstalledVersion='2.5.18'
    expectedTargetVersion='2.5.19'
    userStatePreserved=$true
    desiredVpnOff=$true
    protectedRoutesAfter=0
    helperStarted=$false
    realClickReceiptSha256=(Get-FileHash $click -Algorithm SHA256).Hash
    negativeReceiptSha256=(Get-FileHash $negFile -Algorithm SHA256).Hash
    sourceGitSha=$env:GITHUB_SHA
    scope='Disposable GitHub Windows Server 2025 x64, NOT native Windows 11 x64'
  }
  [IO.File]::WriteAllText((Join-Path $folder 'published-old-real-update-e2e-result.json'),($proof|ConvertTo-Json -Depth 4)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
  Write-Host ('NEGATIVE_CONTROL_DETECTOR_PASS_PRODUCT_LEGACY_AUTO_UPDATE_FAIL='+($proof|ConvertTo-Json -Depth 4 -Compress))
  # Clear only the expected sentinel exit 42 after a fully validated negative
  # receipt. GitHub's pwsh wrapper otherwise propagates stale LASTEXITCODE
  # even though this diagnostic script returned successfully.
  $global:LASTEXITCODE=0
  return
}
if($driverExit -ne 0){throw ('AUTHENTIC_OLD_GUI_DRIVER_INFRASTRUCTURE_FAILURE_'+$driverExit)}
$deadline=(Get-Date).AddMinutes(5)
while(!(Test-Path $receipt -PathType Leaf) -and (Get-Date) -lt $deadline){Start-Sleep -Seconds 1}
$observed=[ordered]@{
  schema='oig-published-old-version-actual-gui-update-e2e-v1'
  scope='Disposable Windows Server 2025 x64, not native Windows 11 x64'
  installedPublishedOld2518=$true
  versionOverride=$false
  realRendererInstallButtonClicked=$true
  helperStarted=(Test-Path -LiteralPath $started)
  helperResultPresent=(Test-Path -LiteralPath $receipt)
  sourceGitSha=$env:GITHUB_SHA
  targetRelease='2.5.19'
}
if(Test-Path $receipt -PathType Leaf){
  $r=Get-Content -Raw $receipt|ConvertFrom-Json
  $observed['helperOK']=$r.ok
  $observed['helperError']=if($r.PSObject.Properties['error']){$r.error}else{''}
  $observed['helperInstallExitCode']=if($r.PSObject.Properties['exitCode']){$r.exitCode}else{$null}
  $observed['helperReceiptSha256']=(Get-FileHash $receipt -Algorithm SHA256).Hash
}
$observed['installedVersionAfter']=if(Test-Path $exe){(Get-Item $exe).VersionInfo.ProductVersion}else{'MISSING'}
$observed['markerPreserved']=((Test-Path $marker) -and ((Get-Content -Raw $marker) -eq $mark))
$observed['vpnDesiredOff']=((Get-Content -Raw $intent|ConvertFrom-Json).desired -eq 'off')
$observed['protectedRouteCount']=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')}).Count
$observed['pass']=($observed.helperResultPresent -and $observed.helperOK -eq $true -and $observed.helperInstallExitCode -eq 0 -and
 $observed.installedVersionAfter -like '2.5.19*' -and $observed.markerPreserved -and $observed.vpnDesiredOff -and $observed.protectedRouteCount -eq 0)
[IO.File]::WriteAllText((Join-Path $folder 'published-old-real-update-e2e-result.json'),($observed|ConvertTo-Json -Depth 5)+[Environment]::NewLine,[Text.UTF8Encoding]::new($false))
Write-Host ('AUTHENTIC_2518_GUI_UPDATE_VERDICT='+($observed|ConvertTo-Json -Depth 5 -Compress))
if(!$observed.pass){throw 'PUBLISHED_2518_REAL_GUI_UPDATE_TO_2519_NOT_ACCEPTED'}
Assert-Offline
Write-Host 'AUTHENTIC_2518_REAL_INSTALLED_GUI_UPDATE_TO_2519_PASS'