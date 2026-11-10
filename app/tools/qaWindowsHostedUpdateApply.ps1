# Real IN-PLACE v2.5.19 -> v2.5.20 updater acceptance on a disposable GitHub-hosted Windows runner ONLY.
param(
  [Parameter(Mandatory=$true)][string]$Installer,
  [Parameter(Mandatory=$true)][string]$ExpectedSha256,
  [Parameter(Mandatory=$true)][string]$Version
)
$ErrorActionPreference='Stop'
if($env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:GITHUB_REPOSITORY -ne 'GOD13emad/OpenInternetGateway' -or [string]::IsNullOrWhiteSpace($env:GITHUB_RUN_ID)){
  throw 'DISPOSABLE_GITHUB_HOSTED_WINDOWS_REQUIRED'
}
if($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$' -or $Version -notmatch '^\d+\.\d+\.\d+$'){throw 'Invalid update version or digest.'}
if(!(Test-Path -LiteralPath $Installer -PathType Leaf)){throw 'Update installer missing.'}
$actual=(Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant()
if($actual -ne $ExpectedSha256.ToLowerInvariant()){throw 'Installer SHA-256 mismatch.'}
$scratch=Join-Path $env:RUNNER_TEMP ('oig-hosted-update-apply-'+$env:GITHUB_RUN_ID)
$receipt=Join-Path $env:RUNNER_TEMP 'oig-hosted-update-apply-receipt.json'
$target=Join-Path $env:LOCALAPPDATA 'Programs\open-internet-gateway\Open Internet Gateway.exe'
$priorVersion='2.5.19'
$priorSha256='761637b5d49f37858973300ec2e9b1bb2b32c684ebabe86f1e8718b4480685db'
if((Test-Path -LiteralPath $scratch) -or (Test-Path -LiteralPath $receipt)){throw 'Preexisting updater scratch or receipt.'}
if(Test-Path -LiteralPath $target){throw 'Existing installed app; no overwrite permitted.'}
# Use the immutable, already published public stable installer as a real prior-version
# fixture. This must never run on an owner workstation; guard above is mandatory.
if([string]::IsNullOrWhiteSpace($env:GH_TOKEN)){throw 'Hosted GitHub release token is missing.'}
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$oldSetup=Join-Path $scratch ('OpenInternetGateway-Setup-'+$priorVersion+'.exe')
& gh release download ('v'+$priorVersion) --repo GOD13emad/OpenInternetGateway --pattern ('OpenInternetGateway-Setup-'+$priorVersion+'.exe') --dir $scratch
if($LASTEXITCODE -ne 0 -or !(Test-Path -LiteralPath $oldSetup -PathType Leaf)){throw 'Pinned published stable installer unavailable.'}
$oldHash=(Get-FileHash -LiteralPath $oldSetup -Algorithm SHA256).Hash.ToLowerInvariant()
if($oldHash -ne $priorSha256){throw 'Pinned previous published installer SHA-256 mismatch.'}
$oldInstall=Start-Process -FilePath $oldSetup -ArgumentList '/S' -PassThru -Wait
if($oldInstall.ExitCode -ne 0){throw ('Published stable NSIS install returned '+$oldInstall.ExitCode)}
if(!(Test-Path -LiteralPath $target -PathType Leaf)){throw 'Published stable installer did not create per-user executable.'}
$previousInstalledVersion=[string](Get-Item -LiteralPath $target).VersionInfo.ProductVersion
if(!$previousInstalledVersion.StartsWith($priorVersion)){throw 'Wrong version after installing published stable.'}
$previousExeSha=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
$asarPath=Join-Path (Split-Path -Parent $target) 'resources\app.asar'
if(!(Test-Path -LiteralPath $asarPath -PathType Leaf)){throw 'Published stable installed app.asar missing.'}
$previousAsarSha=(Get-FileHash -LiteralPath $asarPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host ('Verified published stable installation: '+$previousInstalledVersion)
$service=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
$before=if($null -eq $service){'Missing'}else{$service.Status.ToString()}
$oldAppData=$env:APPDATA;$oldCaptureOnly=$env:OIG_CAPTURE_ONLY;$oldCaptureRoot=$env:OIG_CAPTURE_ROOT;$oldCapturePath=$env:OIG_CAPTURE_PATH
New-Item -ItemType Directory -Path (Join-Path $scratch 'backend\scripts') -Force|Out-Null
New-Item -ItemType Directory -Path (Join-Path $scratch 'Roaming') -Force|Out-Null
Copy-Item -LiteralPath (Join-Path (Get-Location) 'backend\windows\scripts\Start-UpdateBootstrap.ps1') -Destination (Join-Path $scratch 'backend\scripts\Start-UpdateBootstrap.ps1') -ErrorAction Stop
$frame=Join-Path $scratch 'updated-dashboard.png'
$env:APPDATA=Join-Path $scratch 'Roaming'
$env:OIG_CAPTURE_ONLY='1';$env:OIG_CAPTURE_ROOT=$scratch;$env:OIG_CAPTURE_PATH=$frame
$env:OIG_HOSTED_UPDATE_SCRATCH=$scratch;$env:OIG_HOSTED_UPDATE_INSTALLER=$Installer
$env:OIG_HOSTED_UPDATE_SHA=$actual;$env:OIG_HOSTED_UPDATE_VERSION=$Version
$nodeScript=Join-Path $scratch 'native-update.cjs'
@'
const fs=require('node:fs');
const path=require('node:path');
const Backend=require(path.join(process.cwd(),'src','main','platform-backend.js'));
const root=process.env.OIG_HOSTED_UPDATE_SCRATCH;
if(process.platform!=='win32'||process.env.RUNNER_ENVIRONMENT!=='github-hosted'||
  process.env.GITHUB_REPOSITORY!=='GOD13emad/OpenInternetGateway')throw Error('Hosted Windows required');
const b=new Backend({version:'2.5.19',resourcesPath:process.cwd(),appPath:process.cwd(),userData:root,emit:()=>{}});
b.platform='win32';b.backendRoot=path.join(root,'backend');
(async()=>{
 const result=await b.launchDownloadedUpdate({
  path:process.env.OIG_HOSTED_UPDATE_INSTALLER,
  sha256:process.env.OIG_HOSTED_UPDATE_SHA,
  info:{latestVersion:process.env.OIG_HOSTED_UPDATE_VERSION}
 },{appPid:2147000000,currentExecutable:path.join(root,'nonexistent-previous-app.exe')});
 if(!result.ok||!result.applying||result.installScope!=='current-user'||
   result.target!==path.join(process.env.LOCALAPPDATA,'Programs','open-internet-gateway','Open Internet Gateway.exe')||
   !result.resultFile.startsWith(b.backendRoot))throw Error('Unsafe or incomplete native updater handoff');
 fs.writeFileSync(path.join(root,'handoff.json'),JSON.stringify(result)+'\n');
})().catch(e=>{console.error('Native update handoff failed:',e.message);process.exitCode=1;});
'@ | Set-Content -LiteralPath $nodeScript -Encoding UTF8
try {
  & node $nodeScript
  if($LASTEXITCODE -ne 0){throw 'Native Windows update handoff failed.'}
  $handoff=Get-Content -LiteralPath (Join-Path $scratch 'handoff.json') -Raw|ConvertFrom-Json
  $resultFile=[string]$handoff.resultFile
  $deadline=(Get-Date).AddSeconds(150)
  while(!(Test-Path -LiteralPath $resultFile -PathType Leaf)){
    if((Get-Date) -ge $deadline){throw 'Native updater apply result timeout.'}
    Start-Sleep -Milliseconds 250
  }
  $update=Get-Content -LiteralPath $resultFile -Raw|ConvertFrom-Json
  if(!$update.ok){throw ('Native updater result: '+$update.error)}
  if($update.installScope -ne 'current-user' -or $update.version -ne $Version -or
     $update.sha256 -ne $actual -or $update.target -ne $target){throw 'Updater result identity mismatch.'}
  if(!(Test-Path -LiteralPath $target -PathType Leaf)){throw 'Updated installed EXE missing.'}
  $detected=[string](Get-Item -LiteralPath $target).VersionInfo.ProductVersion
  if(!$detected.StartsWith($Version)){throw 'Installed version mismatch.'}
  $updatedExeSha=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash.ToLowerInvariant()
  if(!(Test-Path -LiteralPath $asarPath -PathType Leaf)){throw 'Updated installed app.asar missing.'}
  $updatedAsarSha=(Get-FileHash -LiteralPath $asarPath -Algorithm SHA256).Hash.ToLowerInvariant()
  if($updatedAsarSha -eq $previousAsarSha){throw 'Updated app.asar is unchanged from published stable.'}
  $deadline=(Get-Date).AddSeconds(45)
  while(!(Test-Path -LiteralPath $frame -PathType Leaf)){
    if((Get-Date) -ge $deadline){throw 'No relaunched installed Dashboard screenshot.'}
    Start-Sleep -Milliseconds 250
  }
  Add-Type -AssemblyName System.Drawing
  $image=[Drawing.Image]::FromFile($frame)
  try {
    if($image.Width -lt 900 -or $image.Height -lt 600){throw 'Updated Dashboard image dimensions invalid.'}
    $dimensions=("$($image.Width)x$($image.Height)")
  } finally {$image.Dispose()}
  $serviceAfter=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
  $after=if($null -eq $serviceAfter){'Missing'}else{$serviceAfter.Status.ToString()}
  if($after -ne $before){throw 'Connector service status changed.'}
  Start-Sleep -Seconds 2
  $uninstaller=Join-Path (Split-Path -Parent $target) 'Uninstall Open Internet Gateway.exe'
  if(!(Test-Path -LiteralPath $uninstaller)){throw 'No installed updater uninstaller.'}
  $p=Start-Process -FilePath $uninstaller -ArgumentList '/S' -PassThru -Wait
  if($p.ExitCode -ne 0 -or (Test-Path -LiteralPath $target)){throw 'Hosted updater uninstall failed.'}
  [pscustomobject]@{
    pass=$true;scope='disposable GitHub-hosted Windows runner only';version=$Version
    installerSHA256=$actual;installedVersion=$detected;installScope='current-user'
    publishedPriorInstallerSHA256=$priorSha256;previousVersion=$previousInstalledVersion
    previousExeSHA256=$previousExeSha;updatedExeSHA256=$updatedExeSha
    previousAsarSHA256=$previousAsarSha;updatedAsarSHA256=$updatedAsarSha
    inPlaceUpgradeVerified=$true
    nativeHandoff=$true;nativeApply=$true;nativeRelaunch=$true;captureDimensions=$dimensions
    silentUninstall=$true;connectorServiceUnchanged=$true
  } | ConvertTo-Json -Compress |Set-Content -LiteralPath $receipt -Encoding UTF8
  Write-Host ('Windows published v2.5.19 -> v2.5.20 in-place updater apply/relaunch/uninstall PASS; Dashboard '+$dimensions)
} finally {
  $env:APPDATA=$oldAppData;$env:OIG_CAPTURE_ONLY=$oldCaptureOnly
  $env:OIG_CAPTURE_ROOT=$oldCaptureRoot;$env:OIG_CAPTURE_PATH=$oldCapturePath
  Remove-Item Env:OIG_HOSTED_UPDATE_SCRATCH,Env:OIG_HOSTED_UPDATE_INSTALLER,Env:OIG_HOSTED_UPDATE_SHA,Env:OIG_HOSTED_UPDATE_VERSION -ErrorAction SilentlyContinue
}
