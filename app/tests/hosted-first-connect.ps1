[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Installer,[Parameter(Mandatory=$true)][string]$Receipt)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

# Hard boundary: this may touch ONLY a disposable GitHub-hosted Windows VM.
foreach($pair in @(@('GITHUB_ACTIONS','true'),@('RUNNER_OS','Windows'),@('RUNNER_ENVIRONMENT','github-hosted'),@('GITHUB_REPOSITORY','GOD13emad/OpenInternetGateway'))){
  if([Environment]::GetEnvironmentVariable($pair[0]) -ne $pair[1]){throw ('DISPOSABLE_RUNNER_REQUIRED_'+$pair[0])}
}
if((Get-CimInstance Win32_ComputerSystem).PartOfDomain){throw 'DOMAIN_JOINED_MACHINE_REFUSED'}
$expected='761637b5d49f37858973300ec2e9b1bb2b32c684ebabe86f1e8718b4480685db'
if((Get-FileHash -LiteralPath $Installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected){throw 'PUBLIC_INSTALLER_SHA_MISMATCH'}
$program=Join-Path $env:LOCALAPPDATA 'Programs\open-internet-gateway'
$exe=Join-Path $program 'Open Internet Gateway.exe'
$backend=Join-Path $env:LOCALAPPDATA 'OpenInternetGateway'
if((Test-Path -LiteralPath $program) -or (Test-Path -LiteralPath $backend) -or (Test-Path 'C:\Program Files\OpenVPN Connect\ovpnconnector.exe')){throw 'RUNNER_NOT_FRESH'}
$beforeRoutes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
if($beforeRoutes.Count){throw 'PREEXISTING_FULL_TUNNEL'}
$preService=Get-Service -Name OVPNConnectorService -ErrorAction SilentlyContinue
if($preService){throw 'PREEXISTING_CONNECTOR_SERVICE'}

$taskName='OIG-HOSTED-FIRSTCONNECT-FAILSAFE'
$taskCreated=$false
$verified=$false
try{
  $p=Start-Process -FilePath $Installer -ArgumentList '/S' -PassThru
  if(-not $p.WaitForExit(180000)){try{$p.Kill()}catch{};throw 'NSIS_INSTALL_TIMEOUT'}
  if($p.ExitCode -ne 0){throw ('NSIS_INSTALL_FAILED_'+$p.ExitCode)}
  if(-not(Test-Path -LiteralPath $exe)){throw 'INSTALLED_EXECUTABLE_MISSING'}
  $pwsh=Join-Path $program 'resources\pwsh\pwsh.exe'
  if(-not(Test-Path -LiteralPath $pwsh)){throw 'BUNDLED_PWSH_MISSING'}
  $disconnect=Join-Path $backend 'OpenInternetGateway.ps1'
  # Distinct OS-scheduled safety path survives any launcher/Node hang.
  $arg='-NoProfile -NonInteractive -File "'+$disconnect+'" -Action Disconnect'
  $trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(9)
  $action=New-ScheduledTaskAction -Execute $pwsh -Argument $arg
  Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -RunLevel Highest -Force | Out-Null
  $taskCreated=$true
  $nodeExe=(Get-Command node.exe -ErrorAction Stop).Source
  $harness=Join-Path $PSScriptRoot 'hosted-first-connect.cjs'
  $stdOut=Join-Path $env:RUNNER_TEMP 'oig-first-connect.stdout.log'
  $stdErr=Join-Path $env:RUNNER_TEMP 'oig-first-connect.stderr.log'
  $psi=[Diagnostics.ProcessStartInfo]::new()
  $psi.FileName=$nodeExe
  $psi.ArgumentList.Add($harness)
  $psi.ArgumentList.Add($program)
  $psi.ArgumentList.Add($Receipt)
  $psi.UseShellExecute=$false
  $psi.CreateNoWindow=$true
  $psi.RedirectStandardOutput=$true
  $psi.RedirectStandardError=$true
  $child=[Diagnostics.Process]::Start($psi)
  $o=$child.StandardOutput.ReadToEndAsync()
  $e=$child.StandardError.ReadToEndAsync()
  if(-not $child.WaitForExit(460000)){try{$child.Kill()}catch{};throw 'NATIVE_FIRST_CONNECT_HARNESS_TIMEOUT'}
  [IO.File]::WriteAllText($stdOut,$o.GetAwaiter().GetResult())
  [IO.File]::WriteAllText($stdErr,$e.GetAwaiter().GetResult())
  Get-Content -LiteralPath $stdOut -Tail 20
  if($child.ExitCode -ne 0){throw ('FIRST_CONNECT_HARNESS_FAILED_'+$child.ExitCode)}
  if(-not(Test-Path -LiteralPath $Receipt)){throw 'ACCEPTANCE_RECEIPT_MISSING'}
  $report=Get-Content -LiteralPath $Receipt -Raw | ConvertFrom-Json
  if($report.pass -ne $true){throw 'ACCEPTANCE_CRITERIA_NOT_MET'}
  $verified=$true
} finally {
  # Idempotent off path before any runner teardown.
  $pwsh=Join-Path $program 'resources\pwsh\pwsh.exe'
  $disconnect=Join-Path $backend 'OpenInternetGateway.ps1'
  if((Test-Path -LiteralPath $pwsh) -and (Test-Path -LiteralPath $disconnect)){
    try{& $pwsh -NoProfile -NonInteractive -File $disconnect -Action Disconnect | Out-Null}catch{}
  }
  Start-Sleep -Seconds 2
  $afterRoutes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
  $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
  $desiredPath=Join-Path $backend 'state\desired-state.json'
  $desired=''
  if(Test-Path -LiteralPath $desiredPath){try{$desired=(Get-Content -LiteralPath $desiredPath -Raw | ConvertFrom-Json).desired}catch{}}
  $safe=($afterRoutes.Count -eq 0 -and (!$svc -or $svc.Status -eq 'Stopped') -and $desired -eq 'off')
  Write-Output ('HOSTED_ROLLBACK_SAFE='+$safe)
  if($safe -and $taskCreated){Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue}
  if(-not $safe){$verified=$false;Write-Output 'HOSTED_ROLLBACK_UNCERTAIN_WATCHDOG_RETAINED'}
}
if(-not $verified){throw 'FIRST_CONNECT_NOT_VERIFIED'}
Write-Output 'HOSTED_FIRST_CONNECT_FULL_ACCEPTANCE_PASS'
