[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot

function Test-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$pwsh=Join-Path $PSHOME 'pwsh.exe'
if(-not(Test-Path -LiteralPath $pwsh)){$pwsh=(Get-Command pwsh.exe -ErrorAction Stop).Source}
if(-not(Test-Admin)){
 try{$p=Start-Process -FilePath $pwsh -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)}
 catch{throw ('Administrator approval is required once to install Open Internet Gateway recovery: '+$_.Exception.Message)}
 if(-not $p -or $p.ExitCode -ne 0){throw ('Elevated Auto-Recovery setup failed with exit code '+$(if($p){$p.ExitCode}else{'unknown'}))}
 $task=Get-ScheduledTask -TaskName 'OpenInternetGateway-AutoRecovery' -ErrorAction SilentlyContinue
 if(-not $task){throw 'Elevated Auto-Recovery setup returned without creating the recovery task.'}
 Write-Host 'AUTO-RECOVERY INSTALLED'
 exit 0
}

$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$ensure=Join-Path $PSScriptRoot 'Ensure-OpenInternet.ps1'
if(-not(Test-Path $ensure)){throw "Ensure script missing: $ensure"}

$name='OpenInternetGateway-AutoRecovery'
$action=New-ScheduledTaskAction -Execute $pwsh -Argument ('-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "'+$ensure+'"')
$trigger=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 10) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

# Remove obsolete tasks from older iterations so there is only one recovery authority.
foreach($old in @('OpenInternetGateway-Connect','OpenInternetGateway-Disconnect')){
 Unregister-ScheduledTask -TaskName $old -Confirm:$false -ErrorAction SilentlyContinue
}
Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

$startup=[Environment]::GetFolderPath('Startup')
Remove-Item (Join-Path $startup 'Open Internet Gateway Auto-Recovery.lnk') -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force -Path (Join-Path $Root 'evidence')|Out-Null
[ordered]@{
 at=(Get-Date).ToString('o')
 user=$user
 task=$name
 runLevel='Highest'
 intervalMinutes=10
 engine='Ensure-OpenInternet.ps1'
 configFactory='Config-Factory.ps1'
 obsoleteTasksRemoved=$true
}|ConvertTo-Json -Depth 4|Set-Content -Encoding UTF8 (Join-Path $Root 'evidence\auto-recovery-install.json')

Write-Host 'AUTO-RECOVERY INSTALLED'
