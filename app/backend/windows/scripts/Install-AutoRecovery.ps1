[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot

function Test-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
if(-not(Test-Admin)){
 Start-Process pwsh.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)
 Write-Host 'ELEVATION STARTED'
 exit 0
}

$pwsh=(Get-Command pwsh.exe -ErrorAction Stop).Source
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
