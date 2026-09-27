[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
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
foreach($name in @('OpenInternetGateway-AutoRecovery','OpenInternetGateway-Connect','OpenInternetGateway-Disconnect')){
 Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
$startup=[Environment]::GetFolderPath('Startup')
Remove-Item (Join-Path $startup 'Open Internet Gateway Auto-Recovery.lnk') -Force -ErrorAction SilentlyContinue
Write-Host 'HEADLESS AUTO-RECOVERY TASKS REMOVED'
