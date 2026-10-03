[CmdletBinding()]
param()
$ErrorActionPreference='Continue'
function Test-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
$pwsh=Join-Path $PSHOME 'pwsh.exe'
if(-not(Test-Path -LiteralPath $pwsh)){$pwsh=(Get-Command pwsh.exe -ErrorAction Stop).Source}
if(-not(Test-Admin)){
 try{$p=Start-Process -FilePath $pwsh -Verb RunAs -Wait -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath)}catch{throw ('Administrator approval is required to remove Open Internet Gateway recovery: '+$_.Exception.Message)}
 if($p -and $p.ExitCode -ne 0){throw ('Elevated Auto-Recovery removal failed with exit code '+$p.ExitCode)}
 exit 0
}
foreach($name in @('OpenInternetGateway-AutoRecovery','OpenInternetGateway-Connect','OpenInternetGateway-Disconnect')){
 Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction SilentlyContinue
}
$startup=[Environment]::GetFolderPath('Startup')
Remove-Item (Join-Path $startup 'Open Internet Gateway Auto-Recovery.lnk') -Force -ErrorAction SilentlyContinue
Write-Host 'HEADLESS AUTO-RECOVERY TASKS REMOVED'
