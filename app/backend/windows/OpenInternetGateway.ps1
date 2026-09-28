[CmdletBinding()]
param([ValidateSet('Connect','Disconnect','Status','RefreshConnect','Ensure','AutoRecoveryInstall','AutoRecoveryRemove','ConsoleStatus','ConsoleEnable','ConsoleDisable','ConfigStatus','ConfigRefresh')][string]$Action='Status',[string]$ProfileSha='')
$Root=$PSScriptRoot
switch($Action){
 'Connect'{& "$Root\scripts\Connect-OpenInternet.ps1" -ProfileSha $ProfileSha}
 'RefreshConnect'{& "$Root\scripts\Config-Factory.ps1" -Action Refresh}
 'Disconnect'{& "$Root\scripts\Disconnect-OpenInternet.ps1"}
 'Ensure'{& "$Root\scripts\Ensure-OpenInternet.ps1"}
 'AutoRecoveryInstall'{& "$Root\scripts\Install-AutoRecovery.ps1"}
 'AutoRecoveryRemove'{& "$Root\scripts\Uninstall-AutoRecovery.ps1"}
 'ConsoleStatus'{& "$Root\scripts\Console-Gateway.ps1" -Action Status}
 'ConsoleEnable'{& "$Root\scripts\Console-Gateway.ps1" -Action Enable}
 'ConsoleDisable'{& "$Root\scripts\Console-Gateway.ps1" -Action Disable}
 'ConfigStatus'{& "$Root\scripts\Config-Factory.ps1" -Action Status}
 'ConfigRefresh'{& "$Root\scripts\Config-Factory.ps1" -Action Refresh}
 default{& "$Root\scripts\Status-OpenInternet.ps1"}
}
