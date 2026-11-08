$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\backend\windows\scripts\Route-Pair.ps1')

# No Get-NetRoute, VPN service, network access or host adapter changes.
# Override adapter inspection within the test process only.
$script:fakeDriver='OpenVPN Data Channel Offload'
$script:adapterMissing=$false
function Get-NetAdapter {
 [CmdletBinding()]
 param([int]$InterfaceIndex)
 if($script:adapterMissing){return}
 return [pscustomobject]@{InterfaceDescription=$script:fakeDriver;InterfaceIndex=$InterfaceIndex}
}
function Row([string]$prefix,[int]$index,[string]$alias) {
 [pscustomobject]@{DestinationPrefix=$prefix;InterfaceIndex=$index;InterfaceAlias=$alias}
}
function Check([object[]]$routes,[bool]$expected,[string]$name) {
 $actual=[bool](Test-OigFullRoutePair -Routes $routes)
 if($actual -ne $expected){throw "Route pair fixture failed: $name got=$actual expected=$expected"}
}
$normal=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
Check $normal $true 'co-located OpenVPN route pair'
Check @($normal[1],$normal[0]) $true 'route order independent'
Check @($normal[0]) $false 'one half only'
Check @($normal[0],$normal[0]) $false 'duplicate lower half'
Check @($normal[0],$normal[1],$normal[1]) $false 'extra route'
Check @($normal[0],(Row '128.0.0.0/1' 21 'Foreign VPN')) $false 'split across interfaces'
Check @($normal[0],(Row '128.0.0.0/1' 20 'Foreign Alias')) $false 'split across aliases'
Check @((Row '0.0.0.0/1' 0 'OpenVPN'),(Row '128.0.0.0/1' 0 'OpenVPN')) $false 'invalid interface index'
Check @((Row '0.0.0.0/1' 20 ''),(Row '128.0.0.0/1' 20 '')) $false 'empty alias'

$script:fakeDriver='Intel(R) Ethernet Controller'
Check $normal $false 'physical Ethernet shadow routes cannot count as VPN'
$script:fakeDriver='Wintun Userspace Tunnel'
Check $normal $false 'generic Wintun alone is not OpenVPN ownership'
$script:fakeDriver='Fortinet SSL VPN Virtual Ethernet Adapter'
Check $normal $false 'different VPN product driver'
$script:adapterMissing=$true
Check $normal $false 'unavailable adapter evidence'
$script:adapterMissing=$false
$script:fakeDriver='TAP-Windows Adapter V9 for OpenVPN Connect'
Check $normal $true 'legacy TAP OpenVPN driver'
Write-Output 'PASS: Windows read-only status route pair only accepts one OpenVPN-capable adapter (14 offline scenarios)'
