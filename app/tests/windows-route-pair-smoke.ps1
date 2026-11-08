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
$script:winnerMode='matching'
$script:v6Mode='none'
function Get-NetRoute {
 param([string]$AddressFamily,[string]$ErrorAction)
 if($AddressFamily -ne 'IPv6'){throw 'Unexpected host route query'}
 if($script:v6Mode -in @('physical-default','owned-default','missing-selected','ambiguous')){
   [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=19}
 }
}
function Find-NetRoute {
 param([string]$RemoteIPAddress,[string]$ErrorAction)
 if($RemoteIPAddress -match ':'){
   if($script:v6Mode -in @('physical-default','specific-foreign')){
     [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=19;InterfaceAlias='Ethernet'}
   }elseif($script:v6Mode -in @('owned-default','ambiguous')){
     [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=20;InterfaceAlias='OpenVPN'}
     if($script:v6Mode -eq 'ambiguous'){
       [pscustomobject]@{DestinationPrefix='::/0';InterfaceIndex=20;InterfaceAlias='OpenVPN'}
     }
   }
   return
 }
 $prefix=$(if($RemoteIPAddress -eq '1.1.1.1'){'0.0.0.0/1'}else{'128.0.0.0/1'})
 $idx=20;$alias='OpenVPN Connect DCO Adapter'
 if($script:winnerMode -eq 'foreign-upper' -and $prefix -eq '128.0.0.0/1'){$idx=37;$alias='Foreign VPN'}
 if($script:winnerMode -eq 'physical-lower' -and $prefix -eq '0.0.0.0/1'){$idx=19;$alias='Ethernet 3'}
 if($script:winnerMode -eq 'specific-lower' -and $prefix -eq '0.0.0.0/1'){$prefix='1.1.1.1/32'}
 [pscustomobject]@{IPAddress='10.8.0.9'} # Windows returns source IP before the route.
 if($script:winnerMode -eq 'missing-upper' -and $prefix -eq '128.0.0.0/1'){return}
 Row $prefix $idx $alias
 if($script:winnerMode -eq 'ambiguous-upper' -and $prefix -eq '128.0.0.0/1'){Row $prefix $idx $alias}
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
$script:winnerMode='foreign-upper'
Check $normal $false 'foreign upper effective route despite installed OpenVPN route pair'
$script:winnerMode='physical-lower'
Check $normal $false 'physical lower effective route wins'
$script:winnerMode='missing-upper'
Check $normal $false 'missing selected upper route'
$script:winnerMode='specific-lower'
Check $normal $false 'more specific non-tunnel host route'
$script:winnerMode='ambiguous-upper'
Check $normal $false 'ambiguous selected upper route'
$script:winnerMode='matching'
Check $normal $true 'both effective routes return to the managed OpenVPN adapter'
# IPv4 route evidence must not hide IPv6 exits via a separate adapter.
$script:v6Mode='none'
if(-not (Test-OigIpv6EgressSafe -InterfaceIndex 20)){throw 'No global IPv6 path should be safe'}
$script:v6Mode='physical-default'
if(Test-OigIpv6EgressSafe -InterfaceIndex 20){throw 'Physical IPv6 default must fail'}
$script:v6Mode='owned-default'
if(-not (Test-OigIpv6EgressSafe -InterfaceIndex 20)){throw 'Owned IPv6 egress should be allowed'}
$script:v6Mode='missing-selected'
if(Test-OigIpv6EgressSafe -InterfaceIndex 20){throw 'Unverifiable public IPv6 path with default must fail'}
$script:v6Mode='specific-foreign'
if(Test-OigIpv6EgressSafe -InterfaceIndex 20){throw 'Foreign IPv6 host route must fail'}
$script:v6Mode='ambiguous'
if(Test-OigIpv6EgressSafe -InterfaceIndex 20){throw 'Ambiguous selected IPv6 path must fail'}
$script:v6Mode='none'
if(Test-OigIpv6EgressSafe -InterfaceIndex 0){throw 'Invalid adapter evidence must fail'}
Write-Output 'PASS: Windows OpenVPN IPv4 and IPv6 winning routes reject foreign alternatives (27 offline scenarios)'
