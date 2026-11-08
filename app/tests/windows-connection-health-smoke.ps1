$ErrorActionPreference='Stop'
$script:root=Join-Path $PSScriptRoot '..\backend\windows\scripts'
. (Join-Path $script:root 'Route-Pair.ps1')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $script:root 'Headless-Control.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count -gt 0){throw ('Headless PowerShell parser failed: '+$errors[0].Message)}
$matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-Health'},$true))
if($matches.Count -ne 1){throw 'Cannot uniquely extract the real Get-Health function'}
Invoke-Expression $matches[0].Extent.Text

# Mock EVERY external dependency used by Get-Health; this test cannot alter
# connection, routing, service, DNS, process state or credential files.
$script:routes=@()
$script:driver='OpenVPN Data Channel Offload'
$script:serviceStatus='Running'
$script:country='US'
$script:dns=@('8.8.8.8')
$script:winnerMode='matching'
function Get-NetRoute {param([string]$AddressFamily,[string]$ErrorAction) return $script:routes}
function Get-NetAdapter {param([int]$InterfaceIndex,[string]$ErrorAction)
 return [pscustomobject]@{InterfaceDescription=$script:driver;InterfaceIndex=$InterfaceIndex}
}
function Get-Service {param([string]$Name,[string]$ErrorAction)
 return [pscustomobject]@{Status=$script:serviceStatus}
}
function Find-NetRoute {
 param([string]$RemoteIPAddress,[string]$ErrorAction)
 $prefix=$(if($RemoteIPAddress -eq '1.1.1.1'){'0.0.0.0/1'}else{'128.0.0.0/1'})
 [pscustomobject]@{IPAddress='10.8.0.9'}
 if($script:winnerMode -eq 'foreign-upper' -and $prefix -eq '128.0.0.0/1'){
   Row '128.0.0.0/1' 37 'Foreign VPN'
   return
 }
 $candidate=@($script:routes|Where-Object{$_.DestinationPrefix -eq $prefix})
 if($candidate.Count -eq 1){$candidate[0]}
}
function curl.exe {return @('ip=198.51.100.10',('loc='+$script:country))}
function Resolve-DnsName {
 param([string]$Name,[string]$Type,[switch]$DnsOnly,[string]$ErrorAction)
 return @($script:dns | ForEach-Object { [pscustomobject]@{IPAddress=$_} })
}
function Row([string]$p,[int]$i,[string]$alias) {
 return [pscustomobject]@{DestinationPrefix=$p;InterfaceIndex=$i;InterfaceAlias=$alias}
}
function Expect([bool]$healthy,[int]$fullRoutes,[string]$scenario,[string]$expectedCountry='US'){
 $s=Get-Health $expectedCountry
 if([bool]$s.Healthy -ne $healthy -or [int]$s.FullRoutes -ne $fullRoutes){
    throw ('Headless health '+$scenario+' wrong: '+($s|ConvertTo-Json -Compress))}
}
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
Expect $true 2 'valid managed OpenVPN service and route pair'
$script:serviceStatus='Stopped'
Expect $false 2 'stopped connector cannot claim health; residual routes must remain visible for cleanup'
$script:serviceStatus='Running'
$script:winnerMode='foreign-upper'
Expect $false 0 'OpenVPN routes present but effective upper route belongs to different VPN'
$script:winnerMode='matching'
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 37 'Another VPN'))
Expect $false 0 'foreign upper route cannot create healthy managed VPN'
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
Expect $false 0 'only one route'
$script:routes=@((Row '0.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'),(Row '128.0.0.0/1' 20 'OpenVPN Connect DCO Adapter'))
$script:driver='Intel Ethernet Controller'
Expect $false 0 'physical shadow routes'
$script:driver='OpenVPN Data Channel Offload'
$script:country='IR'
Expect $false 2 'foreign-country requirement'
$script:country='US'
$script:dns=@('10.10.34.35')
Expect $false 2 'DNS poisoning'
$script:dns=@()
Expect $false 2 'DNS unknown must not be healthy'
$script:dns=@('8.8.8.8')
Expect $false 2 'expected-country mismatch' 'JP'
Write-Output 'PASS: Windows headless health refuses effective foreign routes, stopped connector and untrusted DNS (10 offline cases)'
