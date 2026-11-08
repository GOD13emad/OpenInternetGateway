# Read-only route selection guard shared by all Windows status, connect,
# and headless recovery paths. It does not prove peer certificate identity.
function Test-OigFullRoutePair {
 [CmdletBinding()]
 param([AllowEmptyCollection()][object[]]$Routes=@())
 $rows=@($Routes|Where-Object{$_ -and $_.DestinationPrefix})
 if($rows.Count -ne 2){return $false}
 $prefixes=@($rows|Select-Object -ExpandProperty DestinationPrefix -Unique)
 if($prefixes.Count -ne 2 -or
    '0.0.0.0/1' -notin $prefixes -or '128.0.0.0/1' -notin $prefixes){return $false}
 $indexes=@($rows|Select-Object -ExpandProperty InterfaceIndex -Unique)
 $aliases=@($rows|Select-Object -ExpandProperty InterfaceAlias -Unique)
 if($indexes.Count -ne 1 -or $aliases.Count -ne 1){return $false}
 if([int]$indexes[0] -lt 1 -or [string]::IsNullOrWhiteSpace([string]$aliases[0])){return $false}
 # Connector routes must be on an OpenVPN-capable adapter, not the physical
 # Ethernet shadow pair or another product's ordinary VPN/PPP adapter.
 $adapter=@(Get-NetAdapter -InterfaceIndex ([int]$indexes[0]) -ErrorAction SilentlyContinue)
 if($adapter.Count -ne 1){return $false}
 $driver=[string]$adapter[0].InterfaceDescription
 if($driver -notmatch 'OpenVPN|TAP-Windows'){return $false}
 # Do not credit installed /1 routes that lose to another VPN's effective
 # route, or a more-specific host/policy route. Find-NetRoute returns both a
 # source-address object and the selected NetRoute; filter to NetRoute only.
 foreach($destination in @('1.1.1.1','208.67.222.222')){
   $winning=@(Find-NetRoute -RemoteIPAddress $destination -ErrorAction SilentlyContinue |
     Where-Object { $_.PSObject.Properties['DestinationPrefix'] })
   if($winning.Count -ne 1){return $false}
   $selected=$winning[0]
   $expectedPrefix=$(if($destination -eq '1.1.1.1'){'0.0.0.0/1'}else{'128.0.0.0/1'})
   if([int]$selected.InterfaceIndex -ne [int]$indexes[0] -or
      [string]$selected.InterfaceAlias -ne [string]$aliases[0] -or
      [string]$selected.DestinationPrefix -ne $expectedPrefix){return $false}
 }
 return $true
}

# IPv4 tunnel ownership does not prevent a parallel IPv6 escape on dual-stack
# networks. Inspect the two effective public-IPv6 route selections without
# sending packets or modifying network configuration. No IPv6 route is safe;
# a physical/foreign selected IPv6 route is not.
function Test-OigIpv6EgressSafe {
 [CmdletBinding()]
 param([int]$InterfaceIndex)
 if($InterfaceIndex -lt 1){return $false}
 $configured=@(Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue |
   Where-Object {$_.DestinationPrefix -in @('::/0','::/1','8000::/1')})
 foreach($destination in @('2606:4700:4700::1111','2001:4860:4860::8888')){
   $selected=@(Find-NetRoute -RemoteIPAddress $destination -ErrorAction SilentlyContinue |
     Where-Object {$_.PSObject.Properties['DestinationPrefix']})
   if($selected.Count -eq 0){
     # No viable IPv6 route is safe only if there is no global default /1.
     if($configured.Count -ne 0){return $false}
     continue
   }
   if($selected.Count -ne 1 -or [int]$selected[0].InterfaceIndex -ne $InterfaceIndex){
     return $false
   }
 }
 return $true
}
