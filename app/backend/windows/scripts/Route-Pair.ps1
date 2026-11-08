# Pure route-shape guard, shared by read-only Windows status paths.
# This is NOT proof that the managed OpenVPN connector owns the adapter.
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
 return $true
}
