# Read-only Windows VPN coexistence guard for all OIG entrypoints.
# Exit 0 = no independent VPN; 17 = independent VPN; 18 = unknown.
# OwnedInterfaceIndex is accepted only from the local OIG-owned route-pair
# validator; all Windows phonebook VPNs remain independent.
[CmdletBinding()]
param([ValidateRange(0,2147483647)][int]$OwnedInterfaceIndex=0)
$ErrorActionPreference='Stop'
try {
  $personal=@(Get-VpnConnection -ErrorAction Stop |
    Where-Object { $_.ConnectionStatus -eq 'Connected' })
  $global=@(Get-VpnConnection -AllUserConnection -ErrorAction Stop |
    Where-Object { $_.ConnectionStatus -eq 'Connected' })
  $adapters=@(Get-NetAdapter -ErrorAction Stop | Where-Object {
    $_.Status -eq 'Up' -and
    (([string]$_.Name+' '+[string]$_.InterfaceDescription) -match
      '(?i)VPN|OpenVPN|TAP|TUN|Wintun|WireGuard|Tailscale') -and
    ($OwnedInterfaceIndex -eq 0 -or [int]$_.ifIndex -ne $OwnedInterfaceIndex)
  })
  $split=@(Get-NetRoute -ErrorAction Stop | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1') -and
    ($OwnedInterfaceIndex -eq 0 -or [int]$_.InterfaceIndex -ne $OwnedInterfaceIndex)
  })
  if($personal.Count -gt 0 -or $global.Count -gt 0 -or
     $adapters.Count -gt 0 -or $split.Count -gt 0){exit 17}
  exit 0
} catch {
  # No network configuration, credentials or host details are written.
  exit 18
}
