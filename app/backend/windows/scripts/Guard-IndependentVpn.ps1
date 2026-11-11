# Read-only Windows VPN coexistence guard for OIG first-launch/Connect.
# Exit 0 = no observed competing VPN; 17 = active independent tunnel;
# 18 = observation unavailable. Never start/stop services, routes, or VPNs.
$ErrorActionPreference='Stop'
try {
  $native=@(Get-VpnConnection -ErrorAction Stop | Where-Object { $_.ConnectionStatus -eq 'Connected' })
  $adapters=@(Get-NetAdapter -ErrorAction Stop | Where-Object {
    $_.Status -eq 'Up' -and (([string]$_.Name+' '+[string]$_.InterfaceDescription) -match '(?i)VPN|OpenVPN|TAP|TUN|Wintun|WireGuard|Tailscale')
  })
  $split=@(Get-NetRoute -ErrorAction Stop | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1','::/1','8000::/1')
  })
  if($native.Count -gt 0 -or $adapters.Count -gt 0 -or $split.Count -gt 0){exit 17}
  exit 0
} catch {
  # Do not disclose network or VPN configuration in diagnostics.
  exit 18
}
