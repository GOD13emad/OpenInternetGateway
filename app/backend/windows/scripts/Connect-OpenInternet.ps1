[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$desired=Join-Path $Root 'state\desired-state.json'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'state')|Out-Null
[ordered]@{desired='on';at=(Get-Date).ToString('o')}|ConvertTo-Json|Set-Content -Encoding UTF8 $desired
schtasks.exe /Run /TN OpenInternetGateway-AutoRecovery | Out-Null
$until=(Get-Date).AddSeconds(150)
do{
 Start-Sleep -Seconds 2
 $routes=@(Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue|Where-Object{$_.DestinationPrefix -in @('0.0.0.0/1','128.0.0.0/1')})
 $cf=@(curl.exe -4 --max-time 4 -s https://www.cloudflare.com/cdn-cgi/trace)
 $loc=[string]((($cf|Where-Object{$_ -like 'loc=*'}|Select-Object -First 1)-replace '^loc=',''));$loc=$loc.Trim()
 $svc=Get-Service OVPNConnectorService -ErrorAction SilentlyContinue
 if($routes.Count -ge 2 -and $loc -eq 'JP' -and $svc -and $svc.Status -eq 'Running'){
   $gui=@(Get-Process OpenVPNConnect -ErrorAction SilentlyContinue).Count
   if($gui -ne 0){throw 'Headless connect succeeded but OpenVPN GUI process is still running.'}
   Write-Host 'CONNECTED'
   exit 0
 }
}while((Get-Date)-lt $until)
throw 'Headless connect task did not reach a validated JP tunnel within 150 seconds.'
