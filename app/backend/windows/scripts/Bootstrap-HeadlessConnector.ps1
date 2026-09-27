[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$Root=Split-Path -Parent $PSScriptRoot
$connector='C:\Program Files\OpenVPN Connect\ovpnconnector.exe'
$service='OVPNConnectorService'
$programData='C:\ProgramData\OpenInternetGateway'
$profile=Join-Path $programData 'connector-current.ovpn'
$log=Join-Path $programData 'ovpnconnector.log'
$evidence=Join-Path $Root 'evidence\headless-bootstrap.json'
New-Item -ItemType Directory -Force -Path (Join-Path $Root 'evidence')|Out-Null

function Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Invoke-Connector([string[]]$CommandArgs,[int]$TimeoutMs=20000){
 $tag=[guid]::NewGuid().ToString('N')
 $outFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-bootstrap-'+$tag+'.out')
 $errFile=Join-Path ([IO.Path]::GetTempPath()) ('oig-bootstrap-'+$tag+'.err')
 try{
   $psi=[Diagnostics.ProcessStartInfo]::new()
   $psi.FileName=$connector
   $psi.UseShellExecute=$false
   $psi.CreateNoWindow=$true
   $psi.RedirectStandardOutput=$true
   $psi.RedirectStandardError=$true
   foreach($a in $CommandArgs){[void]$psi.ArgumentList.Add([string]$a)}
   $p=[Diagnostics.Process]::new();$p.StartInfo=$psi
   [void]$p.Start()
   $outTask=$p.StandardOutput.ReadToEndAsync()
   $errTask=$p.StandardError.ReadToEndAsync()
   if(-not $p.WaitForExit($TimeoutMs)){try{$p.Kill()}catch{};throw ('timeout '+($CommandArgs -join ' '))}
   $o=$outTask.GetAwaiter().GetResult()
   $e=$errTask.GetAwaiter().GetResult()
   if($p.ExitCode -ne 0){
     throw ('exit='+$p.ExitCode+' stdout='+([string]$o).Trim()+' stderr='+([string]$e).Trim())
   }
   return ([string]$o).Trim()
 }finally{
   foreach($f in @($outFile,$errFile)){if($f -and(Test-Path $f)){Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue}}
 }
}

$report=[ordered]@{at=(Get-Date).ToString('o');admin=(Admin);steps=@()}
try{
 if(-not $report.admin){throw 'Scheduled task did not run elevated.'}
 if(-not(Test-Path $connector)){throw 'ovpnconnector.exe missing.'}
 New-Item -ItemType Directory -Force -Path $programData|Out-Null
 $report.steps += 'programdata-ready'

 $svc=Get-Service $service -ErrorAction SilentlyContinue
 if(-not $svc){
   $out=Invoke-Connector @('install')
   $report.installOutput=$out
   $report.steps += 'service-installed'
 }else{$report.steps += 'service-already-installed'}

 $svc=Get-Service $service -ErrorAction SilentlyContinue
 if(-not $svc){throw 'OVPNConnectorService still missing after install.'}

 $settings=@(
   @('set-config','profile',$profile),
   @('set-config','log',$log),
   @('set-config','dco','false'),
   @('set-config','security-level','legacy'),
   @('set-config','seamless-tunnel','false'),
   @('set-config','allow-local-dns','false'),
   @('set-config','google-dns-fallback','true')
 )
 foreach($settingArgs in $settings){[void](Invoke-Connector $settingArgs);$report.steps += ('configured '+($settingArgs[1..($settingArgs.Count-1)] -join '='))}
 Set-Service -Name $service -StartupType Manual
 $svc=Get-Service $service
 $report.service=[ordered]@{status=$svc.Status.ToString();startType=$svc.StartType.ToString()}
 $report.result='PASS'
 $report|ConvertTo-Json -Depth 8|Set-Content -Encoding UTF8 $evidence
 New-Item -ItemType File -Force -Path (Join-Path $Root 'state\headless-bootstrap.ready')|Out-Null
 Write-Host 'HEADLESS BOOTSTRAP PASS'
}catch{
 $report.result='FAIL'
 $report.error=$_.Exception.Message
 $report.stack=$_.ScriptStackTrace
 $report|ConvertTo-Json -Depth 8|Set-Content -Encoding UTF8 $evidence
 throw
}
