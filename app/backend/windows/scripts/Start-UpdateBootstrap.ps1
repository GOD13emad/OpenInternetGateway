# Current-user Windows update handoff. The native Start-Process child survives
# the intermediate launcher exiting while windowsHide remains enabled.
# All payload paths come from the already hash-validated GitHub update flow.
param(
  [Parameter(Mandatory=$true)][string]$Runner,
  [Parameter(Mandatory=$true)][string]$Helper,
  [Parameter(Mandatory=$true)][string]$Installer,
  [Parameter(Mandatory=$true)][string]$ExpectedSha,
  [Parameter(Mandatory=$true)][string]$Version,
  [Parameter(Mandatory=$true)][int]$WaitPid,
  [Parameter(Mandatory=$true)][string]$Target,
  [Parameter(Mandatory=$true)][string]$Fallback,
  [Parameter(Mandatory=$true)][string]$ResultFile,
  [Parameter(Mandatory=$true)][string]$LaunchLog
)
$ErrorActionPreference='Stop'
function Quote-UpdateArg([string]$Text) {
  if([string]::IsNullOrWhiteSpace($Text) -or $Text.Contains('"')){throw 'Unsafe update argument.'}
  return '"'+$Text+'"'
}
try {
  if($ExpectedSha -notmatch '^[a-fA-F0-9]{64}$' -or $Version -notmatch '^\d+\.\d+\.\d+$' -or $WaitPid -lt 1) {
    throw 'Invalid update identity or process scope.'
  }
  if(-not(Test-Path -LiteralPath $Runner -PathType Leaf) -or
     -not(Test-Path -LiteralPath $Helper -PathType Leaf) -or
     -not(Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw 'Update runtime, helper or installer missing.'
  }
  $arguments=@(
    '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',(Quote-UpdateArg $Helper),
    '-Installer',(Quote-UpdateArg $Installer),
    '-ExpectedSha',$ExpectedSha,
    '-Version',$Version,
    '-WaitPid',([string]$WaitPid),
    '-Target',(Quote-UpdateArg $Target),
    '-Fallback',(Quote-UpdateArg $Fallback),
    '-ResultFile',(Quote-UpdateArg $ResultFile)
  )
  $native=Start-Process -FilePath $Runner -ArgumentList $arguments -WindowStyle Hidden -PassThru -ErrorAction Stop
  if($null -eq $native -or $native.Id -lt 1){throw 'Native update child did not launch.'}
  exit 0
} catch {
  # Never log credentials, raw paths or exception contents in the launch log.
  try{'WINDOWS_UPDATE_BOOTSTRAP_FAILED' | Set-Content -LiteralPath $LaunchLog -Encoding UTF8}catch{}
  exit 1
}
