# Disposable GitHub-hosted Windows runner only. Never use against the owner's desktop.
param(
  [Parameter(Mandatory=$true)][string]$InstalledExe,
  [Parameter(Mandatory=$true)][string]$ScratchRoot
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) {
  throw 'Hosted tray acceptance is restricted to an isolated GitHub Actions runner.'
}
if (-not (Test-Path -LiteralPath $InstalledExe -PathType Leaf)) { throw 'Installed EXE missing' }
if (-not [IO.Path]::IsPathFullyQualified($ScratchRoot)) { throw 'Scratch root must be absolute' }
$runnerRoot = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
$testRoot = [IO.Path]::GetFullPath($ScratchRoot).TrimEnd('\','/') + [IO.Path]::DirectorySeparatorChar
if (-not $testRoot.StartsWith($runnerRoot,[StringComparison]::OrdinalIgnoreCase)) {
  throw 'Scratch root must be inside the disposable RUNNER_TEMP.'
}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class OigHostedWindow {
  [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr FindWindow(string className, string windowName);
  [DllImport("user32.dll")]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool IsWindowVisible(IntPtr handle);
  [DllImport("user32.dll", SetLastError = true)]
  [return: MarshalAs(UnmanagedType.Bool)]
  public static extern bool PostMessage(IntPtr handle, uint message, IntPtr wParam, IntPtr lParam);
}
'@
$null = New-Item -ItemType Directory -Force -Path $ScratchRoot
$roaming = Join-Path $ScratchRoot 'Roaming'
$local = Join-Path $ScratchRoot 'Local'
$null = New-Item -ItemType Directory -Force -Path $roaming,$local
$envs = @{ APPDATA=$roaming; LOCALAPPDATA=$local }
function Start-Isolated([string]$arguments) {
  $startInfo = [Diagnostics.ProcessStartInfo]::new()
  $startInfo.FileName = $InstalledExe
  $startInfo.Arguments = $arguments
  $startInfo.UseShellExecute = $false
  foreach($key in $envs.Keys) { $startInfo.Environment[$key] = $envs[$key] }
  # Prevent accidental reuse of the passive capture-only path in this lifecycle test.
  foreach($key in @('OIG_CAPTURE_ONLY','OIG_CAPTURE_PATH','OIG_CAPTURE_ROOT')) {
    [void]$startInfo.Environment.Remove($key)
  }
  $result = [Diagnostics.Process]::Start($startInfo)
  if ($null -eq $result) { throw 'Failed to start installed Electron executable' }
  return $result
}
$script:observedWindow = [IntPtr]::Zero
function Wait-Window([bool]$wantVisible,[int]$timeoutMs) {
  $stopwatch = [Diagnostics.Stopwatch]::StartNew()
  while ($stopwatch.ElapsedMilliseconds -lt $timeoutMs) {
    if ($main.HasExited) { throw "App exited unexpectedly ($($main.ExitCode))" }
    # A hidden Chromium window may not have a discoverable title/handle
    # until it has first been shown. After first show, use the observed HWND.
    $h = if ($script:observedWindow -ne [IntPtr]::Zero) {
      $script:observedWindow
    } else {
      # Hosted Electron process reported a nonzero MainWindowHandle even
      # while exact-title FindWindow returned zero (CI 39340175319).
      # Prefer the handle *owned by the launched process*, not a title.
      $main.Refresh()
      if ($main.MainWindowHandle -ne [IntPtr]::Zero) {
        $main.MainWindowHandle
      } else {
        [OigHostedWindow]::FindWindow($null,'Open Internet Gateway')
      }
    }
    if ($h -ne [IntPtr]::Zero -and [OigHostedWindow]::IsWindowVisible($h) -eq $wantVisible) {
      if ($wantVisible) { $script:observedWindow = $h }
      return $h
    }
    Start-Sleep -Milliseconds 300
  }
  $p = Get-Process -Id $main.Id -ErrorAction SilentlyContinue
  throw "Hosted Windows HWND unavailable: desiredVisible=$wantVisible, observedHWND=$($script:observedWindow), mainWindowHandle=$($p.MainWindowHandle), session=$($p.SessionId)"
}
function Send-Secondary([string]$arguments) {
  $secondary=Start-Isolated $arguments
  try {
    if (-not $secondary.WaitForExit(15000)) {
      throw "Secondary app instance did not exit ($arguments)"
    }
  } finally {
    if (-not $secondary.HasExited) { $secondary.Kill($true) }
    $secondary.Dispose()
  }
}
$main=Start-Isolated '--background'
try {
  Start-Sleep -Seconds 3
  if ($main.HasExited) { throw 'Background-installed app exited before second instance' }
  Write-Host 'Hosted installed Electron background process remained alive'
  # First show via a second instance; hidden windows are not guaranteed
  # to be enumerable via FindWindow in hosted Windows service sessions.
  Send-Secondary ''
  $handle=Wait-Window $true 20000
  Write-Host 'Hosted second-instance Dashboard show PASS'
  if (-not [OigHostedWindow]::PostMessage($handle,0x0010,[IntPtr]::Zero,[IntPtr]::Zero)) {
    throw 'WM_CLOSE delivery failed'
  }
  $handle=Wait-Window $false 12000
  if ($main.HasExited) { throw 'Close incorrectly terminated tray process' }
  Write-Host 'Hosted Dashboard WM_CLOSE -> hidden tray-lifetime PASS'
  Send-Secondary ''
  $null=Wait-Window $true 20000
  Write-Host 'Hosted second-instance Dashboard reopen PASS'
  Send-Secondary '--quit'
  if (-not $main.WaitForExit(45000)) {
    throw 'Explicit Quit did not terminate installed Electron after managed disconnect'
  }
  if ($main.ExitCode -ne 0) { throw "Installed Electron exit code: $($main.ExitCode)" }
  Write-Host 'Hosted explicit Quit -> installed app exit PASS'
} finally {
  if (-not $main.HasExited) {
    $main.Kill($true)
    [void]$main.WaitForExit(5000)
  }
  $main.Dispose()
}
