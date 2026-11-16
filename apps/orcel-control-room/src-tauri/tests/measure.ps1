# SG-000119 A5: start time, memory, idle CPU and binary size of the Tauri
# Control Room shell beside the WPF preview (apps/orcel-desktop-preview),
# for CR-04. Report only: it sets no budget and fails only if an app does
# not open or close.
#
# It injects no input. Each app is launched, its window is found by
# enumerating top-level windows (read-only), the process tree is sampled,
# and the window is closed with WM_CLOSE posted to that window. The WPF
# preview gets an empty USERPROFILE and an app API instance nothing serves,
# as its tests/e2e.ps1 does. The shell has no endpoint override by design:
# if this user's orceld runs, the shell reads its status, read-only.
#
# "first" is the first launch in this run, after the build; it is not a
# cold boot (the system file cache is not flushed). "warm" are the later
# launches. Memory is sampled once, SettleSeconds after the window shows,
# then idle CPU over the next IdleSeconds. Memory is the whole process tree: for the shell, the shell and
# every WebView2 process under it; the WebView2 runtime and .NET Framework
# are operating-system components and are not counted in binary size.
#
# Output: one SG119-MEASURE line per launch, one SG119-MEASURE-SUMMARY line
# per app, and the same as JSON when -OutPath is given.
param(
    [Parameter(Mandatory = $true)] [string]$Shell,
    [string]$WpfBuildDirectory = (Join-Path $env:TEMP "OrcelA5WpfBuild"),
    [int]$Launches = 5,
    [int]$SettleSeconds = 5,
    [int]$IdleSeconds = 10,
    [string]$OutPath = ""
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Shell)) { throw "No shell binary at $Shell" }
$Shell = (Resolve-Path $Shell).Path

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class Sg119Windows {
    delegate bool EnumProc(IntPtr hwnd, IntPtr data);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr data);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int max);
    [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr hwnd, uint message, IntPtr w, IntPtr l);
    public static IntPtr FindVisible(int pid, string titlePrefix) {
        IntPtr found = IntPtr.Zero;
        EnumWindows(delegate (IntPtr hwnd, IntPtr data) {
            uint owner;
            GetWindowThreadProcessId(hwnd, out owner);
            if (owner != (uint)pid || !IsWindowVisible(hwnd)) return true;
            StringBuilder text = new StringBuilder(256);
            GetWindowTextW(hwnd, text, 256);
            if (text.ToString().StartsWith(titlePrefix, StringComparison.Ordinal)) { found = hwnd; return false; }
            return true;
        }, IntPtr.Zero);
        return found;
    }
}
"@

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..\..")).Path
$ownWpfBuild = -not (Test-Path $WpfBuildDirectory)
& (Join-Path $repo "apps\orcel-desktop-preview\build.ps1") -OutputDirectory $WpfBuildDirectory | Out-Null
$wpfExe = Join-Path $WpfBuildDirectory "Orcel.Desktop.exe"
if (-not (Test-Path $wpfExe)) { throw "The WPF preview did not build: $wpfExe" }

function Tree([int]$root) {
    $all = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name)
    $ids = New-Object System.Collections.Generic.List[int]
    $ids.Add($root)
    $grew = $true
    while ($grew) {
        $grew = $false
        foreach ($p in $all) {
            if ($ids.Contains([int]$p.ParentProcessId) -and -not $ids.Contains([int]$p.ProcessId)) { $ids.Add([int]$p.ProcessId); $grew = $true }
        }
    }
    return @($ids | ForEach-Object { Get-Process -Id $_ -ErrorAction SilentlyContinue } | Where-Object { $_ })
}
function Mb([double]$bytes) { [math]::Round($bytes / 1MB, 1) }
function Median([double[]]$values) {
    if ($values.Count -eq 0) { return $null }
    $sorted = @($values | Sort-Object)
    $middle = [int][math]::Floor($sorted.Count / 2)
    if ($sorted.Count % 2 -eq 1) { return $sorted[$middle] }
    return ($sorted[$middle - 1] + $sorted[$middle]) / 2
}

$apps = [ordered]@{
    tauri = @{ exe = $Shell; title = "Orcel Control Room"; env = @{}; bytes = (Get-Item $Shell).Length }
    wpf   = @{ exe = $wpfExe; title = "Orcel"; env = @{}; bytes = (Get-Item $wpfExe).Length }
}
$runs = New-Object System.Collections.Generic.List[object]
$webview2 = "unknown"
$emptyProfile = Join-Path $env:TEMP ("orcel-a5-measure-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $emptyProfile | Out-Null
$apps.wpf.env["USERPROFILE"] = $emptyProfile
$apps.wpf.env["ORCEL_APP_API_INSTANCE"] = "a5-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
try {
    foreach ($name in $apps.Keys) {
        $app = $apps[$name]
        for ($launch = 1; $launch -le $Launches; $launch++) {
            $start = New-Object System.Diagnostics.ProcessStartInfo $app.exe
            $start.UseShellExecute = $false
            $start.CreateNoWindow = $true
            $start.RedirectStandardOutput = $true
            $start.RedirectStandardError = $true
            foreach ($variable in @($start.EnvironmentVariables.Keys)) {
                if ($variable -like "WEBVIEW2_*") { $start.EnvironmentVariables.Remove($variable) }
            }
            foreach ($key in $app.env.Keys) { $start.EnvironmentVariables[$key] = $app.env[$key] }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $process = [System.Diagnostics.Process]::Start($start)
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()
            try {
                $hwnd = [IntPtr]::Zero
                while ($hwnd -eq [IntPtr]::Zero -and $clock.ElapsedMilliseconds -lt 60000) {
                    if ($process.HasExited) { throw "$name exited with $($process.ExitCode) before its window appeared" }
                    $hwnd = [Sg119Windows]::FindVisible($process.Id, $app.title)
                    if ($hwnd -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 10 }
                }
                $startupMs = $clock.ElapsedMilliseconds
                if ($hwnd -eq [IntPtr]::Zero) { throw "$name showed no window within 60 s" }
                Start-Sleep -Seconds $SettleSeconds
                $tree = Tree $process.Id
                $workingSet = ($tree | Measure-Object -Property WorkingSet64 -Sum).Sum
                $private = ($tree | Measure-Object -Property PrivateMemorySize64 -Sum).Sum
                $mainWorkingSet = ($tree | Where-Object { $_.Id -eq $process.Id }).WorkingSet64
                if ($name -eq "tauri" -and $webview2 -eq "unknown") {
                    $browser = $tree | Where-Object { $_.ProcessName -eq "msedgewebview2" } | Select-Object -First 1
                    if ($browser) { try { $webview2 = $browser.MainModule.FileVersionInfo.ProductVersion } catch { } }
                }
                $cpuBefore = ($tree | ForEach-Object { $_.Refresh(); $_.TotalProcessorTime.TotalMilliseconds } | Measure-Object -Sum).Sum
                $idleClock = [Diagnostics.Stopwatch]::StartNew()
                Start-Sleep -Seconds $IdleSeconds
                $tree = Tree $process.Id
                $cpuAfter = ($tree | ForEach-Object { $_.Refresh(); $_.TotalProcessorTime.TotalMilliseconds } | Measure-Object -Sum).Sum
                $idlePct = [math]::Round(100 * ($cpuAfter - $cpuBefore) / $idleClock.ElapsedMilliseconds, 2)
                $run = [ordered]@{
                    app = $name
                    launch = $launch
                    kind = $(if ($launch -eq 1) { "first" } else { "warm" })
                    startup_ms = $startupMs
                    working_set_mb = Mb $workingSet
                    private_mb = Mb $private
                    main_working_set_mb = Mb $mainWorkingSet
                    processes = $tree.Count
                    cpu_idle_pct_of_one_core = [math]::Max([double]0, [double]$idlePct)
                }
                $runs.Add([pscustomobject]$run)
                Write-Output ("SG119-MEASURE " + (($run.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "))
                [void][Sg119Windows]::PostMessageW($hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
                if (-not $process.WaitForExit(20000)) { throw "$name did not close within 20 s of WM_CLOSE" }
            }
            finally {
                if (-not $process.HasExited) { $process.Kill() }
            }
            Start-Sleep -Seconds 2
        }
    }
}
finally {
    Remove-Item -Recurse -Force $emptyProfile -ErrorAction SilentlyContinue
    if ($ownWpfBuild) { Remove-Item -Recurse -Force $WpfBuildDirectory -ErrorAction SilentlyContinue }
}

$summaries = New-Object System.Collections.Generic.List[object]
foreach ($name in $apps.Keys) {
    $mine = @($runs | Where-Object { $_.app -eq $name })
    $warm = @($mine | Where-Object { $_.kind -eq "warm" })
    $summary = [ordered]@{
        app = $name
        first_startup_ms = ($mine | Where-Object { $_.kind -eq "first" }).startup_ms
        warm_startup_median_ms = Median @($warm | ForEach-Object { [double]$_.startup_ms })
        working_set_median_mb = Median @($mine | ForEach-Object { [double]$_.working_set_mb })
        private_median_mb = Median @($mine | ForEach-Object { [double]$_.private_mb })
        processes = ($mine | Select-Object -First 1).processes
        cpu_idle_median_pct_of_one_core = Median @($mine | ForEach-Object { [double]$_.cpu_idle_pct_of_one_core })
        binary_bytes = $apps[$name].bytes
    }
    $summaries.Add([pscustomobject]$summary)
    Write-Output ("SG119-MEASURE-SUMMARY " + (($summary.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "))
}
$report = [ordered]@{
    shell = Split-Path -Leaf $Shell
    webview2 = $webview2
    windows_build = [Environment]::OSVersion.Version.ToString()
    logical_processors = [Environment]::ProcessorCount
    launches = $Launches
    settle_seconds = $SettleSeconds
    idle_seconds = $IdleSeconds
    runs = $runs
    summaries = $summaries
}
Write-Output "SG119-MEASURE-ENV webview2=$webview2 windows=$($report.windows_build) logical_processors=$($report.logical_processors)"
if ($OutPath -ne "") { $report | ConvertTo-Json -Depth 4 | Set-Content -Path $OutPath -Encoding UTF8 }
