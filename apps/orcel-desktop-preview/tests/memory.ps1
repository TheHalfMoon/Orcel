# #288: a repeatable memory profile of the WPF preview against a minimal WPF
# window built the same way, on the same machine. Report only: it sets no
# budget. It opens windows and types into the app's own command box, so it
# runs only on a disposable CI runner (GITHUB_ACTIONS) unless -AllowLocal is
# given. Each app gets an isolated, empty LOCALAPPDATA and an app API
# instance nothing serves, as tests\e2e.ps1 does.
#
# For each app (orcel, baseline) and rendering mode (hardware, software):
# cold and warm launches with startup time, idle working set, private bytes,
# managed GC heap, loaded managed assemblies and native modules. Then the
# Orcel app alone: memory across repeated runtime queries and after idling.
# Output: WPF-MEM lines and a JSON report (-OutPath).
param(
    [string]$BuildDirectory = (Join-Path $env:TEMP "OrcelDesktopMemoryBuild"),
    [int]$Launches = 4,
    [int]$Queries = 40,
    [string]$OutPath = "",
    [switch]$AllowLocal
)
$ErrorActionPreference = "Stop"
if ($env:GITHUB_ACTIONS -ne "true" -and -not $AllowLocal) {
    throw "memory.ps1 opens windows and types into them: it runs on a CI runner only (or pass -AllowLocal on a disposable machine)"
}
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $root "build.ps1") -OutputDirectory $BuildDirectory | Out-Null
$framework = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319"
$wpf = Join-Path $framework "WPF"
$baselineExe = Join-Path $BuildDirectory "Orcel.MinimalWpf.exe"
& (Join-Path $framework "csc.exe") /nologo /target:winexe /optimize+ /platform:anycpu "/out:$baselineExe" `
    "/reference:$(Join-Path $wpf 'PresentationFramework.dll')" "/reference:$(Join-Path $wpf 'PresentationCore.dll')" `
    "/reference:$(Join-Path $wpf 'WindowsBase.dll')" "/reference:$(Join-Path $framework 'System.Xaml.dll')" `
    (Join-Path $PSScriptRoot "baseline\MinimalWindow.cs")
if ($LASTEXITCODE -ne 0) { throw "baseline build failed" }
$apps = [ordered]@{
    orcel    = @{ exe = (Join-Path $BuildDirectory "Orcel.Desktop.exe"); window = "OrcelMainWindow" }
    baseline = @{ exe = $baselineExe; window = "BaselineWindow" }
}

$uiaRoot = [System.Windows.Automation.AutomationElement]::RootElement
$scope = [System.Windows.Automation.TreeScope]
function ById($parent, [string]$id) {
    $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, $id)
    return $parent.FindFirst($scope::Descendants, $condition)
}
function WaitFor([scriptblock]$probe, [int]$timeoutMs) {
    $clock = [Diagnostics.Stopwatch]::StartNew()
    while ($clock.ElapsedMilliseconds -lt $timeoutMs) {
        $value = & $probe
        if ($value) { return $value }
        Start-Sleep -Milliseconds 50
    }
    return $null
}
function Mb([double]$bytes) { [math]::Round($bytes / 1MB, 1) }

# .NET Framework's own performance counters, by process instance name.
function ClrCounter([System.Diagnostics.Process]$process, [string]$category, [string]$counter) {
    try {
        $instance = $process.ProcessName
        $names = (New-Object System.Diagnostics.PerformanceCounterCategory $category).GetInstanceNames()
        foreach ($name in $names) {
            if ($name -ne $instance -and -not $name.StartsWith("$instance#")) { continue }
            $idCounter = New-Object System.Diagnostics.PerformanceCounter($category, "Process ID", $name, $true)
            if ([int]$idCounter.RawValue -ne $process.Id) { continue }
            return (New-Object System.Diagnostics.PerformanceCounter($category, $counter, $name, $true)).NextValue()
        }
    } catch { }
    return $null
}
function Sample([System.Diagnostics.Process]$process) {
    $process.Refresh()
    $modules = @($process.Modules)
    $managed = @($modules | Where-Object { $_.FileName -match '\\assembly\\|\\Microsoft\.NET\\|\.ni\.dll$' })
    $heap = ClrCounter $process ".NET CLR Memory" "# Bytes in all Heaps"
    [ordered]@{
        working_set_mb    = Mb $process.WorkingSet64
        private_mb        = Mb $process.PrivateMemorySize64
        gc_heap_mb        = $(if ($null -ne $heap) { Mb $heap } else { $null })
        clr_assemblies    = ClrCounter $process ".NET CLR Loading" "Current Assemblies"
        native_modules    = $modules.Count
        managed_images    = $managed.Count
        handles           = $process.HandleCount
        threads           = $process.Threads.Count
    }
}
function Start-App([string]$name) {
    $info = New-Object System.Diagnostics.ProcessStartInfo $apps[$name].exe
    $info.UseShellExecute = $false
    $empty = Join-Path $env:TEMP ("orcel-mem-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $empty | Out-Null
    $info.EnvironmentVariables["LOCALAPPDATA"] = $empty
    $info.EnvironmentVariables["ORCEL_APP_API_INSTANCE"] = "mem-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $process = [System.Diagnostics.Process]::Start($info)
    $window = WaitFor { ById $uiaRoot $apps[$name].window } 30000
    if ($null -eq $window) { $process.Kill(); throw "$name window did not appear" }
    return @{ process = $process; window = $window; startup_ms = $clock.ElapsedMilliseconds; empty = $empty }
}
function Stop-App($run) {
    try { $run.window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close() } catch { }
    if (-not $run.process.WaitForExit(10000)) { $run.process.Kill(); $run.process.WaitForExit(5000) | Out-Null }
    Remove-Item -Recurse -Force $run.empty -ErrorAction SilentlyContinue
}
function Names([System.Diagnostics.Process]$process) {
    $process.Refresh()
    @($process.Modules | Where-Object { $_.FileName -match '\\assembly\\|\\Microsoft\.NET\\' } | ForEach-Object { [IO.Path]::GetFileName($_.FileName) } | Sort-Object -Unique)
}

# WPF's documented per-user switch for software rendering, set only for this
# measurement and always restored.
$avalon = "HKCU:\Software\Microsoft\Avalon.Graphics"
function Set-SoftwareRendering([bool]$on) {
    if (-not (Test-Path $avalon)) { New-Item -Path $avalon -Force | Out-Null }
    if ($on) { Set-ItemProperty -Path $avalon -Name DisableHWAcceleration -Value 1 -Type DWord }
    else { Remove-ItemProperty -Path $avalon -Name DisableHWAcceleration -ErrorAction SilentlyContinue }
}
$hadSwitch = $null -ne (Get-ItemProperty -Path $avalon -Name DisableHWAcceleration -ErrorAction SilentlyContinue)
if ($hadSwitch) { throw "DisableHWAcceleration is already set on this machine; refusing to change it" }

$report = [ordered]@{ schema = "orcel-wpf-memory/1"; machine = [ordered]@{
        os = [Environment]::OSVersion.VersionString; cpus = [Environment]::ProcessorCount
        dotnet_framework = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release
    }; launches = @(); queries = $null; assemblies = [ordered]@{} }

try {
    foreach ($mode in @("hardware", "software")) {
        Set-SoftwareRendering ($mode -eq "software")
        foreach ($name in $apps.Keys) {
            for ($i = 0; $i -lt $Launches; $i++) {
                $run = Start-App $name
                try {
                    Start-Sleep -Seconds 3
                    $sample = Sample $run.process
                    if ($mode -eq "hardware" -and $i -eq 0) { $report.assemblies[$name] = Names $run.process }
                } finally { Stop-App $run }
                $entry = [ordered]@{ app = $name; mode = $mode; launch = $i; kind = $(if ($i -eq 0) { "cold" } else { "warm" }); startup_ms = $run.startup_ms; idle = $sample }
                $report.launches += $entry
                Write-Output ("WPF-MEM {0} {1} {2}#{3} startup={4}ms ws={5}MB private={6}MB gc={7}MB assemblies={8} modules={9}" -f `
                        $name, $mode, $entry.kind, $i, $run.startup_ms, $sample.working_set_mb, $sample.private_mb, $sample.gc_heap_mb, $sample.clr_assemblies, $sample.native_modules)
            }
        }
    }
} finally {
    Set-SoftwareRendering $false
}

# Repeated runtime queries in one Orcel window (hardware rendering).
$run = Start-App "orcel"
try {
    $window = $run.window
    $box = ById $window "CommandBox"
    $send = ById $window "SendButton"
    Start-Sleep -Seconds 3
    $points = @([ordered]@{ after = 0; memory = (Sample $run.process) })
    for ($q = 1; $q -le $Queries; $q++) {
        $command = $(if ($q % 2) { "status" } else { "tasks" })
        $box.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($command)
        $send.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
        Start-Sleep -Milliseconds 400
        if ($q % 10 -eq 0) { $points += [ordered]@{ after = $q; memory = (Sample $run.process) } }
    }
    Start-Sleep -Seconds 10
    $points += [ordered]@{ after = "idle-10s"; memory = (Sample $run.process) }
    $report.queries = $points
    foreach ($point in $points) {
        Write-Output ("WPF-MEM orcel queries after={0} ws={1}MB private={2}MB gc={3}MB handles={4} threads={5}" -f `
                $point.after, $point.memory.working_set_mb, $point.memory.private_mb, $point.memory.gc_heap_mb, $point.memory.handles, $point.memory.threads)
    }
} finally { Stop-App $run }

$extra = @($report.assemblies["orcel"] | Where-Object { $report.assemblies["baseline"] -notcontains $_ })
Write-Output ("WPF-MEM assemblies only in orcel ({0}): {1}" -f $extra.Count, ($extra -join ", "))
if ($OutPath) { $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutPath -Encoding UTF8 }
