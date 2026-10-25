# Native Windows end-to-end test of the read-only desktop foundation, driven
# through Windows UI Automation (no third-party framework). It launches the
# real executable with an isolated LOCALAPPDATA for the app process only:
# -RuntimeRoot points at a per-user runtime install made for testing; without
# it an empty temporary folder is used, so the user's real install is never
# queried. It checks what a person would see and performs no computer actions
# beyond typing into the app's own command box.
param(
    [string]$RuntimeRoot = "",
    [string]$BuildDirectory = (Join-Path $env:TEMP "OrcelDesktopPreviewBuild"),
    [string]$EvidencePath = ""
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$app = Join-Path $BuildDirectory "Orcel.Desktop.exe"
if (-not (Test-Path $app)) { throw "Build the app first (tests\verify.ps1): $app" }
$expectInstalled = $RuntimeRoot -ne ""
$emptyRoot = $null
if (-not $expectInstalled) {
    $emptyRoot = Join-Path $env:TEMP ("orcel-e2e-empty-" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $emptyRoot | Out-Null
}
$results = New-Object System.Collections.Generic.List[object]
function Check([string]$name, [bool]$ok, [string]$detail) {
    $results.Add([pscustomobject]@{ check = $name; pass = $ok; detail = $detail })
    if (-not $ok) { Write-Output "FAIL $name : $detail" } else { Write-Output "PASS $name" }
}

$root = [System.Windows.Automation.AutomationElement]::RootElement
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
        Start-Sleep -Milliseconds 100
    }
    return $null
}
function TranscriptTexts($window) {
    $transcript = ById $window "Transcript"
    $condition = New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::Text)
    $items = $transcript.FindAll($scope::Descendants, $condition)
    return @($items | ForEach-Object { $_.Current.Name })
}
function SendCommand($window, [string]$text) {
    $box = ById $window "CommandBox"
    $box.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern).SetValue($text)
    (ById $window "SendButton").GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
}
function WaitForMessage($window, [string]$needle, [int]$timeoutMs) {
    return WaitFor { TranscriptTexts $window | Where-Object { $_ -like "*$needle*" } | Select-Object -First 1 } $timeoutMs
}

$start = New-Object System.Diagnostics.ProcessStartInfo $app
$start.UseShellExecute = $false
$start.EnvironmentVariables["LOCALAPPDATA"] = $(if ($expectInstalled) { $RuntimeRoot } else { $emptyRoot })
# SG-000127: the app API pipe is per user, not per LOCALAPPDATA. Unless the
# caller names an instance served by a test orceld, point the app at an
# instance nothing serves, so the user's real runtime is never read.
$appApiInstance = $(if ($env:ORCEL_E2E_APP_API_INSTANCE) { $env:ORCEL_E2E_APP_API_INSTANCE } else { "e2e-" + [guid]::NewGuid().ToString("N").Substring(0, 12) })
$start.EnvironmentVariables["ORCEL_APP_API_INSTANCE"] = $appApiInstance
$clock = [Diagnostics.Stopwatch]::StartNew()
$process = [System.Diagnostics.Process]::Start($start)
try {
    $window = WaitFor { ById $root "OrcelMainWindow" } 15000
    $startupMs = $clock.ElapsedMilliseconds
    Check "window appears" ($null -ne $window) "startup ${startupMs} ms"
    if ($null -eq $window) { throw "window not found" }
    $windowProcess = $window.Current.ProcessId
    Check "window belongs to the launched process" ($windowProcess -eq $process.Id) "pid $windowProcess"

    # Activate the window (a test launch is not foreground); WPF restores the
    # element that received focus on load, which must be the command box.
    $window.SetFocus()
    $focused = WaitFor { if ((ById $window "CommandBox").Current.HasKeyboardFocus) { $true } } 3000
    Check "keyboard focus starts in the command box" ($focused -eq $true) ""

    $runtime = WaitFor { $t = (ById $window "RuntimeState").Current.Name; if ($t -and $t -ne "Checking...") { $t } } 15000
    $readyMs = $clock.ElapsedMilliseconds
    if ($expectInstalled) {
        Check "runtime panel reports the real install" ($runtime -like "Orcel runtime 0.*" -and $runtime -like "*not running*") "$runtime (after ${readyMs} ms)"
    } else {
        Check "runtime panel reports not installed" ($runtime -eq "Not installed") "$runtime"
    }

    $shell = (ById $window "ShellState").Current.Name
    Check "shell and process sessions are labelled unavailable" ($shell -like "Unavailable:*not armed*") "$shell"

    SendCommand $window "tasks"
    if ($env:ORCEL_E2E_APP_API_INSTANCE) {
        $tasks = WaitForMessage $window "Report tasks in this orceld run" 15000
        Check "tasks shows the live orceld's report tasks" ($null -ne $tasks -and $tasks -like "*$($env:ORCEL_E2E_EXPECT_TASK_TITLE)*") "$(($tasks -split "`n") -join ' | ')"
    } else {
        $tasks = WaitForMessage $window "Task timeline unavailable" 15000
        Check "tasks reports an absent app API instead of inventing tasks" ($null -ne $tasks) "$tasks"
    }

    SendCommand $window "status"
    $status = WaitForMessage $window $(if ($expectInstalled) { "is installed and not running" } else { "is not installed" }) 15000
    Check "status command shows the runtime's own state" ($null -ne $status) "$status"


    # Let earlier runtime queries finish so only new children are counted.
    Start-Sleep -Milliseconds 1500
    $refusedAt = Get-Date
    SendCommand $window "rm -rf / ; calc.exe"
    $refused = WaitFor { TranscriptTexts $window | Where-Object { $_.StartsWith("Not executed. Orcel AI is not connected.", [StringComparison]::Ordinal) } | Select-Object -First 1 } 5000
    Check "shell-like text is refused, not executed" ($null -ne $refused) "$refused"
    Start-Sleep -Milliseconds 1500
    # Direct children still alive, plus Calculator (Windows 11 launches it through a broker).
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId = $($process.Id)" | Where-Object { $_.CreationDate -ge $refusedAt })
    $calculators = @(Get-Process -Name "calc", "CalculatorApp" -ErrorAction SilentlyContinue | Where-Object { $_.StartTime -ge $refusedAt })
    Check "no process was started by the refused text" ($children.Count -eq 0 -and $calculators.Count -eq 0) ((@($children | ForEach-Object { $_.Name }) + @($calculators | ForEach-Object { $_.Name })) -join ", ")

    if ($expectInstalled) {
        SendCommand $window "doctor"
        $doctor = WaitForMessage $window "Health check:" 45000
        Check "doctor summarizes the real health report" ($null -ne $doctor -and $doctor -match "\d+ passed, \d+ warnings, \d+ failed") "$(($doctor -split "`n")[0])"
        SendCommand $window "version"
        $version = WaitForMessage $window "Orcel CLI" 15000
        Check "version reports CLI and installed release" ($null -ne $version) "$version"
    }

    $box = ById $window "CommandBox"
    Check "command box has an accessible name" ($box.Current.Name -eq "Command") "name '$($box.Current.Name)'"
    Check "controls are keyboard focusable" ($box.Current.IsKeyboardFocusable -and (ById $window "SendButton").Current.IsKeyboardFocusable) ""

    $process.Refresh()
    $workingSetMb = [math]::Round($process.WorkingSet64 / 1MB, 1)
    $privateMb = [math]::Round($process.PrivateMemorySize64 / 1MB, 1)
    Check "memory measured" $true "working set ${workingSetMb} MB, private ${privateMb} MB"

    $window.GetCurrentPattern([System.Windows.Automation.WindowPattern]::Pattern).Close()
    Check "window closes cleanly" ($process.WaitForExit(10000)) "exit code $(if ($process.HasExited) { $process.ExitCode } else { 'running' })"
}
finally {
    if (-not $process.HasExited) { $process.Kill() }
    if ($emptyRoot) { Remove-Item -Recurse -Force $emptyRoot -ErrorAction SilentlyContinue }
}

$failed = @($results | Where-Object { -not $_.pass }).Count
$evidence = [pscustomobject]@{
    app = $app
    app_bytes = (Get-Item $app).Length
    runtime_root_isolated = $expectInstalled
    startup_ms = $startupMs
    runtime_status_ready_ms = $readyMs
    windows_build = [Environment]::OSVersion.Version.ToString()
    checks = $results
    failed = $failed
}
if ($EvidencePath -ne "") { $evidence | ConvertTo-Json -Depth 4 | Set-Content -Path $EvidencePath -Encoding UTF8 }
if ($failed -gt 0) { throw "$failed native E2E check(s) failed" }
Write-Output "PASS: native UI Automation end-to-end checks ($($results.Count))"
