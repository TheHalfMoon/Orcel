# SG-000127 slice 5 (timeline): the Windows app reads a live orceld's report
# tasks through the read-only app API. Starts a real orceld with an isolated
# app API instance, workspace and state, drives report/start and
# report/preview over its stdio channel (nothing reaches the approval
# broker, so no dialog can appear), then runs the UI Automation end-to-end
# test against that instance and requires the task to appear, and a second
# task's update to appear with nothing typed. The user's
# real runtime and pipe are never touched.
param(
    [Parameter(Mandatory = $true)][string]$Orceld,
    [string]$BuildDirectory = (Join-Path $env:TEMP "OrcelDesktopPreviewBuild"),
    # orceld refuses an audit log or state root with an ancestor another user
    # can change; on some machines %TEMP% (under AppData) has such an entry,
    # so the default is the profile root.
    [string]$WorkRoot = $env:USERPROFILE
)
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Orceld)) { throw "orceld not found: $Orceld" }

$base = Join-Path $WorkRoot (".orcel-e2e-tasks-" + [guid]::NewGuid().ToString("N").Substring(0, 12))
$state = Join-Path $base "state"
$workspace = Join-Path $base "ws"
New-Item -ItemType Directory -Force -Path $state, (Join-Path $workspace "data"), (Join-Path $workspace "reports") | Out-Null
[IO.File]::WriteAllText((Join-Path $workspace "data\q3.csv"), "region,quarter,revenue_cents`nnorth,Q3,1250000`nsouth,Q3,980050`n")
$instance = "e2etasks-" + [guid]::NewGuid().ToString("N").Substring(0, 12)
$title = "Q3 revenue e2e " + [guid]::NewGuid().ToString("N").Substring(0, 6)

$start = New-Object System.Diagnostics.ProcessStartInfo $Orceld
$start.UseShellExecute = $false
$start.RedirectStandardInput = $true
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.EnvironmentVariables["ORCEL_WORKSPACE_ROOT"] = $workspace
$start.EnvironmentVariables["ORCEL_WORKSPACE_ID"] = "default"
$start.EnvironmentVariables["ORCEL_APP_API_INSTANCE"] = $instance
$start.EnvironmentVariables["ORCEL_AUDIT_PATH"] = (Join-Path $state "audit\audit.jsonl")
$start.EnvironmentVariables["LOCALAPPDATA"] = $state
# Only the variables set above reach orceld: every other ORCEL_* setting of
# the caller is dropped.
$keep = @("ORCEL_WORKSPACE_ROOT", "ORCEL_WORKSPACE_ID", "ORCEL_APP_API_INSTANCE", "ORCEL_AUDIT_PATH")
foreach ($name in @($start.EnvironmentVariables.Keys)) { if ($name -like "ORCEL_*" -and $keep -notcontains $name) { $start.EnvironmentVariables.Remove($name) } }
# .NET Framework builds the child's stdin writer from Console.InputEncoding,
# whose UTF-8 preamble would precede the first JSON line; use one without.
$savedEncoding = [Console]::InputEncoding
[Console]::InputEncoding = New-Object System.Text.UTF8Encoding($false)
try { $daemon = [System.Diagnostics.Process]::Start($start) } finally { [Console]::InputEncoding = $savedEncoding }
# Drain stderr so orceld never blocks on a full pipe.
$stderr = $daemon.StandardError.ReadToEndAsync()
$requests = $daemon.StandardInput
$requests.NewLine = "`n"

function Report([string]$operation, [hashtable]$arguments, [int]$n) {
    $request = @{ version = 1; request_id = "e2e-tasks-$n"; client_session_id = "e2e-tasks"; workspace_id = "default";
        capability = "report"; operation = $operation; target = $null; arguments = $arguments } | ConvertTo-Json -Compress -Depth 5
    $requests.WriteLine($request)
    $requests.Flush()
    $pending = $daemon.StandardOutput.ReadLineAsync()
    if (-not $pending.Wait(15000)) { throw "orceld did not answer report/$operation within 15 s" }
    $line = $pending.Result
    if ($null -eq $line) { throw "orceld exited: $($stderr.Result)" }
    return $line | ConvertFrom-Json
}

$failed = $false
try {
    $started = Report "start" @{ title = $title; sources = @("data/q3.csv"); folder = "reports" } 1
    if (-not $started.ok) { throw "report/start failed: $($started | ConvertTo-Json -Compress -Depth 6)" }
    $taskId = $started.result.task_id
    Write-Output "PASS orceld started task $taskId"
    $preview = Report "preview" @{ task_id = $taskId; name = "q3.md"; content = "# Q3`n" } 2
    if (-not $preview.ok) { throw "report/preview failed: $($preview | ConvertTo-Json -Compress -Depth 6)" }
    Write-Output "PASS orceld previewed the report (no approval requested)"

    $second = Report "start" @{ title = "$title live"; sources = @("data/q3.csv"); folder = "reports" } 3
    if (-not $second.ok) { throw "report/start failed: $($second | ConvertTo-Json -Compress -Depth 6)" }
    $secondId = $second.result.task_id

    $signal = Join-Path $base "watching"
    $env:ORCEL_E2E_APP_API_INSTANCE = $instance
    $env:ORCEL_E2E_EXPECT_TASK_TITLE = "report proposed, waiting for approval: ""$title"""
    $env:ORCEL_E2E_LIVE_SIGNAL = $signal
    $env:ORCEL_E2E_EXPECT_LIVE_UPDATE = "Task ${secondId}: report proposed, waiting for approval."
    # This task's preview happens once the app is watching, so only a live
    # update can show it.
    $driver = Start-Job -ScriptBlock {
        param($Signal, $Deadline)
        while (-not (Test-Path $Signal) -and (Get-Date) -lt $Deadline) { Start-Sleep -Milliseconds 200 }
        Test-Path $Signal
    } -ArgumentList $signal, (Get-Date).AddMinutes(3)
    $app = Start-Process powershell.exe -PassThru -NoNewWindow -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "e2e.ps1"), "-BuildDirectory", $BuildDirectory)
    # Start-Process leaves ExitCode empty unless its handle was read first.
    $null = $app.Handle
    $ready = Receive-Job -Job $driver -Wait
    Remove-Job -Job $driver
    if (-not $ready) { throw "the app never reached its task view" }
    # Give its watcher a moment to be subscribed: a slow one still catches this
    # on its first read, but as history rather than news.
    Start-Sleep -Seconds 2
    $livePreview = Report "preview" @{ task_id = $secondId; name = "live.md"; content = "# Live`n" } 4
    if (-not $livePreview.ok) { throw "report/preview failed: $($livePreview | ConvertTo-Json -Compress -Depth 6)" }
    Write-Output "PASS orceld previewed a second report while the app watched"
    $app.WaitForExit()
    if ($app.ExitCode -ne 0) { $failed = $true }
} finally {
    Remove-Item Env:\ORCEL_E2E_APP_API_INSTANCE, Env:\ORCEL_E2E_EXPECT_TASK_TITLE, Env:\ORCEL_E2E_LIVE_SIGNAL, Env:\ORCEL_E2E_EXPECT_LIVE_UPDATE -ErrorAction SilentlyContinue
    try { $requests.Close() } catch { }
    if (-not $daemon.WaitForExit(5000)) { $daemon.Kill(); $daemon.WaitForExit() }
    $reports = @(Get-ChildItem (Join-Path $workspace "reports") -File)
    if ($reports.Count -ne 0) { Write-Output "FAIL a report file exists although nothing was approved: $($reports.Name -join ', ')"; $failed = $true }
    else { Write-Output "PASS nothing was written (no approval was requested)" }
    Remove-Item -Recurse -Force $base -ErrorAction SilentlyContinue
}
if ($failed) { exit 1 }
Write-Output "PASS: the Windows app shows a live orceld's report task read-only"
