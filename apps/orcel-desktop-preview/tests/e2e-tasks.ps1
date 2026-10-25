# SG-000127 slice 5 (timeline): the Windows app reads a live orceld's report
# tasks through the read-only app API. Starts a real orceld with an isolated
# app API instance, workspace and state, drives report/start and
# report/preview over its stdio channel (nothing reaches the approval
# broker, so no dialog can appear), then runs the UI Automation end-to-end
# test against that instance and requires the task to appear. The user's
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
foreach ($name in @("ORCEL_WORKSPACES_JSON", "ORCEL_MCP_TRANSPORT", "ORCEL_APP_API")) { $start.EnvironmentVariables.Remove($name) }
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
    $line = $daemon.StandardOutput.ReadLine()
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

    $env:ORCEL_E2E_APP_API_INSTANCE = $instance
    $env:ORCEL_E2E_EXPECT_TASK_TITLE = "$title"": report proposed, waiting for approval"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "e2e.ps1") -BuildDirectory $BuildDirectory
    if ($LASTEXITCODE -ne 0) { $failed = $true }
} finally {
    Remove-Item Env:\ORCEL_E2E_APP_API_INSTANCE, Env:\ORCEL_E2E_EXPECT_TASK_TITLE -ErrorAction SilentlyContinue
    try { $requests.Close() } catch { }
    if (-not $daemon.WaitForExit(5000)) { $daemon.Kill(); $daemon.WaitForExit() }
    $reports = @(Get-ChildItem (Join-Path $workspace "reports") -File)
    if ($reports.Count -ne 0) { Write-Output "FAIL a report file exists although nothing was approved: $($reports.Name -join ', ')"; $failed = $true }
    else { Write-Output "PASS nothing was written (no approval was requested)" }
    Remove-Item -Recurse -Force $base -ErrorAction SilentlyContinue
}
if ($failed) { exit 1 }
Write-Output "PASS: the Windows app shows a live orceld's report task read-only"
