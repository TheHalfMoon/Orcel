# Test the Windows-native foundation without performing computer actions.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $env:TEMP "OrcelDesktopPreviewBuild"
& (Join-Path $root "build.ps1") -OutputDirectory $outDir
if ($LASTEXITCODE -ne 0) { throw "Build failed" }
$smoke = Join-Path $outDir "Orcel.Smoke.exe"
$app = Join-Path $outDir "Orcel.Desktop.exe"
if (-not (Test-Path $app)) { throw "Missing desktop executable" }
& $smoke --self-test
if ($LASTEXITCODE -ne 0) { throw "Self-test failed" }
& $smoke --ui-self-test
if ($LASTEXITCODE -ne 0) { throw "WPF layout construction failed" }
if ((Get-Item $app).Length -ge 5MB) { throw "Preview binary exceeded its guard" }
$source = [IO.File]::ReadAllText((Join-Path $root "src\Program.cs"))
# A tripwire against obvious capability creep, not proof of absence.
foreach ($forbidden in @("WebClient", "HttpClient", "TcpClient", "HttpListener", "ProcessStartInfo(commandBox.Text)", "ProcessStartInfo(value)")) {
    if ($source.Contains($forbidden)) { throw "Forbidden capability: $forbidden" }
}
Write-Output "PASS: compiled WPF preview, command router (read-only plus the sizes-only preview setting), fixed runtime, size and no network API."
