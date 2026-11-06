# Build with Windows' existing .NET Framework C# compiler, offline. That compiler can't
# build reproducibly, so a release package passes -Deterministic and uses the Roslyn
# compiler of an installed .NET SDK, against the same Windows assemblies.
param(
    [string]$OutputDirectory = (Join-Path $env:TEMP "OrcelDesktopPreviewBuild"),
    [switch]$Deterministic
)
$ErrorActionPreference = "Stop"
$framework = Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319"
$csc = Join-Path $framework "csc.exe"
$wpf = Join-Path $framework "WPF"
$src = Join-Path $PSScriptRoot "src\Program.cs"
$refs = @(
    (Join-Path $wpf "PresentationFramework.dll"),
    (Join-Path $wpf "PresentationCore.dll"),
    (Join-Path $wpf "WindowsBase.dll"),
    (Join-Path $framework "System.Xaml.dll"),
    (Join-Path $framework "System.Windows.Forms.dll"),
    (Join-Path $framework "System.Core.dll"),
    (Join-Path $framework "System.Web.Extensions.dll")
)
foreach ($component in @($csc, $src) + $refs) {
    if (-not (Test-Path $component)) { throw "Required built-in Windows component missing: $component" }
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
foreach ($target in @("winexe", "exe")) {
    $name = if ($target -eq "winexe") { "Orcel.Desktop.exe" } else { "Orcel.Smoke.exe" }
    $out = Join-Path $OutputDirectory $name
    $compilerArgs = @("/nologo", "/target:$target", "/optimize+", "/platform:anycpu", "/out:$out")
    foreach ($reference in $refs) { $compilerArgs += "/reference:$reference" }
    $compilerArgs += $src
    if ($Deterministic) {
        # No build path inside, and every assembly named, so two builds match.
        $sdk = (& dotnet --list-sdks | Select-Object -Last 1)
        if (-not $sdk) { throw "-Deterministic needs an installed .NET SDK" }
        $roslyn = Join-Path ($sdk -replace '^(\S+) \[(.*)\]$', '$2\$1') "Roslyn\bincore\csc.dll"
        if (-not (Test-Path $roslyn)) { throw "The SDK's compiler is missing: $roslyn" }
        $compilerArgs = @("/noconfig", "/nostdlib+", "/deterministic", "/pathmap:$PSScriptRoot=.") + $compilerArgs
        foreach ($base in @("mscorlib.dll", "System.dll", "System.Xml.dll")) {
            $compilerArgs += "/reference:" + (Join-Path $framework $base)
        }
        & dotnet exec $roslyn @compilerArgs
    } else {
        & $csc @compilerArgs
    }
    if ($LASTEXITCODE -ne 0) { throw "Compilation failed for $target" }
}
$app = Join-Path $OutputDirectory "Orcel.Desktop.exe"
Write-Output ("Compiled: {0} ({1} bytes)" -f $app, (Get-Item $app).Length)
