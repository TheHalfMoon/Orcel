<#
.SYNOPSIS
  SG-000132 install E2E: runs the founder's installation procedure, with the runbook's exact command lines, on a
  disposable GitHub-hosted Windows runner, and writes a JSON report. CI ONLY.

.DESCRIPTION
  This script installs and uninstalls a Windows service, creates folders under Program Files and ProgramData,
  creates a temporary local standard user and plants hostile files in the runner account's profile. It refuses
  to run anywhere but a GitHub-hosted runner (GITHUB_ACTIONS=true, RUNNER_ENVIRONMENT=github-hosted), where the
  job runs as an administrator and the machine is discarded afterwards. Never run it on a PC.

  It takes the Stage, Install and Uninstall command lines from the `Start-Process` lines of
  docs/orcel/implementation-readiness/prep/SG132_INSTALL_RUNBOOK.md (only `/k` made `/c` and `--pause` removed,
  the <...> values filled in) and launches them the way an elevated launch from the founder's session would
  inherit its environment, made hostile: a planted PowerShell module in the account's Documents folder, a .NET
  profiler (COR_PROFILER) pointing at a canary DLL, and redirected PATH, SystemRoot, ProgramFiles and
  ProgramData. It checks staging, the refusals (nothing changed), rollback, a clean install, fail-closed grant
  and reset without Windows Hello, recovery, uninstall, the console-mode scripted grant and revoke tests, the
  pinned TPM root, and that neither canary ran. Every check is recorded; the script exits 1 if any failed.

.PARAMETER ArtifactDir
  Folder holding orcel-authority.exe, orceld.exe and orcel.exe (the artifact).

.PARAMETER ReportPath
  Where the JSON report is written.

.PARAMETER Commit
  The commit the artifact was built from.
#>
param(
  [Parameter(Mandatory = $true)][string]$ArtifactDir,
  [Parameter(Mandatory = $true)][string]$ReportPath,
  [Parameter(Mandatory = $true)][string]$Commit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted') {
  throw 'CI only: this script installs a service and creates a local user; it runs only on a disposable GitHub-hosted runner. Nothing was changed.'
}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'The hosted runner job is expected to run as an administrator.'
}

$System32 = 'C:\Windows\System32'
$Sc = "$System32\sc.exe"
$Icacls = "$System32\icacls.exe"
$RepoRoot = Split-Path -Parent $PSScriptRoot
$Runbook = Join-Path $RepoRoot 'docs\orcel\implementation-readiness\prep\SG132_INSTALL_RUNBOOK.md'
$Names = @('orcel-authority.exe', 'orceld.exe', 'orcel.exe')
$ServiceName = 'OrcelAuthority'
$Staging = 'C:\Program Files\OrcelStaging'
$StagedAuthority = Join-Path $Staging 'orcel-authority.exe'
$ProgramFilesOrcel = 'C:\Program Files\Orcel'
$InstalledOrceld = Join-Path $ProgramFilesOrcel 'orceld.exe'
$InstalledOrcel = Join-Path $ProgramFilesOrcel 'orcel.exe'
$ProgramDataOrcel = 'C:\ProgramData\Orcel'
$StateDir = Join-Path $ProgramDataOrcel 'authority'
$PublicKey = Join-Path $ProgramDataOrcel 'authority-public\lease-signing-key.json'
$EventKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel'
$OldBuildDir = 'C:\OrcelBuild'
$Download = Join-Path $env:RUNNER_TEMP 'orcel-download'
$Hostile = 'C:\OrcelE2EHostile'
$CanaryDir = 'C:\OrcelE2ECanary'

$Checks = New-Object System.Collections.ArrayList
$Report = [ordered]@{
  schema = 'orcel.authority-install-e2e/2'
  commit = $Commit
  run_url = "$env:GITHUB_SERVER_URL/$env:GITHUB_REPOSITORY/actions/runs/$env:GITHUB_RUN_ID"
  event = $env:GITHUB_EVENT_NAME
  ref = $env:GITHUB_REF
  artifact_source = $null
  runner = [ordered]@{
    os = (Get-CimInstance Win32_OperatingSystem).Caption
    version = [Environment]::OSVersion.Version.ToString()
    image = $env:ImageVersion
  }
  artifact_sha256 = [ordered]@{}
  uac = $null
  hostile_environment = $null
  tpm_root_2014 = $null
  console_scripted_grant = $null
  installed_service_status = $null
  reset_refused_by = $null
  not_verified = New-Object System.Collections.ArrayList
  founder_steps = @(
    'Windows Hello enrollment against a real TPM attestation (runbook step 10)',
    'An installed-service grant with the service-observed unlock, the confirmation box and real Windows Hello (step 11)',
    'An installed-service revoke of that lease (step 12) and a Browser Full Access grant (step 13)'
  )
  checks = $Checks
  result = 'fail'
}

function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
  [void]$Checks.Add([ordered]@{ name = $Name; status = $(if ($Ok) { 'pass' } else { 'fail' }); ok = $Ok; detail = $Detail })
  $mark = if ($Ok) { 'PASS' } else { 'FAIL' }
  Write-Host "[$mark] ${Name}: $Detail"
}

function NotVerified([string]$Name, [string]$Detail) {
  # Recorded and listed, never counted as a pass: the runner could not show it.
  [void]$Checks.Add([ordered]@{ name = $Name; status = 'not_verified'; ok = $true; detail = $Detail })
  [void]$Report.not_verified.Add("${Name}: $Detail")
  Write-Host "[NOT VERIFIED] ${Name}: $Detail"
}

function Get-Sha256Hex([string]$Path) {
  return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLowerInvariant()
}

function Invoke-Process([string]$File, [string]$Arguments, [int]$TimeoutSeconds = 300, [string]$WorkingDirectory = $RepoRoot, [hashtable]$Environment = @{}) {
  $info = New-Object System.Diagnostics.ProcessStartInfo -ArgumentList $File, $Arguments
  $info.UseShellExecute = $false
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardError = $true
  $info.CreateNoWindow = $true
  $info.WorkingDirectory = $WorkingDirectory
  foreach ($key in $Environment.Keys) { $info.EnvironmentVariables[$key] = $Environment[$key] }
  $process = [System.Diagnostics.Process]::Start($info)
  $stdout = $process.StandardOutput.ReadToEndAsync()
  $stderr = $process.StandardError.ReadToEndAsync()
  if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    $process.Kill()
    throw "$File $Arguments did not finish within $TimeoutSeconds seconds"
  }
  $process.WaitForExit()
  $text = $stdout.Result + $stderr.Result
  Write-Host "---- $File (exit $($process.ExitCode))"
  Write-Host $text
  return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $text; Stdout = $stdout.Result }
}

# ---- The runbook's command lines --------------------------------------------------------------------------

function Get-RunbookCommands {
  $commands = @()
  foreach ($line in (Get-Content -LiteralPath $Runbook)) {
    if ($line -notlike 'Start-Process -Verb RunAs *') { continue }
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($line, [ref]$null, [ref]$errors)
    if ($errors -and $errors.Count) { throw "The runbook line does not parse: $line" }
    $command = $ast.Find({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    $elements = @($command.CommandElements)
    $values = @{}
    for ($i = 0; $i -lt $elements.Count - 1; $i++) {
      if ($elements[$i] -is [System.Management.Automation.Language.CommandParameterAst]) {
        $next = $elements[$i + 1]
        if ($next -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $values[$elements[$i].ParameterName] = $next.Value }
      }
    }
    $commands += [pscustomobject]@{ FilePath = $values['FilePath']; Arguments = $values['ArgumentList'] }
  }
  return $commands
}

function Get-RunbookTableRows {
  $lines = Get-Content -LiteralPath $Runbook
  $start = [array]::IndexOf($lines, '| Step | Program location | Exact command line |')
  if ($start -lt 0) { return @() }
  $rows = @()
  for ($i = $start + 2; $i -lt $lines.Count -and $lines[$i].StartsWith('| '); $i++) { $rows += $lines[$i] }
  return $rows
}

function Select-Command($Commands, [scriptblock]$Where, [string]$What) {
  $found = @($Commands | Where-Object $Where)
  if ($found.Count -ne 1) { throw "The runbook has $($found.Count) $What lines; expected exactly one." }
  return $found[0]
}

function Invoke-Documented($Command, [hashtable]$Values, [hashtable]$Environment, [int]$TimeoutSeconds = 300) {
  # As the founder starts it, minus what only keeps a window open: /k becomes /c, --pause goes.
  $arguments = $Command.Arguments.Replace(' /k ', ' /c ').Replace(' --pause', '')
  foreach ($key in $Values.Keys) { $arguments = $arguments.Replace($key, $Values[$key]) }
  if ($arguments -match '<[a-z0-9-]+>') { throw "A placeholder is left in: $arguments" }
  return Invoke-Process $Command.FilePath $arguments $TimeoutSeconds 'C:\Windows\System32' $Environment
}

function Get-ExpectedStagingAcl {
  $lines = Get-Content -LiteralPath $Runbook
  $start = [array]::IndexOf($lines, '<!-- expected-staging-acl -->')
  if ($start -lt 0 -or $lines[$start + 1] -ne '```text') { throw 'The runbook lacks the expected staging ACL block.' }
  $out = @()
  for ($i = $start + 2; $i -lt $lines.Count -and $lines[$i] -ne '```'; $i++) { $out += $lines[$i] }
  return $out
}

function ConvertTo-Comparable([string[]]$Lines) {
  return @($Lines | ForEach-Object { ($_ -replace '\s+', ' ').Trim() } | Where-Object { $_ })
}

# ---- System state -----------------------------------------------------------------------------------------

function Get-ServiceSid {
  $text = (& $Sc showsid $ServiceName) -join ' '
  if ($text -match '(S-1-5-80(-\d+){5})') { return $Matches[1] }
  throw 'sc.exe showsid gave no SID'
}

function Get-Tree([string]$Path) {
  if (-not (Test-Path -LiteralPath $Path)) { return 'absent' }
  $items = @(Get-ChildItem -LiteralPath $Path -Recurse -Force | ForEach-Object { $_.FullName.Substring($Path.Length) } | Sort-Object)
  return 'present:' + ($items -join '|')
}

function Get-Snapshot {
  $state = [ordered]@{
    service = [bool](Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)
    program_files_orcel = Get-Tree $ProgramFilesOrcel
    program_data_orcel = Get-Tree $ProgramDataOrcel
    event_source = [bool](Test-Path -LiteralPath $EventKey)
  }
  return ($state | ConvertTo-Json -Compress)
}

function Test-ServiceProfileHandled([string]$Output) {
  # The virtual account's profile is removed, or the installer said it was left (Windows still holds it loaded).
  $sid = Get-ServiceSid
  $present = Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$sid"
  return [pscustomobject]@{ Ok = ((-not $present) -or ($Output -match 'PROFILE LEFT')); Detail = "profile present: $present" }
}

function Get-StagingFingerprint {
  if (-not (Test-Path -LiteralPath $Staging)) { return 'absent' }
  $files = @(Get-ChildItem -LiteralPath $Staging -Force | Sort-Object Name | ForEach-Object { "$($_.Name)=$(Get-Sha256Hex $_.FullName)" })
  return 'present:' + ($files -join '|')
}

function Wait-Running([int]$Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running') { return $true }
    try { Start-Service -Name $ServiceName -ErrorAction Stop } catch { Start-Sleep -Seconds 2 }
  }
  return $false
}

function Wait-Stopped([int]$Seconds = 60) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -eq 'Stopped') { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Get-AuthorityStatus {
  $run = Invoke-AsStandardUserProcess $InstalledOrceld 'authority-status' 60
  if ($run.ExitCode -ne 0) { return $null }
  $line = @($run.Stdout -split "`r?`n" | Where-Object { $_.TrimStart().StartsWith('{') }) | Select-Object -Last 1
  return ($line | ConvertFrom-Json)
}

function Get-OrcelEvents([int]$Id, [datetime]$Since) {
  $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Orcel'; Id = $Id; StartTime = $Since } -ErrorAction SilentlyContinue)
  return @($events | ForEach-Object { (@($_.Message) + @($_.Properties | ForEach-Object { $_.Value })) -join ' ' })
}

# ---- A hostile environment for the elevated steps -----------------------------------------------------------

function New-HostileEnvironment {
  # 1. A PowerShell module in the runner account's Documents folder that shadows the cmdlets an elevated
  #    PowerShell would autoload; each writes a canary file if it ever runs.
  # 2. A .NET profiler canary DLL: any .NET process started with COR_ENABLE_PROFILING=1 and
  #    COR_PROFILER_PATH pointing at it loads it, and its DllMain writes a canary file.
  # 3. PATH, SystemRoot, windir, ProgramFiles and ProgramData pointing at a user-writable decoy folder.
  # The COR_* values are also written to HKCU\Environment, where an elevated launch from the founder's session
  # would pick them up; the launched steps get the same values in their environment block here.
  New-Item -ItemType Directory -Force -Path $CanaryDir, $Hostile, (Join-Path $Hostile 'Program Files'), (Join-Path $Hostile 'ProgramData') | Out-Null
  & $Icacls $CanaryDir /grant '*S-1-1-0:(OI)(CI)M' | Out-Null
  & $Icacls $Hostile /grant '*S-1-1-0:(OI)(CI)M' | Out-Null

  $documents = [Environment]::GetFolderPath('MyDocuments')
  $moduleDir = Join-Path $documents 'WindowsPowerShell\Modules\OrcelE2ECanary'
  New-Item -ItemType Directory -Force -Path $moduleDir | Out-Null
  $functions = @('Join-Path', 'Get-FileHash', 'Get-Acl', 'Copy-Item', 'Test-Path', 'Get-Item')
  $body = ($functions | ForEach-Object { "function $_ { Set-Content -LiteralPath ('$CanaryDir\psmodule-$_-' + [System.Diagnostics.Process]::GetCurrentProcess().Id + '.txt') -Value 'ran' }" }) -join "`n"
  Set-Content -LiteralPath (Join-Path $moduleDir 'OrcelE2ECanary.psm1') -Encoding ascii -Value $body
  $exports = ($functions | ForEach-Object { "'$_'" }) -join ', '
  Set-Content -LiteralPath (Join-Path $moduleDir 'OrcelE2ECanary.psd1') -Encoding ascii -Value "@{ RootModule = 'OrcelE2ECanary.psm1'; ModuleVersion = '1.0'; GUID = '6a1f2f39-5a4e-4d3e-9a43-0c9b66e10001'; FunctionsToExport = @($exports) }"

  $source = Join-Path $Hostile 'canary.rs'
  Set-Content -LiteralPath $source -Encoding ascii -Value @'
#[no_mangle]
pub extern "system" fn DllMain(_module: *mut u8, reason: u32, _reserved: *mut u8) -> i32 {
    if reason == 1 {
        let path = format!("C:\\OrcelE2ECanary\\cor-profiler-loaded-{}.txt", std::process::id());
        let _ = std::fs::write(path, b"loaded");
    }
    1
}
'@
  $dll = Join-Path $Hostile 'canary.dll'
  $rustc = (Get-Command rustc.exe).Source
  $built = Invoke-Process $rustc "--crate-type cdylib -O -o `"$dll`" `"$source`"" 600 $Hostile
  if ($built.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $dll)) { throw 'the canary DLL did not build' }

  $profiler = '{6A1F2F39-5A4E-4D3E-9A43-0C9B66E10002}'
  foreach ($pair in @(@('COR_ENABLE_PROFILING', '1'), @('COR_PROFILER', $profiler), @('COR_PROFILER_PATH', $dll))) {
    [Environment]::SetEnvironmentVariable($pair[0], $pair[1], 'User')
  }
  $environment = @{
    COR_ENABLE_PROFILING = '1'
    COR_PROFILER = $profiler
    COR_PROFILER_PATH = $dll
    PSModulePath = "$documents\WindowsPowerShell\Modules;$env:PSModulePath"
    PATH = "$Hostile;$env:PATH"
    SystemRoot = $Hostile
    windir = $Hostile
    ProgramFiles = Join-Path $Hostile 'Program Files'
    ProgramW6432 = Join-Path $Hostile 'Program Files'
    ProgramData = Join-Path $Hostile 'ProgramData'
    ALLUSERSPROFILE = Join-Path $Hostile 'ProgramData'
  }

  # Positive control: a .NET PowerShell started with this environment runs both canaries.
  $control = Invoke-Process "$System32\WindowsPowerShell\v1.0\powershell.exe" '-NoProfile -NonInteractive -Command "Join-Path a b"' 120 $Hostile @{
    COR_ENABLE_PROFILING = '1'; COR_PROFILER = $profiler; COR_PROFILER_PATH = $dll; PSModulePath = $environment.PSModulePath
  }
  $profilerRan = @(Get-ChildItem -LiteralPath $CanaryDir -Filter 'cor-profiler-loaded-*.txt').Count -gt 0
  $moduleRan = @(Get-ChildItem -LiteralPath $CanaryDir -Filter 'psmodule-*.txt').Count -gt 0
  Check 'hostile environment armed: an elevated PowerShell started with it would run both canaries' ($profilerRan -and $moduleRan) "profiler canary loaded: $profilerRan; Documents module canary ran: $moduleRan; exit $($control.ExitCode)"
  Get-ChildItem -LiteralPath $CanaryDir -File | Remove-Item -Force
  $Report.hostile_environment = [ordered]@{ variables = $environment; documents_module = $moduleDir; canary_dll = $dll }
  return $environment
}

function Get-CanaryHits {
  return @(Get-ChildItem -LiteralPath $CanaryDir -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
}

# ---- A temporary local standard user ----------------------------------------------------------------------

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class OrcelE2ELogon {
  [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
  public static extern bool LogonUserW(string user, string domain, string password, int logonType, int provider, out IntPtr token);
}
'@

$UserName = 'orcele2e' + (Get-Random -Minimum 1000 -Maximum 9999)
$script:UserIdentity = $null

function New-StandardUser {
  $bytes = New-Object byte[] 24
  [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $password = [Convert]::ToBase64String($bytes) + 'a1!A'
  $secure = ConvertTo-SecureString -String $password -AsPlainText -Force
  New-LocalUser -Name $UserName -Password $secure -AccountNeverExpires -PasswordNeverExpires -Description 'Orcel install E2E standard user (temporary)' | Out-Null
  Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $UserName
  $token = [IntPtr]::Zero
  $logonType = 'interactive'
  if (-not [OrcelE2ELogon]::LogonUserW($UserName, '.', $password, 2, 0, [ref]$token)) {
    $logonType = 'network'
    if (-not [OrcelE2ELogon]::LogonUserW($UserName, '.', $password, 3, 0, [ref]$token)) {
      throw "LogonUser failed for the standard user: $([ComponentModel.Win32Exception]::new([Runtime.InteropServices.Marshal]::GetLastWin32Error()).Message)"
    }
  }
  $script:UserIdentity = New-Object System.Security.Principal.WindowsIdentity -ArgumentList $token
  $script:UserCredential = New-Object System.Management.Automation.PSCredential -ArgumentList $UserName, $secure
  # A folder the standard user's processes start in and write their output to.
  $script:UserIo = 'C:\OrcelE2EUserIo'
  New-Item -ItemType Directory -Path $script:UserIo -Force | Out-Null
  & $Icacls $script:UserIo /grant "${UserName}:(OI)(CI)M" | Out-Null
  $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.Name -like "*\$UserName" })
  $userPrincipal = New-Object Security.Principal.WindowsPrincipal($script:UserIdentity)
  Check 'standard user created' ((-not $admins.Count) -and -not $userPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) "$UserName, member of Users only, logon type $logonType"
}

function Invoke-AsStandardUserProcess([string]$File, [string]$Arguments, [int]$TimeoutSeconds = 120) {
  # A separate process with the standard user's interactive logon (CreateProcessWithLogonW): its token carries
  # INTERACTIVE, which the authority pipe requires; it is not elevated and not the console session's logon.
  $id = [guid]::NewGuid().ToString('N')
  $out = Join-Path $script:UserIo "$id.out"
  $err = Join-Path $script:UserIo "$id.err"
  $process = Start-Process -FilePath $File -ArgumentList $Arguments -Credential $script:UserCredential -WorkingDirectory $script:UserIo -RedirectStandardOutput $out -RedirectStandardError $err -PassThru -WindowStyle Hidden
  $null = $process.Handle  # keeps the handle, so ExitCode is available after the exit
  if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
    throw "$File $Arguments (as $UserName) did not finish within $TimeoutSeconds seconds"
  }
  $process.WaitForExit()
  $stdout = if (Test-Path -LiteralPath $out) { [IO.File]::ReadAllText($out) } else { '' }
  $stderr = if (Test-Path -LiteralPath $err) { [IO.File]::ReadAllText($err) } else { '' }
  Write-Host "---- $File $Arguments as $UserName (exit $($process.ExitCode))"
  Write-Host ($stdout + $stderr)
  return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $stdout + $stderr; Stdout = $stdout }
}

function Invoke-AsStandardUser([scriptblock]$Block) {
  $context = $script:UserIdentity.Impersonate()
  try { return (& $Block) } finally { $context.Undo() }
}

function Test-CanList([string]$Dir) { try { [void][IO.Directory]::GetFileSystemEntries($Dir); return $true } catch { return $false } }
function Test-CanRead([string]$File) { try { $s = [IO.File]::Open($File, 'Open', 'Read', 'ReadWrite'); $s.Dispose(); return $true } catch { return $false } }
function Test-CanOpenForWrite([string]$File) { try { $s = [IO.File]::Open($File, 'Open', 'Write', 'ReadWrite'); $s.Dispose(); return $true } catch { return $false } }
function Test-CanCreateFile([string]$Dir) {
  $path = Join-Path $Dir ('e2e-' + [guid]::NewGuid().ToString('N'))
  try { $s = [IO.File]::Open($path, 'CreateNew', 'Write', 'None'); $s.Dispose(); [IO.File]::Delete($path); return $true } catch { return $false }
}
function Test-CanCreateFolder([string]$Dir) {
  $path = Join-Path $Dir ('e2e-' + [guid]::NewGuid().ToString('N'))
  try { [void][IO.Directory]::CreateDirectory($path); [IO.Directory]::Delete($path); return $true } catch { return $false }
}
function Test-CanChangeAcl([string]$Path) {
  # Writes the object's own, unchanged DACL back: succeeds only with WRITE_DAC.
  try {
    $item = Get-Item -LiteralPath $Path -Force
    $acl = $item.GetAccessControl('Access')
    $acl.SetAccessRuleProtection($acl.AreAccessRulesProtected, $true)
    $item.SetAccessControl($acl)
    return $true
  } catch { return $false }
}

# ---- The run ----------------------------------------------------------------------------------------------

function Invoke-E2E {
  $expectedHashes = [ordered]@{}
  foreach ($name in $Names) {
    $path = Join-Path $ArtifactDir $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "The artifact lacks $name" }
    $expectedHashes[$name] = Get-Sha256Hex $path
  }
  $Report.artifact_sha256 = $expectedHashes
  $sums = Join-Path $ArtifactDir 'SHA256SUMS.txt'
  if (Test-Path -LiteralPath $sums) {
    $Report.artifact_source = 'the attested authority-artifact of this run (main)'
    $listed = Get-Content -LiteralPath $sums
    $agree = $true
    foreach ($name in $Names) { if ($listed -notcontains "$($expectedHashes[$name])  $name") { $agree = $false } }
    Check 'artifact SHA256SUMS.txt agrees' ($agree -and ($listed -contains "commit $Commit")) ($listed -join '; ')
  } else {
    $Report.artifact_source = 'built in this job the same way (not main: the attested artifact and its gh attestation verify step run only for main)'
    NotVerified 'attested artifact download' 'this run is not on main, so the attestation and its verification did not run; they first run on the push to main'
  }
  $values = @{
    '<download-folder>' = $Download
    '<authority-sha256>' = $expectedHashes['orcel-authority.exe']
    '<orceld-sha256>' = $expectedHashes['orceld.exe']
    '<orcel-sha256>' = $expectedHashes['orcel.exe']
  }

  $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
  $uac = [ordered]@{}
  foreach ($name in @('EnableLUA', 'ConsentPromptBehaviorAdmin', 'PromptOnSecureDesktop', 'FilterAdministratorToken')) {
    $value = (Get-ItemProperty -Path $uacKey -Name $name -ErrorAction SilentlyContinue)
    $uac[$name] = if ($value) { $value.$name } else { $null }
  }
  $uac['always_notify_on_secure_desktop'] = ($uac.EnableLUA -eq 1 -and $uac.ConsentPromptBehaviorAdmin -eq 2 -and $uac.PromptOnSecureDesktop -eq 1)
  $Report.uac = $uac

  # The runbook's lines: every table row has its Start-Process line, each names an absolute program.
  $commands = @(Get-RunbookCommands)
  $rows = @(Get-RunbookTableRows)
  $complete = ($commands.Count -eq 8) -and ($rows.Count -eq $commands.Count) -and (@($commands | Where-Object { -not $_.FilePath -or -not $_.Arguments -or -not [IO.Path]::IsPathRooted($_.FilePath) }).Count -eq 0)
  foreach ($command in $commands) {
    $exact = '`"' + $command.FilePath + '" ' + $command.Arguments + '`'
    if (@($rows | Where-Object { $_.Replace('\|', '|').Contains($exact) }).Count -ne 1) { $complete = $false }
  }
  $stage = Select-Command $commands { $_.Arguments -like '*mkdir "C:\Program Files\OrcelStaging"*' } 'Stage'
  $install = Select-Command $commands { $_.FilePath -eq $StagedAuthority -and $_.Arguments -like 'install *' } 'Install'
  $uninstall = Select-Command $commands { $_.Arguments -like '* uninstall && rmdir *' } 'Uninstall'
  Check 'runbook command lines found: 8 Start-Process lines, each matching its UAC table row' $complete "$($commands.Count) lines, $($rows.Count) table rows"
  Check 'the elevated steps start no PowerShell and no .NET program' (-not (@($stage, $install, $uninstall) | Where-Object { ($_.FilePath + ' ' + $_.Arguments) -match 'powershell|pwsh|\.ps1' })) 'Stage and Uninstall: cmd.exe with System32 tools; Install: the staged native binary'

  # Clean baseline.
  $baseline = Get-Snapshot
  $clean = (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) -and -not (Test-Path -LiteralPath $ProgramFilesOrcel) -and -not (Test-Path -LiteralPath $ProgramDataOrcel) -and -not (Test-Path -LiteralPath $Staging) -and -not (Test-Path -LiteralPath $EventKey)
  Check 'runner starts clean' $clean $baseline
  if (-not $clean) { throw 'The runner is not clean; nothing more is meaningful.' }

  New-Item -ItemType Directory -Path $Download -Force | Out-Null
  foreach ($name in $Names) { Copy-Item -LiteralPath (Join-Path $ArtifactDir $name) -Destination $Download }
  New-StandardUser
  # Commands this process uses later are loaded now, before the hostile module exists.
  Get-Acl -LiteralPath 'C:\' | Out-Null
  $hostileEnv = New-HostileEnvironment

  # ---- The old procedure's flaw: mkdir C:\OrcelBuild as an administrator.
  New-Item -ItemType Directory -Path $OldBuildDir | Out-Null
  $inheritedWritable = Invoke-AsStandardUser { Test-CanCreateFile $OldBuildDir }
  Check 'old flaw reproduced: a folder made by an administrator under C:\ is writable by a standard user' $inheritedWritable "$OldBuildDir created with New-Item (as mkdir does); standard user can create files: $inheritedWritable"
  foreach ($name in $Names) { Copy-Item -LiteralPath (Join-Path $ArtifactDir $name) -Destination $OldBuildDir }
  $replaceable = Invoke-AsStandardUser { Test-CanOpenForWrite (Join-Path $OldBuildDir 'orcel-authority.exe') }
  Check 'old flaw: the standard user can overwrite a binary an elevated step would run' $replaceable "$OldBuildDir\orcel-authority.exe open for write as the standard user: $replaceable"
  $hashArgs = "--authority-sha256 $($values['<authority-sha256>']) --orceld-sha256 $($values['<orceld-sha256>']) --orcel-sha256 $($values['<orcel-sha256>'])"
  $before = Get-Snapshot
  $run = Invoke-Process (Join-Path $OldBuildDir 'orcel-authority.exe') "install $hashArgs" 120 'C:\Windows\System32' $hostileEnv
  Check 'the installer refuses to run from anywhere but the staging folder, nothing changed' (($run.ExitCode -ne 0) -and ($run.Output -match 'Nothing was changed') -and ($run.Output -match 'refused:') -and ((Get-Snapshot) -eq $before)) "exit $($run.ExitCode)"

  # ---- Stage, with a wrong hash first.
  $wrong = $values.Clone()
  $wrong['<orcel-sha256>'] = '0' * 64
  $run = Invoke-Documented $stage $wrong $hostileEnv
  Check 'Stage refuses a binary with another SHA-256 and removes the staging folder' (($run.ExitCode -ne 0) -and ($run.Output -match 'STAGING REFUSED') -and -not (Test-Path -LiteralPath $Staging)) "exit $($run.ExitCode)"

  $run = Invoke-Documented $stage $values $hostileEnv
  $staged = Get-StagingFingerprint
  $wantStaged = 'present:' + (($Names | Sort-Object | ForEach-Object { "$_=$($expectedHashes[$_])" }) -join '|')
  Check 'Stage (runbook line) stages exactly the three verified files' (($run.ExitCode -eq 0) -and ($run.Output -match 'STAGED:') -and ($staged -eq $wantStaged)) "exit $($run.ExitCode); $staged"

  $actual = @()
  $actual += @(& $Icacls $Staging)
  $actual += @(& $Icacls (Join-Path $Staging '*'))
  $actual += @(Get-ChildItem -Force -LiteralPath $Staging | ForEach-Object { '{0} {1}' -f $_.Name, (Get-Acl -LiteralPath $_.FullName).Owner })
  $actual += @(Get-Acl -LiteralPath $Staging | ForEach-Object { '{0} protected={1}' -f $_.Owner, $_.AreAccessRulesProtected })
  $want = ConvertTo-Comparable (Get-ExpectedStagingAcl)
  $have = ConvertTo-Comparable $actual
  Check 'staging ACL equals the runbook''s expected icacls output' (($want -join "`n") -eq ($have -join "`n")) ($have -join ' / ')

  $userView = Invoke-AsStandardUser {
    [ordered]@{
      read_binary = Test-CanRead $StagedAuthority
      create_file = Test-CanCreateFile $Staging
      create_folder = Test-CanCreateFolder $Staging
      change_folder_acl = Test-CanChangeAcl $Staging
      write_any_staged_file = @($Names | Where-Object { Test-CanOpenForWrite (Join-Path $Staging $_) }).Count -gt 0
      change_any_staged_acl = @($Names | Where-Object { Test-CanChangeAcl (Join-Path $Staging $_) }).Count -gt 0
    }
  }
  Check 'standard user can read but not change the staging folder or any staged file' ($userView.read_binary -and -not ($userView.create_file -or $userView.create_folder -or $userView.change_folder_acl -or $userView.write_any_staged_file -or $userView.change_any_staged_acl)) ($userView | ConvertTo-Json -Compress)

  $run = Invoke-Documented $stage $values $hostileEnv
  Check 'Stage refuses an existing staging folder and changes nothing' (($run.ExitCode -ne 0) -and ($run.Output -match 'already exists') -and ((Get-StagingFingerprint) -eq $wantStaged)) "exit $($run.ExitCode)"

  # ---- Failed installs: nothing changed.
  $run = Invoke-Process $StagedAuthority "install --authority-sha256 $('0' * 64) --orceld-sha256 $($values['<orceld-sha256>']) --orcel-sha256 $($values['<orcel-sha256>'])" 120 'C:\Windows\System32' $hostileEnv
  Check 'failed install: wrong hash refused, nothing changed' (($run.ExitCode -ne 0) -and ($run.Output -match 'SHA-256 mismatch') -and ((Get-Snapshot) -eq $baseline)) "exit $($run.ExitCode)"

  $planted = Join-Path $Staging 'version.dll'
  Set-Content -LiteralPath $planted -Value 'not a DLL' -Encoding ascii
  $run = Invoke-Process $StagedAuthority "install $hashArgs" 120 'C:\Windows\System32' $hostileEnv
  Remove-Item -LiteralPath $planted -Force
  Check 'failed install: an extra file in the staging folder is refused, nothing changed' (($run.ExitCode -ne 0) -and ($run.Output -match 'unexpected entry') -and ((Get-Snapshot) -eq $baseline)) "exit $($run.ExitCode)"

  New-Item -ItemType Directory -Path $StateDir -Force | Out-Null
  $before = Get-Snapshot
  $run = Invoke-Process $StagedAuthority "install $hashArgs" 120 'C:\Windows\System32' $hostileEnv
  Check 'failed install: pre-existing state directory refused, nothing changed' (($run.ExitCode -ne 0) -and ($run.Output -match 'already exists') -and ((Get-Snapshot) -eq $before)) "exit $($run.ExitCode)"
  Remove-Item -LiteralPath $ProgramDataOrcel -Recurse -Force
  Check 'pre-existing state directory removed again' ((Get-Snapshot) -eq $baseline) ''

  # ---- Rollback: a pre-created pipe name makes the service start fail after every other change.
  $holderScript = Join-Path $env:RUNNER_TEMP 'hold-authority-pipe.ps1'
  Set-Content -LiteralPath $holderScript -Encoding ascii -Value '$pipe = New-Object System.IO.Pipes.NamedPipeServerStream(''orcel-authority''); Start-Sleep -Seconds 900'
  $holder = Start-Process -FilePath "$System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$holderScript`"" -PassThru -WindowStyle Hidden
  $deadline = (Get-Date).AddSeconds(30)
  while (-not ([IO.Directory]::GetFiles('\\.\pipe\') -contains '\\.\pipe\orcel-authority') -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
  $run = Invoke-Documented $install $values $hostileEnv
  $afterRollback = Get-Snapshot
  Stop-Process -Id $holder.Id -Force -ErrorAction SilentlyContinue
  Check 'rollback: install failing at its last step undoes every change' (($run.ExitCode -ne 0) -and ($run.Output -match 'Created the service') -and ($run.Output -match 'every change it made was rolled back') -and ($afterRollback -eq $baseline)) "exit $($run.ExitCode); after: $afterRollback"
  $profileState = Test-ServiceProfileHandled $run.Output
  Check 'rollback: the virtual account profile removed, or reported as left' $profileState.Ok $profileState.Detail

  # ---- Clean install with the runbook's line (hostile environment).
  $installedAt = Get-Date
  $run = Invoke-Documented $install $values $hostileEnv
  $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  Check 'clean install (runbook line) succeeds; service running, automatic' (($run.ExitCode -eq 0) -and $service -and $service.Status -eq 'Running' -and $service.StartType -eq 'Automatic') "exit $($run.ExitCode)"
  $decoys = @(Get-ChildItem -LiteralPath $Hostile -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName.Substring($Hostile.Length) -match 'Orcel' })
  Check 'the install ignored the redirected ProgramFiles/ProgramData/SystemRoot: nothing landed in the decoy folders' ($decoys.Count -eq 0 -and (Test-Path -LiteralPath $StateDir) -and (Test-Path -LiteralPath $InstalledOrcel)) "decoy entries: $(@($decoys | ForEach-Object { $_.FullName }) -join ', ')"
  $qc = (& $Sc qc $ServiceName) -join ' '
  $sidType = (& $Sc qsidtype $ServiceName) -join ' '
  $privs = (& $Sc qprivs $ServiceName) -join ' '
  $failure = (& $Sc qfailure $ServiceName) -join ' '
  Check 'service account, SID type, privileges and failure actions' (($qc -match 'NT SERVICE\\OrcelAuthority') -and ($qc -match 'AUTO_START') -and ($sidType -match 'UNRESTRICTED') -and ($privs -match 'SeChangeNotifyPrivilege') -and ($privs -match 'SeImpersonatePrivilege') -and ($privs -match 'SeCreateGlobalPrivilege') -and ($failure -match 'RESTART')) "$sidType; $privs; $failure"
  $eventMessages = (Get-ItemProperty -Path $EventKey -Name 'EventMessageFile' -ErrorAction SilentlyContinue).EventMessageFile
  Check 'Event Log source registered with an absolute message file under the real Windows folder' ($eventMessages -like 'C:\Windows\*') "$eventMessages"
  $installed = @(@('orcel-authority.exe', (Join-Path $ProgramFilesOrcel 'Authority\orcel-authority.exe')), @('orceld.exe', $InstalledOrceld), @('orcel.exe', $InstalledOrcel))
  $same = @($installed | Where-Object { (Get-Sha256Hex $_[1]) -ne $expectedHashes[$_[0]] }).Count -eq 0
  Check 'installed binaries are the artifact bytes' $same ''

  $stateAcl = Get-Acl -LiteralPath $StateDir
  $stateSids = @($stateAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value } | Sort-Object -Unique)
  $serviceSid = Get-ServiceSid
  $wantSids = @('S-1-5-18', 'S-1-5-32-544', $serviceSid) | Sort-Object
  Check 'state directory: owner Administrators, protected, SYSTEM/Administrators/service only' (($stateAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -eq 'S-1-5-32-544') -and $stateAcl.AreAccessRulesProtected -and (($stateSids -join ',') -eq ($wantSids -join ','))) ($stateSids -join ',')

  $stateFiles = @(Get-ChildItem -LiteralPath $StateDir -Force -File | ForEach-Object { $_.FullName })
  $access = Invoke-AsStandardUser {
    [ordered]@{
      list_state = Test-CanList $StateDir
      readable_state_files = @($stateFiles | Where-Object { Test-CanRead $_ } | ForEach-Object { Split-Path -Leaf $_ })
      read_public_key = Test-CanRead $PublicKey
      create_in_program_files_orcel = Test-CanCreateFile $ProgramFilesOrcel
      write_installed_orcel = Test-CanOpenForWrite $InstalledOrcel
      write_installed_orceld = Test-CanOpenForWrite $InstalledOrceld
      create_in_program_data_orcel = Test-CanCreateFile $ProgramDataOrcel
    }
  }
  $stateNames = @($stateFiles | ForEach-Object { Split-Path -Leaf $_ })
  Check 'state directory and files unreadable for a standard user' ((-not $access.list_state) -and @($access.readable_state_files).Count -eq 0 -and ($stateNames -contains 'config.json') -and ($stateNames -contains 'lease-signing.key')) "state files: $($stateNames -join ','); readable by the user: $(@($access.readable_state_files) -join ',')"
  Check 'public key readable for a standard user' $access.read_public_key $PublicKey
  Check 'installed binaries and folders not writable for a standard user' (-not ($access.create_in_program_files_orcel -or $access.write_installed_orcel -or $access.write_installed_orceld -or $access.create_in_program_data_orcel)) ($access | ConvertTo-Json -Compress)

  $status = Get-AuthorityStatus
  Check 'orceld authority-status (standard user): service mode with a key id' ($status -and $status.mode -eq 'service' -and $status.key_id) $(if ($status) { "key_id $($status.key_id), epoch $($status.epoch)" } else { 'no status' })
  $anchors = @(Get-OrcelEvents 4100 $installedAt)
  Check 'Event Log: anchor event 4100 written by the service' ($anchors.Count -gt 0) "$($anchors.Count) event(s)"

  # ---- Fail closed without Windows Hello, for two callers: the runner's job process (the elevated
  # administrator of the active console session, so it reaches the service's own gates) and the standard user
  # (an interactive logon, not elevated, not the console session).
  $callers = [ordered]@{
    'elevated administrator (console session)' = { param($exe, $arguments) Invoke-Process $exe $arguments 60 }
    'standard user' = { param($exe, $arguments) Invoke-AsStandardUserProcess $exe $arguments 60 }
  }
  $Report.installed_service_status = [ordered]@{}
  $Report.reset_refused_by = [ordered]@{}
  foreach ($caller in $callers.Keys) {
    $invoke = $callers[$caller]
    $statusRun = & $invoke $InstalledOrcel 'authority status --json'
    $cli = $null
    try { $cli = ($statusRun.Stdout | ConvertFrom-Json).authority } catch { $cli = $null }
    $Report.installed_service_status[$caller] = $cli
    Check "${caller}: orcel authority status reaches the service; no key enrolled, nothing can be issued" ($cli -and $cli.mode -eq 'service' -and $cli.caller_enrolled -eq $false -and $cli.can_issue -eq $false) $(if ($cli) { "role $($cli.caller_role), elevated $($cli.caller_elevated), owner CLI $($cli.caller_is_owner_cli), enrollment_available $($cli.enrollment_available), uac_always_notify $($cli.uac_always_notify_on_secure_desktop)" } else { 'no status' })
    $epochBefore = if ($cli) { $cli.epoch } else { $null }

    $grant = & $invoke $InstalledOrcel 'full-control grant'
    Check "${caller}: grant refused without an enrolled Windows Hello key (fail closed)" (($grant.ExitCode -ne 0) -and ($grant.Output -match 'no Windows Hello key')) "exit $($grant.ExitCode)"

    $reset = & $invoke $InstalledOrcel 'authority reset'
    $by = switch -Regex ($reset.Output) {
      'UAC set to Always notify' { 'the service: UAC is not Always notify on the secure desktop'; break }
      'interactive logon' { 'the service: no interactive logon in the active console session'; break }
      'no key is enrolled' { 'the service: no key is enrolled'; break }
      'elevated' { 'the CLI: not elevated'; break }
      default { $null }
    }
    $Report.reset_refused_by[$caller] = $by
    Check "${caller}: enrollment-class request (reset) refused" (($reset.ExitCode -ne 0) -and $by) "exit $($reset.ExitCode); refused by $by"
    if ($caller -like 'elevated*' -and $cli -and $cli.caller_role -eq 'interactive' -and $cli.caller_elevated -eq $true -and $uac.always_notify_on_secure_desktop -eq $false) {
      # The elevated owner CLI in the console session passes every earlier gate, so the service's UAC gate decides.
      Check 'installed service refuses enrollment-class requests because UAC is not Always notify' ($by -eq 'the service: UAC is not Always notify on the secure desktop') ("runner UAC " + ($uac | ConvertTo-Json -Compress))
    }

    if ($cli -and $cli.enrollment_available -ne $true) {
      $enroll = & $invoke $InstalledOrcel 'authority enroll'
      Check "${caller}: enroll refused (no pinned TPM root here, or not elevated)" (($enroll.ExitCode -ne 0) -and ($enroll.Output -match 'enrollment is refused|elevated')) "exit $($enroll.ExitCode)"
    } else {
      NotVerified "${caller}: enroll" 'enrollment is available on this runner and enroll would open Windows Hello, so it was not attempted'
    }

    $after = & $invoke $InstalledOrcel 'authority status --json'
    $cliAfter = $null
    try { $cliAfter = ($after.Stdout | ConvertFrom-Json).authority } catch { $cliAfter = $null }
    Check "${caller}: after the refusals still no enrolled key, epoch unchanged" ($cliAfter -and $cliAfter.caller_enrolled -eq $false -and $cliAfter.epoch -eq $epochBefore) $(if ($cliAfter) { "epoch $($cliAfter.epoch)" } else { 'no status' })
  }

  # ---- Recovery.
  $keyId = if ($status) { $status.key_id } else { $null }
  Restart-Service -Name $ServiceName
  $restarted = Wait-Running 60
  $status2 = Get-AuthorityStatus
  Check 'recovery: a restart keeps key_id (DPAPI under the virtual account)' ($restarted -and $status2 -and $status2.key_id -eq $keyId) $(if ($status2) { "key_id $($status2.key_id)" } else { 'no status' })

  Stop-Service -Name $ServiceName -Force
  [void](Wait-Stopped 60)
  $key = Join-Path $StateDir 'lease-signing.key'
  $aside = Join-Path $StateDir 'lease-signing.key.e2e-aside'
  Rename-Item -LiteralPath $key -NewName (Split-Path -Leaf $aside)
  $refusedAt = (Get-Date).AddSeconds(-1)
  try { Start-Service -Name $ServiceName -ErrorAction Stop } catch { Write-Host "Start-Service failed as expected: $($_.Exception.Message)" }
  Start-Sleep -Seconds 5
  $runningWithoutKey = (Get-Service -Name $ServiceName).Status -eq 'Running'
  $refusals = @(Get-OrcelEvents 4103 $refusedAt | Where-Object { $_ -match 'refused-start' })
  Check 'recovery: a missing key with audit history refuses the start (event 4103)' ((-not $runningWithoutKey) -and $refusals.Count -gt 0 -and -not (Test-Path -LiteralPath $key)) "running: $runningWithoutKey; 4103: $($refusals -join ' | ')"
  [void](Wait-Stopped 30)
  Rename-Item -LiteralPath $aside -NewName 'lease-signing.key'
  $back = Wait-Running 90
  $status3 = Get-AuthorityStatus
  Check 'recovery: with the key back the service starts with the same key_id' ($back -and $status3 -and $status3.key_id -eq $keyId) $(if ($status3) { "key_id $($status3.key_id)" } else { 'no status' })

  # ---- Console-mode scripted grant and revoke (test feature only), and the TPM root.
  $marker = Join-Path $env:RUNNER_TEMP 'scripted-grant-marker.txt'
  $cargo = (Get-Command cargo.exe).Source
  $tests = Invoke-Process $cargo 'test --locked -p orcel-authority --features authority-scripted-consent --test console_harness -- --test-threads=1' 2400 $RepoRoot @{ ORCEL_E2E_SCRIPTED_GRANT_MARKER = $marker }
  $outcome = if (Test-Path -LiteralPath $marker) { (Get-Content -LiteralPath $marker -Raw).Trim() } else { 'no outcome recorded' }
  $Report.console_scripted_grant = $outcome
  Check 'console-mode scripted-consent tests pass' (($tests.ExitCode -eq 0) -and ($outcome -match '^(ran|skipped):')) $outcome
  if ($outcome -notmatch '^ran:') { NotVerified 'console-mode scripted grant and revoke' $outcome }

  $tpm = Invoke-Process $cargo 'test --locked -p orcel-authority --lib tpm_root -- --nocapture --test-threads=1' 1800
  $line = if ($tpm.Output -match 'TPM-ROOT-2014: [^\r\n]*') { $Matches[0] } else { $null }
  $Report.tpm_root_2014 = $line
  Check 'TPM root tests pass (a lookalike root with the same name is refused)' (($tpm.ExitCode -eq 0) -and $line) "$line"
  if ($line -match 'absent') {
    NotVerified 'pinned TPM root equals the certificate on this machine' 'the Microsoft TPM Root Certificate Authority 2014 is not in this runner''s stores; the founder checks it (runbook step 9)'
  }

  # ---- Uninstall with the runbook's line (hostile environment).
  $run = Invoke-Documented $uninstall $values $hostileEnv
  $final = Get-Snapshot
  Check 'uninstall (runbook line) reverses every change and removes the staging' (($run.ExitCode -eq 0) -and ($final -eq $baseline) -and -not (Test-Path -LiteralPath $Staging)) "exit $($run.ExitCode); after: $final"
  $profileState = Test-ServiceProfileHandled $run.Output
  Check 'uninstall: the virtual account profile removed, or reported as left' $profileState.Ok $profileState.Detail

  $hits = @(Get-CanaryHits)
  Check 'no planted module and no profiler DLL ran in any elevated step' ($hits.Count -eq 0) "canary files: $($hits -join ', ')"
}

try {
  Invoke-E2E
} catch {
  Check 'the E2E ran to the end' $false "$($_.Exception.Message) at $($_.InvocationInfo.PositionMessage)"
} finally {
  try { Remove-LocalUser -Name $UserName -ErrorAction SilentlyContinue } catch { Write-Host "Could not remove $UserName (the runner is discarded)." }
  foreach ($name in @('COR_ENABLE_PROFILING', 'COR_PROFILER', 'COR_PROFILER_PATH')) { [Environment]::SetEnvironmentVariable($name, $null, 'User') }
  $failed = @($Checks | Where-Object { $_.status -eq 'fail' })
  $Report.result = if ($failed.Count -eq 0 -and $Checks.Count -gt 0) { 'pass' } else { 'fail' }
  New-Item -ItemType Directory -Path (Split-Path -Parent $ReportPath) -Force | Out-Null
  [IO.File]::WriteAllText($ReportPath, ($Report | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
  Write-Host "Report: $ReportPath (result $($Report.result), $($Checks.Count) checks, $($failed.Count) failed, $($Report.not_verified.Count) not verified)"
  foreach ($item in $Report.not_verified) { Write-Host "  not verified: $item" }
}
if ($Report.result -ne 'pass') { exit 1 }
exit 0
