<#
.SYNOPSIS
  Installs or uninstalls the Orcel authority service (SG-000132 slice 1).

.DESCRIPTION
  The FOUNDER runs this script, elevated, on the PC that will run Orcel.
  Agents never run it. Read docs/orcel/implementation-readiness/prep/SG132_INSTALL_RUNBOOK.md first.
  Run with -WhatIf to see every change without making any.

  Install makes exactly these system changes:
    1. Copies orcel-authority.exe to %ProgramFiles%\Orcel\Authority\ (admin-only write, so no user process can
       replace the service binary).
    2. Registers the service with the SCM: name OrcelAuthority, display name "Orcel Authority", own process,
       automatic start, account NT SERVICE\OrcelAuthority (a virtual account; no password), service SID type
       unrestricted, required privileges SeChangeNotifyPrivilege, SeImpersonatePrivilege and
       SeCreateGlobalPrivilege only, restart on failure.
    3. Creates %ProgramData%\Orcel (only if missing) owned by Administrators with a protected DACL: SYSTEM and
       Administrators full control, Users read and execute. An existing %ProgramData%\Orcel is not changed; the
       script stops if users could add, delete or rename entries in it.
    4. Creates %ProgramData%\Orcel\authority owned by Administrators with a protected DACL: SYSTEM,
       Administrators and NT SERVICE\OrcelAuthority full control, nobody else. Users cannot read it.
       Writes config.json there (the trusted orceld image path).
    5. Creates %ProgramData%\Orcel\authority-public owned by Administrators with a protected DACL: SYSTEM and
       Administrators full control, NT SERVICE\OrcelAuthority modify, Users read and execute (the published
       lease-signing public key).
    6. Registers the Event Log source "Orcel" in the Application log
       (HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel) unless it already exists, marked as
       created by this script.
    7. Starts the service.

  Uninstall (-Uninstall) reverses them: stops and deletes the service, removes the Event Log source if this
  script created it, deletes %ProgramFiles%\Orcel\Authority, %ProgramData%\Orcel\authority-public and (unless
  -KeepState) %ProgramData%\Orcel\authority, and deletes %ProgramData%\Orcel if it is then empty and this script
  created it.

.PARAMETER BinaryDir
  Directory holding the built orcel-authority.exe (default: <repo>\target\release).

.PARAMETER OrceldPath
  The orceld.exe image the service trusts for Authorize (default: <BinaryDir>\orceld.exe).

.PARAMETER Uninstall
  Remove everything Install made.

.PARAMETER KeepState
  With -Uninstall: keep %ProgramData%\Orcel\authority (the audit chain, leases and signing key).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$BinaryDir,
  [string]$OrceldPath,
  [switch]$Uninstall,
  [switch]$KeepState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'OrcelAuthority'
$ServiceAccount = 'NT SERVICE\OrcelAuthority'
$DisplayName = 'Orcel Authority'
$Description = 'Orcel Full Control authority (SG-000132): holds the lease-signing key, leases, epoch and audit outside the user session. It never elevates anything.'
$ProgramFilesDir = Join-Path $env:ProgramFiles 'Orcel\Authority'
$ProgramDataOrcel = Join-Path $env:ProgramData 'Orcel'
$StateDir = Join-Path $ProgramDataOrcel 'authority'
$PublicDir = Join-Path $ProgramDataOrcel 'authority-public'
$EventKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel'
$Marker = 'install-orcel-authority.ps1'
$OrcelDirMarker = Join-Path $ProgramDataOrcel '.created-by-install-orcel-authority'

function Assert-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated PowerShell (Run as administrator). Nothing was changed.'
  }
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
  Write-Host ">> $File $($Arguments -join ' ')"
  & $File @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
}

function Get-OwnerSid([string]$Path) {
  $acl = Get-Acl -LiteralPath $Path
  return ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Test-UsersCanChangeEntries([string]$Path) {
  # True when anyone other than SYSTEM, Administrators or TrustedInstaller may add, delete or rename entries.
  $privileged = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
  $change = [Security.AccessControl.FileSystemRights]'CreateFiles, AppendData, DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership'
  $acl = Get-Acl -LiteralPath $Path
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne 'Allow') { continue }
    $sid = $null
    try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = $rule.IdentityReference.Value }
    if ($privileged -contains $sid) { continue }
    if (($rule.FileSystemRights -band $change) -ne 0) { return $true }
  }
  return $false
}

function Set-ProtectedAcl([string]$Path, [string[]]$Grants) {
  Invoke-Checked 'icacls.exe' @($Path, '/setowner', '*S-1-5-32-544', '/q')
  Invoke-Checked 'icacls.exe' (@($Path, '/inheritance:r', '/q') + ($Grants | ForEach-Object { @('/grant:r', $_) }))
}

function Install-Authority {
  Assert-Elevated
  $repo = Split-Path -Parent $PSScriptRoot
  if (-not $BinaryDir) { $BinaryDir = Join-Path $repo 'target\release' }
  $binary = Join-Path $BinaryDir 'orcel-authority.exe'
  if (-not (Test-Path -LiteralPath $binary)) { throw "No $binary. Build it first: cargo build --release -p orcel-authority" }
  if (-not $OrceldPath) { $OrceldPath = Join-Path $BinaryDir 'orceld.exe' }
  $OrceldPath = [IO.Path]::GetFullPath($OrceldPath)
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "The service $ServiceName already exists. Run with -Uninstall first. Nothing was changed."
  }
  foreach ($dir in @($StateDir, $PublicDir)) {
    if (Test-Path -LiteralPath $dir) {
      throw "$dir already exists. Someone may have pre-created it; inspect and remove it (or run -Uninstall). Nothing was changed."
    }
  }
  if (Test-Path -LiteralPath $ProgramDataOrcel) {
    $owner = Get-OwnerSid $ProgramDataOrcel
    if (@('S-1-5-18', 'S-1-5-32-544') -notcontains $owner) {
      throw "$ProgramDataOrcel is owned by $owner, not SYSTEM or Administrators. Inspect and remove it first. Nothing was changed."
    }
    if (Test-UsersCanChangeEntries $ProgramDataOrcel) {
      throw "$ProgramDataOrcel lets non-administrators add, delete or rename entries, so the state directory could be swapped. Fix its ACL or remove it first. Nothing was changed."
    }
  }

  Write-Host 'Planned system changes:'
  Write-Host "  copy $binary -> $ProgramFilesDir"
  Write-Host "  SCM: create $ServiceName ($DisplayName) as $ServiceAccount, automatic start, SID type unrestricted"
  Write-Host "  directories with protected ACLs: $StateDir (no user access), $PublicDir (users read)"
  Write-Host "  Event Log source Orcel (Application) unless present; trusted orceld image: $OrceldPath"

  if ($PSCmdlet.ShouldProcess($ProgramFilesDir, 'Copy orcel-authority.exe')) {
    New-Item -ItemType Directory -Force -Path $ProgramFilesDir | Out-Null
    Copy-Item -LiteralPath $binary -Destination (Join-Path $ProgramFilesDir 'orcel-authority.exe') -Force
  }
  $serviceBinary = Join-Path $ProgramFilesDir 'orcel-authority.exe'

  if ($PSCmdlet.ShouldProcess($ServiceName, 'Register the service with the SCM')) {
    Invoke-Checked 'sc.exe' @('create', $ServiceName, 'binPath=', "`"$serviceBinary`"", 'type=', 'own', 'start=', 'auto', 'obj=', $ServiceAccount, 'DisplayName=', $DisplayName)
    Invoke-Checked 'sc.exe' @('description', $ServiceName, $Description)
    Invoke-Checked 'sc.exe' @('sidtype', $ServiceName, 'unrestricted')
    Invoke-Checked 'sc.exe' @('privs', $ServiceName, 'SeChangeNotifyPrivilege/SeImpersonatePrivilege/SeCreateGlobalPrivilege')
    Invoke-Checked 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000//')
  }

  if (-not (Test-Path -LiteralPath $ProgramDataOrcel)) {
    if ($PSCmdlet.ShouldProcess($ProgramDataOrcel, 'Create with a protected ACL (SYSTEM, Administrators full; Users read)')) {
      New-Item -ItemType Directory -Path $ProgramDataOrcel | Out-Null
      Set-ProtectedAcl $ProgramDataOrcel @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', '*S-1-5-32-545:(OI)(CI)RX')
      Set-Content -LiteralPath $OrcelDirMarker -Value $Marker -Encoding ascii
    }
  }

  if ($PSCmdlet.ShouldProcess($StateDir, 'Create with a protected ACL (service, SYSTEM, Administrators only)')) {
    New-Item -ItemType Directory -Path $StateDir | Out-Null
    Set-ProtectedAcl $StateDir @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "${ServiceAccount}:(OI)(CI)F")
    $config = @{ trusted_orceld_images = @($OrceldPath) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $StateDir 'config.json'), $config, (New-Object Text.UTF8Encoding($false)))
  }

  if ($PSCmdlet.ShouldProcess($PublicDir, 'Create with a protected ACL (users read the public key)')) {
    New-Item -ItemType Directory -Path $PublicDir | Out-Null
    Set-ProtectedAcl $PublicDir @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F', "${ServiceAccount}:(OI)(CI)M", '*S-1-5-32-545:(OI)(CI)RX')
  }

  if (-not (Test-Path -LiteralPath $EventKey)) {
    if ($PSCmdlet.ShouldProcess($EventKey, 'Register the Event Log source Orcel')) {
      New-Item -Path $EventKey | Out-Null
      $messages = Join-Path $env:SystemRoot 'Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll'
      New-ItemProperty -Path $EventKey -Name 'EventMessageFile' -PropertyType ExpandString -Value $messages | Out-Null
      New-ItemProperty -Path $EventKey -Name 'TypesSupported' -PropertyType DWord -Value 7 | Out-Null
      New-ItemProperty -Path $EventKey -Name 'OrcelInstalledBy' -PropertyType String -Value $Marker | Out-Null
    }
  } else {
    Write-Host "The Event Log source Orcel already exists; left unchanged."
  }

  if ($PSCmdlet.ShouldProcess($ServiceName, 'Start the service')) {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    Get-Service -Name $ServiceName | Format-List Name, Status, StartType
    Write-Host 'Next: run "orceld authority-status" as your normal user (not elevated).'
  }
}

function Uninstall-Authority {
  Assert-Elevated
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop and delete the service')) {
      Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
      Invoke-Checked 'sc.exe' @('delete', $ServiceName)
    }
  }
  if (Test-Path -LiteralPath $EventKey) {
    $by = (Get-ItemProperty -Path $EventKey -Name 'OrcelInstalledBy' -ErrorAction SilentlyContinue)
    if ($by -and $by.OrcelInstalledBy -eq $Marker) {
      if ($PSCmdlet.ShouldProcess($EventKey, 'Remove the Event Log source Orcel')) { Remove-Item -Path $EventKey -Recurse }
    } else {
      Write-Host 'The Event Log source Orcel was not created by this script; left unchanged.'
    }
  }
  foreach ($dir in @($ProgramFilesDir, $PublicDir)) {
    if ((Test-Path -LiteralPath $dir) -and $PSCmdlet.ShouldProcess($dir, 'Delete')) { Remove-Item -LiteralPath $dir -Recurse -Force }
  }
  if ((Test-Path -LiteralPath $StateDir) -and -not $KeepState) {
    if ($PSCmdlet.ShouldProcess($StateDir, 'Delete (audit chain, leases, signing key)')) { Remove-Item -LiteralPath $StateDir -Recurse -Force }
  }
  if ((Test-Path -LiteralPath $OrcelDirMarker)) {
    $rest = @(Get-ChildItem -LiteralPath $ProgramDataOrcel -Force | Where-Object { $_.FullName -ne $OrcelDirMarker })
    if ($rest.Count -eq 0 -and $PSCmdlet.ShouldProcess($ProgramDataOrcel, 'Delete (created by this script, now empty)')) {
      Remove-Item -LiteralPath $ProgramDataOrcel -Recurse -Force
    }
  }
  $parent = Split-Path -Parent $ProgramFilesDir
  if ((Test-Path -LiteralPath $parent) -and @(Get-ChildItem -LiteralPath $parent -Force).Count -eq 0) {
    if ($PSCmdlet.ShouldProcess($parent, 'Delete (empty)')) { Remove-Item -LiteralPath $parent -Force }
  }
  Write-Host 'Uninstalled.'
}

if ($Uninstall) { Uninstall-Authority } else { Install-Authority }
