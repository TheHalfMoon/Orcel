<#
.SYNOPSIS
  Installs or uninstalls the Orcel authority service (SG-000132 slice 1).

.DESCRIPTION
  The FOUNDER runs this script, elevated, on the PC that will run Orcel. Agents never run it.
  Read docs/orcel/implementation-readiness/prep/SG132_INSTALL_RUNBOOK.md first, and run a copy of this script
  whose SHA-256 you checked (the script prints its own hash first). Run with -WhatIf to see every change
  without making any.

  The script installs only hash-pinned bytes: -ArtifactDir holds orcel-authority.exe, orceld.exe and orcel.exe (the CI
  "Authority service artifact" of the reviewed commit, or a build made in a folder only administrators can
  write), and -AuthoritySha256 / -OrceldSha256 / -OrcelSha256 are the SHA-256 values from that artifact's SHA256SUMS.txt.
  All files are hashed before copying and again after copying into %ProgramFiles%; any mismatch stops the
  install. It never copies from the repository's target directory implicitly.

  Install makes exactly these system changes:
    1. Copies orcel-authority.exe to %ProgramFiles%\Orcel\Authority\, and orceld.exe and orcel.exe (the owner
       CLI the service trusts for grants, enrollment and reset) to %ProgramFiles%\Orcel\ (admin-only write), after
       verifying every hash.
    2. Registers the service with the SCM: name OrcelAuthority, display name "Orcel Authority", own process,
       automatic start, account NT SERVICE\OrcelAuthority (a virtual account; no password), service SID type
       unrestricted, required privileges SeChangeNotifyPrivilege, SeImpersonatePrivilege and
       SeCreateGlobalPrivilege only, restart twice on failure within a day.
    3. Creates %ProgramData%\Orcel (only if missing) with its security set at creation: owner Administrators,
       protected DACL with SYSTEM and Administrators full control and Users read and execute. An existing
       %ProgramData%\Orcel is not changed; the script stops if it is not admin-owned or users could add,
       delete or rename entries in it.
    4. Creates %ProgramData%\Orcel\authority at once with owner Administrators and a protected DACL: SYSTEM,
       Administrators and NT SERVICE\OrcelAuthority full control, nobody else. Writes config.json there,
       trusting only %ProgramFiles%\Orcel\orceld.exe (for Authorize) and %ProgramFiles%\Orcel\orcel.exe (to
       record grant, enrollment and reset intents).
    5. Creates %ProgramData%\Orcel\authority-public at once with owner Administrators and a protected DACL:
       SYSTEM and Administrators full control, the service modify, Users read and execute.
    6. Registers the Event Log source "Orcel" in the Application log
       (HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel) unless it already exists, marked as
       created by this script.
    7. Starts the service.
  Every created directory's owner and DACL are read back and checked; a difference stops the install.

  Uninstall (-Uninstall) reverses them: stops the service and waits until it has stopped, deletes it, removes
  the virtual account's user profile if Windows created one, removes the Event Log source if this script
  created it, deletes the copied binaries, %ProgramData%\Orcel\authority-public and (unless -KeepState)
  %ProgramData%\Orcel\authority, and deletes %ProgramData%\Orcel if it is then empty and this script created
  it. Events already written to the Application log stay in the log.

.PARAMETER ArtifactDir
  Directory holding orcel-authority.exe, orceld.exe and orcel.exe to install. Required for install.

.PARAMETER AuthoritySha256
  Expected SHA-256 (hex) of orcel-authority.exe. Required for install.

.PARAMETER OrceldSha256
  Expected SHA-256 (hex) of orceld.exe. Required for install.

.PARAMETER OrcelSha256
  Expected SHA-256 (hex) of orcel.exe (the owner CLI). Required for install.

.PARAMETER Uninstall
  Remove everything Install made.

.PARAMETER KeepState
  With -Uninstall: keep %ProgramData%\Orcel\authority (the audit chain, leases and signing key).
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ArtifactDir,
  [string]$AuthoritySha256,
  [string]$OrceldSha256,
  [string]$OrcelSha256,
  [switch]$Uninstall,
  [switch]$KeepState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServiceName = 'OrcelAuthority'
$ServiceAccount = 'NT SERVICE\OrcelAuthority'
$DisplayName = 'Orcel Authority'
$Description = 'Orcel Full Control authority (SG-000132): holds the lease-signing key, leases, epoch and audit outside the user session. It never elevates anything.'
$ProgramFilesOrcel = Join-Path $env:ProgramFiles 'Orcel'
$ProgramFilesDir = Join-Path $ProgramFilesOrcel 'Authority'
$InstalledAuthority = Join-Path $ProgramFilesDir 'orcel-authority.exe'
$InstalledOrceld = Join-Path $ProgramFilesOrcel 'orceld.exe'
$InstalledOrcel = Join-Path $ProgramFilesOrcel 'orcel.exe'
$ProgramDataOrcel = Join-Path $env:ProgramData 'Orcel'
$StateDir = Join-Path $ProgramDataOrcel 'authority'
$PublicDir = Join-Path $ProgramDataOrcel 'authority-public'
$EventKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel'
$Marker = 'install-orcel-authority.ps1'
$OrcelDirMarker = Join-Path $ProgramDataOrcel '.created-by-install-orcel-authority'
$PrivilegedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')

function Get-Sha256([string]$Path) {
  # .NET directly: Get-FileHash honours -WhatIf in Windows PowerShell 5.1 and then hashes nothing.
  $stream = [System.IO.File]::OpenRead($Path)
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
  } finally {
    $stream.Dispose()
  }
}

$self = Get-Sha256 $PSCommandPath
Write-Host "This script: $PSCommandPath"
Write-Host "SHA-256 of this script: $self (compare it with the reviewed commit's copy before going on)"

function Assert-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($WhatIfPreference) {
      Write-Host 'Not elevated: running the -WhatIf preview only; nothing will be changed.'
      return
    }
    throw 'Run this script from an elevated PowerShell (Run as administrator). Nothing was changed.'
  }
}

function Invoke-Checked([string]$File, [string[]]$Arguments) {
  Write-Host ">> $File $($Arguments -join ' ')"
  & $File @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$File failed with exit code $LASTEXITCODE" }
}

function Assert-Hash([string]$Path, [string]$Expected) {
  $actual = Get-Sha256 $Path
  Write-Host "SHA-256 $actual  $Path"
  if ($actual -ne $Expected.ToLowerInvariant()) {
    throw "SHA-256 mismatch for ${Path}: expected $Expected, found $actual. Nothing more was changed."
  }
}

function Get-OwnerSid([string]$Path) {
  $acl = Get-Acl -LiteralPath $Path
  return ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Test-UsersCanChangeEntries([string]$Path) {
  # True when anyone but SYSTEM, Administrators or TrustedInstaller may add, delete or rename entries.
  $change = [Security.AccessControl.FileSystemRights]'CreateFiles, AppendData, DeleteSubdirectoriesAndFiles, Delete, ChangePermissions, TakeOwnership'
  $acl = Get-Acl -LiteralPath $Path
  foreach ($rule in $acl.Access) {
    if ($rule.AccessControlType -ne 'Allow') { continue }
    if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
    $sid = $null
    try { $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $sid = $rule.IdentityReference.Value }
    if ($PrivilegedSids -contains $sid) { continue }
    if (($rule.FileSystemRights -band $change) -ne 0) { return $true }
  }
  return $false
}

function New-ProtectedDirectory([string]$Path, [string]$Sddl) {
  # Creates the directory with its owner and protected DACL in one call, so it never exists with inherited
  # access, then reads the security back and compares it.
  $security = New-Object System.Security.AccessControl.DirectorySecurity
  $security.SetSecurityDescriptorSddlForm($Sddl)
  if ($PSVersionTable.PSEdition -eq 'Core') {
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $security) | Out-Null
  } else {
    [System.IO.Directory]::CreateDirectory($Path, $security) | Out-Null
  }
  $readBack = Get-Acl -LiteralPath $Path
  $sidType = [System.Security.Principal.SecurityIdentifier]
  $describe = {
    param($acl)
    $rules = $acl.GetAccessRules($true, $true, $sidType) | ForEach-Object {
      '{0}|{1}|{2}|{3}|{4}' -f $_.IdentityReference.Value, [int]$_.FileSystemRights, $_.AccessControlType, $_.InheritanceFlags, $_.IsInherited
    }
    return (@($rules) | Sort-Object) -join ';'
  }
  $owner = $readBack.GetOwner($sidType).Value
  $want = & $describe $security
  $have = & $describe $readBack
  if ($owner -ne 'S-1-5-32-544' -or -not $readBack.AreAccessRulesProtected -or $want -ne $have) {
    throw "The security of $Path is not what was asked for (owner $owner, protected $($readBack.AreAccessRulesProtected), wanted [$want], found [$have]). Stop and inspect."
  }
  Write-Host "Created $Path (owner Administrators, protected): $have"
}

function Install-Authority {
  Assert-Elevated
  if (-not $ArtifactDir -or -not $AuthoritySha256 -or -not $OrceldSha256 -or -not $OrcelSha256) {
    throw 'Install needs -ArtifactDir, -AuthoritySha256, -OrceldSha256 and -OrcelSha256 (from the reviewed commit''s CI artifact SHA256SUMS.txt). Nothing was changed.'
  }
  foreach ($hash in @($AuthoritySha256, $OrceldSha256, $OrcelSha256)) {
    if ($hash -notmatch '^[0-9a-fA-F]{64}$') { throw "Not a SHA-256: $hash. Nothing was changed." }
  }
  $sourceAuthority = Join-Path $ArtifactDir 'orcel-authority.exe'
  $sourceOrceld = Join-Path $ArtifactDir 'orceld.exe'
  $sourceOrcel = Join-Path $ArtifactDir 'orcel.exe'
  foreach ($file in @($sourceAuthority, $sourceOrceld, $sourceOrcel)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "No $file. Nothing was changed." }
  }
  Assert-Hash $sourceAuthority $AuthoritySha256
  Assert-Hash $sourceOrceld $OrceldSha256
  Assert-Hash $sourceOrcel $OrcelSha256

  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "The service $ServiceName already exists. Run with -Uninstall first. Nothing was changed."
  }
  foreach ($dir in @($StateDir, $PublicDir)) {
    if (Test-Path -LiteralPath $dir) {
      throw "$dir already exists. Someone may have pre-created it; inspect and remove it (or run -Uninstall). Nothing was changed."
    }
  }
  foreach ($dir in @($ProgramFilesOrcel, $ProgramFilesDir)) {
    if (Test-Path -LiteralPath $dir) {
      $owner = Get-OwnerSid $dir
      if ($PrivilegedSids -notcontains $owner) {
        throw "$dir is owned by $owner, not SYSTEM, Administrators or TrustedInstaller. Inspect and remove it first. Nothing was changed."
      }
      if (Test-UsersCanChangeEntries $dir) {
        throw "$dir lets non-administrators add, delete or rename entries, so an installed binary could be replaced. Fix its ACL or remove it first. Nothing was changed."
      }
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
  Write-Host "  copy the verified binaries to $InstalledAuthority, $InstalledOrceld and $InstalledOrcel"
  Write-Host "  SCM: create $ServiceName ($DisplayName) as $ServiceAccount, automatic start, SID type unrestricted"
  Write-Host "  directories created with protected ACLs: $StateDir (no user access), $PublicDir (users read)"
  Write-Host "  Event Log source Orcel (Application) unless present; trusted orceld image: $InstalledOrceld; trusted owner CLI: $InstalledOrcel"

  if ($PSCmdlet.ShouldProcess($ProgramFilesOrcel, 'Copy and re-verify orcel-authority.exe, orceld.exe and orcel.exe')) {
    New-Item -ItemType Directory -Force -Path $ProgramFilesDir | Out-Null
    Copy-Item -LiteralPath $sourceAuthority -Destination $InstalledAuthority -Force
    Copy-Item -LiteralPath $sourceOrceld -Destination $InstalledOrceld -Force
    Copy-Item -LiteralPath $sourceOrcel -Destination $InstalledOrcel -Force
    try {
      Assert-Hash $InstalledAuthority $AuthoritySha256
      Assert-Hash $InstalledOrceld $OrceldSha256
      Assert-Hash $InstalledOrcel $OrcelSha256
    } catch {
      Remove-Item -LiteralPath $InstalledAuthority, $InstalledOrceld, $InstalledOrcel -Force -ErrorAction SilentlyContinue
      throw
    }
  }

  if ($PSCmdlet.ShouldProcess($ServiceName, 'Register the service with the SCM')) {
    Invoke-Checked 'sc.exe' @('create', $ServiceName, 'binPath=', "`"$InstalledAuthority`"", 'type=', 'own', 'start=', 'auto', 'obj=', $ServiceAccount, 'DisplayName=', $DisplayName)
    Invoke-Checked 'sc.exe' @('description', $ServiceName, $Description)
    Invoke-Checked 'sc.exe' @('sidtype', $ServiceName, 'unrestricted')
    Invoke-Checked 'sc.exe' @('privs', $ServiceName, 'SeChangeNotifyPrivilege/SeImpersonatePrivilege/SeCreateGlobalPrivilege')
    Invoke-Checked 'sc.exe' @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/5000/restart/5000//')
  }
  try {
    $serviceSid = ([Security.Principal.NTAccount]$ServiceAccount).Translate([Security.Principal.SecurityIdentifier]).Value
  } catch {
    if (-not $WhatIfPreference) { throw }
    $serviceSid = '<service SID, known once the service exists>'
  }

  if (-not (Test-Path -LiteralPath $ProgramDataOrcel)) {
    if ($PSCmdlet.ShouldProcess($ProgramDataOrcel, 'Create with owner Administrators and a protected ACL (SYSTEM, Administrators full; Users read)')) {
      New-ProtectedDirectory $ProgramDataOrcel 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
      Set-Content -LiteralPath $OrcelDirMarker -Value $Marker -Encoding ascii
    }
  }

  if ($PSCmdlet.ShouldProcess($StateDir, 'Create with owner Administrators and a protected ACL (service, SYSTEM, Administrators only)')) {
    New-ProtectedDirectory $StateDir "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$serviceSid)"
    $config = @{ trusted_orceld_images = @($InstalledOrceld); trusted_owner_cli_images = @($InstalledOrcel) } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText((Join-Path $StateDir 'config.json'), $config, (New-Object Text.UTF8Encoding($false)))
  }

  if ($PSCmdlet.ShouldProcess($PublicDir, 'Create with owner Administrators and a protected ACL (users read the public key)')) {
    New-ProtectedDirectory $PublicDir "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$serviceSid)(A;OICI;0x1200a9;;;BU)"
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
    Write-Host 'The Event Log source Orcel already exists; left unchanged.'
  }

  if ($PSCmdlet.ShouldProcess($ServiceName, 'Start the service')) {
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 2
    Get-Service -Name $ServiceName | Format-List Name, Status, StartType
    Write-Host "Next: run `"$InstalledOrceld authority-status`" as your normal user (not elevated)."
  }
}

function Wait-ServiceStopped([string]$Name, [int]$Seconds) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -eq 'Stopped') { return }
    Start-Sleep -Milliseconds 500
  }
  throw "The service $Name did not stop within $Seconds seconds; nothing was deleted. Retry -Uninstall."
}

function Uninstall-Authority {
  Assert-Elevated
  $serviceSid = $null
  try { $serviceSid = ([Security.Principal.NTAccount]$ServiceAccount).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $serviceSid = $null }
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop (and wait), then delete the service')) {
      Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
      Wait-ServiceStopped $ServiceName 60
      Invoke-Checked 'sc.exe' @('delete', $ServiceName)
    }
  }
  if ($serviceSid) {
    $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$serviceSid'" -ErrorAction SilentlyContinue
    if ($profile -and $PSCmdlet.ShouldProcess($profile.LocalPath, 'Remove the virtual account profile (its DPAPI keys included)')) {
      $profile | Remove-CimInstance
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
  foreach ($item in @($InstalledOrceld, $InstalledOrcel, $ProgramFilesDir, $PublicDir)) {
    if ((Test-Path -LiteralPath $item) -and $PSCmdlet.ShouldProcess($item, 'Delete')) { Remove-Item -LiteralPath $item -Recurse -Force }
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
  if ((Test-Path -LiteralPath $ProgramFilesOrcel) -and @(Get-ChildItem -LiteralPath $ProgramFilesOrcel -Force).Count -eq 0) {
    if ($PSCmdlet.ShouldProcess($ProgramFilesOrcel, 'Delete (empty)')) { Remove-Item -LiteralPath $ProgramFilesOrcel -Force }
  }
  Write-Host 'Uninstalled. Events already written to the Application log remain there.'
}

if ($Uninstall) { Uninstall-Authority } else { Install-Authority }
