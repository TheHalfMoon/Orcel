<#
.SYNOPSIS
  Installs or uninstalls the Orcel authority service (SG-000132).

.DESCRIPTION
  The FOUNDER runs this script, elevated, on the PC that will run Orcel. Agents never run it on a PC; CI runs it
  on a disposable GitHub-hosted runner only (job "Authority install E2E").
  Follow docs/orcel/implementation-readiness/prep/SG132_INSTALL_RUNBOOK.md, the one supported procedure: the
  script and the binaries are staged in %ProgramFiles%\OrcelStaging (created by the runbook's "Stage" step with
  a protected, admin-only DACL, which also checks this script's SHA-256), and the script runs from there.
  Run with -WhatIf to see every change without making any.

  Before it reads or changes anything, the script checks where it runs from: its own file, the folder holding
  it, -ArtifactDir and every binary in it, and every parent folder up to the volume root, must be on a local
  fixed drive, contain no junction, symbolic link or mount point, be owned by SYSTEM, Administrators or
  TrustedInstaller, and grant no other account a right to change them (write, append, add, delete, change
  permissions or take ownership; on a parent folder: delete entries, delete, change permissions or take
  ownership). A folder that any user could change is refused, with nothing changed: a standard user could
  replace a file an elevated step consumes.

  The script installs only hash-pinned bytes: -ArtifactDir holds orcel-authority.exe, orceld.exe and orcel.exe
  from the CI "Authority service artifact" of the reviewed commit, and -AuthoritySha256 / -OrceldSha256 /
  -OrcelSha256 are their SHA-256 values from that job's log. Each binary is opened once, with no write or
  delete sharing, and hashed and copied from that same open handle, so it cannot be swapped between the check
  and the copy; the copy in %ProgramFiles% is hashed again. Any mismatch stops the install.

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
    7. Starts the service and waits until it runs and has published its public key.
  Every created directory's owner and DACL are read back and checked; a difference stops the install.
  If any step fails, every change already made is undone (rollback) before the script stops.

  Uninstall (-Uninstall) reverses them: stops the service and waits until it has stopped, deletes it, removes
  the virtual account's user profile if Windows created one, removes the Event Log source if this script
  created it, deletes the copied binaries, %ProgramData%\Orcel\authority-public and (unless -KeepState)
  %ProgramData%\Orcel\authority, and deletes %ProgramData%\Orcel if it is then empty and this script created
  it. Events already written to the Application log stay in the log. With -RemoveStaging it then deletes the
  four staged files and %ProgramFiles%\OrcelStaging (it must be the folder this script runs from).

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

.PARAMETER RemoveStaging
  With -Uninstall: afterwards delete the staged files and %ProgramFiles%\OrcelStaging.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
  [string]$ArtifactDir,
  [string]$AuthoritySha256,
  [string]$OrceldSha256,
  [string]$OrcelSha256,
  [switch]$Uninstall,
  [switch]$KeepState,
  [switch]$RemoveStaging
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
$PublicKeyFile = Join-Path $PublicDir 'lease-signing-key.json'
$StagingDir = Join-Path $env:ProgramFiles 'OrcelStaging'
$StagedFiles = @('install-orcel-authority.ps1', 'orcel-authority.exe', 'orceld.exe', 'orcel.exe')
$EventKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel'
$Marker = 'install-orcel-authority.ps1'
$OrcelDirMarker = Join-Path $ProgramDataOrcel '.created-by-install-orcel-authority'
# SYSTEM, Administrators, TrustedInstaller.
$PrivilegedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# OWNER RIGHTS: an ACE for it applies to the owner, which the location check requires to be privileged.
$OwnerRightsSid = 'S-1-3-4'

# Access-mask bits (winnt.h). On a parent folder, a non-administrator must not be able to delete or rename an
# entry, delete or rename the folder itself, or change its permissions or owner. Creating NEW entries in a
# parent is harmless to the path (C:\ lets Authenticated Users create folders) and is not refused there.
$FILE_WRITE_DATA = 0x2          # add a file, on a folder
$FILE_APPEND_DATA = 0x4         # add a subfolder, on a folder
$FILE_WRITE_EA = 0x10
$FILE_DELETE_CHILD = 0x40
$FILE_WRITE_ATTRIBUTES = 0x100
$DELETE = 0x10000
$WRITE_DAC = 0x40000
$WRITE_OWNER = 0x80000
$GENERIC_ALL = 0x10000000
$GENERIC_WRITE = 0x40000000
$EntryChangeRights = $FILE_DELETE_CHILD -bor $DELETE -bor $WRITE_DAC -bor $WRITE_OWNER -bor $GENERIC_ALL -bor $GENERIC_WRITE
# On the consumed file or folder itself: every right that changes it or what it holds.
$ContentChangeRights = $EntryChangeRights -bor $FILE_WRITE_DATA -bor $FILE_APPEND_DATA -bor $FILE_WRITE_EA -bor $FILE_WRITE_ATTRIBUTES

function Get-Sha256([string]$Path) {
  # .NET directly: Get-FileHash honours -WhatIf in Windows PowerShell 5.1 and then hashes nothing.
  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  try { return Get-StreamSha256 $stream } finally { $stream.Dispose() }
}

function Get-StreamSha256([System.IO.Stream]$Stream) {
  $Stream.Position = 0
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return -join ($sha.ComputeHash($Stream) | ForEach-Object { $_.ToString('x2') }) } finally { $sha.Dispose() }
}

function Get-AclProblems([string]$Path, [int]$Forbidden) {
  # Problems that let someone other than SYSTEM, Administrators or TrustedInstaller change $Path. Reads the raw
  # security descriptor, so ACE types .NET would hide are seen; an ACE type this cannot judge is a problem.
  $problems = @()
  $item = Get-Item -LiteralPath $Path -Force
  if (([int]$item.Attributes -band [int][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    $problems += "$Path is a reparse point (junction, symbolic link or mount point)"
  }
  $acl = Get-Acl -LiteralPath $Path
  $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
  $owner = $descriptor.Owner.Value
  if ($PrivilegedSids -notcontains $owner) {
    $problems += "$Path is owned by $owner, not SYSTEM, Administrators or TrustedInstaller (an owner can always change the permissions)"
  }
  if ($null -eq $descriptor.DiscretionaryAcl) {
    return $problems + "$Path has no DACL, so everyone has full control"
  }
  foreach ($ace in $descriptor.DiscretionaryAcl) {
    # Inherit-only ACEs apply to children created later, not to this object.
    if (([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
    if ($ace -isnot [System.Security.AccessControl.QualifiedAce]) {
      $problems += "$Path has an ACE of type $($ace.AceType) that this check cannot judge"
      continue
    }
    if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
    $sid = $ace.SecurityIdentifier.Value
    if ($PrivilegedSids -contains $sid -or $sid -eq $OwnerRightsSid) { continue }
    if (($ace.AccessMask -band $Forbidden) -ne 0) {
      $problems += ('{0} lets {1} change it (access mask 0x{2:x8})' -f $Path, $sid, $ace.AccessMask)
    }
  }
  return $problems
}

function Get-LocationProblems([string]$Path) {
  # $Path is a file or folder an elevated step consumes: checked with every content right, and each parent up
  # to the volume root with the entry rights.
  $full = [System.IO.Path]::GetFullPath($Path)
  if ($full -notmatch '^[A-Za-z]:\\') { return @("$full is not a path on a local drive letter") }
  $root = [System.IO.Path]::GetPathRoot($full)
  if ([System.IO.DriveInfo]::new($root).DriveType -ne [System.IO.DriveType]::Fixed) {
    return @("$root is not a fixed local drive")
  }
  if (-not (Test-Path -LiteralPath $full)) { return @("$full does not exist") }
  $problems = @(Get-AclProblems $full $ContentChangeRights)
  $parent = Split-Path -Parent $full
  while ($parent) {
    $problems += @(Get-AclProblems $parent $EntryChangeRights)
    $next = Split-Path -Parent $parent
    if ($next -eq $parent) { break }
    $parent = $next
  }
  return $problems
}

function Assert-TrustedLocation([string[]]$Paths) {
  $problems = @()
  foreach ($path in $Paths) { $problems += @(Get-LocationProblems $path) }
  if ($problems.Count) {
    $problems | Sort-Object -Unique | ForEach-Object { Write-Host "  refused: $_" }
    throw "A file or folder this elevated step consumes could be changed by a non-administrator, so another process could replace it. Stage the files with the runbook's Stage step (%ProgramFiles%\OrcelStaging) and run this script from there. Nothing was changed."
  }
  foreach ($path in $Paths) { Write-Host "Location checked (admin-only up to the volume root): $([System.IO.Path]::GetFullPath($path))" }
}

function Assert-Elevated {
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ($WhatIfPreference) {
      Write-Host 'Not elevated: running the -WhatIf preview only; nothing will be changed.'
      return
    }
    throw 'Run this script elevated, started as the runbook says. Nothing was changed.'
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
    throw "SHA-256 mismatch for ${Path}: expected $Expected, found $actual."
  }
}

function Assert-StreamHash([System.IO.Stream]$Stream, [string]$Path, [string]$Expected) {
  $actual = Get-StreamSha256 $Stream
  Write-Host "SHA-256 $actual  $Path (held open, no write or delete sharing)"
  if ($actual -ne $Expected.ToLowerInvariant()) {
    throw "SHA-256 mismatch for ${Path}: expected $Expected, found $actual. Nothing was changed."
  }
}

function Copy-FromHeldStream([System.IO.Stream]$Source, [string]$Destination, [string]$Expected) {
  # Copies from the handle that was hashed (so the bytes cannot change in between) into a new file, then
  # hashes the new file through its own handle.
  $out = [System.IO.File]::Open($Destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  try {
    $Source.Position = 0
    $Source.CopyTo($out)
    $out.Flush($true)
    $actual = Get-StreamSha256 $out
  } finally {
    $out.Dispose()
  }
  if ($actual -ne $Expected.ToLowerInvariant()) {
    throw "SHA-256 mismatch for the copy ${Destination}: expected $Expected, found $actual."
  }
}

function Get-OwnerSid([string]$Path) {
  $acl = Get-Acl -LiteralPath $Path
  return ([Security.Principal.NTAccount]$acl.Owner).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-ServiceSid {
  # sc.exe showsid computes the virtual account's SID from the name, whether or not the service exists.
  $text = (& sc.exe showsid $ServiceName) -join ' '
  if ($text -match '(S-1-5-80(-\d+){5})') { return $Matches[1] }
  return $null
}

function Test-UsersCanChangeEntries([string]$Path) {
  # True when anyone but SYSTEM, Administrators or TrustedInstaller may add, delete or rename entries.
  return @(Get-AclProblems $Path ($EntryChangeRights -bor $FILE_WRITE_DATA -bor $FILE_APPEND_DATA)).Count -gt 0
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

function Wait-ServiceStopped([string]$Name, [int]$Seconds) {
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -eq 'Stopped') { return }
    Start-Sleep -Milliseconds 500
  }
  throw "The service $Name did not stop within $Seconds seconds; nothing was deleted. Retry -Uninstall."
}

function Wait-ServiceReady([int]$Seconds) {
  # Running, and the public key published: the service passed its start checks.
  $deadline = (Get-Date).AddSeconds($Seconds)
  while ((Get-Date) -lt $deadline) {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq 'Running' -and (Test-Path -LiteralPath $PublicKeyFile)) {
      Start-Sleep -Seconds 2
      $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
      if ($service -and $service.Status -eq 'Running') { return }
    }
    Start-Sleep -Milliseconds 500
  }
  throw "The service $ServiceName did not reach Running with its public key published within $Seconds seconds (read event 4103 in the Application log)."
}

function Remove-ServiceProfile([string]$ServiceSid) {
  if (-not $ServiceSid) { return }
  $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$ServiceSid'" -ErrorAction SilentlyContinue
  if ($profile -and $PSCmdlet.ShouldProcess($profile.LocalPath, 'Remove the virtual account profile (its DPAPI keys included)')) {
    # Windows may keep a service account's profile loaded after the service stopped; retry for a while, then
    # leave it with a warning (it holds only that account's DPAPI keys, readable by administrators anyway).
    $deadline = (Get-Date).AddSeconds(30)
    while ($true) {
      try { $profile | Remove-CimInstance -ErrorAction Stop; return } catch {
        if ((Get-Date) -ge $deadline) {
          Write-Warning "PROFILE LEFT: the virtual account profile $($profile.LocalPath) ($ServiceSid) is still loaded, so it was not removed. After the next restart of Windows, remove it elevated: Get-CimInstance Win32_UserProfile -Filter `"SID='$ServiceSid'`" | Remove-CimInstance"
          return
        }
        Start-Sleep -Seconds 2
        $profile = Get-CimInstance -ClassName Win32_UserProfile -Filter "SID='$ServiceSid'" -ErrorAction SilentlyContinue
        if (-not $profile) { return }
      }
    }
  }
}

function Undo-Install($Made, [string]$ServiceSid) {
  # Rollback: reverses, newest first, exactly the changes this run made. Returns the steps that failed.
  Write-Warning 'The install failed; undoing every change it made.'
  $failed = @()
  $steps = @(
    @{ When = $Made.Service; What = 'stop and delete the service'; Do = {
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Wait-ServiceStopped $ServiceName 60
        & sc.exe delete $ServiceName | Out-Null
        $deadline = (Get-Date).AddSeconds(30)
        while ((Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'the service still exists' }
      } },
    @{ When = $Made.Service; What = 'remove the virtual account profile'; Do = { Remove-ServiceProfile $ServiceSid } },
    @{ When = $Made.EventSource; What = 'remove the Event Log source'; Do = { Remove-Item -Path $EventKey -Recurse -Force } },
    @{ When = $Made.PublicDir; What = "delete $PublicDir"; Do = { Remove-Item -LiteralPath $PublicDir -Recurse -Force } },
    @{ When = $Made.StateDir; What = "delete $StateDir"; Do = { Remove-Item -LiteralPath $StateDir -Recurse -Force } },
    @{ When = $Made.ProgramDataOrcel; What = "delete $ProgramDataOrcel"; Do = {
        Remove-Item -LiteralPath $OrcelDirMarker -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $ProgramDataOrcel -Force
      } },
    @{ When = $Made.Orcel; What = "delete $InstalledOrcel"; Do = { Remove-Item -LiteralPath $InstalledOrcel -Force } },
    @{ When = $Made.Orceld; What = "delete $InstalledOrceld"; Do = { Remove-Item -LiteralPath $InstalledOrceld -Force } },
    @{ When = $Made.Authority; What = "delete $InstalledAuthority"; Do = { Remove-Item -LiteralPath $InstalledAuthority -Force } },
    @{ When = $Made.ProgramFilesDir; What = "delete $ProgramFilesDir"; Do = { Remove-Item -LiteralPath $ProgramFilesDir -Force } },
    @{ When = $Made.ProgramFilesOrcel; What = "delete $ProgramFilesOrcel"; Do = { Remove-Item -LiteralPath $ProgramFilesOrcel -Force } }
  )
  foreach ($step in $steps) {
    if (-not $step.When) { continue }
    try {
      & $step.Do
      Write-Host "  rolled back: $($step.What)"
    } catch {
      $failed += "$($step.What): $($_.Exception.Message)"
    }
  }
  return $failed
}

function Install-Authority {
  Assert-Elevated
  if (-not $ArtifactDir -or -not $AuthoritySha256 -or -not $OrceldSha256 -or -not $OrcelSha256) {
    throw 'Install needs -ArtifactDir, -AuthoritySha256, -OrceldSha256 and -OrcelSha256 (from the reviewed commit''s CI job log). Nothing was changed.'
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
  # This script, its folder, the artifact folder and each binary, with every parent: admin-only.
  Assert-TrustedLocation @($PSCommandPath, (Split-Path -Parent $PSCommandPath), $ArtifactDir, $sourceAuthority, $sourceOrceld, $sourceOrcel)

  # Held open from here to the copy: no other process can write, delete or rename them meanwhile.
  $held = @{}
  try {
    foreach ($pair in @(@('Authority', $sourceAuthority), @('Orceld', $sourceOrceld), @('Orcel', $sourceOrcel))) {
      $held[$pair[0]] = [System.IO.File]::Open($pair[1], [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    }
    Assert-StreamHash $held.Authority $sourceAuthority $AuthoritySha256
    Assert-StreamHash $held.Orceld $sourceOrceld $OrceldSha256
    Assert-StreamHash $held.Orcel $sourceOrcel $OrcelSha256
    Install-Held $held
  } finally {
    foreach ($stream in $held.Values) { $stream.Dispose() }
  }
}

function Install-Held($held) {
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    throw "The service $ServiceName already exists. Run with -Uninstall first. Nothing was changed."
  }
  foreach ($dir in @($StateDir, $PublicDir)) {
    if (Test-Path -LiteralPath $dir) {
      throw "$dir already exists. Someone may have pre-created it; inspect and remove it (or run -Uninstall). Nothing was changed."
    }
  }
  foreach ($file in @($InstalledAuthority, $InstalledOrceld, $InstalledOrcel)) {
    if (Test-Path -LiteralPath $file) {
      throw "$file already exists (left from an earlier install?). Run with -Uninstall first. Nothing was changed."
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

  $made = @{}
  $serviceSid = Get-ServiceSid
  try {
    if ($PSCmdlet.ShouldProcess($ProgramFilesOrcel, 'Copy and re-verify orcel-authority.exe, orceld.exe and orcel.exe')) {
      if (-not (Test-Path -LiteralPath $ProgramFilesOrcel)) { New-Item -ItemType Directory -Path $ProgramFilesOrcel | Out-Null; $made.ProgramFilesOrcel = $true }
      if (-not (Test-Path -LiteralPath $ProgramFilesDir)) { New-Item -ItemType Directory -Path $ProgramFilesDir | Out-Null; $made.ProgramFilesDir = $true }
      $made.Authority = $true
      Copy-FromHeldStream $held.Authority $InstalledAuthority $AuthoritySha256
      $made.Orceld = $true
      Copy-FromHeldStream $held.Orceld $InstalledOrceld $OrceldSha256
      $made.Orcel = $true
      Copy-FromHeldStream $held.Orcel $InstalledOrcel $OrcelSha256
      Assert-Hash $InstalledAuthority $AuthoritySha256
      Assert-Hash $InstalledOrceld $OrceldSha256
      Assert-Hash $InstalledOrcel $OrcelSha256
    }

    if ($PSCmdlet.ShouldProcess($ServiceName, 'Register the service with the SCM')) {
      $made.Service = $true
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
        $made.ProgramDataOrcel = $true
        New-ProtectedDirectory $ProgramDataOrcel 'O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'
        Set-Content -LiteralPath $OrcelDirMarker -Value $Marker -Encoding ascii
      }
    }

    if ($PSCmdlet.ShouldProcess($StateDir, 'Create with owner Administrators and a protected ACL (service, SYSTEM, Administrators only)')) {
      $made.StateDir = $true
      New-ProtectedDirectory $StateDir "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;$serviceSid)"
      $config = @{ trusted_orceld_images = @($InstalledOrceld); trusted_owner_cli_images = @($InstalledOrcel) } | ConvertTo-Json -Compress
      [IO.File]::WriteAllText((Join-Path $StateDir 'config.json'), $config, (New-Object Text.UTF8Encoding($false)))
    }

    if ($PSCmdlet.ShouldProcess($PublicDir, 'Create with owner Administrators and a protected ACL (users read the public key)')) {
      $made.PublicDir = $true
      New-ProtectedDirectory $PublicDir "O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$serviceSid)(A;OICI;0x1200a9;;;BU)"
    }

    if (-not (Test-Path -LiteralPath $EventKey)) {
      if ($PSCmdlet.ShouldProcess($EventKey, 'Register the Event Log source Orcel')) {
        $made.EventSource = $true
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
      Wait-ServiceReady 30
      Get-Service -Name $ServiceName | Format-List Name, Status, StartType
      Write-Host "Next: run `"$InstalledOrceld authority-status`" as your normal user (not elevated)."
    }
  } catch {
    $cause = $_
    $failed = @(Undo-Install $made $serviceSid)
    if ($failed.Count) {
      $failed | ForEach-Object { Write-Host "  ROLLBACK FAILED: $_" }
      throw "The install failed ($($cause.Exception.Message)) and the rollback could not undo everything; inspect the items above. Then run -Uninstall."
    }
    throw "The install failed ($($cause.Exception.Message)); every change it made was rolled back."
  }
}

function Uninstall-Authority {
  Assert-Elevated
  Assert-TrustedLocation @($PSCommandPath, (Split-Path -Parent $PSCommandPath))
  $scriptDir = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSCommandPath)).TrimEnd('\')
  if ($RemoveStaging -and $scriptDir -ne [System.IO.Path]::GetFullPath($StagingDir).TrimEnd('\')) {
    throw "-RemoveStaging removes $StagingDir and must be run from the script staged there (this one runs from $scriptDir). Nothing was changed."
  }
  $serviceSid = $null
  try { $serviceSid = ([Security.Principal.NTAccount]$ServiceAccount).Translate([Security.Principal.SecurityIdentifier]).Value } catch { $serviceSid = Get-ServiceSid }
  if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($ServiceName, 'Stop (and wait), then delete the service')) {
      Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
      Wait-ServiceStopped $ServiceName 60
      Invoke-Checked 'sc.exe' @('delete', $ServiceName)
    }
  }
  Remove-ServiceProfile $serviceSid
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
  if ($RemoveStaging) {
    # Only the four staged files, by name, then the folder if it is empty: no recursive delete.
    foreach ($name in $StagedFiles) {
      $file = Join-Path $StagingDir $name
      if ((Test-Path -LiteralPath $file -PathType Leaf) -and $PSCmdlet.ShouldProcess($file, 'Delete the staged file')) { Remove-Item -LiteralPath $file -Force }
    }
    if ((Test-Path -LiteralPath $StagingDir) -and @(Get-ChildItem -LiteralPath $StagingDir -Force).Count -eq 0) {
      if ($PSCmdlet.ShouldProcess($StagingDir, 'Delete (empty)')) { Remove-Item -LiteralPath $StagingDir -Force }
    } elseif (Test-Path -LiteralPath $StagingDir) {
      Write-Host "$StagingDir holds other files; left in place."
    }
  }
  Write-Host 'Uninstalled. Events already written to the Application log remain there.'
}

# Dot-sourcing (tests) defines the functions above and changes nothing.
if ($MyInvocation.InvocationName -eq '.') { return }

$self = Get-Sha256 $PSCommandPath
Write-Host "This script: $PSCommandPath"
Write-Host "SHA-256 of this script: $self (the Stage step checked it against the reviewed commit's value)"

if ($Uninstall) { Uninstall-Authority } else { Install-Authority }
