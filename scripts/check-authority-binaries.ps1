<#
.SYNOPSIS
  SG-000132 install hardening: checks the three authority binaries' PE headers. Reads files only.

.DESCRIPTION
  orcel-authority.exe runs elevated from the staging folder. A DLL it imports that is not a KnownDLL would be
  looked for in that folder first, before main runs. This check fails unless:
    - none of orcel-authority.exe, orceld.exe and orcel.exe imports a C runtime DLL (VCRUNTIME*, MSVCP*,
      ucrtbase*, api-ms-win-crt-*): the CI release build links the runtime statically (+crt-static);
    - orcel-authority.exe's load configuration has DependentLoadFlags 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32), so
      the DLLs it imports directly are resolved from System32 only (crates/orcel-authority/build.rs);
    - orcel-authority.exe imports normally only KnownDLLs and API sets (kernel32, advapi32, oleaut32, ntdll,
      api-ms-win-*), and delay-loads wtsapi32, bcrypt and crypt32, whose own imports (SspiCli, msasn1) are not
      KnownDLLs: they load after main restricted every load, their dependencies included, to System32.
  It prints each file's imports and flags and exits 1 on any failure.

.PARAMETER Dir
  Folder holding the three binaries.
#>
param([Parameter(Mandatory = $true)][string]$Dir)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Read-PeInfo([string]$Path) {
  $bytes = [IO.File]::ReadAllBytes($Path)
  $pe = [BitConverter]::ToInt32($bytes, 0x3C)
  if ([BitConverter]::ToUInt32($bytes, $pe) -ne 0x00004550) { throw "$Path is not a PE file" }
  $coff = $pe + 4
  $sections = [BitConverter]::ToUInt16($bytes, $coff + 2)
  $optionalSize = [BitConverter]::ToUInt16($bytes, $coff + 16)
  $optional = $coff + 20
  if ([BitConverter]::ToUInt16($bytes, $optional) -ne 0x20B) { throw "$Path is not PE32+" }
  $directories = $optional + 112
  $table = $optional + $optionalSize
  $toOffset = {
    param([uint32]$rva)
    for ($i = 0; $i -lt $sections; $i++) {
      $s = $table + 40 * $i
      $va = [BitConverter]::ToUInt32($bytes, $s + 12)
      $size = [Math]::Max([BitConverter]::ToUInt32($bytes, $s + 8), [BitConverter]::ToUInt32($bytes, $s + 16))
      if ($rva -ge $va -and $rva -lt $va + $size) { return [int]($rva - $va + [BitConverter]::ToUInt32($bytes, $s + 20)) }
    }
    throw "RVA 0x$('{0:x}' -f $rva) is in no section"
  }
  $readName = {
    param([int]$offset)
    $end = $offset
    while ($bytes[$end] -ne 0) { $end++ }
    return [Text.Encoding]::ASCII.GetString($bytes, $offset, $end - $offset)
  }
  $imports = @()
  $importRva = [BitConverter]::ToUInt32($bytes, $directories + 8)
  if ($importRva) {
    $entry = & $toOffset $importRva
    while ($true) {
      $nameRva = [BitConverter]::ToUInt32($bytes, $entry + 12)
      if ($nameRva -eq 0) { break }
      $imports += & $readName (& $toOffset $nameRva)
      $entry += 20
    }
  }
  $flags = 0
  $loadConfigRva = [BitConverter]::ToUInt32($bytes, $directories + 8 * 10)
  if ($loadConfigRva) {
    $config = & $toOffset $loadConfigRva
    $configSize = [BitConverter]::ToUInt32($bytes, $config)
    if ($configSize -ge 0x50) { $flags = [BitConverter]::ToUInt16($bytes, $config + 0x4E) }
  }
  $delayed = @()
  $delayRva = [BitConverter]::ToUInt32($bytes, $directories + 8 * 13)
  if ($delayRva) {
    $entry = & $toOffset $delayRva
    while ($true) {
      $nameRva = [BitConverter]::ToUInt32($bytes, $entry + 4)
      if ($nameRva -eq 0) { break }
      $delayed += & $readName (& $toOffset $nameRva)
      $entry += 32
    }
  }
  return [pscustomobject]@{ Imports = $imports; Delayed = $delayed; DependentLoadFlags = $flags }
}

$failures = @()
foreach ($name in @('orcel-authority.exe', 'orceld.exe', 'orcel.exe')) {
  $info = Read-PeInfo (Join-Path $Dir $name)
  Write-Host ("{0}: DependentLoadFlags 0x{1:x}; imports {2}; delay-loads {3}" -f $name, $info.DependentLoadFlags, ($info.Imports -join ', '), ($info.Delayed -join ', '))
  $runtime = @($info.Imports | Where-Object { $_ -match '^(vcruntime|msvcp|ucrtbase|api-ms-win-crt-)' })
  if ($runtime.Count) { $failures += "$name imports the C runtime DLLs $($runtime -join ', ') (build with -C target-feature=+crt-static)" }
  if ($name -eq 'orcel-authority.exe' -and $info.DependentLoadFlags -ne 0x800) {
    $failures += "$name has DependentLoadFlags 0x$('{0:x}' -f $info.DependentLoadFlags), not 0x800 (LOAD_LIBRARY_SEARCH_SYSTEM32)"
  }
  if ($name -eq 'orcel-authority.exe') {
    $known = @('kernel32.dll', 'advapi32.dll', 'oleaut32.dll', 'ntdll.dll')
    $other = @($info.Imports | Where-Object { $known -notcontains $_.ToLowerInvariant() -and $_ -notmatch '^api-ms-win-' })
    if ($other.Count) { $failures += "$name imports DLLs that are not KnownDLLs without delay-loading them: $($other -join ', ')" }
    foreach ($dll in @('wtsapi32.dll', 'bcrypt.dll', 'crypt32.dll')) {
      if (@($info.Delayed | Where-Object { $_ -ieq $dll }).Count -ne 1) { $failures += "$name does not delay-load $dll" }
    }
  }
}
if ($failures.Count) {
  $failures | ForEach-Object { Write-Host "FAIL: $_" }
  exit 1
}
Write-Host 'PASS: no C runtime DLL imported; orcel-authority.exe imports only KnownDLLs and API sets, resolves them from System32 only, and delay-loads wtsapi32, bcrypt and crypt32.'
exit 0
