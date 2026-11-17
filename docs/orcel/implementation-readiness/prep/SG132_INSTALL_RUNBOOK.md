# SG-000132 slice 1: installing the Orcel authority service (founder runbook)

This runbook is for the founder. The founder runs every step here on the PC that runs Orcel, from an elevated
PowerShell where it says so. Agents do not run the install, do not trigger UAC and make no registry, ACL or
service changes. The design and its limits are in [SG132_SLICE1.md](SG132_SLICE1.md).

## What the install changes on the PC

`scripts/install-orcel-authority.ps1` makes exactly these system changes, and `-Uninstall` reverses them:

| # | Change | Where | Reversed by `-Uninstall` |
| --- | --- | --- | --- |
| 1 | Copies `orcel-authority.exe`, so no user process can replace the service binary | `%ProgramFiles%\Orcel\Authority\` | Deleted |
| 2 | SCM registration: service `OrcelAuthority`, display name "Orcel Authority", own process, automatic start, account `NT SERVICE\OrcelAuthority` (a virtual account with no password), service SID type unrestricted, required privileges `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege` and `SeCreateGlobalPrivilege` only, restart on failure | Service Control Manager | Service stopped and deleted |
| 3 | Only if missing: `%ProgramData%\Orcel` owned by Administrators, protected DACL (SYSTEM and Administrators full control, Users read and execute) | `%ProgramData%\Orcel` | Deleted if this script created it and it is empty |
| 4 | State directory owned by Administrators, protected DACL: SYSTEM, Administrators and `NT SERVICE\OrcelAuthority` full control, no access for users; `config.json` with the trusted orceld path | `%ProgramData%\Orcel\authority` | Deleted (kept with `-KeepState`) |
| 5 | Public key directory owned by Administrators, protected DACL: SYSTEM and Administrators full control, the service modify, Users read and execute | `%ProgramData%\Orcel\authority-public` | Deleted |
| 6 | Event Log source `Orcel` in the Application log, unless it already exists (marked `OrcelInstalledBy`) | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel` | Removed only if this script created it |
| 7 | Starts the service | SCM | Stopped |

The script changes nothing else. It refuses to run, with nothing changed, if the service already exists, if
`%ProgramData%\Orcel\authority` or `authority-public` already exist (someone may have pre-created them), or if
an existing `%ProgramData%\Orcel` is not owned by SYSTEM or Administrators or lets other users add, delete or
rename entries in it.

## Steps

1. Build, as your normal user (not elevated):

   ```powershell
   cargo build --release -p orcel-authority -p orceld
   ```

2. Preview, elevated (changes nothing):

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\install-orcel-authority.ps1 -WhatIf
   ```

   Optional: `-BinaryDir <dir>` if the binaries are not in `target\release`, and `-OrceldPath <path>` for the
   `orceld.exe` the service should trust for `Authorize` (default `<BinaryDir>\orceld.exe`).

3. Install, elevated:

   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts\install-orcel-authority.ps1
   ```

4. Check, as your normal user (not elevated):

   ```powershell
   Get-Service OrcelAuthority                     # Running, Automatic
   target\release\orceld.exe authority-status    # JSON: "mode":"service", epoch, key_id, "can_issue":true
   Get-ChildItem C:\ProgramData\Orcel\authority  # must fail: access denied
   Get-Content C:\ProgramData\Orcel\authority-public\lease-signing-key.json   # readable public key
   Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -eq Orcel
   ```

   `authority-status` verifies the server before it sends anything: the pipe's server process must be the
   service's process from the SCM, and the pipe's owner must be the `NT SERVICE\OrcelAuthority` SID. The Event
   Log should show an event 4100 anchor (`orcel-anchor/1|authority|audit.jsonl|1|...`) written with the service
   account as its user.

## What to verify by hand (cannot be shown by tests before install)

- **The state is unreadable**: step 4's `Get-ChildItem` is refused for your account.
- **A pre-created pipe name stops the service**: optional. Stop the service, create `\\.\pipe\orcel-authority`
  from a user process, start the service: it must fail to start and write an error event 4103
  (`refused-start|the pipe name ... already exists`). Then end that process and start the service again.
- **DPAPI under the virtual account**: the service started at all means it created and stored its signing key;
  restart it (`Restart-Service OrcelAuthority`) and check `key_id` in `authority-status` stays the same.
- **The confirmation can reach your session**: slice 1 has no grant client yet (the CLI's `enroll` and
  `grant` are slice 2), so this is checked in slice 2. If the virtual account lacks the right to send a message
  to the console session, event 4102 records `confirmation-failed` and nothing is issued.

## Uninstall

Elevated:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install-orcel-authority.ps1 -Uninstall
```

Add `-KeepState` to keep `%ProgramData%\Orcel\authority` (the audit chain, the leases and the DPAPI-wrapped
signing key) for inspection; delete it later from an elevated shell. After uninstall, Full Control answers
`AUTHORITY_UNAVAILABLE` again and nothing else in Orcel changes.

## Update after a rebuild

The service runs the copy in `%ProgramFiles%\Orcel\Authority`. To update it and keep its state (epoch,
revocation counter, audit chain, signing key), elevated:

```powershell
Stop-Service OrcelAuthority
Copy-Item target\release\orcel-authority.exe "$env:ProgramFiles\Orcel\Authority\" -Force
Start-Service OrcelAuthority
```

A full `-Uninstall` followed by an install starts over with a new key and epoch 1; leases from before are gone.
