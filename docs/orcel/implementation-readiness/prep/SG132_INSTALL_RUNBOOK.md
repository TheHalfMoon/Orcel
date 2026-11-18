# SG-000132 slice 1: installing the Orcel authority service (founder runbook)

This runbook is for the founder. The founder runs every step here on the PC that runs Orcel, from an elevated
PowerShell where it says so. Agents do not run the install, do not trigger UAC and make no registry, ACL or
service changes. The design and its limits are in [SG132_SLICE1.md](SG132_SLICE1.md).

What the install gives you: the service holds the key, epoch, revocation counter and audit out of your
session's reach, and orceld can check its status. With slice 2 ([SG132_SLICE2.md](SG132_SLICE2.md)) you then
enroll a TPM-attested Windows Hello key from an elevated terminal and grant leases through the service; see
"After install" below.

## Before you start: how you work daily

An agent that runs elevated owns the machine, the authority service included. Do your daily work, and run
Orcel and its agents, on a standard (non-administrator) account, or at least set User Account Control to
"Always notify" so no process of yours elevates silently. Elevate only for steps of this runbook.

## What the install changes on the PC

`scripts/install-orcel-authority.ps1` makes exactly these system changes, and `-Uninstall` reverses them:

| # | Change | Where | Reversed by `-Uninstall` |
| --- | --- | --- | --- |
| 1 | Copies the hash-verified `orcel-authority.exe` and `orceld.exe` (hashes checked before and after copying) | `%ProgramFiles%\Orcel\Authority\orcel-authority.exe`, `%ProgramFiles%\Orcel\orceld.exe` | Deleted |
| 2 | SCM registration: service `OrcelAuthority`, "Orcel Authority", own process, automatic start, account `NT SERVICE\OrcelAuthority` (virtual account, no password), SID type unrestricted, privileges `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege`, `SeCreateGlobalPrivilege` only, restart on failure | Service Control Manager | Stopped (waited for), deleted |
| 3 | Only if missing: `%ProgramData%\Orcel`, created with its security in one call: owner Administrators, protected DACL (SYSTEM and Administrators full control, Users read and execute) | `%ProgramData%\Orcel` | Deleted if this script created it and it is empty |
| 4 | State directory created with its security in one call: owner Administrators, protected DACL with SYSTEM, Administrators and the service full control, no access for users; `config.json` trusting only `%ProgramFiles%\Orcel\orceld.exe` | `%ProgramData%\Orcel\authority` | Deleted (kept with `-KeepState`) |
| 5 | Public key directory created the same way: SYSTEM and Administrators full control, the service modify, Users read and execute | `%ProgramData%\Orcel\authority-public` | Deleted |
| 6 | Event Log source `Orcel` in the Application log, unless it exists (marked `OrcelInstalledBy`) | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel` | Removed only if this script created it |
| 7 | Starts the service; Windows may create a profile for the virtual account (it holds the account's DPAPI keys) | SCM, user profiles | Profile removed (`Win32_UserProfile`) |

The script reads back the owner and DACL of every directory it creates and stops on any difference. It refuses
to run, with nothing changed, if a hash does not match, the service already exists,
`%ProgramData%\Orcel\authority` or `authority-public` already exist (someone may have pre-created them), or an
existing `%ProgramData%\Orcel` is not owned by SYSTEM or Administrators or lets other users add, delete or rename
entries in it. What uninstall leaves: events already written to the Application log.

## Steps

1. **Get hash-pinned binaries.** Either:
   - **CI artifact from main only.** Use only a run of workflow CI, job "Authority service artifact", whose
     event is a `push` to `main` of `TheHalfMoon/Orcel` (or a manual `workflow_dispatch` on `main`) and whose
     commit is the reviewed head now on `main`. The job does not run for pull requests; an artifact from any
     other run (a pull request, a fork, another branch) is untrusted, whatever it contains. Open that job's
     log on github.com, step "Record the SHA-256 of each binary", and copy the two `AUTHORITY-ARTIFACT
     <sha256>  <file>` lines and the `commit` line from the log: these are your expected values. Then download
     the `orcel-authority-windows-x64` artifact into an admin-only folder. Do not take the expected hashes from
     the `SHA256SUMS.txt` inside the zip; it only has to agree with the log. Or:
   - **Admin-only build.** Clone the reviewed commit into a folder only administrators can write (for example
     `C:\OrcelBuild`, created from an elevated shell), build there with
     `cargo build --release --locked -p orcel-authority -p orceld`, and take the hashes with
     `Get-FileHash -Algorithm SHA256`.

   Never install from the repository's `target` directory in your user profile: any process running as you
   could replace those files between the build and the install.

2. **Check the script itself.** Copy `scripts\install-orcel-authority.ps1` from the reviewed commit to an
   admin-only folder and compare its hash with the reviewed commit's copy
   (`git show <commit>:scripts/install-orcel-authority.ps1 | Out-File ...` then `Get-FileHash`). The script
   prints its own SHA-256 as its first line; compare that too.

3. **Preview** (changes nothing; it also runs unelevated, under Windows PowerShell 5.1 or PowerShell 7):

   ```powershell
   powershell -ExecutionPolicy Bypass -File C:\OrcelBuild\install-orcel-authority.ps1 -WhatIf `
     -ArtifactDir C:\OrcelBuild\artifact -AuthoritySha256 <sha256> -OrceldSha256 <sha256>
   ```

4. **Install, elevated:** the same command without `-WhatIf`.

5. **Check, as your normal user (not elevated):**

   ```powershell
   Get-Service OrcelAuthority                                   # Running, Automatic
   & "$env:ProgramFiles\Orcel\orceld.exe" authority-status      # "mode":"service", epoch, key_id
   Get-ChildItem C:\ProgramData\Orcel\authority                 # must fail: access denied
   Get-Content C:\ProgramData\Orcel\authority-public\lease-signing-key.json
   Get-WinEvent -LogName Application -MaxEvents 20 | Where-Object ProviderName -eq Orcel
   ```

   `authority-status` verifies the server before it sends anything: the pipe's server process must be the
   service's process from the SCM, and the pipe's owner must be the `NT SERVICE\OrcelAuthority` SID. Event 4100
   anchors (`orcel-anchor/1|authority|audit.jsonl|1|...|sig=...`) carry the service account as their user and a
   signature by the lease key; the public key in `authority-public` verifies them.

## After install: enroll, then a first grant (slice 2)

6. **Check the pinned TPM root** (not elevated): `Get-ChildItem Cert:\LocalMachine\CA | Where-Object Thumbprint
   -eq D4FFDB19BA590FFFAA34DB5F4B568706A2978436`; its SHA-256 (`[Security.Cryptography.SHA256]::Create().
   ComputeHash($cert.RawData)`) must be `870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da`,
   the Microsoft TPM Root Certificate Authority 2014 Microsoft publishes. `orcel authority status` must say
   `enrollment available true`.
7. **Enroll, elevated:** `orcel authority enroll`. Windows Hello asks you to create the key. The command prints
   a one-time code and the key fingerprint; the Orcel Authority box must show both. Choose Yes only if they
   match; Windows Hello asks once more. If the command says the key cannot be attested, enrollment stays
   refused by design; report the message.
8. **First grant, not elevated:** `orcel full-control grant` (desktop input only, 30 minutes). Lock (Win+L)
   and unlock within 5 minutes; the box shows the code, the process and the scope; Yes; Windows Hello. Then
   `orcel full-control status` and `orceld authority-status`.
9. **Browser Full Access:** `orcel browser grant --session <bs-...> --client-ref <cl-...> --origin
   https://<site>` with the values `browser_session_create` returned.
10. **Event Viewer** (Application, source Orcel): 4102 (intents), 4104 (enrollment), 4101 (granted scope).

Replacing the key: `orcel authority enroll --replace`; removing it: `orcel authority reset` (both elevated,
both confirmed in the service's box, both end your leases).

## The one-time code is a link, not a secret

`orcel full-control grant` prints a one-time code, and the Orcel Authority box shows the code of
the intent it is confirming. The code links the box to the command you just ran; it is not a secret. A process
running as you can read your console or the screen through UI Automation, and it can take the session's single
pending-intent slot first, in which case your command is refused and a box for its request appears instead.
Refuse (choose No on) any confirmation whose code you did not just start yourself in that terminal, or whose
requesting process is not your command. Windows Hello (attested and enrolled from an elevated caller)
is the real gate; the code only helps you spot a box you did not ask for.

## What to verify by hand

- **The state is unreadable**: step 5's `Get-ChildItem` is refused for your account.
- **The trusted orceld path is protected**: the service refuses to start if `config.json` names an orceld
  outside `%ProgramFiles%\Orcel\`, one a non-administrator could replace, or a path with a junction, symbolic
  link or mount point on it (event 4103 says which). It applies the same check to its own
  `orcel-authority.exe`. The install also refuses a pre-existing `%ProgramFiles%\Orcel` (or `Authority`
  folder) not owned by SYSTEM, Administrators or TrustedInstaller, or one that lets other users change entries. Only the
  `%ProgramFiles%\Orcel\orceld.exe` copy is trusted for `Authorize`; an orceld run from the repository is an
  ordinary interactive caller.
- **A pre-created pipe name stops the service** (optional): stop the service, create `\\.\pipe\orcel-authority`
  from a user process, start the service: it must fail and write error event 4103. End that process, start again.
- **DPAPI under the virtual account**: `Restart-Service OrcelAuthority`, then `key_id` in `authority-status`
  must be unchanged.
- **A missing key is not replaced**: if `lease-signing.key` is ever missing while the audit chain has records,
  the service refuses to start rather than create a new key; restore the key or reset the state deliberately.

## Recovery

The service restarts automatically after a failure, twice within a day; after that it stays stopped and Full
Control answers `AUTHORITY_UNAVAILABLE` (it fails closed, nothing else in Orcel changes). Read events 4103 and
the System log, fix the cause, then `Start-Service OrcelAuthority` elevated. A broken audit chain, a missing
state file or a missing key with audit history are refusals by design: inspect before resetting.

## Update after a rebuild

Repeat steps 1 and 2 for the new commit, then elevated: `-Uninstall -KeepState` and the install again with the
new hashes (the install refuses an existing state directory, so move the kept one back only after you have
inspected it), or a full `-Uninstall` and install to start over with a new key and epoch 1.

## Uninstall

Elevated: `powershell -ExecutionPolicy Bypass -File C:\OrcelBuild\install-orcel-authority.ps1 -Uninstall`.
Add `-KeepState` to keep `%ProgramData%\Orcel\authority` (audit chain, leases, DPAPI-wrapped key) for inspection.
The virtual account's profile is removed with its DPAPI keys, so a kept key can no longer be unwrapped by a
reinstalled service; keep it only as evidence.
