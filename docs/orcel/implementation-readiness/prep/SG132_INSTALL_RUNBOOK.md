# SG-000132 slice 1: installing the Orcel authority service (founder runbook)

This runbook is for the founder. The founder runs every step here on the PC that runs Orcel. Steps marked
elevated are started as "How every elevated step is started" says, never from an elevated terminal. Agents do not run the install, do not trigger UAC and make no registry, ACL or
service changes. The design and its limits are in [SG132_SLICE1.md](SG132_SLICE1.md).

What the install gives you: the service holds the key, epoch, revocation counter and audit out of your
session's reach, and orceld can check its status. With slice 2 ([SG132_SLICE2.md](SG132_SLICE2.md)) you then
enroll a TPM-attested Windows Hello key with the elevated, installed `orcel.exe` and grant leases through the service; see
"After install" below.

## Before you start: how you work daily

An agent that runs elevated owns the machine, the authority service included. Set User Account Control to
"Always notify" (Control Panel, User Account Control settings, top position): enrollment and reset are REFUSED
unless `EnableLUA` is 1, `ConsentPromptBehaviorAdmin` is 2 and `PromptOnSecureDesktop` is 1 (the service reads
them, read-only, and `orcel authority status` shows them). Elevate only for steps of this runbook. A standard
account that elevates with a separate administrator's credentials is NOT supported in slice 2: the elevated
process runs as the administrator, so the key would be enrolled for the administrator, not for you, and your
grants would find no key (refused). Use your administrator account with "Always notify".

## How every elevated step is started

Never run an elevated step from an elevated terminal you opened, and never from an elevated shell that loads
your PowerShell profile: a profile, a module or a terminal extension that a process running as you planted
would then run elevated. From your NORMAL (not elevated) PowerShell, start the one program directly, so the
UAC prompt on the secure desktop names that program:

```powershell
# A verified script (the install, the uninstall):
Start-Process -Verb RunAs -Wait -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','C:\OrcelBuild\install-orcel-authority.ps1', <arguments>
# The installed owner CLI (enroll, reset):
Start-Process -Verb RunAs -FilePath "$env:ProgramFiles\Orcel\orcel.exe" -ArgumentList 'authority','enroll','--pause'
```

The UAC prompt must name Windows PowerShell (for the script) or `orcel.exe` from `C:\Program Files\Orcel`
(for enroll and reset); choose No for anything else. `--pause` keeps the window open until you press Enter.


## What the install changes on the PC

`scripts/install-orcel-authority.ps1` makes exactly these system changes, and `-Uninstall` reverses them:

| # | Change | Where | Reversed by `-Uninstall` |
| --- | --- | --- | --- |
| 1 | Copies the hash-verified `orcel-authority.exe`, `orceld.exe` and `orcel.exe` (hashes checked before and after copying) | `%ProgramFiles%\Orcel\Authority\orcel-authority.exe`, `%ProgramFiles%\Orcel\orceld.exe`, `%ProgramFiles%\Orcel\orcel.exe` | Deleted |
| 2 | SCM registration: service `OrcelAuthority`, "Orcel Authority", own process, automatic start, account `NT SERVICE\OrcelAuthority` (virtual account, no password), SID type unrestricted, privileges `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege`, `SeCreateGlobalPrivilege` only, restart on failure | Service Control Manager | Stopped (waited for), deleted |
| 3 | Only if missing: `%ProgramData%\Orcel`, created with its security in one call: owner Administrators, protected DACL (SYSTEM and Administrators full control, Users read and execute) | `%ProgramData%\Orcel` | Deleted if this script created it and it is empty |
| 4 | State directory created with its security in one call: owner Administrators, protected DACL with SYSTEM, Administrators and the service full control, no access for users; `config.json` trusting only `%ProgramFiles%\Orcel\orceld.exe` (Authorize) and `%ProgramFiles%\Orcel\orcel.exe` (grant, enrollment and reset intents) | `%ProgramData%\Orcel\authority` | Deleted (kept with `-KeepState`) |
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
     log on github.com, step "Record the SHA-256 of each binary", and copy the three `AUTHORITY-ARTIFACT
     <sha256>  <file>` lines and the `commit` line from the log: these are your expected values. Then download
     the `orcel-authority-windows-x64` artifact into an admin-only folder. Do not take the expected hashes from
     the `SHA256SUMS.txt` inside the zip; it only has to agree with the log. Or:
   - **Admin-only build.** Clone the reviewed commit into a folder only administrators can write (for example
     `C:\OrcelBuild`, created directly with `Start-Process -Verb RunAs -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d','/c','mkdir','C:\OrcelBuild'`, where `/d` skips cmd AutoRun), build there with
     `cargo build --release --locked -p orcel-authority -p orceld -p orcel-lifecycle --bin orcel-authority --bin orceld --bin orcel`, and take the hashes with
     `Get-FileHash -Algorithm SHA256`.

   Never install from the repository's `target` directory in your user profile: any process running as you
   could replace those files between the build and the install.

2. **Check the script itself.** Copy `scripts\install-orcel-authority.ps1` from the reviewed commit to an
   admin-only folder and compare its hash with the reviewed commit's copy
   (`git show <commit>:scripts/install-orcel-authority.ps1 | Out-File ...` then `Get-FileHash`). The script
   prints its own SHA-256 as its first line; compare that too.

3. **Preview** (changes nothing; it also runs unelevated, under Windows PowerShell 5.1 or PowerShell 7):

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File C:\OrcelBuild\install-orcel-authority.ps1 -WhatIf `
     -ArtifactDir C:\OrcelBuild\artifact -AuthoritySha256 <sha256> -OrceldSha256 <sha256> -OrcelSha256 <sha256>
   ```

4. **Install, elevated** (started directly, see above):

   ```powershell
   Start-Process -Verb RunAs -Wait -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
     -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','C:\OrcelBuild\install-orcel-authority.ps1',
       '-ArtifactDir','C:\OrcelBuild\artifact','-AuthoritySha256','<sha256>','-OrceldSha256','<sha256>','-OrcelSha256','<sha256>'
   ```

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
   `enrollment available true` and `UAC always notify on secure desktop true`.
7. **Enroll, elevated, started directly:** `Start-Process -Verb RunAs -FilePath "$env:ProgramFiles\Orcel\orcel.exe"
   -ArgumentList 'authority','enroll','--pause'`. The UAC prompt must name `orcel.exe` in `C:\Program
   Files\Orcel`. Windows Hello asks you to create the key (a PIN or fingerprint is recommended over face
   recognition). The window prints a one-time code and the key fingerprint; the Orcel Authority box must show
   both. Choose Yes only if they match; Windows Hello asks once more. If the window says the key cannot be
   attested, enrollment stays refused by design; report the message.
8. **First grant, not elevated:** `& "$env:ProgramFiles\Orcel\orcel.exe" full-control grant` (desktop input
   only, 30 minutes; only the installed `orcel.exe` may record an intent). Lock (Win+L)
   and unlock within 5 minutes; the box shows the code, the process and the scope; Yes; Windows Hello. Then
   `orcel full-control status` and `orceld authority-status`.
9. **Browser Full Access:** `& "$env:ProgramFiles\Orcel\orcel.exe" browser grant --session <bs-...> --client-ref <cl-...> --origin
   https://<site>` with the values `browser_session_create` returned.
10. **Event Viewer** (Application, source Orcel): 4102 (intents), 4104 (enrollment), 4101 (granted scope).

Replacing the key: `authority enroll --replace --pause`; removing it: `authority reset --pause` (both started
elevated and directly as in step 7, both confirmed in the service's box, both end your leases). A replacement
creates the new key beside the enrolled one; the enrolled key is deleted from Windows Hello only after the
service enrolled the new one. A process running as you can delete your Windows Hello keys: grants then fail
closed (no key to sign), and you enroll again.

## The one-time code is a link, not a secret

`orcel full-control grant` prints a one-time code, and the Orcel Authority box shows the code of
the intent it is confirming. The code links the box to the command you just ran; it is not a secret. A process
running as you can read your console or the screen through UI Automation, and it can take the session's single
pending-intent slot first, in which case your command is refused and a box for its request appears instead.
Refuse (choose No on) any confirmation whose code you did not just start yourself in that terminal, or whose
requesting process is not your command. The human gate is your Yes in the service's box after an unlock the
service observed. Windows Hello is not an independent gate: it shows that someone is at the PC and that the
enrolled key signs, and the attestation cannot prove the key needs a gesture (see SG132_SLICE2.md). The code
only helps you spot a box you did not ask for.

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
the System log, fix the cause, then start it elevated and directly: `Start-Process -Verb RunAs -FilePath "$env:SystemRoot\System32\sc.exe" -ArgumentList 'start','OrcelAuthority'`. A broken audit chain, a missing
state file or a missing key with audit history are refusals by design: inspect before resetting.

## Update after a rebuild

Repeat steps 1 and 2 for the new commit, then, each started elevated and directly as above: `-Uninstall -KeepState` and the install again with the
new hashes (the install refuses an existing state directory, so move the kept one back only after you have
inspected it), or a full `-Uninstall` and install to start over with a new key and epoch 1.

## Uninstall

Elevated, started directly: `Start-Process -Verb RunAs -Wait -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-NoExit','-File','C:\OrcelBuild\install-orcel-authority.ps1','-Uninstall'`.
Add `-KeepState` to keep `%ProgramData%\Orcel\authority` (audit chain, leases, DPAPI-wrapped key) for inspection.
The virtual account's profile is removed with its DPAPI keys, so a kept key can no longer be unwrapped by a
reinstalled service; keep it only as evidence.
