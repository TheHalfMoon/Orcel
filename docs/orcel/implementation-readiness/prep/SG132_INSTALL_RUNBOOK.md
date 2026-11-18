# SG-000132: installing the Orcel authority service (founder runbook)

This runbook is for the founder, and it is the one supported installation procedure. The founder runs every
step on the PC that runs Orcel. Agents do not run the install on any PC, do not trigger UAC and make no
registry, ACL or service changes there. CI runs this same procedure, with these exact command lines, on a
disposable GitHub-hosted runner for every change (job "Authority install E2E", see the end of this file).
The design and its limits are in [SG132_SLICE1.md](SG132_SLICE1.md) and [SG132_SLICE2.md](SG132_SLICE2.md).

What the install gives you: the service holds the key, epoch, revocation counter and audit out of your
session's reach, and orceld can check its status. With slice 2 you then enroll a TPM-attested Windows Hello key
with the elevated, installed `orcel.exe` and grant leases through the service ("After install" below).

## The rules this procedure enforces

1. **Nothing an elevated step consumes can be changed by a standard user.** The install script and the three
   binaries are staged in `C:\Program Files\OrcelStaging`, a folder the Stage step creates in one call with an
   explicit, protected DACL (owner Administrators; SYSTEM and Administrators full control; Users read and
   execute only; nothing inherited). The installer refuses to run, with nothing changed, unless
   its own file, its folder, the artifact folder, every binary and every parent folder up to `C:\` are owned by
   SYSTEM, Administrators or TrustedInstaller, contain no junction, symbolic link or mount point, and grant no
   other account a right to change them. A folder made with a plain `mkdir C:\...` is refused: `C:\` gives
   Authenticated Users modify rights on everything created under it, so every user could replace the files.
2. **Only the reviewed commit's bytes are installed.** You check each file's build provenance with
   `gh attestation verify` (built by this repository's `ci.yml` on `main`, from the commit you reviewed) and
   its SHA-256 against the job log. The Stage step refuses an install script whose SHA-256 differs from the
   value on its command line; the installer refuses any binary whose SHA-256 differs from the values on its
   command line, and it hashes and copies each binary through one handle that blocks writes and deletes.
3. **Every elevated program and command line is checked on the UAC prompt**, not in your shell (below).

## Before you start

- **UAC "Always notify".** An agent that runs elevated owns the machine, the authority service included. Set
  User Account Control to "Always notify" (Control Panel, User Account Control settings, top position):
  enrollment and reset are REFUSED unless `EnableLUA` is 1, `ConsentPromptBehaviorAdmin` is 2 and
  `PromptOnSecureDesktop` is 1 (the service reads them, read-only, and `orcel authority status` shows them).
  Elevate only for steps of this runbook. A standard account that elevates with a separate administrator's
  credentials is NOT supported: the elevated process runs as the administrator, so the key would be enrolled
  for the administrator, not for you, and your grants would find no key (refused). Use your administrator
  account with "Always notify". The built-in Administrator account (SID ending in `-500`) elevates without a
  prompt unless `FilterAdministratorToken` is 1; the service refuses enrollment and reset from it otherwise.
- **GitHub CLI** (`gh`) signed in, for downloading the artifact and verifying its attestation.
- **A second device** (phone or another PC) for reading the job log and the commit on github.com. A process
  running as you could change what your own browser or shell shows; the values you type into the UAC-checked
  command lines are only as good as where you read them.

## How every elevated step is started, and the check on every UAC prompt

Never run an elevated step from an elevated terminal, and never from an elevated shell that loads your
PowerShell profile. From your NORMAL (not elevated) PowerShell, start the one program directly with
`Start-Process -Verb RunAs`, using the lines below with your values in the `<...>` places.

Your normal shell runs as you, so a program running as you could change what it starts. The check that does
not depend on your shell is the UAC prompt itself, drawn on the secure desktop. **On every UAC prompt:**

1. Select **Show more details**.
2. Read **Program location**: it must be exactly the program in the table below, and the full command line
   after it must be exactly the one below (your own values in the `<...>` places, nothing added, nothing
   missing).
3. If anything differs, or the prompt names another program, choose **No** and stop. Do not retry from the
   same shell; restart Windows, sign in, and start again.

`orcel.exe` is not code-signed in this slice, so UAC shows it as "Unknown publisher"; the path and command
line check is what identifies it. `-NoExit` and `--pause` only keep the window open so you can read it.

| Step | Program location | Exact command line |
| --- | --- | --- |
| Stage | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -NoExit -Command "$ErrorActionPreference = 'Stop'; $env:PSModulePath = Join-Path $PSHOME 'Modules'; $from = '<download-folder>'; $d = Join-Path $env:ProgramFiles 'OrcelStaging'; if (Test-Path -LiteralPath $d) { throw ($d + ' already exists; nothing was changed') }; $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)'); [void][IO.Directory]::CreateDirectory($d, $s); foreach ($n in 'install-orcel-authority.ps1', 'orcel-authority.exe', 'orceld.exe', 'orcel.exe') { $t = Join-Path $d $n; Copy-Item -LiteralPath (Join-Path $from $n) -Destination $t; $f = Get-Item -LiteralPath $t; $a = $f.GetAccessControl('Owner'); $a.SetOwner([Security.Principal.SecurityIdentifier]'S-1-5-32-544'); $f.SetAccessControl($a) }; if ((Get-FileHash -LiteralPath (Join-Path $d 'install-orcel-authority.ps1')).Hash -ne '<script-sha256>') { Remove-Item -LiteralPath $d -Recurse -Force; throw 'the staged install script does not match the expected SHA-256; the staging folder was removed' }; icacls $d; icacls (Join-Path $d '*')"` |
| Install | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -ArtifactDir "C:\Program Files\OrcelStaging" -AuthoritySha256 <authority-sha256> -OrceldSha256 <orceld-sha256> -OrcelSha256 <orcel-sha256>` |
| Uninstall | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -Uninstall -RemoveStaging` |
| Uninstall, keeping the state | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | `"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -Uninstall -KeepState -RemoveStaging` |
| Start the service | `C:\Windows\System32\sc.exe` | `"C:\Windows\System32\sc.exe" start OrcelAuthority` |
| Enroll | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" authority enroll --pause` |
| Replace the key | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" authority enroll --replace --pause` |
| Reset | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" authority reset --pause` |

What the Stage line does, so you can read it on the prompt: it loads PowerShell modules only from Windows'
own folder ($PSHOME\Modules; your Documents module folder is writable by anything running as you); stops if `C:\Program Files\OrcelStaging`
exists; creates it in one call with owner Administrators and the protected DACL
`O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)` (`FA` full control,
`0x1200a9` read and execute, nothing for anyone else); copies the four files from `<download-folder>` into it (they inherit that DACL); makes
Administrators their owner; deletes the folder again and stops if the install script's SHA-256 is not
`<script-sha256>`; and prints the folder's and the files' ACLs.

The `Start-Process` lines that produce exactly these command lines (CI runs these lines' command lines):

```powershell
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -Command "$ErrorActionPreference = ''Stop''; $env:PSModulePath = Join-Path $PSHOME ''Modules''; $from = ''<download-folder>''; $d = Join-Path $env:ProgramFiles ''OrcelStaging''; if (Test-Path -LiteralPath $d) { throw ($d + '' already exists; nothing was changed'') }; $s = New-Object Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm(''O:BAG:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)''); [void][IO.Directory]::CreateDirectory($d, $s); foreach ($n in ''install-orcel-authority.ps1'', ''orcel-authority.exe'', ''orceld.exe'', ''orcel.exe'') { $t = Join-Path $d $n; Copy-Item -LiteralPath (Join-Path $from $n) -Destination $t; $f = Get-Item -LiteralPath $t; $a = $f.GetAccessControl(''Owner''); $a.SetOwner([Security.Principal.SecurityIdentifier]''S-1-5-32-544''); $f.SetAccessControl($a) }; if ((Get-FileHash -LiteralPath (Join-Path $d ''install-orcel-authority.ps1'')).Hash -ne ''<script-sha256>'') { Remove-Item -LiteralPath $d -Recurse -Force; throw ''the staged install script does not match the expected SHA-256; the staging folder was removed'' }; icacls $d; icacls (Join-Path $d ''*'')"'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -ArtifactDir "C:\Program Files\OrcelStaging" -AuthoritySha256 <authority-sha256> -OrceldSha256 <orceld-sha256> -OrcelSha256 <orcel-sha256>'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -Uninstall -RemoveStaging'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -Uninstall -KeepState -RemoveStaging'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'start OrcelAuthority'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'authority enroll --pause'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'authority enroll --replace --pause'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'authority reset --pause'
```

In the Stage line, `<download-folder>` must not contain a single quote. Explorer's **Run as administrator**
passes no arguments, and every step above needs them, so do not use Explorer for these steps.

## What the install changes on the PC

`install-orcel-authority.ps1` makes exactly these system changes, and `-Uninstall` reverses them:

| # | Change | Where | Reversed by `-Uninstall` |
| --- | --- | --- | --- |
| 1 | Copies the hash-verified `orcel-authority.exe`, `orceld.exe` and `orcel.exe` (each hashed and copied through one handle that blocks writes and deletes, and the copy hashed again) | `%ProgramFiles%\Orcel\Authority\orcel-authority.exe`, `%ProgramFiles%\Orcel\orceld.exe`, `%ProgramFiles%\Orcel\orcel.exe` | Deleted |
| 2 | SCM registration: service `OrcelAuthority`, "Orcel Authority", own process, automatic start, account `NT SERVICE\OrcelAuthority` (virtual account, no password), SID type unrestricted, privileges `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege`, `SeCreateGlobalPrivilege` only, restart on failure | Service Control Manager | Stopped (waited for), deleted |
| 3 | Only if missing: `%ProgramData%\Orcel`, created with its security in one call: owner Administrators, protected DACL (SYSTEM and Administrators full control, Users read and execute) | `%ProgramData%\Orcel` | Deleted if this script created it and it is empty |
| 4 | State directory created with its security in one call: owner Administrators, protected DACL with SYSTEM, Administrators and the service full control, no access for users; `config.json` trusting only `%ProgramFiles%\Orcel\orceld.exe` (Authorize) and `%ProgramFiles%\Orcel\orcel.exe` (grant, enrollment and reset intents) | `%ProgramData%\Orcel\authority` | Deleted (kept with `-KeepState`) |
| 5 | Public key directory created the same way: SYSTEM and Administrators full control, the service modify, Users read and execute | `%ProgramData%\Orcel\authority-public` | Deleted |
| 6 | Event Log source `Orcel` in the Application log, unless it exists (marked `OrcelInstalledBy`) | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel` | Removed only if this script created it |
| 7 | Starts the service and waits until it runs and has published its public key; Windows may create a profile for the virtual account (it holds the account's DPAPI keys) | SCM, user profiles | Profile removed (`Win32_UserProfile`); if Windows still holds it loaded, the script prints `PROFILE LEFT` with the command to remove it after a restart |

The script reads back the owner and DACL of every directory it creates and stops on any difference. **If any
step fails, it undoes every change it already made, newest first, and says "every change it made was rolled
back"** (or lists what it could not undo). It refuses to run, with nothing changed, if the location check
fails, a hash does not match, the service already exists, any installed binary already exists,
`%ProgramData%\Orcel\authority` or `authority-public` already exist (someone may have pre-created them), or an
existing `%ProgramFiles%\Orcel` or `%ProgramData%\Orcel` is not admin-owned or lets other users add, delete or
rename entries. `-RemoveStaging` then deletes the four staged files by name and the empty staging folder. What
uninstall leaves: events already written to the Application log.

## The procedure

### 1. Pick the commit and its two CI jobs (second device)

On github.com, open the reviewed pull request's merge commit on `main` of `TheHalfMoon/Orcel`; that commit's
full SHA is `<commit>`. Open the workflow run "CI" for that commit with event `push` (Actions, filter by branch
`main`), or from your shell:

```powershell
gh run list --repo TheHalfMoon/Orcel --workflow ci.yml --branch main --event push --commit <commit>
```

Use only that run (or a manual `workflow_dispatch` run on `main` at that commit). The artifact jobs do not run
for pull requests; an artifact from any other run, branch or fork is untrusted, whatever it contains. In that
run, both of these jobs must have passed:

- **Authority service artifact / windows-latest.** Open its log, step "Record the SHA-256 of each file", and
  write down the four `AUTHORITY-ARTIFACT <sha256>  <file>` lines and the `commit` line (it must be
  `<commit>`). These are `<authority-sha256>` (`orcel-authority.exe`), `<orceld-sha256>` (`orceld.exe`),
  `<orcel-sha256>` (`orcel.exe`) and `<script-sha256>` (`install-orcel-authority.ps1`). Do not take them from
  the `SHA256SUMS.txt` inside the download; it only has to agree with the log. Step "Verify the attestation
  as the runbook does" must show four successful verifications.
- **Authority install E2E / windows-latest.** It ran this procedure on a disposable runner with these same
  bytes (see "What CI proves" below). Its artifact `authority-install-e2e-report` holds
  `authority-install-e2e.json`; its `result` must be `pass`, its `commit` `<commit>`, and its
  `artifact_sha256` the four values you wrote down.

### 2. Download the artifact (normal shell)

```powershell
gh run download <run-id> --repo TheHalfMoon/Orcel --name orcel-authority-windows-x64 --dir <download-folder>
```

`<run-id>` is the run's number from step 1; `<download-folder>` is a new, empty folder, for example
`C:\Users\<you>\Downloads\orcel-authority-<commit>`.

### 3. Verify provenance and hashes (normal shell)

```powershell
foreach ($n in 'install-orcel-authority.ps1', 'orcel-authority.exe', 'orceld.exe', 'orcel.exe') {
  gh attestation verify (Join-Path '<download-folder>' $n) --repo TheHalfMoon/Orcel --signer-workflow TheHalfMoon/Orcel/.github/workflows/ci.yml --source-ref refs/heads/main --source-digest <commit> --deny-self-hosted-runners
  Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path '<download-folder>' $n)
}
```

Each file must report a successful verification (a GitHub-hosted run of `ci.yml` on `refs/heads/main` of
`TheHalfMoon/Orcel` at `<commit>` built it), and each hash must equal the value from the job log. Any failure:
stop. These checks run in your shell, so they guard against a wrong or tampered download, not against a
process running as you; the binding checks are the hashes on the UAC-checked command lines in steps 4 and 6.

### 4. Stage, elevated

Start the **Stage** line of the table above (your `<download-folder>` and `<script-sha256>`), and check the UAC
prompt against the table. The window must end with the ACLs below and no error. If it says the folder already
exists, an earlier staging is still there: uninstall first (it removes the staging), or inspect the folder.

### 5. Check the staging folder's ACL (normal shell)

```powershell
icacls "C:\Program Files\OrcelStaging"
icacls "C:\Program Files\OrcelStaging\*"
Get-ChildItem -Force 'C:\Program Files\OrcelStaging' | ForEach-Object { '{0} {1}' -f $_.Name, (Get-Acl -LiteralPath $_.FullName).Owner }
Get-Acl -LiteralPath 'C:\Program Files\OrcelStaging' | ForEach-Object { '{0} protected={1}' -f $_.Owner, $_.AreAccessRulesProtected }
```

Expected output, line by line (column spacing may differ; on a Windows display language other than English the
account names are translated). The files carry the folder's three entries; `(OI)(CI)` on the folder makes new files get them too:

<!-- expected-staging-acl -->
```text
C:\Program Files\OrcelStaging NT AUTHORITY\SYSTEM:(OI)(CI)(F)
BUILTIN\Administrators:(OI)(CI)(F)
BUILTIN\Users:(OI)(CI)(RX)
Successfully processed 1 files; Failed processing 0 files
C:\Program Files\OrcelStaging\install-orcel-authority.ps1 NT AUTHORITY\SYSTEM:(F)
BUILTIN\Administrators:(F)
BUILTIN\Users:(RX)
C:\Program Files\OrcelStaging\orcel-authority.exe NT AUTHORITY\SYSTEM:(F)
BUILTIN\Administrators:(F)
BUILTIN\Users:(RX)
C:\Program Files\OrcelStaging\orcel.exe NT AUTHORITY\SYSTEM:(F)
BUILTIN\Administrators:(F)
BUILTIN\Users:(RX)
C:\Program Files\OrcelStaging\orceld.exe NT AUTHORITY\SYSTEM:(F)
BUILTIN\Administrators:(F)
BUILTIN\Users:(RX)
Successfully processed 4 files; Failed processing 0 files
install-orcel-authority.ps1 BUILTIN\Administrators
orcel-authority.exe BUILTIN\Administrators
orcel.exe BUILTIN\Administrators
orceld.exe BUILTIN\Administrators
BUILTIN\Administrators protected=True
```

Any other entry (Authenticated Users, Everyone, INTERACTIVE, your own account, CREATOR OWNER, OWNER RIGHTS), a missing
`protected=True`, or another owner: stop, and uninstall or delete the folder elevated. The installer makes the
same check itself before it changes anything.

### 6. Preview (changes nothing; not elevated)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "C:\Program Files\OrcelStaging\install-orcel-authority.ps1" -WhatIf -ArtifactDir "C:\Program Files\OrcelStaging" -AuthoritySha256 <authority-sha256> -OrceldSha256 <orceld-sha256> -OrcelSha256 <orcel-sha256>
```

It prints the location check, the three hashes and every planned change.

### 7. Install, elevated

Start the **Install** line of the table above with your three hashes, and check the UAC prompt against the
table. The window must end with the service `Running`. On a failure it says what failed and that every change
was rolled back.

### 8. Check, as your normal user (not elevated)

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

9. **Check the pinned TPM root** (not elevated):

   ```powershell
   $cert = Get-ChildItem Cert:\LocalMachine\CA, Cert:\LocalMachine\Root | Where-Object Subject -eq 'CN=Microsoft TPM Root Certificate Authority 2014, O=Microsoft Corporation, L=Redmond, S=Washington, C=US' | Select-Object -First 1
   $cert.Thumbprint
   -join ([Security.Cryptography.SHA256]::Create().ComputeHash($cert.RawData) | ForEach-Object { $_.ToString('x2') })
   ```

   The thumbprint must be `D4FFDB19BA590FFFAA34DB5F4B568706A2978436` and the SHA-256
   `870c7a35ceab3d59979f2c6a524042d404cb71518004350925fb2ced79a999da`, the value pinned in
   `crates/orcel-authority/src/attestation.rs`. Compare both with the certificate Microsoft publishes for the
   Microsoft TPM Root Certificate Authority 2014 (on your second device). The service trusts an attestation
   chain only if it ends at a certificate with exactly that SHA-256: a certificate someone adds to a store
   under the same name is not trusted (test `tpm_root_lookalike_named_like_microsofts_is_refused`), and CI checks
   that the root found by name on the runner, when present, has the pinned hash. `orcel authority status`
   must say `enrollment available true` and `UAC always notify on secure desktop true`.
10. **Enroll, elevated, started directly:** the Enroll line of the table above. Check **Show more details** on
    the UAC prompt: `"C:\Program Files\Orcel\orcel.exe" authority enroll --pause` exactly, else No. Windows
    Hello asks you to create the key (a PIN or fingerprint is recommended over face recognition). The window
    prints a one-time code and the key fingerprint; the Orcel Authority box must show both. Choose Yes only if
    they match; Windows Hello asks once more. If the window says the key cannot be attested, enrollment stays
    refused by design; report the message.
11. **First grant, not elevated:** `& "$env:ProgramFiles\Orcel\orcel.exe" full-control grant` (desktop input
    only, 30 minutes; only the installed `orcel.exe` may record an intent). Lock (Win+L) and unlock within 5
    minutes; the box shows the code, the process and the scope; Yes; Windows Hello. Then
    `orcel full-control status` and `orceld authority-status`.
12. **Revoke:** `& "$env:ProgramFiles\Orcel\orcel.exe" full-control revoke`; `orcel full-control status` must
    list no active lease, and `orceld authority-status` a higher epoch.
13. **Browser Full Access:** `& "$env:ProgramFiles\Orcel\orcel.exe" browser grant --session <bs-...>
    --client-ref <cl-...> --origin https://<site>` with the values `browser_session_create` returned.
14. **Event Viewer** (Application, source Orcel): 4102 (intents), 4104 (enrollment), 4101 (granted scope).

Replacing the key: the "Replace the key" line; removing it: the "Reset" line (both started elevated and
directly as in step 10, both confirmed in the service's box, both end your leases). A replacement creates the
new key beside the enrolled one; the enrolled key is deleted from Windows Hello only after the service enrolled
the new one. A process running as you can delete your Windows Hello keys: grants then fail closed (no key to
sign), and you enroll again.

## The one-time code is a link, not a secret

`orcel full-control grant` prints a one-time code, and the Orcel Authority box shows the code of the intent it
is confirming. The code links the box to the command you just ran; it is not a secret. A process running as
you can read your console or the screen through UI Automation, and it can take the session's single
pending-intent slot first, in which case your command is refused and a box for its request appears instead.
Refuse (choose No on) any confirmation whose code you did not just start yourself in that terminal, or whose
requesting process is not your command. The human gate is your Yes in the service's box after an unlock the
service observed. Windows Hello is not an independent gate: it shows that someone is at the PC and that the
enrolled key signs, and the attestation cannot prove the key needs a gesture (see SG132_SLICE2.md). The code
only helps you spot a box you did not ask for.

## What to verify by hand

- **The state is unreadable**: step 8's `Get-ChildItem` is refused for your account.
- **The trusted orceld path is protected**: the service refuses to start if `config.json` names an orceld
  outside `%ProgramFiles%\Orcel\`, one a non-administrator could replace, or a path with a junction, symbolic
  link or mount point on it (event 4103 says which). It applies the same check to its own
  `orcel-authority.exe`. Only the `%ProgramFiles%\Orcel\orceld.exe` copy is trusted for `Authorize`; an orceld
  run from the repository is an ordinary interactive caller.
- **A pre-created pipe name stops the service** (optional): stop the service, create `\\.\pipe\orcel-authority`
  from a user process, start the service: it must fail and write error event 4103. End that process, start
  again. (CI uses exactly this to make an install fail at its last step and checks the rollback.)
- **DPAPI under the virtual account**: `Restart-Service OrcelAuthority`, then `key_id` in `authority-status`
  must be unchanged.
- **A missing key is not replaced**: if `lease-signing.key` is ever missing while the audit chain has records,
  the service refuses to start rather than create a new key; restore the key or reset the state deliberately.

## Recovery

The service restarts automatically after a failure, twice within a day; after that it stays stopped and Full
Control answers `AUTHORITY_UNAVAILABLE` (it fails closed, nothing else in Orcel changes). Read events 4103 and
the System log, fix the cause, then start it with the "Start the service" line of the table above, checked on
the UAC prompt. A broken audit chain, a missing state file or a missing key with audit history are refusals by
design: inspect before resetting.

## Update after a rebuild

Elevated and checked on the UAC prompt: "Uninstall, keeping the state" (it also removes the staging). Then
steps 1 to 7 for the new commit. The install refuses an existing state directory, so move the kept one back
only after you have inspected it; or use the plain "Uninstall" and install to start over with a new key and
epoch 1.

## Uninstall

Elevated: the "Uninstall" line of the table above, checked on the UAC prompt. It also deletes the staged files
and `C:\Program Files\OrcelStaging`. "Uninstall, keeping the state" keeps `%ProgramData%\Orcel\authority`
(audit chain, leases, DPAPI-wrapped key) for inspection. The virtual account's profile is removed with its
DPAPI keys, so a kept key can no longer be unwrapped by a reinstalled service; keep it only as evidence.

## What CI proves, and what stays the founder's

Job **Authority install E2E / windows-latest** in `.github/workflows/ci.yml` runs `scripts/authority-install-e2e.ps1`
for every pull request, every push to `main` and every manual dispatch, on a disposable GitHub-hosted runner
where it is an administrator. On `main` it installs the very files the "Authority service artifact" job built
and attested in the same run; on a pull request it builds them the same way. It extracts the Stage, Install
and Uninstall command lines from this file's `Start-Process` lines (only `-NoExit` removed, the `<...>`
values filled in) and fails on any mismatch. Its report, `authority-install-e2e.json` in the artifact
`authority-install-e2e-report` of the run for your commit (Actions, the run, Artifacts; or
`gh run download <run-id> --repo TheHalfMoon/Orcel --name authority-install-e2e-report`), records every check:

- **Staging:** the Stage line with a wrong `<script-sha256>` removes the folder and fails; the real one gives
  exactly the ACL output in step 5; a temporary local standard user (created for the run) can read but cannot
  write, append or create anything in the staging folder; the Stage line refuses an existing folder.
- **The old flaw:** a folder made like `mkdir C:\OrcelBuild` is writable by that standard user, and the
  installer refuses it (as its own location and as `-ArtifactDir`) with nothing changed.
- **Failed installs, nothing changed:** a wrong hash, a pre-existing `%ProgramData%\Orcel\authority`.
- **Rollback:** a pre-created `\\.\pipe\orcel-authority` makes the service start fail after every other change;
  the system is then exactly as before the install.
- **Clean install:** the Install line; service running, automatic, as `NT SERVICE\OrcelAuthority`; the state
  directory and its files unreadable for the standard user, the public key readable, `%ProgramFiles%\Orcel`
  not writable for that user; `orceld authority-status` in service mode.
- **Fail closed without Windows Hello**, for two callers: the runner's job process (the elevated administrator
  of the runner's active console session, the closest a runner comes to you starting the owner CLI elevated)
  and the temporary standard user (an interactive logon, not elevated). For both, `orcel authority status`
  reaches the service and shows no enrolled key and nothing issuable; `orcel full-control grant` is refused
  (no enrolled Windows Hello key); `orcel authority reset` and `enroll` are refused; the epoch is unchanged.
  The hosted runner's UAC is not "Always notify" (its values are in the report), and the elevated owner CLI's
  reset must be refused by the service for exactly that reason; the report names the gate for each caller
  (`reset_refused_by`).
- **Recovery:** a restart keeps `key_id`; with `lease-signing.key` missing and audit history present the
  service refuses to start (event 4103); with the key back it starts with the same `key_id`.
- **Uninstall:** the Uninstall line; every row of the table above reversed and the staging gone.
- **Grant and revoke in console mode:** the scripted-consent console tests (test feature only, never in the
  installed binaries); the report says whether the full grant and revoke test ran or the runner had no
  interactive console session.
- **Trust chain:** whether the Microsoft TPM Root Certificate Authority 2014 is present on the runner and, if
  so, that its SHA-256 equals the pinned value.

What CI cannot do, and stays the founder's step on the real PC: Windows Hello enrollment against a real TPM
attestation, the service-observed unlock and the confirmation box, and an installed-service grant and revoke
with real Windows Hello (steps 9 to 14). Those cannot be produced without a person at a real console.
