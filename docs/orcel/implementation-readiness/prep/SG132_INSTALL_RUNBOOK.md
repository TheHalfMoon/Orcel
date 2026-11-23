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

1. **No elevated step runs PowerShell or any .NET program.** An elevated PowerShell loads modules from your
   Documents folder and any .NET program loads a profiler named in your user environment
   (`HKCU\Environment`), both writable by anything running as you, before a single line of the step runs. The
   Stage and Uninstall steps are `C:\Windows\System32\cmd.exe` running only System32 tools by full path (they
   first reset `PATH`, `SystemRoot`, `windir` and `COMSPEC`, which your user environment could redirect); the Install step
   is the staged, hash-checked native `orcel-authority.exe`, which takes no folder from the environment and
   never loads a DLL from its own folder: at start it imports only KnownDLLs and API sets (kernel32,
   advapi32, oleaut32, ntdll; no C runtime DLL at all), resolved from System32 only (`DependentLoadFlags`
   0x800); the DLLs that are not KnownDLLs (wtsapi32, bcrypt, crypt32, and through them SspiCli and msasn1)
   are delay-loaded, after its first instruction has restricted every load, their dependencies included, to
   System32.
2. **Nothing an elevated step consumes can be changed by a standard user.** The three binaries are staged in
   `C:\Program Files\OrcelStaging`: owner Administrators; SYSTEM and Administrators full control; Users read and
   execute; nothing inherited from `C:\Program Files`. `orcel-authority install` refuses to run, with nothing
   changed, unless it is itself `C:\Program Files\OrcelStaging\orcel-authority.exe`, and the staging folder,
   its three binaries and every parent up to `C:\` are owned by SYSTEM, Administrators or TrustedInstaller,
   contain no junction, symbolic link or mount point, give no other account a right to change them, and the
   folder holds nothing else (a DLL there would load into the elevated program) and no binary has a second
   hard link. A folder made with a plain `mkdir C:\...` is refused: `C:\` gives Authenticated Users modify
   rights on everything created under it.
3. **Only the reviewed commit's bytes are installed.** You prove the artifact's commit is the reviewed head,
   check each file's build provenance with `gh attestation verify`, and take the SHA-256 values from the job
   log. The Stage step checks the SHA-256 of each copy inside the admin-only folder against the values on its
   UAC-checked command line and deletes the folder on any mismatch; the Install step checks them again, through
   handles that block writes and deletes, and copies from those same handles.
4. **Every elevated program and command line is checked on the UAC prompt**, not in your shell (below).

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
- **GitHub CLI** (`gh`) signed in, for the commit check, the download and the attestation check.
- **A second device** (phone or another PC) for reading the commit, the job log and Microsoft's TPM root on
  github.com and microsoft.com. A process running as you could change what your own browser or shell shows;
  the values you type into the UAC-checked command lines are only as good as where you read them.

## How every elevated step is started, and the check on every UAC prompt

Never run an elevated step from an elevated terminal. From your NORMAL (not elevated) PowerShell, start the one
program directly with `Start-Process -Verb RunAs`, using the lines below with your values in the `<...>`
places. `<download-folder>` must be a plain path without quotes, `%`, `!`, `^` or `&` in it.

Your normal shell runs as you, so a program running as you could change what it starts. The check that does
not depend on your shell is the UAC prompt itself, drawn on the secure desktop. **On every UAC prompt:**

1. Select **Show more details**.
2. Read **Program location**: it must be exactly the program in the table below, and the full command line
   after it must be exactly the one below (your own values in the `<...>` places, nothing added, nothing
   missing).
3. If anything differs, or the prompt names another program, choose **No** and stop. Do not retry from the
   same shell; restart Windows, sign in, and start again.

`orcel-authority.exe` and `orcel.exe` are not code-signed in this slice, so UAC shows them as "Unknown
publisher"; the path and command line check is what identifies them, and the Stage step's hash check is what
makes the staged `orcel-authority.exe` the reviewed bytes. `& pause` and `--pause` only keep the window open until you
have read it: press a key (or Enter) and the elevated window closes; never leave an elevated window open.

| Step | Program location | Exact command line |
| --- | --- | --- |
| Stage | `C:\Windows\System32\cmd.exe` | `"C:\Windows\System32\cmd.exe" /d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && mkdir "C:\Program Files\OrcelStaging" && (C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging" /setowner *S-1-5-32-544 && C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" && copy /b /y "<download-folder>\orcel-authority.exe" "C:\Program Files\OrcelStaging\orcel-authority.exe" && copy /b /y "<download-folder>\orceld.exe" "C:\Program Files\OrcelStaging\orceld.exe" && copy /b /y "<download-folder>\orcel.exe" "C:\Program Files\OrcelStaging\orcel.exe" && C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging\*" /setowner *S-1-5-32-544 /L && C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging\*" /reset /L && C:\Windows\System32\cmd.exe /d /c dir /b /a "C:\Program Files\OrcelStaging" \| C:\Windows\System32\find.exe /c /v "" \| C:\Windows\System32\findstr.exe /l /x /c:"3" && C:\Windows\System32\certutil.exe -hashfile "C:\Program Files\OrcelStaging\orcel-authority.exe" SHA256 \| C:\Windows\System32\findstr.exe /l /x /i /c:"<authority-sha256>" && C:\Windows\System32\certutil.exe -hashfile "C:\Program Files\OrcelStaging\orceld.exe" SHA256 \| C:\Windows\System32\findstr.exe /l /x /i /c:"<orceld-sha256>" && C:\Windows\System32\certutil.exe -hashfile "C:\Program Files\OrcelStaging\orcel.exe" SHA256 \| C:\Windows\System32\findstr.exe /l /x /i /c:"<orcel-sha256>" && echo STAGED: exactly the three files, each with its SHA-256 \|\| (rmdir /s /q "C:\Program Files\OrcelStaging" & echo STAGING REFUSED: the folder was removed & C:\Windows\System32\cmd.exe /d /c exit 1)) & pause"` |
| Remove the staging | `C:\Windows\System32\cmd.exe` | `"C:\Windows\System32\cmd.exe" /d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && rmdir /s /q "C:\Program Files\OrcelStaging" && echo REMOVED: the staging folder & pause"` |
| Install | `C:\Program Files\OrcelStaging\orcel-authority.exe` | `"C:\Program Files\OrcelStaging\orcel-authority.exe" install --authority-sha256 <authority-sha256> --orceld-sha256 <orceld-sha256> --orcel-sha256 <orcel-sha256> --pause` |
| Uninstall | `C:\Windows\System32\cmd.exe` | `"C:\Windows\System32\cmd.exe" /d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && "C:\Program Files\OrcelStaging\orcel-authority.exe" uninstall && rmdir /s /q "C:\Program Files\OrcelStaging" && echo UNINSTALLED: the staging folder was removed & pause"` |
| Uninstall, keeping the state | `C:\Windows\System32\cmd.exe` | `"C:\Windows\System32\cmd.exe" /d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && "C:\Program Files\OrcelStaging\orcel-authority.exe" uninstall --keep-state && rmdir /s /q "C:\Program Files\OrcelStaging" && echo UNINSTALLED: the staging folder was removed & pause"` |
| Start the service | `C:\Windows\System32\sc.exe` | `"C:\Windows\System32\sc.exe" start OrcelAuthority` |
| Enroll | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" authority enroll --pause` |
| Replace the key | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" authority enroll --replace --pause` |
| Reset | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" authority reset --pause` |
| Reset the audit anchor | `C:\Program Files\Orcel\orcel.exe` | `"C:\Program Files\Orcel\orcel.exe" audit reset-anchor --pause` |

(In the table, `\|` is a plain `|`: Markdown needs it escaped inside a table cell. The UAC prompt and the lines
below show it plain.)

What the Stage line does, so you can read it on the prompt: `/d` skips cmd's AutoRun, `/e:on` and `/v:off` fix
the command extensions and turn off delayed expansion whatever your registry says; it resets `PATH`,
`SystemRoot`, `windir` and `COMSPEC`; it creates `C:\Program Files\OrcelStaging` and stops if it already exists;
it makes Administrators the folder's owner and replaces its permissions with exactly SYSTEM and Administrators
full control and Users read and execute, nothing inherited; it copies each of the three files from
`<download-folder>` to its own file name in the folder (never to the folder as a whole, so a source that is
really a folder can bring nothing else along); it makes Administrators their owner and gives them exactly the
folder's permissions (`/reset`); it checks that the folder holds exactly three entries (a DLL beside the
program would load into it when it runs elevated); it checks each copy's SHA-256 with `certutil` against your
three values; and if any step fails it deletes the folder and says `STAGING REFUSED`. The Uninstall lines run
the staged `orcel-authority.exe uninstall` and then delete the staging folder; Remove the staging only deletes
it (`rmdir` does not follow junctions). None of them runs `orcel-authority.exe` from a folder you have not
checked: Remove the staging runs nothing from it.

The `Start-Process` lines that produce exactly these command lines (CI runs these lines' command lines):

```powershell
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\cmd.exe' -ArgumentList '/d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && mkdir "C:\Program Files\OrcelStaging" && (C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging" /setowner *S-1-5-32-544 && C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" && copy /b /y "<download-folder>\orcel-authority.exe" "C:\Program Files\OrcelStaging\orcel-authority.exe" && copy /b /y "<download-folder>\orceld.exe" "C:\Program Files\OrcelStaging\orceld.exe" && copy /b /y "<download-folder>\orcel.exe" "C:\Program Files\OrcelStaging\orcel.exe" && C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging\*" /setowner *S-1-5-32-544 /L && C:\Windows\System32\icacls.exe "C:\Program Files\OrcelStaging\*" /reset /L && C:\Windows\System32\cmd.exe /d /c dir /b /a "C:\Program Files\OrcelStaging" | C:\Windows\System32\find.exe /c /v "" | C:\Windows\System32\findstr.exe /l /x /c:"3" && C:\Windows\System32\certutil.exe -hashfile "C:\Program Files\OrcelStaging\orcel-authority.exe" SHA256 | C:\Windows\System32\findstr.exe /l /x /i /c:"<authority-sha256>" && C:\Windows\System32\certutil.exe -hashfile "C:\Program Files\OrcelStaging\orceld.exe" SHA256 | C:\Windows\System32\findstr.exe /l /x /i /c:"<orceld-sha256>" && C:\Windows\System32\certutil.exe -hashfile "C:\Program Files\OrcelStaging\orcel.exe" SHA256 | C:\Windows\System32\findstr.exe /l /x /i /c:"<orcel-sha256>" && echo STAGED: exactly the three files, each with its SHA-256 || (rmdir /s /q "C:\Program Files\OrcelStaging" & echo STAGING REFUSED: the folder was removed & C:\Windows\System32\cmd.exe /d /c exit 1)) & pause"'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\cmd.exe' -ArgumentList '/d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && rmdir /s /q "C:\Program Files\OrcelStaging" && echo REMOVED: the staging folder & pause"'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\OrcelStaging\orcel-authority.exe' -ArgumentList 'install --authority-sha256 <authority-sha256> --orceld-sha256 <orceld-sha256> --orcel-sha256 <orcel-sha256> --pause'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\cmd.exe' -ArgumentList '/d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && "C:\Program Files\OrcelStaging\orcel-authority.exe" uninstall && rmdir /s /q "C:\Program Files\OrcelStaging" && echo UNINSTALLED: the staging folder was removed & pause"'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\cmd.exe' -ArgumentList '/d /e:on /v:off /s /c "set "PATH=C:\Windows\System32" && set "SystemRoot=C:\Windows" && set "windir=C:\Windows" && set "COMSPEC=C:\Windows\System32\cmd.exe" && "C:\Program Files\OrcelStaging\orcel-authority.exe" uninstall --keep-state && rmdir /s /q "C:\Program Files\OrcelStaging" && echo UNINSTALLED: the staging folder was removed & pause"'
Start-Process -Verb RunAs -FilePath 'C:\Windows\System32\sc.exe' -ArgumentList 'start OrcelAuthority'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'authority enroll --pause'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'authority enroll --replace --pause'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'authority reset --pause'
Start-Process -Verb RunAs -FilePath 'C:\Program Files\Orcel\orcel.exe' -ArgumentList 'audit reset-anchor --pause'
```

Explorer's **Run as administrator** passes no arguments, and every step above needs them, so do not use
Explorer for these steps.

## What the install changes on the PC

`orcel-authority install` makes exactly these system changes, and `orcel-authority uninstall` reverses them:

| # | Change | Where | Reversed by `uninstall` |
| --- | --- | --- | --- |
| 1 | Copies the hash-verified `orcel-authority.exe`, `orceld.exe` and `orcel.exe` (each hashed and copied through one handle that blocks writes and deletes, and the copy hashed again); `Orcel` and `Authority` are created, if missing, with owner Administrators and a protected DACL (SYSTEM and Administrators full control, Users read and execute) | `%ProgramFiles%\Orcel\Authority\orcel-authority.exe`, `%ProgramFiles%\Orcel\orceld.exe`, `%ProgramFiles%\Orcel\orcel.exe` | Deleted |
| 2 | SCM registration: service `OrcelAuthority`, "Orcel Authority", own process, automatic start, account `NT SERVICE\OrcelAuthority` (virtual account, no password), SID type unrestricted, privileges `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege`, `SeCreateGlobalPrivilege` only, restart twice on failure within a day | Service Control Manager | Stopped (waited for), deleted |
| 3 | Only if missing: `%ProgramData%\Orcel`, created with its security in one call: owner Administrators, protected DACL (SYSTEM and Administrators full control, Users read and execute) | `%ProgramData%\Orcel` | Deleted if this install created it and it is empty |
| 4 | State directory created with its security in one call: owner Administrators, protected DACL with SYSTEM, Administrators and the service full control, no access for users; `config.json` trusting only `%ProgramFiles%\Orcel\orceld.exe` (Authorize) and `%ProgramFiles%\Orcel\orcel.exe` (grant, enrollment and reset intents) | `%ProgramData%\Orcel\authority` | Deleted (kept with `--keep-state`) |
| 5 | Public key directory created the same way: SYSTEM and Administrators full control, the service modify, Users read and execute | `%ProgramData%\Orcel\authority-public` | Deleted |
| 6 | Event Log source `Orcel` in the Application log, created only if it does not exist (marked `OrcelInstalledBy`; its message file is an absolute path under the Windows folder; nobody but administrators may change the key) | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\Orcel` | Removed only if this install created it |
| 7 | Starts the service and waits until it runs and has published its public key; Windows may create a profile for the virtual account (it holds the account's DPAPI keys) | SCM, user profiles | Profile removed; if Windows still holds it loaded, the window prints `PROFILE LEFT` and how to remove it after a restart |

The folders come from Windows' known folders, never from environment variables. Every directory created is
read back (owner, protection, exact entries) and any difference stops the install. **If any step fails, the
install undoes every change it already made, newest first, and says "every change it made was rolled back"**
(or lists what it could not undo). It refuses to run, with nothing changed, if the location check fails, a
hash does not match, the service already exists, any installed binary already exists,
`%ProgramData%\Orcel\authority` or `authority-public` already exist (someone may have pre-created them), or an
existing `%ProgramFiles%\Orcel`, `%ProgramData%\Orcel` or Event Log source key could be changed by a
non-administrator. Uninstall deletes folder trees only after checking that nothing in them is a junction or
link. What uninstall leaves: events already written to the Application log.

## The procedure

### 1. Prove the commit, and find its two CI jobs (second device)

`<reviewed-head>` is the head commit of the pull request you reviewed. On `main` of `TheHalfMoon/Orcel` find
the merge commit of that pull request; its full SHA is `<commit>`. Prove that `<commit>` is exactly what you
reviewed:

```powershell
gh api repos/TheHalfMoon/Orcel/commits/<commit> --jq '.parents[].sha'
gh api repos/TheHalfMoon/Orcel/compare/<reviewed-head>...<commit> --jq '.files | length'
gh api repos/TheHalfMoon/Orcel/branches/main --jq '.commit.sha'
```

The first must list `<reviewed-head>` among the parents; the second must print `0` (no file differs between
what you reviewed and the commit; `main` only merges up-to-date branches); the third shows whether `<commit>`
is still the head of `main` (if not, review what came after, or use the newer head's own reviewed pull request).
Then find the workflow run "CI" for `<commit>` with event `push`:

```powershell
gh run list --repo TheHalfMoon/Orcel --workflow ci.yml --branch main --event push --commit <commit>
```

Use only that run (or a manual `workflow_dispatch` run on `main` at that commit). The artifact jobs do not run
for pull requests; an artifact from any other run, branch or fork is untrusted, whatever it contains. In that
run both of these jobs must have passed:

- **Authority service artifact / windows-latest.** Open its log, step "Record the SHA-256 of each file", and
  write down the three `AUTHORITY-ARTIFACT <sha256>  <file>` lines and the `commit` line (it must be
  `<commit>`). These are `<authority-sha256>` (`orcel-authority.exe`), `<orceld-sha256>` (`orceld.exe`) and
  `<orcel-sha256>` (`orcel.exe`). Do not take them from the `SHA256SUMS.txt` inside the download; it only has
  to agree with the log. Step "Verify the attestation as the runbook does" must show three successful
  verifications.
- **Authority install E2E / windows-latest.** It ran this procedure on a disposable runner with these same
  bytes (see "What CI proves" below). Its artifact `authority-install-e2e-report` holds
  `authority-install-e2e.json`; its `result` must be `pass`, its `commit` `<commit>`, its `artifact_sha256`
  the three values you wrote down, and its `not_verified` list tells you what the runner could not show.

### 2. Download the artifact (normal shell)

```powershell
gh run download <run-id> --repo TheHalfMoon/Orcel --name orcel-authority-windows-x64 --dir <download-folder>
```

`<run-id>` is the run's number from step 1; `<download-folder>` is a new, empty folder, for example
`C:\Users\<you>\Downloads\orcel-authority-<commit>`.

### 3. Verify provenance and hashes (normal shell)

```powershell
foreach ($n in 'orcel-authority.exe', 'orceld.exe', 'orcel.exe') {
  gh attestation verify (Join-Path '<download-folder>' $n) --repo TheHalfMoon/Orcel --signer-workflow TheHalfMoon/Orcel/.github/workflows/ci.yml --source-ref refs/heads/main --source-digest <commit> --deny-self-hosted-runners
  Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path '<download-folder>' $n)
}
```

Each file must report a successful verification (a GitHub-hosted run of `ci.yml` on `refs/heads/main` of
`TheHalfMoon/Orcel` at `<commit>` built it), and each hash must equal the value from the job log. Any failure:
stop. These checks run in your shell, so they guard against a wrong or tampered download, not against a
process running as you; the binding checks are the hashes on the UAC-checked command lines in steps 4 and 7.

### 4. Stage, elevated

Start the **Stage** line of the table above (your `<download-folder>` and three hashes), and check the UAC
prompt against the table. The window must end with `STAGED: exactly the three files, each with its SHA-256`, the
count `3` and the three hashes printed above it, and no error; press a key to close it. `STAGING REFUSED` means the folder was removed again: check the
download and the hashes. "A subdirectory or file ... already exists" means an earlier staging is still there,
whose contents you have not checked now: run the Remove the staging line (it runs nothing from the folder),
then steps 1 to 5 again; if you meant to uninstall an earlier install, uninstall from that fresh staging.

### 5. Check the staging folder's ACL (normal shell)

```powershell
icacls "C:\Program Files\OrcelStaging"
icacls "C:\Program Files\OrcelStaging\*"
Get-ChildItem -Force 'C:\Program Files\OrcelStaging' | ForEach-Object { '{0} {1}' -f $_.Name, (Get-Acl -LiteralPath $_.FullName).Owner }
Get-Acl -LiteralPath 'C:\Program Files\OrcelStaging' | ForEach-Object { '{0} protected={1}' -f $_.Owner, $_.AreAccessRulesProtected }
```

Expected output, line by line (column spacing may differ; on a Windows display language other than English the
account names are translated). `(I)` marks an entry the files inherit from the folder; the folder's own
entries have none:

<!-- expected-staging-acl -->
```text
C:\Program Files\OrcelStaging BUILTIN\Users:(OI)(CI)(RX)
BUILTIN\Administrators:(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(OI)(CI)(F)
Successfully processed 1 files; Failed processing 0 files
C:\Program Files\OrcelStaging\orcel-authority.exe BUILTIN\Users:(I)(OI)(CI)(RX)
BUILTIN\Administrators:(I)(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
C:\Program Files\OrcelStaging\orcel.exe BUILTIN\Users:(I)(OI)(CI)(RX)
BUILTIN\Administrators:(I)(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
C:\Program Files\OrcelStaging\orceld.exe BUILTIN\Users:(I)(OI)(CI)(RX)
BUILTIN\Administrators:(I)(OI)(CI)(F)
NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
Successfully processed 3 files; Failed processing 0 files
orcel-authority.exe BUILTIN\Administrators
orcel.exe BUILTIN\Administrators
orceld.exe BUILTIN\Administrators
BUILTIN\Administrators protected=True
```

Any other entry (Authenticated Users, Everyone, INTERACTIVE, your own account, CREATOR OWNER, OWNER RIGHTS),
any other file, a missing `protected=True`, or another owner: stop, and run the Remove the staging line (it
runs nothing from the folder, it only deletes it). The installer makes the same checks itself before it changes
anything.

### 6. Preview (changes nothing; not elevated)

```powershell
& 'C:\Program Files\OrcelStaging\orcel-authority.exe' install --dry-run --authority-sha256 <authority-sha256> --orceld-sha256 <orceld-sha256> --orcel-sha256 <orcel-sha256>
```

It prints the location check, the three hashes and every planned change, and ends with `Dry run: nothing was
changed.`

### 7. Install, elevated

Start the **Install** line of the table above with your three hashes, and check the UAC prompt against the
table. The window must end with `The service OrcelAuthority is running.` and `Installed.`; press Enter to
close it. On a failure it says what failed and that every change was rolled back.

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
    under the same name is not trusted (test `tpm_root_lookalike_named_like_microsofts_is_refused`), and a
    test checks that the root found by name on the machine, when present, has the pinned hash (the hosted CI
    runner has no such certificate, so the report lists this as not verified). `orcel authority status` must
    say `enrollment available true` and `UAC always notify on secure desktop true`.
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
    --client-ref <cl-...> --origin https://<site>` with the values `browser_session_create` returned to a local
    client. A remote (ChatGPT) session's reference (`cl-remote-...`) is refused: no lease covers a remote session.
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

### Lost or replaced audit chain (WP1-03 owner anchor reset)

orceld writes its own hash-chained audit log (`audit-chain.jsonl` beside `audit.jsonl` in your Orcel state
folder) and the service holds an anchor of it every 32 records. If that file is deleted, or replaced by one
that does not continue it, the service refuses the new file's anchors and orceld refuses every dispatch
(`audit write failed before dispatch`): by design, a rewritten audit trail must not pass silently.

First try to keep the trail:

1. `orceld audit-verify` (not elevated) says why. If the file is only broken (an edit, a torn tail, a cut),
   `orceld audit-move-aside` keeps it and opens a new file linked to its last verifiable record; the service
   accepts that continuation, no reset needed.
   It refuses a chain path that is a link (move the file it leads to there first) and a read-only file
   (clear the attribute first), and so does the reset below.
2. If the original file still exists somewhere (a backup, the `.quarantine-*` files beside the chain),
   restore it instead. An orceld that is already running refuses a restored file that is older than, or other
   than, the one it read: restart it.

Only when the file the service holds anchors of is gone for good, reset the anchor:

3. Stop every Orcel client (orceld runs per client session).
4. **Elevated, started directly:** the "Reset the audit anchor" line of the table above. On the UAC prompt
   select **Show more details**: Program location `C:\Program Files\Orcel\orcel.exe` and the command line
   `"C:\Program Files\Orcel\orcel.exe" audit reset-anchor --pause` exactly, else **No**. The service refuses
   the reset unless the caller is that installed `orcel.exe`, elevated, with UAC set to Always notify on the
   secure desktop, from your own (not the built-in) administrator account: the same checks as enrollment.
5. The window prints a one-time code and the held head (chain file id, seq, digest). The Orcel Authority box
   must show the same code, the log `orceld` and the same head. Choose **Yes** only if they match and you lost
   the chain yourself; anything else, **No**.
6. On Yes the service records a signed `anchor_reset` in its own audit chain and in the Event Log (event 4100,
   `orcel-anchor-reset/1|orceld|<file>|<seq>|<digest>|record <digest>`), and the command opens a new first
   chain file whose opening record names that reset record. Any file still at the chain's path is kept beside
   it as `audit-chain.jsonl.quarantine-reset-*`.
   The command then asks the service to hold the new file's opening record at once (orceld does it before
   its first record if that failed), so no other file naming the same reset can take its place.
   If the command stopped after your Yes (closed window, error), run it again: the service still reports the
   reset, so it opens a file without a new box. It never keeps a file it finds at the chain path (even one an
   earlier run opened): it moves it aside and opens a fresh one, then anchors that file's opening. If the service refused the reset file (it was replaced, or grew too long first), run the command again:
   a pending reset can be reset again with the same checks and box, and the new reset replaces the old. Only that file is accepted: until its first anchor, the
   service refuses any other first file (one that does not name the reset record, or a long chain grown
   before it asked), and `orceld audit-verify` reports such a file as broken.
   A crash in the middle of `audit-move-aside` or of this command leaves the old or the new file at the chain
   path, never neither, and at most `audit-chain.jsonl.recovering-*` and an extra `.quarantine-moved-*` or
   `.quarantine-reset-*` name beside it. They stop neither orceld nor another run, but `orcel state migrate`
   refuses a state root in which the chain file has such a second name. Once `orceld audit-verify` is
   satisfied, with every client stopped, delete the `.recovering-*` files and only those
   `.quarantine-moved-*` and `.quarantine-reset-*` names that no file's first record gives as
   `moved_aside.file`; every other `.quarantine-*` file is evidence.
7. Start your client again. `orceld audit-verify` now reports `reset_by_owner` (exit code 8), never a silent
   `intact`, and names the reset record; the next anchors the service holds are of the new file. The abandoned
   file stays refused by id.

## Update after a rebuild

Elevated and checked on the UAC prompt: "Uninstall, keeping the state" (it also removes the staging; if the
staging is already gone, stage any reviewed commit first, steps 1 to 5). Then steps 1 to 8 for the new commit.
The install refuses an existing state directory, so move the kept one back only after you have inspected it;
or use the plain "Uninstall" and install to start over with a new key and epoch 1.

## Uninstall

Elevated: the "Uninstall" line of the table above, checked on the UAC prompt. It runs the staged
`orcel-authority.exe uninstall` and then deletes `C:\Program Files\OrcelStaging`. "Uninstall, keeping the
state" keeps `%ProgramData%\Orcel\authority` (audit chain, leases, DPAPI-wrapped key) for inspection. The
virtual account's profile is removed with its DPAPI keys, so a kept key can no longer be unwrapped by a
reinstalled service; keep it only as evidence. If the staging folder is gone, stage any reviewed commit first
(steps 1 to 5).

## What CI proves, and what stays the founder's

Job **Authority install E2E / windows-latest** in `.github/workflows/ci.yml` runs `scripts/authority-install-e2e.ps1`
for every pull request, every push to `main` and every manual dispatch, on a disposable GitHub-hosted runner
where it is an administrator. On `main` it installs the very files the "Authority service artifact" job built
and attested in the same run; elsewhere it builds them the same way (so the attestation, its `gh attestation
verify` step and the attested download first run on the push to `main`; the report says which source it used).
It takes the Stage, Remove the staging, Install and Uninstall command lines from this file's `Start-Process`
lines (only `& pause` and `--pause` removed, the `<...>` values filled in) and launches them with a hostile environment: a
PowerShell module planted in the runner account's Documents folder that shadows the cmdlets an elevated
PowerShell would load, a .NET profiler (`COR_PROFILER`, also written to `HKCU\Environment`) pointing at a
canary DLL, and `PATH`, `SystemRoot`, `ProgramFiles` and `ProgramData` pointing at a decoy folder. A positive
control first shows that a PowerShell started with that environment runs both canaries. It fails on any
mismatch. Its report, `authority-install-e2e.json` in the artifact `authority-install-e2e-report` of the run
for your commit (Actions, the run, Artifacts; or
`gh run download <run-id> --repo TheHalfMoon/Orcel --name authority-install-e2e-report`), records every check
and lists separately (`not_verified`) what the runner could not show:

- **Runbook:** every `Start-Process` line parses and matches exactly one UAC table row, and every row one line; no elevated step
  starts PowerShell or a .NET program.
- **Binaries:** none of the three imports a C runtime DLL (the release build links it statically), and
  `orcel-authority.exe` imports only KnownDLLs and API sets, resolves them from System32 only
  (`DependentLoadFlags` 0x800) and delay-loads wtsapi32, bcrypt and crypt32, so a DLL beside it is never loaded (`scripts/check-authority-binaries.ps1`, also run before the attestation).
- **Staging:** the Stage line with a wrong hash removes the folder and fails; so does a download in which
  `orcel-authority.exe` is really a folder holding the genuine program and a `wtsapi32.dll`; the real one gives exactly the
  ACL output in step 5; a temporary local standard user (created for the run) can read but cannot write,
  append, create or re-permission anything in the staging folder; the Stage line refuses an existing folder;
  the Remove the staging line deletes it.
- **The old flaw:** a folder made like `mkdir C:\OrcelBuild` is writable by that standard user, and the
  installer refuses to run from it, with nothing changed.
- **Failed installs, nothing changed:** a wrong hash; a real canary DLL planted in the staging folder as
  `wtsapi32.dll`, `VCRUNTIME140.dll`, `SspiCli.dll`, `msasn1.dll`, `bcrypt.dll` and `crypt32.dll` in turn
  (each refused, and never loaded); a pre-existing
  `%ProgramData%\Orcel\authority`; a `%ProgramData%\Orcel` a standard user created (refused, and the user's
  folder and file left as they were).
- **Rollback:** a pre-created `\\.\pipe\orcel-authority` makes the service start fail after every other change;
  the system is then exactly as before the install.
- **Clean install:** the Install line; nothing lands in the decoy folders; service running, automatic, as
  `NT SERVICE\OrcelAuthority`, with its SID type, privileges and failure actions; the Event Log message file
  under the real Windows folder; the state directory and its files unreadable for the standard user, the
  public key readable, `%ProgramFiles%\Orcel` not writable for that user; `orceld authority-status` in service
  mode.
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
- **Hostile environment:** neither canary ran in any elevated step.
- **Grant and revoke in console mode:** the scripted-consent console tests (test feature only, never in the
  installed binaries); the report says whether the full grant and revoke test ran.
- **Trust chain:** a lookalike root with the Microsoft root's name is refused; whether the Microsoft TPM Root
  Certificate Authority 2014 is present on the runner (if absent, `not_verified`).

What CI cannot do, and stays the founder's step on the real PC: the commit proof and the provenance check
(steps 1 to 3), the TPM root check (step 9), Windows Hello enrollment against a real TPM attestation, the
service-observed unlock and the confirmation box, and an installed-service grant and revoke with real Windows
Hello (steps 10 to 13). Those cannot be produced without a person at a real console.
