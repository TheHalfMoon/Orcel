# Orcel Desktop — read-only Windows foundation

**Status:** experimental native user-interface grain. This is **not a production release** and does not implement the unadopted Computer Use master plan or any newly privileged action.

This is a real Windows Presentation Foundation desktop executable built entirely with the Windows .NET Framework compiler. The preview itself needs no Electron, Chromium download, NuGet packages, Node runtime, model weights, cloud AI, hosted API, administrator privileges, or network access.

## Working features

- Native Windows desktop window with a compact conversation area, this computer's identity and the live state of the local Orcel runtime.
- Finds the per-user runtime the same way the runtime itself does (`%LOCALAPPDATA%\Orcel\bin\orcel.exe`); never searches PATH or runs a user- or model-provided path.
- Truthful runtime states, parsed from the runtime's own JSON (`orcel status|version|doctor --json`): **not installed**, **not responding**, **incompatible response**, or **installed** with its version, run state (running / degraded / not running), detail and workspace count. An error or unparsable answer is never shown as healthy.
- Read-only commands: `help`, `status`, `version`, `doctor` (health-check summary with the failing and warning checks), `devices`, `files`, `tasks`. Anything else is refused without action; chat text is never passed to an interpreter, operating-system command or AI service.
- Report task timeline (`tasks`, SG-000127): reads the current orceld run's report tasks through orceld's local app API (`orcel-app-api/1`, this user's pipe `\\.\pipe\orcel-<user SID>-app`): the newest five with their state, report destination and steps. Only `task.list` and `task.get` are ever sent, one bounded request per connection (frames at most 64 KiB, newline included), with 4 s in all per call: on timeout the pipe is closed, which cancels the read. Before reading, the app checks that the process serving the pipe runs as this user at Medium integrity or above (`GetNamedPipeServerProcessId` and its token, as `ORCEL_APP_API_1.md` section 7 asks); the pipe name is predictable, so another same-user process at normal integrity could still serve it first and show invented task states (display only: the app sends nothing that acts and connects as an identification-only client). The check reads the server's process id and then opens that process, so a pipe whose creating process exited while another kept its handle could, in a narrow race, be attributed to an unrelated process of this user that reused the id. orceld's state is shown before the planner's title. Titles and paths come from the planner and the workspace: line, paragraph and bidi control characters are replaced and a title cannot close its quotes. When the pipe does not answer or answers unusably, the app says so and shows no tasks. The app cannot start, approve or stop a task; it reads once per `tasks` command and does not follow `task.updated` events yet.
- Shell and process sessions are labelled **unavailable** (not armed in this build).
- Runtime queries run off the UI thread with both output streams drained concurrently (no full-pipe deadlock), output bounded to 256 KB, and the child placed in a kill-on-close Job Object: on timeout (8 s; 30 s for `doctor`, which starts the daemon for an IPC probe) the job is terminated, and descendants still alive when a query ends are killed with it. Processes started in the few milliseconds before the child joins the job are not covered; if no job can be created, only the direct child is killed on timeout. A failed query is reported as such; it never crashes the window.
- The runtime is located only through a drive-qualified `%LOCALAPPDATA%` (UNC and drive-relative values are ignored).
- Folder preview: a user-selected folder is enumerated off the UI thread without materializing the directory and limited to 12 names; the app stops waiting after 10 s even if the file system never answers (for example a stalled network share; the abandoned enumeration may keep one thread blocked until the file system returns); nothing is modified or uploaded.
- Accessible controls: UI Automation ids and names on the window, command box, Send/Refresh buttons, transcript, runtime and device state; keyboard focus starts in the command box.
- Orcel AI, voice and pairing are shown as **not connected**; no remote devices are fabricated.

## Build and test

Run these in a regular, non-elevated Windows PowerShell session from the repository root:

    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\apps\orcel-desktop-preview\tests\verify.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\apps\orcel-desktop-preview\tests\e2e.ps1
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\apps\orcel-desktop-preview\tests\e2e.ps1 -RuntimeRoot <isolated LOCALAPPDATA with an installed runtime>

`verify.ps1` compiles the application with the in-box .NET Framework compiler and runs the self-tests: command allowlist and refusal of shell-shaped input, interpretation of real runtime JSON (installed, timeout, garbage, error, doctor failures, version), a stalled child stopped at its timeout, a child flooding both streams drained without deadlock and bounded, and the bounded, cancellable folder preview.

`e2e-tasks.ps1 -Orceld <path to orceld.exe>` starts a real orceld on an isolated app API instance, workspace and state (under the profile root by default: orceld refuses a state path with an ancestor another user can change), drives `report/start` and `report/preview` over its stdio channel (nothing reaches the approval broker), runs `e2e.ps1` against that instance, requires the app to show the live task, and checks that nothing was written.

`e2e.ps1` is a native Windows end-to-end test driven through Windows UI Automation (no third-party framework). It launches the real executable with an isolated `LOCALAPPDATA` (an empty temporary folder by default, or `-RuntimeRoot` for a real test install), checks the runtime panel and initial keyboard focus, sends `status`, a shell-like string (must be refused and the app must start no child process afterwards), and with `-RuntimeRoot` also `doctor` and `version`; it checks accessible names and keyboard focusability, measures startup and memory, and closes the window. The user's real install is never queried.

Measured on Windows 11 build 26300 (Intel UHD Graphics, 120 DPI, 1536×960), single runs: executable 43,008 bytes; window in 443–810 ms; live runtime status in 512–858 ms; `doctor` against a real install about 8 s. Memory there: about 149 MB working set / 145 MB private idle, about 228 MB / 211 MB after runtime queries.

**Memory against a minimal WPF window (#288).** `tests/memory.ps1` builds a minimal WPF window the same way (`tests/baseline/MinimalWindow.cs`) and profiles both on the same machine. The Rust CI job runs it on its Windows runner and prints `WPF-MEM` lines; it is report only, with no budget, and it refuses to run outside CI unless `-AllowLocal` is given, so it never opens windows on a person's desktop. Measured on a hosted `windows-latest` runner (no GPU), runs 40770847310 (before) and 40770985711 (after):

| | Orcel | Minimal WPF | Orcel above baseline |
|---|---|---|---|
| Idle working set, hardware rendering | 64.1–65.3 MB | 55.4–55.8 MB | about 9 MB |
| Idle private bytes, hardware rendering | 44.7–45.7 MB | 39.7–40.1 MB | about 5 MB |
| Idle working set, software rendering | 53.6–53.7 MB | 46.7–46.9 MB | about 7 MB |
| Warm startup to window | 163–224 ms | 128–136 ms | |

At idle the preview loads one assembly the baseline does not (`PresentationFramework-SystemXml`); `System.Web.Extensions` and WinForms load only when a query or the folder dialog needs them. The footprint at idle is therefore mostly WPF itself. The larger figures on the 120 DPI Intel UHD machine above come from the graphics stack and could not be reproduced on a runner without a GPU.

Across 250 alternating `status`/`tasks` queries, the working set rose without bound before the fix (88.0 MB after 100 queries, 96.3 MB after 250, with nothing released after idling), because every message kept its visuals for the life of the window. The transcript now keeps the most recent 200 messages, and the working set is flat at 88.4–89.9 MB from query 100 to 250. The first 50 queries still add about 20 MB in both runs: one-time costs of first use (thread-pool threads, JIT, the query and JSON code, text caches), not growth.

All generated binaries go to the user's TEMP directory. A signed installer and installed-size qualification have not been performed.

## Security boundary

The preview's only connection to orceld besides the fixed CLI queries is the read-only app API pipe (this user's local pipe, whose server must run as this user; no network). The preview does not create a network listener, model connection, browser automation service, input actuation, shell execution API, file mutation, remote pairing endpoint, or delegated approval. It never attempts to elevate privileges.

Only fixed read-only compatibility CLI operations may be invoked from the known per-user installation path. The existing Orcel/Orcel core remains the policy authority; the preview does not duplicate its grants or bypass local approvals.

Security finding #278 remains open and blocks promotion of ledger-backed production actions until independent qualification.

## Follow-up engineering gates

1. Evaluate long-term native UI stack against actual memory, accessibility, update-signing and cold-start measurements; this WPF prototype does not dictate the final cross-platform stack.
2. Integrate a reviewed read-only status IPC instead of repeatedly spawning the compatibility CLI.
3. Adopt the existing authorization broker before any action preview/approval/execution UI.
4. Build secure multi-device enrollment/status and revocation, with no default raw remote control.
5. Design cloud-only Orcel AI API integration with authenticated task IDs, user-granted screen/data sharing and explicit model unavailability, then add voice.
6. Prove native E2E, signed delivery, security review, independent tests, product packaging and installer/download size before release.

See master planning issue #279, identity #281 and security blocker #278 in the Orcel GitHub repository.
