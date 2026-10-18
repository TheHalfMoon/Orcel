# Windows v1 application decision

Status: ADOPTED planning direction (founder decision, 2026-10-09; Sol revision governs where it differs from the Opus baseline). Grants no authority: every capability still needs its own grain, review and qualification. Current execution state: `EXECUTION_FRONTIER.md`. Evidence baseline of this revision: PR #283 at `87bc9d6a69b6c5b5dc415ee6e30ee0fcb60d8985`, PR #282 at `10540885f3c52bd0c0d2f00cc23e3cafe067fe36`.

## Decision: keep WPF

PR282 is a genuine small read-only foundation, not the product. Its fixed allowlist and explicit unconfigured AI/pairing states are worth preserving. Independently running its verification script compiled a 22,016-byte executable and passed router and layout tests. That number excludes kernel, hosts, Node, production JavaScript, installer, updates, caches and OS prerequisites. It proves neither RAM nor startup speed.

| Criterion | WPF / in-box .NET Framework | Tauri 2 / WebView2 | Windows v1 assessment |
|---|---|---|---|
| Startup/RAM | No bundled runtime; mature native controls | Native host plus web renderer processes | Both NOT MEASURED; test identical screens and process trees |
| Native integration | Direct Windows accessibility, dialogs, tray and hotkeys | Rust/Windows bindings plus frontend bridge | WPF already provides a tested starting point |
| Polish/flexibility | Templates/resources support compact professional UI | CSS and web ecosystem offer flexibility | Existing preview needs actual UX work in either case |
| Arabic/English RTL | FlowDirection, localization, native automation patterns | CSS direction and web accessibility | Both supported in principle, neither qualified in Orcel |
| Accessibility | Standard controls expose UIA, custom controls need testing | DOM semantics, focus and WebView accessibility testing | Name controls, test Narrator, keyboard, scaling and high contrast |
| Packaging | Small app; OS framework prerequisite must be detected | Small host; WebView2 availability/version still a prerequisite | Measure online/offline and clean Windows 11 installs |
| Updates/signing | Existing lifecycle can install signed WPF payload | Tauri updater adds its own mechanism unless integrated | One governed signed update path, not two competing updaters |
| Isolation/security | Separate client process, no arbitrary process API | Renderer plus narrowly allowlisted IPC/CSP/navigation | Neither can guarantee protection against same-user malware |
| Windows 11 | Framework available on supported images, detect failures | WebView2 often available, detect/offline repair | Pin supported Windows builds and explicit prerequisite handling |
| Future platforms | Windows only | Cross-platform UI candidate | Cross-platform kernel/host work remains regardless of toolkit |
| Effort/reuse | Builds on PR282 now | Requires new shell/front-end integration | Marketing apps/web is not a reusable product frontend |

No head-to-head toolkit benchmark was run. C# is not a material problem in an already Rust/Go/TypeScript product. The app must never mint consent. Kernel-owned dialogs reduce coupling and forgery opportunities, but a dedicated process alone does not prevent same-user UI spoofing or synthetic input; preserve Hello and present residual risk honestly.

## Preview corrections before evolving it

Source review found synchronous UI-thread folder enumeration: GetFileSystemEntries materializes the directory before Take(12). Use cancellable bounded enumeration off the UI thread, report inaccessible/network folders without freezing. The CLI reader waits for process exit before draining redirected streams, which can deadlock on full pipes. Drain both streams concurrently with byte limits, timeout and owned-process cleanup. Executable presence is not daemon health. Use authenticated status/version responses and distinguish installed, stopped, reachable and incompatible.

The 1,160-pixel three-column preview is not the requested compact chat experience. Add a compact conversation/task view, optional expanded files/terminal pane, device selector and real event timeline. Bind actual capability availability; no placeholder model messages or apparent paired devices. Add UIA names, visible keyboard focus and explicit RTL layout. The existing verify script constructs layout; it does not exercise a visible Windows session.

## Incremental acceptance

1. Read-only app: status unavailable/timeout/version mismatch are truthful; huge-directory and 5-second stalled-process fixtures leave UI responsive; bounded events recover after sequence gaps.
2. Real task: intent goes through kernel; no free-form shell execution in UI; create-only report shows exact save path and approval; independent checker verifies bytes/hash.
3. Control: cancel/stop during observation, approval wait and dispatch; cloud disconnected; Hello unavailable; owned process cleanup and input release verified. Unknown state remains visible.
4. Usability: keyboard-only and Narrator, 100/150/200% DPI, multiple monitors, long English/Arabic text, RTL, reduced motion and high contrast.
5. Release: non-admin clean Windows installation, signed payload/update verification, stale-version rejection, rollback without authority resurrection, full size report.

## Exact reversal conditions

Move to Tauri only if (a) macOS/Linux becomes a funded near-term product requirement, (b) a real reusable frontend or prototype demonstrably reduces implementation effort, and (c) the same functional app passes all authority, accessibility/RTL, installer/offline, update and non-admin tests with acceptable measured startup and memory within the overall 400 MB limit. Record total porting effort and regressions. A tiny Rust executable or a preference for one language does not satisfy these conditions.

Status (2026-10-18): condition (a) is met as a founder-directed requirement that macOS and Linux are first-class (funding is not separately recorded). The toolkit change itself is still FD-03 (open). Condition (b) has a candidate in Agent-Native's AgentKit headless client and Toolkit components. Condition (c) remains the gate (backlog CR-03, CR-04 in `docs/orcel/implementation-readiness/`).

Measure signed installer download, full installed bytes including bundled runtime/dependencies, allocated disk, cold/warm time to interactive, aggregate working set/private bytes at idle and under task load, update download, and separately bounded cache growth. The founder's 400 MB target applies to the installed app/dependencies; optional cache is separately reported and cannot obscure product growth.

## Historical component-size evidence (Opus, not independently remeasured)

### 3.1 Measured inputs (reported by Opus on the research machine, 2026-10-09)

| Artifact | Bytes | gzip bytes | Command |
|---|---:|---:|---|
| `orceld.exe` (release build, toolchain 1.97.1) | 3,708,928 | 1,340,870 | `cargo build --release -p orceld -p orcel-browser-host`; `ls -la`; `gzip -c | wc -c` |
| `orcel-browser-host.exe` (release) | 488,960 | n/m | same |
| Published release zip `cotra-0.1.0-windows-x64.zip` | 4,839,256 | (zip) | `gh release view v0.1.0` |
| External Node.js runtime `node.exe` 24.19.0 (required today, not bundled) | 92,825,416 | 34,716,108 | `ls -la`; `gzip -c | wc -c` |
| `orcel-computer-host.exe` (Go) | UNMEASURED (Go toolchain not installed) | | |


These component figures are not a complete installation and do not quantify incremental Playwright costs. One bundled Node runtime plus dependencies and separate workers remains the preferred MVP path; measure the complete release.
