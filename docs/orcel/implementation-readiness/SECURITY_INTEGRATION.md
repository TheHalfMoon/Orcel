# Trusted security architecture for the cross-platform plan

Status: ADOPTED planning direction (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. Living threat baseline remains `docs/security/THREAT_MODEL.md` and `docs/orcel/SECURITY_THREAT_MODEL.md`; this file is the delta introduced by the integrations in this package. Nothing here weakens an existing control.

## 1. Non-negotiable rule

**The AI proposes. Orcel authorizes. Orcel executes. Orcel verifies.** For every imported donor unit:

1. It runs inside an Orcel-owned process with no listener and a closed request vocabulary.
2. It never decides policy, never presents or answers an approval, never mints identity, leases or tokens.
3. It never evaluates caller-, model- or page-supplied script.
4. It never opens a second channel to the browser, the desktop or the network.
5. It never retries a mutation; unknown outcomes go to the journal and reconciliation.
6. Its telemetry, auto-update and download paths are removed or compiled out.
7. Its notices and provenance travel with it.

A donor unit that cannot meet these is not imported, whatever its license.

## 2. Privilege boundaries (unchanged, extended to new OSes)

| Boundary | Windows | macOS | Linux |
|---|---|---|---|
| User ↔ Orcel approvals | `MessageBoxW` system-modal, Hello | CFUserNotification, LocalAuthentication helper (code-signature checked) | GTK4 helper, polkit `auth_self` |
| orceld ↔ hosts | inherited pipes | inherited pipes | inherited pipes |
| orceld ↔ local UI | named pipe + DACL | Unix socket 0700 + peer creds | Unix socket 0700 + `SO_PEERCRED` |
| orceld ↔ remote | relay + OAuth + device identity | same | same |
| Host ↔ target app | UIA | AX (TCC Accessibility), ScreenCaptureKit (TCC Screen Recording) | AT-SPI bus, X11, Wayland portals |
| Browser engine ↔ network | resolver rules + no-route proxy | resolver rules + host-owned sink | resolver rules + host-owned sink |

## 3. Threat-model delta

| Id | Integration | New or changed threat | Control | Test | Task |
|---|---|---|---|---|---|
| S-01 | Any non-Windows build | Approval/audit state in shared `/tmp/orcel` can be pre-created, symlinked or read by another user | per-OS 0700 state root; refuse symlinks, foreign owner, group/other bits; no temp fallback | symlink/permission negative tests | XP-01 |
| S-01b | Any non-Windows build (found by the #345 security review) | Full-control authority, executable registry, remote-lease stores (`orcel-policy`), trust records (`orceld/src/trust.rs`) and the browser profile (`orcel-provider-browser`) default to `std::env::temp_dir()/orcel` | same private state root; error instead of temp; protected-path list never loses coverage | grep test; symlinked root refused | XP-01B (fixed: release_blocker_sweep `xp01b_*` rules; per-store symlink and world-writable tests; old temp state ignored, not migrated) |
| S-02 | Native host on macOS/Linux (Cua) | Vendored code reaches a socket, CDP endpoint, QuickJS or telemetry | P-03 compiles them out; enum dispatch; fd audit test; `cargo deny`/`cargo audit` on the host workspace | binary symbol check; fd test | XP-05, XP-06 |
| S-03 | macOS approvals | Same-user process draws a fake prompt or answers the helper | SOFT: system-owned CFUserNotification returns a decision for the prompt submitted by the broker; the broker and ledger bind the resulting decision to that prompt's nonce and digest; STRONG: in-process LocalAuthentication (no separate helper); residual same-user spoofing documented as on Windows | XP-09 native regression tests plus real-hardware GUI and SSH-origin checks (2026-10-19; issue #362) | XP-09 (Mac live approval/denial and genuine SSH-origin rejection **verified on real hardware** 2026-10-19; release review and platform packaging remain separate gates). SOFT is a system `CFUserNotification` caution alert, default button Deny, body fields bounded and escaped; STRONG is LocalAuthentication `DeviceOwnerAuthentication` in the broker's own process, so there is no helper and no IPC answer to verify; the T-CUA-27 signature check is needed only if XP-16 moves presence into a helper. The SOFT UI returns only a decision; the broker supplies the originating request, and the ledger binds the decision to its nonce and digest when recording it. The UI itself never performs request binding. No GUI session (`SessionGetInfo` failing, without `sessionHasGraphicAccess`, or with `sessionIsRemote`), a CI runner, cancel, timeout or an unshowable dialog is denied or unavailable, never approved and never a SOFT downgrade of STRONG. Residual risk as on Windows: a same-user process can draw a look-alike window, and one the person has granted the Accessibility permission could click the alert's Approve button, as `SendInput` can on Windows; it cannot supply Touch ID or the password that STRONG requires. Tests: `xp09_*` in `crates/orcel-approval`; CI runs the real macOS path headless) |
| S-04 | Linux approvals | Fake polkit agent; headless session silently auto-approves; the STRONG prompt cannot show the digest (polkit takes `--detail` only from root) | `auth_self` for active sessions only (`allow_any=no`, `allow_inactive=no`), never `allow_active=yes`; no agent → unavailable; STRONG always follows the SOFT helper that shows the full body; residual risks documented: a same-user text agent (for example `pkttyagent`) started inside the active session can register and answer `auth_self`, as same-user prompt spoofing on Windows; STRONG text is static | dbus mock denial; headless unavailable | XP-10 |
| S-05 | macOS background input (SkyLight SPI) | Private API changes behavior after an OS update; events reach the wrong process | capability-gated; post-to-pid only with bound pid+generation; public fallback; re-observe after every action | conformance cells per macOS release | XP-12 |
| S-06 | Browser on macOS/Linux | `http://0.0.0.0:9` no-route proxy reaches loopback; a local listener receives confined traffic | host-owned loopback sink port held for the lifetime | listener-on-9 receives zero bytes | XP-14 |
| S-07 | Browser on Linux | Engine binary authenticity weaker than Authenticode/codesign | package ownership + package signature status + pinned path; report `verification: package` in status | tampered binary refused when package check fails | XP-14 |
| S-08 | New browser actions | fill/select/check/press used to submit secrets or unintended forms | secret fields refused; value digest in SOFT approval; navigation ends multi-action proposals | negative tests in BR-02 | BR-02 |
| S-09 | Uploads | Data exfiltration to an admitted origin | separate grant per file and origin; staged copy; STRONG for sensitive workspaces | origin mismatch refused | BR-03 |
| S-10 | Dialogs | Auto-accepting `confirm()` triggers destructive page actions | default dismiss; accept is its own SOFT action with dialog text digest | dismiss without approval | BR-05 |
| S-11 | Cross-frame observation | Hidden third-party frame text steers the model | only admitted frame origins; same hidden-text rules; untrusted labelling | non-admitted frame omitted | BR-06 |
| S-12 | Stale-ref recovery | Re-resolution acts on a different element | equality on role + name + frame; exactly one match | swap test | BR-01 |
| S-13 | Firecrawl regex scope | ReDoS or huge patterns | `regex` crate (no backtracking) with size and DFA limits; pattern count/length bounds | oversize pattern refused | WI-01 |
| S-14 | Document parser | Malicious PDF/Office exploits parser | separate process, no network, no write, time/size bounds; macros and external links never evaluated | fuzz 10 min; zip bomb bounded | WI-05 |
| S-15 | Control Room (Tauri) | Renderer compromise reaches mutating IPC; remote content loads | command allowlist (read-only first), CSP `default-src 'self'`, no remote URLs, no shell/fs plugins, no updater plugin | unlisted command refused; navigation blocked | CR-03 |
| S-16 | AgentKit import | UI answers approvals | approval commands removed on import; static check | bundle grep test | CR-02 |
| S-17 | Kernel journal | Torn writes or two writers corrupt outcomes; blind retry duplicates effects | one writer lock, fsync, parent dir sync on Unix; `unknown` blocks dependents; no auto-retry | crash at each transition | RJ-01, RJ-02 |
| S-18 | Sandboxes | Escape; network egress; default credentials (Lume) | gVisor/VM isolation; `--network=none`; per-VM credentials; no published ports; runtime binaries pinned | egress blocked; default login refused | SX-* |
| S-19 | Search adapters | API key leakage; arbitrary egress | keys in OS secret store; destination pinned per provider; key never in tool output | output scan | WI-06 |
| S-20 | Agent-Reach channels | Cookie export, personal browser sessions (OpenCLI) | `cookie_extract.py` and OpenCLI channels rejected | n/a | - |
| S-21 | Cua cuabot | Known upstream security issues | rejected | n/a | - |
| S-22 | Packaging macOS | TCC grants attached to an unsigned or changing binary; users re-grant to anything named Orcel | stable bundle id + Developer ID signature; doctor verifies signature | tampered bundle refused | XP-16 |
| S-23 | Secrets on Linux without a keyring | Plaintext fallback | unavailable, never plaintext | test | XP-19 |
| S-24 | Cua `biometric.rs` copy (XP-09, XP-10) | Two donor env bypasses: `CUA_ENV_SKIP_SENSITIVE_AUTH` (skips the gate entirely in any debug build, including `cargo test`) and `CUA_ENV_ALLOW_UNVERIFIED_SENSITIVE_EXPORT` | both deleted on import; Windows CredUI fallback not taken | test in debug and release builds: neither variable changes a STRONG outcome | XP-09 (done for macOS: `xp09_donor_bypass_variables_are_not_read_by_shipped_code`, and the macOS CI step runs `xp09_*` in debug and release with both variables set), XP-10 |
| S-25 | Cua containment copy (XP-13, WI-05) | macOS boundary relies on deprecated `sandbox-exec`; seccomp is per-architecture | capability report stays truthful; refuse to spawn when a boundary cannot be installed; unsupported arch refused | capability-refusal tests per OS | XP-13 (done: `apps/orcel-contain` refuses when `capabilities()` misses a boundary on every OS; Linux refuses without Landlock or below ABI 3 (`xp13_a_kernel_without_landlock_makes_the_helper_refuse`, seccomp-faked ENOSYS) and on an architecture without a seccomp table; macOS refuses without `sandbox-exec`; Windows refuses when the AppContainer profile cannot be created. The donor bypass and fixture variables (`CUA_ENV_SKIP_*`, `CUA_ENV_ALLOW_UNVERIFIED_*`, `CUA_TEST_PYTHON*`, `CUA_DRIVER_ACL_RENAME_*`) are not read: `xp13_donor_bypass_variables_are_not_honoured` sets them on the helper and the boundary holds. The helper is pinned by SHA-256 (`xp13_a_tampered_or_unpinned_helper_is_refused`).) |
| S-26 | Cua Spaces Tauri scaffolding (CR-03) | Donor CSP allows `'wasm-unsafe-eval'` and `ws:`/`wss:`; donor ships an updater plugin, `createUpdaterArtifacts`, process restart and `macOSPrivateApi` | CSP tightened; updater, updater artifacts, process permission and private macOS API removed; single read-only command | CSP and capability tests | CR-03 |
| S-27 | Cua `caller.rs` peer identity (CR-01) | Linux same-uid processes can ptrace each other, so binary identity is not provable | Linux peers trusted only as same uid (`os_verified: false`), as upstream marks them | other-uid refused; Linux peer never reported verified | CR-01 |

### XP-09 manual live check (macOS)

CI cannot answer a dialog, so the approving path is checked by hand on a Mac at the keyboard, outside CI, in a GUI login session with Touch ID or a login password:

1. `ORCEL_LIVE_APPROVAL_DIALOG=1 ORCEL_LIVE_APPROVAL_EXPECT=approve cargo test -p orcel-approval xp09_live -- --nocapture --test-threads=1`. A caution alert titled "Orcel approval SOFT" shows the request; Deny is the default button. Click Approve. Then the LocalAuthentication prompt names the STRONG request; confirm with Touch ID or the password. The test passes only if both are approved.
2. Run it again with `ORCEL_LIVE_APPROVAL_EXPECT=deny`: press Return on the alert (Deny) and cancel the LocalAuthentication prompt. The test passes only if both are refused.
3. Over SSH to the same Mac, the same commands with `approve` fail (no GUI session); `cargo test -p orcel-approval xp09_macos_headless` passes there and nothing is shown.

Record the macOS version, hardware, and observed outcome as GitHub evidence (issue #362 and PR #361).

Status 2026-10-19: **ALL THREE LIVE QUALIFICATION CHECKS PASS** on MacBook Pro Mac14,7 (Apple M2, macOS 26.6.2) at merged commit `ceec7a0`. The founder answered both actual GUI prompts: SOFT Approve and STRONG LocalAuthentication succeeded; SOFT Deny and STRONG cancellation returned `ApprovalDenied`. A separate **real OpenSSH login** into the same Mac was classified as `NoGraphicSession` (`SessionGetInfo Ok(5000)`); `ORCEL_REQUIRE_XP09_HEADLESS=1` ran the true SOFT/STRONG failure-closed paths (1/1 pass, no prompt). Attempting the approval-mode live test from SSH failed its GUI-session precondition as expected. Remote Login was returned to off and the temporary test credentials were deleted, with port 22 verified closed. Native `cargo fmt --check`, full-workspace clippy and tests (927 passed, 0 failed, 1 ignored) and XP-09 21 unit/contract tests passed. Full evidence: [issue #362](https://github.com/TheHalfMoon/Orcel/issues/362#issuecomment-6266816540), [PR #361](https://github.com/TheHalfMoon/Orcel/pull/361). This evidence qualifies XP-09's manual macOS approval/denial/remote-session gate; it does not imply that the overall macOS product or release packaging is qualified. Note the GitHub `macos-latest` runner's `SessionGetInfo` may report graphic access (`0x2030`), so CI's `CI`/`GITHUB_ACTIONS` guard is still mandatory to prevent unattended prompts.

## 4. Forbidden introductions (checked at review)

- A second privileged MCP execution authority (Cua `cua-driver mcp`, Playwright MCP server, Desktop Commander server, Cua Spaces `/mcp`).
- Independent desktop input outside the host protocol (Agent-Native helper, nut-js operators).
- Duplicate browser channels (extensions, CDP ports, Cua's CDP engine, `--grant existing-profile`).
- Hidden approvals (any UI or donor code that resolves a pending approval).
- Automatic privilege escalation (gsudo paths that bypass consent; polkit `allow_active=yes`; macOS privileged helpers without user authorization).
- Uncontrolled secret access (cookie export, storage dumps, `webstorage.ts`, `cookies.ts`).
- Unsafe retry (re-dispatch after an unknown outcome).

## 5. Release-blocking acceptance tests for the cross-platform track

1. #278 approval ledger regressions pass on macOS and Linux.
2. No non-test `std::env::temp_dir()` use in approval, audit, policy-store, trust, browser-profile or journal paths (grep in CI).
3. Native host: fd audit shows only inherited stdio; no listening socket in `lsof`/`ss` during the conformance suite.
4. Browser network-leak suite on macOS and Linux, including the port-9 listener case.
5. Control Room IPC allowlist test and CSP test.
6. Every imported unit has a provenance record whose object SHAs match the donor pin (`tools/readiness_check.py --donors`).
