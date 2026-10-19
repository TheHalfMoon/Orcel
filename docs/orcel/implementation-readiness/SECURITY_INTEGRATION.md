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
| S-03 | macOS approvals | Same-user process draws a fake prompt or answers the helper | prompt owned by system (CFUserNotification) or a code-signature-verified helper; nonce binding; residual same-user spoofing documented as on Windows | wrong-signature helper refused | XP-09 (implemented, **not release-qualified** until the manual live check below passes on real Mac hardware (FD-05 open; not run). SOFT is a system `CFUserNotification` caution alert, default button Deny, body fields bounded and escaped; STRONG is LocalAuthentication `DeviceOwnerAuthentication` in the broker's own process, so there is no helper and no IPC answer to verify; the T-CUA-27 signature check is needed only if XP-16 moves presence into a helper. Every answer is bound to the request's nonce and digest before the ledger records it. No GUI session (`SessionGetInfo` failing, without `sessionHasGraphicAccess`, or with `sessionIsRemote`), a CI runner, cancel, timeout or an unshowable dialog is denied or unavailable, never approved and never a SOFT downgrade of STRONG. Residual risk as on Windows: a same-user process can draw a look-alike window, and one the person has granted the Accessibility permission could click the alert's Approve button, as `SendInput` can on Windows; it cannot supply Touch ID or the password that STRONG requires. Tests: `xp09_*` in `crates/orcel-approval`; CI runs the real macOS path headless) |
| S-04 | Linux approvals | Fake polkit agent; headless session silently auto-approves; the STRONG prompt cannot show the digest (polkit takes `--detail` only from root) | `auth_self` for active sessions only (`allow_any=no`, `allow_inactive=no`), never `allow_active=yes`; no agent → unavailable; STRONG always follows the SOFT helper that shows the full body; residual risks documented: a same-user text agent (for example `pkttyagent`) started inside the active session can register and answer `auth_self`, as same-user prompt spoofing on Windows; STRONG text is static | dbus mock denial; headless unavailable | XP-10 (implemented, **not release-qualified** until the manual live check below passes on a real GNOME and KDE desktop (not run; no Linux desktop available). SOFT is the GTK4 helper `apps/orcel-approval-helper-linux`, spawned by orceld from a pinned path (next to orceld, else `/usr/libexec/orcel/`; owner root or the user, writable by nobody else, never `PATH`) with a cleared environment except a fixed display/session-bus allowlist; the request goes in on stdin with a fresh 128-bit channel nonce and exactly one answer line with that nonce is accepted from stdout (both pipes orceld's own), so a forged, missing or replayed nonce, extra output, a crash, silence or a hang fails closed. Deny is the default button, Approve is insensitive for 1.5 s, Escape, close and the 120 s timeout deny; the body fields are bounded and escaped by orceld (`display_field`) and the helper refuses unescaped text. STRONG shows the full request (workspace, action, target, summary, digest, nonce prefix) in the helper first and only after Approve asks polkit `CheckAuthorization` for `ai.orcel.approve.strong` through the pinned root-owned `/usr/bin/pkcheck` (`--allow-user-interaction`, never `--enable-internal-agent`); polkit exit 1 is denied, 2 (no agent) unavailable, 3 cancelled, errors and D-Bus failures unavailable or failed, a missing policy or pkcheck unavailable. Every path except an active, local (non-remote) X11/Wayland logind session of class `user` with `WAYLAND_DISPLAY`/`DISPLAY`, outside SSH and CI, is unavailable before anything is shown; a session that cannot be read is too. The broker and ledger bind every answer to the request's nonce and digest; STRONG never degrades to SOFT. Policy `distribution/linux/ai.orcel.approve.policy`: `allow_any=no`, `allow_inactive=no`, `allow_active=auth_self` (T-CUA-35; packaged by XP-17). Tests: `xp10_*` in `crates/orcel-approval` on every OS (pure session classification, answer parsing, helper protocol cross-check, pkcheck mapping, escaping, policy file); on Linux the real runner against scripted helpers; CI runs the real headless path in debug and release and the real GTK helper under Xvfb) |
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
| S-24 | Cua `biometric.rs` copy (XP-09, XP-10) | Two donor env bypasses: `CUA_ENV_SKIP_SENSITIVE_AUTH` (skips the gate entirely in any debug build, including `cargo test`) and `CUA_ENV_ALLOW_UNVERIFIED_SENSITIVE_EXPORT` | both deleted on import; Windows CredUI fallback not taken | test in debug and release builds: neither variable changes a STRONG outcome | XP-09 (done for macOS: `xp09_donor_bypass_variables_are_not_read_by_shipped_code`, and the macOS CI step runs `xp09_*` in debug and release with both variables set), XP-10 (done for Linux: `xp10_no_environment_variable_can_approve` scans the shipped `linux.rs` for every environment read, and the Linux CI step runs `xp10_*` in debug and release with both variables set) |
| S-25 | Cua containment copy (XP-13, WI-05) | macOS boundary relies on deprecated `sandbox-exec`; seccomp is per-architecture | capability report stays truthful; refuse to spawn when a boundary cannot be installed; unsupported arch refused | capability-refusal tests per OS | XP-13 |
| S-26 | Cua Spaces Tauri scaffolding (CR-03) | Donor CSP allows `'wasm-unsafe-eval'` and `ws:`/`wss:`; donor ships an updater plugin, `createUpdaterArtifacts`, process restart and `macOSPrivateApi` | CSP tightened; updater, updater artifacts, process permission and private macOS API removed; single read-only command | CSP and capability tests | CR-03 |
| S-27 | Cua `caller.rs` peer identity (CR-01) | Linux same-uid processes can ptrace each other, so binary identity is not provable | Linux peers trusted only as same uid (`os_verified: false`), as upstream marks them | other-uid refused; Linux peer never reported verified | CR-01 |

### XP-09 manual live check (macOS)

CI cannot answer a dialog, so the approving path is checked by hand on a Mac at the keyboard, outside CI, in a GUI login session with Touch ID or a login password:

1. `ORCEL_LIVE_APPROVAL_DIALOG=1 ORCEL_LIVE_APPROVAL_EXPECT=approve cargo test -p orcel-approval xp09_live -- --nocapture --test-threads=1`. A caution alert titled "Orcel approval SOFT" shows the request; Deny is the default button. Click Approve. Then the LocalAuthentication prompt names the STRONG request; confirm with Touch ID or the password. The test passes only if both are approved.
2. Run it again with `ORCEL_LIVE_APPROVAL_EXPECT=deny`: press Return on the alert (Deny) and cancel the LocalAuthentication prompt. The test passes only if both are refused.
3. Over SSH to the same Mac, the same commands with `approve` fail (no GUI session); `cargo test -p orcel-approval xp09_macos_headless` passes there and nothing is shown.

Record the macOS version, the hardware (Touch ID or not) and the outcome in the PR.

Status 2026-10-19: **NOT RUN**. No Mac hardware is available and FD-05 (self-hosted Mac runner) is open. macOS approvals are implemented and fail closed in CI, but they are not release-qualified until steps 1-3 pass on real hardware. Note that the GitHub `macos-latest` runner's session reports `SessionGetInfo` attributes `0x2030` (graphic access), so in CI only the `CI`/`GITHUB_ACTIONS` guard keeps prompts from showing; the session classification itself is covered by synthetic-input unit tests (`xp09_session_classification_fails_closed`).

### XP-10 manual live check (Linux)

CI cannot answer a dialog or a polkit agent, so the approving path is checked by hand at the keyboard of a Linux desktop, outside CI and SSH, once on GNOME (Wayland) and once on KDE Plasma (X11 or Wayland), each with its own polkit authentication agent running:

1. Build the helper and install the policy (development only; XP-17 packages both): `cargo build --release --manifest-path apps/orcel-approval-helper-linux/Cargo.toml`, then `sudo install -m 0644 distribution/linux/ai.orcel.approve.policy /usr/share/polkit-1/actions/` and `sudo install -D -m 0755 apps/orcel-approval-helper-linux/target/release/orcel-approval-helper-linux /usr/libexec/orcel/orcel-approval-helper-linux`.
2. `ORCEL_LIVE_APPROVAL_DIALOG=1 ORCEL_LIVE_APPROVAL_EXPECT=approve cargo test -p orcel-approval xp10_live -- --nocapture --test-threads=1`. A window titled "Orcel approval SOFT" shows the request; Deny has focus and Approve becomes clickable after 1.5 s. Click Approve. Then "Orcel approval STRONG" shows the STRONG request with its digest; click Approve, and the desktop's polkit agent asks for your password (or fingerprint) with the static Orcel message. Authenticate. The test passes only if both are approved.
3. Run it again with `ORCEL_LIVE_APPROVAL_EXPECT=deny`: press Return in the SOFT window (Deny), press Escape in the STRONG window. Run once more with `deny` and click Approve in the STRONG window but cancel the polkit prompt. Each run passes only if both requests are refused.
4. Over SSH to the same machine, and from a second, inactive session (switch user), the same command with `approve` fails (no active local graphical session) and nothing is shown; `cargo test -p orcel-approval xp10_linux_headless -- --nocapture` passes there.
5. Stop the polkit agent (for example kill `polkit-gnome-authentication-agent-1` or `polkit-kde-authentication-agent-1`), rerun step 2 and approve the STRONG window: it must fail as unavailable (pkcheck status 2), never approve.

Record the distribution, desktop, session type, agent and the outcome of every step in the PR.

Status 2026-10-19: **NOT RUN**. No Linux desktop is available. Linux approvals are implemented and fail closed in CI (the real headless path in debug and release, and the real GTK helper under Xvfb timing out to deny), but they are not release-qualified until steps 1-5 pass on GNOME and KDE.

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
