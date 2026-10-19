# Cross-platform architecture: Windows, macOS, Linux

Status: FOUNDER-DIRECTED goal (2026-10-18: all three OSes are first-class); the design below is ADOPTED (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`). It grants no authority. Owning tasks: `backlog/tasks.json` XP-01..XP-20.

## 1. Rule

Same kernel, same policy, same tool names, same approval semantics on every OS. Only adapters differ. An adapter reports facts and performs one bound operation; it never decides policy, mints identity, retries, or widens scope. When an OS cannot prove a binding, the capability is reported `unavailable` or `refused` with a typed reason, and the tool says so. No silent fallback.

```text
MCP clients / Control Room / founder AI
          |
     apps/orcel-mcp (Node edge, unchanged)        app API (CR-01, local IPC)
          |                                              |
        orceld  ── policy, approvals, leases, journal, dispatch (one authority)
          |
  ┌───────┼───────────────┬────────────────────┬─────────────────┐
  |       |               |                    |                 |
orcel-platform   providers (fs, git,     computer host          browser host
(paths, identity, process, clipboard,    orcel-computer-host/2  (Rust) + worker
 peer creds,      network)               Win: Go host (kept)    (playwright-core)
 secrets,                                mac/Linux: orcel-native-host
 presence)                                 (Rust, embeds Cua Driver platform crates)
```

## 2. Per-OS adapter table

| Concern | Windows (today) | macOS (new) | Linux (new) | Task |
|---|---|---|---|---|
| State root | `%LOCALAPPDATA%\Orcel` | `~/Library/Application Support/Orcel` (0700) | `$XDG_STATE_HOME/orcel` else `~/.local/state/orcel` (0700) | XP-01 |
| Runtime sockets | named pipes with DACL | Unix socket in state root | `$XDG_RUNTIME_DIR/orcel` (0700) | CR-01 |
| Process generation | creation time | `proc_pidinfo` BSD start time | boot id + `/proc/<pid>/stat` starttime | XP-03 |
| Session identity | SID + logon session | uid + audit session id | uid + login session id | XP-03 |
| IPC peer check | pipe client pid + token | `getpeereid` + `LOCAL_PEERPID` | `SO_PEERCRED` | XP-03 |
| SOFT approval | `MessageBoxW` system-modal | `CFUserNotificationDisplayAlert`, default Deny | broker-spawned GTK4 helper, default Deny | XP-09, XP-10 |
| STRONG presence | Windows Hello `UserConsentVerifier` | LocalAuthentication in a signed helper | polkit `auth_self` action `ai.orcel.approve.strong` | XP-09, XP-10 |
| Accessibility tree | UIA (Go host) | AX via Cua `platform-macos/src/ax` | AT-SPI via Cua `platform-linux/src/atspi` (pure Rust zbus) | XP-06 |
| Window list and identity | HWND + pid + generation + nonce | CGWindowID + pid + generation + nonce | X11 window id or Wayland toplevel token + pid + generation | XP-06 |
| Window capture | Go host `native_capture_windows.go` | ScreenCaptureKit via Cua `capture.rs` | X11 MIT-SHM, wlroots screencopy; GNOME/KDE via portal (later) | XP-07 |
| Semantic actions | UIA patterns | AX actions (background) | AT-SPI actions (background) | XP-11 |
| Raw input | `SendInput`, fresh human-input tick | CGEvent / SkyLight post-to-pid; idle via `CGEventSourceSecondsSinceLastEventType` | XTest/MPX on X11; Sway; GNOME portal/libei; KDE refused | XP-12 |
| Clipboard | Win32 | NSPasteboard via `clipboard-rs` | X11/Wayland via `clipboard-rs` | XP-15 |
| Process confinement | Job Objects, AppContainer | process group, rlimits, kqueue; Seatbelt only as defense in depth | process group, pidfd, cgroup v2, Landlock, seccomp | XP-13 |
| Browser engine discovery and verification | Authenticode | `SecStaticCodeCheckValidity` with vendor team id | package ownership + signature status (weaker) | XP-14 |
| Browser no-route proxy | `0.0.0.0:9` | host-owned loopback sink | host-owned loopback sink | XP-14 |
| Secrets | DPAPI (current user) | Keychain (default user keychain; unsigned-binary ACL until XP-16) | Secret Service over a local session bus (unavailable without a keyring daemon, never plaintext) | XP-19 (done; S-23) |
| Daemon lifecycle | per-user install | LaunchAgent, signed app bundles | systemd `--user` unit | XP-16, XP-17 |
| Node runtime | pinned (SG-000106) | pinned per arch | pinned per arch | XP-18 |
| Privileged operations | gsudo-derived broker (SG-000098) | Authorization Services / SMAppService (new, later) | polkit/pkexec (new, later) | after SG-000098 |

## 3. Native computer-use engine decision

Candidates compared (source inspection, pins in `donor_registry.json`):

| Candidate | macOS | Linux | Windows | Evidence | Verdict |
|---|---|---|---|---|---|
| Orcel Go host (from Open Computer Use) | - | - | UIA, capture, foreground input; qualified SG-000094/95 | Orcel CI and native suites | KEEP for Windows |
| Cua Driver platform crates (Rust, MIT) | AX tree with walk budgets, ScreenCaptureKit, background input via SkyLight/AX, permissions gate, app launch | AT-SPI over zbus, X11 (x11rb, XTest, MPX), wlroots/Sway, GNOME/KDE identity helpers, portal/libei | UIA, WGC capture, background input, UIAccess worker | Upstream accepted matrix: macOS 145/145, X11 116/116, Sway 116/116, Windows 122/122 (SOURCE-DOCUMENTED, `libs/cua-driver/docs/action-support.md`); same toolchain 1.97.1 and edition 2021 as Orcel | ADOPT for macOS and Linux (WRAP in-process); bake-off for Windows (XP-20) |
| Open Computer Use macOS/Linux (newer than the Orcel pin) | Swift kit (~21.5K lines) | Go, X11 only, shells out to xdotool/ffmpeg | Go (Orcel's donor) | Upstream docs: Linux window tools "in progress" | REFERENCE; fallback if Cua fails its gate |
| Agent-Native macOS helper | Foreground `CGEvent` to the HID tap, frontmost app only, no capture | - | - | 639-line Swift file | REJECT as an engine |
| Desktop Commander | - | - | - | Terminal/files only | Not a desktop engine; SG-000096 terminal donor |
| UI-TARS | - | - | - | Model action parser | SG-000104 parser only |

Why Cua is subordinate, not a peer: `cua-spacesd` itself links the platform crates in-process and "never injects input itself" (`libs/cua-spacesd/README.md`), and Cua's authorization lives above the tool layer (`cua-driver-core/src/authorization.rs`, `session_authorization.rs`), not in the platform tools. Orcel's host calls the tool implementations directly; Cua's MCP server, HTTP envelope, daemon, browser engine, run_script and history are never constructed (patch P-03 compiles them out). There is still one authority: `orceld`.

## 4. Private host protocol `orcel-computer-host/2` (skeleton; full spec is XP-04's deliverable)

- Transport: stdio JSON lines, inherited pipes, no listener. Request ≤ 64 KiB, response ≤ 16 MiB, unchanged bounds from `/1`.
- `hello` request: `{"id", "protocol": "orcel-computer-host/2", "op": "hello"}`. Response adds:

```json
{
  "platform": "macos",
  "backend": "ax",
  "host_version": "0.1.0",
  "donor": {"name": "cua-driver", "commit": "a802eaf26ca97616a6bf0de6a29729a9346fbb1f"},
  "permissions": {"accessibility": "granted", "screen_recording": "missing"},
  "capabilities": {
    "list_windows": {"support": "delivered"},
    "observe_window": {"support": "delivered"},
    "capture_window": {"support": "unavailable", "reason": "permission_missing"},
    "semantic_action": {"support": "delivered", "delivery": "background"},
    "input_click": {"support": "delivered", "delivery": "background"},
    "input_hotkey": {"support": "refused", "reason": "background_unavailable"}
  }
}
```

- Window reference in every bound request: `{"kind": "hwnd|cgwindow|x11|wl_toplevel", "id": u64, "expected_pid": u32, "expected_start_generation": u64, "expected_window_nonce": u64}`. `/1` fields (`hwnd`, `expected_*`) remain accepted from Windows callers.
- Refusal codes (closed set, mapped to existing `orcel_contracts::FailureCode` by the Rust adapter): `invalid_request`, `capability_denied`, `target_stale`, `permission_missing`, `background_unavailable`, `background_occluded`, `background_uipi_blocked`, `protected_surface`, `output_limit`, `timeout`, `provider_unavailable`.
- Capability omission means unavailable. The registry never treats `delivered` as permission; it only skips calls that cannot work.

## 5. Tool names stay

Public tool names (`desktop_window_tree` → `uia.tree/observe`, `desktop_element_invoke` → `uia.element/invoke`, ...) are compatibility identifiers (`docs/identity/ORCEL_RENAME.md`). On macOS and Linux the same names drive AX and AT-SPI. `system_status` reports the backend so clients can tell. Renaming is out of scope.

## 6. Capability matrix (target and evidence state)

`T` = target in the named task; `-` = not planned; evidence is attached when the task lands (no Orcel evidence exists yet for macOS/Linux).

| Capability | Windows | macOS | Linux X11 | Linux Sway | Linux GNOME | Linux KDE | Task |
|---|---|---|---|---|---|---|---|
| list/observe windows | qualified | T | T | T | T (helper) | T (identity only) | XP-06 |
| window capture | qualified | T | T | T | T (portal) | T (portal) | XP-07, XP-12 |
| semantic actions | qualified | T | T | T | T | T | XP-11 |
| raw input | qualified (foreground) | T (background + foreground) | T | T | T (portal/libei) | refused by design | XP-12 |
| approvals SOFT/STRONG | qualified | T | T | T | T | T | XP-09, XP-10 |
| browser (SG-000108 policies) | in progress | T | T | T | T | T | XP-14 |
| process Safe | qualified | T | T | T | T | T | XP-13 |
| clipboard | qualified | T | T | T | T | T | XP-15 |
| Control Room | WPF preview | T (Tauri) | T | T | T | T | CR-03 |
| install/update/rollback | qualified | T | T | T | T | T | XP-16, XP-17 |

## 7. Packaging and what Tauri does not solve

A cross-platform UI toolkit does not give native capability. Tauri or any other shell changes how the Control Room renders; desktop control, approvals, confinement and engine verification are still per-OS kernel work (section 2). Packaging per OS:

- **Windows:** existing per-user lifecycle; adds the Control Room payload when CR-03 lands.
- **macOS:** `Orcel.app` (Control Room) and an embedded `Orcel Computer Host.app` helper with its own bundle id so Accessibility and Screen Recording grants attach to a stable signature; LaunchAgent for `orceld`; Developer ID signing and notarization (FD-05).
- **Linux:** per-user tarball with a systemd user unit; a small deb/rpm only for the polkit action file; AppImage not planned (no system integration for polkit).

## 8. Order

X0 foundation (XP-01..04, BM-01, CR-01) has no authority delta and can start now. X1 adds read-only observation on macOS/Linux. X2 adds approvals; X3 adds actions; X4 browser/process/clipboard; X5 packaging. See ROADMAP.md.
