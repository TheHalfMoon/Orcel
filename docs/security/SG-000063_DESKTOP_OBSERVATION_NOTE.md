# SG-000063 Structured Desktop Observation Note

Status: IMPLEMENTATION FOR ORCEL-P16
SpecGrain: SG-000063
Base: `0f41c0c8f7b5461ee32ecb595d44e6adb43844cf`
Date: 2026-10-02
Code: `crates/orcel-provider-uia/src/native_desktop.rs`,
`crates/orcel-provider-uia/src/lib.rs` (`NativeAdapter`,
`DESKTOP_SHAPE_QUALIFICATIONS`, `UiaRegistry::observe_tree`),
`apps/orcel-mcp/src/desktop.ts`, `apps/orcel-mcp/src/oauth_authorization.ts`
(`LOCAL_ONLY_TOOL_NAMES`). Decision record:
`docs/p16/DESKTOP_QUALIFICATION.md`.

## 1. New MCP tools

| Tool | Shape | Approval | Bounds |
| --- | --- | --- | --- |
| `desktop_window_list` | `uia.window/list` | none (read) | 64 windows, 256 chars per string, 64 KiB response |
| `desktop_window_tree` | `uia.tree/observe` | none (read) | depth 8, 256 nodes, 256 chars per string, 64 KiB response; bound to `window_id` and `window_generation`; SG-000128: optional `root_element_id` with its `tree_generation` (an element issued for that window in its latest tree, both or neither) reads below that element with the same bounds, at most 8 such reads per window until the window itself is replaced (process instance, nonce or class; not a title change) or an approved action on it succeeds |

Both reuse the existing SG-000027 kernel shapes, policy authorization, and
registry. No kernel shape, policy rule, or approval class is added.

## 2. Authority delta

- Process: read-only facts (image name, image digest, session, creation
  time) for processes that own visible top-level windows in the caller's
  session. No process is opened with more than
  `PROCESS_QUERY_LIMITED_INFORMATION`, and none is signalled or terminated.
- UI: read-only. The adapter calls `EnumWindows`, `IsWindowVisible`,
  `GetWindowTextW`, `GetClassNameW`, `DwmGetWindowAttribute(DWMWA_CLOAKED)`,
  `GetWindowThreadProcessId`, and UI Automation property and pattern
  getters on the control view. It never sends window messages, calls a
  pattern's actuation method, sets focus, activates a window, synthesizes
  input, or captures pixels.
- Filesystem, network, browser, clipboard, secrets, approval, privilege:
  none.

## 3. Observation boundaries

- Interactive station only: any window station other than `WinSta0` fails
  closed as unavailable, so a service or non-interactive host reports no
  desktop rather than an empty one.
- Same session only: windows of processes in another session are never
  listed; their trees are denied.
- Self and Orcel exclusion: windows of the observing process and of
  `orcel.exe`, `orceld.exe`, and `orcel-mcp-host.exe` are never listed.
- Windows security prompt exclusion: windows of `CredentialUIBroker.exe`
  (which hosts the Windows Hello STRONG approval dialog), `consent.exe`, and
  `LogonUI.exe` are never listed, and a tree read is denied if the handle's
  owner is one of them at read time.
- Protected markers: titles or classes carrying a Orcel approval, trust, or
  emergency-revoke marker are omitted and counted.
- Unidentifiable owners: a process whose image path or creation time cannot
  be read is omitted rather than given a fabricated identity.

## 4. Redaction

Password values are never read: when UIA reports `IsPassword` true, or the
flag cannot be read, the adapter does not call `ValuePattern.CurrentValue`.
The registry also redacts any element whose control type, automation id, or
name carries a password, secret, or token marker. Redacted elements carry
`redacted: true` and a null value.

## 5. Stale identity

Window identities are typed and generation-bound. Before every tree read
the registry re-lists the owning process's windows and requires the same
handle with the same process-instance nonce (PID and creation time) and the
same class; otherwise it fails closed as `TARGET_STALE`. A drifted
`window_generation` fails closed as `TARGET_STALE`. Tree reads re-register
elements under a new tree generation every call.

## 6. Hang resistance

UIA connection and transaction timeouts are 2 s and 5 s, and the walk
stops one node past the registry bound, so one hung application cannot
stall orceld indefinitely or produce an unbounded response.

## 7. Remote reach

Both tools are local-only. They are absent from `OAUTH_SCOPE_TOOL_MATRIX`
and listed in `LOCAL_ONLY_TOOL_NAMES`, so the relay edge and the device
uplink deny them as `tool_unmapped` for every scope. orceld's
remote-session scope table has no `uia.*` entry, so a remote request fails
closed in the kernel as well. OAuth scopes never enable desktop
observation; a later governed grain may map a locally enabled
`desktop_structured` profile.

## 8. Not exposed

Structured invoke, set_value, select, toggle, scroll, screenshot capture,
visual and coordinate proposals, and bounded input execution are not
implemented by the native adapter and fail closed as unavailable. They are
recorded as `intentionally_denied` in the parity inventory and are pinned
off the MCP surface by tests. Raw `SendInput`, keyboard or mouse injection,
focus stealing, and process termination remain absent.

## 9. Evidence

- Real Windows 11 (interactive session): `cargo test -p
  orcel-provider-uia sg000063` creates a probe window process with a plain
  text box, a system password box, and a protected-titled form, and proves
  listing, process identity, bounded trees, truncation, password
  non-reading, protected omission, and own-window denial.
- Real end to end: `node apps/orcel-mcp/dist/index.js` with a real
  `orceld.exe` lists 28 tools, observes the probe through both desktop
  tools with the password value absent, and rejects drifted generations and
  malformed identities.
- Contract tests: `apps/orcel-mcp/src/uia.test.ts`,
  `oauth-authorization.test.ts`, `parity-inventory.test.ts`,
  `surface.test.ts`, `transport-contract.test.ts`, and the release
  qualification catalog pin the 28-tool surface and the local-only
  decision.
