# Cua Driver patch queue (Orcel)

Upstream: [trycua/cua](https://github.com/trycua/cua) at
`a802eaf26ca97616a6bf0de6a29729a9346fbb1f` (MIT, `LICENSE.md` in this
directory). Provenance, tree ids and the patched-file list:
[docs/orcel/cua_driver_provenance.json](../../../../docs/orcel/cua_driver_provenance.json).

Every file under `crates/` and `Skills/` is upstream's bytes except the files listed below.
`node scripts/check-vendored-cua.mjs` proves that in CI: it rebuilds each
crate's git tree with the upstream blob put back for every listed file and
requires the upstream tree id.

Each patch is its own commit. Rebasing to a new pin means re-importing the
crates unmodified and replaying this queue.

## Import

The seven crate directories copied blob for blob from the pin (no patch):
`platform-macos`, `platform-linux`, `cua-driver-core`, `cua-driver-contract`,
`cursor-overlay`, `pip-preview`, and `cua-cursor-motion` (a path dependency of
`cursor-overlay`, matrix row T-CUA-38), plus `Skills/cua-driver/` (T-CUA-39):
the Markdown that `cua-driver-core/src/mcp_skills.rs` embeds with
`include_str!("../../../Skills/cua-driver/...")`. It sits at the same relative
place as upstream, so that path needs no patch.

Known out-of-tree reference left as is: the `#[cfg(test)]` module of
`platform-linux/src/wayland/shell_helper.rs` includes
`../../../../../wayland-helper/winrects@cua/*`, the GNOME Shell helper that
XP-12 vendors. XP-05 builds no platform-linux test target, so nothing reads it.

## P-01: workspace wiring

Orcel side: `apps/orcel-native-host/Cargo.toml` is a standalone workspace
(the root workspace does not list it, so orceld's `Cargo.lock` is unchanged).
It carries the `[workspace.package]` and `[workspace.dependencies]` entries
the vendored manifests inherit, copied from upstream's
`libs/cua-driver/rust/Cargo.toml`. `Cargo.lock` started as upstream's lockfile,
and Cargo pruned it to this graph, so every shared crate keeps the version
upstream tested.

The vendored crate layout keeps upstream's relative paths, so no source path
needed rewriting. One manifest line changes in each of two files, so the
workspace's `cua-driver-core` `default-features = false` survives feature
unification. Without it, upstream's defaults `yaml`, `rego` and `script` (the
QuickJS `run_script` engine) come back:

- `platform-macos/Cargo.toml`: `cua-driver-core = { path = "../cua-driver-core", default-features = false }`
- `platform-linux/Cargo.toml`: the same.

`cursor-overlay` already declares `default-features = false` upstream.

## P-02: no cua-driver binary or telemetry in the graph

No vendored file changes. Upstream's telemetry lives in the `cua-driver`
binary crate: `cua-telemetry`'s config reader plus a `ureq` POST to PostHog.
That crate is not vendored, and none of the seven vendored crates depends on
it, on `cua-driver-sdk` or on any HTTP client. The patch is the guard that
keeps it that way. `scripts/check-vendored-cua.mjs` fails if
`apps/orcel-native-host/Cargo.lock` names `cua-driver`, `cua-driver-sdk`,
`cua-daemon`, `cua-telemetry`, `posthog-rs`, `ureq`, `reqwest` or `hyper`.
Cargo.lock lists every package for every target and feature, so absence there
means absence from every build. The same check also fails if the root
`Cargo.lock` names any vendored crate or `orcel-native-host`.

What "no HTTP client" does and does not cover: the lockfile still has
`tungstenite` and `tokio-tungstenite`. `cua-driver-core` declares
`tokio-tungstenite` unconditionally, and on macOS `platform-macos` declares it
with `native-tls`. Their only callers are the CDP WebSocket clients
(`cua-driver-core/src/browser/cdp_ws.rs` and `cdp.rs`, and
`platform-macos/src/browser/cdp_client.rs`),
which P-03 compiles out, so with `orcel-minimal` nothing calls them. P-03
gates code, not manifests, so the crates are still compiled. The
graph-level guarantee covers HTTP clients only, not WebSocket libraries.

XP-06 finding (no patch): on the GitHub macOS runner the live host holds two
`[ctl com.apple.netsrc]` kernel-control sockets (NetworkStatistics) from the
moment it starts, before it reads a request. The diagnostic in CI run
39352665447 (job 118400225275) linked a trivial C program against each
framework the host links, plus CFNetwork, Network and SystemConfiguration:
every variant, including the one that links nothing but libSystem, held the
same two sockets and no more. They come from libSystem's process start-up,
not from any vendored or host code, and they carry no route, address or
connection. `stdio_conformance::host_holds_only_inherited_stdio` therefore
allows exactly that socket, and only as many of them as a plain `/bin/sleep`
started beside it holds; every other descriptor must be a pipe, a character
device or a file. (CloudKit and CoreData are linked through `clipboard-rs`,
but they add no socket; the clipboard tool is not in the host's registry,
P-07.)

## P-03: feature `orcel-minimal`

`orcel-minimal` compiles out every Cua surface the Orcel host must not carry.
`orcel-native-host` turns it on for `cua-driver-core`, `platform-macos` and
`platform-linux`. With the feature off, every vendored crate compiles exactly
as upstream does. The patch only adds lines; no upstream line is deleted or
reworded.

Almost every added line is `#[cfg(not(feature = "orcel-minimal"))]` on an
item, field, field initializer, statement or match arm. The exceptions are
the feature definitions in the three manifests and these cfg-selected
replacements, each shown next to the item it replaces:

- `cua-driver-core/src/tool.rs`: an import list without `pip_hook`, `recording`
  and the recording tools. In `ToolRegistry::invoke`, the dispatch is awaited
  directly (`tool.invoke(args.clone()).await`) instead of through
  `recording::scope_dispatch_click_capture`. With no recording turn, that
  wrapper only scopes `None` around the same future.
- `cua-driver-core/src/recording_tools.rs`: imports for the one item it keeps.
- `platform-macos/src/browser/electron_js.rs`: `ElectronJs::execute_main`
  returns the error upstream already treats as "inspector route unavailable".
  The SIGUSR1-plus-CDP route into an Electron app's main process is gone. An
  Electron background drag gets upstream's `background_unavailable` refusal,
  and an Electron hover takes the native route.

### What is compiled out

cua-driver-core:
- `cdp.rs`, `daemon.rs`, `history.rs`, `perception_client.rs` (with
  `perception_client/`), `recording.rs`: the whole module.
- Dependents of those modules, also whole: `perception_tools.rs`, and the
  `pub use recording::RecordingSession` re-export.
- `browser/`: every submodule and re-export except `types` (plain serde data
  types such as `ProcessFingerprint`, carried by `consent.rs` and `tool.rs`).
  Also `download.rs` except its `MCP_HOST_DOWNLOAD_APPROVAL_ARG` constant. The
  trusted-evidence path in `tool.rs` still strips that reserved key from
  caller arguments.
- `server.rs`: the MCP request dispatch (`ToolProvider`, `handle_request*`,
  `dispatch_request`), the stdio observer and the completion classifiers. What
  remains is the closed observation vocabulary (`ToolOperation`,
  `tool_operation`, `is_computer_action`, `ToolCompletionObservation` and its
  enums), which `session.rs` uses.
- `recording_tools.rs`: every tool. Only the `ReplayRegistrySlot` type alias
  remains, used by `run_steps`.
- `tool.rs`: the `recording` and `history` registry fields and their
  initializers, `register_recording_tools`, `register_history_tools`,
  `history()`, `register_perception_tool*`, and in `invoke` the recording turn,
  history action and PiP frame push. Also the helpers only those used
  (`recording_args_for`, `is_existing_profile_prepare`,
  `synthesize_action_label`, `current_dispatch_authorization_context`) and
  the `stop_recording` approval arm.
- `capture_registry.rs`: `screenshot_to_action`, used only by recording.
- Modules with no caller left once the above is gone, also whole:
  `ffmpeg_install.rs` (runs the platform package manager to install ffmpeg),
  `video.rs`, `video_ffmpeg.rs` and `recording_render.rs` (spawn ffmpeg),
  `recording_loader.rs`, `recording_zoom.rs`, `cursor_sampler.rs` (the
  recording-time pointer poller), `pip_hook.rs` and `socket_io.rs` (framed
  writes to the daemon socket).

Still compiled with the feature on, but with no caller from the host or from
any registered tool:
- `page.rs`: the cross-platform `page` tool definition. Both platform
  backends and both registrations are compiled out, so it is never
  registered. Its CDP paths go through `cdp.rs`, which is gone.
- `mcp_wire.rs` and `mcp_skills.rs`: MCP message shaping and the read-only
  skill pack (the `Skills/` Markdown). `protocol.rs` uses `mcp_wire` for its
  response types, so both stay. Without `server.rs`'s dispatch nothing serves
  them.

platform-macos:
- `history.rs`, `recording_hooks.rs`, `video_sckit.rs`, `pip/`: the whole
  module.
- `browser/`: `ax_page_reader`, `cdp_client`, `consent_ui`, `platform`,
  `setup_ui`, `wk_web_view` and their re-exports. In `browser_js.rs`
  everything except `BrowserJs::supports` and the bundle-id table it reads,
  which removes AppleScript `do JavaScript`. In `electron_js.rs`, `execute`
  (CDP) and the inspector route above. `ElectronJs::is_electron` stays: it is
  bundle inspection, and click, drag, hotkey, scroll, set_value and type_text
  route on it.
- `tools/mod.rs`: the `page` and `kill_app` tools and their registration,
  the `cdp_sessions` state field, the browser tool engine registration,
  `register_recording_tools`, `recording_hooks::set_snapshots`, and the
  recording test module. `kill_app`'s process-identity guard came from
  `browser/platform.rs`. The tool goes whole rather than unguarded, and it is
  not on Orcel's allowlist.
- `ax/tree.rs`: `walk_native_chrome_bounded`, used only by the browser
  consent/setup UI.

platform-linux:
- `history.rs`, `recording_hooks.rs`, `video_wayland.rs`, `pip/`,
  `browser_setup_ui.rs`, `browser_consent_ui.rs`, `tools/page.rs`: the whole
  module.
- `browser_platform.rs`: everything except `is_chromium_identity`, a
  product-name predicate that `atspi/native.rs` reads.
- `tools/impl_.rs`: the `kill_app` tool (same reason as macOS) with its
  helpers and constants; `parallel_mouse_drag` with `parallel_drag_inject`
  (its `fn` drag paths evaluate caller expressions with `meval`); the Hyprland
  recording point hook; and the page, browser and recording registrations.
- `input/mod.rs`: `sample_function`, the only `meval` caller. The `meval`
  crate stays in the graph but nothing calls it.
- `proc_fs.rs` (`ProcessStat`, `read_process_stat`, `process_exit_observation`)
  and `atspi/mod.rs` (`walk_tree_for_recording`): used only by kill_app and
  recording.

The release-blocker sweep exempts unpatched vendored files from its marker,
panic/unreachable/mock and `#[ignore]` rules. A file this queue changes gets
no such exemption: `docs/orcel/cua_driver_provenance.json` records, for each
patched file, the SHA-256 of every upstream line those rules flag. The sweep
allows exactly that multiset of lines and nothing more. A blocker line that a
patch adds therefore fails the sweep as it would anywhere else.

With the feature on, the compiler reports no new warnings on either target.
The only warnings left are upstream's own.

Test note: `cargo test -p cua-driver-core --no-default-features --lib` runs
upstream's code (the feature is off). Fifteen upstream tests load a YAML
capability manifest, and without upstream's default `yaml` feature
`session_manifest::load_manifest` always returns an error. Those tests fail
on every OS, upstream included. CI skips exactly those fifteen by name.

## P-04: the host owns permission UX

`platform-macos/src/tools/mod.rs`: with `orcel-minimal`,
`ToolState::new_with_capture_service` ignores the caller's
`host_owns_permission_ux` and stores `true`. Every `ToolState`, including
`Default`, is built there, so Cua's `check_permissions` never calls
`request_accessibility` / `request_screen_recording`. It reports state only.
TCC requests belong to the Orcel host's signed identity (XP-16). Upstream's
own tests (`direct_host_runtime_cannot_raise_permission_prompts`) define what
`true` means.

The other prompt sites are unreachable from the host. They are the hidden
probe `permissions::gate::run_permission_probe_if_requested`, which a binary's
`main` must call, and the permission panel. The host's `main.rs` calls
neither.

platform-linux has no counterpart, because no TCC exists there.

`ToolState::host_owns_permission_ux` is a `pub` field, so code that holds a
`ToolState` (any of `platform_macos::tools`) could still overwrite it after
construction. Nothing does. XP-06 settles it from the host side:
- The adapter (`apps/orcel-native-host/src/cua_adapter.rs`) never holds a
  `ToolState`. It builds the registry with `register_all(.., compat: false,
  cursor_overlay_available: false, host_owns_permission_ux: true, None)` and
  only ever sees the registry. `host_source_never_touches_the_permission_ux_field`
  fails if any host source file reads or writes the field.
- `registered_check_permissions_is_a_direct_runtime_that_never_prompts`
  (macOS CI) calls the registered `check_permissions` with `prompt: true`,
  an argument the adapter itself never sends, and requires
  `source.direct_runtime == true` and `direct_capture_status == "not_checked"`:
  the request calls and the capture probe were not reached.

## P-05: no file the exact-diff review cannot read

The required Jev check reviews every changed line, in slices of at most
10,000 characters including the diff headers. It refuses binary files. Six
upstream files fail one of those limits, so they are not vendored. The
provenance file records each one (`removed_files`, with its upstream blob id
and the reason), and `check-vendored-cua.mjs` puts that blob back when it
rebuilds the upstream tree. The checker now also fails on any vendored file
that is binary or has a line longer than 9,000 characters, so a future re-pin
cannot bring one back unnoticed.

Removed:
- `cua-cursor-motion/fixtures/golden.json` (one 855,400-character line)
- `cua-cursor-motion/tests/fixtures/motion_parity.json` (540,828)
- `cursor-overlay/tests/fixtures/motion_equivalence.json` (705,133)
- `cursor-overlay/assets/cua.default.lottie` (binary, read by one test)
- `cursor-overlay/assets/Inter.ttf` (binary font, 876,576 bytes)
- `cursor-overlay/assets/cua.default.cua-theme` (binary, 14,557 bytes)

Added:
- `cursor-overlay/assets/cua.default.cua-theme.rs`: the same 14,557 bytes as
  a Rust `&[0x.., ...]` literal, 16 per line. The checker decodes it and
  requires it to hash to the upstream blob
  `0beb13487d3d84d424cec03dea9695a7d004978d`, so the theme the overlay embeds is
  still upstream's byte for byte. cursor-overlay's own theme tests (decoding,
  id, size, magic) pass against it.

Code that read the removed files: each crate gets an `upstream-assets`
feature. Every reader is behind it, and the feature is documented as needing
the files restored from the pin first:
- `cua-cursor-motion/Cargo.toml`, `cua-cursor-motion/tests/golden.rs`,
  `cua-cursor-motion/tests/motion_parity.rs`: the two fixture test crates
  (crate-level `#![cfg]`).
- `cursor-overlay/Cargo.toml`, `cursor-overlay/src/render_state.rs` (the
  `motion_equivalence_tests` module and three badge tests that need the
  font), `cursor-overlay/src/theme_artifact.rs` (the lottie test, and the
  choice between `include_bytes!` of the binary and `include!` of the array),
  `cursor-overlay/src/session_badge.rs` (its test module, and the font).
- Behavior change, only in cursor-overlay without `upstream-assets`:
  `FONT_BYTES` is empty, so `font()` returns `None` and
  `session_badge_layout` returns `None`. The session badge is not drawn, a
  case upstream already handles. The Orcel host never installs the overlay
  (`cursor_overlay_available = false`, CUA_INTEGRATION.md 2.3), so it never
  draws a badge either way.
- XP-06 (issue #355, item 4): the observation host still never installs the
  overlay, so the empty font changes nothing it can do. The decision is left
  to the first task that installs the overlay (raw input, XP-12): it must
  either build with `upstream-assets` from restored upstream bytes or vendor
  a reviewed font, and test that the badge is drawn.

cursor-overlay and cua-cursor-motion tests pass without the feature, and CI
now runs them.

## P-06: secure text values never leave the AX read (XP-06)

`platform-macos/src/ax/tree.rs` (already patched by P-03), with
`orcel-minimal` only. Upstream's tree walk copies `AXValue` (and
`AXPlaceholderValue`) of every node, and its structured `elements` carry the
role but not the subrole, so a consumer cannot tell an `NSSecureTextField`
(role `AXTextField`, subrole `AXSecureTextField`) from a plain field. The
patch adds, in `walk_element`:

- after the value reads: `secure_text` is true for role `AXSecureTextField`,
  or role `AXTextField` with subrole `AXSecureTextField` (one extra AX read,
  for text fields only); for such a node `copied_value` and `value` become
  `None`, so neither `value` nor `value_state` is ever filled;
- before the node is built: the node's `role` becomes `AXSecureTextField`.

The Orcel host maps that role to `control_type: "Edit"`,
`value_is_password: true` and no value (`map.rs`, as the Windows host does
with UIA `IsPassword`). Lines added only; nothing upstream is deleted or
reworded; with the feature off the file compiles exactly as upstream.
Linux needs no counterpart: upstream's `atspi/native.rs` never reads the
text of a `password text` node, and the host marks that role the same way.

## P-07: a host narrows the registry to its allowlist (XP-06)

`cua-driver-core/src/tool.rs` (already patched by P-03), with `orcel-minimal`
only: one added method, `ToolRegistry::retain_tools(keep: &[&str])`, which
drops every registered tool whose name is not in `keep` from the tool map and
the ordered name list. Upstream has no way to remove a tool, and the platform
crates expose only `register_all` / `build_registry`, which register every
tool. The Orcel host calls `retain_tools(&ALLOWED_TOOLS)` right after
construction (`apps/orcel-native-host/src/cua_adapter.rs`), so the registry
holds exactly `list_windows`, `get_window_state`, `get_cursor_position`,
`get_screen_size`, `check_permissions` and (P-09) `orcel_semantic_action`; any
other name is unknown to `invoke`. This is defence in depth under the closed `CuaCall` enum.
`registry_holds_the_allowlist_and_no_compiled_out_tool` (macOS and Linux CI)
requires the registered names to equal the allowlist exactly. Lines added
only; with the feature off the file compiles exactly as upstream.

## P-08: exact-window capture only, in process, never prompting (XP-07)

The Orcel host captures one window by calling Cua's own capture modules
(`apps/orcel-native-host/src/capture.rs`, through `cua_adapter.rs`). No
capture tool is registered (P-07 still keeps five tools), so no display or
region capture is reachable from the protocol. With `orcel-minimal` only,
three files change; nothing upstream is deleted or reworded, and with the
feature off each compiles exactly as upstream.

- `platform-macos/src/capture.rs`:
  - `screenshot_window_bytes` is cfg-selected. The replacement checks Cua's
    consent gate, then runs only the ScreenCaptureKit path
    (`screenshot_window_bytes_sck`: a desktop-independent window filter, the
    WindowServer identity re-checked after the frame, a 3 s bounded worker).
    It drops the `screencapture` CLI fallback, a PATH-resolved subprocess
    that writes a temporary file, and the private SkyLight
    `SLSHWCaptureWindowList` read. A window ScreenCaptureKit cannot capture,
    for example one on another Space, is an error, and the host reports it as
    unavailable.
  - `build_window_capture_plan` adds `with_shows_cursor(false)`. The
    `SCStreamConfiguration` default draws the pointer into the frame.
  - The six functions only the upstream route uses get
    `#[cfg_attr(feature = "orcel-minimal", allow(dead_code))]`, so the build
    adds no warning.
- `platform-macos/src/capture_consent.rs`: one added function,
  `direct_capture_consent_recorded(home, bundle)`, and its helper
  `bundle_identifier_of`. From macOS 15 the first capture by an app raises
  replayd's "bypass the private window picker" alert (module docs). Upstream's
  `capture_blocked_reason` can look only at the process's own bundle. A
  bare binary is let through, and an unreadable approvals file counts as
  consent. The host is a bare binary until XP-16, so it asks this function
  about the app macOS holds responsible for it. The function fails closed:
  an unknown macOS version and an unreadable file both count as not
  recorded.
- `platform-linux/src/capture.rs`: `screenshot_window_bytes` is
  cfg-selected. The replacement runs MIT-SHM, then plain `XGetImage`, both in
  process on the session's own X connection. It drops the ImageMagick
  `import` fallback, a PATH-resolved subprocess that, for a window id the
  server no longer knows, falls back to an interactive grab of the whole
  X server. `capture_via_import` gets the same `allow(dead_code)`.

What P-08 does not do: Cua's X11 capture reads the window's area of the
screen, so a window covered by another one would carry the other window's
pixels. The host refuses that case itself before and after the capture
(`capture.rs`, `x11_exposure`). Cua's Wayland backend captures whole outputs
only, so the host never calls it, and Wayland capture stays unavailable.

## P-09: one accessibility-only action tool (XP-11)

The Orcel host delivers semantic actions (invoke, set_value, select, toggle)
through one added tool, `orcel_semantic_action`, and registers no other
action tool. Upstream's `click`, `set_value` and `scroll` stay out of the
host's registry (P-07 keeps the allowlist at six names) because each of them
can leave the accessibility route when it fails:

- macOS `click`: a CGEvent pixel click (`button=middle`, the list-selection
  fallback, any `x,y`), a private SkyLight activation to prime the key window,
  a menu opened by the press. macOS `set_value`: an Apple Event to Finder or
  Safari (the first use raises a TCC Automation prompt, which P-04 forbids),
  synthesized key presses, a popup menu opened and its item pressed, a
  document key edit to mark it changed. macOS `scroll`: wheel events.
- Linux `click`: when `doAction` is declined, an XTest or uinput pointer click
  at the element, and for entries and menu items a real pointer click first.
  Linux `set_value`: a click, select-all and virtual key typing; a combo box
  popup opened with the pointer. Linux `scroll`: Button4/5 and uinput wheel.

Patching each branch out of 15,000 lines of tool code would leave a registry
whose safety is a negative property of many edits. The tool is instead added
with `orcel-minimal` only, so the property is positive and short enough to
read: it calls only the accessibility primitives upstream's tools are built
on, on the element a `get_window_state` snapshot of the same process resolved,
and has no other route. Nothing upstream is deleted or reworded; with the
feature off each file compiles exactly as upstream.

- `platform-macos/src/tools/mod.rs`: a `tools::orcel_semantic` module and one
  registration. It resolves the token through upstream's snapshot store
  (which also binds it to the asked window), takes upstream's exact-window
  gate (`gate_background_window_action`, `AxSemantic`), wraps the call in
  upstream's focus suppression and window-change watch, then reads the live
  `AXRole`/`AXSubrole`/`AXEnabled` and refuses a secure text field, a role
  the verb does not act on, a role that differs from the one the host listed,
  and a disabled element. Invoke, toggle and select send `AXPress` through
  `ax_actions::perform_ax_action`, only when the element advertises it.
  Set value writes `AXValue` (a CFNumber for a number, else a CFString), only
  when `AXValue` is settable, on a text field, slider, stepper or date
  field. Every `unsafe` call has a SAFETY comment. No CGEvent, no
  SkyLight, no Apple Event, no key event, no menu.
- `platform-linux/src/atspi/native.rs`: one added function,
  `live_role_and_checked_ref`, which reads the live role name and `Checked`
  state of a snapshot-cached object (one state read, one role read, no walk).
  The Linux tool calls it right before acting: the role must still be the one
  the host listed, must not be a password field, and a toggle must not already
  be in the state it asks for.
- `platform-linux/src/tools/impl_.rs`: a private `orcel_semantic` module and
  one registration. It resolves the token the same way, compares the
  snapshot's AT-SPI role with the host's, and acts on the object the
  snapshot observed: invoke, toggle and select call
  `atspi::perform_action_observed` (`Action.doAction`) under the focus guard,
  set value calls `atspi::native::set_value_ref` (`EditableText` or `Value`).
  It never re-resolves an element by index: a vanished object is
  `target_stale`. A declined `doAction` is `postcondition_failed`, an
  unacknowledged one `outcome_unknown`; neither is retried or followed by a
  pointer click.
- Toggle never flips blindly. The host passes the state it asks for
  (`toggle_to`); macOS reads `AXValue` and Linux the `Checked` state on the live
  element immediately before pressing, and an element already in that state, or
  one whose state is unreadable, is refused (`target_stale`, `capability_denied`).
- Both tools take exactly `pid`, `window_id`, `element_token`, `verb`,
  `expect_role` and, for set value, `value`, for toggle `toggle_to`. A name that could carry a
  position, key, button, count, modifier, delivery mode, scope, capture id or
  zoom flag is refused before any accessibility call, a token must be one
  `get_window_state` minted (a bare row number is refused), and `scroll` is
  not a verb. The host's own `CuaCall::SemanticAction` cannot build any of
  those fields, and `the_action_tool_refuses_every_argument_that_could_address_a_pixel`
  (macOS and Linux CI) calls the registered tool with each of them.
- `cua-driver-core/src/authorization.rs`: one arm in `advertised_risk_for`
  classifies `orcel_semantic_action` as R1, the class of the `click` and
  `set_value` it replaces. Upstream's coordinator denies a tool with no
  reviewed risk class. The tool is deliberately not one of
  `DESKTOP_INPUT_OPERATIONS`: it sends no input, so upstream's `desktop_input`
  grant adapter does not apply, and Orcel's kernel (approval bound to the
  exact target) is the authority.

What P-09 does not do: scroll. Upstream scrolls by wheel event at a screen
position on both platforms, which is pixel-addressed input, so the host
refuses the `scroll` verb (`capability_denied`) until XP-12. Set value on web
content is refused by the host (an AXValue write there is echoed back without
reaching the page), and a value write that moves text into a document does
not mark the document edited, because upstream's way of doing that sends key
events.

## Patched file index

Every vendored file that differs from upstream, as recorded in the
provenance `patched_files`, `removed_files` and `added_files`. `scripts/check-vendored-cua.mjs` requires each one
to be named here.

- `platform-macos/Cargo.toml` (upstream blob `8d429484aa47`)
- `platform-macos/src/ax/tree.rs` (upstream blob `681c636058fd`)
- `platform-macos/src/browser/browser_js.rs` (upstream blob `5d1e2c2adf62`)
- `platform-macos/src/browser/electron_js.rs` (upstream blob `c22f3e9989f2`)
- `platform-macos/src/browser/mod.rs` (upstream blob `859243557ed7`)
- `platform-macos/src/capture.rs` (upstream blob `fd519a81c9fd`)
- `platform-macos/src/capture_consent.rs` (upstream blob `62752a2f054b`)
- `platform-macos/src/lib.rs` (upstream blob `329c62985332`)
- `platform-macos/src/tools/mod.rs` (upstream blob `771e6717e3e5`)
- `platform-linux/Cargo.toml` (upstream blob `dfb5ec0fdc3f`)
- `platform-linux/src/atspi/mod.rs` (upstream blob `77c5608cf2f5`)
- `platform-linux/src/atspi/native.rs` (upstream blob `36451e533335`)
- `platform-linux/src/capture.rs` (upstream blob `b2c04867dcfa`)
- `platform-linux/src/browser_platform.rs` (upstream blob `ddecce24e400`)
- `platform-linux/src/input/mod.rs` (upstream blob `7a0cd50dae20`)
- `platform-linux/src/lib.rs` (upstream blob `fc866c39a61b`)
- `platform-linux/src/proc_fs.rs` (upstream blob `7cf1622cdfa3`)
- `platform-linux/src/tools/impl_.rs` (upstream blob `3be700798b93`)
- `platform-linux/src/tools/mod.rs` (upstream blob `38b9c42d143b`)
- `cua-driver-core/Cargo.toml` (upstream blob `de9e618d6b51`)
- `cua-driver-core/src/authorization.rs` (upstream blob `a5ce1cc99c47`)
- `cua-driver-core/src/browser/download.rs` (upstream blob `3a2a4677056a`)
- `cua-driver-core/src/browser/mod.rs` (upstream blob `070d6c0734fa`)
- `cua-driver-core/src/capture_registry.rs` (upstream blob `f7e6be0d533e`)
- `cua-driver-core/src/lib.rs` (upstream blob `5fd18d21964e`)
- `cua-driver-core/src/recording_tools.rs` (upstream blob `1c3d8a4a7bc0`)
- `cua-driver-core/src/server.rs` (upstream blob `7c85f09756a8`)
- `cua-driver-core/src/tool.rs` (upstream blob `677392578aa0`)
- `cursor-overlay/Cargo.toml` (upstream blob `0b55e9e2b1b9`)
- `cursor-overlay/src/render_state.rs` (upstream blob `482d1867a06b`)
- `cursor-overlay/src/session_badge.rs` (upstream blob `f66e866ad1c1`)
- `cursor-overlay/src/theme_artifact.rs` (upstream blob `473940efee1c`)
- `cursor-overlay/assets/Inter.ttf`: removed (upstream blob `047c92f6e221`)
- `cursor-overlay/assets/cua.default.cua-theme`: removed (upstream blob `0beb13487d3d`)
- `cursor-overlay/assets/cua.default.lottie`: removed (upstream blob `7eb34db807ff`)
- `cursor-overlay/tests/fixtures/motion_equivalence.json`: removed (upstream blob `2cfe677d0738`)
- `cursor-overlay/assets/cua.default.cua-theme.rs`: added, re-encodes `assets/cua.default.cua-theme`
- `cua-cursor-motion/Cargo.toml` (upstream blob `2b43c7604f1d`)
- `cua-cursor-motion/tests/golden.rs` (upstream blob `010853fccbcc`)
- `cua-cursor-motion/tests/motion_parity.rs` (upstream blob `adfa6134418e`)
- `cua-cursor-motion/fixtures/golden.json`: removed (upstream blob `6b0f36a568ff`)
- `cua-cursor-motion/tests/fixtures/motion_parity.json`: removed (upstream blob `7121f9e027f5`)
