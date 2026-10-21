# Cua → Orcel transplantation blueprint

Status: ADOPTED planning direction (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. Donor: [trycua/cua](https://github.com/trycua/cua/tree/a802eaf26ca97616a6bf0de6a29729a9346fbb1f) at `a802eaf26ca97616a6bf0de6a29729a9346fbb1f` (2026-10-17). Inspection only: no Cua build script, binary or test was run for this blueprint. File-level rows with object SHAs: `transplant_matrix.json` rows `T-CUA-*`.

## 1. Licensing map (from `LICENSING.md` at the pin)

| Component | License | Founder authorization | Plan |
|---|---|---|---|
| `libs/cua-driver/**` (core, contract, platform-macos/linux/windows, sdk, cursor-overlay, pip-preview, e2e, fixtures) | MIT | Not needed for MIT terms; notice must travel | WRAP |
| `libs/cua/crates/{cua-sdk, cua-sandbox-core, cua-vmm, cua-image, cua-daemon, cua-proto, cua-mesh, ...}` | MIT | Not needed | cua-vmm COPY_ADAPT; rest REFERENCE |
| `libs/lume` | MIT | Not needed | WRAP the CLI (later) |
| `libs/cua-bench`, `cua-bench-rl`, `cua-s1/python`, `cua-bench-s1/python` | MIT | Not needed | PORT task format; S1 REFERENCE |
| Cua Spaces: `apps/cua-spaces*`, `libs/cua-spacesd`, `cua-spaces-*`, `cua-keyvault`, `cua-teleport*`, `cua-machine-seal`, `cua-volume`, `cua-media-*`, `cua-viewer`, `cua-spacesd-html5`, `cua-logging`, `libs/spaces-*-swift`, FSL samples | FSL-1.1-MIT (no "Competing Use") | Authorized for reuse and commercial distribution (FD-04 confirmed 2026-10-18) | REJECT by architecture (network services on 3211/3212, own enrollment and keyvault) |
| `benchmarks/cua-driver-bench` | FSL-1.1-MIT | Authorized (FD-04 confirmed 2026-10-18) | REFERENCE for BM-02; adopt task files with per-file provenance |
| `libs/python/som` | AGPL-3.0-or-later | Cua-owned? not established | REJECT (not needed) |
| `cua-perception` model artifacts (OmniParser icon detector) | AGPL-3.0-only, third-party | Not covered: third party | REJECT |

FSL's Competing Use clause would block a commercial computer-use product under the default public terms. The founder confirmed on 2026-10-18 that the direct authorization covers copying and commercial distribution of Cua-owned FSL components (FD-04, `docs/orcel/grants/2026-10-18-founder-attestation.md`). The plan still does not depend on FSL code; FSL parts are judged per component on architecture.

## 2. Cua Driver (`libs/cua-driver`)

### 2.1 What it is (VERIFIED SOURCE FACT)

- Rust workspace, version 0.36.0, toolchain 1.97.1, edition 2021: identical toolchain to Orcel (`rust-toolchain.toml` in both).
- Crates and sizes (lines incl. tests): `cua-driver-core` 91,939; `platform-linux` 72,426; `platform-macos` 57,625; `platform-windows` 42,566; `cua-driver` (binary, MCP/CLI, telemetry client) 44,880; `cua-driver-e2e` 29,707; `cua-driver-sdk` 14,069; `cua-driver-testkit` 12,546; `cursor-overlay` 9,418.
- Platform crates are pure execution: their `tools/` implement `Tool` over `ToolState` (snapshots, capture bindings, config, CDP session cache, cursor flags, `host_owns_permission_ux`). Authorization, sessions and manifests are in core (`authorization.rs`, `session_authorization.rs`, `session_manifest.rs`) and applied by the server/daemon, not by the tools.
- Low-level modules depend on a few small core modules: `walk_budget` (340 lines, no deps), `element_token` (154), `delivery` (189), `interactive_input` (421), `background_input` (749), `single_flight` (149), `window_observation` (187); `snapshot_store` (1,649) pulls `session`, `tool`, `action_record`.
- Optional QuickJS `run_script` is a default core feature (`script`); `default-features = false` drops it, and yaml/rego policy engines with it.
- Telemetry HTTP (`ureq`) lives in the `cua-driver` binary crate only.
- macOS background mouse/keyboard delivery uses SkyLight SPI `SLEventPostToPid` with public `CGEvent::post_to_pid` fallback (`platform-macos/src/input/mouse.rs`, `skylight.rs`).
- Linux AT-SPI is native (`atspi` 0.30 over zbus, no Python), X11 through `x11rb` (XTest, XInput, MIT-SHM), Wayland through `wayland-client` with wlroots protocols; GNOME/KDE portal input and PipeWire capture are features (`portal-input`, `portal-capture`).
- Accepted upstream evidence (SOURCE-DOCUMENTED, not Orcel evidence): `docs/action-support.md` lists Windows 122/122, macOS 145/145 effective, Linux X11 116/116, Sway 116/116 with run ids and exact commits, plus a GNOME 46 GTK3 31/31 run and KDE identity-only status.

### 2.2 Decision

**WRAP the platform crates in-process inside an Orcel-owned private host (`apps/orcel-native-host`) for macOS and Linux.** Rationale, against the alternatives:

| Option | Engineering cost | Behavior inherited | Upstream tracking | Verdict |
|---|---|---|---|---|
| Run `cua-driver mcp` as a subprocess | lowest | all | easy | REJECT: second MCP server and its own permission modes = second authority |
| Link `cua-driver-sdk` embedded runtime | low | all, plus sessions, browser bindings, consent, history | easy | REJECT for now: brings Cua's authorization coordinator, CDP browser engine and Computer History into the host |
| **Vendor platform crates + call tool impls directly through an allowlist** | medium | the proven AX/AT-SPI/X11/Wayland routing in `tools/*` | patch queue, rebase per pin | **ADOPT** |
| Copy only `ax/`, `atspi/`, `capture`, `input/` and rewrite routing | high | primitives only; the tested routing in `tools/click.rs` etc. is lost | hard | REJECT |
| Build new | highest | none | n/a | REJECT |

ENGINEERING INFERENCE: the accepted matrix is a property of the tool-level routing (AX first, pixel fallback with focus guards, exact refusals), so the boundary must include `tools/`.

### 2.3 Integration under the trusted kernel

```text
orceld (policy, approvals, leases, journal)
  └─ orcel-provider-uia UiaRegistry (identity, bindings, redaction, protected surfaces)
       └─ ComputerHostAdapter  ── orcel-computer-host/2 over inherited stdio ──┐
                                                                               │
apps/orcel-native-host (Orcel-owned binary, separate Cargo workspace)          │
  supervisor (never touches AX/AT-SPI) ◄───────────────────────────────────────┘
    └─ one-shot worker per request
         └─ cua_adapter.rs: enum-dispatched allowlist
              list_windows | get_window_state | get_cursor_position | get_screen_size | check_permissions
              | click(AX) | set_value | scroll | type_text | press_key | hotkey | drag
              | launch_app (later, approval-gated) | bring_to_front (window_action focus)
              └─ third_party/cua-driver/crates/platform-{macos,linux} tools (vendored, patched)
```

XP-06 implements the observation part of this allowlist: `CuaCall` in `apps/orcel-native-host/src/cua_adapter.rs` holds the typed `cua-driver-contract` input of `list_windows`, `get_window_state` (tree only, no screenshot), `get_cursor_position` and `get_screen_size` (for the cursor reply's screen size), plus `check_permissions` with `prompt: false`. The tool name is the input type's `TOOL_NAME`; no request field names a tool. Patch P-06 keeps secure text values inside the AX read.

Rules inside the host:
1. No listener, no MCP, no HTTP, no daemon socket. Patch P-03 compiles out `server.rs`, `daemon.rs`, `browser/`, `cdp*.rs`, `history.rs`, `recording*.rs`, `perception_client*`, platform `browser/`, `video_*`, `pip/`.
2. `ToolState` is constructed with `cursor_overlay_available = false`, `host_owns_permission_ux = true`; the host never raises TCC prompts.
3. Tool dispatch is a Rust `enum`, not a name lookup, so an unlisted tool cannot be reached by input.
4. Identity: Cua's window ids and element tokens are carried as opaque values; Orcel adds pid start generation (`orcel-platform`, XP-03) and a nonce, and the registry rebinds on every request.
5. Results map to the closed refusal set in CROSS_PLATFORM_ARCHITECTURE.md section 4. The host never retries a mutation.

### 2.4 Exact source to bring in (pin `a802eaf2`)

| Source | Object | Destination | Method | Task |
|---|---|---|---|---|
| `libs/cua-driver/rust/crates/platform-macos` | tree `ad71d18f` | `apps/orcel-native-host/third_party/cua-driver/crates/platform-macos` | WRAP | XP-05 |
| `libs/cua-driver/rust/crates/platform-linux` | tree `13172960` | `.../crates/platform-linux` | WRAP | XP-05 |
| `libs/cua-driver/rust/crates/cua-driver-core` | tree `e30a399d` | `.../crates/cua-driver-core` (no default features) | WRAP | XP-05 |
| `libs/cua-driver/rust/crates/cua-driver-contract` | tree `4a1b8f96` | `.../crates/cua-driver-contract` | WRAP | XP-05 |
| `cursor-overlay`, `pip-preview` | see matrix | build deps only | WRAP | XP-05 |
| `libs/cua-driver/tests/fixtures` | see matrix | `tests/native-fixtures` | COPY | XP-08 |
| `cua-driver-e2e/tests/cross_platform_behavior_test.rs` | see matrix | `apps/orcel-native-host/tests/conformance_shared_web.rs` | PORT | XP-08 |
| `platform-windows` | see matrix | bake-off only | REFERENCE | XP-20 |
| `libs/cua-driver/wayland-helper` (GNOME Shell extension `winrects@cua`) | see matrix | `.../wayland-helper`, optional, user-enabled | WRAP | XP-12 |
| `libs/cua-driver/kwin-target-helper` | see matrix | `.../kwin-target-helper`, identity only | WRAP | XP-12 |

Object SHAs are the git tree/blob ids printed by `tools/readiness_check.py --donors <dir>`; the full ids are in `transplant_matrix.json`.

Review scope for the vendored tree (from the adversarial review): line-by-line exact-diff review of roughly 220K vendored lines is not feasible. XP-05 therefore proposes a CI step proving every unpatched vendored file is byte-identical to the upstream tree at `a802eaf2`, with Jev/OCR exact-diff review covering the patch queue (`PATCHES.md` commits), the Orcel adapter and the workspace manifests, the same admission model already used for playwright-core's npm sources. This narrowing of the review gate is a **proposal that requires explicit approval in the XP-05 grain**; until then the normal gates apply to the whole diff.

### 2.5 Dependency impact

The vendored set adds, on macOS: tokio, objc2 0.5 family, core-foundation, core-graphics, block2, clipboard-rs, image; on Linux: tokio, x11rb, x11, atspi 0.30, atspi-connection, zbus, wayland-client/backend/scanner/protocols-wlr, evdev, memmap2, meval, tiny-skia, keyring, image. All are confined to the separate `apps/orcel-native-host` workspace, so `orceld`'s 62-package lockfile does not change. XP-05 runs `cargo deny check licenses` and `cargo audit` on that workspace and records the package count and binary size (UNMEASURED today).

Notable dependency risks: `meval` (math-expression evaluator used by `parallel_mouse_drag` `fn` paths) is a parser of caller-supplied expressions; the Orcel allowlist does not include that tool, and patch P-03 should cfg it out. `keyring` on Linux is used by Cua for its own state; the host never calls it.

### 2.6 OS coverage the host will claim, and only after Orcel evidence

| Environment | Observation | Capture | Semantic | Raw input | Notes |
|---|---|---|---|---|---|
| macOS 15/26 | XP-06 | XP-07 | XP-11 | XP-12 | Needs Accessibility + Screen Recording on the signed host identity (XP-16) |
| Linux X11 (Openbox, real Xorg) | XP-06 | XP-07 | XP-11 | XP-12 | Xvfb does not prove the MPX background pointer (upstream note) |
| Linux Sway / wlroots | XP-06 | XP-07 | XP-11 | XP-12 | Raw focus-bound input on occluded surfaces refuses (upstream) |
| Linux GNOME (Mutter) | XP-12 | XP-12 | XP-11 | XP-12 | Requires Cua's WinRects Shell helper install + session restart, portal session |
| Linux KDE (KWin) | XP-06 identity | XP-12 | XP-11 | refused | Upstream disables target-addressed raw input on KWin |

### 2.7 Tests Orcel inherits

- Unit: `cua-driver-core` lib tests with `--no-default-features` (XP-05).
- Native conformance: the shared web harness 40-cell catalog per host app, and the AppKit (macOS) and GTK3 (Linux) harnesses, with fixture-owned state oracles and focus/z-order/cursor/no-leak oracles (XP-08). The pinned fixture tree also holds SwiftUI and GTK4 harnesses; Orcel does not stage or run them (`tests/native-fixtures/orcel-stage.sh` builds GTK3, AppKit, WKWebView and Electron only), so they are not conformance evidence (#390). Upstream CI scripts at repo root: `scripts/ci/linux/run-rust-e2e.sh`, `run-rust-e2e-wayland.sh`, `scripts/ci/macos/run-rust-e2e.sh` are the reference for runner setup.

## 3. Cua SDK (`libs/cua`)

VERIFIED SOURCE FACT: `cua-sdk` is the only UniFFI export; `Cua.embedded()` or `Cua.connect()` to `cua daemon` on `~/.cua/cua.sock` (0600) or loopback + token; sandboxes over `cua-vmm`; `cua-spacesd` optional; cloud via `cua-fleet`.

Decision:
- **cua-vmm: COPY_ADAPT** into `crates/orcel-sandbox` (SX-01..03). It is the one place that already abstracts Lume, QEMU (hvf/kvm/whpx/tcg) and OCI containers behind `Runtime` (`start/stop/suspend/resume/fork/checkpoint/list/status/delete/endpoints/guest_exec`). Remove `auto.rs` provisioning ("download the built-in Lume", "download the built-in Linux runtime") and `managed.rs` first-use downloads.
- **cua-sdk, cua-daemon, cua-host, cua-fleet, cua-mesh: REFERENCE.** Orcel already has a qualified daemon; a second daemon socket and a cloud fleet client would duplicate authority. `cua-mesh` (WireGuard via boringtun, MIT) is a candidate only if a later multi-device task needs direct transport; the adopted plan says no LAN/QUIC prerequisite.
- **cua-proto (`cua.env.v1`): REFERENCE** for the guest-agent service split (System, Process, Filesystem, Computer, Windows, Accessibility).

## 4. Cua Spaces

VERIFIED SOURCE FACT: three shells over one Rust app core: Tauri 2 (`apps/cua-spaces`), SwiftUI (`apps/cua-spaces-macos`), Electron (`apps/cua-spaces-desktop`), sharing `apps/cua-spaces-web`; `cua-spacesd` serves gRPC/gRPC-Web on 3211, `/mcp`, `/files`, `/tunnel`, media on QUIC 3212, and links cua-driver in-process.

Against the Orcel Control Room and multi-device plan: Spaces solves remote-sandbox desktop streaming, presence and teleport for Cua's own cloud identity. Orcel's Control Room is a local authority console for the user's own devices. Feature overlap is limited (device list, live preview, agent runs). Decision: **REJECT as code (FSL) and as architecture** (network listeners on 3211/3212, its own keyvault and enrollment). Ideas carried: one shared app core with thin shells; picture-in-picture preview of an agent's window as a later Control Room feature.

## 5. Lume

VERIFIED SOURCE FACT: Swift CLI/framework for macOS and Linux arm64 guests on Apple Virtualization; unattended presets create user `lume`/`lume` with SSH and autologin; `lume serve` binds `127.0.0.1:<port>` (`src/Server/Server.swift`); telemetry module present.

Decision: **WRAP (SX-03), macOS host only.** Invoke a pinned, signature-checked `lume` subprocess; never `lume serve`; telemetry off; replace the default credential per VM. Not a Windows or Linux isolation answer.

## 6. Cua Bench

`libs/cua-bench` (MIT): tasks are directories with `main.py` and oracle checks, run locally in gVisor containers or VMs, or on Cua cloud. `cb run --dry-run` exists. Decision: **PORT the task format and oracle discipline (BM-02)**; Orcel's runner talks to Orcel, records `BENCHMARK_REPORT_1` rows, and never uses `--on cloud`. `benchmarks/cua-driver-bench` (FSL): REJECT until FD-04.

## 7. CUA-S1

`libs/cua-s1`: research models (`cua-s1-nano-0.1` ~855K-parameter option-attention classifier; `cua-s1-4b-0.1/0.2` LoRA on Qwen3.5-4B). Python package is MIT; weights and training data are separate artifacts with their own terms (not inspected). Decision: **REFERENCE** as a candidate local decision head for later Hala ablations; never mandatory, never on the authority path (advice only, as `ORCEL_AI_SERVER_ARCHITECTURE.md` already requires for decision models).

## 8. cuabot

Upstream README: "Deprecated and unsafe to run: cuabot has known security issues". **REJECT.**

## 9. Expected engineering savings

ESTIMATE, not a measurement. Building macOS AX + capture + background input and Linux AT-SPI + X11 + wlroots + GNOME/KDE handling to the upstream matrix level from scratch: roughly 120-200 engineer-days, based on the size of the upstream platform crates (130K lines for macOS+Linux) and their documented per-compositor edge cases. Integrating through XP-05..XP-12: 26-39 engineer-days by the backlog estimates. The saving is in edge cases (focus guards, occlusion, compositor identity), which are the expensive part.

## 10. Additional Cua reuse found by the 2026-10-18 reuse review

Detail and estimates: REUSE_REVIEW.md. Matrix rows T-CUA-20..34.

| Source | License | Orcel use | Task |
|---|---|---|---|
| `libs/cua/crates/cua-teleport/src/biometric.rs` | FSL (FD-04) | STRONG presence on macOS (LocalAuthentication) and Linux (polkit `auth_self`); override variable removed | XP-09, XP-10 |
| `cua-driver-core/src/perception_client/containment*` | MIT | `apps/orcel-contain` (own workspace; the donor uses tokio): pinned one-shot sandbox helper for untrusted processes | XP-13, WI-05 |
| `platform-linux/src/proc_fs.rs`, `cua-daemon/src/lib.rs` (peer section) | MIT | process generation, Unix peer credentials | XP-03 |
| `cua-keyvault/src/caller.rs`, `winpeer.rs`, `macos.rs` | FSL (FD-04) | kernel-derived peer identity; macOS code-requirement checks for the browser engine and the approval helper | CR-01, XP-14, XP-09 |
| `rust/scripts/CuaDriverBundle`, `CuaDriver.entitlements`, `.github/scripts/macos-review-codesign.sh` (MIT); `apps/cua-spaces-macos/scripts/notarize.sh` (FSL) | mixed | macOS bundle identity, entitlements, codesign review, notarization | XP-16 |
| `apps/cua-spaces/src-tauri/tauri.conf.json`, `capabilities/` | FSL (FD-04) | Control Room shell scaffolding with a tightened CSP | CR-03 |
| `libs/cua-bench/cua_bench` (MIT), `benchmarks/cua-driver-bench/taskpack` (FSL) | mixed | benchmark runner (test-only Python) and starting task set | BM-02 |

Patch P-03 still compiles `perception_client` out of the native host; containment is copied into its own helper workspace, `apps/orcel-contain`, so neither the vendored tree nor tokio enters the kernel.

## 11. Exit gate for the integration

Cua integration is accepted only when, on Orcel's own runners: the XP-08 catalog passes for X11, Sway and macOS; no Cua code path opens a socket (a test asserts the host's file descriptors); the patch queue rebases cleanly onto the next upstream pin in a dry run; and `cargo deny` reports no unknown or copyleft license in the host workspace. If the gate fails, the fallback is Open Computer Use's macOS kit and a reduced Linux X11 scope (REFERENCE rows T-OCU-01/02).
