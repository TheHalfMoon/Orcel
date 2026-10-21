# Dependency and License Review

Status: SG-000072 v0.2 review of every third-party component in the Orcel Windows x64 release, recorded with the evidence used. This is an engineering review, not legal advice; it records declared licenses and shipped license texts and does not claim legal certainty. Every component version below was re-verified against the live `Cargo.lock` and `package-lock.json` on 2026-10-04; the shipped dependency closure is unchanged since the ORCEL-P13 review.

Scope: the crates linked into the shipped binaries (`orcel.exe`, `orcel-mcp-host.exe`, `orceld.exe`) for `x86_64-pc-windows-msvc`, following normal (non-dev) dependency edges from `cargo metadata`, and the npm packages present in the packaged `app\orcel-mcp\node_modules`. Development-only dependencies (TypeScript, `@types/node`, test-only crates) are listed separately because they are not distributed.

Sources: `Cargo.lock` (exact versions and registry SHA-256 checksums), `package-lock.json` (exact versions and integrity hashes), each package's declared license, and the license files the package itself ships (collected into `THIRD_PARTY_NOTICES.txt` by `scripts/third-party-notices.mjs`).

## Orcel

| Component | License | Notes |
|---|---|---|
| Orcel (all workspace crates and `@orcel/mcp`) | Apache-2.0 | `LICENSE` at the repository root, shipped in the release payload. |

## Rust crates in the shipped binaries

All are from crates.io, pinned by `Cargo.lock` with registry checksums.

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| serde, serde_core, serde_derive | 1.0.229 | MIT OR Apache-2.0 | Typed JSON records, configuration, IPC envelopes |
| serde_json | 1.0.151 | MIT OR Apache-2.0 | JSON parsing and serialization |
| itoa | 1.0.18 | MIT OR Apache-2.0 | Integer formatting (serde_json) |
| zmij | 1.0.23 | MIT | Floating-point formatting (serde_json) |
| memchr | 2.8.3 | Unlicense OR MIT | Byte search (serde_json) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | SHA-256 for manifests, digests, approvals, audit chains |
| digest, block-buffer, crypto-common | 0.10.7 / 0.10.4 / 0.1.7 | MIT OR Apache-2.0 | RustCrypto traits used by sha2 |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | CPU feature detection for sha2 |
| generic-array | 0.14.7 | MIT (declared by the crate; it ships an MIT `LICENSE`) | Fixed-size arrays for RustCrypto |
| typenum | 1.20.1 | MIT OR Apache-2.0 | Type-level numbers for generic-array |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | Conditional compilation helper |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 | Raw Win32 bindings (ACLs, jobs, processes, registry, console, WinHTTP) |
| windows | 0.52.0, 0.58.0 | MIT OR Apache-2.0 | WinRT/Win32 bindings (Windows Hello presence, UI Automation, clipboard) |
| windows-core | 0.52.0, 0.58.0 | MIT OR Apache-2.0 | Core support for the windows bindings |
| windows-implement | 0.58.0 | MIT OR Apache-2.0 | Procedural macro for COM implementations (compile time) |
| windows-interface | 0.58.0 | MIT OR Apache-2.0 | Procedural macro for COM interfaces (compile time) |
| windows-result | 0.2.0 | MIT OR Apache-2.0 | Windows error and result types |
| windows-strings | 0.1.0 | MIT OR Apache-2.0 | Windows string types |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 | Import-library selection for the Windows targets |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 | Import libraries for x86_64-pc-windows-msvc |
| proc-macro2, quote, syn (2.x and 3.x), unicode-ident | 1.0.107 / 1.0.47 / 2.0.119, 3.0.6 / 1.0.26 | MIT OR Apache-2.0 (unicode-ident adds Unicode-3.0) | Compile-time procedural macros (serde_derive, windows-implement/interface); not linked into the binaries |

Observations:
- Two major versions of `windows` (0.52 and 0.58) are linked because different capability providers adopted different versions. This increases binary size but is not a security issue; consolidating them would touch closed provider grains and is recorded as a future, non-release improvement.
- `syn` 2.x and 3.x are both used at compile time only.
- No crate requires copyleft obligations; every license is permissive (MIT, Apache-2.0, Unlicense, Unicode-3.0).
- No unused runtime dependency was found in the shipped graph; each entry above is reached from code that is compiled into a shipped binary.

## Rust crates admitted for macOS and Linux (XP-15)

Admitted 2026-10-19 for the XP-15 clipboard provider (`crates/orcel-provider-clipboard`, target-gated to `target_os = "macos"` and `target_os = "linux"`). None of these crates is built for `x86_64-pc-windows-msvc`, so the Windows x64 release, its SBOM and its `THIRD_PARTY_NOTICES.txt` are unchanged (`cargo tree -i arboard --target x86_64-pc-windows-msvc` prints nothing). They become part of the shipped closure when macOS and Linux packages exist; `scripts/generate-sbom.mjs` and `scripts/third-party-notices.mjs` currently target Windows only and must gain those targets then.

`arboard` is pinned at `=3.6.1` (3.7.0 was four days old at admission) with default features off (no `image-data`, no `wayland-data-control`). On Linux, arboard serves only X11 writes. Linux reads are bounded by Orcel itself: `x11rb` `=0.13.2` (X11) and `wl-clipboard-rs` `=0.9.4` (Wayland) are direct dependencies, and `libc` provides `poll`. Every read has a 2 s deadline and a 64 KiB cap, so an owner that stalls, never closes its pipe, or sends an endless INCR transfer fails closed. arboard's own Linux reads have no such bound. Wayland writes also go through wl-clipboard-rs, which keeps the data in memory and serves it from a background thread; arboard is never constructed under Wayland. `cargo tree -e normal` on both targets contains no async runtime (no tokio, async-std, smol, or futures executor). Clipboard work runs on the calling thread, plus the X11 selection-server thread and the Wayland copy-serving thread that arboard and wl-clipboard-rs start. No crate spawns a process, and `wl-copy` is never run.

arboard was chosen over clipboard-rs 0.3.5, which the backlog card named, because clipboard-rs prints to stdout with `println!` from its X11 selection-server thread (for example "Somebody else owns the clipboard now" when another client takes the clipboard). orceld speaks JSON on stdout and holds the stdout lock, so that thread would block forever, or would corrupt the stream in a process that does not hold the lock. arboard reports through the `log` facade. Its only direct print is an `eprintln!` to stderr, made when a handle is dropped within 100 ms of a write and stderr is a terminal; the adapter never drops its handle. The `xp15_clipboard_ownership` test fails with clipboard-rs (stdout received "Somebody else owns the clipboard now") and passes with arboard under Xvfb.

Built for Linux (`x86_64-unknown-linux-gnu`, normal edges):

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| arboard | 3.6.1 | MIT OR Apache-2.0 | X11 text writes (selection owner); notice: `docs/orcel/notices/arboard-MIT.txt` |
| x11rb, x11rb-protocol | 0.13.2 | MIT OR Apache-2.0 | Pure-Rust X11 protocol; direct use for bounded CLIPBOARD reads |
| gethostname | 1.1.0 | Apache-2.0 | Host name for X11 authentication (x11rb) |
| wl-clipboard-rs | 0.9.4 | MIT OR Apache-2.0 | In-process Wayland data-control reads (bounded by Orcel), writes, and the data-control probe |
| wayland-client, wayland-backend, wayland-protocols, wayland-protocols-wlr, wayland-sys | 0.31.15 / 0.3.17 / 0.32.13 / 0.3.12 / 0.31.11 | MIT | Wayland protocol (pure-Rust backend) |
| wayland-scanner, quick-xml | 0.31.11 / 0.41.0 | MIT | Protocol code generation (compile time) |
| tree_magic_mini, petgraph, fixedbitset, nom, indexmap, hashbrown, equivalent, foldhash | 3.2.2 / 0.8.3 / 0.5.7 / 8.0.0 / 2.14.2 / 0.15.5, 0.17.1 / 1.0.3 / 0.1.5 | MIT; MIT OR Apache-2.0; foldhash Zlib | MIME detection inside wl-clipboard-rs and its graph and parser support |
| parking_lot, parking_lot_core, lock_api, scopeguard | 0.12.5 / 0.9.12 / 0.4.14 / 1.2.0 | MIT OR Apache-2.0 | Locks in arboard's X11 backend |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | URI handling in arboard (file lists; unused by Orcel) |
| rustix, linux-raw-sys | 1.1.5 / 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | System calls |
| os_pipe, libc (direct: `poll` for the bounded pipe reader), log, thiserror, thiserror-impl, smallvec, downcast-rs, bitflags | 1.2.3 / 0.2.189 / 0.4.34 / 2.0.21 / 2.0.21 / 1.16.3 / 1.2.1 / 2.13.2 | MIT; MIT OR Apache-2.0 | Pipes, FFI, logging facade, error derive (thiserror-impl is a compile-time proc macro), containers |
| cc, find-msvc-tools, shlex, pkg-config | 1.8.0 / 0.1.14 / 2.0.1 / 0.3.34 | MIT OR Apache-2.0 | Build-dependencies of wayland-backend (cc) and wayland-sys (pkg-config); not linked |

Built for macOS (`aarch64-apple-darwin`, normal edges):

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| arboard | 3.6.1 | MIT OR Apache-2.0 | Text get/set over NSPasteboard |
| objc2, objc2-encode | 0.6.5 / 4.1.0 | MIT | Objective-C runtime bindings |
| objc2-foundation | 0.3.2 | MIT | Foundation bindings (NSString, NSArray) |
| objc2-app-kit, objc2-core-foundation, objc2-core-graphics | 0.3.2 | Zlib OR Apache-2.0 OR MIT | AppKit NSPasteboard and the frameworks it references |
| bitflags | 2.13.2 | MIT OR Apache-2.0 | Flag types (objc2 bindings) |

In `Cargo.lock` but not built for macOS, Linux or Windows in this workspace: `clipboard-win` 5.4.1 and `error-code` 3.4.0 (arboard's Windows backend; Orcel's Windows clipboard stays on the existing `windows` 0.58 code), `dispatch2` 0.3.1 and `objc2-io-surface` 0.3.2 (optional macOS edges of the objc2 framework crates that this feature set does not enable), and `redox_syscall` 0.5.18 (parking_lot_core on Redox). Lockfile resolution also moved the Windows-only `windows-sys` requirement of the existing `errno` and `rustix` entries from 0.52.0 to the already-locked 0.61.2; neither crate is built for Windows (`cargo tree --target x86_64-pc-windows-msvc -i rustix` and `-i errno` print nothing), so the Windows build graph is unchanged.

All licenses are permissive (MIT, Apache-2.0, Zlib, LLVM exception); none carries copyleft obligations. wayland-backend is used with its default features, which select the pure-Rust protocol backend, so no system libwayland is linked (`ldd` on the Linux test binary shows no libwayland, libX11 or libxcb).

The adapter pattern (long-lived Linux context, read-then-map) is adapted from cua@a802eaf2 `libs/cua-driver/rust/crates/platform-linux/src/clipboard.rs`, MIT, with its notice in `docs/orcel/notices/cua-driver-clipboard-MIT.txt`.

## Rust crates admitted for macOS approvals (XP-09)

Admitted 2026-10-19 for the macOS STRONG presence verifier in `crates/orcel-approval` (target-gated to `target_os = "macos"`). They are the LocalAuthentication bindings the Cua donor uses (`libs/cua/crates/cua-teleport`). None is built for Windows or Linux (`cargo tree -p orcel-approval --target x86_64-pc-windows-msvc -i block2` prints nothing), so the Windows x64 release, its SBOM and its `THIRD_PARTY_NOTICES.txt` are unchanged. The SOFT dialog (`CFUserNotificationDisplayAlert`) and the session probe (`SessionGetInfo`) are raw CoreFoundation and Security framework externs and add no crate.

Built for macOS (`aarch64-apple-darwin`, normal edges, new to this crate):

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| objc2-local-authentication | 0.3.2 | Zlib OR Apache-2.0 OR MIT | `LAContext` `canEvaluatePolicy` / `evaluatePolicy` (`LAPolicyDeviceOwnerAuthentication`) |
| block2 | 0.6.2 | MIT | The reply block LocalAuthentication calls |
| objc2, objc2-encode, objc2-foundation | 0.6.5 / 4.1.0 / 0.3.2 | MIT | Already admitted for XP-15; NSString and NSError here |

The presence code itself is adapted from cua@a802eaf2 `libs/cua/crates/cua-teleport/src/biometric.rs`, FSL-1.1-MIT (FD-04), with its notice in `docs/orcel/notices/cua-FSL-1.1-MIT.txt`.

## Rust crates admitted for the Linux approval helper (XP-10)

Admitted 2026-10-19 for `apps/orcel-approval-helper-linux`, the GTK4 approval dialog orceld spawns on Linux. The helper is its own Cargo workspace with its own `Cargo.lock` and `deny.toml` (CI runs `cargo audit` and `cargo deny check licenses` on it), so the root workspace, orceld's dependency graph and the Windows x64 release, its SBOM and its `THIRD_PARTY_NOTICES.txt` are unchanged. `crates/orcel-approval` adds no crate for Linux: the session probe and polkit check run the pinned system `loginctl` and `pkcheck`.

Built for Linux (`x86_64-unknown-linux-gnu`, normal edges):

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| gtk4, gtk4-sys, gtk4-macros | 0.11.5 | MIT | The dialog window, label and buttons |
| gdk4, gsk4 (+ `-sys`) | 0.11.5 | MIT | GTK 4 display and rendering bindings gtk4 requires |
| glib, gio, glib-macros, glib-sys, gio-sys, gobject-sys | 0.22.x | MIT | Main loop and timeouts |
| pango, cairo-rs, graphene-rs, gdk-pixbuf (+ `-sys`) | 0.22.x | MIT | Required by gtk4 |
| serde, serde_json | 1.x | MIT OR Apache-2.0 | The request line from orceld |
| sha2 (and digest, block-buffer, crypto-common, generic-array, typenum, cpufeatures) | 0.10.9 | MIT OR Apache-2.0 (generic-array MIT) | SHA-256 of the request bytes echoed in the answer (judge round 1, M1) |

Build-time only: `system-deps` and its graph (MIT OR Apache-2.0; `target-lexicon` is Apache-2.0 WITH LLVM-exception). The GTK 4, GLib, Pango and Cairo C libraries are the distribution's own (LGPL-2.1-or-later), linked dynamically and not shipped by Orcel. The polkit action file is adapted from Cua (FSL-1.1-MIT, FD-04), notice in `docs/orcel/notices/cua-FSL-1.1-MIT.txt`.

## orcel-platform identity primitives (XP-03)

Admitted 2026-10-19 for `crates/orcel-platform` `process`, `session` and `peer`. No new crate enters `Cargo.lock`; only edges are added.

| Crate | Version | License | Target | Use |
|---|---|---|---|---|
| libc | 0.2.189 (already locked) | MIT OR Apache-2.0 | `cfg(unix)` | `proc_pidinfo`, `getpeereid`, `getsockopt(SO_PEERCRED / LOCAL_PEERPID)`, `geteuid`, `kill` in tests |
| windows | 0.58.0 (already locked, already in orceld through orcel-provider-uia) | MIT OR Apache-2.0 | `cfg(windows)` | `OpenProcess`, `GetProcessTimes`, `GetExitCodeProcess`, `QueryFullProcessImageNameW`, `ProcessIdToSessionId` (features `Win32_Foundation`, `Win32_System_RemoteDesktop`, `Win32_System_Threading`) |

The Windows x64 SBOM component set is unchanged: `windows` 0.58.0 was already linked into orceld, and libc is not built for Windows. macOS `getaudit_addr` is declared directly against libSystem, which std already links. The Linux `/proc` parse and the `getsockopt` peer pattern are adapted from cua@a802eaf2 (transplant rows T-CUA-23 and T-CUA-24, MIT, notice `docs/orcel/notices/cua-MIT.txt`).

## orceld app API (CR-01)

Admitted 2026-10-19 for `crates/orceld/src/app_api.rs`. No new crate enters `Cargo.lock`. orceld's existing `windows-sys` 0.52.0 edge (`cfg(windows)`, MIT OR Apache-2.0) gains features `Win32_Security`, `Win32_Security_Authorization`, `Win32_Storage_FileSystem`, `Win32_System_IO` and `Win32_System_Pipes`, for `CreateNamedPipeW`, `ConnectNamedPipe`, overlapped `ReadFile`/`WriteFile`, `GetNamedPipeClientProcessId`, `GetNamedPipeClientSessionId`, `PeekNamedPipe`, the token user (`OpenProcessToken`, `GetTokenInformation`, `EqualSid`) and the DACL from SDDL. The backlog card also proposed `security-framework`, `core-foundation`, `Win32_Security_WinTrust` and `Win32_Security_Cryptography` for code-signature checks; these are not admitted because the read-only slice does not take those checks (see the protocol document, "Code identity"). The cua-keyvault files the code adapts are FSL-1.1-MIT (FD-04), notice `docs/orcel/notices/cua-FSL-1.1-MIT.txt`.

## orcel-contain, the contained-tier helper (XP-13)

Admitted 2026-10-19 for `apps/orcel-contain`, its own Cargo workspace with its own `Cargo.lock` (27 packages, all targets) and `deny.toml`. Nothing enters the root `Cargo.lock`: the kernel-side client, `crates/orcel-provider-process/src/contained.rs`, is std only (it carries its own SHA-256, checked against the `sha2` dev-dependency the crate already had). CI runs `cargo audit` and `cargo deny check licenses bans sources` on the helper workspace.

| Crate | Version | License | Target | Use |
|---|---|---|---|---|
| tokio | 1.53.3 | MIT | all | `current_thread` runtime, `process`, `io-util`, `time`, `sync`, `macros` (`select!`); `net` on Windows for the private named pipes. The donor code is async; the runtime is current-thread so the forking thread is the one `PR_SET_PDEATHSIG` watches |
| libc | 0.2.191 | MIT OR Apache-2.0 | `cfg(unix)` | Landlock, seccomp, `prctl`, rlimits, `close_range`, `proc_pidinfo`, `kill` |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | dev only | test fixtures |

tokio's own graph adds bytes, mio, socket2, pin-project-lite, signal-hook-registry, errno, windows-sys/windows-link and the `tokio-macros` proc-macro (syn, quote, proc-macro2, unicode-ident), all MIT or MIT OR Apache-2.0 (unicode-ident also Unicode-3.0). The Windows FFI (AppContainer, Job Object, desktop, ACL and `BCryptGenRandom`) is declared directly against system DLLs, as the donor does; no `windows` crate is used. The donor's `fs2`, `uuid` and `tracing` dependencies were removed with the code that used them.

The helper is not yet in a release package: XP-16 (macOS bundle), XP-17 (Linux packages) and the Windows lifecycle payload (SG-000106) ship it, and `scripts/generate-sbom.mjs` and `scripts/third-party-notices.mjs` must add this workspace when they do.


## orceld secret store (XP-19)

Admitted 2026-10-19 for `crates/orceld/src/secret_store.rs`, the per-OS store for the device private key. Orcel WRAPs the `keyring` project's per-OS store crates directly. That is the crate family Cua's `cua-auth` uses (transplant row T-CUA-34, REFERENCE only, so no code was copied and no notice is needed). The umbrella `keyring` crate is not used, so each OS builds only its own store.

- **Windows:** no new crate. orceld's existing `windows-sys` 0.52.0 edge gains the feature `Win32_Security_Cryptography` for `CryptProtectData`/`CryptUnprotectData` (DPAPI). That feature is already in the graph through orcel-policy. The Windows x64 release, its SBOM and `THIRD_PARTY_NOTICES.txt` are unchanged: `cargo tree -p orceld -e normal --target x86_64-pc-windows-msvc` reaches none of the crates below.
- **Packages:** the root `Cargo.lock` grows from 112 to 210 packages (98 added, none removed). 13 of them are lockfile-only: build dependencies or crates for other targets (wasm-bindgen family, js-sys, bumpalo, r-efi, hermit-abi, uds_windows, tempfile, memoffset, rustversion, autocfg).
- **Release age:** packages released less than 14 days before admission were pinned back with `cargo update --precise` to an older compatible release. These are keyring-core 1.0.0, sha2 0.11.0, uuid 1.27.0, zvariant/zvariant_derive 5.15.0, zbus_names 4.3.4, inout 0.2.2, ctutils 0.4.2, and toml_datetime/toml_edit/toml_parser 1.1.1/0.25.15/1.1.3. keyring-core 1.0.0 and zbus-secret-service-keyring-store 1.0.x are the versions `apps/orcel-native-host` already locks.

Built for macOS (`aarch64-apple-darwin`, normal edges, new to orceld):

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| keyring-core | 1.0.0 | MIT OR Apache-2.0 | Entry/store API the per-OS stores implement |
| apple-native-keyring-store | 1.0.2 | MIT OR Apache-2.0 | Generic-password items in the user's default keychain (feature `keychain`) |
| security-framework, security-framework-sys | 3.7.0 / 2.17.0 | MIT OR Apache-2.0 | Keychain Services; `SecKeychain::disable_user_interaction` so orceld never prompts |
| core-foundation, core-foundation-sys | 0.10.1 / 0.8.7 | MIT OR Apache-2.0 | CoreFoundation types used by security-framework |

Built for Linux (`x86_64-unknown-linux-gnu`, normal edges, new to orceld; 80 crates):

| Crate | Version | License | Purpose in Orcel |
|---|---|---|---|
| keyring-core | 1.0.0 | MIT OR Apache-2.0 | Entry/store API |
| zbus-secret-service-keyring-store | 1.0.1 | MIT OR Apache-2.0 | Secret Service items (feature `rt-async-io-crypto-rust`) |
| secret-service | 5.2.0 | MIT OR Apache-2.0 | freedesktop Secret Service client; encrypted session (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) |
| zbus, zbus_macros, zbus_names, zvariant, zvariant_derive, zvariant_utils, zcheapstr, endi | 5.19.0 / 5.19.0 / 4.3.4 / 5.15.0 / 5.15.0 / 4.2.0 / 1.1.0 / 1.1.1 | MIT | Pure-Rust D-Bus client (no libdbus) |
| aes, cbc, cipher, block-padding, inout, hkdf, hmac, sha2, digest, block-buffer, crypto-common, hybrid-array, const-oid, cmov, ctutils, cpubits, cpufeatures | 0.9.3 / 0.2.1 / 0.5.2 / 0.4.2 / 0.2.2 / 0.13.0 / 0.13.0 / 0.11.0 / 0.11.3 / 0.12.1 / 0.2.2 / 0.4.15 / 0.10.2 / 0.5.4 / 0.4.2 / 0.1.1 / 0.3.1 | MIT OR Apache-2.0 | RustCrypto primitives of the Secret Service session encryption |
| num, num-bigint, num-complex, num-integer, num-iter, num-rational, num-traits | 0.4.3 / 0.4.8 / 0.4.6 / 0.1.47 / 0.1.46 / 0.4.2 / 0.2.19 | MIT OR Apache-2.0 | Diffie-Hellman arithmetic (secret-service) |
| async-io, async-executor, async-channel, async-lock, async-broadcast, async-task, async-process, async-signal, async-recursion, async-trait, blocking, polling, piper, futures-core, futures-io, futures-lite, futures-macro, futures-task, futures-util, event-listener, event-listener-strategy, concurrent-queue, atomic-waker, parking, slab, pin-project-lite, ordered-stream, fastrand, crossbeam-utils, signal-hook-registry, once_cell | various | MIT OR Apache-2.0 (slab MIT) | zbus's async-io runtime; zbus is driven through secret-service's blocking API on the calling thread |
| enumflags2, enumflags2_derive, serde_repr, hex, uuid, getrandom | 0.7.12 / 0.7.12 / 0.1.21 / 0.4.3 / 1.27.0 / 0.4.3 | MIT OR Apache-2.0 | zbus and secret-service support |
| tracing, tracing-core, tracing-attributes | 0.1.44 / 0.1.36 / 0.1.31 | MIT | zbus diagnostics; orceld installs no subscriber, so nothing is emitted |
| proc-macro-crate, toml_edit, toml_datetime, toml_parser, winnow | 3.5.0 / 0.25.15 / 1.1.1 / 1.1.3 / 1.0.4 | MIT OR Apache-2.0 (winnow MIT) | Compile-time support for zbus's proc macros; not linked |

Every license is permissive (MIT, Apache-2.0); none carries copyleft obligations. No crate adds a listener: zbus connects as a client to the session bus. orceld refuses any `DBUS_SESSION_BUS_ADDRESS` that is not a local `unix:path=`/`unix:abstract=` socket before zbus reads it, so zbus's `tcp:`, `nonce-tcp:`, `unixexec:` (which would spawn a program through async-process) and `launchd:` transports are never used. These crates become part of the shipped closure in the Linux packages (XP-17 runs `scripts/third-party-notices.mjs --target x86_64-unknown-linux-gnu`) and in the macOS bundle (XP-16).

## npm packages in the release

Pinned by `package-lock.json` and copied into the release from the locked production dependency closure.

| Package | Version | License | Purpose |
|---|---|---|---|
| @modelcontextprotocol/server | 2.3.1 | Apache-2.0 (MIT through 2.2.0) | MCP server (stdio transport, tool registration); 2.3.x fixes GHSA-jm63-cq47-j5jp, GHSA-46jr-4wx8-v453 and GHSA-rvq5-wwqv-78pq |
| @modelcontextprotocol/core | 2.3.1 | Apache-2.0 (MIT through 2.2.0) | Protocol types used by the server |
| zod | 4.2.0 | MIT | Tool input schemas |

## Development-only dependencies (not distributed)

| Package | Version | License | Purpose |
|---|---|---|---|
| typescript | 5.9.3 | Apache-2.0 | Compiles `apps/orcel-mcp` |
| @types/node, undici-types | 24.10.1 / 7.16.0 | MIT | Node.js type definitions |

## Security considerations

- Rust dependencies are resolved only from crates.io with lockfile checksums; npm dependencies are installed with `npm ci` from the lockfile with integrity hashes.
- No dependency performs network access on Orcel's behalf except the Windows OS transport (WinHTTP) used by the closed SG-000016/SG-000017/SG-000040 paths.
- No build script downloads code at build time (`npm` runs with `--ignore-scripts`).
- Known-vulnerability scanning: on 2026-10-04, `cargo audit` 0.22.2 against the RustSec advisory database (1,290 advisories, database commit `ef6173cb` dated 2026-10-03) reported 0 vulnerabilities for the 54 crates in `Cargo.lock` (exit 0, verified on native Windows against the SG-000072 tree), and `npm audit` reported 0 vulnerabilities for `package-lock.json` (production and development). Both audits run in CI on every change (the `Supply chain audit` job) and fail the build on any known vulnerability.

## Third-party notices

`THIRD_PARTY_NOTICES.txt` is generated from the actual release payload and shipped inside it, with each component's declared license and the full text of every license or notice file the component ships. The generator lists any component without a declared license or shipped license file; the current release has none.
