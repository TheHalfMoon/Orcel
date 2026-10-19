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

## npm packages in the release

Pinned by `package-lock.json` and copied into the release from the locked production dependency closure.

| Package | Version | License | Purpose |
|---|---|---|---|
| @modelcontextprotocol/server | 2.1.0 | MIT | MCP server (stdio transport, tool registration) |
| @modelcontextprotocol/core | 2.1.0 | MIT | Protocol types used by the server |
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
