# Reuse review (2026-10-18): more qualified donor code, less new code

Status: ADOPTED planning direction (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. This is a focused pass over the existing backlog and matrix, not a new plan. The data lives where it always did: `backlog/tasks.json` (each task now carries a `reuse` block) and `transplant_matrix.json` (21 new rows). Every new row's git object SHA was verified against a local checkout at its pin with `tools/readiness_check.py --donors`, except the Playwright row, which was read from GitHub at tag v1.63.0.

## 1. Result

| Measure | Before | After |
|---|---|---|
| Tasks marked BUILD_NEW | 20 | 11 (each with a written reason in its card) |
| Tasks that copy, adapt or wrap donor code | 22 | 32 |
| Matrix rows | 58 | 79 |
| Matrix rows that reuse code (COPY, COPY_ADAPT, WRAP) | 33 | 53 |
| Total backlog effort, ESTIMATE engineer-days | 182-266 | 161-234 |
| Saved by this pass, ESTIMATE | - | 21-32 days, plus avoiding a second sandbox for WI-05 |

These are planning estimates from the task cards, not measurements. The earlier package already counted the large Cua saving for the native hosts (CUA_INTEGRATION.md §9, about 120-200 days of build-new work replaced by 26-39). This pass adds 21-32 days on top.

## 2. New transplants

| Task | Was | Now | Donor source (pin) | What it replaces | ESTIMATE before → after |
|---|---|---|---|---|---|
| XP-09 macOS approvals | BUILD_NEW | COPY_ADAPT | Cua `libs/cua/crates/cua-teleport/src/biometric.rs` (`3fa6cc41`, FSL, FD-04) | LocalAuthentication presence gate; SecCode helper check from `cua-keyvault/src/macos.rs` | 4-6 → 2-3 |
| XP-10 Linux approvals | BUILD_NEW | COPY_ADAPT | same file, polkit `pkcheck` `auth_self` path | polkit STRONG verifier | 4-6 → 2-3 |
| XP-13 process confinement | BUILD_NEW | COPY_ADAPT | Cua `cua-driver-core/src/perception_client/containment.rs` + `containment/` (`6179d5ea`, `2c05bb8d`, MIT) | a three-OS sandbox for untrusted helpers: Landlock + seccomp, Seatbelt, AppContainer + Job Object, capability-reported (refuses to run when a boundary is missing) | 6-10 → 3-5 |
| WI-05 document parser | COPY_ADAPT | COPY_ADAPT, now launched through `orcel-contain` | same containment crate | the parser's own sandbox | 4-6 → 2-3 |
| XP-03 identity primitives | BUILD_NEW | COPY_ADAPT | Cua `platform-linux/src/proc_fs.rs` (`7cf1622c`, MIT); `cua-daemon/src/lib.rs` peer section (`10940238`, MIT) | Linux process generation; Unix peer credentials | 2-3 → 1-2 |
| CR-01 app API transport | BUILD_NEW | COPY_ADAPT | Cua `cua-keyvault/src/caller.rs` (`16c562b9`), `winpeer.rs` (`cbf13894`) (FSL, FD-04) | kernel-derived peer identity on three OSes: macOS audit token + code requirement, Linux `SO_PEERCRED`, Windows pipe client + Authenticode | 4-6 → 3-4 |
| XP-14 browser host macOS/Linux | BUILD_NEW | COPY_ADAPT | Cua `cua-keyvault/src/macos.rs` (`a630391a`, FSL); Playwright `server/registry/index.ts` (`077fd78e`, Apache-2.0) | macOS vendor-signature check of Chrome/Edge; stable-channel install paths | 8-12 → 6-9 |
| XP-16 macOS packaging | BUILD_NEW | COPY_ADAPT | Cua `CuaDriverBundle` (`e7a2941e`), `CuaDriver.entitlements` (`9570bbca`), `.github/scripts/macos-review-codesign.sh` (`47c6cd40`) (MIT); `apps/cua-spaces-macos/scripts/notarize.sh` (`ea269f8e`, FSL) | TCC-identity app bundle, entitlements, codesign review, notarization | 6-9 → 4-6 |
| XP-19 secret storage | BUILD_NEW | WRAP | `keyring` crate, as Cua uses it (`cua-auth/src/lib.rs`, REFERENCE) | per-OS secret backends | 3-5 → 2-3 |
| CR-03 Control Room | BUILD_NEW | COPY_ADAPT | Cua Spaces `src-tauri/tauri.conf.json` (`6fbb5741`), `capabilities/` (`fc862b2f`) (FSL); Agent-Native Toolkit `root.tsx`, `context.tsx`, `stop-button.tsx`, `streaming-text.tsx` (MIT) | Tauri window/CSP/capability scaffolding; AgentKit React provider, hooks, stop button, text rendering | 8-12 → 5-8 |
| BM-02 task benchmarks | PORT | COPY_ADAPT | Cua `libs/cua-bench/cua_bench` (`d8a26f15`, MIT); `benchmarks/cua-driver-bench/taskpack` (`72a1d950`, FSL, FD-04) | a benchmark runner and a starting task set; Python stays test-only, so no language port | 5-7 → 3-4 |

## 3. What each new import must change (security)

| Import | Required adaptation | Security row |
|---|---|---|
| `biometric.rs` | Delete `CUA_ENV_ALLOW_UNVERIFIED_SENSITIVE_EXPORT`; no environment variable may bypass STRONG. Do not take the Windows CredUI password fallback: it would change Windows STRONG semantics, which stay Hello-only. | S-24 |
| `containment*` | macOS uses `sandbox-exec`, which Apple marks deprecated; keep the capability report honest and refuse on any OS where a boundary cannot be installed. seccomp is per-architecture; unsupported architectures are refused, as upstream does. | S-25 |
| `tauri.conf.json`, `capabilities/` | Remove the updater plugin (the lifecycle owns updates) and `process:allow-restart`. Tighten the CSP: no `'wasm-unsafe-eval'`, no `ws:`/`wss:`, no remote `connect-src`. The only command is the read-only `app_api_call`. | S-15, S-26 |
| `caller.rs` | On Linux the donor marks peers `os_verified: false`, because same-uid processes can ptrace each other. Orcel trusts Linux peers only as "same uid", never as a verified binary. | S-27 |
| Toolkit React files | Remove approval-response controls; the UI shows broker state only. | S-16 |
| `notarize.sh` | Credentials come only from the release environment, never the repository. | S-22 |

## 4. Remaining BUILD_NEW tasks, and why reuse is not better

| Task | Reason (also in the task card) |
|---|---|
| XP-01, XP-01B | Orcel's own state contract with ancestor checks; donor state-dir handling is product-specific and weaker. XP-01 is in PR #345. |
| XP-02 | CI configuration of Orcel's own workflows (PR #346). |
| XP-04 | Orcel's private protocol is a compatibility contract with the qualified Go host. Cua's MCP/envelope protocol would add a second protocol and a second authority surface. Its refusal codes are reused as reference. |
| XP-17 | No donor ships per-user Linux packaging without Nix or Electron. |
| XP-18 | Extends Orcel's own runtime pin (PR #336); no donor pins a Node runtime tree with held handles. |
| CR-04, XP-20 | Measurement and decision records. |
| RJ-01, RJ-02 | Orcel's own qualified journal and per-provider reconciliation. The donor journals are tied to SQL/PostgreSQL stores Orcel does not run; their semantics are taken as rules (SPACE) and as a port (RJ-03, Agent-Native). |
| SX-06 | Governed tool contract; donor MCP tools would be a second authority. |
| BM-01 | A one-day schema; Cua's e2e results-summary design is reused for the dimensions. |

Two sub-parts of reused tasks are still new code, and their cards say so:
- XP-09's macOS SOFT dialog: no donor presents an approval-style system modal. Cua's consent modules automate Chrome's own dialog.
- XP-10's Linux GTK4 SOFT helper: same reason.

## 5. Rows still PORT, REFERENCE or REJECT, and why they stay

| Rows | Method | Why not COPY or WRAP |
|---|---|---|
| T-BU-01, T-BU-02 (browser-use heuristics), T-C4-01 (crawl4ai filters) | PORT | Python sources. Wrapping them would ship a Python runtime in the product, which the plan rejects. The ported logic is small and pure. |
| T-FC-02..05 (crawl-regex, canonical-url, map-cosine, change-tracking) | PORT | TypeScript files of 19-201 lines feeding the Rust host's crawl queue. A same-language copy would put crawl scope in the worker, which the host must own. |
| T-AN-04 (tool-call journal) | PORT | 391 lines whose semantics belong in the Rust kernel journal. |
| T-PW-13 (Playwright registry paths) | PORT | A 20-line path table. The Rust host's discovery must not depend on the worker. |
| T-CUA-08 (e2e catalog) | PORT | The catalog drives Cua's MCP surface; Orcel's suite must drive `orcel-computer-host/2`. The fixtures themselves are copied (T-CUA-07). |
| T-BU-03 | REFERENCE | Semantics only; the code is page-script based. |
| T-CUA-09, T-SP-05 | REFERENCE | Documentation. |
| T-CUA-10 (platform-windows) | REFERENCE | Waits for the XP-20 measurement against the qualified Go host. |
| T-CUA-34 (cua-auth) | REFERENCE | Orcel wraps the same `keyring` crate directly. |
| T-AN-10 (Toolkit `components.tsx`) | REFERENCE | 5,618 lines on assistant-ui, Radix and CodeMirror; the Control Room needs a timeline, a device list and stop. |
| T-OCU-01/02 | REFERENCE | Fallback if the Cua gate fails. |
| T-BU-04, T-PW-10, T-PW-11 | REJECT | Evaluate page or caller script (SG-000108 invariant). |
| T-CUA-14 (cuabot) | REJECT | Upstream marks it unsafe. |
| T-CUA-16 (Cua Spaces app as a whole) | REJECT | Bound to `cua-spacesd` network services and Cua cloud enrollment. Its Tauri scaffolding is now reused (T-CUA-32/33). |
| T-CUA-17 (perception model) | REJECT | Third-party AGPL-3.0-only model, outside Cua's grant. |
| T-AN-05 (macOS helper) | REJECT | Superseded by Cua `platform-macos`; two input engines are forbidden. |
| T-AR-01 (cookie extraction) | REJECT | Credential export. |

## 6. Areas checked with no change

- **Cua streaming (`cua-media-*`, FSL, authorized).** The media stack serves QUIC on port 3212 and is bound to `cua-spacesd`. Orcel hosts have no listeners, and remote screen viewing is not in the adopted multi-device journeys. DEFER: if a takeover-view journey is added, run it through the outbound relay first.
- **Cua virtualization.** `cua-vmm` and Lume were already reused (SX-01..03).
- **SPACE.** Firecracker, guest process and idempotency were already reused (SX-04/05). `credential/injection/store` stays REFERENCE: Orcel never injects credentials into a sandbox by default.
- **Browser Use sessions and recovery.** The Orcel host already owns crash, download and popup supervision. The watchdogs stay REFERENCE because they act through page script.
- **Skyvern and Stagehand.** Unchanged (BROWSER_INTEGRATION.md).

## 7. Costs this adds (ESTIMATE)

- **Runtime:** one extra helper process per contained parse (Landlock/seccomp or Seatbelt setup, milliseconds, to be measured); one `pkcheck` or LocalAuthentication call per STRONG approval (the same user cost as today on Windows); one system WebView for the Control Room, measured in CR-04.
- **Maintenance:** Orcel owns copies of three FSL files (`biometric.rs`, `caller.rs`/`winpeer.rs`, `macos.rs`) and one MIT module (containment). They are rebased only on security fixes, each one reviewed. The Tauri scaffolding follows Tauri 2 releases.
- **Licensing:** FSL files carry their FSL header and notice, citing the founder authorization; MIT files keep their notices.

## 8. Unresolved risks

1. `sandbox-exec` deprecation on macOS (S-25).
2. Linux peer identity is uid-level only (S-27).
3. The donor's sensitive-export override must not survive the copy (S-24); a test enforces it.
4. Paid Apple Developer ID for macOS distribution (FD-05).
5. Upstream FSL code will diverge from Orcel's copies over time.
