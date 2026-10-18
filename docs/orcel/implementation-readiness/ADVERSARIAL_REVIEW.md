# Second-pass adversarial review of this package

Status: PROPOSED (Fable, 2026-10-18). Each question from the founder directive was answered against the source, not against the first draft. "Changed" lists what the first draft got wrong and what was revised in the JSON sources (re-rendered tables carry the changes).

| # | Challenge | Finding | Changed |
|---:|---|---|---|
| 1 | Are we asking Opus to build what Cua already has? | Approval presenters, process confinement, packaging and the app API are built new; Cua has TCC onboarding panels (`platform-macos/src/permissions/panel.rs`) but no approval broker outside FSL Spaces. Clipboard reuses Cua's `clipboard-rs` approach. GNOME/KDE identity helpers exist in Cua and were missing. | Added `wayland-helper/winrects@cua` and `kwin-target-helper` (rows T-CUA-18/19, XP-12). |
| 2 | Recreating Browser Use? | No: heuristics are ported, actions come from playwright-core's own backend because Browser Use's actions evaluate page script (27 call sites). | - |
| 3 | Overlooked Firecrawl implementations? | `html.rs` metadata extraction (title, description, Open Graph) is useful even though Orcel reads the rendered DOM. Scrape "actions" are covered by typed browser actions. | Metadata noted in WI-01 scope (WEB_INTELLIGENCE_INTEGRATION.md §2). |
| 4 | Duplicating Agent-Native runtime? | Only AgentKit's protocol/client and the journal classification are taken; the 14K-line production agent and SQL store are not. | - |
| 5 | Do SPACE and Cua sandboxes overlap? | Complementary: cua-vmm abstracts local backends (Lume/QEMU/containers); SPACE contributes Firecracker and a guest agent. Cua's in-guest daemon (`cua-spacesd`) is FSL, SPACE's guest service is Apache-2.0, so the guest agent comes from SPACE. | - |
| 6 | Is the computer engine actually cross-platform? | Yes by composition (Go host on Windows, Rust host on macOS/Linux behind one protocol), not by one binary. Two native codebases remain until XP-20. | Stated explicitly in AD-05 and CROSS_PLATFORM_ARCHITECTURE.md §3. |
| 7 | Overestimating Linux? | The first draft read as if Linux = X11 + Sway. The most common Linux desktop (Ubuntu/Fedora GNOME on Wayland) needs Cua's Shell extension plus a session restart for window identity; KDE raw input is refused upstream. CI covers X11 and Sway only. | XP-06 now reports GNOME/KDE partial availability with a typed reason; XP-12 and XP-17 add the user-enabled GNOME extension; capability matrix marks GNOME "helper". |
| 8 | Confusing Tauri packaging with native support? | Explicitly separated (CROSS_PLATFORM_ARCHITECTURE.md §7). | - |
| 9 | A second privileged action channel? | The native host links Cua code that includes a daemon, MCP server, CDP engine and QuickJS. Compiled out by P-03, plus enum dispatch and an fd audit. `launch_app` is excluded until it has its own approval. | - |
| 10 | Unnecessary cloud costs? | None required. Apple Developer ID is a paid membership needed for macOS distribution; surfaced as FD-05, not assumed. | - |
| 11 | Large frameworks where small modules suffice? | The Cua import is large (core + two platform crates). Smaller cuts lose the tested tool routing, so the size is justified, but **exact-diff review of a ~220K-line vendored tree is not feasible**: the first draft would have made XP-05 unreviewable. | XP-05 now verifies unpatched files byte-identical to the upstream tree in CI and limits line review to the patch queue, adapter and manifests, treated like dependency admission. |
| 12 | Obsolete decisions retained? | WP24 deferral and "WPF for Windows v1" were obsolete under the directive; both are revised (ARCHITECTURE_DECISIONS.md §2). "One active grain" is kept and turned into FD-02 rather than ignored. | - |
| 13 | Simpler ways? | For Windows, keeping the Go host is simpler than switching to Cua now. For Linux sandboxes, Podman + runsc before Firecracker. For UI, AgentKit headless instead of Toolkit wholesale. | - |
| 14 | Legal scope verified per module? | Cua per-component map read from `LICENSING.md`; Agent-Native has no LICENSE text (metadata MIT); crawl4ai adds an attribution clause; `pdf-inspector`/`anydoc` licenses not inspected (WI-05 must check); Playwright ships a NOTICE file that Apache-2.0 4(d) requires us to carry. | Added T-PW-12 and a BR-02 step for the Playwright NOTICE. |
| 15 | Third-party license restrictions overlooked? | Cua's `cua-perception` models (AGPL-3.0-only, third party) and `libs/python/som` (AGPL) are excluded; Cua's `THIRD_PARTY_NOTICES.md` is carried in XP-05. | - |
| 16 | Sources overlooked? | Every donor in the P20 ledger, reuse matrix, browser/web decisions and provenance JSON is in the registry. BrowserSafe and OpenCLI have no recorded source; OpenCLI appears only as an Agent-Reach channel that uses personal browser sessions (rejected). | Registry `unresolved_sources`. |
| 17 | Release-blocking security risks? | S-01 (temp fallback) and S-06 (0.0.0.0 proxy is loopback on Unix) block any macOS/Linux release; both have tasks and tests. | XP-01 placed first. |
| 18 | Can Opus execute every task without asking? | Three tasks contain a bounded in-task choice: XP-01 constructor shape (rule: smallest diff, recorded), SX-01 Docker API vs podman CLI (rule: decide by SBOM size), XP-19 begins by recording where keys live today. None needs architecture research. | - |
| 19 | Are dependencies coherent? | First draft had X2 approval tasks depending on X5 packaging. Fixed with development-signed helpers; the validator checks the graph is acyclic and that every changed path exists or is created by a prerequisite. | XP-09/XP-10 dependencies. |
| 20 | Does the plan improve Orcel or only enlarge it? | It is large (49 tasks), but releases 1-3 need only X0-X5 plus the in-flight Windows work; browser, web, journal, sandbox tracks are ordered after and individually optional. Sandboxes are explicitly not required for Core. | - |

## Residual risks after review

1. SkyLight private API drift on macOS (S-05): mitigated, not removed.
2. Same-user prompt spoofing on all three OSes: documented residual risk, as on Windows today.
3. Linux engine verification is weaker than on Windows/macOS (S-07).
4. macOS GUI E2E depends on a founder-provided runner (FD-05); without it macOS evidence is manual.
5. Cua upstream moves fast (v0.36, daily commits); the patch queue must be rebased per pin bump, and pin bumps are their own reviewed changes.
6. None of this package's performance targets is measured.
