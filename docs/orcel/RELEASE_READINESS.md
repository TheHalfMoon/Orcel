# Release readiness (F4 / SG-000127, tracking #446)

Status record, not an authority. **Core MVP is not complete**, and nothing
here releases, signs or publishes Orcel. Each item is in exactly one of the
five classes below. Update this file when an item moves; the restart
checkpoint at the end says where engineering stands.

## 1. Engineering that is complete (merged, qualified on exact-head CI)

| Item | Where |
|---|---|
| F4 slice 2: installed-size inventory and 400 MB gate | #449 |
| F4 slice 3: local-only MCP report tools (orceld's broker decides every commit) | #450 |
| F4 slice 5a: read-only Windows task timeline, unarmed-shell label | #451 |
| F4 slice 6: installed report journey through `bin\orcel.exe mcp stdio` (fixed #452) | #453 |
| SG-000120 resume summary | #464 |
| Browser lifetime fixes: Edge teardown race (#483 → #497), cold-start launch timeout (#438 LaunchFailed → #495) | #495, #497 |
| XP-14 no-authority half: macOS discovery and code-signature checks, Linux package verification | #487, #488 |
| BM-02 runner, report guard, pinned taskpack | #482, #484, #486 |
| BM-02 Tier A: 20 read-only tasks through the real `orceld` binary on Windows, macOS and Linux CI | #499 → `a4ee1f8` |
| BM-02 Tier B: 21 mutating tasks (12 solved, 9 expected refusals) through orceld's request entry and real broker; scripted SOFT consent and no mutation journal, both labelled; per-OS evidence on Windows Server 2025, macOS 26.6.2 arm64 and Linux 6.17 | #500 → `f6a4dbe` |
| XP-14 host-owned network sink (no authority) | #501 → `daba78f` |
| #503 Linux package verification: separate 120 s verify deadline, typed `VerificationTimedOut`, process-group kill | #504 → `b21d3a1` |
| #292 contained PowerShell cold start: explicit test-only allowance and diagnostics; production limits unchanged | #505 → `5bbd1fc` |
| F4 slice 5 stop: implementation-ready proposal (no surface) | #506 → `ef9500a` |
| BM-02 Tier C C1 no-op baseline: reset and evaluator on every OS | #509 → `44aa182` |
| SG-000122 and SG-000124 preparation packets (no activation) | #510 → `89b08d3` |
| #438 fixture response diagnostics (test-only) | #511 → `6e44ec1` |
| #288 WPF memory: profiled against a minimal WPF window on CI; transcript bounded (working set flat over 250 queries; private bytes still rose 4–6 MB, see the preview README) | #513 → `f9a69d8` |
| BM-02 Tier C C2a: a pinned GUI task's Electron apps launched on a CI runner, observed through the real orceld, cleaned up | #514 → `d9a899a` |
| #515 scoped UIA subtree observation: preparation packet (no shape change) | #517 → `2b4062d` |
| SG-000115 preparation packet (no activation) | #502 → `89066a6` |
| SG-000128 (#515, founder decision 2026-10-29) activation | #519 → `aec4c3b` |
| SG-000128 slice 1: scoped `uia.tree/observe` (`root_element_id` + `expected_tree_generation`) in orcel-policy, the provider registry (root validated before replacement, per-window budget of 8) and orceld | #520 → `540657e` |
| SG-000128 slice 3a / BM-02 Tier C C2b on CI: every cdb-s02 blocker-form element reached through the scoped read on the real app; the first action refused by the DesktopInput gate; nothing written against the evaluator's baseline; labelled scripted plan | #521 → `a58d336` |
| SG-000128 slice 1b: the Windows computer host's scoped read and its bounded action lookup (4096 nodes, depth 64); the native host refuses a subtree root | #522 → `3e5ed71` |
| SG-000128 slice 2: optional subtree root on the local-only `desktop_window_tree` MCP tool | #523 → `c99b8d8` |
| SG-000115 pre-activation engineering, inert (test builds only, no production caller, macOS/Linux launch still refused): A1 managed-policy inspection, A2 supervision and descendant tracking, A3 profile hold, A4 network-confinement primitives, A5 profile sweep and crash recovery, A6 integration rehearsal | #527, #529, #530, #531, #532, #535 |
| SG-000115 risk work (inert): A2b verified termination (Linux subreaper proven by ECHILD; macOS unique-id lineage, freeze, kill, confirm); S-07 Linux install tree root-owned with real-dpkg tamper tests; A3b profile walk refuses links anywhere and keeps a live engine's profile; A6b kept sink port held, verified release, crash residual pinned. Residuals are recorded, not accepted (class 4) | #549 → `9407cc9`, #550 → `ade0f2c`, #551 → `25083f1`, #552 → `9695da4` |
| Orcel Agent (SG-000129, authority-neutral planner client of the edge; orceld stays the sole authority): M0 audit and plan, M1 stdlib client, activation, slice 1 locked dependencies, 2 LangChain adapter, 3 loop detection, 4a1/4a2/4b/4c previews, failures, todos, compaction, 5a SQLite checkpoint, 5b Windows owner-only DACL, 6 labelled deterministic-scripted evaluation (not model performance) | #533, #534, #537, #538, #539, #541 to #548 |
| M4 local model candidates and benchmark plan (research only; nothing downloaded or run) | #553 → `c7b64f1` |
| Lifecycle on main `89066a6`: Windows release qualification (install, run, update, recover, uninstall, local report client, 400 MB budget) and Linux deb/rpm/tarball install, systemd units, tamper detection and uninstall | main CI 40672122647 |

## 2. Engineering that can still be completed without the founder

| Item | Note |
|---|---|
| #438 residual: navigation `read: TimedOut` on CI | Waiting for a recurrence; #494's diagnostics capture it |
| SG-000129 slice 5c: Windows agent store held by handle, orceld's ancestor rule, no junction on the path, claim-before-delete expiry | PR #554 (judge round 2, exact-head CI) |
| #540 flaky vendored batch-pause test | PR #555: patch P-13 in the vendored patch queue (independently approved; exact-head CI) |
| SG-000115 B1 (inert): a pid reused within one macOS scan counts as torn (clock mark) | PR #557 (security review, exact-head CI incl. macOS) |
| SG-000115 Priority B (inert): retained-.deb signature chain for S-07, PID-namespace or cgroup containment feasibility, profile delete through the held walk, macOS ACLs on profiles | Engineering solutions to shrink the class 4 residuals; none activates SG-000115 |
| #292 flaky SG-000013 contained PowerShell test on windows-latest | Root cause not yet found |
| macOS install / start / uninstall lifecycle | No macOS package yet: macOS packaging (XP-16) waits for FD-05; Windows and Linux lifecycle are in class 1 |
| SG-000128 closeout | After slice 3b (class 3) is accepted or the founder records otherwise; the closeout judge checks that slice 1's deferred items are evidenced |
| BM-02 Tier C beyond C2b (C3 agent runs) | Blocked: needs a planner model (class 4) |
| CI flakes under watch | #438 (navigation), #508 (UIA bind), #512 (real git fetch), #516 (Go helper start), #524 (macOS jobs cancelled before a runner is assigned) |
| Governance preparation for SG-000115, SG-000122, SG-000124, SG-000127 closeout | Specs, tests, dependency and security analysis only; activation is a founder decision |
| SG-000115 inert pre-activation engineering (founder decision 2026-10-29, #526) | Category A in `prep/SG-000115.md`: test-only or never-default builds, no production caller, pinned by tests to leave macOS/Linux launch refused. A slice that cannot meet the conditions stays a Draft PR. Activation, wiring, S-07 and the macOS descendant escape stay with the founder |
| Documentation consistency (frontier, roadmap, benchmark plan) | Ongoing with each merge |

## 3. Acceptance tests that need the founder present

| Item | Why an agent cannot do it |
|---|---|
| F4 slice 4: one supported client transcript with an approved commit | A person must answer orceld's local approval prompt; an agent or test answering it through the real binaries would be manufactured consent |
| BM-02 solved removals (`fs.remove`) and other STRONG operations | Need platform user presence (Windows Hello, Touch ID, polkit); Tier B shows only that the broker refuses them when presence is unavailable (a stub verifier) |
| XP-20 | Needs a disposable Windows session, not the founder's live desktop |
| macOS direct-capture consent; XP-07/XP-12 delivered capture and input | The founder grants consent on the Mac; nothing may forge or pre-grant it |
| Real GNOME/KDE XP-10 approval checks | A person at the desktop prompt |
| SG-000128 slice 3b: the cdb-s02 scripted plan acting (set_value, invoke) through the scoped read on a disposable Windows machine | UIA actions need a Full User lease, issued only after a STRONG platform-presence approval (Windows Hello); granting it from a test would be manufactured consent. Never on the founder's live desktop |

## 4. Founder decisions

| Decision | Options recorded |
|---|---|
| Code signing (Windows Authenticode, macOS identity) | Gates F4 closeout, slice 5 (option 1), FD-05 / XP-16 macOS packaging |
| F4 slice 5 stop and takeover | (1) signing, (2) governed amendment for an authority-reducing task-scoped stop, (3) record as an open F4 gate — see #446 |
| F4 slice 7: live browser in release builds | Its own governed change and security review |
| FD-03 (gates CR-03), FD-05, FD-08 | As recorded in the frontier |
| Activation of SG-000115 (XP-14 launch, network sink, supervision on macOS/Linux) and the other prepared grains | Activation grants authority; only the founder activates |
| Release and publication | Not authorized; no release is created |
| A planner model for BM-02 Tier C agent runs | Paid inference is excluded by the zero-cost rule; the local d1 model is an advisory classifier, not a planner |
| M4 model selection and licensing | Candidates and the benchmark plan are in `prep/M4-local-model-candidates.md`; nothing is downloaded or run before this gate |
| SG-000115 residuals (recorded, **not accepted**; engineering continues on each) | (a) macOS: a pid reused within one descendant scan (B1, #557, an open draft, would narrow it to a backward clock step during a scan); (b) descendants of another user that cannot be read; (c) false positives of the unattributable rule; (d) the network sink's port after an orceld crash; (e) S-07 binds ownership and modes, not a signature (stock GitHub Ubuntu has `/opt/google` at 0777, so Chrome there is unverified); (f) engines in another PID namespace; (g) profile paths with spaces and `hidepid` on `/proc` |
| Real platform presence (Windows Hello, Touch ID, polkit), macOS permissions | Never simulated or pre-granted |
| Paid infrastructure, deployment | Excluded by the zero-cost rule |

## 5. External hardware or credentials

| Need | For |
|---|---|
| Code-signing certificates / Apple Developer identity | Signing, notarization, slice 5 option 1 |
| An isolated VM (Windows, and ideally macOS and Linux desktops) | BM-02 Tier C GUI tasks, XP-20 |
| The Mac with Chrome or Edge installed | Positive vendor-bundle evidence on hardware (CI has it hosted) |
| `remote-desktop-commander` OAuth (`/mcp` in an interactive terminal) | Remote runs on the user's devices from this agent |

## Readiness by area (2026-11-01)

| Area | State |
|---|---|
| Engineering | Class 1 merged on exact-head green CI with independent review; class 2 in progress |
| Core MVP | **Not complete**: F4 slices 4, 5 and 7 and the closeout are open (classes 3 and 4) |
| AI capability | Planner client (SG-000129) evaluated only with scripted plans and a scripted policy model; no model has been run. M4 waits for its selection and licensing gate |
| Cross-platform | Windows and Linux lifecycle qualified on CI; macOS has no package (FD-05); macOS/Linux browser launch is refused until SG-000115 is activated |
| Security | No accepted risks; SG-000115 residuals are open founder decisions (class 4) |
| Release | Not authorized: nothing is signed, published or released |

## Restart checkpoint

If a session ends, resume from here (2026-11-01, main `c7b64f1`):

1. Open PRs from this work: #554 (slice 5c, head `feae43a`), #555 (#540,
   head `4d16776`, independently approved), #556 (this handoff) and #557
   (SG-000115 B1, macOS pid reuse within a scan, draft). Drafts are marked
   ready once reviewed, then merged with `--match-head-commit` on a green
   exact-head run. #342 and #328 belong to
   other work: do not touch them.
2. Local runs on Windows need a private temp folder (`TEMP`/`TMP` outside
   AppData, or `ORCEL_BM02_STATE_PARENT` for Tier A): this host's AppData
   grants an app-container SID delete rights, so orceld and the agent store
   refuse it. GUI work (`tests/memory.ps1`, `tierc-observe`, `tierc-act`)
   runs on CI runners only. Locally, run only filtered `orcel-provider-uia`
   tests. Rust builds run in WSL Ubuntu (copy the tree without `target`,
   touch the sources, use a per-PR `CARGO_TARGET_DIR`); rustfmt is there too.
3. Vendored cua-driver changes go through the patch queue: a P-xx entry in
   `PATCHES.md`, a `patched_files` entry in `docs/orcel/cua_driver_provenance.json`,
   then `node scripts/check-vendored-cua.mjs` on a commit.
4. Next engineering, in order: merge #554, #555 and #556, then #557 after its review; the class 2 SG-000115
   Priority B items; #438 when it recurs; Windows checkpoint hardening
   follow-ups; then the next roadmap items (F4 slices that need no founder,
   BR items behind governance, cross-platform).
5. Known CI flakes: macOS toolchain install conflict (rerun failed jobs),
   #438, #508, #512, #516, #524.
6. Do not repeat: XP-06/XP-11 Mac hardware tests (#425); the SG-000115 A1 to
   A6b slices; the M4 research (#553).
7. Never mark Core MVP complete; classes 3 to 5 stay open.
