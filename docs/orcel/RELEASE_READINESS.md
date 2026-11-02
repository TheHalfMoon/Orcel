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
| SG-000129 slice 5c: Windows agent store held by handle, orceld's ancestor rule, no junction or link on the path (8.3 short names expanded), a closed store refuses writes, claim-before-delete expiry. Notes from its judge, not yet recorded in the spec: stores on mapped or `subst` drives are refused (fail-closed, but the message names a junction); the rename-blocking claim is measured on NTFS only | #554 → `e462652` |
| #540 flaky vendored batch-pause test: patch P-13 in the vendored patch queue | #555 → `f8f0c8f` |
| #573 flaky vendored session idle-expiry test (1 ms idle TTL): patch P-14 gives the idle case 200 ms of headroom, assertions unchanged, test only | #574 → `717ed16` |
| #575 flaky browser-worker capture timing test on Windows: wall-clock bounds replaced by sentinel-timer ordering, regression still caught (mutation checked), test only | #577 → `09b0e1e` |
| RUSTSEC-2026-0429 (zip 8.6.0 `ZipArchive::extract` abort) recorded under the doc parser's extraction-only audit rule: zip 9 is blocked because anydoc (every release to 0.2.4) requires zip ^8.6; neither the parser nor anydoc 0.2.2 calls `extract` (rechecked), and the parser has no writable root. Drop with the other zip ignores when anydoc accepts zip 9 (the parser's own `=8.6.0` pin moves with it) | #578 → `05caf96` |
| Agent store path aliases: a requested path whose held final path differs (mapped or `subst` drive, junction, link, mount point) is refused with a message naming all possible causes, not only a junction; a CI-only test maps a `subst` drive and shows the refusal | #562 → `19d55bd` |
| SG-000115 B1 (inert): a pid reused within one macOS scan counts as torn (clock mark); the node is kept, so freeze and kill coverage is unchanged. On hosted macOS CI the clock test passed and the lineage cases still verify every attributable escape, with the fast orphan detected in 5 of 5 rounds | #557 → `32c5087` (main CI 41327036226) |
| SG-000115 B2 (inert): macOS same-user browser process-argument scan detects `--user-data-dir` before `SingletonLock`, including paths with spaces as whole arguments; on macOS CI the profile was retained until the running process exited, then removed. Other-user/root processes and sandboxed-host `permission denied` remain unaccepted residuals. | #560 → `878c84d` (main CI 41356507864 passed) |
| SG-000115 B3 (inert): macOS ownership comes from the kernel's own list of this user's processes (`sysctl KERN_PROC_UID`, record layout checked at run time, record size read and pinned at 648 bytes), never from a refusal; any failure keeps the profile. A first design ("a refusal keeps") was disproved by macOS CI, which showed every other user's process info refused, and was not used. On hosted macOS CI the list is served without privilege, and under `sandbox-exec` with process info denied the engine's profile is still kept | #563 → `7be4b3b` (main CI green) |
| SG-000115 B5 (inert): profile recovery through the symlink-resistant walk (`recover_stale_profile_beneath`); the final directory is removed with `unlinkat` relative to its held, private parent. A profile moved behind a link under its old name is refused (a test that fails without the held parent); opened by another session, reviewed, its duplicate workflow removed | #564 → `ce50d6a` |
| SG-000115 B4 (inert): on macOS, while root runs a browser engine (a living root process named like Google Chrome, Microsoft Edge or Chromium, from the kernel's unprivileged list of root's processes; the name field's offset checked at run time against this process's own record), every profile is kept, since by its 0700 mode only the owner and root can use one. Rests on no ACL granting another user access (A3's open item). On macOS CI root's list was served without privilege and blocked nothing; a real root engine was not started (needs privilege) | #566 → `83c25a6` (main CI 41383593998) |
| SG-000115 B6a (inert): on macOS the profile hold walks each extended ACL's entries with the ACL library (profile, lock, state root, every walked directory) and refuses any entry that is not a deny entry; deny-only ACLs (macOS's own on home folders) are accepted, an unreadable ACL refuses, and `verify` repeats it. Closes A3's ACL item, which B4 rests on. On macOS CI real allow ACLs on the profile, its lock, an ancestor, inherited from a parent, or added after the hold were refused, and a deny-only ACL accepted; a first design that parsed ACL text was replaced in review (flags could hide an allow entry) | #568 → `542ff8d` (main CI 41391234618) |
| SG-000115 B6b (investigation, test only): PID-namespace containment for the sink crash residual, option (a). An unprivileged user and PID namespace whose init is killed takes its `setsid` helper with it; on the hosted Ubuntu runner (CI run 41399210347) and locally on WSL2 the helper was taken. A CI step prints the outcome on every Linux run. Evidence only: nothing is wired, the rehearsal runs without a namespace, and the crash-residual test is unchanged; a host with AppArmor's user-namespace restriction would refuse | #570 → `8ef2422` (main CI 41404809356) |
| SG-000115 B5b (inert): `recover_stale_profile` and the A6 rehearsal now run through the held walk anchored at the profile's parent, so recovery, the hold and teardown's final removal are all symlink-resistant and relative to the held parent. The parent must be private; a path without a usable parent (a bare name, the root, a `..` ending) is refused, never reported absent. Cost: a profile directly under `/tmp` or a symlinked parent is left in place | #572 → `ffa3d87` |
| Lifecycle on main `89066a6`: Windows release qualification (install, run, update, recover, uninstall, local report client, 400 MB budget) and Linux deb/rpm/tarball install, systemd units, tamper detection and uninstall | main CI 40672122647 |

## 2. Engineering that can still be completed without the founder

| Item | Note |
|---|---|
| #438 residual: navigation `read: TimedOut` on CI | Waiting for a recurrence; #494's diagnostics capture it |
| SG-000115 Priority B (inert): retained-.deb signature chain for S-07; wiring PID-namespace containment into the rehearsal (B6b showed it works on the hosted runner) or a cgroup alternative where namespaces are refused | Engineering solutions to shrink the class 4 residuals; none activates SG-000115 |
| #292 flaky SG-000013 contained PowerShell test on windows-latest | Root cause not yet found |
| macOS install / start / uninstall lifecycle | No macOS package yet: macOS packaging (XP-16) waits for FD-05; Windows and Linux lifecycle are in class 1 |
| SG-000128 closeout | After slice 3b (class 3) is accepted or the founder records otherwise; the closeout judge checks that slice 1's deferred items are evidenced |
| BM-02 Tier C beyond C2b (C3 agent runs) | Blocked: needs a planner model (class 4) |
| CI flakes under watch | #438 (navigation), #508 (UIA bind), #512 (real git fetch), #516 (Go helper start), #524 (macOS jobs cancelled before a runner is assigned), #558 (orceld app API re-bind on macOS) |
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
| SG-000115 residuals (recorded, **not accepted**; engineering continues on each) | (a) macOS: a pid reused within one descendant scan (narrowed by B1, #557, to a backward wall-clock step: during a scan it can hide a reuse; afterwards it tears every scan, so the sweep fails closed); (b) descendants of another user that cannot be read, including root-run engines (on macOS recovery since B4, #566, keeps every profile while root runs an engine by a recognised name; a root engine under another name is not seen; since B6a, #568, a macOS profile with any non-deny ACL entry is refused at hold and at `verify` (an ACL added between those checks is not seen until the next one); the sandboxed-host `permission denied` ambiguity was closed by B3, #563); (c) false positives of the unattributable rule; (d) the network sink's port after an orceld crash (B6b, #570, shows PID-namespace containment would remove the orphaned helper on hosts that allow unprivileged user namespaces; not wired); (e) S-07 binds ownership and modes, not a signature (stock GitHub Ubuntu has `/opt/google` at 0777, so Chrome there is unverified); (f) engines in another PID namespace; (g) profile paths with spaces (whole-argument matching now covers macOS always, and Linux only where the title is not rewritten), and `hidepid` on `/proc` |
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

If a session ends, resume from here (2026-11-02, main `09b0e1e`, main CI
41437216979 green after a rerun of the #438 Windows flake):

1. Merged since the last checkpoint: #571 (handoff), #572 (B5b), #574
   (P-14, fixing flake #573), #578 (RUSTSEC-2026-0429 under the doc parser's
   extraction-only rule) and #577 (fixing flake #575). Open from this work:
   this handoff and #579 (SG-000115 B3b: a process the kernel reports gone
   or zombie no longer keeps a profile; approved, CI pending). Branch
   protection needs each PR up to date with main, so PRs merge one at a
   time: rebase, exact-head green run, then `--match-head-commit`. #342 and
   #328 belong to other work: do not touch them.
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
4. Next engineering, in order: the class 2 SG-000115 Priority B items; #438 when it recurs; Windows checkpoint hardening
   follow-ups; then the next roadmap items (F4 slices that need no founder,
   BR items behind governance, cross-platform).
5. Known CI flakes: macOS toolchain install conflict (rerun failed jobs),
   #438, #508, #512, #516, #524, #558 (orceld app API re-bind on macOS).
6. Do not repeat: XP-06/XP-11 Mac hardware tests (#425); the SG-000115 A1 to
   A6b, B1 to B5, B5b, B6a and B6b slices; P-13 and P-14; the M4 research (#553).
7. Never mark Core MVP complete; classes 3 to 5 stay open.
