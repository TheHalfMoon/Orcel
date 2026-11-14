# Release readiness (F4 / SG-000127, tracking #446)

Status record, not an authority. **Core MVP is not complete**, and nothing
here releases, signs or publishes Orcel. Each item is in exactly one of the
five classes below. Update this file when an item moves; the restart
checkpoint at the end says where engineering stands.

The per-component view (state, commits, tests, limitations, blockers) is in
`COMPLETION_LEDGER.md`.

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
| SG-000129 slice 5c: Windows agent store held by handle, orceld's ancestor rule, no junction or link on the path (8.3 short names expanded), a closed store refuses writes, claim-before-delete expiry. Its judge's notes are now recorded in the spec: stores on mapped or `subst` drives are refused (fail-closed; the message names every cause since #562); the rename-blocking claim is measured on NTFS only | #554 → `e462652` |
| SG-000129 governance closeout PR (the canonical closeout is on implementation PR #554): spec CLOSED with canonical evidence, ledger record, open-grain tests and CURRENT.md; the closeout judge's round-1 residuals recorded (no-egress hooks miss native calls, the real kill tested on M1 only, the crashed-run checkpoint readable until expiry, the agent CI job not required) and an open follow-up for the Unix store's ancestor and by-handle checks | #589 → `b42b552` |
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
| SG-000115 B3b (inert): after a failed or unparseable arguments read, macOS recovery re-reads the process's own kernel record and keeps the profile only if it is still listed and not a zombie (or the record cannot be read); a process the kernel reports gone no longer keeps it. Found when a rehearsal run kept a profile no engine used (likely a fixture caught exiting; not proven). A `SG115-DIAG kept` line now shows the cause of any recurrence | #579 → `7cccf4b` |
| SG-000115 B7 (inert): the Linux S-07 retained-package signature chain: `gpgv` verifies `InRelease` (exactly one good signature from a pinned primary key; expired, revoked or bad statuses refuse, measured: gpgv exits 0 with `EXPKEYSIG` and `VALIDSIG` for an expired key), the signed release binds `Packages`, `Packages` binds the retained `.deb`, and every package entry (files by SHA-256 and mode, directories, symlink targets, hard links) must match the installed tree with nothing extra in the install directory. Any missing link leaves the engine unverified. On the hosted Ubuntu runner a real Chrome has the vendor keyring but no signed index and no retained package, so it stays unverified. The pinned Google fingerprint is from memory and used only for evidence | #581 → `25673a7` |
| SG-000115 B8 (inert): the A6 rehearsal's sink host as pid 1 of a user, PID and mount namespace; killing it takes the engine and its orphaned helper, and the freed port then receives nothing (local WSL2 run). On the hosted Ubuntu runner the namespace is created but the `setgroups` write is refused (consistent with Ubuntu 24.04's AppArmor restriction), so this form (uid maps and a `/proc` remount) is unavailable there; the refusal is recorded as evidence, never a pass | #582 → `c4547d1` |
| SG-000115 B8b (inert): the engine family alone runs in its own user and PID namespace (no uid maps, no `/proc` remount), its init chained to the host by parent-death signals and a pipe check; when the host is killed the whole family dies and the freed port receives nothing, **on the hosted Ubuntu runner too** (CI run 41542568945), where B8's maps were refused. Also the Linux side of B3b: a `cmdline` read failing with `ESRCH`, or for a pid already gone, no longer keeps a profile (1 uncaptured failure in about 40 local runs remains, with a diagnostic) | #586 → `dee9050` (main CI 41553882525) |
| #438 / #584 diagnostics: the HTTPS fixture reports each connection, TLS handshake and TLS error, and a failing native test prints their counts and every port-443 listener (the fixture uses a fixed `127.0.0.1:443`) | #587 → `017be67` |
| CI flake fixes: #583 a failed macOS memory sample of a live contained process is retried for up to 100 ms (rule change recorded; still fails closed) #591 → `bfa0fb7`; #558 the app API re-bind test retries `InUse` as orceld's start loop does and names the lock's holders #592 → `dabaded`; #292 the SG013 cold-start evidence now reaches the CI log (libtest had captured it) #593 → `03cdb2b`. #583 and #558 stay open as watch items | #591 to #593 |
| SG-000115 B9a (inert): Linux fires a parent-death signal when the spawning *thread* exits; measured (a child spawned from a short-lived thread is killed with it) and designed around (one lifetime spawner thread; its child outlives the requesting thread), on the hosted Ubuntu runner too (PR CI run 41585992656). Residuals: the spawner must be held and never panic for the host's lifetime, and the signal ties only the direct engine process | #594 → `5e14fc3` |
| #358 closed: no recurrence of item 5 (`inspection_reports_lock_contention_as_busy`) in the failed CI runs back to 2026-10-30 | — |
| SG-000129 open follow-up closed on Unix (#596): the agent store follows orceld's ancestor rule (owner user or root, no group/other write unless root-owned sticky, every link's resolved chain checked), makes missing directories 0700, and opens, checks and holds the root and run directories by descriptor (`O_DIRECTORY | O_NOFOLLOW`, the run directory relative to the held root). The source-boundary test lets `store.py` open directories only (recorded rule change). Residuals: macOS extended ACLs are not read; a held descriptor does not block a rename (the ancestor rule does) | #597 → `8003770` |
| Agent assurance A1: real OS process kills and new-process restarts. A scripted MCP server logs every call, so duplicates are read from the server's side. An unknown write, a refused write and a completed write each reach the server once across the kill. The checkpointed M3 chat planner (scripted model) restores its todos from the checkpoint a kill left behind, on all three OSes | #599 → `aedfe44` |
| Agent assurance A2 (Linux): a seccomp filter (allowlist: Unix and netlink sockets only; io_uring and foreign ABIs killed; TSYNC) makes any native socket outside the allowlist kill the egress probe. Controls show it fires on the hosted runner's kernel. The locked LangChain/LangGraph probe completes under it, in the plain and network-namespace legs. Windows and macOS still rely on the audit hooks alone | #600 → `8385044` |
| Agent assurance A3 (macOS, #601): the agent store reads extended ACLs as orceld does. Any allow entry on its own directories, or a write-granting one on an ancestor, is refused. `macacl.py` admits ctypes with a pinned native surface (recorded rule change). Shown on the macOS CI leg | #602 → `5a1fa71` |
| SG-000115 B9b (inert): where user namespaces are refused entirely, the host runs as a systemd user service (`KillMode=control-group`, `KillSignal=SIGKILL`); killing it kills the `setsid` helper too, while the same family without the unit leaves the helper alive. Shown on the hosted Ubuntu runner with lingering enabled (CI requires the result line). A same-user process can still leave the cgroup or ask systemd for a new unit | #604 → `bed54cb` |
| #438 class: the worker's resolver-pinning positive controls wait on #374's event deadline instead of a fixed 10 s (seen in PR run 41659893527 and again on main at `5a1fa71`, run 41698027722, before the fix). #438 itself: 80 isolated stress repetitions and 60 adjacent-pair repetitions passed, and none in about 55 CI runs since 2026-11-03; no mechanism shown, issue open with diagnostics | #603 → `e653280` |
| #438, first mechanism shown: the worker's activation click (and the WebMCP submit) waited, inside its 5 s click budget, for the navigation it started to commit (Playwright's default `noWaitAfter: false`), so a slow commit was reported `failed` after the click had happened (run 41709022637: the fixture served the target, the host got `ActionFailed`). Now `noWaitAfter: true`, as the download click already was; a native test with a target answering after 7 s passes on Windows. The earlier 0-request timeouts remain unexplained | #606 → `5895a3b` |
| Consolidated founder decision register: every open founder or external gate with the smallest decision that unblocks it (`docs/orcel/FOUNDER_DECISIONS.md`) | this PR |
| F4 slice 5, kernel only: conditional task transitions, so a second writer can't overwrite a stop, and a commit started only if the task still proposes what was approved; a final `Stopped` state. `stop` is compiled for tests only: **no surface exists** until the decision on #446. Requests run one at a time today, so this is hardening for that second writer, not a fix of a reachable race | #607 → `1ec4e72` |
| F4 slice 4 kit and runbook: everything around the person's approval (`prep/F4_SLICE4_CLIENT_JOURNEY.md`). **Not yet run**: it needs the founder at the prompt | #608 → `dd3ec8b` |
| F4 decision proposals: stop without paid signing, and the release-build browser. Nothing activated | #609 → `12a18dd` |
| M4 selection package: Qwen3.5-4B primary, Granite 4.0 H-Tiny fallback, runtime and benchmark bar. **Nothing downloaded or run; no model capability is measured** | #610 → `5efc52d` |
| Unsigned macOS development tarball, built and checked in CI, with `orceld` answering from it on the hosted Mac. Not a release | #612 → `3dd082e` |
| #438: a stage timeline of a navigation that times out, after the 0-request mode recurred with diagnostics (run 41748009453: no connection at the only listener, no TLS, not a policy timeout). No mechanism shown yet | #613 → `08d5063` |
| Founder decision packet: the six decisions blocking the next milestones (`FOUNDER_DECISION_PACKET.md`), a narrow SG-000122 proposal, and the three-platform plan | #611 → `b0fc676` |
| M4 model scorer: labelled rows, an answer check per task, and a verdict in which a missing or unusable measure fails. Stricter than the package's first bar, recorded there before implementing: the injected task is required, a task counts only at 4 of 5 repeats, and egress must name the model. **No model has run** | #614 → `85efe13` |
| #438: the first stage timelines. A navigation stalled 27.3 s between `goto` and the worker hearing of the request, and another stalled past the 30 s budget with nothing after `goto`. Same place, longer stall: this supports, without proving, one cause. The timeline now also records the worker's largest event-loop gap and the machine's CPU busy share, to tell the sides apart. **No cause shown, and no timeout changed** | #618 → `2bfd844` |
| F5 client matrix: every configuration in `examples/mcp-clients` reaches the same 45 tools on the installed Windows release, over stdio and loopback HTTP, with a missing or wrong credential refused. **Configuration and protocol only, not those clients** | #619 |
| M4a harness: a bridge process that speaks only to `127.0.0.1`, one model task through the real agent, edge and orceld, and another process's peak memory on Windows and Linux. CI checks the wiring on all three OSes against a fixed stub, labelled `stub-no-model`, which the scorer refuses. **It says nothing about any model.** Starting a pinned server waits on the download decision | #615 → `4e85551` |
| Doc parser zip advisory reachability, completed: anydoc 0.2.2 searched in full; one `ZipArchive`, read only by name under caps; no `extract` anywhere | #580 → `e272277` |
| Lifecycle on main `89066a6`: Windows release qualification (install, run, update, recover, uninstall, local report client, 400 MB budget) and Linux deb/rpm/tarball install, systemd units, tamper detection and uninstall | main CI 40672122647 |

## 2. Engineering that can still be completed without the founder

| Item | Note |
|---|---|
| #438 residual: navigation `read: TimedOut` on CI | Waiting for a recurrence; #613's timeline captures it. #603's merge closed the issue by mistake on 2026-11-03, and the failure recurred afterwards; reopened 2026-11-04 |
| SG-000115 Priority B (inert): wiring B9a's lifetime spawner and B8b/B9b containment into a launch path (activation work); a cgroup the engine cannot leave (B9b's residual); S-07 key shipping and pinning (a founder decision) | Engineering solutions to shrink the class 4 residuals; none activates SG-000115 |
| Doc parser zip advisories (RUSTSEC-2026-0367/0368/0369/0429, extraction only) | Recorded exceptions, not accepted risk (founder direction 2026-11-02): reachability checked module by module in `apps/orcel-doc-parser/.cargo/audit.toml`. Remove when anydoc accepts zip >= 9 (anydoc 0.2.4 is the latest and still requires ^8.6); remediate at once if any becomes reachable. F5 slice 1 (founder decision 7) ships the parser in the Windows release with no caller in a release build, so these exceptions are in shipped code, still recorded as unreachable and not accepted |
| #292 flaky SG-000013 contained PowerShell test on windows-latest | Root cause not yet found |
| macOS install / start / uninstall lifecycle | No macOS package yet: macOS packaging (XP-16) waits for FD-05; Windows and Linux lifecycle are in class 1 |
| SG-000128 closeout | After slice 3b (class 3) is accepted or the founder records otherwise; the closeout judge checks that slice 1's deferred items are evidenced |
| BM-02 Tier C beyond C2b (C3 agent runs) | Blocked: needs a planner model (class 4) |
| CI flakes under watch | #438 (navigation), #508 (UIA bind), #512 (real git fetch), #516 (Go helper start), #524 (macOS jobs cancelled before a runner is assigned), #558 (orceld app API re-bind on macOS), #583 (macOS contained-tier memory sampler, fix in #591), #584 (three Windows download tests time out with the fixture never contacted; intermittent, #438 class; seen on main after runner image 20261030) |
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
| F4 slice 5 stop and takeover | Decided 2026-11-13: (2), the amendment for `task.stop` only; shipped as #640. Pause/resume would be another state-changing method — see #446 |
| Filesystem race residuals (#670–#680, #740) | Accepted for development builds by founder decision 8 of 2026-11-14; decided again before any release build (see `COMPLETION_LEDGER.md`) |
| A workbook in the report task (F5 Journey 2) | Decided 2026-11-14 (founder decision 7 (the founder's 2026-11-14 decision packet, `docs/orcel/FOUNDER_DECISION_PACKET.md`; not SG-000108's decision 7)): option A of `prep/F5_SPREADSHEET_JOURNEY.md`, the confined parser, slice by slice. Activates no grain: slice 2's approval question needs its security review and slice 3's exposure its grain. Slice 1 ships the parser in the Windows release with no caller (see `COMPLETION_LEDGER.md`) |
| F4 slice 7: live browser in release builds | Its own governed change and security review |
| FD-03 (gates CR-03), FD-05, FD-08 | As recorded in the frontier |
| Activation of SG-000115 (XP-14 launch, network sink, supervision on macOS/Linux) and the other prepared grains | Activation grants authority; only the founder activates. Gate (F4 slice 5, #640): before SG-000115 is activated, the Unix browser engine (on Linux it runs in new user and PID namespaces but no new mount namespace, `orcel-browser-host/src/unix_supervise.rs`) must be shown unable to reach orceld's app API socket (`$XDG_RUNTIME_DIR/orcel/app-api.sock`, or the macOS per-user temp directory's), or `task.stop`'s exception to the first-party code rule (`ORCEL_APP_API_1.md` section 2, founder decision of 2026-11-13, #446) is judged again. The exception rests on no confined process being able to reach the endpoint yet not signal orceld |
| Release and publication | Not authorized; no release is created. When one is, note that the release workflow keeps build artifacts 30 days: a publish approved later than that needs a full re-run |
| A planner model for BM-02 Tier C agent runs | Paid inference is excluded by the zero-cost rule; the local d1 model is an advisory classifier, not a planner |
| M4 model selection and licensing | Candidates and the benchmark plan are in `prep/M4-local-model-candidates.md`; nothing is downloaded or run before this gate |
| SG-000115 residuals (recorded, **not accepted**; engineering continues on each) | (a) macOS: a pid reused within one descendant scan (narrowed by B1, #557, to a backward wall-clock step: during a scan it can hide a reuse; afterwards it tears every scan, so the sweep fails closed); (b) descendants of another user that cannot be read, including root-run engines (on macOS recovery since B4, #566, keeps every profile while root runs an engine by a recognised name; a root engine under another name is not seen; since B6a, #568, a macOS profile with any non-deny ACL entry is refused at hold and at `verify` (an ACL added between those checks is not seen until the next one); the sandboxed-host `permission denied` ambiguity was closed by B3, #563); (c) false positives of the unattributable rule; (d) the network sink's port after an orceld crash (B8b, #586, removes the orphaned helper and the port traffic with an engine-only namespace that needs no uid maps, shown on the hosted Ubuntu runner; not wired into any launch path, and where unprivileged user namespaces are refused entirely, B9b, #604, contains the family through a systemd user service's cgroup, which a same-user process can still leave); (e) S-07 binds ownership and modes; B7, #581, adds a signature chain that verifies only where the signed index and the retained package are still on disk (stock GitHub Ubuntu has neither, and `/opt/google` at 0777, so Chrome there is unverified); (f) engines in another PID namespace; (g) profile paths with spaces (whole-argument matching now covers macOS always, and Linux only where the title is not rewritten), and `hidepid` on `/proc` |
| Real platform presence (Windows Hello, Touch ID, polkit), macOS permissions | Never simulated or pre-granted |
| Paid infrastructure, deployment | Excluded by the zero-cost rule |

## 5. External hardware or credentials

| Need | For |
|---|---|
| Code-signing certificates / Apple Developer identity | Signing, notarization, slice 5 option 1 |
| An isolated VM (Windows, and ideally macOS and Linux desktops) | BM-02 Tier C GUI tasks, XP-20 |
| The Mac with Chrome or Edge installed | Positive vendor-bundle evidence on hardware (CI has it hosted) |
| `remote-desktop-commander` OAuth (`/mcp` in an interactive terminal) | Remote runs on the user's devices from this agent |

## Completion, tracked separately (2026-11-07)

Decision numbers are those of `FOUNDER_DECISION_PACKET.md`. Orcel isn't finished while its core user journeys are incomplete. These five are separate, and one being ahead says nothing about another. Nothing is signed, published or released.

| Track | State | What's open |
|---|---|---|
| **1. Engineering** | Class 1 merged on exact-head green CI with independent review; class 2 in progress | Slice 5's surface is a draft waiting on decision 2. The rest of section 2 |
| **2. Real end-to-end product** | **Not complete. No real client has driven a real approval to a verified report.** The installed Windows journey passes in release qualification up to the prompt (`release_qualification.rs`, `orcel mcp stdio`), with a test client | Slice 4 needs the founder at the prompt (`prep/F4_SLICE4_CLIENT_JOURNEY.md`). Slice 5 (stop and takeover) needs decision 2. Slice 7 needs decision 6. Then the F4 closeout |
| **3. AI model** | **No model has been run.** Every agent result is scripted, and labelled so. The harness and scoring exist (`model_eval.py`, `model_run.py`, `model_memory.py`), and have only run against a stub | Decision 3 approves the download. A model may miss the bar, and then the honest result is "no qualified model yet" |
| **4. Cross-platform** | Windows and Linux lifecycle qualified on CI. Unsigned dev tarballs for macOS and Linux reach the approval through a test client. The Windows app has no macOS or Linux equal (decision 4) | macOS package (FD-05). macOS and Linux browser launch waits for SG-000115. Real GNOME and KDE approvals, and macOS direct-capture consent, need a person |
| **5. Security and release** | No accepted risks. SG-000115's residuals are open founder decisions, and B9c shows Landlock alone doesn't close the cgroup. Release isn't authorized | Signing, publication, and the residuals in section 4. The repository stays public by founder decision (2026-11-06), with plans kept privately. Earlier versions of those plans remain in public history, which is treated as already disclosed. Irreversible cleanup would be its own decision |

## Restart checkpoint

If a session ends, resume from here (2026-11-10, updated from 2026-11-07). Check GitHub for
the current head and CI: this checkpoint can't name its own merge. The per-component state
is in `COMPLETION_LEDGER.md`; start there.

Merged 2026-11-07 to 2026-11-10, after the list below:
- Filesystem and parser safety: #668, #670, #671, #674, #675, #676, #678, #679, #680; clipboard
  privacy #672 (Windows) and #681 (Linux, macOS); macOS sampler #688.
- Approval UX (founder decision 1): #682 (one escaped prompt text), #683 (STRONG summary before
  Hello and Touch ID), #684 (Origin line), #685 (typed targets), #686 and #689 (bounded,
  redacted previews), #690 (saved sizes-only choice), #691 (credential warning), #693 (Windows
  dialog timeout), #694 (application line), #695 (origin in approval history).
- Desktop app: #697 (read-only `approval.history` on the app API and a `history` command),
  #699 (tighten-only `previews sizes`), #702 (stop desktop control, `control`, `revoke all`).
- Security: #701 closed a race where a grant waiting for Windows Hello could overwrite a
  revoke or emergency stop made meanwhile.
- CI: #687 (Tier C GUI download cache), #698 (rehearsal flake retry, #696). Flakes under watch
  also include #700 (X11 latency scroll) and #508 (UIA bind, seen again 2026-11-10).

Working rules learned this stretch: a PR must contain current main before Jev reviews it;
inline shell heredocs on this PC collapse doubled backslashes, so edit scripts go through
files; CI runners are the bottleneck, so cancel runs for superseded heads and merge one PR
at a time.

The 2026-11-07 checkpoint follows.

Plans and the founder decision documents are kept privately, at the same paths, and the
files here are short notes (founder decision, 2026-11-06). Read the private copies for
those. Orcel itself stays public.

1. Merged since the last checkpoint: #617 (XLSX reader, decision 7 still open then; decided 2026-11-14, see section 4),
   #621 (MCP from the dev tarballs), #622 (live task timeline in the Windows app),
   #623 (workbook source, test-only), #624 (browser tasks on the controlled site),
   #625 (native host memory) and #626 (a broken pipe to `orceld` no longer ends the
   MCP edge; longer tarball journey). #627 (refusals name the source), #629 (M-NAT-03,
   100 actions per type), #630 (`orceld` alone killed during an Agent run, on macOS and
   Linux), #631 (M-BR-04, worker and engine only), #633 (M-NAT-01, 200 calls), #634
   (M-WI-01, crawl), #635 (#438: the engine's processes at a timeout), #636 (B9c:
   Landlock alone doesn't give a cgroup the engine can't leave) and #637 (a test race
   on `ORCEL_TRUST_PATH`) followed. Then #639 (the F4 journey with recovery, history and a
   preflight, ready for a person at a real prompt), #643 (build packages kept only on a manual
   run, for 3 days, and both review jobs refuse forks), #644 (plans moved to private documents),
   #645 (clean toolchain in the agent job; PowerShell limit tests get time to start) and #646
   (the Windows app ships in the release, opened with `orcel app`). Then #641 (the five tracks),
   #642 (M-WI-02 on five real pages: text reduction only, no tokens or answer accuracy), #647
   (provenance needs the .NET SDK's version), #648 (the F4 kit built by CI, `ready` needs `orceld`
   to answer, runbook corrected from an audit) and #650 (evidence for #438 and #649, no limit
   changed). Then #654, #656 and #657: Windows state moves to `%USERPROFILE%\.orcel`, since other
   software on an ordinary account can hold rights on `AppData` that the unchanged ancestor check
   rightly refuses. `orceld` and most commands that write state refuse while data at
   `%LOCALAPPDATA%\Orcel` is undecided, and `orcel state migrate` or `keep-separate` decides. Real
   binaries on a real Windows account with those grants, non-elevated, show it creating the private
   root, restarting, and refusing the old location, foreign grants and hard links. A real install
   under the new root ran only in CI's release qualification. #656 samples the machine in the
   Windows Node job, and prints `MACHINE` lines to set a timeout against.
   Evidence so far, all scripted or test clients, never a model or a real client:
   browser tasks 15/15 with no timeouts, on Windows only, p50 about 1.0 to 1.8 s across
   runs; native host peak 6.7 MiB on X11, 6.4 to 6.9 on Sway across three runs,
   11.0 on macOS, under the suite and not idle, before #629 added its actions; dev
   tarballs reach the approval and stop (macOS `APPROVAL_DENIED`, Linux
   `APPROVAL_UNAVAILABLE`), and survive a killed `orceld` in the same session; semantic
   actions p50 324 ms on X11, 107 on Sway, 727 on macOS; raw click 762, drag 1016, scroll
   835 ms, on X11 only; worker and engine peak 327 to 343 MiB committed, on Windows,
   without the host. Linux's p95 is within a few ms of its p50, which suggests fixed
   waits. From reading the code, not measured: X11's extra 215 ms on semantic actions
   fits the focus guard's settle watch of about 240 ms (`focus_guard.rs`), which needs a
   reachable `DISPLAY` and is skipped on CI's Sway. It catches and undoes a late focus
   steal, so it isn't a saving to take. The X11 raw click pays the same watch, which leaves about
   520 ms of its 762 unexplained. The 250 ms human-input quiet wait (`worker.rs`) isn't it: a
   local run on Xvfb in WSL, with `raw_latency` changed by hand to 40 samples each and a sleep
   before each action, left click p50 at 840 ms and 843 ms with 350 ms more between actions,
   drag 1120 and 1150, scroll 906 and 920. `EFFECT_SETTLE` is on the uinput route, which Xvfb doesn't use. `list_windows` p50 27 ms on X11,
   44 on Sway, 73 on macOS, and `observe_window` 50, 78, 121, with no Windows figure yet
   to check M-NAT-01's 1.5x target against. A crawl of ten pages, six read, takes about
   2.2 s on Windows, with 359 MiB committed at peak. #438's latest timeline shows a
   2 ms worst event-loop gap and 19% CPU across a 30 s stall after `goto`, so that stall
   is on the engine's side; what it waits for isn't known. Branch
   protection needs each PR up to date with main, so PRs merge one at a
   time: merge main in, exact-head green run, then `--match-head-commit`. #342 and
   #328 belong to other work: do not touch them.
2. Local test runs on Windows need a private temp folder (`TEMP`/`TMP` outside
   AppData and outside the repository, or `ORCEL_BM02_STATE_PARENT` for Tier A):
   this host grants others rights on both, which tests' private folders inherit or
   are refused under. The real root isn't affected. GUI work (`tests/memory.ps1`,
   `tierc-observe`, `tierc-act`) runs on CI runners only. Locally, run only filtered
   `orcel-provider-uia` tests. Rust builds also work natively here with the pinned MSVC
   toolchain, which lacks clippy and rustfmt: use WSL for clippy for the Windows target, and
   `cargo +stable fmt` or WSL's rustfmt (stable can drift from the pin). `orceld` is built from `crates/orceld/src/sg000039_main.rs`, not
   `main.rs`: a change meant for the binary needs a test that runs the binary.
3. Vendored cua-driver changes go through the patch queue: a P-xx entry in
   `PATCHES.md`, a `patched_files` entry in `docs/orcel/cua_driver_provenance.json`,
   then `node scripts/check-vendored-cua.mjs` on a commit.
4. Next engineering, in order: the next product milestone that needs no
   founder (the frontier's "Next executable grain" and `FOUNDER_DECISIONS.md`), with
   these candidates: the rest of the X11 raw click's time; M-WI-02's real tokens and answer
   accuracy (#642 measured characters; tokens need a tokenizer, accuracy a scoring method or a
   planner); a terminal task timeline
   on macOS and Linux, once someone decides whether that client may use `task.*`.
   Checked figures for CSV reports aren't on the roadmap and would change what
   `verified` means, so they need adopting first. Then #438: a browser loop on CI shows about 40 s of slowdown during a
   `StorSvc` or VSS burst after a Defender update, in 3 of 3 runs, gone in the 2 runs with `StorSvc`
   stopped and the update running, but with no navigation timeout in any of them, so its link to
   this issue is unproven. Compare `MACHINE` lines at the next real timeout. Don't change Windows
   services on a person's machine for this. Then #649 when its evidence first prints, #653 by comparing supervisor logs if it recurs,
   and #655 (uninstall's lists miss some state). A cgroup the engine cannot leave stays open: B9c shows Landlock alone
   doesn't do it (an inherited descriptor, `clone3` and the user bus all get past it),
   and refusing `clone3` needs a real engine to test against, which waits on activation.
   Then what the founder's answers to
   `FOUNDER_DECISION_PACKET.md` unlock.
5. Known CI flakes: toolchain install conflict on macOS and Ubuntu (the `Orcel Agent M1` job now
   installs its toolchain from clean, #645; rerun failed jobs elsewhere),
   #438, #649 (the Windows app's window; not known to be the runner), #653 (the MCP edge didn't answer within 60 s in the lifecycle test; seen once), #508, #512, #516, #524, #558 (orceld app API re-bind on macOS), #583 (macOS memory sampler, #591).
   Seen once, not yet tracked: `unix_rehearsal::tests::survivors_and_unverified_coverage_keep_the_sink_and_the_profile`
   on macOS, and the upstream-asset parity tests when GitHub blob fetches fail.
   Wording: GitHub reads "fix #N" and "close #N" as closing keywords even after "doesn't",
   which closed #438 by mistake, so check `closingIssuesReferences` on any PR naming it.
6. Do not repeat: XP-06/XP-11 Mac hardware tests (#425); the SG-000115 A1 to
   A6b, B1 to B5, B5b, B6a, B6b, B7, B8, B8b, B9a and B9b slices; the agent A1-A3 tests; P-13 and P-14; the M4 research (#553).
7. Never mark Core MVP complete; classes 3 to 5 stay open.
