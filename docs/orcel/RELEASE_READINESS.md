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
| #288 WPF memory: profiled against a minimal WPF window on CI; transcript bounded (working set flat over 250 queries) | #513 → `f9a69d8` |
| BM-02 Tier C C2a: a pinned GUI task's Electron apps launched on a CI runner, observed through the real orceld, cleaned up | #514 → `d9a899a` |
| #515 scoped UIA subtree observation: preparation packet (no shape change) | #517 → `2b4062d` |
| SG-000115 preparation packet (no activation) | #502 → `89066a6` |
| Lifecycle on main `89066a6`: Windows release qualification (install, run, update, recover, uninstall, local report client, 400 MB budget) and Linux deb/rpm/tarball install, systemd units, tamper detection and uninstall | main CI 40672122647 |

## 2. Engineering that can still be completed without the founder

| Item | Note |
|---|---|
| #438 residual: navigation `read: TimedOut` on CI | Waiting for a recurrence; #494's diagnostics capture it |
| #292 flaky SG-000013 contained PowerShell test on windows-latest | Root cause not yet found |
| macOS install / start / uninstall lifecycle | No macOS package yet: macOS packaging (XP-16) waits for FD-05; Windows and Linux lifecycle are in class 1 |
| BM-02 Tier C C2b: a scripted plan acting through orceld's approval-gated UIA shapes (scripted consent, labelled) | Written on `grain/bm-02-tier-c-c2b`; blocked by #515 (orceld's UIA tree cap ends at Electron's web Document); C3 agent runs are blocked (class 4) |
| CI flakes under watch | #438 (navigation), #508 (UIA bind), #512 (real git fetch), #516 (Go helper start) |
| Governance preparation for SG-000115, SG-000122, SG-000124, SG-000127 closeout | Specs, tests, dependency and security analysis only; activation is a founder decision |
| Documentation consistency (frontier, roadmap, benchmark plan) | Ongoing with each merge |

## 3. Acceptance tests that need the founder present

| Item | Why an agent cannot do it |
|---|---|
| F4 slice 4: one supported client transcript with an approved commit | A person must answer orceld's local approval prompt; an agent or test answering it through the real binaries would be manufactured consent |
| BM-02 solved removals (`fs.remove`) and other STRONG operations | Need platform user presence (Windows Hello, Touch ID, polkit); Tier B shows only that the broker refuses them when presence is unavailable (a stub verifier) |
| XP-20 | Needs a disposable Windows session, not the founder's live desktop |
| macOS direct-capture consent; XP-07/XP-12 delivered capture and input | The founder grants consent on the Mac; nothing may forge or pre-grant it |
| Real GNOME/KDE XP-10 approval checks | A person at the desktop prompt |

## 4. Founder decisions

| Decision | Options recorded |
|---|---|
| Code signing (Windows Authenticode, macOS identity) | Gates F4 closeout, slice 5 (option 1), FD-05 / XP-16 macOS packaging |
| F4 slice 5 stop and takeover | (1) signing, (2) governed amendment for an authority-reducing task-scoped stop, (3) record as an open F4 gate — see #446 |
| F4 slice 7: live browser in release builds | Its own governed change and security review |
| FD-03 (gates CR-03), FD-05, FD-08 | As recorded in the frontier |
| Activation of SG-000115 (XP-14 launch, network sink, supervision on macOS/Linux) and the other prepared grains | Activation grants authority; only the founder activates |
| Release and publication | Not authorized; no release is created |
| Opening the #515 governed change (SG-000027 shape, native host request, SG-000063 MCP contract) | Packet: `prep/UIA_SUBTREE_OBSERVATION.md` |
| A planner model for BM-02 Tier C agent runs | Paid inference is excluded by the zero-cost rule; the local d1 model is an advisory classifier, not a planner |

## 5. External hardware or credentials

| Need | For |
|---|---|
| Code-signing certificates / Apple Developer identity | Signing, notarization, slice 5 option 1 |
| An isolated VM (Windows, and ideally macOS and Linux desktops) | BM-02 Tier C GUI tasks, XP-20 |
| The Mac with Chrome or Edge installed | Positive vendor-bundle evidence on hardware (CI has it hosted) |
| `remote-desktop-commander` OAuth (`/mcp` in an interactive terminal) | Remote runs on the user's devices from this agent |

## Restart checkpoint

If a session ends, resume from here:

1. Everything listed in class 1 is merged on exact-head green CI with an
   independent review; main is green through `2b4062d`. No PR from this
   work is open. `grain/bm-02-tier-c-c2b` holds C2b (unmerged, blocked by
   #515).
2. Local runs on Windows need a private temp folder (`TEMP`/`TMP`, or
   `ORCEL_BM02_STATE_PARENT` for Tier A); orceld refuses state another
   account can reach. GUI work (`tests/memory.ps1`, `tierc-observe`,
   `tierc-act`) runs on CI runners only and refuses elsewhere. WSL2 on the
   development PC stopped starting processes (an I/O error inside the
   distro); it was not restarted, because that would also stop Docker
   Desktop.
3. Next engineering, in order:
   - the remaining SG-000115 authority-neutral pieces (Unix managed-policy
     reads, supervision primitives, profile hold) as unexposed, tested code;
   - CI flakes when they recur with diagnostics (#438, #508, #512, #516);
   - C2b once the #515 governed change exists.
4. Never mark Core MVP complete; classes 3 to 5 stay open.
