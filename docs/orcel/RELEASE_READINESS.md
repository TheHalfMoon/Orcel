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

## 2. Engineering that can still be completed without the founder

| Item | Note |
|---|---|
| BM-02 Tier B: 21 mutating tasks (12 solved, 9 expected refusals) through orceld's request entry and real broker; scripted SOFT consent and no mutation journal, both labelled | #500, in review; moves to class 1 once merged on exact-head CI |
| #438 residual: navigation `read: TimedOut` on CI | Waiting for a recurrence; #494's diagnostics capture it |
| #292 flaky SG-000013 contained PowerShell test on windows-latest | Root cause not yet found |
| #288 WPF idle memory | Needs a measurement baseline, then a budget |
| Install / start / uninstall lifecycle re-qualification on current main | Release qualification job covers the package; a fresh lifecycle run is due |
| BM-02 Tier C (GUI taskpack tasks) | Engineering is possible, but runs need an isolated VM (class 5); never on the live desktop |
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

## 5. External hardware or credentials

| Need | For |
|---|---|
| Code-signing certificates / Apple Developer identity | Signing, notarization, slice 5 option 1 |
| An isolated VM (Windows, and ideally macOS and Linux desktops) | BM-02 Tier C GUI tasks, XP-20 |
| The Mac with Chrome or Edge installed | Positive vendor-bundle evidence on hardware (CI has it hosted) |
| `remote-desktop-commander` OAuth (`/mcp` in an interactive terminal) | Remote runs on the user's devices from this agent |

## Restart checkpoint

If a session ends, resume from here:

1. #499 (Tier A) is merged; #500 (Tier B) follows it. Both run in
   `cargo test --workspace` on all three OSes, and the Rust job's `BM-02
   evidence` step prints `BM02-EVIDENCE` / `BM02B-EVIDENCE` lines.
2. Local runs on Windows need a private temp folder:
   `ORCEL_BM02_STATE_PARENT` (Tier A) or `TEMP`/`TMP` pointing at one;
   orceld refuses state another account can reach.
3. Next engineering: class 2 above, in order: #438 residual (on
   recurrence), #292, lifecycle re-qualification, governance preparation,
   then Tier C harness work that can be built without running it on a live
   desktop.
4. Never mark Core MVP complete; classes 3–5 are open.
