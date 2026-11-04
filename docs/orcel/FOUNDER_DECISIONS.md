# Founder decision register

One list of every open decision that only the founder (or an external party) can make, as of 2026-11-03. Engineering continues around each one. Nothing here is decided by this document: each row names the **smallest decision that would unblock the work**, what it blocks, and what happens meanwhile.

**To act on the ones blocking the next milestones, start with `FOUNDER_DECISION_PACKET.md`.** Sources are linked so each row can be checked. When a decision is made, record it in its own source (a grant record, the spec, or the issue), then update its row here.

## Activations (governance)

| ID | Smallest decision | Blocks | Meanwhile | Source |
|---|---|---|---|---|
| SG-000115 | Activate the macOS/Linux browser launch, sink and supervision grain. If yes, accept or reject each open class 4 residual (below). | Any wired macOS/Linux browser launch path | Inert, test-only risk work (A1–A6b and B1–B9b merged) keeps narrowing residuals. **NOT ACTIVATED.** | `docs/orcel/implementation-readiness/prep/SG-000115.md` |
| SG-000122 | Activate governed exposure of the browser agent actions (form actions, waits, uploads, dialogs, the verifier) through orceld/MCP. | Those actions reaching any agent | Host and worker only, unexposed. **NOT ACTIVATED.** | `prep/SG-000122.md` |
| SG-000124 | Activate the optional sandbox runtimes (SX-01 to SX-05). | Those runtimes | Preparation only. **NOT ACTIVATED.** | `prep/SG-000124.md` |
| SG-000125 (SX-06) | Decide whether to expose the sandbox to agents. This is its own decision, separate from SG-000124. | Sandbox exposure | Nothing exposed. | `prep/SG-000124.md`, `EXECUTION_FRONTIER.md` |
| SG-000128 slice 3b and closeout | Provide a disposable Windows machine, and grant a STRONG-presence Full User lease there for the cdb-s02 scripted plan to act. Or record the closeout otherwise. | The SG-000128 closeout | Slices 1, 1b, 2 and 3a merged; the action is refused by the DesktopInput gate on CI. | `RELEASE_READINESS.md` (classes 3 and 4) |
| SG-000096 T04/T05 | How to proceed with governed shell dispatch, after the implementing session was stopped by an automated safety classifier: a human implementer, a narrower design, or deferral. | Full User shell (stays unarmed) | T02/T03 merged and unexposed. | #266, #267 |

## SG-000115 class 4 residuals (decided at activation)

| Residual | Smallest decision | Current mitigation (inert) |
|---|---|---|
| (d) a network sink's port after an orceld crash | Accept B8b (engine-only user/PID namespace) as the Linux design and, where namespaces are refused, B9b (systemd user unit). Or reject both. | B8b contains the family on the hosted runner (#586). B9b (#604) contains it with a user manager. A same-user process can leave a cgroup or ask systemd for a new unit. |
| (e) S-07 signing keys | Which vendor keys Orcel ships and pins (Google Linux signing key; others), and how they are updated. | B7 verifies the chain where the signed index and package are on disk (#581). The pinned fingerprint is recorded from memory and unverified. |
| A root engine under an unrecognised name (part of (b)) | Accept, or require an allowlist beyond Chrome, Edge and Chromium. | B4 checks root engines by name (#566). |
| The other recorded residuals: (a) macOS pid reuse within one scan; (c) false positives of the unattributable rule; (f) engines in another PID namespace; (g) profile paths with spaces | Accept each, or require more work before activation. | The full text of each, with its mitigation, is the "SG-000115 residuals" row in `RELEASE_READINESS.md`. |

## Core MVP (F4, SG-000127)

| Item | Smallest decision | Why an agent cannot | Source |
|---|---|---|---|
| Slice 4: client transcript with an approved commit | Sit at Orcel's local approval prompt once while Claude or Codex runs the report journey. | An agent approving would be manufacturing consent. | #446 |
| Slice 5: stop and takeover | Choose: (1) a Windows code-signing identity; (2) a governed amendment allowing an authority-reducing, task-scoped stop with peer-identity admission; or (3) record stop/takeover as an open F4 gate. | `ORCEL_APP_API_1.md` requires a first-party code requirement for the first state-changing method. | #446, `prep/F4_TASK_STOP.md` |
| Slice 7: live browser in release builds | Decide whether release builds carry live-browser authority. | Release-build authority is governed. | #446 |

## Product direction (FD table)

| ID | Smallest decision | Blocks | Default if undecided | Source |
|---|---|---|---|---|
| FD-03 | Tauri 2 Control Room on all three OSes, with WPF kept on Windows until the CR-04 parity gate? | CR-03 | WPF stays; CR-01/CR-02 proceed. | `IMPLEMENTATION_BACKLOG.md` |
| FD-05 | (a) a Mac usable as a self-hosted runner with Accessibility and Screen Recording; (b) an Apple Developer ID (paid). | XP-08 macOS GUI E2E, XP-16 signing/notarization, macOS packaging | Unsigned macOS dev builds only. | same |
| FD-07 | After XP-20, consolidate Windows on the Rust native host? | Windows consolidation | Keep the Go host. | same |
| FD-08 | Admit the engine's experimental WebMCP flag through an SG-000074 argv amendment? | BR-08 | Declarative WebMCP only. | same |

## AI capability

| Item | Smallest decision | Blocks | Source |
|---|---|---|---|
| M4 local model (SG-000129 decision 2) | Which model, under which license, and how users obtain it. Candidates and a benchmark plan are prepared. | Any real model run; every agent result so far is **deterministic-scripted**, not model performance | `prep/M4-local-model-candidates.md` (#553) |
| Read-only lease signal | A separately decided edge change exposing a read-only lease-state signal, through governance. The spec does not name the founder as its decider. | Any mutating allowlist for the agent | SG-000129 spec, open follow-ups |
| Hosted inference | A budget, if hosted inference is wanted at all. | BM-02 Tier C beyond C2b (C3 agent runs) | `EXECUTION_FRONTIER.md` |

## Release, legal and external

| Item | Smallest decision | Source |
|---|---|---|
| Signing and distribution | A Windows code-signing identity, and FD-05 for macOS. | `RELEASE_READINESS.md` |
| Production release | Whether and when to publish. Nothing is published until then. | same |
| Rights records | Written model rights and Firecrawl rights records. | `EXECUTION_FRONTIER.md` |
| macOS direct-capture consent | The founder grants it interactively on the Mac. It cannot be requested noninteractively or spoofed. | XP-07/XP-12 |
| GNOME/KDE approval sessions | Interactive approval/refusal sessions on real desktops. | XP-10 |
| Multi-device | Second and third Windows machines. | `EXECUTION_FRONTIER.md` |
| STRONG operations (BM-02 solved removals, `fs.remove` and others) | Real platform presence (Windows Hello, Touch ID or polkit) for a qualification run. It is never simulated. | `RELEASE_READINESS.md` |
| XP-20 and BM-02 Tier C GUI tasks | An isolated VM or disposable Windows session, not the founder's live desktop. | same |

## Accepted exceptions (not risk acceptance)

| Item | Status | Removal condition |
|---|---|---|
| RUSTSEC-2026-0367, 0368, 0369 and 0429 (zip, via anydoc) in the doc parser | 0429 is kept for now on the founder's instruction (#580); 0367 to 0369 were ignored earlier because the parser never extracts entries. **Not permanent risk acceptance.** Reachability is analysed module by module in `apps/orcel-doc-parser/.cargo/audit.toml`. | Remove when anydoc accepts zip 9 or later (the fixed version), qualified. If found reachable, stop relying on them and remediate. |

## Not founder decisions

Engineering keeps these without asking:

- reliability fixes;
- inert SG-000115 work;
- Agent assurance tests;
- handoffs;
- CI diagnostics on hosted runners at no cost.
