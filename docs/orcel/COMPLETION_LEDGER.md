# Completion ledger

Status record, not an authority. It tracks every component the founder's directive of
2026-11-10 ("finish the entire Orcel project") lists. Each row is backed by merged pull
requests and their exact-head CI, or says plainly that it isn't. There is no completion
percentage. **Orcel is not finished**, and nothing here releases, signs or publishes it.

`RELEASE_READINESS.md` keeps the five-class view and the restart checkpoint. This file keeps
the per-component view. Update the row a merge changes, in the same PR where practical.

States:
- **Done (qualified)** means merged, exact-head CI, independent review, and no open work in scope.
- **Partial** means merged pieces with named work left.
- **Blocked** means the next step needs a founder decision, a person present, or external hardware.
- **Not started** means no merged work yet.

Last updated: 2026-11-10, main at `203616b1` (#689).

## Approval and security UX

| Component | State | Evidence (merged PR → commit) | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| One escaped, bounded prompt text on every OS | Done (qualified) | #682 → `aac855c1` | `prompt_text` unit tests (bidi, controls, default-ignorables, combining marks, middle ellipsis) | Prompts escape what they show; they don't decide what is safe | none | none |
| STRONG summary before Windows Hello and Touch ID | Done (qualified) | #683 → `9c4f58ca` | `windows_summary_decision`, `soft_macos::summary_decision` tests | Real Hello and Touch ID are not exercised in CI; a person must be present | Founder-present acceptance run | Class 3 (a person at the prompt) |
| Origin line (local or remote, with provider, device and connection) | Done (qualified) | #684 → `a03baf96` | `OriginStamp` wiring test with a negative control | — | Origin is not yet stored in approval history | none |
| Typed targets, file Type line, move destination | Done (qualified) | #685 → `7a65b4c0` | `target_lines` tests | — | none | none |
| Bounded, redacted content previews: file write and edit | Done (qualified) | #686 → `67799449` | `Preview` and `looks_secret` tests | `looks_secret` is a pattern list, not a guarantee | none | none |
| Previews for clipboard writes, typed input, UI values; typed line breaks and control characters counted | Done (qualified) | #689 → `203616b1` | `typed_text_is_shown_only_in_the_bounded_preview` | No end-to-end clipboard or `set_value` prompt test | none | none |
| Saved sizes-only choice | In review | #690 (open) | config round-trip and `child_environment` tests | Linux systemd uses its env file; a running session keeps its choice | A switch in the desktop app's settings | none |
| Plain warning when hidden content looks like a credential | In review | #691 (open) | `a_credential_or_sizes_only_shows_no_content` | Refusing credential-like typed text, or making it STRONG, is not done (safer default chosen: hide, warn, keep approval) | none | none |
| Application and window identity on desktop prompts | Not started | — | — | — | Window title and executable from the verified process | none |
| Windows approval dialog timeout | Not started | — | — | `MessageBoxW` waits indefinitely | Bounded wait that denies on expiry | none |
| Request origin in approval history | Not started | — | — | — | Store the origin with each decision | none |

## Filesystem, clipboard, process and parser safety

| Component | State | Evidence | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| Filesystem mutation races (create, write, edit, remove, mkdir, move) | Partial | #670 → `99e957bb`, #676 → `ba0397f0`, #678 → `2808070f`, #679 → `7684055f`, #680 → `03e847db` | per-OS race tests in `orcel-provider-fs` | Volume mount points; non-NTFS file systems; a directory replaced in the same folder; a destination that becomes Git data; `RENAME_NOREPLACE` unsupported on some file systems; ReFS 128-bit ids | Decide which residuals to close and which to record | none |
| Git control paths and effective configuration | Done (qualified) | #668 → `ff10f1d7`, #670 → `99e957bb` | `orcel-provider-git` and fs Git-guard tests | — | none | none |
| Clipboard privacy (content its app marks private) | Partial | #672 → `4893bcc5` (Windows), #681 → `cbae3987` (Linux, macOS) | `xp15_*` tests in CI only (they touch a real clipboard) | Linux check-then-read gap; forged X11 TARGETS with property NONE; unmarked content; Wayland and macOS untested with a marked copy | Runtime evidence on Wayland and macOS | Disposable desktop for marked-copy runs |
| Contained parser scratch and run directories | Done (qualified) | #671 → `7300fbb9`, #674 → `5f82044c`, #675 → `dd91822c` | doc-parser and contained-tier tests | — | none | none |
| macOS contained memory sampler | Done (qualified) | #688 → `74489605` | `a_zombie_is_recognised_as_exited_at_once` | macOS has no memory rlimit; the ceiling is sampled | none | none |
| Doc parser zip advisories | Partial | `apps/orcel-doc-parser/.cargo/audit.toml` | supply-chain audit job | Recorded exceptions, not accepted risk | Remove when anydoc accepts zip ≥ 9 | Upstream anydoc |

## Computer-use capabilities

| Component | State | Evidence | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| Desktop observation (windows, scoped UIA subtree) | Partial | SG-000128 slices 1, 1b, 2, 3a (#520, #522, #523, #521) | BM-02 Tier A and Tier C C2b on CI | Native host on macOS and Linux refuses a subtree root | Slice 3b acting | Class 3: a Full User lease needs a STRONG Hello approval on a disposable machine |
| Desktop input (mouse, keyboard, text, UIA values) | Partial | Full User lease and approvals; #689 prompts | live-input tests on CI runners | Every action needs a lease and an approval | Founder-present run on a disposable machine | Class 3 |
| Browser interaction | Partial | SG-000108, SG-000115 inert engineering (`RELEASE_READINESS.md` class 1) | BM-02 browser tasks on Windows | macOS and Linux launch refused until SG-000115 activation; release-build live browser needs its own decision | Activation work | Founder decisions (SG-000115 activation, slice 7) |
| Process execution (contained tier, shell) | Partial | SG-000096 plan (#260, #266, #267 open) | contained-tier tests | #292 flaky on Windows | T04 and T05 | none recorded |
| Stop, pause, resume, human takeover | Blocked | #640 (draft) | — | — | Slice 5 surface | Founder decision 2 |
| Crash recovery and state reconciliation | Partial | SG-000120 resume summary #464; mutation journal; #639 recovery and history | journal tests; #630 orceld killed during an Agent run | Effects orceld can't read back are recorded as unknown | Recovery UI in the app | none |
| Multi-client isolation | Partial | Remote leases and origin stamping (#667 → `26f17234`, #684) | `fix395_tunnel_remote`, origin tests | — | A qualification suite across concurrent clients | none |

## Desktop application and lifecycle

| Component | State | Evidence | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| Windows app (task timeline, errors, Start Menu) | Partial | #622, #646, #660 → `46aa680c`, #663 → `1ff4fc14`, #664 → `7a73bac3`, #665 → `6d176867` | Windows app task timeline job | #649 flaky window lookup | Onboarding, client connection management, permissions, settings and privacy screen, history, emergency stop, accessibility review | Stop needs decision 2 |
| macOS and Linux app | Not started | — | — | — | — | Founder decision 4 |
| Windows install, start, update, rollback, uninstall | Partial | #654 → `e0e3fa41`, #659 → `93f33b25`, #661 → `e8fd1692`, #665 | release qualification on Windows CI | #655 (uninstall lists miss some state) | #655 | Signing (founder) for a release build |
| macOS package | Blocked | — | — | — | XP-16 packaging | FD-05, signing identity |
| Linux packages | Partial | Linux packages job | dev tarball journeys | — | — | none recorded |
| Release workflow separation | Blocked | #673 (draft) | — | — | Merge once the `release` environment exists | Founder creates the environment; no settings changed by agents |

## Product end to end

| Component | State | Evidence | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| A real client drives a real approval to a verified report | Not started | Release qualification reaches the prompt with a test client | `release_qualification.rs` | No person has answered a real prompt in a journey | F4 slice 4 | Class 3: the founder at the prompt |
| AI model integration | Not started | Harness only (`model_eval.py`, `model_run.py`) | stub runs | No model has been run | Run a candidate | Founder decision 3 (download) |
| Passkey test environment | Not started | — | — | — | A disposable environment and protocol | Never the founder's personal desktop or accounts |

## How to resume

1. Read this file and the restart checkpoint in `RELEASE_READINESS.md`.
2. Check GitHub for open PRs (`gh pr list --author @me`) and main CI.
3. Take the first row above whose state is not Done and whose Blockers column is "none".
