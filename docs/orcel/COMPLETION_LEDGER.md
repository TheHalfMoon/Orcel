# Completion ledger

Status record, not an authority. It tracks every component the founder's directive of
2026-11-10 ("finish the entire Orcel project") lists. Each row is backed by merged pull
requests and their exact-head CI, or says plainly that it isn't. There is no completion
percentage. **Orcel is not finished**, and nothing here releases, signs or publishes it.

`RELEASE_READINESS.md` keeps the five-class view and the restart checkpoint. This file keeps
the per-component view. Update the row a merge changes, in the same PR where practical.

States:
- **Done (qualified)** means merged, exact-head CI, independent review, and no open work in scope. The independent reviews are recorded in each PR's description, alongside the review gates' checks.
- **Partial** means merged pieces with named work left.
- **Blocked** means the next step needs a founder decision, a person present, or external hardware.
- **Not started** means no merged work yet.

Last updated: 2026-11-12, main at `67781427` (#730). Open PRs: #640 and #673 (drafts waiting on founder decisions), #342 and #328 (other work).

## Approval and security UX

| Component | State | Evidence (merged PR → commit) | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| One escaped, bounded prompt text on every OS | Done (qualified) | #682 → `aac855c1` | `prompt_text` unit tests (bidi, controls, default-ignorables, combining marks, middle ellipsis) | Prompts escape what they show; they don't decide what is safe | none | none |
| STRONG summary before Windows Hello and Touch ID | Blocked (merged; acceptance needs a person) | #683 → `9c4f58ca` | `windows_summary_decision`, `soft_macos::summary_decision` tests | Real Hello and Touch ID are not exercised in CI; a person must be present | Founder-present acceptance run | Class 3 (a person at the prompt) |
| Origin line (local or remote, with provider, device and connection) | Done (qualified) | #684 → `a03baf96` | `OriginStamp` wiring test with a negative control | — | none (approval history stores it since #695) | none |
| Typed targets, file Type line, move destination | Done (qualified) | #685 → `7a65b4c0` | `target_lines` tests | — | none | none |
| Bounded, redacted content previews: file write and edit | Done (qualified) | #686 → `67799449` | `Preview` and `looks_secret` tests | `looks_secret` is a pattern list, not a guarantee. It over-hides: text naming Orcel's own crates (`orcel-approval`, `orcel-trust`) or words like `mnemonic` hides the preview, which fails safe | none | none |
| Previews for clipboard writes, typed input, UI values; typed line breaks and control characters counted | Done (qualified) | #689 → `203616b1` | `typed_text_is_shown_only_in_the_bounded_preview` | No end-to-end clipboard or `set_value` prompt test | none | none |
| Saved sizes-only choice | Done (qualified) | #690 → `5c55fd46` | config round-trip, `child_environment`, rollback refusal tests | Linux systemd and the dev tarball read their own environment; rollback refuses while sizes is saved | none (desktop switch: #699 → `b18c67ba`, tighten-only) | none |
| Plain warning when hidden content looks like a credential | Done (qualified) | #691 → `ca7ca02a` | `a_credential_or_sizes_only_shows_no_content` | Refusing credential-like typed text, or making it STRONG, is not done (safer default chosen: hide, warn, keep approval) | none | none |
| Application and window identity on desktop prompts | Partial | #694 → `3e6ef8e2`, #722 → `93a39bf8` | prompt-text and registry tests; `desktop_prompt_tests` sends a screenshot request through orceld's `handle_envelope` and checks the prompt names the application and window | The title is the one recorded at observation; the executable is a name, not a signed identity; the orceld-level test covers the capture prompt, the other ten sites share `with_target_application` | A code-signature line | none |
| Windows approval dialog timeout | Done (qualified) | #693 → `e90e51d6` | answer mapping on every OS; a real dialog on the Windows CI runner | Windows Hello's own prompt keeps its own timing | none | none |
| Request origin in approval history | Done (qualified) | #695 → `574ccece` | origin recorded, reload, tamper and older-record tests | Unkeyed checksums catch corruption, not a determined same-user writer; a stripped origin shows as unrecorded; since #708 → `eef75e1e`, a history answer says whether it was verified or is the last view (busy or unverifiable) | none (history view: #697 → `3d46d797`) | none |

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
| Stop, pause, resume, human takeover | Partial | Desktop: Stop desktop control, `control`, `stop control` and `revoke all` (#702 → `9af70ae3`), its own red look with a stop mark (#710 → `3faee4e9`); grant/revoke race fix #701 → `f5731130`; task stop: #640 (draft) | desktop self-tests, including the stop button's look and accessible name | The app only takes authority away. #701 closed a race where a grant waiting for Windows Hello could overwrite a revoke made meanwhile; a revoke's store lock waits at most 5 s and then fails closed; whether the Windows Hello prompt comes to the front when the app starts `revoke all` is unchecked; while the pointer is over it, Windows' default hover colour replaces the stop button's red | A task-scoped stop and pause/resume (slice 5) | Founder decision 2 for task stop; a person to check the Hello prompt |
| Crash recovery and state reconciliation | Done (qualified) | SG-000120 resume summary #464; mutation journal; #639 recovery and history; desktop `recovery` #720 → `c1e94a9f` | journal tests; #630 orceld killed during an Agent run; desktop self-tests and the Windows app job (`recovery` against a live orceld) | Effects orceld can't read back are recorded as unknown; the app looks at the newest ten tasks; no CI run shows the app a real interrupted report | none | none |
| Multi-client isolation | Partial | Remote leases and origin stamping (#667 → `26f17234`, #684); MC-01 #723 → `f544eb5c`; audit appends #724 → `e706ffd6`, bounds #725 → `d198f10e` and the start-up tail check #728 → `81976651`; cross-session task view #727 → `3c3b73ff`; report journal busy at start #730 → `67781427` | `fix395_tunnel_remote`, origin tests; `mc01_concurrent_clients` (three real orcelds, one sandbox, on Windows, macOS and Linux: per-session hello records, remote hello refused, remote requests isolated per session, report tasks actionable only by their own orceld); `concurrent_records_stay_whole_lines` | Other sessions' report tasks are listed read-only (`owner: other_session`) but drop out of the endpoint holder's list when their orceld exits, until the holder restarts, and have no title; approval tokens aren't bound to a session (they never leave orceld); an orceld started while another holds the report journal lock restores it before its next commit, and refuses that commit as busy (retryable) while it is still held; the audit log has no fsync or hash chain | More MC suites: concurrent approval-ledger appends (needs a person) | none |

## Desktop application and lifecycle

| Component | State | Evidence | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| Windows app (guided start, task timeline, recovery, approval history, preview setting, stop controls, workspaces, client setup, connected clients, accessibility, errors, Start Menu) | Partial | #622, #646, #660 → `46aa680c`, #663 → `1ff4fc14`, #664 → `7a73bac3`, #665 → `6d176867`, #697 → `3d46d797` (`history`), #699 → `b18c67ba` (`previews sizes`), #702 → `9af70ae3` (stop controls), #703 → `f73aeb68` (high contrast, live region), #704 → `56aae7c0` (`workspaces`, busy guard), #707 → `a35a9459` (`connect`), #708 → `eef75e1e` (history caveat when not verified), #710 → `3faee4e9` (stop button look), #711 → `92d8bbfe` (`connect` end to end), #713 → `b4b8cf02`, #714 → `f19746c8` and #715 → `ecb64614` (`clients`: connected local AI clients), #717 → `29e87831` (loopback HTTP clients listed too), #718 → `b278dea7` (`setup`: guided start), #720 → `c1e94a9f` (`recovery`) | self-tests; Windows app task timeline job (UI Automation against a real orceld; `connect` without an install and starting no process; the guided start at launch without an install; `recovery` against the live orceld) | #649 flaky window lookup; the app never grants anything (folders, desktop control, content previews), by design; CI's managed UI Automation client can't read `LiveSetting`; `clients` shows names each client reports about itself, unverified, and lists only local stdio and loopback HTTP sessions on an Orcel that says hello; the e2e check of `connect`'s setup text with an install runs only by hand (`-RuntimeRoot`) | A settings screen; checking the guided start's workspace and first-action steps (today it can't tell whether they were done); trying each `connect` snippet in its client by hand (today the settings are commands); a person checking Narrator or NVDA speech, high contrast hover and pressed states, 150% and 200% scaling and right-to-left text | Task stop needs decision 2; the UI toolkit (FD-03) is undecided |
| macOS and Linux app | Not started | — | — | — | — | Founder decision 4 |
| Windows install, start, update, rollback, uninstall | Partial | #654 → `e0e3fa41`, #659 → `93f33b25`, #661 → `e8fd1692`, #665 | release qualification on Windows CI | Unsigned; a real install under the new state root has run only in CI's release qualification | A founder-present install, upgrade and uninstall journey on a disposable machine (#655, uninstall missing stores, was closed by #659 and #661) | Signing (founder) for a release build |
| macOS package | Blocked | — | — | — | XP-16 packaging | FD-05, signing identity |
| Linux packages | Partial | Linux packages job | dev tarball journeys | — | — | none recorded |
| Release workflow separation | Blocked | #673 (draft) | — | — | Merge once the `release` environment exists | Founder creates the environment; no settings changed by agents |

## Product end to end

| Component | State | Evidence | Tests | Known limitations | Remaining work | Blockers |
|---|---|---|---|---|---|---|
| A real client drives a real approval to a verified report | Not started | Release qualification reaches the prompt with a test client | `release_qualification.rs` | No person has answered a real prompt in a journey | F4 slice 4 | Class 3: the founder at the prompt |
| AI model integration | Not started | Harness only (`model_eval.py`, `model_run.py`) | stub runs | No model has been run | Run a candidate | Founder decision 3 (download) |
| Passkey test environment | Not started | — | — | — | A disposable environment and protocol | Never the founder's personal desktop or accounts |

## CI reliability

| Item | State | Evidence | Remaining |
|---|---|---|---|
| Browser-host rehearsal flakes (#696) | Fixed, issue closed | #698 → `4e332520`: the two racing steps retry a fail-closed `InUse` for up to 10 s; 40 of 40 results passed across 10 main runs | none |
| Native host X11 latency scroll never shows its effect (#700) | Open, evidence only | Seen once on #699 | Print the fixture's scroll state and the host's outcome at the deadline if it recurs |
| Jev review needs the PR to contain current main | Known | its merge-base check | Update a PR to main before its review gate runs |
| Jev review runs `git diff --check` | Known | a CRLF file fails it (#692) | Write repository files with LF line endings |
| macOS jobs cancelled before a runner is assigned (#524) | Recurring | seen on #704, #705 and #707, and on main after #703 and #705 (both green on re-run), 2026-11-10 | Re-run the job; no code cause |
| `workspace list` held the CLI lifecycle lock | Fixed | #705 → `bb959446` | none |
| Windows browser download tests: fixture never contacted (#584) | Recurring | seen again on #708, 2026-11-10; a related read timeout (`a_page_is_extracted_as_untrusted_markdown_in_pieces_without_hidden_text`) on #717 and `a_staged_file_never_outlives_a_worker_that_dies_or_hangs` on #723, 2026-11-11, green on re-run | Re-run the job; cause still unknown |
| `orcel-approval` `recovery_refuses_missing_verified_or_busy_ledgers` could not take the writer lock with zero wait | Seen once | #725 on Ubuntu, 2026-11-12, green on re-run | Investigate if it recurs |
| Audit `concurrent_records_stay_whole_lines` saw a blank line | Fixed | introduced by #725 (each logger's first record read the log while another append was half done), seen on #727, 2026-11-12; fixed by #728 → `81976651` | none |
| Ubuntu runners could not resolve Ubuntu's package mirrors | Outage | #723, 2026-11-11 (four re-runs over about two hours) | Wait and re-run; no code cause |

## How to resume

1. Read this file and the restart checkpoint in `RELEASE_READINESS.md`.
2. Check GitHub for open PRs (`gh pr list --author @me`) and main CI.
3. Take the first row above whose state is not Done and whose Blockers column is "none".
