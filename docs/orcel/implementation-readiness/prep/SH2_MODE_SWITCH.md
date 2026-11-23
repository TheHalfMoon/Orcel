# SH-2: switching a task between Shadow and Visible

**Status: merged as #842 (03c638e5) (SG-000135 acceptance SH-2, listed under OB-04 and OB-05). Unit tests only; no live browser run has been made with this code. UNVERIFIED (founder run): toggling a real mission with a person at the PC.**

Founder requirement (Shadow test 2): "Toggle checkbox mid-mission: agent transitions to isolated session without duplicating a prior submit and preserves state." The Shadow Mode specification also lists "Return to Shadow" among a mission's one-click controls, so the switch works both ways. The master decision adds: "Never auto-repeat an uncertain form submission, purchase or publication."

OB-04 fixed a session's mode for its life, because the engine is launched headless or headed. A switch therefore never changes a running engine. It moves the task to a new session.

## 1. Choices

Each choice is engineering's, made conservatively where the specifications leave it open. None is a founder quote.

1. **A switch is a new session.** `browser_session_create {continue_from, mode}` names an open session of the same MCP session and the other mode. It takes the old session's profile and task label, so it may name neither. It is not a new tool: the broker tool list, the remote-safe list and the OAuth matrix are unchanged.
2. **Nothing non-idempotent is replayed.** Only the recorded committed URL of each tab is reopened, as an ordinary GET navigation. No click, fill, select, submit, Enter or download is repeated. Unsubmitted field values are not carried. A page that a form POST produced is reopened with GET, which never resends the form body.
3. **URLs that look secret-bearing, and links that look single-use, are not carried.** The test is a heuristic (a secret-looking name, or token-like text); what it misses is in section 5.
   - **No tab is carried once the old session showed a sign-in page.** After a sign-in, any URL may hold what the person typed (a GET sign-in form) or be a one-time link.
   - **A tab whose path has a token-like segment is not carried** (`agent_url::token_like_path`, the sanitizer's own `token_like` rule: a run of 16 or more token characters, or a segment longer than 64). It may be a single-use link (a reset, verification or magic sign-in link), so it is not reopened. A long slug is dropped too; that is the conservative cost. A shorter segment (a six-digit code, for example) is not recognised.
   - **Otherwise the URL is carried exactly** when the agent could already read all of it (`agent_url` changes nothing) and no query or fragment value is token-like by the same rule (`agent_url::no_token_values`). If either fails, only its scheme, host and path are carried (`agent_url::bare`): no query, fragment or userinfo.
   - **A tab that is not an `https` page** (a blank tab, for example) is not carried.
   - Every dropped tab is counted in `tabs_not_carried`. A switch carries nothing the agent could not read itself.
4. **An uncertain action blocks the switch.** If any action of the session has an unknown effect, or a receipt the audit chain refused, the switch is refused with `OUTCOME_UNKNOWN`. The count is kept until the session ends, so such a session cannot switch later either: the person or the agent checks the effect on the site, and the session is closed. The B1 idempotency guard and the page store that keep an uncertain write from being repeated live in the old session's folders, and a new session would not have them.
5. **A person using the window blocks the switch.** A Visible window held by the takeover gate (OB-06) is refused with `HUMAN_TAKEOVER`, as `browser_close` is.
6. **A page that waits for the person may move only to Visible.** Moving a Shadow session's sign-in, code or CAPTCHA page into a Visible window is the OB-07 handoff. Moving a waiting page into Shadow, where nobody can complete it, is refused with `HUMAN_VERIFICATION_REQUIRED`.
7. **Moving to Visible asks the owner first.** The owner gets a fresh SOFT approval, titled `move an Orcel browser session to a visible window`, before the old session ends. It replaces OB-04's Visible-window approval for this path and says the same about the window, the foreground, the clipboard and file dialogs. Its target is `orcel-browser-session:<old id>`. Its digest binds the workspace, the client and the switch plan: the old session, its last receipt, the target mode, the profile, the task and each carried URL's digest and kind. Moving to Shadow asks nothing extra, as a Shadow create does.
8. **Each reopened page asks.** Each reopened page asks its own SOFT approval, as `browser_open` and `browser_tabs new` do. The new session's lease cache is held while a page is reopened (`FullAccess::hold`), so a lease the owner grants to the new session meanwhile never covers a reopen. The first refusal stops the rest. The new session stays open, and the reply lists what was and was not reopened.
9. **A Full Access lease is not carried.** A lease names one session id (`BrowserLease.session_id`), so the old session's lease never covers the new one. The old session's end also ends its lease (`FullAccess::session_ended`), as any session end does. The owner grants the new session anew with `orcel browser grant`. The specification says Shadow "changes the execution location, not the permissions". Carrying the lease would still be a silent widening, because the owner granted a session, not a task, and the new session in Visible mode is a different execution location. The conservative option was taken.
10. **The persistent profile moves with the task.** The old session releases the profile when its worker is confirmed gone, and the new session acquires it. Its cookies and site storage carry over in the profile's data folder. A profile approval this MCP session already holds is reused; one that was forgotten (after a revoke) is asked again. An ephemeral profile's cookies end with the old session, as OB-01 requires: the switch never copies a profile folder.
11. **Every check runs before anything changes.** The checks, the approvals and a fresh epoch check all come before the old session ends. The plan is computed again right before the end, and a session that changed meanwhile (an action, a person's input, a page that now waits) is refused with `TARGET_STALE`. If the new session then cannot open (for example, the old worker was not confirmed gone and the profile stays quarantined), the reply says the old session ended and nothing was carried.
12. **Remote callers switch under the same rules as a remote Visible create.** The shape is `browser.session/create` (`orcel.execute`), which a remote `browser_full` caller already reaches. Its approvals go to the owner's Windows dialog, marked remote. A remote client can name only its own sessions, which are always ephemeral. A plan whose caller differs from the session's caller is refused, and a remote session holding a persistent profile is refused again in the switch check.

## 2. What happens

```
browser_session_create {continue_from: <old>, mode: <other mode>}
  -> epoch checked; plan_switch: the old session is the caller's, the mode differs,
     no uncertain action, no person in the window, no waiting page if moving to Shadow
  -> the plan: profile, task, each tab's carried URL (exact or path only), background tabs first
  -> profile approval if this MCP session lost it; for Visible, the switch approval (plan digest)
  -> epoch checked again; end_for_switch: the plan again (TARGET_STALE if changed), then the
     old session ends with reason mode_switch (worker gone, ephemeral profile and evidence removed,
     lease ended, session_end chained)
  -> the profile acquired again (persistent only); the new session starts in the other mode,
     its session_start naming continued_from {session_id, mode, last_receipt_sha256, carried, dropped, plan_sha256}
  -> each carried tab reopened: the first in the session's page (browser_open), each later one
     in a new tab (browser_tabs new), the active tab last; each its own intent, approval and receipt
  -> the epoch checked once more, as after any action: a revoke during the last reopen ends the new session
     now, and restore_stopped says so
  -> reply: the new session, continued_from with the old session's end report, carried pages
     (sanitized URL, new page id, receipt seq, restored), tabs_not_carried, restore_stopped
```

Code: `crates/orceld/src/browser_mode_switch.rs` (checks, carry rule, plan digest), `Broker::plan_switch` and `Broker::end_for_switch` in `browser_broker.rs`, the `switch` path in `live_dispatch.rs`, the `SessionWorker::switch_state` read of the live browser's own records (tabs, sign-in, takeover hold and Needs-you), and the verifier's link check in `browser_receipts.rs`.

## 3. Receipts link the two sessions

- The old session's `session_end` event says `reason: mode_switch`, with its action count and last receipt, as OB-05 records every end.
- The new session's `session_start` event carries `continued_from`: the old session's id, mode and last receipt digest, the number of tabs carried and not carried, and the plan digest. It holds no URL.
- `orceld audit-verify --receipts` checks the link when the old session is in the same chain file. It must have started, ended with `mode_switch`, in the other mode, with the named last receipt, and no other session may continue it. A link that fails any of these is a broken receipt (exit 9). A `continued_from` naming a session that is not in this chain file (after a move-aside or rotation, or a forged name) is **unverifiable**: the verifier does not check it and does not report it as verified. It reports neither a pass nor a failure for that link, as OB-05's one-file limit says.
- The reopened pages are ordinary `browser_open` and `browser_tabs` receipts of the new session. Their URLs are digests only, as for every receipt.
- The receipt contract and digest are unchanged (`orcel.browser-receipt/1`, `orcel-ob05-receipt/4`), so `scripts/browser-full-e2e.mjs` needs no digest change.

## 4. Threat model

| Threat | Control | Test |
|---|---|---|
| A submit, fill or click is repeated in the new session | Only GET navigations to recorded committed URLs are made; no other action is replayed, and a new session starts with no actions | `sh2_a_task_moves_both_ways_and_the_receipts_link_the_sessions` (no action used in the new session) |
| An uncertain write is repeated without its guard | A session with an unknown effect or an unrecorded receipt cannot switch (`OUTCOME_UNKNOWN`) | `sh2_a_refused_switch_changes_nothing`, `sh2_a_switch_is_refused_before_anything_changes` |
| A token, code or typed password in a URL is sent again | No tab after a sign-in; exact carry only when `agent_url` changes nothing and no value is token-like; otherwise scheme, host and path. A heuristic: a short token under an ordinary name is missed (section 5) | `sh2_secret_bearing_urls_are_never_carried`, `sh2_tabs_are_carried_background_first_and_active_last` |
| A single-use link (a token in the path) is reopened | A tab with a token-like path segment (a run of 16 or more token characters, or more than 64) is dropped and counted in `tabs_not_carried`; a shorter one is missed, and its reopen asks the owner (section 5) | `sh2_secret_bearing_urls_are_never_carried` |
| A lease granted mid-switch covers a reopened page | The new session's lease is held while each page is reopened; every reopen asks | `sh2_a_held_lease_covers_nothing_so_reopened_pages_always_ask` |
| A revoke lands during the last reopen | The epoch is checked again at the end of the switch; a moved or unverifiable epoch ends every session, and the reply says so | `sh2_a_revoke_during_the_last_reopen_ends_the_new_session` |
| A URL reaches the audit chain | The start event holds counts and digests only | `sh2_a_task_moves_both_ways_and_the_receipts_link_the_sessions` (no URL text in the chain) |
| A window appears on the desktop without the owner's say | Switching to Visible asks a fresh SOFT approval bound to the plan before anything ends | `sh2_the_plan_digest_binds_every_choice`; the prompt path is in `live_dispatch.rs` (live build only) |
| The task is pulled out from under a person | A held window refuses (`HUMAN_TAKEOVER`); a waiting page never moves into Shadow | `sh2_a_refused_switch_changes_nothing`, `sh2_a_switch_is_refused_before_anything_changes` |
| A Full Access lease silently covers the new session | A lease names one session id; the old session's end ends its lease | `sh2_a_full_access_lease_is_not_carried_to_the_new_session` |
| The session changes between the approval and the end | The plan is recomputed and must be equal (`TARGET_STALE`) | `sh2_a_refused_switch_changes_nothing` |
| Another client or caller moves a session | Broker ownership; the caller must equal the session's caller | `sh2_a_refused_switch_changes_nothing`, `sh2_a_switch_is_refused_before_anything_changes` |
| A remote caller reaches a signed-in profile | Remote sessions are ephemeral; a remote plan on a persistent profile is refused | `sh2_a_switch_is_refused_before_anything_changes` |
| A forged link claims continuity | The verifier checks the old session's end reason, mode, last receipt and single successor | `sh2_a_task_moves_both_ways_and_the_receipts_link_the_sessions` (two forged starts found) |
| A persistent profile is opened while the old engine may still run | The profile is released only after the worker is confirmed gone; otherwise it stays quarantined and the switch reports that nothing was carried | `sh2_a_persistent_profile_moves_with_the_task`; quarantine itself: `ob04_a_profile_whose_worker_is_not_confirmed_gone_stays_locked` |
| A malformed request names a path or page as the session | Parse and MCP schema accept only a broker session id, with `mode`, and refuse `task` and `profile` beside it | `sh2_continue_from_names_a_session_and_a_mode_only`; `browser-full.test.ts` "SH-2: continue_from is a broker session id" |

Local behaviour without `continue_from` is unchanged: the OB-04, OB-05 and OB-09 tests pass as before, and a `session_start` without a switch has no `continued_from` field.

## 5. Residuals

- **Unsubmitted field values are lost.** A half-filled form is reopened empty. Re-filling it is the agent's choice, under the new session's approvals.
- **An ephemeral session's cookies end with it.** A switch on an ephemeral profile lands signed out. Use a persistent profile to keep a sign-in across a switch (local callers only).
- **A GET can still have an effect.** A site that changes state on a GET would see the reopened page as a new visit. Each reopened page asks the owner, who sees its URL. The token test is a heuristic: queries whose names look secret or whose values are token-like, and paths with a token-like segment, are not carried, but a token or code shorter than 16 characters under an ordinary name (`?v=483920`), a short single-use path (`/verify/483920`) or a short state-changing path (`/cart/add/7`) would still be reopened if the owner approves it.
- **One MCP timeout for the whole switch.** The call waits at most 10 minutes (`APPROVAL_TIMEOUT_MS` in `browser_full.ts`) for everything: the profile and window approvals, the old session's end and one approval per reopened page (at most 8 tabs). If the client times out first, orceld is not stopped: it goes on with the approvals it still asks, the old session may already have ended, and the reply that names the new session is lost, so the agent may not know the new session's id. Nothing non-idempotent is repeated, the receipts on the chain still link the two sessions, and the new session ends with the MCP session. An agent should keep few tabs open before it switches.
- **The prompts add up.** A move to Visible asks once for the window and once per reopened page; a move to Shadow asks once per reopened page. Reopens always ask, even under a lease (choice 8); a lease granted to the new session covers only its later routine actions.
- **After a sign-in nothing is reopened.** The new session starts with no page; the agent opens what it needs under the new session's approvals.
- **Window activation.** A Visible window may come to the front as it opens and as each page opens (OB-04 section 2a); the switch approval says so.
- **Only recorded tabs.** A popup the worker adopted after the last tab read, or a page Orcel never committed, is not carried. Tab ids change; the reply maps each old page id to its new one.
- **The old session's evidence files** are removed with it when its profile is ephemeral (OB-05). Its receipts keep their digests on the chain.
- **The link is checked within one chain file** (section 3). A link to a session outside the file is unverifiable, not verified.

## 6. Not proven here

- **No live run.** The switch path in `live_dispatch.rs` is compiled with `live-browser-dev` and linted. It needs Edge and the scripted-consent harness to run; `scripts/browser-full-e2e.mjs` has no SH-2 phase yet.
- **UNVERIFIED (founder run):** toggling a real mission with a person at the PC, Shadow to Visible and back, with a submitted form that must not be submitted again, and the approvals answered by the person.
- **Review:** the change touches authority (approvals, profile handoff, remote callers), so a fresh-context security judge is advised before merge. d1-local is advisory only and never clears a gate.
