# OB-05: evidence receipts on the audit chain

**Status: merged as #818 (028bca74) (SG-000135 work packet OB-05, acceptance FA-J). The independent security review of de1deb42 passed with findings; section 11 lists each and its fix. Unit tests only; no live browser run has been made with this code, and the founder-present run has not happened.**

Founder requirement J: measured performance, no fake completion, fully clear receipts. The grain's FA-J: measured latency and memory per session are recorded, and receipts state what completed, what is uncertain and what needs the person.

Before this packet, every `browser_full` action already had a receipt (OB-01), chained by digest within its session and, since WP1-03 (#813), copied into orceld's hash-chained audit log after the action. That receipt was provisional: it held ids, generations, an outcome word and one evidence digest. It said nothing of the origin, the target or the authority's epoch, and nothing was on the chain before the action was sent.

## 1. What happens

```
browser_full page action (open, snapshot, click, fill, select, verify, extract, screenshot, tabs)
  -> epoch checked, action budget counted (unchanged)
  -> INTENT written to orceld's audit chain (browser_intent)
       a chain that refuses it refuses the action: nothing is sent
  -> challenge check, takeover gate, approval or lease, dispatch (all unchanged)
  -> evidence files kept (snapshot frame, masked screenshot), content-addressed
  -> RECEIPT written to the chain (browser_receipt), naming its intent
       a chain that refuses it withholds the result: the outcome is unrecorded
  -> the reply carries the receipt; browser_task_status lists the session's receipts
```

- **Every page action has both records.** That includes refusals: a page waiting for the person (`HUMAN_VERIFICATION_REQUIRED`), a person using the window (`HUMAN_TAKEOVER`), a denied approval, an invalid lease and a stale node. The intent is written before the challenge check and the takeover gate, so a refused action has an intent and a refused receipt. Nothing was sent for it.
- **Session start and end are chained too** (`browser_session`, events `session_start` and `session_end`). The start names the mode, the profile and the task label's digest. The end names the reason, the number of actions recorded, the last receipt's digest, whether the worker was confirmed gone and the profile removed, and whether the session's evidence files were removed. The verifier checks the end against the session's intents and receipts, and refuses anything of the session after its end. The same source records evidence pruned for the store's bounds (`evidence_pruned`) and a deleted profile's evidence (`profile_evidence_removed`). These events are best effort: if the chain refuses them, the next intent is refused anyway.
- **Not receipted:** `browser_session_create`, `browser_close`, `browser_task_status` and the profile tools. They are not page actions, and the broker's session events cover create and close. `browser_structured` runs on the broker's structured worker but is not a broker session and has no receipts (section 10).

## 2. What a receipt holds

Contract `orcel.browser-receipt/1`. Digest domain `orcel-ob05-receipt/4`: SHA-256 of the domain, a newline and the canonical JSON (RFC 8785, `orcel_contracts::canonical_json_value`) of every field except `receipt_sha256`, `audit` and `provisional`. An absent field is `null`, so it never digests like a present one. The OB-01 length-prefixed scheme is retired. `scripts/browser-full-e2e.mjs` recomputes the new digest.

| Field | What it says |
|---|---|
| `seq`, `session_id`, `action` | The action, numbered per session. The intent and the receipt of one action share the seq. |
| `mode`, `profile` | Shadow or Visible; the persistent profile, or `null` for an ephemeral one. |
| `authority` | `kind` (`approval`, `lease` or `none`), the approval record id, the Full Access lease id, the authority service's epoch the lease was checked at (`lease_epoch`), and the approval epoch the action was checked against (`approval_epoch`). `record_id` and `lease_id` are also kept at the top level for older readers. |
| `page_id`, `generation_before`, `generation_after` | As before. |
| `origin_before`, `origin_after` | The page's origin: scheme, host and port. |
| `url_sha256` | The committed URL's SHA-256. The intent carries the requested URL's digest. Never the URL. |
| `target` | The page, and for a click, fill or select the node id, its role and the host's keyed name digest from the session's latest snapshot of that page. A tab switch or close names the tab's page id. Never a value or an option label. |
| `outcome` | The OB-01 word, kept: `done`, `denied`, `refused`, `not_dispatched`, `failed` or `unknown`. |
| `result` | `sent`, `refused`, `failed`, `superseded` or `unknown` (section 3). |
| `effect` | `applied`, `none` or `unknown`: whether the action took effect. |
| `needs_person` | True for a page that waits for the person, a person using the window, a superseded action, and an unknown outcome only a person can reconcile. |
| `failure_code` | The refusal's contract code. |
| `pre_evidence` | The snapshot the action was planned on: page, generation and frame digest. |
| `evidence_kind`, `evidence_sha256` | The post-action evidence digest, as before (reply, observe, verify, screenshot). |
| `evidence_files` | Each evidence file: kind, scope (the session id, or `p-<profile>`), SHA-256, size, whether it was stored, and if not, why (`too_large`, `quota`, `no_store`, `conflict` or `write_failed`). |
| `intent_sha256`, `intent_audit` | The intent's digest and its place in the chain (log, file id, seq, event digest). Covered by the receipt's digest. |
| `intent_at_ms`, `at_ms`, `duration_ms` | When the intent and the receipt were written, and the time between them. |
| `previous_sha256`, `receipt_sha256` | The session's receipt chain, as before. |
| `audit`, `recorded` | The receipt's own place in the chain (or the error), and whether the chain took it. Not covered by the digest, because they are known only after the write. A receipt the chain refused is listed with `recorded: false` and does not move the session's head. |
| `provisional` | Now `false`. |

The intent (`orcel.browser-intent/1`, domain `orcel-ob05-intent/1`) holds the seq, session, action, mode, profile, page, generation, origin, requested URL digest, target, approval epoch, its time and the session's receipt chain head when it was written.

## 3. Outcomes

| Broker outcome | Failure code | Result | Effect | Needs person |
|---|---|---|---|---|
| done, no input during the flight | | sent | applied | no |
| done, a person's input during the flight | | superseded | applied | yes |
| denied or refused | `HUMAN_TAKEOVER`, `HUMAN_VERIFICATION_REQUIRED` | refused | none | yes |
| denied or refused | any other | refused | none | no |
| failed (the host refused before acting) | `HUMAN_TAKEOVER` (the late check after the approval was spent) | refused | none | yes |
| failed | any other | failed | none | no |
| not_dispatched | | failed | none | no |
| unknown (lost reply, timeout, unconfirmed) | | unknown | unknown | yes |

**Superseded** is decided after the frame came back. It applies when the action can change the page and the takeover gate holds the page (`HUMAN_OVERRIDE` or `QUIET`). The gate drains a person's input when the write ends (OB-06 `after_write`), so a hold there means the input came while the action was in flight.

## 4. Write before dispatch, and a crash between

- **Before:** the intent is appended and flushed before the challenge check, the approval and the frame. If the append fails, the action is refused (`INTERNAL_ERROR`, "the audit chain refused the intent ... so nothing was sent"). The request-level dispatch record of WP1-03 (`audit_before_dispatch`) is still written before that, unchanged.
- **After:** the receipt is appended once the outcome is known. If that append fails, the result is withheld (`INTERNAL_ERROR`), and the message says the outcome is unrecorded (`DISPATCHED_UNRECORDED`). The session's head stays at the last receipt on the chain, and `browser_task_status` lists the refused receipt with `recorded: false`, so the verifier reads the action as unrecorded (10), not as broken (9).
- **A crash between them** leaves an intent with no receipt. The verifier lists it under `dispatched_unrecorded`, with its session, seq, action and time. That action may have run. The B1 idempotency guard and the SG-000120 journal still keep an uncertain consequential write from being repeated, unchanged.
- The seq is taken by the intent. An intent with no receipt leaves a gap, and the next intent names the session's receipt chain head, so a missing receipt cannot be hidden by renumbering.

## 5. Evidence files

- **What is kept:** two kinds of file.
  - The snapshot frame, the exact bytes whose digest is the snapshot receipt's `evidence_sha256`. It holds node ids, roles, the host's keyed name and value digests, the redaction flags and the bounded untrusted names of form controls. It holds no field values.
  - The masked PNG screenshot, the image the reply carried, with secret fields painted over before capture.
- **Where:** `<browser state>/browser-profile/live/broker/evidence/<scope>/<sha256>.json|png`. The scope is the session id for an ephemeral session and `p-<profile>` for a persistent profile. The folder is created by `orcel_platform::paths::ensure_private_dir`: a protected owner-only DACL on Windows, 0700 on Unix. A file is written to a temporary name and renamed, and it is never followed through a link. Writing the same content again stores it once; a different file at the name is never adopted (`conflict`).
- **Lifetime (privacy).** A masked screenshot still shows the page's other content, and a snapshot frame holds the untrusted names of form controls. So evidence lives no longer than its owner:
  - an ephemeral session's folder (every Shadow or Visible session without a persistent profile) is removed when the session ends, by any path: close, the end of the MCP session, an emergency stop, a lost host;
  - if orceld exits or crashes before its sessions end, the next broker removes that instance's session folders when it opens the store. It does this only for `bs-<instance>-...` scopes with a well-formed session id whose instance lock is free, never through a link and never a profile's scope, and it records the removal on the chain (`evidence_swept`);
  - a persistent profile's folder is removed when the profile is deleted (`browser_profile_delete`), and the chain records it (`profile_evidence_removed`).

  The receipts keep their digests on the chain either way. The verifier reports a file whose scope was removed as `removed`, not `missing`.
- **Bounds:** at most 512 MiB and 4096 files in the store, and 4 MiB per file. Past the store's bounds, the oldest files are pruned first, and each prune is named on the chain (`evidence_pruned`), so the verifier reports the file `pruned`, not `missing`. A file larger than a bound is never stored (`too_large`); a file that could not be written says why.
- **The quota is shared.** There is no per-scope share. A busy session can therefore prune older evidence of other sessions and profiles. Each such prune is on the chain and reported `pruned`, and the receipts keep their digests.
- **Not kept:** reply bodies, extracted page text, verify reports, URLs and typed values. For those, the receipt keeps a digest at most, and never a digest of a typed value.
- **Post-action evidence for writes** is the digest of the reply (committed URL, status and generation). No snapshot is taken after a write on the agent's behalf. An automatic snapshot would count as the fresh observation that ends OB-06's re-observe hold.

## 6. Redaction

| Value | In the chain and the receipt |
|---|---|
| URL, query, fragment, path | SHA-256 only (spec 4.8). The origin is kept in clear. |
| Typed value, option label | Absent: no value or digest of one. |
| Field names | The host's keyed name digest (keyed per lifetime) and the role. The untrusted names appear only in the snapshot evidence file, which the agent was already shown. |
| Cookies, credentials, secret fields | Never read by the receipt path. Screenshots are masked before capture. |
| Task label | SHA-256 only, in the session start event. |

The test `ob05_no_secret_reaches_the_chain_or_the_receipt` writes an action on a URL carrying a token and a fragment, with a typed secret in the reply and a cookie in the profile. It checks that none of them, nor `/reset` or `token=`, appears in the chain file or the receipt.

## 7. The verifier

`orceld audit-verify [--chain <path>] [--receipts] [--receipt <sha256>] [--evidence <dir>]`

- Without the new flags it is unchanged.
- **`--receipts`** adds a `receipts` section to the report. For every intent and receipt in the chain file, it checks:
  - the digest recomputes from the fields, and a receipt's `result`, `effect` and `needs_person` follow from its `outcome` and `failure_code` (section 3);
  - each receipt follows an intent with the same session, seq and action, and names that intent's digest and its chain place (seq and event digest); a receipt that names no place fails;
  - each session's intents are numbered without repeat, in order, and without a gap once the session's start is in the file; its intents and receipts follow its receipt chain;
  - a session's end names its last receipt and its count of actions, and nothing of the session follows its end;
  - every stored evidence file hashes to its name (`intact`, `missing`, `mismatch`, `unreadable`, `malformed`), except one the chain records as `pruned` or whose scope it records as `removed`.

  Intents with no receipt are listed as `dispatched_unrecorded`. Receipts written before OB-05 (no contract, the old digest) are counted as `legacy_receipts` and covered by the chain's own digests only; inside a session that has OB-05 records, such a receipt fails.
- **`--receipt <sha256>`** reports whether that receipt is in the file, whether it recomputes, what its links and evidence files check as, and its event seq and digest. It also says how far the authority service's held anchor covers it (`anchoring`):
  - `anchored`: at or below the last event the held anchor covers (the chain report's `last_verified_anchor_seq`);
  - `unanchored_tail`: after it. Anchors come every 32 events, so up to 31 events are protected by the chain's digests only;
  - `unanchored`: the service holds no anchor of this chain. Without the installed authority service there are no anchors at all.
- **`--evidence <dir>`** names the evidence folder. The default is orceld's own, when it exists; the verifier never creates it. Without a folder the files are reported `not_checked`, never as verified.
- **Exit codes**, in this order:
  - the chain's own code when it is broken or missing (4 or 5): nothing in it can be trusted;
  - 9 (`EXIT_RECEIPTS_BROKEN`) when a receipt, intent or evidence file does not verify, or `--receipt` named one that is not there. This applies also over a chain whose verdict is a torn tail, recovered, truncated or reset by the owner (3, 6, 7, 8);
  - the chain's own code when it is otherwise not intact;
  - 10 (`EXIT_RECEIPTS_UNRECORDED`) when the chain is intact and every receipt verifies, but some intent has no receipt.
- **What a writer of the state folder can still do.** The chain's digests can be recomputed by anyone who can write orceld's state folder. Only the authority service's held anchor fixes a prefix of the chain.
  - Events after the last held anchor (up to 31), and every event when the service is not installed, can be rewritten or appended consistently.
  - A forged receipt appended after its session's end is found (nothing of a session may follow its end), and so is any append that breaks a session's numbering, links or result words.
  - A forged receipt that closes an unrecorded intent inside the unanchored tail of a session that has not ended, with every digest recomputed, is not found.
  - `--receipt` therefore states the receipt's anchoring.

## 8. Contract and replies

- Every page action's reply carries `receipt` in the new shape. The OB-01 fields are kept with their meaning, except that `provisional` is now `false`. New fields are only added. The receipt digest changed scheme, so a reader that recomputed the OB-01 digest must use the new one. The only such reader in the repository was `scripts/browser-full-e2e.mjs`, which is updated.
- `browser_task_status` adds `receipt_contract` and `measured`:
  - `actions_recorded`;
  - the total and the largest intent-to-receipt latency in milliseconds;
  - on Windows, `worker_peak_memory_bytes`: the peak committed memory of the session's browser job (host, worker runtime and engine), read with `QueryInformationJobObject`.
- A refused action's error message ends with the receipt's `result`, where it ended with the outcome word before.
- No failure code, tool or MCP schema was added. Two descriptions changed, the `browser_open` and `browser_task_status` tool texts. The tool contract's output bounds say "evidence receipt", and `docs/p16/TOOL_CONTRACT.md` follows them.
- orcel-agent reads no receipt field and needs no change.

## 9. Tests

- **`browser_receipts.rs`:**
  - the outcome table of section 3;
  - URLs as digests only;
  - targets from a snapshot frame;
  - the digest covers every field but its own;
  - the evidence store is content-addressed, refuses to adopt a tampered file, reports mismatched, missing and malformed files, and keeps digests only past its bounds or without a folder.
- **`browser_broker.rs`:**
  - `ob05_every_action_family_is_receipted_on_the_chain_and_verifies`:
    - snapshot, open, click under a lease, fill, select, tabs, verify, extract, screenshot, and a click refused for a challenge;
    - an intent and a receipt per action, both chain places, authority kinds and epochs, the target role and name digest, pre-evidence from the snapshot, and evidence files;
    - session start and end events;
    - the chain verifies intact, and the receipt verifier passes with 2 evidence files checked;
    - one receipt's inclusion found by digest, and an absent one reported broken.
  - `ob05_no_secret_reaches_the_chain_or_the_receipt`: section 6.
  - `ob05_tampered_receipts_and_evidence_files_are_detected`: an edited and a removed evidence file, an edited receipt field, and a removed intent.
  - `ob05_intent_before_dispatch_and_a_crash_between_is_detected`:
    - an intent with no receipt is `DISPATCHED_UNRECORDED`, with CLI exit code 10;
    - a broken chain refuses the next intent ("nothing was sent") and marks a receipt failed;
    - a broker without a chain says so.
  - `ob05_outcomes_map_to_what_completed_what_is_uncertain_and_who_is_needed`: sent, superseded, refused before the send for `HUMAN_TAKEOVER`, the late takeover refusal, denied, failed and unknown, and the status's `measured`.
- **The OB-01 receipt tests** run on the new digest, including `an_absent_receipt_field_never_digests_like_a_present_one`.
- **The live path** (`live_dispatch.rs`, Windows `live-browser-dev`) is compiled and linted with `live-browser-dev` and `live-browser-test`. It is not run here: that needs Edge and the scripted-consent harness.

## 10. Not done, and limits

- **No live run.** `scripts/browser-full-e2e.mjs` recomputes the new receipt digest, but it has not been run against this code. The founder-present run has not happened.
- **`browser_structured` through the broker** (the move OB-04 deferred here) is done on `browser/structured-via-broker` (`OB04_MODES_PROFILES.md`, section 5). The structured browser is now the broker's structured worker and ends with its sessions, but it is not a broker session and gets no receipts. An intent written before dispatch would add a refusal when the chain refuses it. A receipt outside a session is one the verifier and `scripts/browser-full-e2e.mjs` do not check. Structured actions keep their SG-000120 journal and the request-level dispatch record.
- **SH-2** (toggling Shadow mid-mission without repeating a submit) was not done in this packet. It merged as #842 (03c638e5) ([`SH2_MODE_SWITCH.md`](SH2_MODE_SWITCH.md)): a session with an unsettled action cannot switch, and the new session's `session_start` names the old session and its last receipt, which the verifier checks.
- **One chain file.** The verifier reads the file it is given. After `orceld audit-move-aside` or a rotation, older receipts are in the moved file, and an intent in the old file whose receipt landed in the new one shows as unrecorded there.
- **Digests can be guessed for guessable values.** A URL digest confirms a guess of the exact URL, such as a public page. Spec 4.8 accepts that for the chain, which is local and in protected state. Origins are in clear.
- **Post-action evidence for writes** is the reply digest, not a page capture (section 5).
- **Unanchored tail.** Receipts after the last held anchor, and every receipt without the installed authority service, rest on digests a writer of the state folder could recompute (section 7).
- **Evidence retention.** Evidence is removed with its ephemeral session (or, after a crash, by the next broker's sweep) or with its profile, and pruned oldest first past 512 MiB or 4096 files. The quota is shared, so one busy session can prune other scopes' older files (each prune chained). A file removed by hand from the folder is `missing` to the verifier. While a persistent profile lives, its evidence stays (bounded by the store).
- **Memory** is the job's peak committed memory on Windows only, read when `browser_task_status` runs. There is no per-action memory figure and no figure on other systems.
- **The session start and end events are best effort** (section 1).
- **Legacy receipts** in a chain from before this packet are counted, not recomputed.
- **Review.** OB-05 is not on the grain's list of packets that need a fresh-context security judge, but it changes what the audit chain holds, so an independent review of the redaction is advised. d1-local is advisory only.

## 11. After the security review of de1deb42

The independent review passed, with these findings, each fixed:

1. **M1, verifier limits.**
   - `--receipt` now states whether the receipt is anchored, in the unanchored tail, or unanchored (section 7).
   - A session's end is checked against its intents and receipts, and nothing of a session may follow its end, so a forged receipt appended after the end to close an unrecorded intent is found.
   - The unanchored tail, the append-forgery case and the absence of anchors without the authority service are documented (sections 7 and 10).
2. **M2, evidence retention and privacy.**
   - Evidence is kept per scope and removed with its ephemeral session or its profile.
   - The store has a 512 MiB quota with oldest-first pruning, and each prune is named on the chain.
   - An unstored file says why, and the verifier reports `pruned` and `removed` apart from `missing` (section 5).
3. **L1, a refused receipt.** It no longer moves the session's head. It is listed with `recorded: false`, and its intent reads as unrecorded (10).
4. **L2, exit codes.** A broken receipt answers 9 also over a chain whose verdict is a torn tail, recovered, truncated or reset; a broken or missing chain keeps its own code (section 7).
5. **L3, the verifier's checks.** It now checks:
   - duplicate intents;
   - order and gaps;
   - the result words recomputed from the outcome;
   - a receipt with no intent place;
   - a contract-less receipt inside an OB-05 session.
6. **L4, node ids.** A node id is bounded at parse as the MCP schema bounds it: 1 to 64 letters, digits, `_` or `-`.
7. **L5, the refused-receipt message.** It now states the result and effect without claiming the action ran.

The tests for these are `ob05_forged_appends_that_break_a_sessions_structure_are_found`, `ob05_a_refused_receipt_leaves_the_head_and_reads_unrecorded`, `ob05_pruned_and_profile_evidence_is_reported_not_missing`, `ob05_the_evidence_store_prunes_the_oldest_and_removes_a_scope`, `ob05_node_ids_are_bounded_like_the_schema`, and the anchoring and removal checks added to `ob05_every_action_family_is_receipted_on_the_chain_and_verifies`.

After the re-review of eb1cda90 (fixes confirmed, two blockers):

1. **B1, the harness digest.** `scripts/browser-full-e2e.mjs` now leaves `recorded` out of the receipt digest, like the Rust digest. It also requires every mission receipt to be on the chain, so a receipt with `recorded: false` never moves its head. The test `ob05_the_e2e_harness_leaves_out_the_same_receipt_fields` keeps the two lists and the digest domain equal.
2. **B2, a crashed orceld's evidence.** The next broker sweeps the evidence of a dead instance's ephemeral sessions and chains `evidence_swept`. The verifier reads those scopes as `removed`. The test is `ob05_a_dead_instances_session_evidence_is_swept`.
3. **Recommended, the shared quota.** Documented in section 5, not changed.
