# Founder decision: Jev retired, D1 optional (2026-11-23)

Status: **DECIDED (founder), effective 2026-11-23.** Relayed to the engineering session by the coordinating session,
which confirmed it. The founder's words, as relayed, are the one sentence quoted here; everything else in this file is the
recording session's account and can be corrected by the founder.

> Jev is retired. D1 is optional. Real tests, independent review, and security enforcement remain mandatory.

## What changes

- Jev is no longer a mandatory review. The `jev-review` job ("Jev Semantic Review") and its adapter
  `.github/scripts/jev-exact-diff.mjs` are removed, not skipped or tolerated.
- Local D1 is an optional, advisory-only assistant. It can never authorize a merge or a privileged operation, clear a gate
  or count as a review.
- The retained process, for every change from now on:
  1. exact-head CI;
  2. the Rust and platform tests;
  3. Alibaba Open Code Review, with manual review of the files it excludes;
  4. independent code review;
  5. targeted security review for authority, permissions, filesystem boundaries, network or privilege;
  6. negative and adversarial regression tests;
  7. zero unresolved blocking findings;
  8. post-merge verification.

The normative form, with who reviews, who records it and where, is `docs/governance/DIFFCIPLINE.md` section 10.

**Independent code review is a process rule, not enforced by a GitHub check.** Whoever merges the pull request (today the
coordinating engineering session) records it on the pull request before merging; the closing pull request of a grain
carries it into `review_basis` in `.specgrain/canonical-evidence.json`.

## Affected gates

The ruleset "Deskal main protection" (24456712), read on 2026-11-23, requires ten checks:

| Required check | After this decision |
|---|---|
| Jev Semantic Review | To be removed from the ruleset by the coordinating session, AFTER this change merges |
| Alibaba OCR Delegation | Stays; the job and its fork refusal are unchanged |
| Governance | Stays; its diff check now also covers the pull request's range (below) |
| Supply chain audit | Stays |
| Rust / ubuntu-latest, Rust / windows-latest | Stay |
| Node / ubuntu-latest, Node / windows-latest | Stay |
| Release qualification / windows-latest | Stays |
| Relay container / ubuntu-latest | Stays |

This change edits no ruleset and no GitHub setting. The change itself still passes Jev, because `pull_request_target` runs
the base branch's workflow. Between its merge and the ruleset edit, no pull request can merge: the required check would
never report. That fails closed. The repository secret `TYPESAFE_API_KEY` is no longer read by any workflow; deleting it is
left to the founder.

## Implementation evidence

- `.github/workflows/review-gates.yml`: the Jev job is removed; the Alibaba OCR job is byte for byte the same, and
  `permissions: contents: read` stays because it uses it.
- `.github/workflows/ci.yml`, Governance: the Jev job was the only required check that ran `git diff --check` over a pull
  request's whole range (#692). That deterministic check moves into the Governance diff check, so it is not lost.
- `apps/orcel-mcp/src/review-process.test.ts`: the workflow holds the Alibaba job alone, with its fork refusal, no
  credential, no job-level condition and no tolerated failure; no open grain requires Jev; grains closed before the
  decision keep their Jev requirement and evidence.
- Checked and needing no change: the Governance step that validates `.specgrain` and the canonical evidence ledger never
  read a Jev field (it reads pull request, heads, CI runs and unresolved threads), and neither did any release sweep or
  closeout test, so old grains stay valid and a new grain needs no Jev evidence. `p20-architecture.test.ts` pins the Jev
  result in SG-000092's frozen activation record; that is history and stays. `release_blocker_sweep.rs` used the Jev
  artifact's name as a sample path only, now renamed. The line-length bound in `check-vendored-cua.mjs` came from Jev's
  slice size and stays as a readability bound.
- The nine open grains (SG-000096, SG-000097, SG-000127, SG-000128, SG-000131 to SG-000135) each carry an `amendments`
  entry and require `independent_code_review` and `adversarial_tests` in place of `jev_semantic_review`.
- Updated: Diffcipline, `CURRENT.md`, the planning index, the delivery plan, the P20 plan and donor ledger, the threat
  models, the source ledger and reuse matrix, the execution frontier, completion ledger, release readiness, the backlog's
  common gates, the unified specification, the contributor guide and the pull request template.

## History

Nothing already recorded changes: no past evidence, no closed grain, no canonical evidence entry. Jev's passes stay, and
so do its failures, among them:

- #831 at `2eac5d6a` (run 44534237836): the job failed at its exact-head step, before any review.
- #831 at `5905dc0e` (run 44536268283): `request_changes`, security / authorization, severity 2.49, confidence 0.49, on
  `prep/SG132_SLICE8.md`.
- #847 at `c80ef149` (run 45134778880): `request_changes`, security / injection, severity 2.57, confidence 0.56, on
  `prep/SG132_SLICE10.md`. #847's description says Jev blocked on it rightly, and the pull request was changed.

Packet and program documents written while Jev was required (the P18 program, the `docs/p20/SG000096_T0*` packets, the
SG-0000xx security notes, `P18_EXIT.md`, `P18_QUALIFICATION.md`, `RELEASE_SECURITY_REVIEW.md`, the activation drafts in
`prep/unified-grains/`, the SG-000119 packet, the XP-05 task) are left as they were. Where one of them still states a
requirement for work not yet done, this decision supersedes the Jev part of it.

## Outstanding risks

- **Less automated semantic review.** Jev read every hunk of every pull request and could block. On the day it was
  retired it had blocked #847 on a real weakness in standing approvals. Nothing automated replaces that.
- **Independent review is not enforced by GitHub.** The ruleset requires no approving review and does not require review
  threads to be resolved. A missing or careless review is visible only in the pull request's record.
- **D1 can be wrong in the dangerous direction.** D1-600M once called an authentication bypass low-risk. That is why it
  can never authorize anything.
- **Review gates on one account.** Authors, reviewers and the merging session act through one GitHub account, so the
  record says who reviewed but GitHub cannot verify it.
- **Alibaba Open Code Review runs in delegation mode.** The check proves the exact range and the rules, not a judgment;
  the judgment is the reviewer's.
