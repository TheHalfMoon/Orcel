# Orcel Diffcipline

Status: ACTIVE PLANNING RULE
Date: 2026-09-23

Diffcipline is Orcel's exact-diff execution discipline. Its purpose is to prevent useful work from becoming unauditable work.

## 1. Core rule

Every implementation unit must be reviewable as one bounded claim.

A PR must answer:
- what exact behavior is being added or changed;
- what authority changes;
- what files changed;
- what tests prove the claim;
- what remains explicitly unproven.

## 2. Exact-live start

Before authoring:
1. fetch canonical main;
2. record exact main SHA;
3. record clean/dirty worktree state when working locally;
4. inspect open PRs that may overlap;
5. confirm the active SpecGrain packet;
6. create a forward-only branch from the exact base.

Do not rely on a handoff SHA without re-verification.

## 3. Scope budget

Default target per implementation packet:
- one capability or one coherent cross-cutting contract;
- <= 12 changed files unless justified;
- <= 600 net added lines unless generated code/tests make a documented exception;
- no unrelated formatting;
- no drive-by dependency upgrades;
- no donor import outside the packet's provenance scope.

The bounds are reviewability defaults, not incentives to hide necessary tests.

## 4. File discipline

Every changed file must map to:
- implementation;
- test;
- contract/schema;
- evidence/governance;
- required dependency metadata.

If a file has no mapping, remove it from the PR or explain it.

## 5. Authority delta

Every PR must explicitly state whether it changes:
- file authority;
- process authority;
- network authority;
- browser authority;
- UI/input authority;
- secret authority;
- approval authority;
- privilege/elevation authority.

Security review is mandatory when any authority expands.

## 6. Dependency discipline

A new dependency requires:
- purpose;
- version/pin;
- license;
- maintenance signal;
- network behavior;
- privilege implications;
- safer alternative considered.

Lockfile changes must correspond exactly to declared dependency changes.

## 7. Donor provenance

For copied/adapted source:
- donor repository;
- exact commit;
- donor path;
- destination path;
- license;
- attribution requirement;
- copied/adapted/concept-only classification;
- local modifications.

No undocumented copy-paste.

## 8. Test discipline

Tests must include:
- happy path;
- denial path;
- malformed input;
- stale/race path when relevant;
- security regression for expanded authority.

Windows-specific claims require Windows-native evidence.

## 9. Exact-head qualification

Before merge:
- record PR head SHA;
- run required CI against that exact head;
- record run IDs;
- verify no new commit appeared after qualification;
- inspect changed-file list and diff stat;
- inspect unresolved review threads;
- obtain the independent code review of that exact head (section 10).

If head moves, qualification resets.

## 10. Review stack

The eight items the founder decision effective 2026-11-23 retains (`docs/governance/2026-11-23-jev-retirement.md`):
1. exact-head CI;
2. Rust and platform tests;
3. Alibaba Open Code Review;
4. independent code review;
5. targeted security review for authority, permissions, filesystem boundaries, network or privilege;
6. negative and adversarial regression tests;
7. zero unresolved blocking findings;
8. post-merge verification.

Rules that were here before that decision and stay, as applicable:
- automated format/lint/type/test and Governance, within exact-head CI;
- SpecGrain acceptance check;
- Diffcipline exact-diff check;
- manual review of the files Alibaba Open Code Review excludes, and delegation mode (founder decision, 2026-10-10);
- targeted human/founder approval for a governance-sensitive merge.

Automated reviewers do not replace security reasoning.

**Independent code review is a process rule. No GitHub check enforces it**, and authors, reviewers and the merging session
act through one GitHub account, so GitHub could not tell one from another.

- Who reviews: a person, or a fresh-context session, that did not write the change. An author's own review and D1's
  output do not count.
- The independent code review and the targeted security review are two separate reviews, each with its own record.
- Who records them: whoever merges the pull request, before merging (today the coordinating engineering session).
- Where: on the pull request, in its description or a comment, with the reviewer, the statement that they did not write
  the change, the exact head SHA, the files covered (the files Open Code Review excluded among them), every finding and
  how each was resolved. At grain closeout the closing pull request carries it into `review_basis` in
  `.specgrain/canonical-evidence.json`.
- When the head moves, the delta is reviewed and recorded too. Without the record the change is not qualified.

**What the ruleset enforces** ("Deskal main protection", read 2026-11-23): a pull request; its required status checks, on a
branch up to date with main; no deletion and no force-push of main; no bypass. `required_approving_review_count` is 0.
`require_extra_approval_for_unattributed_changes` is true; what it does for this repository's pull requests is not verified.
The required status checks carry no `integration_id`, so any check or commit status with one of those names counts,
whoever posts it: an actor with push access could post one without running the job.

**What nothing in the ruleset enforces**, so it holds only if people and sessions do it and record it:
- the independent code review, and its record;
- the targeted security review, and its record;
- the negative and adversarial regression tests (CI runs the tests that exist; it cannot say one is missing);
- the judgment behind Alibaba Open Code Review: the check proves the exact range and the rules, not that anyone applied them;
- the manual review of the files Open Code Review excludes;
- zero unresolved blocking findings, and resolved review threads (`required_review_thread_resolution` is false);
- the SpecGrain acceptance check, the Diffcipline exact-diff check and the recorded authority delta;
- founder approval for a governance-sensitive merge;
- post-merge verification, and the evidence in a closeout (Governance checks its form, not its truth);
- the platform jobs that are not required checks: every macOS job, the native host, the contained tier, the approval
  helper, the Control Room client and shell, the document parser, Orcel Agent, the licence gates, the Linux and macOS
  packages, the web job, BM-02 Tier C GUI, the authority service artifact and install E2E jobs, the document parser fuzz and the Windows task timeline;
- that a required check was posted by its own workflow (above);
- signed and signed-off commits, and normal merge commits (the ruleset also allows squash and rebase);
- that D1 authorizes nothing.

**D1 is optional and advisory.** A local D1 run may help to sort work. It can never authorize a merge, clear a gate,
stand in for a review above, or authorize a privileged operation.

**Jev is retired** as a mandatory review. Its past results, passes and failures, stay in the record as they were; a grain
closed under it keeps its evidence, and a new grain needs none.

## 11. Merge discipline

Never merge:
- a disqualified head;
- a PR with unresolved blocking findings;
- a PR whose authority delta is undocumented;
- a PR whose Windows-only claim lacks Windows evidence;
- a PR that silently widens workspace/network/approval authority.

Use expected-head SHA when the merge mechanism supports it.

## 12. Post-merge evidence

After merge:
- record merge SHA;
- verify canonical main contains the intended tree;
- run/observe post-merge CI when configured;
- close or advance the SpecGrain packet only after effectiveness evidence exists.

Merged is not automatically equivalent to proven.

## 13. Failure behavior

If a gate cannot be run:
- say UNPROVEN;
- preserve evidence;
- do not invent success;
- do not compensate by widening scope.

If a security test exposes an architectural flaw:
- stop that authority expansion;
- repair the design before proceeding.

## 14. Planning PR rule

Planning-only PRs:
- do not claim implementation;
- do not advance runtime completion state;
- may define future authority but do not grant it;
- must identify any unresolved architectural question.

## 15. Canonical completion

A task is COMPLETE_CANONICAL only when:
- implementation merged;
- acceptance criteria proven;
- required platform evidence green;
- post-merge state verified;
- no blocking review finding remains;
- governance state reflects the result.
