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

Required (founder decision effective 2026-11-23, `docs/governance/2026-11-23-jev-retirement.md`):
1. exact-head CI: automated format/lint/type/test, the Rust and platform tests, Governance;
2. SpecGrain acceptance check;
3. Diffcipline exact-diff check;
4. Alibaba Open Code Review, with a manual review of the files it excludes;
5. independent code review of the exact head;
6. targeted security review for a change to authority, permissions, filesystem boundaries, network or privilege;
7. negative and adversarial regression tests for every changed boundary;
8. zero unresolved blocking findings;
9. targeted human/founder approval for a governance-sensitive merge;
10. post-merge verification.

Automated reviewers do not replace security reasoning.

**Independent code review is a process rule. No GitHub check enforces it**: the ruleset requires no approving review,
authors and reviewers act through one GitHub account, and a merge without the review would not be blocked.

- Who reviews: a person, or a fresh-context session, that did not write the change. An author's own review and D1's
  output do not count. The security review of item 6 may be the same review when it covers the changed boundary
  explicitly.
- Who records it: whoever merges the pull request, before merging (today the coordinating engineering session).
- Where: on the pull request, in its description or a comment, with the reviewer, the statement that they did not write
  the change, the exact head SHA, the files covered (the files Open Code Review excluded among them), every finding and
  how each was resolved. At grain closeout the closing pull request carries it into `review_basis` in
  `.specgrain/canonical-evidence.json`.
- When the head moves, the delta is reviewed and recorded too. Without the record the change is not qualified.

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
