---
issue: https://github.com/TheHalfMoon/Orcel/issues/31
status: windows-path-guard-recovery
last_updated: "2026-10-09"
---

# Windows extension-contract declaration glob recovery

## Problem and scope

The compiler-stage profiling research for issue #31 encountered the same
Windows-local `guard:invariants` failure twice while assembling extension
capability reports. Rule 36 passed the TypeScript declaration build but
API Extractor then reported a missing `extension-contracts/entrypoints/extension.d.ts`
under its temporary declaration root.

The generated tsconfig's `include` uses a glob assembled with
`node:path.join(contractRoot, "entrypoints/**/*.ts")`. On Windows that
constructs a backslash-delimited pattern; a standalone TypeScript v7.0.2
probe with that absolute pattern emitted TS18003 (no inputs).
Converting the same glob path to slash-delimited form advanced the
probe past input discovery, though a separate missing `node` type-definition
setup problem prevented using that independent probe as the final guard test.

## Controlled end-to-end experiment

On the authorized Windows device in
`D:/Orcel-Issue31-DiscoveryWrite-20261009` with the normal pnpm v12.7.0
dependency tree, one **temporary, uncommitted** edit changed only the
extension-entrypoint include glob to:

```js
toPosix(join(contractRoot, "entrypoints/**/*.ts"))
```

`node scripts/guard-invariants.mjs` then reported:

```text
[orcel:guard:invariants] ok ? all mechanical lints passed.
WINDOWS_GLOB_FIX_GUARD_EXIT=0
```

The previously unmodified guard had failed on the same worktree on
two independent invocations with the missing
`extension-contracts/entrypoints/extension.d.ts` exception.

The exploratory change was reverted from that worktree after the
successful run, and this one-line fix was isolated onto a new branch
from canonical `main`. No invariant-baseline update, assertion removal,
capability epoch change, bypass, or product runtime behavior change
is part of this fix.

## Qualification limits

This one-host experiment supports the Windows path-normalization cause
for the declaration-discovery failure. It does **not** explain the
separate compiler manifest-stage wall time, prove a speedup, or provide
an Ubuntu benchmark. GitHub exact-head CI, including independent
Windows and Ubuntu jobs, remains authoritative before normal merge.
Issue #31 still requires compiler root-cause attribution and real
platform comparisons; issue #32 remains independent.
