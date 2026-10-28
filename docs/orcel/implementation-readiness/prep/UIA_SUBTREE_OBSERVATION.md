# Preparation: scoped UIA subtree observation (#515)

**Status: PREPARATION ONLY.** This proposes a governed change to a closed
grain's shape. It adds no argument, shape, tool or bound, and changes no
spec state. Shipping it needs its own governed step (a successor spec or a
recorded amendment to SG-000063's shape), review, and exact-head CI.

## Evidence

On a hosted `windows-latest` runner (run 40784710382, BM-02 Tier C), orceld
observed an Electron window (cua-driver-bench cdb-s02, Signal Quay Chat)
with `uia.tree observe`:

```
11 nodes, deepest 8, truncated true, actionable ["Document:Signal Quay Chat@8"]
```

`orcel-provider-uia` caps a tree at `MAX_TREE_DEPTH = 8` and
`MAX_TREE_NODES = 256`. The window frame and panes use the first eight
levels, so Chromium's web `Document` arrives exactly at the cap and none of
its content (form fields, buttons, text) is ever observed. Every
Chromium- or Electron-rendered control is therefore unobservable and so
untargetable for `uia.element set_value` / `invoke`, although those shapes
already admit `Edit`, `Document`, `ComboBox` and `Button` controls.

## What binds the change

- **SG-000063 A1** (CLOSED): "Window listing and bounded tree observation
  are live on real Windows, bounded, redacted, and exclude protected
  surfaces and other sessions."
- **SG-000063**: structured desktop MCP exposure, including the tree
  observation tool. Any new argument also changes that tool's contract.
- **`UIA_WIDENING_FIELDS`** (`orcel-policy/src/sg000027.rs`): no
  caller-supplied PID, HWND, runtime id, selector, XPath or coordinate is
  accepted by any UIA shape. The proposal keeps that rule.

## Proposal

An optional root for `uia.tree observe`:

| Argument | Meaning |
|---|---|
| `root_element_id` | A server-allocated element id from a prior observation of the same window |
| `expected_tree_generation` | The tree generation that id belongs to (stale ids fail closed, as for actions) |

- The returned subtree is bounded **per call exactly as today**: depth 8
  below the root, 256 nodes, the response byte bound.
- The same redaction (passwords and secret-like values) and the same
  protected-surface and other-session exclusions apply.
- The root must be inside the same live window. A root whose window was
  re-created, or whose tree generation is stale, is refused
  `TARGET_STALE`.
- No new identifier kind: the caller can name only an element orceld
  itself allocated.

### Why not raise the caps

A larger global depth or node cap would make every observation larger,
including windows where the caller needs only the frame, and would widen
SG-000063 A1's bound for all callers. A scoped root keeps every response
within today's bound and makes deeper observation an explicit,
caller-requested step over an element already seen.

## Security review (preparation)

| Risk | Treatment |
|---|---|
| Unbounded traversal by repeated calls | Each call is bounded; repeated calls are already possible on any window. The registry's element and window caps still apply |
| Naming arbitrary UI by id | Only ids orceld allocated for this window and tree generation; foreign or stale ids fail closed |
| Reaching protected surfaces through a subtree | The same protected-surface exclusion runs on the subtree root's window; a protected window yields no root |
| Secret values in deeper controls | The same redaction: `IsPassword`, secret-like names, value bounds |
| MCP contract drift | The tool's contract, discovery, documentation and remote-scope tables change together (as SG-000063's agreement tests require) |

## Tests to write

- A subtree rooted at an Electron `Document` returns its form fields and
  buttons, within depth 8 and 256 nodes.
- A stale `expected_tree_generation`, a foreign window's element, and a
  malformed id are refused, and nothing is observed.
- A password field inside the subtree is redacted.
- A protected window cannot supply a root.
- The existing SG-000063 live tests pass unchanged.
- BM-02 Tier C C2b (`orcel-tasks/tierc/cdb-s02-blocker.plan.json`) reaches
  the blocker form through the subtree and its scripted plan completes.

## Decision needed

Whether to open the governed change at all, and in which grain (a
successor to SG-000063, or a recorded amendment). This is a governance step,
not an authority grant to an agent: observation stays read-only, and every
action keeps its fresh per-action approval.
