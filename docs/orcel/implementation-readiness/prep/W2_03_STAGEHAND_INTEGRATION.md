# W2-03: Stagehand browser intelligence in the Orcel browser worker

Packet W2-03 of the transplant ledger
(`docs/orcel/implementation-readiness/prep/TRANSPLANT_LEDGER.json`, source
`stagehand`). It brings Stagehand's hybrid accessibility and DOM snapshot,
and the deterministic parts of its act, observe and extract services, into
`apps/orcel-browser-worker`.

- Donor: browserbase/stagehand at `82827a219512f0399cb159720a63f7d271d21480`
  (MIT License, Copyright (c) 2024 Browserbase Inc.). Read-only clone:
  `D:\Orcel-REA-W2\stagehand`.
- Authorization: OWNER-ASSERTED AUTHORIZATION, founder 2026-11-17 (copy
  first; the licence does not block; notices and provenance are kept).
- Notice: `docs/orcel/notices/stagehand-MIT.txt` (the upstream LICENSE
  verbatim, with the list of adapted files). It is also listed in
  `scripts/third-party-notices.mjs`, so release notices carry it.
- Provenance: `docs/orcel/stagehand_provenance.json`, with a staged entry in
  the WP1-01 central manifest format (`donor-provenance.json` on
  `origin/wp1/licence-gates`), ready to merge when that manifest lands.

## 1. What Orcel already had

The worker already had most of the browser control that Stagehand provides.
This packet does not duplicate it.

| Capability | Orcel before W2-03 | Stagehand | Decision |
| --- | --- | --- | --- |
| Accessibility snapshot with element references | `src/snapshot.ts`: Playwright `ariaSnapshotJSON({ mode: "ai" })`, refs `e12` / `f1e3`, value-free, 512 nodes, depth 16, 56 KiB | `capture.ts` + `a11yTree.ts`: CDP `Accessibility.getFullAXTree` + `DOM.getDocument`, encoded ids `frame-backendId`, text outline, XPath and URL maps | Kept the existing snapshot as the observation and action surface. Added the Stagehand outline as a separate, richer read-only view (DOM tags, input types, scrollable regions, XPaths), denied by default |
| Form-control names that may reach callers | `src/actions/names.ts` (SG-000122 slice A5): deny-by-default checks in Playwright's isolated world | Forwards every name, plus the field `value` | The outline applies its own deny-by-default rule (`withholdNames`, section 3) and never forwards a value |
| Element targeting | `src/actions/targets.ts` (BR-01): snapshot ref, or the single element with the approved role and exact name | XPath selectors from the snapshot's id-to-XPath map | `outline/targets.ts` only resolves an outline id to XPath, role and name. Actions stay on the existing frames |
| Acting | `activate`, `form_action` (fill, select, check, press, hover, Enter), `upload`, `download`: per-action host approval (SG-000122) | `actService.ts`: Playwright-style methods on an XPath, LLM planning, self-heal | Not copied. A second way to act would be a second browser control path |
| Postcondition checks | `src/verify.ts` (BR-07) | none | Kept as is |
| Page content extraction | `src/extract/` (slice 6): Markdown from a CDP `DOMSnapshot`, chunked | `extractService.ts`: LLM fills a JSON schema from the outline | Added `outline/schema-extract.ts`: deterministic schema matching on the outline, with no model |
| Declarative tools | `src/webmcp/` (slice 4) | none | Kept as is |
| Action cache | none | `cacheService.ts`: Browserbase server-side cache | Not copied (cloud) |

## 2. Module map

| Stagehand source (at the pin) | Orcel file | Kind |
| --- | --- | --- |
| `understudy/a11y/snapshot/xpathUtils.ts`, `utils.ts` (`trimTrailingTextNode`) | `src/outline/xpath.ts` | Copied pure helpers; page-script helpers dropped |
| `understudy/a11y/snapshot/domTree.ts` | `src/outline/dom-tree.ts` | Copied; deadline instead of `Progress`; node bound |
| `understudy/a11y/snapshot/a11yTree.ts` | `src/outline/a11y-tree.ts` | Copied; no values; name withholding added |
| `understudy/a11y/snapshot/treeFormatUtils.ts` | `src/outline/tree-format.ts` | Copied; `untrustedText` sanitiser added |
| `understudy/a11y/snapshot/capture.ts` | `src/outline/capture.ts` | Adapted: main document only, read-only CDP allowlist, bounded wire nodes |
| `services/extractService.ts` | `src/outline/schema-extract.ts` | Deterministic half kept; inference replaced by exact matching |
| `services/actService.ts`, `services/observeService.ts` | `src/outline/targets.ts` | Id-to-XPath resolution only |
| `understudy/a11y/snapshot/domTree.test.ts` | `src/outline/dom-tree.test.ts` | Ported from vitest to `node:test` |
| `services/cacheService.ts` | none | Not copied: Browserbase cloud cache |
| `focusSelectors.ts`, `coordinateResolver.ts`, `activeElement.ts` | none | Not copied: these run code in the page |
| `llm/`, `inference.ts`, `prompt.ts`, `services/llmService.ts` | none | Not copied: model calls never run in the worker |

Every copied file starts with a provenance header: repository, commit, path,
blob, licence, the notice and provenance file paths, and the changes made
for Orcel.

## 3. How it is wired

### Protocol (worker generation 18)

Two host frames and four worker frames were added to the closed vocabulary.
`WORKER_PROTOCOL_GENERATION` is 18 on both sides
(`src/protocol.ts`, `crates/orcel-browser-host/src/worker_launch.rs`).

- `{"frame":"outline","out_id":N}` returns
  `{"frame":"outlined","out_id":N,"url":...,"truncated":...,"nodes":[...]}`
  or `outline_failed`. A node is `{id, role, name, xpath, url?, children}`:
  `id` is `0-<backend node id>`, `xpath` uses element names and positions
  only, `name` is cleaned page text or empty, and `url` is present only for
  an absolute http(s) link without credentials.
- `{"frame":"extract_schema","xs_id":N,"fields":[...]}` returns
  `schema_extracted` (one value per field, in order) or
  `schema_extraction_failed`. A field is
  `{key, take: "text"|"texts"|"url", role, name?}` or
  `{key, take, xpath}`: exactly one target, up to 32 fields, closed keys.

Both frames are refused while a navigation runs, and they fail when the page
URL exceeds the frame bound or the document changes during the capture.

### Worker

`entry.ts` opens one CDP session on the primary page and wraps it in
`readOnlyCdp`. The wrapper rejects every method except `DOM.enable`,
`DOM.getDocument`, `DOM.describeNode`, `Accessibility.enable` and
`Accessibility.getFullAXTree`. Nothing runs page script: there is no
`Runtime.*`, no `Input.*`, and nothing that changes the page. The capture
runs inside `captureWithin`, with a 4 s budget plus 1 s.

Bounds:

- at most 512 nodes, depth 32, and 56 KiB of node JSON;
- names of at most 512 bytes, XPaths of at most 1024 bytes;
- a DOM index of at most 50,000 nodes;
- schema lists of at most 32 items, and text of at most 2 KiB.

Any page string passes through `untrustedText` before it crosses. That
function repairs lone surrogates and strips C0 and C1 controls,
bidirectional overrides and isolates, and zero-width and format characters.
It also folds line breaks into spaces and cuts on a character boundary.

Names are withheld (`withholdNames`) for:

- every form control or editable node;
- every node inside one, and every node that holds one;
- every node whose name comes from another element (`relatedElement`, which
  covers aria-labelledby, a label, a legend or a caption);
- every non-text node whose name source the engine does not report.

No field value, description, or checked or selected state is ever sent. A
schema extraction reads only this withheld outline, so it can never return
a value.

### Host (the authority)

`crates/orcel-browser-host/src/worker_outline.rs` holds the policy gate.
`admit(WorkerCapability::Outline | SchemaExtract)` returns an error naming
the pending amendment, and `admitted()` is a `const fn` that returns
`false`. `BrowserWorker::outline` and `BrowserWorker::extract_schema` call
the gate before anything is sent, so the host never sends either frame
today. Once a grain admits a capability, the host does three things:

1. It validates the schema (`validate_schema`).
2. It re-checks every reply bound (`check_outline`, `check_values`).
3. It refuses a stale document, and keeps the result as host-internal page
   text (`Outline`, `SchemaExtraction`) bound to the document generation.

The off-Windows fallback calls the same gate first.

### Models

The worker never calls a model, and nothing in `src/outline/` imports a
network module. A test enforces this. A language-model step (Stagehand's
`inference.observe` / `act` / `extract`) is optional and belongs to orceld,
with the user's own key. For example, orceld may run a model over a
host-redacted outline and map the element id it returns to a role and name
with `resolveOutlineTarget`. The host then asks for the usual per-action
approval on the existing frames. This is a design note: none of it is wired.

## 4. Grain amendments needed

Both capabilities are denied by default until these amendments land:

- **SG-000076** (live DOM and accessibility observation) for the outline.
  The outline is a second observation surface. The amendment must decide
  which outline names a caller may see, and how the host redacts, digests
  and identifies outline nodes. The SG-000076 pipeline currently runs on
  `observe` only.
- **SG-000133** (web intelligence: scrape, search and extract) for
  `extract_schema`. This is a browser-backed, schema-driven extraction on a
  live admitted page, with no model.
- **SG-000122** (form actions), only if an outline node is ever to be an
  action target. That would extend BR-01 targeting from snapshot refs and
  exact role/name to outline ids or XPaths. It is not requested here.

## 5. Tests (2026-11-17)

- Stagehand's own vitest suites: **NOT RUN**. The donor clone has no
  `node_modules` and is read-only, and its suites import Stagehand's Page,
  Progress and CDP stack, which needs the whole pnpm workspace installed. The
  applicable tests were ported to `node:test` instead.
- Worker (`node --test`, named files, all non-native suites plus
  `scripts/dev-pin.test.mjs`): **237 passed, 0 failed**. This includes the
  new `outline/dom-tree.test.js` (10 tests, 4 of them ported from Stagehand),
  `outline/outline.test.js` (12), 3 new protocol tests and 3 new worker
  tests. The native Edge suites (`native.test.js`,
  `extract/extract.native.test.js`) were not run: they launch Edge, and
  Edge 157 is unqualified on this machine.
- Host (`cargo test -p orcel-browser-host --lib`): **239 passed, 0 failed,
  38 ignored**, including
  `worker_outline::tests` (4) and
  `worker_launch::tests::w2_03_outline_and_schema_frames_match_the_typescript_vocabulary`.
  The native tests stay ignored, as before. `cargo clippy -p
  orcel-browser-host --all-targets -- -D warnings` (1.98.1 clippy) is clean;
  rustfmt was checked on the changed files.

## 6. Gaps

- The outline covers the main document only. Stagehand stitches child frames
  and out-of-process iframes (`computeFramePrefixes`, `injectSubtrees` over
  per-frame sessions); here an iframe is a leaf.
- There is no live-engine evidence yet. The outline was tested against a
  fake CDP session only. Chrome's exact `name.sources` and `editable`
  reporting should be measured on a qualified Edge before an amendment
  admits the outline. If Edge omits `sources`, the outline withholds most
  names, which fails safe but makes it less useful.
- The host does not yet redact, digest or issue identities for outline nodes
  (SG-000076 work), and no caller surface (orceld, MCP) exposes either
  capability.
- No local action cache (the Stagehand cache is cloud-only). Replaying a
  remembered action would need its own grain.
- `scripts/check-donor-provenance.mjs` (WP1-01) is not on main yet. The
  staged manifest entry must be merged into `donor-provenance.json` when
  WP1-01 lands.
