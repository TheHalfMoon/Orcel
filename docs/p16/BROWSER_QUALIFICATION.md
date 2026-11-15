# Structured Browser Exposure Qualification (SG-000062)

Status: CANONICAL DECISION FOR ORCEL-P16

## Question

SG-000021 through SG-000026 closed a structured browser layer: isolated
profile, origin-bound destinations, page lifecycle and navigation, DOM
snapshot, click and fill actuation, scoped downloads, and scoped uploads.
Before any of it becomes an MCP tool, each shape must be qualified against a
live browser engine. An MCP tool must not claim browser capability that the
implementation does not have.

## Evidence

- `crates/orcel-provider-browser` and `crates/orceld/src/browser.rs` launch no
  browser process, attach to none, and open no DevTools, debugger, WebSocket,
  or socket channel. The only process launches in the crate are test helpers
  that create junctions.
- Pages are records in a Orcel page registry. Navigation validates and
  records the destination; it does not load the page in an engine.
- `build_snapshot` documents and implements "deterministic structural
  metadata bound to the page generation and document generation, never live
  browser content": the nodes come from a fixed template.
- Click and fill bind typed node identities from those snapshots and record
  generation changes; they do not actuate a rendered page.
- Downloads and uploads move bytes the caller supplies under strict
  workspace rules; no page transfer occurs.

## Per-shape decision

| Shape | Engine | Decision |
| --- | --- | --- |
| `browser.profile/status` | model-only | not exposed |
| `browser.destination/validate` | model-only (policy) | not exposed |
| `browser.page/open` | live (SG-000108) | `browser_page_open`, under `browser_structured` only |
| `browser.navigation/preview` | model-only | not exposed |
| `browser.navigation/navigate` | live (SG-000108) | `browser_navigate`, under `browser_structured` only |
| `browser.snapshot/observe` | live (SG-000108) | `browser_observe`, under `browser_structured` only |
| `browser.dom/click` | live (SG-000108) | `browser_click`, under `browser_structured` only |
| `browser.dom/fill` | live (SG-000122) | `browser_fill`, under `browser_structured` only |
| `browser.download/preview` | live (SG-000108) | `browser_download_preview`, under `browser_structured` only |
| `browser.download/download` | live (SG-000108) | `browser_download`, under `browser_structured` only |
| `browser.upload/preview` | model-only | not exposed |
| `browser.upload/submit` | model-only | not exposed |

SG-000122 admits five shapes beside the twelve (its amendment of SG-000108 A13). They have no model-only form: on
the model-only path every `browser.form`, `browser.wait` and `browser.verify` shape stays denied.

| Shape | Engine | Decision |
| --- | --- | --- |
| `browser.wait/text` | live (SG-000122) | `browser_wait_text`, under `browser_structured` only |
| `browser.verify/check` | live (SG-000122) | `browser_verify`, under `browser_structured` only |
| `browser.form/select` | live (SG-000122) | `browser_select`, under `browser_structured` only |
| `browser.form/check` | live (SG-000122) | `browser_check`, under `browser_structured` only |
| `browser.form/enter` | live (SG-000122) | `browser_enter`, under `browser_structured` only |

SG-000062 found that no shape qualified against a live engine, so no browser tool was exposed then. SG-000108 later
qualified the isolated engine and made six of the twelve shapes live (the first table above); SG-000122 makes six more
live on the same engine: `browser.dom/fill` from the twelve and the five shapes of the second table. The shapes still
marked model-only stay unexposed: exposing one would let an AI client believe it browsed a page when it only exercised
policy bookkeeping.

SG-000108 slice 3c (docs/security/SG-000108_PRODUCT_CALLER.md) makes six shapes live MCP tools on the qualified
isolated engine, under the `browser_structured` profile only, which local configuration alone selects. They reach a
real browser only in `live-browser-dev` builds; every other build answers typed unavailable. The uploads stay
model-only, and the model-only forms of the live shapes are unreachable through the MCP edge.

SG-000122 slice A3 (`.specgrain/specs/SG-000122.json`, issue #753) adds three live MCP tools under the same profile
and rules, on Windows `live-browser-dev` builds only (release builds, macOS and Linux answer typed unavailable), never
remote:
- `browser_fill` fills one observed single-line text field (an input of type text, search, email, url or tel; never
  a secret-looking field) after a fresh SOFT approval bound to the page generation, the field and the value. The
  prompt shows the value exactly and in full, or the value is refused; it shows the field's role and name labelled
  page-supplied.
- `browser_wait_text` waits up to 8 s for a literal one-line text to appear or disappear, and `browser_verify` checks
  element, text, value, checked-state and URL postconditions. Both are read-only and need no approval; their text
  probes look only at the main frame's committed document, and each lifetime admits at most 16 distinct awaited
  texts across them.

SG-000122 slice A4 adds the last three under the same profile and rules, each after its own fresh SOFT approval bound
to the page generation, the control and the stated option, state or key, used once:
- `browser_select` chooses exactly one option of one observed native select, named by its exact label; the prompt
  shows the label exactly and in full, or the label is refused.
- `browser_check` sets one observed checkbox or radio input to a stated state (checked or unchecked).
- `browser_enter` presses Enter, and only Enter (it takes no key), in one observed single-line text field as
  `browser_fill` defines it. Its prompt says that the page may submit or send what it holds; the lifetime's one
  admitted site is the only place it can go. Since slice A6 that is enforced by the Enter route rule: the page may
  open one new top-level document, a GET or POST on its own origin, once, with redirects that stay on it. The reply
  says `navigation: document_committed` with the page's new generation (observe again before acting), or
  `navigation: none` when the page stayed on its document (check what it did with `browser_verify`). A submission
  that would leave the origin, by its form's action, a redirect or a page script, is refused before it leaves and
  answers `CAPABILITY_DENIED`; the page must then be navigated again. Fill, select and check still open no document.

Each prompt shows the control's role and name labelled page-supplied. A radio can only be selected: `checked: false`
on a radio is refused before any approval (the host's live check, and orceld's prompt builder again); to clear a
radio, select another in its group. A checkbox may be set either way. Every SG-000122 schema, A3's three and A4's three, is strict: an unknown field (a key
for Enter, a list of options for select, a selector or frame) is refused, never dropped.

The native Windows run (slice A6) is part of `npm run browser-launcher:native`, which Windows CI requires: on the
loopback HTTPS fixture, orceld drives the worker-mode host through observe, fill, select, check, an Enter that submits
to the page's own origin, a text wait and the verifier, under the real broker and ledger with a **scripted** consent,
and a stale generation and a cross-origin form are refused; a host-level test covers the GET, a field outside any form,
and the redirect and script exits. A person answering the real prompt through a real MCP client is the founder-present
run in `docs/orcel/implementation-readiness/prep/SG-000122.md`, which is pending.

## What remains true

- The policy controls stay canonical and tested (origin binding, SSRF and
  redirect-widening denial, personal-profile denial, scoped transfers) and
  are the specification a future live engine must satisfy.
- Arbitrary JavaScript, generic DevTools or CDP access, debugger
  attachment, personal-profile use, and hidden network primitives remain
  intentionally denied.
- Live structured browser automation is recorded in the parity inventory as
  missing and outside the v0.2 target. It is not part of Desktop Commander's
  feature set, so it does not affect the Desktop Commander replacement goal.
  A future grain must bring a live, isolated engine and qualify every shape
  against it before exposure.

`apps/orcel-mcp/src/browser-qualification.test.ts` pins this decision: no
MCP tool is browser-named, the browser layer launches and attaches nothing,
and every shape above is recorded as not exposed.
