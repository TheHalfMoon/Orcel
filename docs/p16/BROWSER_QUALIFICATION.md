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
| `browser.dom/fill` | model-only | not exposed |
| `browser.download/preview` | live (SG-000108) | `browser_download_preview`, under `browser_structured` only |
| `browser.download/download` | live (SG-000108) | `browser_download`, under `browser_structured` only |
| `browser.upload/preview` | model-only | not exposed |
| `browser.upload/submit` | model-only | not exposed |

SG-000062 found that no shape qualified against a live engine, so no browser tool was exposed then; SG-000108 later qualified the six live shapes below.
Exposing these shapes would let an AI client believe it browsed a page when
it only exercised policy bookkeeping.

SG-000108 slice 3c (docs/security/SG-000108_PRODUCT_CALLER.md) makes six shapes live MCP tools on the qualified
isolated engine, under the `browser_structured` profile only, which local configuration alone selects. They reach a
real browser only in `live-browser-dev` builds; every other build answers typed unavailable. `browser.dom/fill` and
the uploads stay model-only, and the model-only forms of the live shapes are unreachable through the MCP edge.

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
