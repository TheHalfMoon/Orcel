# Implementation readiness package (cross-platform revision, 2026-10-18)

Status: ADOPTED planning package (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. It grants no authority, imports no donor code and changes no runtime behavior. Start at [OPUS_HANDOFF.md](OPUS_HANDOFF.md).

## One authoritative document per question

| Question | Document |
|---|---|
| Where do I start, in what order, what must not change? | [OPUS_HANDOFF.md](OPUS_HANDOFF.md) |
| What is true about the current code? | [ARCHITECTURE_AUDIT.md](ARCHITECTURE_AUDIT.md) |
| Which decisions are adopted, kept, proposed, or waiting for the founder? | [ARCHITECTURE_DECISIONS.md](ARCHITECTURE_DECISIONS.md) |
| How does each OS work (adapters, protocol /2, capability matrix, packaging)? | [CROSS_PLATFORM_ARCHITECTURE.md](CROSS_PLATFORM_ARCHITECTURE.md) |
| What exactly do we take from Cua? | [CUA_INTEGRATION.md](CUA_INTEGRATION.md) |
| Browser: who owns what; Browser Use, Playwright tools, Stagehand, Skyvern, WebMCP | [BROWSER_INTEGRATION.md](BROWSER_INTEGRATION.md) |
| Scrape, crawl, map, extract, research (Firecrawl, crawl4ai, Agent-Reach) | [WEB_INTELLIGENCE_INTEGRATION.md](WEB_INTELLIGENCE_INTEGRATION.md) |
| Runtime, journal, app API, Control Room, macOS helper (Agent-Native) | [AGENT_RUNTIME_INTEGRATION.md](AGENT_RUNTIME_INTEGRATION.md) |
| Sandboxes and multi-device boundary (SPACE, cua-vmm, Lume) | [SECURE_EXECUTION_INTEGRATION.md](SECURE_EXECUTION_INTEGRATION.md) |
| Threat-model delta and release-blocking security tests | [SECURITY_INTEGRATION.md](SECURITY_INTEGRATION.md) |
| Benchmarks, conformance, report format | [BENCHMARK_AND_E2E.md](BENCHMARK_AND_E2E.md) |
| Tracks, phases, release sequence, critical path | [ROADMAP.md](ROADMAP.md) |
| Every donor: pin, license, strategy, status | [DONOR_REGISTRY.md](DONOR_REGISTRY.md) (data: [donor_registry.json](donor_registry.json)) |
| Every donor file → Orcel destination, with git object SHAs | [SOURCE_TRANSPLANT_MATRIX.md](SOURCE_TRANSPLANT_MATRIX.md) (data: [transplant_matrix.json](transplant_matrix.json)) |
| Every task card | [IMPLEMENTATION_BACKLOG.md](IMPLEMENTATION_BACKLOG.md) (data: [backlog/tasks.json](backlog/tasks.json)) |
| What the second-pass review challenged and changed | [ADVERSARIAL_REVIEW.md](ADVERSARIAL_REVIEW.md) |

The three generated Markdown tables are rendered from the JSON by `tools/render_tables.py`; edit the JSON and re-render.

## Checks

```bash
python -I docs/orcel/implementation-readiness/tools/readiness_check.py
```

```bash
python -I docs/orcel/implementation-readiness/tools/render_tables.py --check
```

With local donor checkouts named `owner_repo` (for example `trycua_cua`) under one directory, add `--donors <dir> --verbose` to verify every donor path and print its git object SHA at the pin.

## Relation to the adopted plan

The adopted Sol revision (`docs/orcel/ORCEL_MASTER_PLAN.md`, `ARCHITECTURE.md`, `IMPLEMENTATION_ROADMAP.md`) stays the baseline. This package changes it only where ARCHITECTURE_DECISIONS.md section 2 says so, chiefly by withdrawing the macOS/Linux deferral (founder directive of 2026-10-18). Canonical grain state stays in `.specgrain/` and `docs/canonical/`.

## Evidence labels used

VERIFIED SOURCE FACT (read in source at a pinned commit), SOURCE-DOCUMENTED (a donor's own written claim, not Orcel evidence), TESTED RESULT (a check actually run; in this package only the planning checks above and GitHub API reads), ENGINEERING INFERENCE, ESTIMATE, UNPROVEN ASSUMPTION, OPEN DECISION. No donor or Orcel code was built or executed to produce this package.
