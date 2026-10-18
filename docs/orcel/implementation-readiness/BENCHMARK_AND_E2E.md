# Benchmark and E2E plan (cross-platform)

Status: PROPOSED (Fable, 2026-10-18). Extends `docs/orcel/BENCHMARK_AND_E2E_PLAN.md` (adopted minimum native evidence). No result in this file is measured; every target is an ESTIMATE to be replaced by data.

## 1. Rules

- Claims of speed, accuracy or superiority require a report produced by the harness below, at an exact Orcel commit, with the same planner and workload for every compared system.
- Upstream donor results (Cua's matrix, browser-use benchmarks) are SOURCE-DOCUMENTED context, never Orcel evidence.
- A model's summary of success is not evidence; oracles are fixture state, file hashes, DOM state probed by the host, or external checkers.

## 2. Suites

### 2.1 Native conformance (XP-08)

Fixture apps copied from Cua (`tests/native-fixtures`, MIT): shared web harness in Electron and Tauri hosts, AppKit, SwiftUI, WKWebView, GTK3, GTK4, WPF, WinUI3. Dimensions per cell (from Cua `docs/test-matrix.md`): OS, window system, harness, targeting (`ax`/`px`), delivery (`background`/`foreground`), scope, oracle, status, observed behavior (`delivered`, `refused`, `no_effect`, `error`, `not_run`). A refusal counts only when the exact refusal code and the no-focus/no-z-order/no-input-leak oracles pass.

Runners: Linux Xvfb + Openbox and headless Sway on GitHub-hosted Ubuntu; macOS on a founder-provided self-hosted runner with Accessibility and Screen Recording granted (FD-05); Windows on `windows-latest` interactive session for observation and the existing native suites for input.

### 2.2 Native metrics

| Id | Metric | Method | Target (ESTIMATE) |
|---|---|---|---|
| M-NAT-01 | list_windows / observe_window latency P50, P95 | 200 calls on fixture desktop, warm | within 1.5x of Windows Go host on the same class of machine |
| M-NAT-02 | capture_window latency P50, P95, bytes | 100 captures, 1920x1080 window | report only |
| M-NAT-03 | semantic and raw action latency to observed fixture state | 100 actions per type | report only |
| M-NAT-04 | host RSS idle and under suite | sampled every 1 s | report only |
| M-NAT-05 | delivered / refused / error per cell | catalog | 0 `error`, 0 unexpected `no_effect` |

### 2.3 Browser and web metrics

| Id | Metric | Method |
|---|---|---|
| M-BR-01 | Task success rate | controlled-site task set (forms, multi-step, tabs, dialogs, downloads, uploads) with host-side oracles |
| M-BR-02 | Step error rate and TargetStale rate | same set, before and after BR-01 |
| M-BR-03 | Wall time per task P50/P95; agent steps; model calls; input/output tokens | same planner (pinned client and model id), 5 repetitions |
| M-BR-04 | Memory of host + worker + engine | sampled |
| M-WI-01 | Crawl throughput pages/min and robots/sitemap correctness | local fixture site with known graph |
| M-WI-02 | Extraction tokens with and without relevance filtering, and answer accuracy on fixture questions | fixture pages |

Comparison baselines (same planner, same tasks): Orcel before the change; Playwright-MCP package used directly (reference only, in a disposable profile, never shipped). Browser Use's agent may be run as an external reference in a disposable environment; its Python runtime is never part of Orcel.

### 2.4 Task benchmarks (BM-02)

Task format ported from `libs/cua-bench` (MIT): each task directory holds setup, the instruction, and an oracle script that inspects final state. Orcel's runner drives tasks through MCP with a pinned client or a deterministic test planner and records the report rows. Datasets: start with 20 Orcel-owned tasks per OS (files, report generation, spreadsheet read via CSV, browser download, form submission on fixture site). `cua-driver-bench` (FSL) is not used until FD-04.

### 2.5 Journeys (from the adopted roadmap, now per OS)

The five journeys in `IMPLEMENTATION_ROADMAP.md` run on Windows first, then macOS and Linux as their capabilities land. TesterArmy E2E (`docs/security/SG-000108_TESTERARMY_E2E.md`) stays the browser journey harness.

## 3. Report format (`BENCHMARK_REPORT_1`, schema in BM-01)

```json
{
  "schema": "orcel-benchmark-report/1",
  "orcel_commit": "<40-hex>",
  "suite": "native-conformance|browser-tasks|web|journeys",
  "machine": {"os": "macos", "os_version": "26.0", "arch": "arm64", "cpu": "...", "ram_gb": 16},
  "planner": {"kind": "deterministic|mcp-client", "name": "...", "version": "...", "model": "..."},
  "rows": [
    {"case": "shared-web/click/ax/background", "status": "pass", "observed": "delivered",
     "latency_ms": {"p50": 0, "p95": 0}, "steps": 0, "model_calls": 0, "tokens_in": 0, "tokens_out": 0,
     "rss_mb_peak": 0, "evidence": "path or run id"}
  ]
}
```

No page text, screenshots or secrets go into reports.

## 4. CI requirements Opus must keep

- Unit and contract tests on ubuntu, windows, macos legs (XP-02).
- Native host build and core tests on macOS and Linux (XP-05).
- `native-e2e.yml` for Linux on every PR touching `apps/orcel-native-host` or `crates/orcel-provider-uia`; macOS on label.
- Existing SG-000094/95/108 native suites stay required on Windows.
- Readiness checks on planning changes: `python -I docs/orcel/implementation-readiness/tools/readiness_check.py` and `render_tables.py --check`.
