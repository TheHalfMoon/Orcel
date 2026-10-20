# Benchmark and E2E plan (cross-platform)

Status: ADOPTED planning direction (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. Extends `docs/orcel/BENCHMARK_AND_E2E_PLAN.md` (adopted minimum native evidence). No result in this file is measured; every target is an ESTIMATE to be replaced by data.

## 1. Rules

- Claims of speed, accuracy or superiority require a report produced by the harness below, at an exact Orcel commit, with the same planner and workload for every compared system.
- Upstream donor results (Cua's matrix, browser-use benchmarks) are SOURCE-DOCUMENTED context, never Orcel evidence.
- A model's summary of success is not evidence; oracles are fixture state, file hashes, DOM state probed by the host, or external checkers.

## 2. Suites

### 2.1 Native conformance (XP-08)

Fixture apps copied from Cua (`tests/native-fixtures`, MIT): shared web harness in Electron and Tauri hosts, AppKit, SwiftUI, WKWebView, GTK3, GTK4, WPF, WinUI3. Dimensions per cell (from Cua `docs/test-matrix.md`): OS, window system, harness, targeting (`ax`/`px`), delivery (`background`/`foreground`), scope, oracle, status, observed behavior (`delivered`, `refused`, `no_effect`, `error`, `not_run`). A refusal counts only when the exact refusal code and the no-focus/no-z-order/no-input-leak oracles pass.

Runners: Linux Xvfb + Openbox and headless Sway on GitHub-hosted Ubuntu; macOS on a founder-provided self-hosted runner with Accessibility and Screen Recording granted (FD-05); Windows on `windows-latest` interactive session for observation and the existing native suites for input.

As built (XP-08):
- Suites: `apps/orcel-native-host/tests/conformance_shared_web.rs` (upstream's 40-cell catalog on the shared page in Electron, plus WKWebView on macOS) and `conformance_native.rs` (GTK3 on Linux, AppKit on macOS, in their task-state mode). Fixture provenance: `tests/native-fixtures/ORCEL.md`; build: `tests/native-fixtures/orcel-stage.sh`.
- CI: steps in the `native-host` job of `.github/workflows/ci.yml`, not a separate `native-e2e.yml`. The governed workflow set is exactly four files (`release_blocker_sweep::workflow_set_is_exactly_the_governed_quartet`).
- macOS: the GitHub-hosted `macos-latest` runner until FD-05. It grants the host Accessibility and Screen Recording (XP-06 CI log), so observation cells run there. A self-hosted run is still wanted for real-hardware latency.
- Oracles: fixture state is the page's loopback journal or the harness's task-state file, never the host's tree. Focus and z-order come from the window system (`xprop` on X11, `swaymsg` on Sway, `lsappinfo` on macOS). The cursor comes from `xdotool` on X11, and on macOS from the host's `cursor_position`, named `cursor-host` in the case id. Sway has no cursor oracle: Wayland gives no client the pointer position, and the suite requires the host to report `cursor_position` as `unavailable`/`provider_unavailable` there.
- Report: one `orcel-benchmark-report/1` file (schema `protocol/BENCHMARK_REPORT_1.schema.json`, checker `scripts/check-benchmark-report.mjs`) per suite and window system, uploaded as the `xp08-native-conformance-<os>-<sha>` artifact. The dimensions sit in the case id: `<suite>/<window system>/<harness>/<action>/<targeting>/<delivery>/<oracles>` for input cells and `<suite>/<window system>/<harness>/observe/<cell>` for observation cells. The OS is `machine.os`.
- Input cells. `ax` cells (XP-11) run through `semantic_action`: the background cell delivers the verb and passes only when the fixture's own state shows the effect (the GTK3 and AppKit task-state file, the shared page's journal) and focus, stacking and the pointer are where they were (`status: pass, observed: delivered`, the oracle names in the case id); the foreground rung has nothing to measure because semantic actions never take the foreground (`skip`, `background-only`); an action with no semantic verb or one refused on purpose (a value written into web content, scroll) sends its frame and requires the exact refusal (`pass`, `refused`); a page whose controls lie below the `/2` depth ceiling reports `skip`, `beyond-depth-bound`. Negative cells (forged, altered, stale-window and stale-process targets, a verb that does not suit the element, scroll, and a frame carrying a position or key) are `pass`, `refused`, with every oracle unchanged. `px` cells wait for XP-12 (raw `input_*`): the cell sends its `/2` frame and requires `capability_denied` with every oracle unchanged, reported as `status: skip, observed: refused`. When the hello stops refusing a pixel operation, the suite fails until its cells are ported. Tauri is reported `not_run`: its icons are binary and are not copied, and the build is too heavy for CI.
- Finding (first CI runs): the host's AX and AT-SPI trees hold interactive elements only, so static labels are never observed. Fixture agreement therefore compares controls: button names with the journal, and checkbox and radio state with the task-state file. Under Linux Chromium, AT-SPI reaches the page's Document at depth 8, the `/2` depth ceiling, so the shared page's controls are not observable through Electron on Linux. That row is reported `skip` / `beyond-depth-bound`, and the suite fails if the controls ever come within the bound. macOS (Electron and WKWebView) and the GTK3 harness observe their controls.

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
- Native conformance (XP-08) for Linux X11, Linux Sway and hosted macOS on every PR, in the `native-host` job of `ci.yml` (the spec's `native-e2e.yml` would be a fifth governed workflow).
- Existing SG-000094/95/108 native suites stay required on Windows.
- Readiness checks on planning changes: `python -I docs/orcel/implementation-readiness/tools/readiness_check.py` and `render_tables.py --check`.
