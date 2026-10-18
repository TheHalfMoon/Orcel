# Optimized engineering roadmap (cross-platform revision)

Status: ADOPTED planning direction (founder, 2026-10-18; `docs/orcel/grants/2026-10-18-founder-attestation.md`), authored by Fable. It extends, and does not restart, the adopted F0-F8 increments in `docs/orcel/IMPLEMENTATION_ROADMAP.md` and the P20 grains in `docs/canonical/ORCEL_P20_UNIVERSAL_AGENT_RUNTIME_PLAN.md`. Effort figures are ESTIMATES in engineer-days (backlog `estimate` fields), not dates.

## 1. Tracks

| Track | Content | Runs with | Governance |
|---|---|---|---|
| **A. Windows Core MVP (in progress)** | SG-000108 browser (Opus active; #336 open), SG-000096 shell; F0 app API, F2 report task, F4 qualification | unchanged | existing grains |
| **X. Cross-platform foundation and hosts** | XP-01..XP-20 | parallel with A (FD-02 approved 2026-10-18) | new grains SG-000109+ |
| **C. Control Room** | CR-01..CR-04 | CR-01/02 with X1; CR-03 after FD-03 | SG-000118, SG-000119 |
| **R. Runtime journal** | RJ-01..RJ-03 | after SG-000108 closes | SG-000120 |
| **B. Browser capability** | BR-01..BR-08 | after SG-000108 closes | SG-000121..123 |
| **W. Web intelligence** | WI-01..WI-06 | after SG-000108 closes | existing P20 ids SG-000101..103 |
| **S. Sandboxes** | SX-01..SX-06 | after X4 and R | SG-000124, SG-000125 |
| **M. Measurement** | BM-01, BM-02, XP-20, CR-04 | continuous | - |

Tracks A and X touch different files (A: `crates/orcel-browser-host`, `apps/orcel-browser-worker`, `crates/orcel-provider-process`; X0/X1: new crates/apps plus `orcel-approval`/`orcel-audit` path functions, `orcel-provider-uia` adapter, CI). The two planned overlaps are deliberate dependencies: XP-14 (browser host on macOS/Linux) and RJ-01 (journal extraction) wait for SG-000108 to close.

## 2. Phases and exit tests

| Phase | Tasks | Exit test | Effort (ESTIMATE) |
|---|---|---|---|
| X0 foundation | XP-01, XP-02, XP-03, XP-04, BM-01, CR-01, XP-15 | three-OS CI green; no temp fallback; `/2` hello works with Go host; app API read-only on three OSes; clipboard on three OSes | 13-21 |
| X1 observe | XP-05, XP-06, XP-07, XP-08, CR-02, (CR-03 after FD-03) | macOS + X11 + Sway observation and capture conformance reports; Control Room shows real status | 18-27 without CR-03; 26-39 with it |
| X2 approve | XP-09, XP-10, RJ-01 | #278 regressions and ledger tests pass on macOS/Linux; real prompts recorded | 10-15 |
| X3 act | XP-11, XP-12, RJ-02, RJ-03 | semantic and input cells green; crash-at-each-transition suite | 19-28 |
| X4 parity | XP-13, XP-14, XP-15 | process, browser, clipboard suites on three OSes | 15-24 |
| X5 ship | XP-16, XP-17, XP-18, XP-19 | clean installs on macOS 15/26, Ubuntu 24.04, Fedora 41; pairing works | 16-25 |
| B1/B2/B3 browser | BR-01..08 | M-BR metrics vs baseline | 27-37 |
| W web | WI-01..06 | M-WI metrics; fixture crawl/map/extract | 15-21 |
| S sandbox | SX-01..06 | per-backend checklists | 30-41 |
| X6 measure | XP-20, CR-04, BM-02 | decision records with data | 10-14 |

## 3. Release sequence

1. **Windows Core MVP (track A, F4)**: unchanged gate (one real MCP client, report task, browser PDF journey, installer <400 MB).
2. **Cross-platform preview**: X0-X2 complete. macOS and Linux can observe, capture and approve; no mutations marketed. Control Room read-only on three OSes if FD-03 is yes.
3. **Core on three OSes**: X3-X5 complete. Desktop actions, browser, process, clipboard, packaging on all three; the five journeys run per OS.
4. **Capability release**: B and W tracks; journal and resume (R) complete.
5. **Isolation and fleet**: S track; F6 two-target journeys mixing OSes; F7 founder AI on the same kernel.

Nothing in releases 1-3 depends on Hala training, founder-hosted inference, sandboxes or paid infrastructure.

## 4. Critical path (task ids)

```text
XP-01 → XP-03 → XP-06 → XP-11 → XP-12 → XP-20
XP-02 ↗        ↗   ↓
XP-04 ─────────┘  XP-07, XP-08
XP-05 ────────────┘
XP-01 → CR-01 → CR-02 → CR-03 → CR-04
XP-01 + XP-02 → XP-09 → XP-11    XP-01 → XP-10 → XP-11
(XP-09 uses a development-signed helper checked against a pinned designated requirement; XP-16 later swaps in the Developer ID requirement. XP-10 installs its polkit action with a test-only script; XP-17 packages it.)
SG-000108 close → RJ-01 → RJ-02 → RJ-03
SG-000108 close → BR-01 → BR-02 → BR-03/BR-05 ; BR-01 → BR-04, BR-06 ; BR-01 + RJ-01 → BR-07
SG-000108 close → WI-01 → WI-02, WI-04 ; WI-03 ; XP-13 → WI-05 ; XP-19 → WI-06
XP-13 + RJ-01 → SX-01 → SX-02 → SX-05 ; SX-01 → SX-03, SX-04, SX-06
```

The full machine-checked graph is `backlog/tasks.json` (`depends_on`), validated acyclic by `tools/readiness_check.py`.

## 5. Parallelizable work (separate files, separate owners)

- XP-01/XP-02/XP-04 in parallel (different files).
- XP-05 (vendoring) in parallel with CR-01 (kernel app API).
- XP-15 (clipboard) any time after XP-02.
- BM-01 any time.
- During SG-000108's remaining slices: all X0/X1 tasks, CR-01/02, BM-01.
