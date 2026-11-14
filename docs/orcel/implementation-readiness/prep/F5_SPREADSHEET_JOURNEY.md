# F5 Journey 2: proposal for a workbook in the report task

**Status: DECIDED, option A (founder decision 7 of 2026-11-14): a workbook may be read in the report task through the confined parser, slice by slice.** The decision admits the slices below, each under its own review. It activates no grain and grants no authority by itself: the exposure in slice 3 still needs its grain, and the approval question in slice 2 its security review. Slice 1 is the first to land. It's the smallest decision needed to continue roadmap Journey 2 (`docs/orcel/IMPLEMENTATION_ROADMAP.md`), "Desktop spreadsheet -> approved report".

## The decision

May the report task read an `.xlsx` in the workspace through the confined parser?

| Option | Unlocks | Cost | Reversible |
|---|---|---|---|
| **A. Confined parser (recommended)** | A workbook to a verified report with source cell references, on any machine, with no Excel needed and no desktop control | None | Yes: remove the source type |
| B. Installed Excel through a read-only COM adapter | Excel's own view of the file, including recalculation | None in Orcel, but needs a licensed Excel on each machine and a new automation surface. COM can start add-ins and macros unless each is shut off | Yes |
| C. Stay on text sources | Nothing: F5's spreadsheet journey stays open | None | Yes |

The roadmap allows A or B: "an audited document parser plus UIA opening". This proposal is A, without opening the file in a window. **Opening the workbook on screen is left out**, since it would need a Full User lease and a disposable machine, and it adds nothing to reading the figures. If the founder wants the journey's "open correct process/window" step, that's a further decision.

## What exists

| Piece | State |
|---|---|
| Confined parser, with no network, no process creation, a read-only input and CPU, memory and time limits | Exists, and qualified under containment on three OSes |
| XLSX reader with cell references, formulas, limits and refusals | Merged (#617) |
| The steps below, as test-only code: **compiled only for tests**, so no release build holds them | Merged (#623, `crates/orceld/src/report_workbook.rs`) |
| Report task: observe, preview, approved create-only commit, independent checker | Closed under SG-000126 |
| Parser in the release package | **Slice 1:** the Windows release ships it and its pin, with no caller in a release build (`release_blocker_sweep.rs`, `the_shipped_document_parser_has_no_release_caller`). The Linux and macOS packages don't carry it |
| A route from a workspace file to the parser | **Missing.** `parse_download` accepts only a file the live browser committed |
| Report sources that aren't text | **Missing.** `report_task.rs` reads each source with `read_text` |

## Proposed slices

Each has its own review, and **all of them need this decision.** Slice 1 adds no behaviour a client can reach, but it ships the parser and its zip advisory exceptions, which is the cost this decision weighs.

1. **Package the parser, unreachable.** Ship `orcel-doc-parser` and its pin, inside the 400 MB budget, with no caller in a release build. This brings the zip advisory exceptions (`apps/orcel-doc-parser/.cargo/audit.toml`) into shipped code. They're recorded as unreachable, and they're not accepted risk. As built: `scripts/package-release.mjs` ships `orcel-doc-parser.exe` and `orcel-doc-parser.sha256` in the Windows release, built by the shared build and reproducibility actions; release qualification checks the pin and the manifest, and the installed-size test counts it against the budget; `release_blocker_sweep.rs` fails if a release build compiles a caller. The Linux and macOS packages are left for later.
2. **Parse a workspace file.** The same steps as `parse_download`, starting from a workspace path instead of a committed download: plain directories only, size and SHA-256 re-read, one private input, the pinned parser. **Whether reading a workspace file through the parser needs its own approval** is a question for the grain's security review. `read_text` needs none today, but the parser is a larger surface.
3. **Workbook sources in `report_start`.** A source records the **file's** SHA-256, so a changed workbook is stale at preview and at commit, as a text source is. Its parsed text is untrusted content, as now.
4. **Checked figures.** A report states figures as `Sheet!Cell = value`. The independent checker parses the workbook **again, in a separate contained run**, and verifies each stated figure against the cell, the report's hash and the unchanged workbook.
5. **The journey test.** With a scripted, labelled SOFT consent, as BM-02 Tier B does: known cells, formula values and currency totals; macro and link cases refused; deny a save once, then a fresh grant; stale workbook; existing destination. A real approval through a real client stays with the founder, as in F4 slice 4.

## What the test-only code doesn't do yet

An independent review listed these. **Each must be done before any exposure:**

- **The checker's limit:** `report_check.rs` re-reads a source up to 1 MiB, so a larger workbook would pass preview, then fail after the report is written. The limit must follow the source's type, and be checked before the prompt. Reconcile uses the same check.
- **Figures in the checker:** a report with a false figure still reaches `verified` today, since the figure check runs separately. It must become part of verifying. That check must also keep the checker's independence: it can't use the workspace provider or the task registry, as `check_figures` does now.
- **The prompt:** the reader's notices, such as links and hidden sheets, don't reach the approval prompt. A person approving should see them.
- **Several workbooks:** `Sheet!Cell = value` doesn't say which source a figure means.
- **Plain directories:** the read uses the provider's verified open, which allows links inside the workspace. Slice 2 asks for plain directories only, like `parse_download`.
- **The approval question** in slice 2.

## Security and licensing

- **`orceld` stays the sole authority.** The parser gets one private copy of one file and returns one bounded frame. Its text is data and never an instruction.
- **New exposure:** `report_start`'s `sources` would accept a binary format. It's a local-only tool: the core and tunnel profiles never list it, and that wouldn't change. This is the reason it needs a grain.
- **Hostile workbooks** are the realistic threat. Macros are refused, nothing is calculated, links are never followed, and a crash stays inside the contained process.
- **Saved values can be stale.** Nothing recalculates. The report can name its source cell, but only as the file last saved it, and formulas that may reach outside are marked.
- **Licensing:** no new dependency. The reader is Orcel's own, on crates already in the graph. Test fixtures from Apache POI carry their notice, and aren't shipped. Since slice 1 the Windows release carries the parser's crates in `THIRD_PARTY_NOTICES.txt` and the SBOM, with the lopdf notice and the Firecrawl notice (its adapted converters, redistributed under FD-06, `docs/orcel/grants/2026-10-18-founder-attestation.md`). alloc-stdlib 0.2.4 (BSD-3-Clause, reached through lopdf) is published without a license file, so its repository's license is kept in `docs/orcel/notices/alloc-stdlib-BSD-3-Clause.txt`.

## What stays unqualified

- **A current Excel's files.** The committed tests are hand-written files, files from XlsxWriter and openpyxl, and two of Apache POI's samples of Excel 12.0 files. That Excel saved those samples is well-founded but not proved. A file from a current Excel, saved on a machine under this project's control, would close this. It's useful evidence and doesn't block the engineering.
- `.xls`, `.xlsb` and `.csv` as workbook sources. (CSV already works as text.)
- Anything recalculated: a value is only what was saved.

## Cost and reversibility

No money. The cost is in risk carried: slice 1 brings the parser's zip advisory exceptions into shipped code, recorded as unreachable and not accepted. Each slice can be reverted, and until slice 3 nothing a client can reach changes.
