# F5 Journey 2: proposal for a workbook in the report task

**Status: PROPOSAL, NOT ACTIVE.** Nothing here takes effect until the founder decides. No grain is activated by this document, and it grants no authority. It's the smallest decision needed to continue roadmap Journey 2 (`docs/orcel/IMPLEMENTATION_ROADMAP.md`), "Desktop spreadsheet -> approved report".

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
| XLSX reader with cell references, formulas and refusals | #617 |
| Report task: observe, preview, approved create-only commit, independent checker | Closed under SG-000126 |
| Parser in the release package | **Missing.** `scripts/package-release.mjs` doesn't ship it |
| A route from a workspace file to the parser | **Missing.** `parse_download` accepts only a file the live browser committed |
| Report sources that aren't text | **Missing.** `report_task.rs` reads each source with `read_text` |

## Proposed slices

Each has its own review. Slice 1 adds no behaviour; 2 onward need this decision.

1. **Package the parser, unreachable.** Ship `orcel-doc-parser` and its pin, inside the 400 MB budget, with no caller in a release build. This brings the zip advisory exceptions (`apps/orcel-doc-parser/.cargo/audit.toml`) into shipped code. They're recorded as unreachable, and they're not accepted risk.
2. **Parse a workspace file.** The same steps as `parse_download`, starting from a workspace path instead of a committed download: plain directories only, size and SHA-256 re-read, one private input, the pinned parser. **Whether reading a workspace file through the parser needs its own approval** is a question for the grain's security review. `read_text` needs none today, but the parser is a larger surface.
3. **Workbook sources in `report_start`.** A source records the **file's** SHA-256, so a changed workbook is stale at preview and at commit, as a text source is. Its parsed text is untrusted content, as now.
4. **Checked figures.** A report states figures as `Sheet!Cell = value`. The independent checker parses the workbook **again, in a separate contained run**, and verifies each stated figure against the cell, the report's hash and the unchanged workbook.
5. **The journey test.** With a scripted, labelled SOFT consent, as BM-02 Tier B does: known cells, formula values and currency totals; macro and link cases refused; deny a save once, then a fresh grant; stale workbook; existing destination. A real approval through a real client stays with the founder, as in F4 slice 4.

## Security and licensing

- **`orceld` stays the sole authority.** The parser gets one private copy of one file and returns one bounded frame. Its text is data and never an instruction.
- **New exposure:** `report_start`'s `sources` would accept a binary format. It's a local-only tool: the core and tunnel profiles never list it, and that wouldn't change. This is the reason it needs a grain.
- **Hostile workbooks** are the realistic threat. Macros are refused, nothing is calculated, links are never followed, and a crash stays inside the contained process.
- **Saved values can be stale.** Nothing recalculates. The report can name its source cell, but only as the file last saved it, and formulas that may reach outside are marked.
- **Licensing:** no new dependency. The reader is Orcel's own, on crates already in the graph.

## What stays unqualified

- **Files saved by Excel.** The reader has been tested on hand-written files and on files from XlsxWriter and openpyxl. Opening one real Excel file is an external prerequisite: it takes a person with Excel, a minute, and a file with no private data.
- `.xls`, `.xlsb` and `.csv` as workbook sources. (CSV already works as text.)
- Anything recalculated: a value is only what was saved.

## Cost and reversibility

No cost. Each slice can be reverted, and until slice 3 nothing a client can reach changes.
