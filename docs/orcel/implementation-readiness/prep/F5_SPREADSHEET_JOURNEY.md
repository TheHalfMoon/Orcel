# F5 Journey 2: proposal for a workbook in the report task

**Status: DECIDED, option A (founder decision 7 of 2026-11-14 (the founder's 2026-11-14 decision packet, `docs/orcel/FOUNDER_DECISION_PACKET.md`; not SG-000108's decision 7)): a workbook may be read in the report task through the confined parser, slice by slice.** The decision admits the slices below, each under its own review. It activates no grain and grants no authority by itself: the exposure in slice 3 still needs its grain, and the approval question in slice 2 its security review. Slice 1 is the first to land. **Slices 1 and 2 are merged (#754, #758). Slice 3's grain, SG-000130 (issue #760), has its activation drafted (branch `sg130/activation`); it merges only on the founder's explicit go-ahead.** On 2026-11-15 the founder settled the approval question, as recorded on #760: the report's existing approval is enough, with no separate prompt to read a workbook, and the prompt for the create-only write shows the workbook's notices and which file each figure came from. It's the smallest decision needed to continue roadmap Journey 2 (`docs/orcel/IMPLEMENTATION_ROADMAP.md`), "Desktop spreadsheet -> approved report".

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
| A route from a workspace file to the parser | **Slice 2:** `observe_workspace_file` and `parse_workspace_file` in `crates/orceld/src/document_parse.rs`, called only by that module's tests |
| Report sources that aren't text | **Missing.** `report_task.rs` reads each source with `read_text` |

## Proposed slices

Each has its own review, and **all of them need this decision.** Slice 1 adds no behaviour a client can reach, but it ships the parser and its zip advisory exceptions, which is the cost this decision weighs.

1. **Package the parser, unreachable.** Ship `orcel-doc-parser` and its pin, inside the 400 MB budget, with no caller in a release build. This brings the zip advisory exceptions (`apps/orcel-doc-parser/.cargo/audit.toml`) into shipped code. They're recorded as unreachable, and they're not accepted risk. As built: `scripts/package-release.mjs` ships `orcel-doc-parser.exe` and `orcel-doc-parser.sha256` in the Windows release, built by the shared build and reproducibility actions; release qualification checks the pin and the manifest, and the installed-size test counts it against the budget; the parser's entry points in `document_parse.rs` carry `expect(dead_code)` in a release build, so a new release caller fails CI's clippy; `release_blocker_sweep.rs` also scans for callers in Rust and in the shipped MCP and Windows app sources; and the executable registry refuses any executable in an Orcel install directory, so the Safe tier can't register and start the shipped helpers unconfined. The Linux and macOS packages are left for later.
2. **Parse a workspace file.** The same steps as `parse_download`, starting from a workspace path instead of a committed download: plain directories only, size and SHA-256 re-read, one private input, the pinned parser. **Whether reading a workspace file through the parser needs its own approval** is a question for the grain's security review. `read_text` needs none today, but the parser is a larger surface. As built, in `document_parse.rs`, two steps:
   - `observe_workspace_file` takes a relative path. It refuses a name not ending in `.xlsx`, and a path that isn't plain relative segments (no `..`, `.`, empty segment, drive, stream, control character, or trailing dot or space). It walks each segment below the canonical workspace root, refusing a link, junction or other reparse point, or anything but plain directories and a regular file. It opens the last name without following a link. The open handle must be a regular file with exactly one hard link, since another name could lie outside the workspace. Its real path, read from the handle, must equal the walked path. The file must be within the parser's 50 MiB input bound, checked before reading, and the read stays within it. Then it walks the path again, opens the last name again, and refuses it unless that is the same file: same volume or device, and same file index or inode (128-bit on Windows). It records the size and SHA-256.
   - `parse_workspace_file` reads the file again by the same checks, and refuses it unless its size and SHA-256 still equal the observed ones. It stages only those bytes, as the one file in a fresh private input, checks the parser against its pin, runs it contained, and refuses a result that isn't a workbook, whatever the file's name.
   - **No client can reach it.** No MCP tool, app API method or `report_start` change. Only the module's tests call it. Each of its items carries `expect(dead_code)` in every build that isn't a test. CI's clippy (`-D warnings`) enforces that for default features only, so a caller in a default build fails CI. A caller compiled only into a live-browser build, which CI doesn't lint, would only warn. `release_blocker_sweep.rs` closes that gap. It checks the attributes, and that `document_parse.rs` names the route's items only inside the route's own section, which defines nothing else. It also checks that no other non-test Rust names the route.
   - **It asks for no approval.** That question stays open for slice 3's security review (below). If an approval is required, it goes between the two steps. It binds the canonical path the route opened, the SHA-256 and the parser's digest, as the download's approval does, never the caller's string.
   - **The open race.** Walking a path and then opening it races with a workspace writer. During the open, the writer swaps an intermediate directory for a junction or link, then swaps it back before the next walk. An opportunistic lock (oplock) on a file in the path pauses the open at the right moment, so this can be made deterministic, not merely likely. The SHA-256 comparison doesn't help, since a writer who wins the race once can win it at both observe and parse. It's closed by checking the handle, not the path. The handle's real path is read from the handle itself (`GetFinalPathNameByHandleW` on Windows, `/proc/self/fd` on Linux, `F_GETPATH` on macOS), so a handle that went through a link names the link's target and is refused. As a second check, the file is opened again after the second walk and its identity must match. What remains: a short (8.3) name in the path is refused, not resolved. A file can still be renamed into the walked path from elsewhere on the volume while it's open, but only by a writer who already has that file, and with one hard link it then has no other name.
3. **Workbook sources in `report_start`.** A source records the **file's** SHA-256, so a changed workbook is stale at preview and at commit, as a text source is. Its parsed text is untrusted content, as now.
4. **Checked figures.** A report states figures as `Sheet!Cell = value`. The independent checker parses the workbook **again, in a separate contained run**, and verifies each stated figure against the cell, the report's hash and the unchanged workbook.
5. **The journey test.** With a scripted, labelled SOFT consent, as BM-02 Tier B does: known cells, formula values and currency totals; macro and link cases refused; deny a save once, then a fresh grant; stale workbook; existing destination. A real approval through a real client stays with the founder, as in F4 slice 4.

## What the test-only code doesn't do yet

An independent review listed these. **Each must be done before any exposure:**

- **The checker's limit:** `report_check.rs` re-reads a source up to 1 MiB, so a larger workbook would pass preview, then fail after the report is written. The limit must follow the source's type, and be checked before the prompt. Reconcile uses the same check.
- **Figures in the checker:** a report with a false figure still reaches `verified` today, since the figure check runs separately. It must become part of verifying. That check must also keep the checker's independence: it can't use the workspace provider or the task registry, as `check_figures` does now.
- **The prompt:** the reader's notices, such as links and hidden sheets, don't reach the approval prompt. A person approving should see them.
- **Several workbooks:** `Sheet!Cell = value` doesn't say which source a figure means.
- **Plain directories:** `report_workbook.rs` still reads through the provider's verified open, which allows links inside the workspace. Slice 2's route takes plain directories and a single-linked regular file only, and ties the open handle to the walked path. Slice 3 must read workbook sources through it. Slice 3 could also pass the parser an expected format, so that a file that isn't a workbook is refused when the parser sniffs its type, before any parse. Today the route refuses it only after the parse.
- **The approval question** from slice 2, for the security review before slice 3. Does a person approve each workbook read through the parser, or is the report's existing approval enough? A text source needs none to be read, and only the report's create-only commit is approved. Arguments for a separate approval: the parser is a larger surface than `read_text`, it reads a binary format a hostile file controls, and a workbook can hold more than the report shows. Arguments against: the parser is contained, with no network, no process creation and a read-only private copy, and it returns only a bounded text frame, which is untrusted data. Hard links matter here too. A second name lets a file that lives outside the workspace be read through a name inside it. `read_text` doesn't refuse that; the route does. If an approval is required, it must bind the canonical path the route opened, the file's SHA-256 and the parser's digest, never the string the caller sent. The review should also weigh what remains of the open race (above).

## Security and licensing

- **`orceld` stays the sole authority.** The parser gets one private copy of one file and returns one bounded frame. Its text is data and never an instruction.
- **New exposure:** `report_start`'s `sources` would accept a binary format. It's a local-only tool: the core and tunnel profiles never list it, and that wouldn't change. This is the reason it needs a grain.
- **Hostile workbooks** are the realistic threat. Macros are refused, nothing is calculated, links are never followed, and a crash stays inside the contained process.
- **Saved values can be stale.** Nothing recalculates. The report can name its source cell, but only as the file last saved it, and formulas that may reach outside are marked.
- **Licensing:** no new dependency. The reader is Orcel's own, on crates already in the parser's graph. Slice 1 ships that existing graph for the first time: every crate in `apps/orcel-doc-parser/Cargo.lock` that the parser links now reaches users, with its license text. Test fixtures from Apache POI carry their notice, and aren't shipped. Since slice 1 the Windows release carries the parser's crates in `THIRD_PARTY_NOTICES.txt` and the SBOM, with the lopdf notice and the Firecrawl notice (its adapted converters, redistributed under FD-06, `docs/orcel/grants/2026-10-18-founder-attestation.md`). alloc-stdlib 0.2.4 (BSD-3-Clause, reached through lopdf) is published without a license file, so its repository's license is kept in `docs/orcel/notices/alloc-stdlib-BSD-3-Clause.txt`.

## What stays unqualified

- **A current Excel's files.** The committed tests are hand-written files, files from XlsxWriter and openpyxl, and two of Apache POI's samples of Excel 12.0 files. That Excel saved those samples is well-founded but not proved. A file from a current Excel, saved on a machine under this project's control, would close this. It's useful evidence and doesn't block the engineering.
- `.xls`, `.xlsb` and `.csv` as workbook sources. (CSV already works as text.)
- Anything recalculated: a value is only what was saved.

## Cost and reversibility

No money. The cost is in risk carried: slice 1 brings the parser's zip advisory exceptions into shipped code, recorded as unreachable and not accepted. Each slice can be reverted, and until slice 3 nothing a client can reach changes.
