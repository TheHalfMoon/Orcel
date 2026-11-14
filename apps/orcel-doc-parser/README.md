# orcel-doc-parser

WI-05's confined converter: one approved, already-downloaded PDF, DOCX, PPTX
or XLSX file in, one bounded Markdown frame out.

It is its own Cargo workspace (like `apps/orcel-contain`), so the PDF and
Office parsers never enter orceld's lockfile and orceld never links them.

## Workbooks

An XLSX is read by `src/workbook.rs`, Orcel's own reader, not anydoc. Each cell
with content is one table row: reference, value as last saved, type, number
format and formula. So a report can name the cell each figure came from.

- Nothing is calculated, and no link is followed or refreshed. A formula with
  no saved value is shown with the note `no saved value`.
- A formula that may reach outside the workbook (external workbook, DDE,
  `WEBSERVICE`, `RTD`, `INDIRECT`, cube and stock functions) is marked
  `external, not refreshed`. This is a text check: a false positive adds a caution,
  and it can miss a form it doesn't know.
- External links, data connections, pivot caches, query tables, reaching defined
  names and manual or on-load calculation are declared at the top. Their targets
  are never shown.
- Macros, including Excel 4 macro sheets, are `active_content`.
- **A structural element out of its place is refused, not skipped.** Only the
  spreadsheet namespace counts. Sheets, cells, values, shared strings, defined names,
  calculation settings and number formats must sit where the reader reads them, so
  inside `mc:AlternateContent` or another wrapper they're `malformed`. Wrappers for
  anything else, which Excel writes for its own features, are left alone and not read.
  A cell holding anything unexpected is `malformed`. So is a reference that's invalid,
  repeated or in the wrong row, and a number, boolean, error or date value that isn't
  one.
- The file format's `_xHHHH_` character escapes are decoded in text, formulas and sheet
  names. Cell content is then escaped for the table, so it stays on its own row and can't
  pass as another cell.
- Hidden sheets are read and labelled `(hidden)`. Hidden rows and columns aren't
  labelled. Chart and dialog sheets are listed as `(no cells)`.
- Binary workbooks (XLSB) are refused: as `active_content` when they declare the
  usual macro-enabled type, and otherwise as `unsupported_format`.
- A sheet is limited to 200,000 rows and a workbook to 500,000 cells and 500 sheets. One
  part's XML is limited to 2,000,000 nodes, 2,000,000 attributes and 256 attributes per
  element. Past those it's `archive_limit` (`too_many_pages` for sheets). These don't bound everything: a very
  large file can still reach the contained memory or time limit first, which ends as a
  contained crash, reported as a failure.

**Tested with hand-written fixtures, with files from XlsxWriter and openpyxl, and with
Apache POI's samples of Excel 12.0 files (`tests/fixtures/WORKBOOKS.md`).** That Excel saved
those samples is well-founded but not proved, and no file from a current Excel is a
committed test. Comments, charts
and other parts aren't read. This reader is not yet wired to a task. Founder decision 7 of
2026-11-14 chose it for the spreadsheet journey (roadmap Journey 2), slice by slice
(`docs/orcel/implementation-readiness/prep/F5_SPREADSHEET_JOURNEY.md`); a client can reach
it only from slice 3, which needs its own grain.

## In the release

Since F5 slice 1, the Windows release ships `orcel-doc-parser.exe` beside `orceld.exe`,
pinned by `orcel-doc-parser.sha256` (`scripts/package-release.mjs`; both are manifest files,
so the installer verifies them). **No release build calls it.** Its only callers are the live
browser's committed downloads, compiled only into `live-browser-*` development builds, and the
workbook source, compiled only into tests. If that changes, the `expect(dead_code)` on the
entry points in `crates/orceld/src/document_parse.rs` fails CI's clippy, and
`release_blocker_sweep.rs` (`the_shipped_document_parser_has_no_release_caller`) scans
production Rust and the shipped MCP and Windows app sources for callers. The executable
registry refuses anything in an Orcel install directory, so it can't be registered and started
unconfined either. Known consequence: the registry treats any folder holding an `orceld`
executable as an install directory, so `cargo install orceld`, for example, makes every tool in
`~/.cargo/bin` unregistrable (and stops a registered one there from launching). Its crates are in
the release's `THIRD_PARTY_NOTICES.txt` and SBOM, with the lopdf and Firecrawl notices. The
Linux and macOS packages don't carry it yet.

## How orceld runs it

`crates/orceld/src/document_parse.rs`, reached from a download the live
browser committed (`LiveBrowser::parse_download`):

1. The pinned parser (`orcel-doc-parser[.exe]` plus `orcel-doc-parser.sha256`)
   and the pinned `orcel-contain` helper are resolved beside orceld. If either
   is missing, the request fails before anything is asked for.
2. The committed file is read again through plain directories only, and is
   refused unless its size and SHA-256 still match what the host committed.
3. An approval is requested and consumed. Its digest binds the workspace, the
   policy revision, the download record, the destination, the file's digest
   and size, the source URL and the parser's digest.
4. The verified bytes are copied into a fresh private `input/` directory,
   where they are the only file. The parser's bytes are checked against its
   pin, and it runs under the contained tier with
   `orcel_provider_process::document_parser::spec`:
   - `input/` is readable and nothing else is;
   - there is no writable root besides the private working directory;
   - there is no network and no process creation;
   - memory is capped at 1 GiB, CPU at 30 s, open files at 64;
   - output is bounded, and the run times out after 30 s.
5. The `orcel-doc-parser/1` frame is decoded. The Markdown is returned
   labelled `"trust": "untrusted"`.

## Bounds

All values come from `document_parser.rs`.

| Bound | Value | Past it |
|---|---|---|
| Input size | 50 MiB | `input_too_large` |
| PDF pages, PPTX slides, XLSX sheets | 500 | `too_many_pages` (refused, not cut) |
| PDF object nesting | 32 | `nesting_too_deep` |
| Office XML element nesting | 128 | `nesting_too_deep` |
| Archive entries | 1,000 | `archive_limit` |
| Total inflated bytes (counted, not declared) | 64 MiB | `archive_limit` |
| Inflation ratio of one entry over 1 MiB | 100 | `archive_limit` |
| PDF stream inflation while loading | 64 MiB | `archive_limit` |
| Markdown | 1,000,000 characters | cut at a character boundary, `truncated: true` |

## What fails closed

Every refusal is a closed code. No text from the document ever reaches an
error.

- `encrypted`: encrypted PDFs and encrypted Office files. The parser never
  tries the empty password.
- `active_content`: PDF JavaScript or launch actions, and Office macro
  projects or ActiveX parts.
- `malformed`: malformed files and XML DTDs.
- `unsupported_format`: OLE binary Office, OpenDocument, RTF, EPUB, CSV and
  anything else.
- `no_text`: scanned PDFs (Orcel runs no OCR).

Links, external relationships and embedded files are never followed or
opened.

## Tests

- `cargo test`: the fixture corpus in `tests/fixtures/mod.rs`, generated from
  source on each run, in process.
- `cargo test --test contained` with `ORCEL_TEST_CONTAIN_DIR=<orcel-contain
  target/debug>`: the same corpus through the real helper. It also runs XP-13's
  probe under the parser's spec to check:
  - no network;
  - no other file;
  - no write;
  - no process;
  - the timeout.

  It ends with a bounded mutation run (`ORCEL_WI05_FUZZ_CASES`).

CI runs both on Linux, macOS and Windows (`Document parser / <os>`), plus
orceld's `wi05_` end-to-end test.

## Provenance

`src/pdf.rs` and `src/document.rs` are adapted from Firecrawl
(`docs/orcel/firecrawl_doc_parser_provenance.json`,
`docs/orcel/notices/firecrawl-AGPL-3.0.txt`).
