# orcel-doc-parser

WI-05's confined converter: one approved, already-downloaded PDF, DOCX, PPTX
or XLSX file in, one bounded Markdown frame out.

It is its own Cargo workspace (like `apps/orcel-contain`), so the PDF and
Office parsers never enter orceld's lockfile and orceld never links them.

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
