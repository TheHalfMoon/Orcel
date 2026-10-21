# lopdf patch queue (Orcel, #391)

Upstream: the crates.io release `lopdf` 0.45.0 (MIT, `LICENSE` in this
directory), archive SHA-256
`bfffda0fe1ab0157e1a13c14bebd3f28671f2fccb7922f0722ec53926e6922d3`. That is
the checksum `apps/orcel-doc-parser/Cargo.lock` carried before this patch.
Provenance, the upstream tree id and the file lists are in
[docs/orcel/lopdf_provenance.json](../../../../docs/orcel/lopdf_provenance.json).

Every file here is upstream's bytes except the files listed below.
`node scripts/check-vendored-lopdf.mjs` proves that in CI. It rebuilds the
crate's git tree with the upstream blob put back for every patched and
removed file, and requires the upstream tree id. With `--upstream` it also
downloads the archive from crates.io and checks the checksum and the tree id
against it.

The parser's workspace uses this copy through `[patch.crates-io]`
(`apps/orcel-doc-parser/Cargo.toml`), so pdf-inspector 1.21.0 and the parser
both link it. The directory is excluded from the workspace, so it is a
dependency, not a member. Rebasing to a new lopdf means re-importing the
crate unmodified and replaying this queue.

## Why lopdf and not pdf-inspector

#391 offered either. Every decode pdf-inspector makes is a call into lopdf's
`Stream` API, and every one of those methods ends in one private function,
`Stream::decode_filters`. That covers all 17 `decompressed_content()` calls
outside its binaries, `get_page_content_with_limit`, and the object and xref
streams its loads read. Patching that one function bounds all of them,
including any call site a later reading of pdf-inspector would miss. It also
covers the parser's own pre-flight.

pdf-inspector 1.21.0 is about 100,000 lines of Rust. It also embeds 170
binary CMap files (`external/bcmaps`, 1.5 MiB, through `include_dir!`) that
the exact-diff review cannot read. lopdf is 22,000 lines of text, with no
binary file and no line over 400 characters. pdf-inspector itself stays the
crates.io release, pinned `=1.21.0`.

## Import

Copied blob for blob from the archive: `src/` (38 files; `src/reader.rs`
patched, P-03), `Cargo.toml` (patched, P-01), `LICENSE` and `README.md`
(patched, P-03; `src/lib.rs` embeds it as the crate's documentation).

Not vendored. Each is put back as its upstream blob or tree when the checker
rebuilds the upstream tree:
- `examples` and `tests`: example binaries and integration tests. Neither is
  built (P-01 drops their targets), and the tests read `assets/`, which the
  published crate excludes.
- `.cargo_vcs_info.json`, `.editorconfig`, `.gitattributes`, `.gitignore`:
  packaging and upstream repository settings.
- `CHANGELOG.md`: release notes.
- `Cargo.lock`: `apps/orcel-doc-parser/Cargo.lock` governs the graph.
- `Cargo.toml.orig`: the manifest before crates.io normalised it.
- `rustfmt.toml`: formatter settings. The copy is never reformatted.

`PATCHES.md` (this file) is Orcel's own.

## P-01: manifest

`Cargo.toml` loses its 39 `[[example]]` and 27 `[[test]]` targets, whose
sources are not vendored. Cargo checks that a manifest's target paths exist,
so the manifest cannot keep them. Nothing else changes: the features,
dependencies and versions are upstream's, so the lockfile resolves exactly
the graph it resolved before the patch. Only lopdf's `source` and `checksum`
lines are gone.

## P-02: one decode budget for every stream decode

- `src/decode_budget.rs` (added).
- `src/object.rs`: `Stream::decode_filters` reserves its limit from the
  budget, decodes as upstream did (the body is unchanged, renamed
  `decode_filters_unbudgeted`), and settles what it produced.
- `src/lib.rs`: `pub mod decode_budget;`.

The parser opens a `decode_budget::Scope` for each phase of a PDF parse
(`apps/orcel-doc-parser/src/pdf.rs`, `within_budget`), with
`MAX_PDF_INFLATED_BYTES` in total and `MAX_ARCHIVE_BYTES` per decode. While
a scope is open:

- every decode, on any thread (lopdf loads object streams on rayon tasks),
  may produce at most `min(per_decode, remaining)` bytes, or the caller's own
  limit if that is smaller. Each filter layer is capped while it decodes, so
  nothing past the cap is ever allocated;
- every decode is charged what it produced. A stream decoded again, such as
  a form XObject drawn on every page, is charged again. A decode that fails
  for any reason other than its limit (an image filter lopdf does not
  implement, a corrupt stream) is charged the stream's raw length, which is
  what pdf-inspector then reads instead;
- once a decode is refused because the budget ran out, rather than the
  caller's own limit, the scope is exhausted. Every later decode is refused,
  and the handler the parser set runs once. The parser binary's handler
  writes the `archive_limit` frame and exits, so nothing more of the
  document is read. Without a handler (unit tests), the phase runs to its
  end and is then refused as `archive_limit`.

With no scope open, a decode with a limit behaves as upstream, and a decode
without one (`decompressed_content`, `get_plain_content`, `decompress`,
`ObjectStream::new`, a load without `max_decompressed_size`) is refused. So
an unbounded decode cannot happen in the parser's process, inside a scope or
outside one.

Scopes are process-wide and serialised: `Scope::enter` waits for an open
scope to close, and `decode_budget::closed()` holds the budget closed. The
parser handles one document per process; the serialisation keeps unit tests
from charging each other.

Behaviour to know (#399; none of it weakens the bound, and the parser fails
closed in every case):

- The budget is per phase, not per document. The parser opens one scope for
  the pre-flight and a second, fresh one for pdf-inspector, so a document can
  cost up to twice `MAX_PDF_INFLATED_BYTES` of decoding in all (512 MiB).
- `reserve` takes the whole grant of a decode up front: up to
  `min(per_decode, remaining)`, so up to `MAX_ARCHIVE_BYTES` (64 MiB), and
  `settle` hands back what the decode did not use. With rayon decoding object
  streams in parallel, several grants can be out at once and the unreserved
  budget can reach zero while most of it is still unused. A later decode then
  finds nothing left and the scope is exhausted: the document is refused as
  `archive_limit` although its decodes would have fitted one after another.
  Refusing is the safe side, and ordinary documents stay far below the
  budget.
- `Scope::enter` is not re-entrant. A second `enter` on the thread that holds
  a scope waits for itself and deadlocks; open one scope per phase and never
  nest them.
- A decode on a thread with no scope of its own is charged to whichever scope
  is open in the process, because the budget is process-wide. The parser
  handles one document per process, so this only matters to tests that run
  decodes concurrently; they should hold `decode_budget::closed()` or a scope
  of their own for the whole test.

Advisories: `cargo audit` cannot match a path dependency against RustSec, so
`scripts/check-lopdf-advisories.mjs` (CI job Governance) lists the RustSec
advisories filed for `lopdf` and fails on one that affects the vendored
version unless `reviewed_advisories` in
`docs/orcel/lopdf_provenance.json` names it with the reason it does not apply.
Run it by hand after any rebase of this copy.

The decode error stays `DecompressError::MemoryLimitExceeded` (with
`limit: 0` when the budget refuses the decode outright). lopdf's public
error types are unchanged, so pdf-inspector compiles against the patched
crate unmodified.

## P-03: no line the review gate's diff check refuses

The review gate runs `git diff --check` over the whole PR, and it refuses a
line that ends in whitespace. Upstream has such lines in two files: `src/reader.rs` (23) and `README.md`
(30). Each vendored file is upstream's with the spaces and tabs at the end of
each line removed, and no other change. `check-vendored-lopdf.mjs --upstream`
checks exactly that against the archive.

Neither change alters what the parser builds. The 23 lines in `reader.rs`
are cross-reference entries (`0000000009 00000 n `) inside string literals
of its `#[test]` functions (lines 1781 to 1963 upstream), which are compiled
only for lopdf's own tests. Those tests are not run here, and some of them
would now see 19-byte entries. `README.md` is only the crate's rustdoc text
(`src/lib.rs` includes it as `#![doc]`).

The checker now also fails on any vendored file with a line ending in
whitespace, so a re-pin cannot bring one back unnoticed.
