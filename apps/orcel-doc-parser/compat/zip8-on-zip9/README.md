# anydoc's zip 8 requirement, served by zip 9.6.1

`anydoc` 0.2.2, the parser's Office converter, depends on `zip = "^8.6.0"`.
Every anydoc release up to 0.2.4 does. zip 8.6.0 carries four advisories
that are fixed only in zip 9:

- RUSTSEC-2026-0545: AES entries are read without the authentication-code
  check.
- RUSTSEC-2026-0546: `ZipArchive::extract` writes outside the destination
  through symlinks.
- RUSTSEC-2026-0547: the legacy Shrink, Reduce and Implode decoders
  preallocate the declared size.
- RUSTSEC-2026-0548: `ZipStreamReader` trusts local-header names over the
  central directory.

cargo audit fails the parser job on them.

This crate is Orcel's own, not a crates.io release. It is named `zip` at
version 8.6.0, so anydoc's requirement resolves to it through
`[patch.crates-io]` in `apps/orcel-doc-parser/Cargo.toml`. Its whole library
is `pub use zip9::*;`. `zip9` is zip 9.6.1 from crates.io with the parser's
own features (`default-features = false`, `deflate`). The parser's own
`zip = "=9.6.1"` requirement does not match version 8.6.0, so it resolves to
crates.io directly. Cargo.lock therefore carries one registry zip, 9.6.1,
which cargo audit checks. This path entry holds no zip code.

## Why the re-export is sound for anydoc

This is anydoc 0.2.2's zip use, read from its published source.
`Package::open` (`src/package/archive.rs`) builds the only `ZipArchive`, over
in-memory bytes. It checks `len()` against its entry-count limit and reads
entries with `by_name`, `size()` and a capped `Read`. It maps
`result::ZipError::FileNotFound` to an absent part. anydoc's other `zip::`
uses are `ZipWriter` and `write::SimpleFileOptions`, all in `#[cfg(test)]`
code. Each of these has the same signature in zip 9.6.1, so anydoc compiles
against the re-export unchanged, and its per-entry and whole-archive caps
apply as before. A future anydoc that uses an API zip 9 changed fails to
compile here. It cannot pick up different behaviour silently.

## When to remove it

When anydoc accepts zip 9, move the parser to that anydoc. Then delete this
directory and its `[patch.crates-io]` line, and check that Cargo.lock still
lists exactly one zip.
