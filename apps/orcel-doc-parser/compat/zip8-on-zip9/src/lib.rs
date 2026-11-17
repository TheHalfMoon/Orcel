//! zip 9.6.1 under zip 8's name, for anydoc 0.2.2 (see README.md).
//!
//! Outside its tests, anydoc uses only `ZipArchive::new`, `len`, `by_name`,
//! `ZipFile::size`, `Read` on an entry and `result::ZipError::FileNotFound`.
//! Its tests also use `ZipWriter` and `write::SimpleFileOptions`. All of
//! these have the same shape in zip 9.6.1 as in zip 8, so a plain re-export
//! serves them. If a later anydoc needs an API that zip 9 changed, this crate
//! stops compiling. Behaviour cannot change silently.
#![forbid(unsafe_code)]

pub use zip9::*;
