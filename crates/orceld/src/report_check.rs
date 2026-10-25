//! SG-000126 (roadmap F2): the independent checker of a created report.
//!
//! It shares no code with the writer: it does not use the workspace file
//! provider, the task registry or the approval path. It re-opens the
//! destination with plain `std::fs` reads and passes only when
//!
//! - the destination is a regular file, not a link or reparse point;
//! - the folder is not a link or reparse point and the destination's
//!   parent canonicalizes to the folder's path recorded at start;
//! - its size and SHA-256 are exactly the approved ones;
//! - every source still hashes to the value the task recorded.
//!
//! A pass is the only way a report task becomes verified.

use crate::report_task::SourceRecord;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::Path;

/// The checker's name and revision in its records.
pub(crate) const CHECKER: &str = "orcel-report-check/1";
/// The largest source the checker re-reads; the provider's read limit.
const MAX_SOURCE_BYTES: u64 = 1024 * 1024;

/// What the created report must be.
pub(crate) struct Expectation<'a> {
    pub root: &'a Path,
    /// The folder's path in the workspace (not resolved).
    pub folder_path: &'a Path,
    /// The folder's canonical path as the task recorded it at start. It is
    /// compared as recorded, never resolved again.
    pub folder: &'a Path,
    /// Workspace-relative destination.
    pub destination: &'a str,
    pub sha256: &'a str,
    pub bytes: u64,
    pub sources: &'a [SourceRecord],
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(windows)]
pub(crate) fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(crate) fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

/// Reads at most `limit` bytes of a regular file that is not a link and
/// returns its SHA-256 and size.
pub(crate) fn hash_regular_file(path: &Path, limit: u64) -> Result<(String, u64), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| format!("inspect: {error}"))?;
    if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
        return Err("is a link or reparse point".into());
    }
    if !metadata.is_file() {
        return Err("is not a regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|error| format!("open: {error}"))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read: {error}"))?;
    if bytes.len() as u64 > limit {
        return Err(format!("is larger than {limit} bytes"));
    }
    Ok((hex(&Sha256::digest(&bytes)), bytes.len() as u64))
}

/// Checks the created report. `Ok` carries the check record; `Err` says
/// why the report does not verify.
pub(crate) fn check(expected: &Expectation<'_>) -> Result<serde_json::Value, String> {
    let path = expected.root.join(expected.destination);
    let (sha256, bytes) = hash_regular_file(&path, expected.bytes)
        .map_err(|reason| format!("the destination {reason}"))?;
    let parent = path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .ok_or("the destination's folder cannot be resolved")?;
    let folder = fs::symlink_metadata(expected.folder_path)
        .map_err(|error| format!("the task folder cannot be inspected: {error}"))?;
    if folder.file_type().is_symlink() || is_reparse_point(&folder) || !folder.is_dir() {
        return Err("the task folder is no longer a plain directory".into());
    }
    if parent != expected.folder {
        return Err("the destination is not in the task's folder".into());
    }
    if bytes != expected.bytes {
        return Err(format!(
            "the destination holds {bytes} bytes, {} were approved",
            expected.bytes
        ));
    }
    if sha256 != expected.sha256 {
        return Err("the destination's SHA-256 differs from the approved bytes".into());
    }
    for source in expected.sources {
        let (current, _) = hash_regular_file(&expected.root.join(&source.path), MAX_SOURCE_BYTES)
            .map_err(|reason| format!("source {} {reason}", source.path))?;
        if current != source.sha256 {
            return Err(format!(
                "source {} changed since the task observed it",
                source.path
            ));
        }
    }
    Ok(serde_json::json!({
        "checker": CHECKER,
        "passed": true,
        "destination": expected.destination,
        "bytes": bytes,
        "sha256": sha256,
        "sources_unchanged": expected.sources.len(),
        "checked_at_ms": orcel_approval::now_ms(),
    }))
}
