//! Shared test fixtures. Every temp directory a test creates is unique per
//! process and per call: the pid plus a process-wide sequence number. A
//! clock-only suffix is not enough, because macOS clocks tick in
//! microseconds and parallel tests can read the same value, so one test's
//! cleanup would delete another test's workspace (#366).

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Creates and returns a fresh directory under the system temp dir.
pub(crate) fn unique_temp_dir(label: &str) -> PathBuf {
    let sequence = TEMP_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("{label}-{}-{sequence}", std::process::id()));
    // A leftover from an earlier run with a recycled pid must not leak in.
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create unique temp dir");
    dir
}
