// SPDX-License-Identifier: MIT
// Portions copyright (c) 2025 Cua AI, Inc.; modifications copyright Orcel.

//! Fallback for targets with no containment implementation.
//!
//! Launching an unconstrained child would be a silent downgrade of the
//! cross-platform containment contract, so the launch fails instead.
//! [`crate::containment::capabilities`] reports every boundary as absent, which
//! makes [`crate::containment::spawn`] fail closed before it ever reaches this
//! module.
//!
//! Provenance (T-CUA-22, COPY_ADAPT): adapted from
//! cua@a802eaf26ca97616a6bf0de6a29729a9346fbb1f
//! `libs/cua-driver/rust/crates/cua-driver-core/src/perception_client/containment/unsupported.rs`
//! (blob 2324f685ebcbb2fb050e1fd99ce02e515013d329), MIT. Orcel's changes: a
//! third stream type and `kill_tree`; messages name the contained process.

use std::path::Path;

use crate::containment::{
    unsupported_error, ContainError, ContainedChild, ContainmentLimits, FilesystemBoundary, RawExit,
};

/// Duplex streams stand in for the stdio pipes so the supervisor type-checks
/// on a target that never launches a child.
pub(crate) type ChildStdin = tokio::io::DuplexStream;
pub(crate) type ChildStdout = tokio::io::DuplexStream;
pub(crate) type ChildStderr = tokio::io::DuplexStream;

pub(crate) struct Guard;

impl Guard {
    pub(crate) fn note_reaped(&mut self) {}

    pub(crate) fn kill_tree(&mut self) {}

    pub(crate) fn memory_ceiling_exceeded(&self) -> bool {
        false
    }
}

pub(crate) struct Process;

impl Process {
    pub(crate) async fn wait(&mut self) -> std::io::Result<RawExit> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "this platform never launches a contained process",
        ))
    }
}

pub(crate) async fn spawn(
    _executable: &crate::pinned::PinnedExecutable,
    _args: &[String],
    _working_directory: &Path,
    _boundary: &FilesystemBoundary,
    _limits: &ContainmentLimits,
) -> Result<ContainedChild, ContainError> {
    Err(unsupported_error(
        "this platform cannot contain a process, so nothing is launched",
    ))
}
