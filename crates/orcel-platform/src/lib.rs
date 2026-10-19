//! Per-OS platform primitives shared by Orcel crates.
//!
//! `paths` resolves the per-user Orcel state root and verifies that it is
//! private, so protected state never lands in a world-shared directory.
//! `files` writes state files readable by their owner only.
//! `process`, `session` and `peer` (XP-03) give every OS the identity facts
//! the registry and local IPC bind to: a pid with its start generation, the
//! current user and login session, and the kernel-reported credentials of a
//! local socket peer.

pub mod files;
pub mod paths;
pub mod peer;
pub mod process;
pub mod session;

pub use paths::PlatformError;
pub use peer::PeerIdentity;
pub use process::ProcessGeneration;
pub use session::SessionIdentity;
