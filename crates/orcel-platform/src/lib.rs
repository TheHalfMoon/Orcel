//! Per-OS platform primitives shared by Orcel crates.
//!
//! `paths` resolves the per-user Orcel state root and verifies that it is
//! private, so protected state never lands in a world-shared directory.

pub mod paths;

pub use paths::PlatformError;
