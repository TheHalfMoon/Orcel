// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Orcel native host for macOS and Linux (XP-05).
//!
//! Compile-only: the binary prints the host protocol version and exits. No
//! tool, listener, MCP server, daemon socket or browser is reachable from it.
//! orceld remains the sole authority; later tasks (XP-06 onward) add the
//! allowlisted adapter over orcel-computer-host/2.

/// The host protocol this binary will speak once it serves requests.
pub const PROTOCOL_VERSION: &str = "orcel-computer-host/2";

fn main() {
    println!("{PROTOCOL_VERSION}");
}
