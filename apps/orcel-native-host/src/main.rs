// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Orcel native host for macOS and Linux.
//!
//! XP-06: read-only desktop observation over the private stdio protocol
//! `orcel-computer-host/2`. orceld spawns this binary with no arguments and
//! talks to the supervisor over the inherited pipes; the supervisor runs
//! every observation in a one-shot `--worker` child. There is no listener,
//! no network client, no telemetry and no permission prompt. orceld remains
//! the sole authority: its registry allocates identities, redacts, bounds
//! and excludes protected surfaces again on everything this host reports.

mod capture;
mod cua_adapter;
mod map;
mod protocol;
mod supervisor;
mod worker;

use std::process::ExitCode;

/// The host protocol this binary speaks.
pub const PROTOCOL_VERSION: &str = protocol::PROTOCOL_V2;

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => supervisor::main(),
        [flag] if flag == "--worker" => worker::main(),
        [flag] if flag == "--version" => {
            println!("{PROTOCOL_VERSION}");
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: orcel-native-host [--version]");
            ExitCode::from(2)
        }
    }
}
