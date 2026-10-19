// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! macOS: point the host binary at the system Swift runtime.
//!
//! platform-macos links ScreenCaptureKit through the `screencapturekit`
//! crate, whose Swift bridge needs `@rpath/libswift_Concurrency.dylib`. That
//! crate's own `-rpath` link argument does not reach the final binary,
//! because Cargo applies `rustc-link-arg` only from the crate that is being
//! linked. Upstream Cua re-emits it from its binary crate
//! (`libs/cua-driver/rust/crates/cua-driver/build.rs` at the pin, blob
//! e26ecf9bbc4d15cf21231d3e8a9c1a4c26a037b6). This does the same for
//! `/usr/lib/swift` only, for every target of this package: the binary and
//! its test harnesses, which link platform-macos too. macOS 12 and later
//! ship the Swift runtime there (in the dyld shared cache). Upstream's extra
//! Xcode toolchain directories are left out: a shipped binary must not
//! search developer tool paths for libraries.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
    }
}
