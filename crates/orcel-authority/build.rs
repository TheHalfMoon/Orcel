//! SG-000132 install hardening: `orcel-authority.exe` runs elevated from
//! the staging folder (`orcel-authority install`). DLLs it imports
//! statically (wtsapi32, bcrypt, crypt32, ...) are not KnownDLLs, so the
//! loader would look for them in the program's own folder first, before
//! `main` can restrict anything. `/DEPENDENTLOADFLAG:0x800`
//! (LOAD_LIBRARY_SEARCH_SYSTEM32) makes the loader resolve this image's
//! imports from System32 only. The CI release build also links the C
//! runtime statically (`-C target-feature=+crt-static`), so no VC++ runtime
//! DLL is imported at all; `scripts/check-authority-binaries.ps1` checks both.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
    }
}
