//! SG-000132 install hardening: `orcel-authority.exe` runs elevated from
//! the staging folder (`orcel-authority install`). A DLL that is not a
//! KnownDLL would otherwise be looked for in the program's own folder,
//! before `main` can restrict anything. Two link settings close that:
//!
//! - `/DEPENDENTLOADFLAG:0x800` (LOAD_LIBRARY_SEARCH_SYSTEM32): the DLLs
//!   this image imports directly are resolved from System32 only. It does
//!   NOT cover the imports of those DLLs (wtsapi32.dll imports SspiCli.dll,
//!   crypt32.dll imports msasn1.dll; neither is a KnownDLL).
//! - `/DELAYLOAD` for every directly imported DLL that is not a KnownDLL
//!   (wtsapi32, bcrypt, crypt32): they load on first use, after `main` has
//!   called SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32), which
//!   then also governs their own dependencies. What remains in the normal
//!   import table is KnownDLLs (kernel32, advapi32, oleaut32, ntdll) and
//!   API sets, which never come from the program's folder.
//!
//! The CI release build also links the C runtime statically
//! (`-C target-feature=+crt-static`), so no VC++ runtime DLL is imported at
//! all. `scripts/check-authority-binaries.ps1` checks all of this on the
//! artifact.

/// Directly imported DLLs that are not KnownDLLs: loaded on first use only.
const DELAY_LOADED: [&str; 3] = ["wtsapi32.dll", "bcrypt.dll", "crypt32.dll"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let windows = std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows");
    let msvc = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc");
    if windows && msvc {
        println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
        for dll in DELAY_LOADED {
            println!("cargo:rustc-link-arg-bins=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bins=delayimp.lib");
    }
}
