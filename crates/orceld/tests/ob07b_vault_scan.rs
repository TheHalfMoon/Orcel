//! SG-000135 OB-07b: Orcel never handles a saved login.
//!
//! Decision (docs/orcel/implementation-readiness/prep/OB07B_VAULT_AUTOFILL.md):
//! the engine's debugging protocol has no password-manager command. Its
//! Autofill domain fills cards and addresses from data the caller supplies,
//! and its WebAuthn domain installs a virtual authenticator. Neither is a
//! way to let the browser's own vault fill a login without Orcel holding or
//! faking the secret, so a sign-in page is handed to the person (OB-07
//! `needs_you` kind `sign_in`), who types the password or picks the
//! browser's own saved one in a Visible window.
//!
//! This test pins that decision on the whole browser path (the browser host
//! crate, the session-state crate, the browser provider, every orceld
//! source, the Node worker and the MCP server): no source calls the
//! Autofill or WebAuthn domains, opens the engine's credential, autofill or
//! cookie stores, changes the password-manager preferences, reads or writes
//! cookies in bulk, or names a tool that would fill a login. Comments may
//! name them to say they are never used.

use std::path::{Path, PathBuf};

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// Calls and names that would let Orcel trigger, read or store a login.
const FORBIDDEN: &[&str] = &[
    // CDP domains: card and address autofill from caller data; a virtual
    // authenticator (excluded by SG-000135, never a passkey bypass).
    "Autofill.",
    "WebAuthn.",
    // The engine profile's credential, autofill and cookie stores.
    "Login Data",
    "Web Data",
    "\"Cookies\"",
    "os_crypt",
    "encrypted_key",
    // Password-manager preferences.
    "credentials_enable_service",
    "password_manager",
    "PasswordManager",
    // Bulk cookie reads and writes (a sign-in carried out of the browser).
    "getAllCookies",
    "Storage.getCookies",
    "Storage.setCookies",
    "Network.getCookies",
    "Network.setCookie",
    ".cookies(",
    "addCookies",
    "storageState",
    // Tool names a later packet must not add without a new decision.
    "browser_autofill",
    "browser_login",
    "browser_password",
    "browser_credential",
    "browser_sign_in",
];

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn sources(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|name| name == "node_modules" || name == "dist")
            {
                continue;
            }
            sources(&path, extension, out)?;
        } else if path.extension().is_some_and(|ext| ext == extension) {
            out.push(path);
        }
    }
    Ok(())
}

/// Whether `line` is a comment (doc or line comment), which may name the
/// forbidden calls to say they are never made.
fn is_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with('*') || trimmed.starts_with("/*")
}

fn is_ts_test(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        name.ends_with(".test.ts") || name.ends_with(".fixture.ts")
    })
}

/// Rust sources up to their first `#[cfg(test)]` module: tests may build
/// fake profile folders (for example a foreign `Local State`).
fn production_part(text: &str) -> &str {
    text.split("#[cfg(test)]").next().unwrap_or(text)
}

#[test]
fn ob07b_no_browser_path_source_triggers_reads_or_stores_a_saved_login() -> Outcome {
    let root = repo();
    let mut rust = Vec::new();
    for dir in [
        "crates/orcel-browser-host/src",
        "crates/orcel-browser-session/src",
        "crates/orcel-provider-browser/src",
        "crates/orceld/src",
    ] {
        sources(&root.join(dir), "rs", &mut rust)?;
    }
    for file in [
        "browser_broker.rs",
        "browser_full.rs",
        "browser_profiles.rs",
        "live_browser.rs",
        "live_dispatch.rs",
        "takeover_gate.rs",
    ] {
        let path = root.join("crates/orceld/src").join(file);
        assert!(rust.contains(&path), "{file} is scanned");
    }
    assert!(rust.len() > 60, "the Rust sources were found");
    let mut typescript = Vec::new();
    for dir in ["apps/orcel-browser-worker/src", "apps/orcel-mcp/src"] {
        let before = typescript.len();
        sources(&root.join(dir), "ts", &mut typescript)?;
        assert!(typescript.len() > before + 5, "{dir} sources were found");
    }
    typescript.retain(|path| !is_ts_test(path));

    let mut hits = Vec::new();
    let mut scan = |file: &Path, text: &str| {
        for (number, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            for call in FORBIDDEN {
                if line.contains(call) {
                    hits.push(format!("{}:{}: {call}", file.display(), number + 1));
                }
            }
        }
    };
    for file in &rust {
        let text = std::fs::read_to_string(file)?;
        // Test modules are in-file; this test file itself is not under src.
        scan(file, production_part(&text));
    }
    for file in &typescript {
        let text = std::fs::read_to_string(file)?;
        scan(file, &text);
    }
    assert!(
        hits.is_empty(),
        "saved-login handling on the browser path: {hits:#?}"
    );
    Ok(())
}

#[test]
fn ob07b_secret_fields_stay_refused_to_fill_and_type() -> Outcome {
    // The worker's secret-field rule (SG-000122, kept by SG-000135) is the
    // other half: no agent action may put a value into a password or
    // one-time-code field, so a credential enters only through the person
    // or the browser's own vault.
    let form =
        std::fs::read_to_string(repo().join("apps/orcel-browser-worker/src/actions/form.ts"))?;
    for selector in [
        ":not([type=\"password\" i])",
        ":not([autocomplete~=\"current-password\" i])",
        ":not([autocomplete~=\"new-password\" i])",
        ":not([autocomplete~=\"one-time-code\" i])",
    ] {
        assert!(form.contains(selector), "form.ts keeps {selector}");
    }
    Ok(())
}
