//! compat/orcel-provider-process/Cargo.toml builds crates/orcel-provider-process's
//! sources inside this workspace, so the release build doesn't depend on the
//! checkout path. It has to stay in step with the crate's own manifest and the
//! root workspace's package fields it inherits.

use std::path::Path;

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The value of `key = "..."` in the `[header]` table of a manifest.
fn field(manifest: &str, header: &str, key: &str) -> Option<String> {
    let mut in_table = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_table = line == header;
            continue;
        }
        if !in_table {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() == key {
            return Some(value.trim().trim_matches('"').to_string());
        }
    }
    None
}

/// The lines of a manifest's `[dependencies]` table that name a dependency.
fn dependencies(manifest: &str) -> Vec<String> {
    let mut in_table = false;
    let mut out = Vec::new();
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_table = line == "[dependencies]";
            continue;
        }
        if in_table && !line.is_empty() && !line.starts_with('#') {
            out.push(line.to_string());
        }
    }
    out
}

#[test]
fn the_in_workspace_provider_process_manifest_matches_the_crate() {
    let mirror = read("compat/orcel-provider-process/Cargo.toml");
    let crate_manifest = read("../../crates/orcel-provider-process/Cargo.toml");
    let root = read("../../Cargo.toml");

    assert_eq!(
        field(&mirror, "[package]", "name"),
        field(&crate_manifest, "[package]", "name")
    );
    for key in ["version", "edition", "license", "rust-version"] {
        assert_eq!(
            field(&crate_manifest, "[package]", &format!("{key}.workspace")).as_deref(),
            Some("true"),
            "crates/orcel-provider-process no longer inherits {key}; update this test"
        );
        assert_eq!(
            field(&mirror, "[package]", key),
            field(&root, "[workspace.package]", key),
            "compat/orcel-provider-process {key} differs from the root workspace's"
        );
    }
    assert_eq!(
        field(&mirror, "[lib]", "path").as_deref(),
        Some("../../../../crates/orcel-provider-process/src/lib.rs")
    );
    assert_eq!(dependencies(&mirror), dependencies(&crate_manifest));
}
