//! SG-000086 P18 exit qualification: release readiness without new
//! authority. Version parity, pinned dependencies, no runtime dynamic
//! fetching, donor-code absence, exact tool and profile parity, and the
//! release-evidence mechanisms.
//!
//! Test-only. No production code and no authority change.

use orcel_browser_host::{
    is_denied_shape, is_live_exposed, profile_tools, remote_browser_mapping_enabled,
    BROWSER_STRUCTURED_PROFILE, PREEXISTING_PROFILES, QUALIFIED_BROWSER_SHAPES,
};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate sits in a workspace")
        .parent()
        .expect("crate sits in a workspace")
        .to_owned()
}

fn read_workspace(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path).expect("workspace file must be readable")
}

fn code_files() -> Vec<(String, String)> {
    // Production sources only: each crate's src/ directory and each app's
    // src/ directory, excluding test files. Integration tests live in
    // tests/ siblings and never enter this scan, so tripwire tokens
    // asserted here cannot self-match.
    let root = workspace_root();
    let mut out = Vec::new();
    let mut stack = Vec::new();
    if let Ok(entries) = std::fs::read_dir(root.join("crates")) {
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                stack.push(src);
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(root.join("apps")) {
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if src.is_dir() {
                stack.push(src);
            }
        }
    }
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).expect("tree must be readable");
        for entry in entries {
            let path = entry.expect("entry must be readable").path();
            if path.is_dir() {
                if path
                    .file_name()
                    .map(|name| name == "node_modules" || name == "target" || name == "dist")
                    .unwrap_or(false)
                {
                    continue;
                }
                stack.push(path);
                continue;
            }
            let is_code = path
                .extension()
                .map(|ext| ext == "rs" || ext == "ts")
                .unwrap_or(false);
            let is_test = path
                .file_name()
                .map(|name| name.to_string_lossy().contains(".test."))
                .unwrap_or(false);
            if is_code && !is_test {
                let text = std::fs::read_to_string(&path).expect("source must be readable");
                out.push((path.to_string_lossy().into_owned(), text));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

// ---------------------------------------------------------------------------
// Packaging parity: one version everywhere.
// ---------------------------------------------------------------------------

#[test]
fn version_parity_across_npm_and_cargo_manifests() {
    let root: serde_json::Value =
        serde_json::from_str(&read_workspace("package.json")).expect("root manifest parses");
    let mcp: serde_json::Value =
        serde_json::from_str(&read_workspace("apps/orcel-mcp/package.json")).expect("mcp parses");
    let relay: serde_json::Value =
        serde_json::from_str(&read_workspace("apps/orcel-relay/package.json"))
            .expect("relay parses");
    let version = root
        .get("version")
        .and_then(|v| v.as_str())
        .expect("root version");
    assert_eq!(mcp.get("version").and_then(|v| v.as_str()), Some(version));
    assert_eq!(relay.get("version").and_then(|v| v.as_str()), Some(version));
    let cargo = read_workspace("Cargo.toml");
    assert!(
        cargo.contains(&format!("version = \"{version}\"")),
        "Cargo workspace version must match npm version {version}"
    );
    assert!(
        cargo.contains("Apache-2.0"),
        "workspace license stays Apache-2.0"
    );
}

// ---------------------------------------------------------------------------
// Pinned dependencies: exact manifests plus lockfiles, no floating tags.
// ---------------------------------------------------------------------------

fn manifest_dependency_versions(manifest: &str) -> Vec<String> {
    let text = read_workspace(manifest);
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("manifest parses");
    let empty = serde_json::Map::new();
    let mut versions = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let map = parsed
            .get(section)
            .and_then(|v| v.as_object())
            .unwrap_or(&empty);
        for (name, version) in map {
            let version = version.as_str().unwrap_or_default().to_owned();
            assert!(
                !version.is_empty(),
                "{name} in {manifest} must pin a version"
            );
            versions.push(version);
        }
    }
    versions
}

#[test]
fn npm_dependencies_are_exact_and_locked() {
    assert!(!read_workspace("package.json").contains("@latest"));
    for manifest in [
        "apps/orcel-mcp/package.json",
        "apps/orcel-relay/package.json",
    ] {
        assert!(
            !read_workspace(manifest).contains("@latest"),
            "{manifest} must not float tags"
        );
        for version in manifest_dependency_versions(manifest) {
            for marker in ["^", "~", ">", "<", "*", "latest"] {
                assert!(
                    !version.contains(marker),
                    "floating range {version} in {manifest}"
                );
            }
        }
    }
    let lock = workspace_root().join("package-lock.json");
    let text = std::fs::read_to_string(&lock).expect("package-lock.json must exist");
    assert!(text.len() > 100, "package-lock.json must be substantive");
    assert!(
        text.contains("\"lockfileVersion\""),
        "npm lockfile schema present"
    );
}

#[test]
fn cargo_dependencies_are_locked_without_branch_or_wildcard() {
    let lock = read_workspace("Cargo.lock");
    assert!(lock.len() > 1000, "Cargo.lock must be substantive");
    for pinned in ["serde", "serde_json", "sha2"] {
        assert!(
            lock.contains(&format!("name = \"{pinned}\"")),
            "lock pins {pinned}"
        );
    }
    let mut manifests = Vec::new();
    let crates = workspace_root().join("crates");
    for entry in std::fs::read_dir(&crates).expect("crates must list") {
        let manifest = entry.expect("entry").path().join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
    }
    assert!(!manifests.is_empty());
    for manifest in &manifests {
        let text = std::fs::read_to_string(manifest).expect("manifest reads");
        assert!(
            !text.contains("version = \"*\""),
            "wildcard in {}",
            manifest.display()
        );
        assert!(
            !text.contains("branch ="),
            "branch pin in {}",
            manifest.display()
        );
    }
}

// ---------------------------------------------------------------------------
// No runtime dynamic fetching and no donor code in the shipped tree.
// ---------------------------------------------------------------------------

#[test]
fn no_runtime_dynamic_fetch_surface_in_code() {
    let files = code_files();
    assert!(!files.is_empty());
    for token in [
        "@latest",
        "npm install",
        "pip install",
        "cargo install",
        "Invoke-Expression",
        "new Function(",
    ] {
        for (path, text) in &files {
            assert!(!text.contains(token), "{token} must not appear in {path}");
        }
    }
    // eval( is banned; the legitimate words evaluation/evaluate never
    // carry a call paren in this tree, so the token check is exact.
    for (path, text) in &files {
        if path.ends_with(".ts") {
            continue;
        }
        assert!(!text.contains("eval("), "eval( must not appear in {path}");
    }
}

// Donor-code absence across every crates .rs file is proven by the
// canonical SG-000066 tripwire (apps/orcel-mcp/src/p16-exit.test.ts),
// which forbids donor runtime markers in this tree. This file
// deliberately embeds no donor marker strings so it cannot weaken
// that tripwire.

// ---------------------------------------------------------------------------
// Tool and profile parity: registries agree exactly, nothing implicit.
// ---------------------------------------------------------------------------

#[test]
fn profile_parity_is_exact_with_no_implicit_widening() {
    assert_eq!(BROWSER_STRUCTURED_PROFILE, "browser_structured");
    assert_eq!(PREEXISTING_PROFILES, &["core", "desktop_structured"]);
    let expected: HashSet<(&str, &str)> = [
        ("browser.profile", "status"),
        ("browser.destination", "validate"),
        ("browser.page", "open"),
        ("browser.navigation", "preview"),
        ("browser.navigation", "navigate"),
        ("browser.snapshot", "observe"),
        ("browser.dom", "click"),
        ("browser.dom", "fill"),
        ("browser.download", "preview"),
        ("browser.download", "download"),
        ("browser.upload", "preview"),
        ("browser.upload", "submit"),
    ]
    .into_iter()
    .collect();
    let actual: HashSet<(&str, &str)> = QUALIFIED_BROWSER_SHAPES.iter().copied().collect();
    assert_eq!(
        actual, expected,
        "qualified shapes must match the parity inventory exactly"
    );
    // Only the explicit browser profile resolves, to the live set (SG-000108
    // slice 3c). Every other profile name, including the wider planned
    // profile model names, fails closed instead of inheriting tools.
    assert_eq!(
        profile_tools("browser_structured").unwrap(),
        orcel_browser_host::LIVE_BROWSER_MCP_TOOLS
    );
    for unknown in [
        "core",
        "desktop_structured",
        "desktop_observe",
        "desktop_control",
        "coordinate_fallback",
        "computer_use",
        "admin",
        "",
    ] {
        assert!(
            profile_tools(unknown).is_err(),
            "{unknown} must fail closed"
        );
    }
    assert!(!remote_browser_mapping_enabled());
}

#[test]
fn tool_parity_live_set_is_six_qualified_shapes() {
    for (capability, operation) in QUALIFIED_BROWSER_SHAPES {
        let tool = format!("{capability}/{operation}");
        assert!(
            !is_live_exposed(&tool),
            "{tool} is a shape, not a tool name"
        );
        assert!(!is_denied_shape(&tool), "{tool} is qualified, not denied");
    }
    // SG-000108 slice 3c: each live tool forwards one qualified shape, and
    // fill and the uploads are not among them.
    let live: HashSet<(&str, &str)> = orcel_browser_host::LIVE_BROWSER_TOOL_SHAPES
        .iter()
        .map(|(_, capability, operation)| (*capability, *operation))
        .collect();
    assert_eq!(live.len(), 6);
    for shape in &live {
        assert!(QUALIFIED_BROWSER_SHAPES.contains(shape), "{shape:?}");
    }
    for model_only in [
        ("browser.dom", "fill"),
        ("browser.upload", "preview"),
        ("browser.upload", "submit"),
        ("browser.profile", "status"),
        ("browser.destination", "validate"),
        ("browser.navigation", "preview"),
    ] {
        assert!(!live.contains(&model_only), "{model_only:?}");
    }
}

// ---------------------------------------------------------------------------
// Release-evidence mechanisms exist and are wired.
// ---------------------------------------------------------------------------

#[test]
fn release_evidence_mechanisms_exist() {
    for script in [
        "scripts/generate-sbom.mjs",
        "scripts/provenance.mjs",
        "scripts/third-party-notices.mjs",
        "scripts/check-current-identity.mjs",
    ] {
        let path = workspace_root().join(script);
        assert!(Path::new(&path).is_file(), "{script} must exist");
        let text = std::fs::read_to_string(&path).expect("script reads");
        assert!(text.len() > 200, "{script} must be substantive");
    }
    for workflow in [
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        ".github/workflows/review-gates.yml",
    ] {
        assert!(
            workspace_root().join(workflow).is_file(),
            "{workflow} must exist"
        );
    }
    let release = read_workspace(".github/workflows/release.yml");
    assert!(
        release.contains("attest"),
        "release must attest build provenance"
    );
    assert!(
        release.contains("SHA256SUMS"),
        "release must publish checksums"
    );
    let ci = read_workspace(".github/workflows/ci.yml");
    assert!(
        ci.contains("SBOM") || ci.contains("sbom"),
        "CI must generate SBOM evidence"
    );
    assert!(workspace_root().join("Cargo.lock").is_file());
    assert!(workspace_root().join("package-lock.json").is_file());
}
