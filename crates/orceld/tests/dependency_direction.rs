//! WP1-01: the crate dependency direction of
//! `docs/orcel/implementation-readiness/prep/UNIFIED_INTEGRATION_SPEC.md`
//! section 3.2, enforced over `cargo metadata` of the main workspace.
//!
//! 1. No kernel crate (`crates/*`) depends on an `apps/*`, `tests/*`,
//!    `packages/*` or `third_party/*` unit; every `crates/*` directory is a
//!    workspace member, so no crate escapes these rules.
//! 2. `orcel-contracts` depends on `serde` and `serde_json` only (dev:
//!    `schemars`), has no target-specific dependency and no platform code:
//!    no `cfg(..)`, `cfg!(..)` or `cfg_attr(..)` naming `windows`, `unix` or
//!    a `target_*` key, in any form (`cfg(any(windows))`, multi-line, ...).
//! 3. `orcel-web` depends on `orcel-contracts` only and `orcel-jobs` on
//!    `orcel-contracts` and `orcel-journal` only (plus the section 7.2
//!    libraries), with no target-specific dependency. The diagram's "only"
//!    and "never" edges: `orcel-jobs`, `orcel-web` and `orcel-browser-host`
//!    are depended on by `orceld` alone, `orcel-journal` by `orcel-jobs` and
//!    `orceld`, `orcel-sidecar` by its listed users, `orceld` by nothing.
//! 4. The separate workspaces stay separate: none is a member here, each has
//!    its own `[workspace]` and lockfile, and tokio and V8 never enter this
//!    graph (AD-16).
//! 5. (Licence sets.) Not enforced: by the founder decision of 2026-11-17
//!    (`docs/orcel/grants/2026-11-17-founder-attestation.md`, owner-asserted)
//!    a licence type blocks nothing. CI reports licences with
//!    `cargo deny list`; this test checks architecture only.
//! 6. No registry dependency uses a wildcard version requirement (the root
//!    `deny.toml` leaves wildcards to this test, see its `[bans]`).
//! 7. Nothing redirects the graph around these rules: the root Cargo.toml
//!    has no `[patch]` or `[replace]`, a root `.cargo/config(.toml)` has no
//!    `[patch]` or `paths`, and every path package in the resolved graph
//!    lives under `crates/`.
//!
//! The metadata is read with every feature enabled, so feature-gated
//! dependencies are checked too.
//!
//! The rules are pure functions over the metadata JSON, so the negative
//! tests below feed them small hand-built graphs.

use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SEPARATE_WORKSPACES: &[&str] = &[
    "apps/orcel-contain",
    "apps/orcel-doc-parser",
    "apps/orcel-native-host",
    "third_party/obscura",
];

/// (crate, the only workspace crates that may depend on it).
const ONLY_CONSUMERS: &[(&str, &[&str])] = &[
    ("orcel-jobs", &["orceld"]),
    ("orcel-web", &["orceld"]),
    ("orcel-browser-host", &["orceld"]),
    ("orcel-journal", &["orcel-jobs", "orceld"]),
    (
        "orcel-sidecar",
        &[
            "orcel-provider-mobile",
            "orcel-fleet-report",
            "orcel-browser-host",
            "orceld",
        ],
    ),
    ("orceld", &[]),
];

/// (crate, allowed normal and build dependencies, allowed dev dependencies).
const CLOSED_DEPENDENCIES: &[(&str, &[&str], &[&str])] = &[
    ("orcel-contracts", &["serde", "serde_json"], &["schemars"]),
    (
        "orcel-web",
        &["orcel-contracts", "serde", "serde_json"],
        &["orcel-contracts", "serde", "serde_json"],
    ),
    (
        "orcel-jobs",
        &[
            "orcel-contracts",
            "orcel-journal",
            "serde",
            "serde_json",
            "sha2",
            "fs4",
        ],
        &[
            "orcel-contracts",
            "orcel-journal",
            "serde",
            "serde_json",
            "sha2",
            "fs4",
        ],
    ),
];

const FORBIDDEN_PACKAGES: &[&str] = &["tokio", "v8"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/").trim_end_matches('/').to_string()
}

/// A path relative to the workspace root, or the normalized absolute path
/// when it lies outside it.
fn relative(root: &str, path: &str) -> String {
    let root = normalize(root);
    let path = normalize(path);
    match path.strip_prefix(&format!("{root}/")) {
        Some(rest) => rest.to_string(),
        None if path == root => String::new(),
        None => path,
    }
}

struct Package<'a> {
    name: &'a str,
    version: &'a str,
    /// Directory of the manifest, relative to the workspace root.
    dir: String,
    value: &'a Value,
}

fn packages<'a>(meta: &'a Value, root: &str) -> BTreeMap<&'a str, Package<'a>> {
    let mut out = BTreeMap::new();
    for value in meta["packages"].as_array().into_iter().flatten() {
        let manifest = value["manifest_path"].as_str().unwrap_or("");
        let dir = relative(root, manifest)
            .trim_end_matches("Cargo.toml")
            .trim_end_matches('/')
            .to_string();
        out.insert(
            value["id"].as_str().unwrap_or(""),
            Package {
                name: value["name"].as_str().unwrap_or(""),
                version: value["version"].as_str().unwrap_or(""),
                dir,
                value,
            },
        );
    }
    out
}

/// Every rule above over one `cargo metadata` document. `contracts_sources`
/// holds `(path, text)` of `crates/orcel-contracts/src`; `crate_dirs` the
/// `crates/*` directories that hold a Cargo.toml; `separate` the separate
/// workspaces that exist, with
/// whether each has its own `[workspace]` table and lockfile.
fn violations(
    meta: &Value,
    contracts_sources: &[(String, String)],
    crate_dirs: &[String],
    separate: &[(String, bool)],
) -> Vec<String> {
    let mut out = Vec::new();
    let root = meta["workspace_root"].as_str().unwrap_or("");
    let all = packages(meta, root);
    let members: Vec<&Package> = meta["workspace_members"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|id| all.get(id.as_str().unwrap_or("")))
        .collect();
    let member_names: BTreeSet<&str> = members.iter().map(|p| p.name).collect();

    // Rule 1, and membership.
    for dir in crate_dirs {
        if !members.iter().any(|p| &p.dir == dir) {
            out.push(format!(
                "rule 1: {dir} is not a member of the main workspace"
            ));
        }
    }
    for member in &members {
        if !member.dir.starts_with("crates/") {
            out.push(format!(
                "rule 1: workspace member {} lives outside crates/ ({})",
                member.name, member.dir
            ));
        }
        for dep in member.value["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let name = dep["name"].as_str().unwrap_or("");
            if let Some(path) = dep["path"].as_str() {
                let target = relative(root, path);
                if !target.starts_with("crates/") {
                    out.push(format!(
                        "rule 1: {} depends on {name} at {target}, outside crates/",
                        member.name
                    ));
                }
            }
            // Rule 6.
            let registry = dep["source"]
                .as_str()
                .is_some_and(|s| s.starts_with("registry+") || s.starts_with("sparse+"));
            if registry && dep["req"].as_str().map(str::trim) == Some("*") {
                out.push(format!(
                    "rule 6: {} uses a wildcard version of {name}",
                    member.name
                ));
            }
        }
    }

    // Rules 2 and 3: closed dependency sets.
    for (krate, normal, dev) in CLOSED_DEPENDENCIES {
        let Some(member) = members.iter().find(|p| p.name == *krate) else {
            if crate_dirs.iter().any(|d| d == &format!("crates/{krate}")) {
                out.push(format!(
                    "rules 2-3: crates/{krate} exists but is not a member"
                ));
            }
            continue;
        };
        for dep in member.value["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let name = dep["name"].as_str().unwrap_or("");
            let kind = dep["kind"].as_str().unwrap_or("normal");
            let allowed = if kind == "dev" { dev } else { normal };
            if !allowed.contains(&name) {
                out.push(format!(
                    "rules 2-3: {krate} may not depend on {name} ({kind}); allowed: {}",
                    allowed.join(", ")
                ));
            }
            if let Some(target) = dep["target"].as_str() {
                out.push(format!(
                    "rules 2-3: {krate} has a target-specific dependency {name} ({target})"
                ));
            }
        }
    }
    for (path, text) in contracts_sources {
        for (line, cfg) in platform_cfgs(text) {
            out.push(format!(
                "rule 2: platform code in orcel-contracts at {path}:{line}: {cfg}"
            ));
        }
    }

    // Rule 3: the diagram's "only" edges.
    for member in &members {
        for dep in member.value["dependencies"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let name = dep["name"].as_str().unwrap_or("");
            if !member_names.contains(name) {
                continue;
            }
            if let Some((_, consumers)) = ONLY_CONSUMERS.iter().find(|(k, _)| *k == name) {
                if !consumers.contains(&member.name) {
                    out.push(format!(
                        "rule 3: {} may not depend on {name} (only: {})",
                        member.name,
                        if consumers.is_empty() {
                            "nothing in-process".to_string()
                        } else {
                            consumers.join(", ")
                        }
                    ));
                }
            }
        }
    }

    // Rule 4.
    for (dir, own_workspace) in separate {
        if members.iter().any(|p| p.dir.starts_with(dir.as_str())) {
            out.push(format!("rule 4: {dir} is a member of the main workspace"));
        }
        if !own_workspace {
            out.push(format!(
                "rule 4: {dir} must keep its own [workspace] and Cargo.lock"
            ));
        }
    }
    for package in all.values() {
        if FORBIDDEN_PACKAGES.contains(&package.name) {
            out.push(format!(
                "rule 4: {} {} is in the main workspace graph",
                package.name, package.version
            ));
        }
    }

    // Rule 7: every path package lives under crates/.
    for (id, package) in &all {
        if id.starts_with("path+") && !package.dir.starts_with("crates/") {
            out.push(format!(
                "rule 7: path package {} at {} is in the main graph, outside crates/",
                package.name, package.dir
            ));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Rule 7: `[patch]` or `[replace]` in the root manifest, or `[patch]` or
/// `paths` in a root `.cargo/config(.toml)`, would let a dependency be
/// swapped without the graph above showing it.
fn graph_overrides(manifest: &str, configs: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    let table = |line: &str| line.split('#').next().unwrap_or("").trim().to_string();
    for line in manifest.lines().map(table) {
        if line.starts_with("[patch") || line.starts_with("[replace") {
            out.push(format!("rule 7: the root Cargo.toml has {line}"));
        }
    }
    for (path, text) in configs {
        for line in text.lines().map(table) {
            if line.starts_with("[patch") || line.starts_with("paths") {
                out.push(format!("rule 7: {path} has {line}"));
            }
        }
    }
    out
}

/// `(line, text)` of every `cfg(..)`, `cfg!(..)` or `cfg_attr(..)` in `code`
/// that names a platform, with comments removed first.
fn platform_cfgs(text: &str) -> Vec<(usize, String)> {
    const PLATFORM: &[&str] = &[
        "windows",
        "unix",
        "target_os",
        "target_family",
        "target_arch",
        "target_env",
        "target_vendor",
        "target_pointer_width",
        "target_endian",
        "target_has_atomic",
    ];
    let code: String = text
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = code.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find("cfg") {
        let start = from + at;
        from = start + 3;
        let before_ok =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let mut open = start + 3;
        if code[open..].starts_with("_attr") {
            open += 5;
        } else if code[open..].starts_with('!') {
            open += 1;
        }
        while open < bytes.len() && bytes[open].is_ascii_whitespace() {
            open += 1;
        }
        if !before_ok || bytes.get(open) != Some(&b'(') {
            continue;
        }
        let mut depth = 0usize;
        let mut end = open;
        for (offset, ch) in code[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        // String literals ("windows-names" in a feature name) are not keys.
        let mut inner = String::new();
        let mut quoted = false;
        for ch in code[open..=end.max(open)].chars() {
            if ch == '"' {
                quoted = !quoted;
            } else if !quoted {
                inner.push(ch);
            }
        }
        let names_platform = inner
            .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .any(|token| PLATFORM.contains(&token));
        if names_platform {
            let line = code[..start].matches('\n').count() + 1;
            out.push((line, code[start..=end.max(open)].replace('\n', " ")));
        }
    }
    out
}

/// The main workspace's metadata with every feature, for every platform (no
/// `--filter-platform`: the rules hold for all three OS legs at once).
/// `--locked` keeps the resolution to Cargo.lock, but cargo may still fetch
/// the index and crate manifests it lacks; CI fetches them anyway, and
/// nothing is compiled.
fn cargo_metadata(root: &Path) -> Value {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--all-features",
        ])
        .current_dir(root)
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata JSON")
}

fn rust_sources(root: &Path, dir: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.join(dir)];
    while let Some(path) = stack.pop() {
        for entry in fs::read_dir(&path).expect("read source directory") {
            let entry = entry.expect("directory entry");
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = fs::read_to_string(&path).expect("read source");
                let rel = normalize(&path.strip_prefix(root).unwrap().to_string_lossy());
                out.push((rel, text));
            }
        }
    }
    out
}

fn crate_dirs(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(root.join("crates"))
        .expect("read crates/")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.join("Cargo.toml").is_file())
        .map(|p| format!("crates/{}", p.file_name().unwrap().to_string_lossy()))
        .collect();
    out.sort();
    out
}

fn separate_workspaces(root: &Path) -> Vec<(String, bool)> {
    SEPARATE_WORKSPACES
        .iter()
        .filter(|dir| root.join(dir).join("Cargo.toml").is_file())
        .map(|dir| {
            let manifest = fs::read_to_string(root.join(dir).join("Cargo.toml")).unwrap();
            let own = manifest.lines().any(|l| l.trim() == "[workspace]")
                && root.join(dir).join("Cargo.lock").is_file();
            (dir.to_string(), own)
        })
        .collect()
}

#[test]
fn the_main_workspace_keeps_the_section_3_2_dependency_direction() {
    let root = repo_root();
    let meta = cargo_metadata(&root);
    let mut found = violations(
        &meta,
        &rust_sources(&root, "crates/orcel-contracts/src"),
        &crate_dirs(&root),
        &separate_workspaces(&root),
    );
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read the root Cargo.toml");
    let configs: Vec<(String, String)> = [".cargo/config.toml", ".cargo/config"]
        .iter()
        .filter_map(|path| {
            fs::read_to_string(root.join(path))
                .ok()
                .map(|text| (path.to_string(), text))
        })
        .collect();
    found.extend(graph_overrides(&manifest, &configs));
    assert!(
        found.is_empty(),
        "section 3.2 violations:\n{}",
        found.join("\n")
    );
}

// ------------------------------------------------------------ negatives

const ROOT: &str = "/w";

fn package(name: &str, license: &str, deps: Value) -> Value {
    json!({
        "id": format!("path+file:///w/crates/{name}#{name}@0.1.0"),
        "name": name,
        "version": "0.1.0",
        "license": license,
        "manifest_path": format!("/w/crates/{name}/Cargo.toml"),
        "source": null,
        "dependencies": deps,
    })
}

fn path_dep(name: &str, dir: &str) -> Value {
    json!({ "name": name, "req": "*", "kind": null, "target": null, "source": null, "path": format!("/w/{dir}") })
}

fn registry_dep(name: &str, req: &str) -> Value {
    json!({ "name": name, "req": req, "kind": null, "target": null,
            "source": "registry+https://github.com/rust-lang/crates.io-index" })
}

fn registry_package(name: &str, license: &str) -> Value {
    json!({
        "id": format!("registry+https://github.com/rust-lang/crates.io-index#{name}@1.0.0"),
        "name": name, "version": "1.0.0", "license": license,
        "manifest_path": format!("/home/.cargo/registry/src/{name}-1.0.0/Cargo.toml"),
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "dependencies": [],
    })
}

/// A metadata document: `members` are workspace crates, `others` registry
/// packages; `edges` are (from, to) by name for the resolve graph.
fn metadata(members: Vec<Value>, others: Vec<Value>, edges: &[(&str, &str)]) -> Value {
    let all: Vec<Value> = members.iter().chain(others.iter()).cloned().collect();
    let id_of = |name: &str| -> String {
        all.iter()
            .find(|p| p["name"] == name)
            .map(|p| p["id"].as_str().unwrap().to_string())
            .unwrap_or_else(|| panic!("no package {name}"))
    };
    let nodes: Vec<Value> = all
        .iter()
        .map(|p| {
            let name = p["name"].as_str().unwrap();
            let deps: Vec<Value> = edges
                .iter()
                .filter(|(from, _)| *from == name)
                .map(|(_, to)| json!({ "pkg": id_of(to), "dep_kinds": [{ "kind": null }] }))
                .collect();
            json!({ "id": p["id"], "deps": deps })
        })
        .collect();
    json!({
        "workspace_root": ROOT,
        "workspace_members": members.iter().map(|p| p["id"].clone()).collect::<Vec<_>>(),
        "packages": all,
        "resolve": { "nodes": nodes },
    })
}

fn check(meta: &Value) -> Vec<String> {
    let dirs: Vec<String> = meta["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| {
            let name = id.as_str().unwrap().rsplit('#').next().unwrap();
            format!("crates/{}", name.split('@').next().unwrap())
        })
        .collect();
    violations(meta, &[], &dirs, &[])
}

fn sound_graph() -> Value {
    metadata(
        vec![
            package(
                "orcel-contracts",
                "Apache-2.0",
                json!([registry_dep("serde", "1")]),
            ),
            package(
                "orcel-web",
                "Apache-2.0",
                json!([path_dep("orcel-contracts", "crates/orcel-contracts")]),
            ),
            package(
                "orceld",
                "Apache-2.0",
                json!([
                    path_dep("orcel-web", "crates/orcel-web"),
                    path_dep("orcel-contracts", "crates/orcel-contracts")
                ]),
            ),
        ],
        vec![registry_package("serde", "MIT OR Apache-2.0")],
        &[
            ("orcel-contracts", "serde"),
            ("orcel-web", "orcel-contracts"),
            ("orceld", "orcel-web"),
            ("orceld", "orcel-contracts"),
        ],
    )
}

#[test]
fn a_sound_graph_passes() {
    assert_eq!(check(&sound_graph()), Vec::<String>::new());
}

#[test]
fn a_forbidden_dependency_edge_fails() {
    let mut meta = sound_graph();
    // orcel-web -> orcel-browser-host: orcel-web is pure, and browser-host is
    // orceld's alone.
    let host = package("orcel-browser-host", "Apache-2.0", json!([]));
    meta["packages"].as_array_mut().unwrap().push(host.clone());
    meta["workspace_members"]
        .as_array_mut()
        .unwrap()
        .push(host["id"].clone());
    meta["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": host["id"], "deps": [] }));
    meta["packages"][1]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(path_dep("orcel-browser-host", "crates/orcel-browser-host"));
    let found = check(&meta);
    assert!(
        found
            .iter()
            .any(|v| v.contains("orcel-web may not depend on orcel-browser-host")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v
                .contains("rule 3: orcel-web may not depend on orcel-browser-host (only: orceld)")),
        "{found:?}"
    );
}

#[test]
fn a_kernel_crate_depending_on_an_app_fails() {
    let mut meta = sound_graph();
    meta["packages"][2]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(path_dep("orcel-mcp-bridge", "apps/orcel-mcp-bridge"));
    meta["packages"][2]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(path_dep("firecrawl", "apps/orcel-firecrawl"));
    let found = check(&meta);
    assert!(
        found
            .iter()
            .any(|v| v
                .contains("rule 1: orceld depends on orcel-mcp-bridge at apps/orcel-mcp-bridge")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v.contains("rule 1: orceld depends on firecrawl at apps/orcel-firecrawl")),
        "{found:?}"
    );
}

#[test]
fn anything_depending_on_orceld_fails() {
    let mut meta = sound_graph();
    meta["packages"][1]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(path_dep("orceld", "crates/orceld"));
    let found = check(&meta);
    assert!(
        found
            .iter()
            .any(|v| v.contains("orcel-web may not depend on orceld (only: nothing in-process)")),
        "{found:?}"
    );
}

#[test]
fn contracts_gaining_a_dependency_or_platform_code_fails() {
    let mut meta = sound_graph();
    meta["packages"][0]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(registry_dep("libc", "0.2"));
    let found = check(&meta);
    assert!(
        found
            .iter()
            .any(|v| v.contains("orcel-contracts may not depend on libc")),
        "{found:?}"
    );
    let sources = vec![(
        "crates/orcel-contracts/src/lib.rs".to_string(),
        "#[cfg(target_os = \"windows\")]\nfn f() {}\n".to_string(),
    )];
    let found = violations(&sound_graph(), &sources, &[], &[]);
    assert!(
        found.iter().any(|v| v
            .contains("platform code in orcel-contracts at crates/orcel-contracts/src/lib.rs:1")),
        "{found:?}"
    );
}

#[test]
fn a_dependency_licence_is_not_judged() {
    // Founder decision of 2026-11-17: licences block nothing. An AGPL,
    // unlicensed or commercial crate reached from every kernel crate leaves
    // the architecture rules satisfied.
    let mut meta = sound_graph();
    for (name, license) in [
        ("agpl-html", "AGPL-3.0-only"),
        ("vendor-sdk", "LicenseRef-Commercial"),
    ] {
        let p = registry_package(name, license);
        meta["packages"].as_array_mut().unwrap().push(p.clone());
        meta["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "id": p["id"], "deps": [] }));
    }
    let mut unlicensed = registry_package("no-licence", "MIT");
    unlicensed["license"] = Value::Null;
    meta["packages"].as_array_mut().unwrap().push(unlicensed);
    assert_eq!(check(&meta), Vec::<String>::new());
}

#[test]
fn tokio_in_the_main_graph_and_wildcard_registry_requirements_fail() {
    let mut meta = sound_graph();
    meta["packages"]
        .as_array_mut()
        .unwrap()
        .push(registry_package("tokio", "MIT"));
    meta["packages"][2]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(registry_dep("tokio", "*"));
    let found = check(&meta);
    assert!(
        found
            .iter()
            .any(|v| v.contains("rule 4: tokio 1.0.0 is in the main workspace graph")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v.contains("rule 6: orceld uses a wildcard version of tokio")),
        "{found:?}"
    );
}

#[test]
fn a_crate_outside_the_workspace_or_a_merged_separate_workspace_fails() {
    let meta = sound_graph();
    let dirs = vec![
        "crates/orcel-contracts".to_string(),
        "crates/orcel-web".to_string(),
        "crates/orceld".to_string(),
        "crates/orcel-stray".to_string(),
    ];
    let separate = vec![("apps/orcel-doc-parser".to_string(), false)];
    let found = violations(&meta, &[], &dirs, &separate);
    assert!(
        found
            .iter()
            .any(|v| v.contains("rule 1: crates/orcel-stray is not a member")),
        "{found:?}"
    );
    assert!(
        found
            .iter()
            .any(|v| v.contains("rule 4: apps/orcel-doc-parser must keep its own [workspace]")),
        "{found:?}"
    );
}

#[test]
fn rule_2_catches_every_platform_cfg_form() {
    let caught = [
        "#[cfg(windows)]",
        "#[cfg(any(windows))]",
        "#[cfg(all(unix, not(target_os = \"macos\")))]",
        "#[cfg_attr(target_family = \"wasm\", allow(dead_code))]",
        "let wide = cfg!(target_pointer_width = \"64\");",
        "if cfg! (unix) {}",
        "#[cfg(\n    any(\n        windows,\n    )\n)]",
        "#[cfg(target_arch = \"x86_64\")]",
    ];
    for code in caught {
        assert_eq!(platform_cfgs(code).len(), 1, "not caught: {code}");
    }
    let multi = platform_cfgs("fn a() {}\n#[cfg(\n  any(windows)\n)]\nfn b() {}\n");
    assert_eq!(multi[0].0, 2);
    let clean = [
        "#[cfg(test)]",
        "#[cfg(feature = \"windows-names\")]",
        "// #[cfg(windows)] only in a comment",
        "let config = 1; // cfg(windows) mentioned",
        "fn mycfg(unix: bool) {}",
    ];
    for code in clean {
        assert!(platform_cfgs(code).is_empty(), "false positive: {code}");
    }
}

#[test]
fn patch_replace_and_cargo_config_paths_are_refused() {
    let manifest = "[workspace]\nmembers = []\n\n[patch.crates-io]\nserde = { path = \"../serde\" }\n[replace]\n\"a:1.0.0\" = { path = \"x\" }\n";
    let configs = vec![(
        ".cargo/config.toml".to_string(),
        "paths = [\"../fork\"]\n[patch.crates-io]\n".to_string(),
    )];
    let found = graph_overrides(manifest, &configs);
    assert_eq!(found.len(), 4, "{found:?}");
    assert!(graph_overrides("[workspace]\n# [patch] in a comment\n", &[]).is_empty());
}

#[test]
fn a_path_package_outside_crates_in_the_graph_fails() {
    let mut meta = sound_graph();
    let stray = json!({
        "id": "path+file:///w/apps/shim#shim@0.1.0",
        "name": "shim", "version": "0.1.0", "license": "MIT",
        "manifest_path": "/w/apps/shim/Cargo.toml", "source": null, "dependencies": [],
    });
    meta["packages"].as_array_mut().unwrap().push(stray);
    let found = check(&meta);
    assert!(
        found
            .iter()
            .any(|v| v.contains("rule 7: path package shim at apps/shim is in the main graph")),
        "{found:?}"
    );
}
