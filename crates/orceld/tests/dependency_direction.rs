//! WP1-01: the crate dependency direction of
//! `docs/orcel/implementation-readiness/prep/UNIFIED_INTEGRATION_SPEC.md`
//! section 3.2, enforced over `cargo metadata` of the main workspace.
//!
//! 1. No kernel crate (`crates/*`) depends on an `apps/*`, `tests/*`,
//!    `packages/*` or `third_party/*` unit, nor on an isolated component of
//!    `docs/orcel/notices/licence-policy.json`; every `crates/*` directory is
//!    a workspace member, so no crate escapes these rules.
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
//! 5. Every workspace crate's licence set (its own and its resolved
//!    dependencies', all targets, all features) passes the allowlist and
//!    named exceptions of the root `deny.toml`; every exception names a
//!    crate version that is in the graph (no stale exception).
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

/// The licence policy of the root `deny.toml`: the `[licenses]` allow list
/// and the per-crate exceptions.
#[derive(Debug, Default)]
struct LicencePolicy {
    allow: BTreeSet<String>,
    exceptions: BTreeMap<String, BTreeSet<String>>,
}

fn quoted(text: &str) -> Vec<String> {
    text.split('"')
        .enumerate()
        .filter(|(index, _)| index % 2 == 1)
        .map(|(_, value)| value.to_string())
        .collect()
}

fn parse_deny_toml(text: &str) -> LicencePolicy {
    let mut policy = LicencePolicy::default();
    let mut section = String::new();
    let mut in_allow = false;
    let mut in_exceptions = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && !in_allow && !in_exceptions {
            section = line.to_string();
            continue;
        }
        if section != "[licenses]" {
            continue;
        }
        if line.starts_with("allow = [") {
            in_allow = true;
        } else if line.starts_with("exceptions = [") {
            in_exceptions = true;
            continue;
        }
        if in_allow {
            policy.allow.extend(quoted(line));
            if line.ends_with(']') {
                in_allow = false;
            }
        } else if in_exceptions {
            if line == "]" {
                in_exceptions = false;
            } else if let Some(rest) = line.strip_prefix("{ crate = ") {
                let values = quoted(rest);
                if let Some((name, allowed)) = values.split_first() {
                    policy
                        .exceptions
                        .entry(name.clone())
                        .or_default()
                        .extend(allowed.iter().cloned());
                }
            }
        }
    }
    policy
}

/// True when an SPDX expression is satisfiable from `allowed`: `OR` (and
/// the legacy `/`) needs one branch, `AND` every branch, `A WITH B` the
/// exact pair. Malformed expressions are not satisfiable.
fn spdx_allowed(expression: &str, allowed: &BTreeSet<String>) -> bool {
    let spaced = expression
        .replace('(', " ( ")
        .replace(')', " ) ")
        .replace('/', " OR ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut index = 0;
    let result = spdx_or(&tokens, &mut index, allowed);
    matches!(result, Some(value) if index == tokens.len() && value)
}

fn spdx_or(tokens: &[&str], index: &mut usize, allowed: &BTreeSet<String>) -> Option<bool> {
    let mut value = spdx_and(tokens, index, allowed)?;
    while tokens.get(*index) == Some(&"OR") {
        *index += 1;
        let next = spdx_and(tokens, index, allowed)?;
        value = value || next;
    }
    Some(value)
}

fn spdx_and(tokens: &[&str], index: &mut usize, allowed: &BTreeSet<String>) -> Option<bool> {
    let mut value = spdx_primary(tokens, index, allowed)?;
    while tokens.get(*index) == Some(&"AND") {
        *index += 1;
        let next = spdx_primary(tokens, index, allowed)?;
        value = value && next;
    }
    Some(value)
}

fn spdx_primary(tokens: &[&str], index: &mut usize, allowed: &BTreeSet<String>) -> Option<bool> {
    let token = *tokens.get(*index)?;
    *index += 1;
    if token == "(" {
        let value = spdx_or(tokens, index, allowed)?;
        if tokens.get(*index) != Some(&")") {
            return None;
        }
        *index += 1;
        return Some(value);
    }
    if matches!(token, ")" | "AND" | "OR" | "WITH") {
        return None;
    }
    if tokens.get(*index) == Some(&"WITH") {
        let exception = *tokens.get(*index + 1)?;
        *index += 2;
        return Some(allowed.contains(&format!("{token} WITH {exception}")));
    }
    Some(allowed.contains(token))
}

struct Package<'a> {
    name: &'a str,
    version: &'a str,
    license: Option<&'a str>,
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
                license: value["license"].as_str(),
                dir,
                value,
            },
        );
    }
    out
}

/// Every rule above over one `cargo metadata` document. `contracts_sources`
/// holds `(path, text)` of `crates/orcel-contracts/src`; `crate_dirs` the
/// `crates/*` directories that hold a Cargo.toml; `isolated` the isolated
/// component paths; `separate` the separate workspaces that exist, with
/// whether each has its own `[workspace]` table and lockfile.
fn violations(
    meta: &Value,
    policy: &LicencePolicy,
    contracts_sources: &[(String, String)],
    crate_dirs: &[String],
    isolated: &[String],
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
                for component in isolated {
                    let component = normalize(component);
                    if target == component || target.starts_with(&format!("{component}/")) {
                        out.push(format!(
                            "rule 1: {} depends on the isolated component {component}",
                            member.name
                        ));
                    }
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

    // Rule 5: each member's licence set, over the resolved graph (dev edges
    // only from the member itself, as cargo resolves them).
    let mut edges: BTreeMap<&str, Vec<(&str, bool)>> = BTreeMap::new();
    for node in meta["resolve"]["nodes"].as_array().into_iter().flatten() {
        let id = node["id"].as_str().unwrap_or("");
        let deps = node["deps"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|dep| {
                let dev_only = dep["dep_kinds"].as_array().is_some_and(|kinds| {
                    !kinds.is_empty() && kinds.iter().all(|k| k["kind"].as_str() == Some("dev"))
                });
                (dep["pkg"].as_str().unwrap_or(""), dev_only)
            })
            .collect();
        edges.insert(id, deps);
    }
    for member in &members {
        let start = member.value["id"].as_str().unwrap_or("");
        let mut seen = BTreeSet::from([start]);
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            for (dep, dev_only) in edges.get(id).into_iter().flatten() {
                if (*dev_only && id != start) || !seen.insert(dep) {
                    continue;
                }
                stack.push(dep);
            }
        }
        for id in seen {
            let Some(package) = all.get(id) else {
                out.push(format!(
                    "rule 5: {} reaches unknown package {id}",
                    member.name
                ));
                continue;
            };
            let mut allowed = policy.allow.clone();
            for key in [
                package.name.to_string(),
                format!("{}@{}", package.name, package.version),
            ] {
                if let Some(extra) = policy.exceptions.get(&key) {
                    allowed.extend(extra.iter().cloned());
                }
            }
            match package.license {
                Some(license) if spdx_allowed(license, &allowed) => {}
                Some(license) => out.push(format!(
                    "rule 5: {} reaches {} {} under \"{license}\", not on the deny.toml allowlist",
                    member.name, package.name, package.version
                )),
                None => out.push(format!(
                    "rule 5: {} reaches {} {} with no declared licence",
                    member.name, package.name, package.version
                )),
            }
        }
    }
    for key in policy.exceptions.keys() {
        let used = all
            .values()
            .any(|p| *key == p.name || *key == format!("{}@{}", p.name, p.version));
        if !used {
            out.push(format!(
                "rule 5: deny.toml exception {key} matches no crate in the graph; remove it"
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

fn isolated_components(root: &Path) -> Vec<String> {
    let text = fs::read_to_string(root.join("docs/orcel/notices/licence-policy.json"))
        .expect("read licence-policy.json");
    let policy: Value = serde_json::from_str(&text).expect("licence-policy.json");
    policy["isolated_components"]
        .as_array()
        .expect("isolated_components array")
        .iter()
        .map(|c| {
            c["path"]
                .as_str()
                .expect("isolated component path")
                .to_string()
        })
        .collect()
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
    let deny = fs::read_to_string(root.join("deny.toml")).expect("read the root deny.toml");
    let policy = parse_deny_toml(&deny);
    assert!(
        policy.allow.contains("Apache-2.0") && policy.allow.contains("MIT"),
        "deny.toml allow list not read: {policy:?}"
    );
    let mut found = violations(
        &meta,
        &policy,
        &rust_sources(&root, "crates/orcel-contracts/src"),
        &crate_dirs(&root),
        &isolated_components(&root),
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

#[test]
fn the_deny_toml_allowlist_is_the_wp1_01_allowlist() {
    let deny = fs::read_to_string(repo_root().join("deny.toml")).unwrap();
    let policy = parse_deny_toml(&deny);
    let expected: BTreeSet<String> = [
        "Apache-2.0",
        "MIT",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "ISC",
        "Unicode-3.0",
        "Zlib",
        "0BSD",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(policy.allow, expected);
    // Every exception pins the crate version it was reviewed at.
    for krate in policy.exceptions.keys() {
        assert!(
            krate.contains('@'),
            "deny.toml exception {krate} must name crate@version"
        );
    }
    // MPL-2.0 only by named exception, and none of the refused families at all.
    for (krate, licences) in &policy.exceptions {
        for licence in licences {
            let upper = licence.to_uppercase();
            assert!(
                !["AGPL", "GPL", "LGPL", "SSPL", "BUSL", "FSL"]
                    .iter()
                    .any(|f| upper.starts_with(f)),
                "deny.toml exception {krate}: {licence} is a refused family"
            );
        }
    }
    let licence_policy: Value = serde_json::from_str(
        &fs::read_to_string(repo_root().join("docs/orcel/notices/licence-policy.json")).unwrap(),
    )
    .unwrap();
    let npm: BTreeSet<String> = licence_policy["allowed_licences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(
        npm, expected,
        "licence-policy.json and deny.toml must agree"
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

fn policy() -> LicencePolicy {
    parse_deny_toml("[licenses]\nallow = [\n  \"Apache-2.0\",\n  \"MIT\",\n]\n")
}

fn boost_policy() -> LicencePolicy {
    parse_deny_toml(
        "[licenses]\nallow = [\n  \"Apache-2.0\",\n  \"MIT\",\n]\nexceptions = [\n  { crate = \"boost\", allow = [\"BSL-1.0\"] },\n]\n",
    )
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
    violations(
        meta,
        &policy(),
        &[],
        &dirs,
        &["apps/firecrawl-sidecar/".into()],
        &[],
    )
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
fn a_kernel_crate_depending_on_an_app_or_isolated_component_fails() {
    let mut meta = sound_graph();
    meta["packages"][2]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(path_dep("orcel-mcp-bridge", "apps/orcel-mcp-bridge"));
    meta["packages"][2]["dependencies"]
        .as_array_mut()
        .unwrap()
        .push(path_dep("firecrawl-sidecar", "apps/firecrawl-sidecar"));
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
            .any(|v| v.contains("depends on the isolated component apps/firecrawl-sidecar")),
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
    let found = violations(&sound_graph(), &policy(), &sources, &[], &[], &[]);
    assert!(
        found.iter().any(|v| v
            .contains("platform code in orcel-contracts at crates/orcel-contracts/src/lib.rs:1")),
        "{found:?}"
    );
}

#[test]
fn an_agpl_dependency_anywhere_in_a_crates_graph_fails() {
    let mut meta = sound_graph();
    let agpl = registry_package("agpl-html", "AGPL-3.0-only");
    meta["packages"].as_array_mut().unwrap().push(agpl.clone());
    meta["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": agpl["id"], "deps": [] }));
    // serde -> agpl-html: reached transitively from every crate.
    let serde = meta["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["id"].as_str().unwrap().contains("#serde@"))
        .unwrap();
    serde["deps"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "pkg": agpl["id"], "dep_kinds": [{ "kind": null }] }));
    let found = check(&meta);
    for krate in ["orcel-contracts", "orcel-web", "orceld"] {
        assert!(
            found.iter().any(|v| v.starts_with(&format!(
                "rule 5: {krate} reaches agpl-html 1.0.0 under \"AGPL-3.0-only\""
            ))),
            "{krate}: {found:?}"
        );
    }
}

#[test]
fn licence_exceptions_are_per_crate_and_or_expressions_need_one_branch() {
    let allowed = policy().allow;
    assert!(spdx_allowed("MIT OR LGPL-2.1-or-later", &allowed));
    assert!(spdx_allowed("(MIT OR Apache-2.0) AND MIT", &allowed));
    assert!(spdx_allowed("MIT/Apache-2.0", &allowed));
    assert!(!spdx_allowed("MIT AND GPL-3.0-only", &allowed));
    assert!(!spdx_allowed("Apache-2.0 WITH LLVM-exception", &allowed));
    assert!(!spdx_allowed("MIT OR", &allowed));
    assert!(!spdx_allowed("(MIT", &allowed));

    let mut meta = sound_graph();
    for name in ["boost", "other-boost"] {
        let p = registry_package(name, "BSL-1.0");
        meta["packages"].as_array_mut().unwrap().push(p.clone());
        meta["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "id": p["id"], "deps": [] }));
        let orceld = meta["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|n| n["id"].as_str().unwrap().contains("#orceld@"))
            .unwrap();
        orceld["deps"]
            .as_array_mut()
            .unwrap()
            .push(json!({ "pkg": p["id"], "dep_kinds": [{ "kind": null }] }));
    }
    let found = violations(&meta, &boost_policy(), &[], &[], &[], &[]);
    assert_eq!(
        found,
        vec!["rule 5: orceld reaches other-boost 1.0.0 under \"BSL-1.0\", not on the deny.toml allowlist".to_string()]
    );
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
    let found = violations(&meta, &policy(), &[], &dirs, &[], &separate);
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

#[test]
fn a_stale_or_version_mismatched_deny_exception_fails() {
    let mut meta = sound_graph();
    let boost = registry_package("boost", "BSL-1.0");
    meta["packages"].as_array_mut().unwrap().push(boost.clone());
    meta["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "id": boost["id"], "deps": [] }));
    let orceld = meta["resolve"]["nodes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|n| n["id"].as_str().unwrap().contains("#orceld@"))
        .unwrap();
    orceld["deps"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "pkg": boost["id"], "dep_kinds": [{ "kind": null }] }));
    let pinned = parse_deny_toml(
        "[licenses]\nallow = [\"Apache-2.0\", \"MIT\"]\nexceptions = [\n  { crate = \"boost@1.0.0\", allow = [\"BSL-1.0\"] },\n  { crate = \"gone@2.0.0\", allow = [\"BSL-1.0\"] },\n]\n",
    );
    let found = violations(&meta, &pinned, &[], &[], &[], &[]);
    assert_eq!(
        found,
        vec![
            "rule 5: deny.toml exception gone@2.0.0 matches no crate in the graph; remove it"
                .to_string()
        ]
    );
    let wrong_version = parse_deny_toml(
        "[licenses]\nallow = [\"Apache-2.0\", \"MIT\"]\nexceptions = [\n  { crate = \"boost@0.9.0\", allow = [\"BSL-1.0\"] },\n]\n",
    );
    let found = violations(&meta, &wrong_version, &[], &[], &[], &[]);
    assert!(
        found
            .iter()
            .any(|v| v.contains("orceld reaches boost 1.0.0 under \"BSL-1.0\"")),
        "{found:?}"
    );
}
