//! SG-000072 repository-wide release-blocker sweep. Fails on any TODO, FIXME,
//! HACK, or XXX marker in code, any todo!/unimplemented! macro, any panic! or
//! unreachable! in non-test code (except the single documented guarded match),
//! focused-test modifiers, console/debugger output, mocks in non-test code,
//! secret-shaped literals outside the exact allowlisted redaction/test
//! vectors, unexpected ignored tests, or unexpected workflows. Any new hit
//! fails the suite until it is fixed at its root or explicitly allowlisted
//! here with a reason.
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn is_test_file(relative: &str) -> bool {
    relative.ends_with(".test.ts")
        || relative.ends_with(".test.js")
        || relative.ends_with(".test.mjs")
        || relative.ends_with("tests.rs")
        || relative.contains("tests/")
        || relative.contains("sg000")
        || relative.starts_with("crates/")
            && (relative.contains("_tests.rs") || relative.contains("/tests/"))
        || relative.contains("examples/")
}

/// XP-05 vendored Cua Driver crates (trycua/cua@a802eaf2, MIT). Their bytes
/// are upstream's: CI (`scripts/check-vendored-cua.mjs`) proves every
/// unpatched file is identical to the pinned tree, and the only edits allowed
/// are the reviewed queue in `third_party/cua-driver/PATCHES.md`. Upstream's
/// own TODO comments, panic!/unreachable! calls, "mock" identifiers and
/// `#[ignore]` desktop tests cannot be rewritten without breaking that proof,
/// so the marker, panic/unreachable/mock and ignored-test rules skip this one
/// prefix. Every other rule (focused tests, console output, secrets, the
/// live-browser feature, workflows) still applies to it, and nothing outside
/// it is exempt. Files the patch queue changes or adds are not trusted this
/// way: `patched_vendored_files_add_no_release_blockers` holds them to these
/// rules, allowing only the upstream lines the provenance records.
const VENDORED_CUA: &str = "apps/orcel-native-host/third_party/cua-driver/crates/";
const CUA_PROVENANCE: &str = "docs/orcel/cua_driver_provenance.json";
/// #391 vendored lopdf 0.45.0 (crates.io, MIT), under the same terms as the
/// Cua crates: CI (`scripts/check-vendored-lopdf.mjs`) proves every
/// unpatched file is the crates.io release's, and its patch queue
/// (`third_party/lopdf/PATCHES.md`) is held to these rules below.
const VENDORED_LOPDF: &str = "apps/orcel-doc-parser/third_party/lopdf/";
const LOPDF_PROVENANCE: &str = "docs/orcel/lopdf_provenance.json";

fn vendored(relative: &str) -> bool {
    relative.starts_with(VENDORED_CUA) || relative.starts_with(VENDORED_LOPDF)
}

/// Every vendored file the patch queues change or add, with the SHA-256 of
/// each upstream line in it that a rule below flags (an added file has none).
fn patched_vendored_files(root: &Path) -> BTreeMap<String, Vec<String>> {
    let mut out = BTreeMap::new();
    for path in [CUA_PROVENANCE, LOPDF_PROVENANCE] {
        patched_files_of(root, path, &mut out);
    }
    out
}

fn patched_files_of(root: &Path, path: &str, out: &mut BTreeMap<String, Vec<String>>) {
    let text = fs::read_to_string(root.join(path)).expect("read vendored provenance");
    let provenance: serde_json::Value = serde_json::from_str(&text).expect("provenance JSON");
    for krate in provenance["crates"].as_array().expect("provenance crates") {
        let destination = krate["destination"].as_str().expect("crate destination");
        for file in krate["patched_files"].as_array().into_iter().flatten() {
            let digests = file["upstream_blocker_lines"]
                .as_array()
                .expect("patched file records its upstream_blocker_lines")
                .iter()
                .map(|digest| digest.as_str().expect("digest").to_owned())
                .collect();
            let path = file["path"].as_str().expect("patched path");
            out.insert(format!("{destination}/{path}"), digests);
        }
        for file in krate["added_files"].as_array().into_iter().flatten() {
            let path = file["path"].as_str().expect("added path");
            out.insert(format!("{destination}/{path}"), Vec::new());
        }
    }
}

/// The union of the marker, panic/unreachable/mock and ignored-test rules for
/// one line, as the tests below apply them.
fn blocker_line(relative: &str, line: &str) -> bool {
    let code = code_file(relative);
    let rust = relative.ends_with(".rs");
    let non_test = code && !is_test_file(relative);
    (code && (contains_marker(line) || line.contains("todo!") || line.contains("unimplemented!")))
        || (non_test && rust && (line.contains("panic!") || line.contains("unreachable!")))
        || (non_test && line.to_lowercase().contains("mock"))
        || (rust && line.contains("#[ignore"))
}

fn text_files(root: &Path) -> Vec<(String, String)> {
    // The gate never scans itself: its allowlists name the exact vectors, and
    // the gate definition is reviewed as ordinary PR diff instead.
    const SELF: &str = "crates/orcel-lifecycle/tests/release_blocker_sweep.rs";
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries =
            fs::read_dir(&dir).unwrap_or_else(|err| panic!("read {}: {err}", dir.display()));
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if path.is_dir() {
                if matches!(name.as_str(), ".git" | "target" | "node_modules" | "dist") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if relative.ends_with(".lock") || relative == "package-lock.json" || relative == SELF {
                continue;
            }
            let bytes = fs::read(&path).unwrap_or_default();
            if bytes.len() > 1_000_000 || bytes.iter().take(8192).any(|b| *b == 0) {
                continue;
            }
            if let Ok(text) = String::from_utf8(bytes) {
                out.push((relative, text));
            }
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn code_file(relative: &str) -> bool {
    matches!(
        Path::new(relative).extension().and_then(|e| e.to_str()),
        Some(
            "rs" | "ts"
                | "mts"
                | "cts"
                | "js"
                | "mjs"
                | "cjs"
                | "ps1"
                | "py"
                | "sh"
                | "toml"
                | "yaml"
                | "yml"
                | "json"
                | "jsonc"
        )
    )
}

/// (path, allowed line substring) pairs. Every other hit fails the gate.
fn marker_allowlist() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut map: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    map.insert(
        "distribution/openai/review/test-cases.json",
        vec!["Find every line that mentions TODO"],
    );
    map.insert(
        "distribution/openai/plugin.config.json",
        vec!["Find every TODO in the src folder."],
    );
    map.insert(
        "docs/security/RELEASE_SECURITY_REVIEW.md",
        vec!["no `TODO`, `FIXME`, `XXX`, `HACK`, `todo!()`, or `unimplemented!()` in code"],
    );
    map
}

fn secret_allowlist() -> BTreeMap<&'static str, Vec<&'static str>> {
    let mut map: BTreeMap<&'static str, Vec<&'static str>> = BTreeMap::new();
    map.insert(
        "apps/orcel-mcp/src/client-examples.test.ts",
        vec![r#"!text.includes("BEGIN PRIVATE")"#],
    );
    map.insert(
        "apps/orcel-mcp/src/openai-plugin.test.ts",
        vec!["-----BEGIN PRIVATE KEY-----"],
    );
    map.insert(
        "apps/orcel-mcp/src/git_push.test.ts",
        vec!["ghp_rawtoken123"],
    );
    map.insert("crates/orcel-tunnel/src/lib.rs", vec!["sk-proj-test"]);
    // Made-up keys that test the approval preview's credential check.
    map.insert(
        "crates/orceld/src/fs_mutation.rs",
        vec![
            "\"OPENAI=sk-proj-abcdefghijklmnop123\",",
            "\"github_pat_11ABCDEFG0123456789_abcdef\",",
            "\"token ghp_abcdefghijklmnopqrstuvwxyz0123\",",
        ],
    );
    map.insert(
        "crates/orcel-provider-clipboard/src/lib.rs",
        vec!["\"sk-live-\""],
    );
    map.insert(
        "crates/orcel-provider-clipboard/src/tests.rs",
        vec!["concat!(\"ghp_\""],
    );
    map.insert(
        "crates/orcel-lifecycle/src/logs.rs",
        vec![
            "&[(\"github_pat_\", 16), (\"sess-\", 8), (\"ghp_\", 16), (\"sk-\", 8)]",
            "connect api_key=sk-proj-abcdef123456",
            "&[\"sk-proj-abcdef123456\", \"abc\", \"xyz.123\", \"sk-1234567890ab\"]",
            "key=sk-proj-abcdef123456",
            "\"OPENAI_API_KEY=sk-proj-abcdef123456\",",
            "&[\"sk-proj-abcdef123456\"],",
        ],
    );
    map.insert(
        "crates/orcel-policy/src/sg000017.rs",
        vec!["ghp_rawtoken123"],
    );
    map.insert(
        "crates/orcel-provider-git/src/push.rs",
        vec!["\"ghp_abcdef123456\""],
    );
    map.insert(
        "crates/orcel-lifecycle/tests/release_qualification.rs",
        vec!["sk-release-qualification-key-0123456789"],
    );
    map
}

fn allowed(allowlist: &BTreeMap<&str, Vec<&str>>, path: &str, line: &str) -> bool {
    allowlist
        .get(path)
        .map(|subs| subs.iter().any(|s| line.contains(s)))
        .unwrap_or(false)
}

fn contains_marker(line: &str) -> bool {
    for token in ["TODO", "FIXME", "HACK", "XXX"] {
        let mut rest = line;
        while let Some(pos) = rest.find(token) {
            let before = rest[..pos].chars().next_back();
            let after = rest[pos + token.len()..].chars().next();
            let before_ok = before
                .map(|c| c.is_ascii_alphanumeric() || c == '_')
                .unwrap_or(false);
            let after_ok = after
                .map(|c| c.is_ascii_alphanumeric() || c == '_')
                .unwrap_or(false);
            if !before_ok && !after_ok {
                return true;
            }
            rest = &rest[pos + token.len()..];
        }
    }
    false
}

fn contains_secret_shape(line: &str) -> bool {
    if line.contains("BEGIN PRIVATE") {
        return true;
    }
    for prefix in ["sk-proj-", "sk-live-", "ghp_", "gho_", "github_pat_"] {
        let mut rest = line;
        while let Some(pos) = rest.find(prefix) {
            let tail = &rest[pos + prefix.len()..];
            let run = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                .count();
            if run >= 6 {
                return true;
            }
            rest = &rest[pos + prefix.len()..];
        }
    }
    false
}

#[test]
fn no_release_blocker_markers_in_code() {
    let root = repo_root();
    let allowlist = marker_allowlist();
    let mut hits = Vec::new();
    for (relative, text) in text_files(&root) {
        // Governance specifications describe the sweep requirement itself in
        // prose; they are not shipped code markers.
        if !code_file(&relative) || relative.starts_with(".specgrain/") || vendored(&relative) {
            continue;
        }
        for (index, line) in text.lines().enumerate() {
            if (contains_marker(line) || line.contains("todo!") || line.contains("unimplemented!"))
                && !allowed(&allowlist, &relative, line)
            {
                hits.push(format!("{}:{}: {}", relative, index + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "release-blocker markers:\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_panic_unreachable_or_mock_in_non_test_code() {
    let root = repo_root();
    let mut hits = Vec::new();
    for (relative, text) in text_files(&root) {
        // Governance specifications describe sweep requirements in prose;
        // they are not shipped code.
        if !code_file(&relative) || is_test_file(&relative) || relative.starts_with(".specgrain/") {
            continue;
        }
        let is_rust = relative.ends_with(".rs");
        let upstream = vendored(&relative);
        for (index, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if is_rust && !upstream && line.contains("panic!") {
                hits.push(format!("{relative}:{}: {trimmed}", index + 1));
            }
            if is_rust
                && !upstream
                && line.contains("unreachable!")
                && !(relative == "crates/orcel-provider-process/src/lib.rs"
                    && line
                        .contains("PrivateExecutionMode::Public | PrivateExecutionMode::Success"))
            {
                hits.push(format!("{relative}:{}: {trimmed}", index + 1));
            }
            if !upstream && line.to_lowercase().contains("mock") {
                hits.push(format!("{relative}:{}: {trimmed}", index + 1));
            }
            // Build/generator scripts report progress on stdout as ordinary CLI
            // output; this rule targets the shipped runtime under apps/.
            if relative.starts_with("apps/")
                && (relative.ends_with(".ts")
                    || relative.ends_with(".js")
                    || relative.ends_with(".mjs"))
                && (line.contains("console.log")
                    || line.contains("console.debug")
                    || line.contains("debugger"))
            {
                hits.push(format!("{relative}:{}: {trimmed}", index + 1));
            }
            if line.contains(".only(") {
                hits.push(format!("{relative}:{}: {trimmed}", index + 1));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "non-test code blockers:\n{}",
        hits.join("\n")
    );
}

/// The vendored exemption covers upstream's bytes only. In a file the patch
/// queue touches, every flagged line must be one upstream already had (matched
/// by SHA-256, as a multiset), so a patch cannot add a marker, panic!,
/// unreachable!, mock or #[ignore] line.
#[test]
fn patched_vendored_files_add_no_release_blockers() {
    let root = repo_root();
    let patched = patched_vendored_files(&root);
    assert!(
        !patched.is_empty(),
        "the vendored provenance lists no patched files"
    );
    let mut hits = Vec::new();
    for (relative, upstream) in &patched {
        assert!(
            vendored(relative),
            "{relative} is outside the vendored prefix"
        );
        let text = fs::read_to_string(root.join(relative))
            .unwrap_or_else(|err| panic!("read {relative}: {err}"));
        let mut remaining: BTreeMap<&str, usize> = BTreeMap::new();
        for digest in upstream {
            *remaining.entry(digest.as_str()).or_default() += 1;
        }
        for (index, line) in text.lines().enumerate() {
            if !blocker_line(relative, line) {
                continue;
            }
            let digest = format!("{:x}", Sha256::digest(line.as_bytes()));
            match remaining.get_mut(digest.as_str()) {
                Some(count) if *count > 0 => *count -= 1,
                _ => hits.push(format!("{relative}:{}: {}", index + 1, line.trim())),
            }
        }
    }
    assert!(
        hits.is_empty(),
        "release blockers added by the vendored patch queue:\n{}",
        hits.join("\n")
    );
}

#[test]
fn no_secret_shaped_literals_outside_allowlisted_vectors() {
    let root = repo_root();
    let allowlist = secret_allowlist();
    let mut hits = Vec::new();
    for (relative, text) in text_files(&root) {
        for (index, line) in text.lines().enumerate() {
            if contains_secret_shape(line) && !allowed(&allowlist, &relative, line) {
                hits.push(format!("{}:{}: {}", relative, index + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "secret-shaped literals:\n{}",
        hits.join("\n")
    );
}

#[test]
fn only_the_documented_ignored_tests_exist() {
    let root = repo_root();
    let mut hits = Vec::new();
    for (relative, text) in text_files(&root) {
        if !relative.ends_with(".rs") || vendored(&relative) {
            continue;
        }
        for (index, line) in text.lines().enumerate() {
            if line.contains("#[ignore") {
                let documented = (relative
                    == "crates/orcel-lifecycle/tests/release_qualification.rs"
                    && line.contains(
                        "requires ORCEL_RELEASE_DIR; run by the release-qualification CI job",
                    ))
                    || (relative == "crates/orcel-provider-network/tests/sg000064_live.rs"
                        && line.contains(
                            "performs one real HTTPS request; run with --ignored for live evidence",
                        ))
                    || ((relative == "apps/orcel-native-host/tests/conformance_native.rs"
                        || relative == "apps/orcel-native-host/tests/conformance_shared_web.rs")
                        && line.contains(
                            "requires ORCEL_XP08_FIXTURES (staged native fixtures); run by the native-host CI job with --include-ignored",
                        ))
                    || ((relative == "crates/orcel-browser-host/src/worker_launch_tests.rs"
                        || relative == "crates/orcel-browser-host/tests/sg000108_worker_host.rs"
                        || relative == "crates/orcel-browser-host/tests/sg000108_dev_host.rs"
                        || relative == "crates/orceld/src/live_browser.rs"
                        || relative == "crates/orceld/src/live_dispatch.rs")
                        && line.contains(
                            "requires the built browser worker and Edge; run by npm run browser-launcher:native",
                        ))
                    // SG-000128 slice 3: the Windows-only Tier C act test,
                    // run by the BM-02 Tier C GUI CI job.
                    || (relative == "crates/orceld/src/bm02_tier_c_act_tests.rs"
                        && line.contains(
                            "run by the BM-02 Tier C harness (tierc-act) on a CI runner with the apps launched",
                        ));
                if !documented {
                    hits.push(format!("{}:{}: {}", relative, index + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        hits.is_empty(),
        "unexpected ignored tests:\n{}",
        hits.join("\n")
    );
}

/// SG-000108 product caller: the test-only `live-browser-test` feature
/// (worker mode with the loopback fixture admitted) never reaches a release
/// build. Only the host crate's own definition and code, its worker-host
/// test, the native-suite launcher and documentation may name it, and it is
/// never a default feature.
#[test]
fn the_live_browser_test_feature_never_reaches_a_release_build() {
    let root = repo_root();
    let mut hits = Vec::new();
    for (relative, text) in text_files(&root) {
        if !text.contains("live-browser-test") {
            continue;
        }
        let allowed = relative == "crates/orcel-browser-host/Cargo.toml"
            || (relative.starts_with("crates/orcel-browser-host/src/")
                && relative.ends_with(".rs"))
            || relative == "crates/orcel-browser-host/tests/sg000108_worker_host.rs"
            || relative == "crates/orcel-browser-host/tests/sg000074_host.rs"
            || relative == "crates/orcel-browser-host/tests/sg000085_qualification.rs"
            || relative == "crates/orceld/Cargo.toml"
            || relative == "crates/orceld/src/live_browser.rs"
            || relative == "crates/orceld/src/sg000039_main.rs"
            // F5 slice 1: only in cfg_attr(.., expect(dead_code)), which
            // enables nothing.
            || relative == "crates/orceld/src/document_parse.rs"
            || relative == "apps/orcel-browser-worker/scripts/native-launcher.mjs"
            || relative.starts_with("docs/");
        if !allowed {
            hits.push(relative);
        }
    }
    assert!(
        hits.is_empty(),
        "live-browser-test is named outside its test-only places:\n{}",
        hits.join("\n")
    );
    // In the manifest it appears exactly once, as its own empty definition:
    // no other feature list (default, or a feature that enables it) names it.
    let manifest = fs::read_to_string(root.join("crates/orcel-browser-host/Cargo.toml")).unwrap();
    let naming: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("live-browser-test") && !line.starts_with('#'))
        .collect();
    assert_eq!(
        naming,
        ["live-browser-test = []"],
        "live-browser-test may only be defined, never enabled by another feature"
    );
    // orceld may only define its own feature of that name, which enables the
    // host crate's (an optional dependency, so a default build has neither).
    let orceld = fs::read_to_string(root.join("crates/orceld/Cargo.toml")).unwrap();
    let naming: Vec<&str> = orceld
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("live-browser-test") && !line.starts_with('#'))
        .collect();
    assert_eq!(
        naming,
        ["live-browser-test = [\"dep:orcel-browser-host\", \"orcel-browser-host/live-browser-test\"]"],
        "orceld may only define live-browser-test, never enable it by default"
    );
    let host_dependencies: Vec<&str> = orceld
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("orcel-browser-host"))
        .collect();
    assert_eq!(
        host_dependencies,
        ["orcel-browser-host = { path = \"../orcel-browser-host\", optional = true }"],
        "orceld depends on the browser host exactly once, and only optionally"
    );
}

/// SG-000108 slice 3b-ii (decision 7): the development-only
/// `live-browser-dev` feature (the host's public worker mode, running only
/// the runtime its build pinned) never reaches a release build. Only the
/// host crate's own definition and code, its dev-host test, orceld's
/// manifest and its live browser modules (slice 3c), the native-suite
/// launcher, the pin script and documentation may name it; in the host
/// manifest it is its own empty definition, and orceld's only enables the
/// host crate's; neither is ever a default.
#[test]
fn the_live_browser_dev_feature_never_reaches_a_release_build() {
    let root = repo_root();
    // A build command can enable a feature without naming it (judge, PR
    // #428): no workflow, action, script or manifest may build with every
    // feature or a feature powerset.
    for (relative, text) in text_files(&root) {
        // Every file that could run a build (workflows, actions, scripts in
        // any folder, manifests), that is everything but documentation and
        // vendored third-party sources.
        // WP1-01's dependency-direction test runs `cargo metadata` with every
        // feature, which resolves the graph and compiles nothing, so the
        // licence gate sees feature-gated dependencies. It may name the flag
        // once, in that metadata call, and run no other cargo command.
        if relative == "crates/orceld/tests/dependency_direction.rs" {
            assert_eq!(text.matches("--all-features").count(), 1, "{relative}");
            assert!(text.contains("\"metadata\","), "{relative}");
            for command in [
                "\"build\"",
                "\"test\"",
                "\"run\"",
                "\"check\"",
                "\"install\"",
            ] {
                assert!(!text.contains(command), "{relative} runs cargo {command}");
            }
            continue;
        }
        let build_surface = !relative.starts_with("docs/")
            && !relative.ends_with(".md")
            && !relative.contains("/third_party/");
        if build_surface {
            for forbidden in ["--all-features", "feature-powerset", "each-feature"] {
                assert!(
                    !text.contains(forbidden),
                    "{relative} builds with {forbidden}, which would enable live-browser-dev unnamed"
                );
            }
        }
    }
    let mut hits = Vec::new();
    for (relative, text) in text_files(&root) {
        if !text.contains("live-browser-dev") {
            continue;
        }
        let allowed = relative == "crates/orcel-browser-host/Cargo.toml"
            || (relative.starts_with("crates/orcel-browser-host/src/")
                && relative.ends_with(".rs"))
            || relative == "crates/orcel-browser-host/tests/sg000108_dev_host.rs"
            || relative == "crates/orceld/Cargo.toml"
            || relative == "crates/orceld/src/sg000039_main.rs"
            // F5 slice 1: only in cfg_attr(.., expect(dead_code)), which
            // enables nothing.
            || relative == "crates/orceld/src/document_parse.rs"
            || relative == "crates/orceld/src/live_browser.rs"
            || relative == "crates/orceld/src/live_dispatch.rs"
            || relative == "apps/orcel-browser-worker/scripts/native-launcher.mjs"
            || relative == "apps/orcel-browser-worker/scripts/dev-pin.mjs"
            || relative.starts_with("docs/")
            // Grain specs are governance records, not build input: they may name the
            // feature they confine a grain to (SG-000122). Build surfaces stay guarded above.
            || relative.starts_with(".specgrain/specs/");
        if !allowed {
            hits.push(relative);
        }
    }
    assert!(
        hits.is_empty(),
        "live-browser-dev is named outside its development-only places:\n{}",
        hits.join("\n")
    );
    let manifest = fs::read_to_string(root.join("crates/orcel-browser-host/Cargo.toml")).unwrap();
    let naming: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("live-browser-dev") && !line.starts_with('#'))
        .collect();
    assert_eq!(
        naming,
        ["live-browser-dev = []"],
        "live-browser-dev may only be defined, never enabled by another feature"
    );
    // orceld defines its own feature of that name, which enables the host
    // crate's (an optional dependency, so a default build has neither).
    let orceld = fs::read_to_string(root.join("crates/orceld/Cargo.toml")).unwrap();
    let naming: Vec<&str> = orceld
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("live-browser-dev") && !line.starts_with('#'))
        .collect();
    assert_eq!(
        naming,
        ["live-browser-dev = [\"dep:orcel-browser-host\", \"orcel-browser-host/live-browser-dev\"]"],
        "orceld may only define live-browser-dev, never enable it by default"
    );
    // The pin variables are read only at compile time, by the host binary.
    for (relative, text) in text_files(&root) {
        let names_pin = text.contains("ORCEL_LIVE_BROWSER_NODE")
            || text.contains("ORCEL_LIVE_BROWSER_WORKER_MAIN")
            || text.contains("ORCEL_LIVE_BROWSER_TREE_SHA256");
        if !names_pin {
            continue;
        }
        let allowed = relative == "crates/orcel-browser-host/src/main.rs"
            || relative == "crates/orcel-browser-host/src/runtime_pin.rs"
            || relative == "apps/orcel-browser-worker/scripts/native-launcher.mjs"
            || relative == "apps/orcel-browser-worker/scripts/dev-pin.mjs"
            || relative == "apps/orcel-browser-worker/scripts/dev-pin.test.mjs"
            // The dev-host test compares the build's pin with its own
            // measurement of the tree (read from the test's environment).
            || relative == "crates/orcel-browser-host/tests/sg000108_dev_host.rs"
            || relative.starts_with("docs/");
        assert!(allowed, "the worker runtime pin is named in {relative}");
        // runtime_pin.rs documents the variables; only main.rs reads them.
        if relative == "crates/orcel-browser-host/src/runtime_pin.rs" {
            for line in text
                .lines()
                .filter(|line| line.contains("ORCEL_LIVE_BROWSER_"))
            {
                assert!(
                    line.trim_start().starts_with("//"),
                    "runtime_pin.rs may name the pin only in comments: {line}"
                );
            }
        }
        if relative == "crates/orcel-browser-host/src/main.rs" {
            for line in text
                .lines()
                .filter(|line| line.contains("ORCEL_LIVE_BROWSER_"))
            {
                assert!(
                    line.contains("option_env!("),
                    "main.rs must read the pin only at compile time: {line}"
                );
            }
        }
    }
}

/// Rust files the parser scan doesn't read: orceld's parser module (its
/// definitions), the frame contract in `orcel-provider-process`, and the
/// parser itself.
fn defines_the_document_parser(relative: &str) -> bool {
    relative == "crates/orceld/src/document_parse.rs"
        || relative == "crates/orcel-provider-process/src/document_parser.rs"
        || relative.starts_with("apps/orcel-doc-parser/")
}

/// The modules the parser scan guards: orceld's parser module and its
/// workbook source, and the provider crate's frame contract.
const PARSER_MODULES: [&str; 3] = ["document_parse", "document_parser", "report_workbook"];

/// The items a listed release file may name only if its allowance lists them:
/// the parser's entry points and pins, the frame's types and limits, the
/// helper's pin, and F5 slice 2's route.
const PARSER_ITEMS: [&str; 18] = [
    "installed_pins",
    "parser_pin_in",
    "parse_download",
    "parse_committed",
    "CommittedDownload",
    "run_parser",
    "ParserPin",
    "HelperPin",
    "DocumentFormat",
    "ParsedDocument",
    "MAX_INPUT_BYTES",
    "decode_frame",
    "EXIT_REFUSED",
    "INPUT_NAME",
    "EXPECT_FLAG",
    "observe_workspace_file",
    "parse_workspace_file",
    "WorkspaceFile",
];

/// F5 slice 2's route, which no release file but `report_workbook.rs` (and
/// `document_parse.rs`, its home, checked separately) may name.
const ROUTE_NAMES: [&str; 3] = [
    "observe_workspace_file",
    "parse_workspace_file",
    "WorkspaceFile",
];

/// What one listed release file may name (SG-000130 W2): the guarded modules
/// it may reach, the guarded items it may name, the modules of which it may
/// name any item, and names it must never use at all.
struct ParserAllowance {
    modules: &'static [&'static str],
    items: &'static [&'static str],
    any_item_of: &'static [&'static str],
    never: &'static [&'static str],
}

/// SG-000130 W2: the per-file release set, at module level as the scan matches
/// it. `live_browser.rs` (compiled only into the live-browser builds) keeps
/// what it had; `report_workbook.rs` reads through the route and names the
/// parser's run, pin and frame; `report_check.rs` names the run, pins and frame
/// and nothing of the writer's side; `report_task.rs` loads the pins and calls
/// the workbook source. `report_journal.rs` is no listed file: reconcile gets
/// the pins from `report_task.rs`.
fn parser_allowance(relative: &str) -> Option<ParserAllowance> {
    match relative {
        "crates/orceld/src/live_browser.rs" => Some(ParserAllowance {
            modules: &["document_parse"],
            items: &["parse_download", "CommittedDownload"],
            any_item_of: &[],
            never: &[],
        }),
        "crates/orceld/src/report_workbook.rs" => Some(ParserAllowance {
            modules: &["document_parse", "document_parser"],
            items: &[
                "observe_workspace_file",
                "parse_workspace_file",
                "WorkspaceFile",
                "run_parser",
                "ParserPin",
                "DocumentFormat",
                "ParsedDocument",
                "MAX_INPUT_BYTES",
                "HelperPin",
            ],
            any_item_of: &[],
            never: &[],
        }),
        "crates/orceld/src/report_check.rs" => Some(ParserAllowance {
            modules: &["document_parse", "document_parser"],
            items: &[
                "run_parser",
                "ParserPin",
                "DocumentFormat",
                "ParsedDocument",
                "MAX_INPUT_BYTES",
                "HelperPin",
            ],
            any_item_of: &[],
            never: &["orcel_provider_fs", "TaskRegistry"],
        }),
        "crates/orceld/src/report_task.rs" => Some(ParserAllowance {
            modules: &["document_parse", "report_workbook"],
            items: &["installed_pins"],
            any_item_of: &["report_workbook"],
            never: &[],
        }),
        _ => None,
    }
}

/// The declarations a file may make of a guarded module, and nothing else of
/// it: orceld declares its two modules, the provider crate its frame contract.
fn parser_declaration(relative: &str, code: &str) -> bool {
    match relative {
        "crates/orceld/src/sg000039_main.rs" => {
            code == "mod document_parse;" || code == "mod report_workbook;"
        }
        "crates/orcel-provider-process/src/lib.rs" => code == "pub mod document_parser;",
        _ => false,
    }
}

/// Whether `code` names `identifier` as a whole identifier (not as part of a
/// longer one, such as `document_parser` for `document_parse`).
fn names_identifier(code: &str, identifier: &str) -> bool {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    code.match_indices(identifier).any(|(at, _)| {
        !code[..at].ends_with(ident) && !code[at + identifier.len()..].starts_with(ident)
    })
}

/// What follows each whole `module` in `text` (the line, or a `use` group the
/// line opens, up to its closing brace): `Some(items)` when a path continues
/// with `::`, each the first identifier of a path or a group's entry, and
/// `None` when the module is named any other way (`as`, alone, `mod`), which
/// no allowance admits.
fn items_after(text: &str, module: &str) -> Option<Vec<String>> {
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut items = Vec::new();
    for (at, _) in text.match_indices(module) {
        if text[..at].ends_with(ident) || text[at + module.len()..].starts_with(ident) {
            continue;
        }
        let rest = text[at + module.len()..].trim_start();
        let rest = rest.strip_prefix("::")?.trim_start();
        if let Some(group) = rest.strip_prefix('{') {
            let group = group.split('}').next().unwrap_or("");
            for entry in group.split(',') {
                let name: String = entry.trim().chars().take_while(|c| ident(*c)).collect();
                if !name.is_empty() {
                    items.push(name);
                }
            }
        } else {
            let name: String = rest.chars().take_while(|c| ident(*c)).collect();
            if name.is_empty() {
                return None;
            }
            items.push(name);
        }
    }
    Some(items)
}

/// Whether a line names the parser's executable in any spelling that builds
/// it (`"orcel-doc-parser"`, `.exe`, `.sha256`, or with a suffix appended).
fn names_the_parser_file(line: &str) -> bool {
    line.to_ascii_lowercase().contains("orcel-doc-parser")
}

/// The production lines of one Rust file that reach the confined document
/// parser beyond what SG-000130 W2's per-file release set admits. In any file:
/// a use of orceld's `document_parse` or `report_workbook` modules or of
/// `orcel_provider_process::document_parser` (whose `spec` and frame, with
/// `run_contained`, can launch any path), `PARSER_NAME`, `PARSER_PIN_NAME` or
/// the parser's file name in any spelling. A file in the release set
/// ([`parser_allowance`]) may name only its listed modules, and of them only
/// its listed items (any item of a module in `any_item_of`), names no other
/// item of [`PARSER_ITEMS`] anywhere, and never uses a name in `never`.
/// `document_parse.rs`, the provider's contract and the parser aren't
/// scanned; comments and items compiled only into tests are skipped. The
/// declarations in [`parser_declaration`] are allowed.
fn document_parser_callers(relative: &str, text: &str) -> Vec<String> {
    if defines_the_document_parser(relative) {
        return Vec::new();
    }
    let allowance = parser_allowance(relative);
    let lines: Vec<(usize, &str)> = non_test_lines(text);
    let mut hits = Vec::new();
    for (index, (number, line)) in lines.iter().enumerate() {
        let code = line.trim();
        if code.starts_with("//") || parser_declaration(relative, code) {
            continue;
        }
        // A `use` group opened here ends on a later line: read it whole.
        let mut statement = code.to_owned();
        if code.ends_with('{') {
            for (_, more) in lines.iter().skip(index + 1) {
                statement.push(' ');
                statement.push_str(more.trim());
                if more.contains('}') {
                    break;
                }
            }
        }
        let refused = names_identifier(code, "PARSER_NAME")
            || names_identifier(code, "PARSER_PIN_NAME")
            || names_the_parser_file(code)
            || PARSER_MODULES.iter().any(|module| {
                if !names_identifier(code, module) {
                    return false;
                }
                let Some(allowed) = &allowance else {
                    return true;
                };
                if !allowed.modules.contains(module) {
                    return true;
                }
                match items_after(&statement, module) {
                    None => true,
                    Some(_) if allowed.any_item_of.contains(module) => false,
                    Some(items) => items
                        .iter()
                        .any(|item| item != "self" && !allowed.items.contains(&item.as_str())),
                }
            })
            || allowance.as_ref().is_some_and(|allowed| {
                PARSER_ITEMS
                    .iter()
                    .any(|item| names_identifier(code, item) && !allowed.items.contains(item))
                    || allowed
                        .never
                        .iter()
                        .any(|name| names_identifier(code, name))
            });
        if refused {
            hits.push(format!("{relative}:{number}: {code}"));
        }
    }
    hits
}

/// The non-test lines of one Rust file that name F5 slice 2's workspace route
/// ([`ROUTE_NAMES`]). Every release file but `report_workbook.rs`, its one
/// release caller (SG-000130 W2), is scanned; `document_parse.rs`, its home,
/// is checked separately.
fn workspace_route_callers(relative: &str, text: &str) -> Vec<String> {
    if relative == "crates/orceld/src/report_workbook.rs" {
        return Vec::new();
    }
    non_test_lines(text)
        .into_iter()
        .filter(|(_, line)| {
            let code = line.trim();
            !code.starts_with("//") && ROUTE_NAMES.iter().any(|name| names_identifier(code, name))
        })
        .map(|(number, line)| format!("{relative}:{number}: {}", line.trim()))
        .collect()
}

/// SG-000130 W2 (judge L1): the report task's hold on the parser's pins. Its
/// accessors (`workbook_pins` and the others below) may be named only in
/// `report_task.rs`, which loads the pins, and `report_journal.rs`, whose
/// reconcile hands them to the checker. The pins' type, `report_check::Pins`,
/// may be named only where it is defined (`report_check.rs`) and where the
/// pins are passed: `report_task.rs`, `report_journal.rs` and
/// `report_workbook.rs` (the writer side receives them as an argument). Any
/// other non-test line naming one is a hit.
fn pin_holder_callers(relative: &str, text: &str) -> Vec<String> {
    const HOLDER: [&str; 5] = [
        "workbook_pins",
        "set_workbook_pins",
        "workbook_pins_or_refusal",
        "loaded_workbook_pins",
        "WORKBOOK_PINS",
    ];
    let holder_allowed = matches!(
        relative,
        "crates/orceld/src/report_task.rs" | "crates/orceld/src/report_journal.rs"
    );
    let type_allowed = holder_allowed
        || matches!(
            relative,
            "crates/orceld/src/report_check.rs" | "crates/orceld/src/report_workbook.rs"
        );
    non_test_lines(text)
        .into_iter()
        .filter(|(_, line)| {
            let code = line.trim();
            !code.starts_with("//")
                && ((!holder_allowed && HOLDER.iter().any(|name| names_identifier(code, name)))
                    || (!type_allowed && names_identifier(code, "Pins")))
        })
        .map(|(number, line)| format!("{relative}:{number}: {}", line.trim()))
        .collect()
}

/// Shipped sources that aren't Rust: the MCP app's TypeScript (compiled into
/// the release's `app/orcel-mcp/dist`) and the Windows app's C# and its build
/// script. Tests are not shipped.
fn shipped_non_rust_source(relative: &str) -> bool {
    let mcp = relative.starts_with("apps/orcel-mcp/src/")
        && [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"]
            .iter()
            .any(|extension| relative.ends_with(extension))
        && !relative.contains(".test.");
    let desktop = relative.starts_with("apps/orcel-desktop-preview/")
        && !relative.starts_with("apps/orcel-desktop-preview/tests/")
        && (relative.ends_with(".cs") || relative.ends_with(".ps1"));
    mcp || desktop
}

/// F5 slice 1 (founder decision 7 of 2026-11-14, the founder's decision
/// packet; not SG-000108's decision 7):
/// `docs/orcel/implementation-readiness/prep/F5_SPREADSHEET_JOURNEY.md`. The
/// Windows release ships the confined document parser and its pin. Its
/// callers are the live browser's committed downloads (`live_browser.rs`,
/// compiled only with the `live-browser-*` features, which the two tests
/// above keep out of release builds) and, since SG-000130 W2 (the rule change
/// its spec records), the report task's workbook sources: `report_task.rs`
/// loads the pins, `report_workbook.rs` reads through F5 slice 2's route, and
/// `report_check.rs` runs the parser on its own. This scan pins that per-file
/// set at module level, each file with the only items it may name
/// ([`parser_allowance`]); every other file names none of them. It is a guard,
/// not a proof: the stronger gates are the `expect(dead_code)` on the live
/// browser's entry points in `document_parse.rs`, which clippy's
/// `-D warnings` turns into a failure once a release build calls one, and the
/// executable registry's refusal of anything in an Orcel install directory.
/// A later slice adds a release caller only by changing this test, under its
/// own review.
///
/// F5 slice 2's route (`observe_workspace_file`, then `parse_workspace_file`)
/// lives inside `document_parse.rs`. Its one release caller is
/// `report_workbook.rs`. This test checks that the module names the route's
/// items only inside the route's own section, which defines nothing else, and
/// that no other non-test Rust names it (`workspace_route_callers`).
#[test]
fn the_shipped_document_parser_has_only_the_listed_release_callers() {
    let root = repo_root();
    let files = text_files(&root);
    let file = |relative: &str| {
        files
            .iter()
            .find(|(path, _)| path == relative)
            .map(|(_, text)| text.replace("\r\n", "\n"))
            .unwrap_or_else(|| panic!("{relative} is missing"))
    };
    let test_modules = test_only_modules(&files);
    for listed in [
        "crates/orceld/src/report_workbook.rs",
        "crates/orceld/src/report_check.rs",
        "crates/orceld/src/report_task.rs",
    ] {
        assert!(
            is_production_rust(listed, &test_modules),
            "{listed} is a release file since SG-000130 W2; the scan must read it"
        );
    }

    // Positive controls: what the scan relies on still exists, so it can't
    // pass because a name moved.
    let main = file("crates/orceld/src/sg000039_main.rs");
    assert!(
        main.contains(
            "#[cfg(all(\n    windows,\n    any(feature = \"live-browser-test\", feature = \"live-browser-dev\")\n))]\nmod live_browser;"
        ),
        "live_browser.rs, the parser's development-build caller, must stay behind the live-browser features"
    );
    for declaration in ["mod document_parse;", "mod report_workbook;"] {
        assert_eq!(
            main.lines()
                .filter(|line| line.trim() == declaration)
                .count(),
            1,
            "orceld no longer declares {declaration} once; this scan's names are stale"
        );
    }
    assert!(
        !main.contains("#[cfg(test)]\nmod report_workbook;"),
        "report_workbook.rs is a release module since SG-000130 W2"
    );
    let parse = file("crates/orceld/src/document_parse.rs");
    assert!(
        parse.contains(
            "pub const PARSER_NAME: &str = if cfg!(windows) {\n    \"orcel-doc-parser.exe\""
        ),
        "document_parse.rs no longer names the parser as this scan expects"
    );
    // The live browser's entry points still expect to be dead code in a
    // release build: exactly this attribute, directly on each. A weaker
    // predicate (`cfg_attr(any(), ..)`, or one without `not(..)`) would never
    // expect anything in a release build.
    const RELEASE_EXPECT: &str = "#[cfg_attr(\n    not(any(\n        test,\n        all(\n            windows,\n            any(feature = \"live-browser-test\", feature = \"live-browser-dev\")\n        )\n    )),\n    expect(dead_code)\n)]\n";
    for entry in ["pub fn parse_download(", "pub fn parse_committed("] {
        let at = parse
            .find(entry)
            .unwrap_or_else(|| panic!("document_parse.rs no longer has {entry}"));
        assert!(
            parse[..at].ends_with(RELEASE_EXPECT),
            "{entry} must carry exactly the release-build expect(dead_code):\n{RELEASE_EXPECT}"
        );
    }
    // The report task's entry points have their release callers now, so they
    // carry no expectation; these two are the module's only ones.
    for entry in [
        "pub fn installed_pins(",
        "pub fn parser_pin_in(",
        "pub(crate) fn run_parser(",
    ] {
        assert!(
            parse.contains(entry),
            "document_parse.rs no longer has {entry}"
        );
    }
    assert_eq!(
        parse.matches("expect(dead_code)").count(),
        2,
        "only parse_download and parse_committed expect to be dead in a release build"
    );
    // (definition, its name, how many cfg-chosen definitions it has)
    const ROUTE_ITEMS: [(&str, &str, usize); 14] = [
        ("pub(crate) struct WorkspaceFile {", "WorkspaceFile", 1),
        ("impl WorkspaceFile {", "WorkspaceFile", 1),
        (
            "pub(crate) fn observe_workspace_file(",
            "observe_workspace_file",
            1,
        ),
        (
            "pub(crate) fn parse_workspace_file(",
            "parse_workspace_file",
            1,
        ),
        ("fn not_a_workbook(", "not_a_workbook", 1),
        ("struct PlainRead {", "PlainRead", 1),
        ("fn read_workspace_plain(", "read_workspace_plain", 1),
        ("fn unprefixed(", "unprefixed", 1),
        ("struct FileIdentity {", "FileIdentity", 1),
        ("fn opened_as(", "opened_as", 1),
        ("fn raced(", "raced", 1),
        ("fn file_identity(", "file_identity", 2),
        ("fn not_plain(", "not_plain", 1),
        ("fn open_no_follow(", "open_no_follow", 1),
    ];
    for (item, _, count) in ROUTE_ITEMS {
        assert_eq!(
            parse.matches(item).count(),
            count,
            "document_parse.rs no longer has exactly {count} {item}"
        );
    }
    // In its own module, the route's items are named only inside the route's
    // section (from its opening comment to `fn result(`), and that section
    // defines nothing else. So no other code in the module, such as
    // `parse_committed` or `run_parser` in a live-browser build (which CI
    // doesn't lint), can call one unnoticed.
    let lines: Vec<&str> = parse.lines().collect();
    let line_of = |marker: &str| {
        lines
            .iter()
            .position(|line| line.starts_with(marker))
            .map(|index| index + 1)
            .unwrap_or_else(|| panic!("document_parse.rs no longer has {marker}"))
    };
    let first = line_of("// F5 slice 2 (founder decision 7 of 2026-11-14,");
    let last = line_of("fn result(");
    assert!(first < last, "the route's section is out of order");
    let outside: Vec<String> = non_test_lines(&parse)
        .into_iter()
        .filter(|(number, line)| {
            let code = line.trim();
            (*number < first || *number >= last)
                && !code.starts_with("//")
                && ROUTE_ITEMS
                    .iter()
                    .any(|(_, name, _)| names_identifier(code, name))
        })
        .map(|(number, line)| format!("document_parse.rs:{number}: {}", line.trim()))
        .collect();
    assert!(
        outside.is_empty(),
        "document_parse.rs names its workspace route outside the route:\n{}",
        outside.join("\n")
    );
    let strays: Vec<&str> = lines[first..last - 1]
        .iter()
        .copied()
        .filter(|line| {
            !line.is_empty()
                && !line.starts_with(' ')
                && !line.starts_with("//")
                && !line.starts_with("#[")
                && !line.starts_with('}')
                && !line.starts_with(')')
                && !ROUTE_ITEMS
                    .iter()
                    .any(|(item, _, _)| line.starts_with(item))
        })
        .collect();
    assert!(
        strays.is_empty(),
        "the workspace route's section defines something else:\n{}",
        strays.join("\n")
    );
    // Each listed file still names what its allowance admits, so the scan
    // reads live code: in a file with no allowance, every one would be a hit.
    for (listed, admitted) in [
        ("crates/orceld/src/live_browser.rs", "parse_download"),
        (
            "crates/orceld/src/report_workbook.rs",
            "parse_workspace_file",
        ),
        ("crates/orceld/src/report_check.rs", "run_parser"),
        ("crates/orceld/src/report_task.rs", "installed_pins"),
    ] {
        let text = file(listed);
        let stand_in = document_parser_callers("crates/orceld/src/stand-in.rs", &text);
        assert!(
            !stand_in.is_empty(),
            "the scan no longer sees {listed}'s calls; it would miss a release caller"
        );
        assert!(
            non_test_lines(&text)
                .iter()
                .any(|(_, line)| !line.trim().starts_with("//") && names_identifier(line, admitted)),
            "{listed} no longer names {admitted}; its allowance is stale"
        );
    }

    let callers: Vec<String> = files
        .iter()
        .filter(|(relative, _)| is_production_rust(relative, &test_modules))
        .flat_map(|(relative, text)| document_parser_callers(relative, &text.replace("\r\n", "\n")))
        .collect();
    assert!(
        callers.is_empty(),
        "a release build reaches the shipped document parser outside SG-000130 W2's per-file set:\n{}",
        callers.join("\n")
    );
    let route: Vec<String> = files
        .iter()
        .filter(|(relative, _)| {
            is_production_rust(relative, &test_modules)
                && relative != "crates/orceld/src/document_parse.rs"
        })
        .flat_map(|(relative, text)| workspace_route_callers(relative, text))
        .collect();
    assert!(
        route.is_empty(),
        "non-test code other than report_workbook.rs names the F5 slice 2 workspace route:\n{}",
        route.join("\n")
    );
    let holders: Vec<String> = files
        .iter()
        .filter(|(relative, _)| is_production_rust(relative, &test_modules))
        .flat_map(|(relative, text)| pin_holder_callers(relative, text))
        .collect();
    assert!(
        holders.is_empty(),
        "non-test code outside the report task names its parser pins:\n{}",
        holders.join("\n")
    );
    // Positive control: the holder's users still name it as the scan expects.
    for (listed, name) in [
        ("crates/orceld/src/report_task.rs", "workbook_pins"),
        ("crates/orceld/src/report_journal.rs", "workbook_pins"),
        ("crates/orceld/src/report_check.rs", "Pins"),
    ] {
        assert!(
            !pin_holder_callers("crates/orceld/src/stand-in.rs", &file(listed)).is_empty(),
            "{listed} no longer names {name}; the pin scan's names are stale"
        );
    }

    let shipped: Vec<&(String, String)> = files
        .iter()
        .filter(|(relative, _)| shipped_non_rust_source(relative))
        .collect();
    for expected in [
        "apps/orcel-mcp/src/index.ts",
        "apps/orcel-desktop-preview/src/Program.cs",
    ] {
        assert!(
            shipped.iter().any(|(relative, _)| relative == expected),
            "{expected} is not among the shipped sources this scan reads"
        );
    }
    let named: Vec<String> = shipped
        .iter()
        .flat_map(|(relative, text)| {
            text.lines()
                .enumerate()
                .filter(|(_, line)| names_the_parser_file(line))
                .map(move |(index, line)| format!("{relative}:{}: {}", index + 1, line.trim()))
        })
        .collect();
    assert!(
        named.is_empty(),
        "shipped non-Rust code names the document parser:\n{}",
        named.join("\n")
    );
}

#[test]
fn the_parser_caller_scan_catches_the_shapes_it_claims() {
    let text = "use crate::document_parse::run_parser;\n\
        fn a() { crate::report_workbook::observe(); }\n\
        use crate::{contained_tier, document_parse as parse};\n\
        const P: &str = \"orcel-doc-parser.exe\";\n\
        // crate::document_parse::parse_download, in a comment\n\
        use orcel_provider_process::document_parser::decode_frame;\n\
        let spec = document_parser::spec(&input);\n\
        let path = format!(\"Orcel-Doc-Parser{}\", EXE_SUFFIX);\n\
        let name = PARSER_NAME;\n\
        let pin = dir.join(PARSER_PIN_NAME);\n\
        let other = MY_PARSER_NAME_TOO;\n\
        #[cfg(test)]\n\
        fn t() {\n    crate::document_parse::parse_download();\n}\n\
        fn b() {\n    #[cfg(test)]\n    let x = crate::report_workbook::digest(a, b);\n}\n";
    // Any file outside the release set, report_journal.rs among them.
    for relative in [
        "crates/orceld/src/x.rs",
        "crates/orceld/src/report_journal.rs",
    ] {
        let hits = document_parser_callers(relative, text);
        assert_eq!(hits.len(), 9, "{hits:?}");
        assert!(hits[0].starts_with(&format!("{relative}:1: use crate::document_parse")));
        assert!(hits[4].contains("document_parser::decode_frame"));
        assert!(hits[6].contains("format!"));
    }
    for name in [
        "use super::super::document_parse::installed_pins;\n",
        "let pins = crate::document_parse::installed_pins();\n",
        "use crate::report_workbook;\n",
        "use orcel_provider_process::document_parser::ParsedDocument;\n",
    ] {
        assert_eq!(
            document_parser_callers("crates/orceld/src/report_journal.rs", name).len(),
            1,
            "report_journal.rs names none of them: {name}"
        );
    }
    // The files that define the parser aren't scanned.
    for defining in [
        "crates/orceld/src/document_parse.rs",
        "crates/orcel-provider-process/src/document_parser.rs",
        "apps/orcel-doc-parser/src/main.rs",
    ] {
        assert!(
            document_parser_callers(defining, text).is_empty(),
            "{defining}"
        );
    }
    // The declarations, only where they belong.
    assert!(document_parser_callers(
        "crates/orceld/src/sg000039_main.rs",
        "mod document_parse;\nmod report_workbook;\n"
    )
    .is_empty());
    assert_eq!(
        document_parser_callers(
            "crates/orceld/src/sg000039_main.rs",
            "use crate::report_workbook::observe;\n"
        )
        .len(),
        1
    );
    assert!(document_parser_callers(
        "crates/orcel-provider-process/src/lib.rs",
        "pub mod document_parser;\n"
    )
    .is_empty());
    for declaration in ["mod document_parse;\n", "mod report_workbook;\n"] {
        assert_eq!(
            document_parser_callers("crates/orceld/src/other.rs", declaration).len(),
            1,
            "{declaration}"
        );
    }

    // SG-000130 W2: each listed file passes with exactly its own items...
    let admitted = [
        (
            "crates/orceld/src/live_browser.rs",
            "committed: Vec<crate::document_parse::CommittedDownload>,\n\
             crate::document_parse::parse_download(workspace, approval, download)\n",
        ),
        (
            "crates/orceld/src/report_workbook.rs",
            "use crate::document_parse::{observe_workspace_file, parse_workspace_file, WorkspaceFile};\n\
             use crate::document_parse::{run_parser, ParserPin};\n\
             use orcel_provider_process::document_parser::{\n    DocumentFormat,\n    ParsedDocument,\n    MAX_INPUT_BYTES,\n};\n\
             use orcel_provider_process::contained::HelperPin;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "use crate::document_parse::{run_parser, ParserPin};\n\
             use orcel_provider_process::contained::HelperPin;\n\
             use orcel_provider_process::document_parser::{DocumentFormat, ParsedDocument, MAX_INPUT_BYTES};\n",
        ),
        (
            "crates/orceld/src/report_task.rs",
            "load(crate::document_parse::installed_pins)\n\
             pub(crate) type WorkbookSource = crate::report_workbook::WorkbookSource;\n\
             crate::report_workbook::observe(workspace, source, Some(pins))\n",
        ),
    ];
    for (relative, code) in admitted {
        assert!(
            document_parser_callers(relative, code).is_empty(),
            "{relative}: {:?}",
            document_parser_callers(relative, code)
        );
    }
    // ...and fails on any item outside its list, a module it may not reach,
    // an alias, or a name it must never use.
    let refused = [
        (
            "crates/orceld/src/live_browser.rs",
            "use crate::document_parse::run_parser;\n",
        ),
        (
            "crates/orceld/src/live_browser.rs",
            "let pins = installed_pins();\n",
        ),
        (
            "crates/orceld/src/live_browser.rs",
            "use crate::report_workbook::observe;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "crate::report_workbook::prompt_entries(a, b, c)\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "use crate::document_parse::parse_workspace_file;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "let seen: WorkspaceFile = todo;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "use orcel_provider_fs::FsProvider;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "fn f(tasks: &TaskRegistry) {}\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "use crate::document_parse::installed_pins;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "use orcel_provider_process::document_parser::decode_frame;\n",
        ),
        (
            "crates/orceld/src/report_check.rs",
            "use orcel_provider_process::document_parser::{\n    DocumentFormat,\n    spec,\n};\n",
        ),
        (
            "crates/orceld/src/report_task.rs",
            "crate::document_parse::run_parser(a, b, None, h, p)\n",
        ),
        (
            "crates/orceld/src/report_task.rs",
            "use crate::document_parse::{installed_pins, run_parser};\n",
        ),
        (
            "crates/orceld/src/report_task.rs",
            "let pin: ParserPin = pins.1;\n",
        ),
        (
            "crates/orceld/src/report_task.rs",
            "use crate::document_parse as parse;\n",
        ),
        (
            "crates/orceld/src/report_task.rs",
            "use orcel_provider_process::document_parser::ParsedDocument;\n",
        ),
        (
            "crates/orceld/src/report_workbook.rs",
            "crate::document_parse::installed_pins()\n",
        ),
        (
            "crates/orceld/src/report_workbook.rs",
            "crate::document_parse::parse_download(w, a, d)\n",
        ),
        (
            "crates/orceld/src/report_workbook.rs",
            "let name = PARSER_NAME;\n",
        ),
    ];
    for (relative, code) in refused {
        assert_eq!(
            document_parser_callers(relative, code).len(),
            1,
            "{relative} must refuse: {code}"
        );
    }

    assert!(shipped_non_rust_source(
        "apps/orcel-mcp/src/entrypoints/stdio.ts"
    ));
    assert!(!shipped_non_rust_source(
        "apps/orcel-mcp/src/kernel.test.ts"
    ));
    assert!(shipped_non_rust_source(
        "apps/orcel-desktop-preview/build.ps1"
    ));
    assert!(!shipped_non_rust_source(
        "apps/orcel-desktop-preview/tests/e2e.ps1"
    ));
    assert!(names_the_parser_file(
        "spawn(join(dir, 'orcel-doc-parser.exe'))"
    ));

    // F5 slice 2's route: seen in any file but report_workbook.rs, the
    // parser's other listed files included; comments and test items are not.
    let route = "let seen = observe_workspace_file(&workspace, path)?;\n\
        use crate::document_parse::{parse_workspace_file as p, WorkspaceFile};\n\
        // parse_workspace_file, in a comment\n\
        let x = reparse_workspace_files();\n\
        #[cfg(test)]\n\
        fn t() {\n    parse_workspace_file(&w, &o, &h, &p);\n}\n";
    for relative in [
        "crates/orceld/src/live_browser.rs",
        "crates/orceld/src/report_task.rs",
        "crates/orceld/src/report_check.rs",
        "crates/orceld/src/report_journal.rs",
    ] {
        let hits = workspace_route_callers(relative, route);
        assert_eq!(hits.len(), 2, "{relative}: {hits:?}");
        assert!(hits[0].contains(":1: let seen"), "{hits:?}");
        assert!(hits[1].contains(":2: use crate"), "{hits:?}");
    }
    assert!(workspace_route_callers("crates/orceld/src/report_workbook.rs", route).is_empty());

    // The report task's pins: the holder only in report_task.rs and reconcile,
    // the type also where it is defined and where the writer receives it.
    let pins = "let pins = crate::report_task::workbook_pins();\n\
        fn f(pins: Option<&report_check::Pins>) {}\n\
        // workbook_pins, in a comment\n\
        let x = my_workbook_pins_too();\n\
        #[cfg(test)]\n\
        fn t() {\n    set_workbook_pins(p);\n}\n";
    for (relative, hits) in [
        ("crates/orceld/src/report_task.rs", 0),
        ("crates/orceld/src/report_journal.rs", 0),
        ("crates/orceld/src/report_check.rs", 1),
        ("crates/orceld/src/report_workbook.rs", 1),
        ("crates/orceld/src/live_browser.rs", 2),
        ("crates/orceld/src/app_api.rs", 2),
    ] {
        assert_eq!(
            pin_holder_callers(relative, pins).len(),
            hits,
            "{relative}: {:?}",
            pin_holder_callers(relative, pins)
        );
    }
}

#[test]
fn workflow_set_is_exactly_the_governed_quartet() {
    let root = repo_root();
    let dir = root.join(".github/workflows");
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["ci.yml", "pages.yml", "release.yml", "review-gates.yml"]
    );
}

/// XP-01B: transient, per-use locations under the shared temp directory that
/// non-test Rust may name, as (path, line substring, reason). None of them is
/// a state default: each is unique per use (nonce or pid in the name), created
/// exclusively or discarded, and never read back as Orcel state. Every other
/// `temp_dir()` in non-test Rust fails the gate; state defaults resolve under
/// `orcel_platform::paths::state_root()` instead.
const TRANSIENT_TEMP_USES: &[(&str, &str, &str)] = &[
    (
        "crates/orcel-lifecycle/src/doctor.rs",
        "orcel-doctor-",
        "throwaway ledger path; doctor only asks the broker whether presence is available",
    ),
    (
        "crates/orcel-lifecycle/src/install.rs",
        "orcel-uninstalled-",
        "uninstall moves the running CLI out of the install root so the root can be removed",
    ),
    (
        "crates/orcel-provider-git/src/mutation.rs",
        "let path = std::env::temp_dir().join(format!(",
        "empty hooks directory, created exclusively per git invocation and removed on drop",
    ),
    (
        "crates/orcel-provider-git/src/push.rs",
        "let path = std::env::temp_dir().join(format!(",
        "empty hooks directory, created exclusively per push and removed on drop",
    ),
    (
        "crates/orcel-provider-git/src/push.rs",
        "let dir = std::env::temp_dir().join(format!(",
        "per-push askpass directory, created exclusively and removed on drop",
    ),
];

/// Files compiled only into tests: `#[cfg(..test..)] mod name;` declarations.
fn test_only_modules(files: &[(String, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (relative, text) in files.iter().filter(|(path, _)| path.ends_with(".rs")) {
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        for pair in lines.windows(2) {
            let is_test_cfg = is_test_only_cfg(pair[0]);
            let Some(name) = pair[1]
                .strip_prefix("mod ")
                .or_else(|| pair[1].strip_prefix("pub(crate) mod "))
                .and_then(|rest| rest.strip_suffix(';'))
            else {
                continue;
            };
            if !is_test_cfg {
                continue;
            }
            let dir = relative.rsplit_once('/').map_or("", |(dir, _)| dir);
            let stem = relative
                .rsplit('/')
                .next()
                .and_then(|file| file.strip_suffix(".rs"))
                .unwrap_or_default();
            out.push(format!("{dir}/{name}.rs"));
            out.push(format!("{dir}/{stem}/{name}.rs"));
        }
    }
    out
}

/// A `#[cfg(..)]` attribute that compiles its item only into tests:
/// `cfg(test)` or `cfg(all(.., test, ..))`. `not(test)` and
/// `any(test, ..)` can reach a non-test build, so they do not count.
fn is_test_only_cfg(attribute: &str) -> bool {
    let Some(predicate) = attribute
        .strip_prefix("#[cfg(")
        .and_then(|rest| rest.strip_suffix(")]"))
    else {
        return false;
    };
    let predicate = predicate.trim();
    if predicate == "test" {
        return true;
    }
    predicate
        .strip_prefix("all(")
        .and_then(|rest| rest.strip_suffix(')'))
        .is_some_and(|inner| {
            !inner.contains('(') && inner.split(',').any(|part| part.trim() == "test")
        })
}

/// Lexer state carried across lines by [`brace_delta`].
#[derive(Clone, Copy, PartialEq)]
enum Lex {
    Code,
    Str,
    RawStr(usize),
    BlockComment(usize),
}

/// Net `{` minus `}` on `line`, and whether any `{` appeared, ignoring
/// braces inside comments, string, raw-string and character literals;
/// `state` carries an unterminated string or block comment to the next line.
fn brace_delta(line: &str, state: &mut Lex) -> (i64, bool) {
    let chars: Vec<char> = line.chars().collect();
    let mut delta = 0;
    let mut opened = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match *state {
            Lex::Str => {
                if c == '\\' {
                    i += 1;
                } else if c == '"' {
                    *state = Lex::Code;
                }
            }
            Lex::RawStr(hashes) => {
                if c == '"'
                    && chars[i + 1..]
                        .iter()
                        .take(hashes)
                        .filter(|h| **h == '#')
                        .count()
                        == hashes
                {
                    *state = Lex::Code;
                    i += hashes;
                }
            }
            Lex::BlockComment(depth) => {
                if c == '*' && next == Some('/') {
                    *state = if depth == 1 {
                        Lex::Code
                    } else {
                        Lex::BlockComment(depth - 1)
                    };
                    i += 1;
                } else if c == '/' && next == Some('*') {
                    *state = Lex::BlockComment(depth + 1);
                    i += 1;
                }
            }
            Lex::Code => {
                if c == '/' && next == Some('/') {
                    break;
                } else if c == '/' && next == Some('*') {
                    *state = Lex::BlockComment(1);
                    i += 1;
                } else if c == '"' {
                    *state = Lex::Str;
                } else if c == 'r'
                    && (next == Some('"') || next == Some('#'))
                    && !chars[..i]
                        .last()
                        .is_some_and(|p| p.is_alphanumeric() || *p == '_')
                {
                    let hashes = chars[i + 1..].iter().take_while(|h| **h == '#').count();
                    if chars.get(i + 1 + hashes) == Some(&'"') {
                        *state = Lex::RawStr(hashes);
                        i += 1 + hashes;
                    }
                } else if c == '\'' {
                    // A character literal ('{', '\'', '\u{..}'); a lifetime
                    // such as 'a has no closing quote right after it.
                    if next == Some('\\') {
                        if let Some(end) = chars[i + 2..].iter().position(|q| *q == '\'') {
                            i += 2 + end;
                        }
                    } else if chars.get(i + 2) == Some(&'\'') {
                        i += 2;
                    }
                } else if c == '{' {
                    delta += 1;
                    opened = true;
                } else if c == '}' {
                    delta -= 1;
                }
            }
        }
        i += 1;
    }
    (delta, opened)
}

/// The non-test part of a Rust file: every line outside items compiled
/// only into tests. An item under `#[cfg(test)]` (or `cfg(all(.., test,
/// ..))`) is skipped through the end of its block, or through its `;` when it
/// has none (`mod tests;`, `use ..;`). Code after a test item is still
/// scanned.
fn non_test_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut index = 0;
    let mut state = Lex::Code;
    while index < lines.len() {
        if state == Lex::Code && is_test_only_cfg(lines[index].trim()) {
            index = test_item_end(&lines, index + 1) + 1;
            continue;
        }
        brace_delta(lines[index], &mut state);
        out.push((index + 1, lines[index]));
        index += 1;
    }
    out
}

/// The last line of the item that starts at `start` (after any further
/// attributes and doc comments).
fn test_item_end(lines: &[&str], start: usize) -> usize {
    let mut index = start;
    while index < lines.len() {
        let trimmed = lines[index].trim();
        if trimmed.starts_with("#[") || trimmed.starts_with("///") {
            index += 1;
        } else {
            break;
        }
    }
    let mut depth = 0;
    let mut opened = false;
    let mut state = Lex::Code;
    while index < lines.len() {
        let line = lines[index];
        let (delta, saw_open) = brace_delta(line, &mut state);
        depth += delta;
        opened |= saw_open;
        if opened && depth <= 0 {
            return index;
        }
        if !opened && depth == 0 && state == Lex::Code && line.trim_end().ends_with(';') {
            return index;
        }
        index += 1;
    }
    lines.len().saturating_sub(1)
}

#[test]
fn non_test_lines_skip_only_the_test_module_block() {
    let text = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() { let _ = '}'; let _ = \"}\"; }\n    // }\n}\nfn after() { std::env::temp_dir(); }\n#[cfg(not(test))]\nmod real {\n    fn r() {}\n}\n";
    let kept: Vec<_> = non_test_lines(text)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    assert_eq!(
        kept,
        vec![
            "fn a() {}",
            "fn after() { std::env::temp_dir(); }",
            "#[cfg(not(test))]",
            "mod real {",
            "    fn r() {}",
            "}",
        ]
    );
    let item = "mod m {\n    #[cfg(test)]\n    pub(super) fn helper(\n        x: u8,\n    ) -> u8 {\n        if x > 0 { x } else { 0 }\n    }\n    #[cfg(test)]\n    use std::fs;\n    fn real() {}\n}\n";
    let kept: Vec<_> = non_test_lines(item)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    assert_eq!(kept, vec!["mod m {", "    fn real() {}", "}"]);
    let raw = "#[cfg(test)]\nmod tests {\n    const S: &str = r#\"{ \"#;\n}\nfn tail() {}\n";
    let kept: Vec<_> = non_test_lines(raw)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    assert_eq!(kept, vec!["fn tail() {}"]);
    assert!(is_test_only_cfg("#[cfg(all(test, windows))]"));
    assert!(!is_test_only_cfg(
        "#[cfg(any(test, feature = \"test-support\"))]"
    ));
    assert!(!is_test_only_cfg("#[cfg(not(test))]"));
}

#[test]
fn xp01b_no_shared_temp_state_default_in_non_test_rust() {
    let root = repo_root();
    let files = text_files(&root);
    let test_modules = test_only_modules(&files);
    let mut hits = Vec::new();
    let mut used = vec![false; TRANSIENT_TEMP_USES.len()];
    for (relative, text) in &files {
        if !relative.ends_with(".rs")
            || vendored(relative)
            || is_test_file(relative)
            || test_modules.contains(relative)
        {
            continue;
        }
        for (number, line) in non_test_lines(text) {
            if !line.contains("temp_dir()") {
                continue;
            }
            let allowed = TRANSIENT_TEMP_USES
                .iter()
                .position(|(path, needle, _)| path == relative && line.contains(needle));
            match allowed {
                Some(index) => used[index] = true,
                None => hits.push(format!("{relative}:{number}: {}", line.trim())),
            }
        }
    }
    assert!(
        hits.is_empty(),
        "non-test std::env::temp_dir() uses (state defaults belong under \
         orcel_platform::paths::state_root()):\n{}",
        hits.join("\n")
    );
    let stale: Vec<_> = TRANSIENT_TEMP_USES
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|((path, needle, _), _)| format!("{path}: {needle}"))
        .collect();
    assert!(stale.is_empty(), "stale allowlist entries: {stale:?}");
}

/// XP-01B: none of the stores XP-01B moved names the shared temp directory
/// outside its tests, even through an allowlisted shape.
#[test]
fn xp01b_moved_stores_never_name_the_shared_temp_directory() {
    let root = repo_root();
    for relative in [
        "crates/orcel-policy/src/full_control_store.rs",
        "crates/orcel-policy/src/executable_registry.rs",
        "crates/orcel-policy/src/remote_session.rs",
        "crates/orcel-policy/src/protected_state.rs",
        "crates/orceld/src/trust.rs",
        "crates/orcel-provider-browser/src/lib.rs",
    ] {
        let text = fs::read_to_string(root.join(relative)).expect("read store source");
        let hits: Vec<_> = non_test_lines(&text)
            .into_iter()
            .filter(|(_, line)| line.contains("temp_dir"))
            .map(|(number, line)| format!("{relative}:{number}: {}", line.trim()))
            .collect();
        assert!(hits.is_empty(), "{hits:?}");
    }
}

/// #655: the files that may resolve Orcel's per-user state root, with what each builds there.
/// Each resolves through `orcel_platform::stores`, so a store is registered before anything
/// creates it, and uninstall and migration follow the registry. A new file here means a new
/// store: register it in `crates/orcel-platform/src/stores.rs` first.
const STATE_ROOT_RESOLVERS: &[(&str, &str)] = &[
    ("crates/orcel-approval/src/lib.rs", "the approval ledger"),
    (
        "crates/orceld/src/app_api.rs",
        "the runtime folder when there's no private one",
    ),
    (
        "crates/orceld/src/sg000039_main.rs",
        "orceld's entry: the earlier-state gate",
    ),
    (
        "crates/orcel-lifecycle/src/linux.rs",
        "the Linux layout's root",
    ),
    ("crates/orcel-audit/src/lib.rs", "the audit log"),
    (
        "crates/orcel-lifecycle/src/layout.rs",
        "the install, its records, state and logs",
    ),
    ("crates/orcel-platform/src/paths.rs", "the root itself"),
    (
        "crates/orcel-policy/src/executable_registry.rs",
        "the executable registry",
    ),
    (
        "crates/orcel-policy/src/full_control_store.rs",
        "full-control authority",
    ),
    (
        "crates/orcel-policy/src/protected_state.rs",
        "the roots a workspace mustn't overlap",
    ),
    ("crates/orcel-policy/src/remote_session.rs", "remote leases"),
    (
        "crates/orcel-provider-browser/src/lib.rs",
        "the browser profile",
    ),
    (
        "crates/orceld/src/contained_tier.rs",
        "contained runs' scratch",
    ),
    (
        "crates/orceld/src/document_parse.rs",
        "document parsing's scratch",
    ),
    (
        "crates/orceld/src/mutation_journal.rs",
        "the mutation journal",
    ),
    (
        "crates/orceld/src/report_task.rs",
        "the report task journal",
    ),
    ("crates/orceld/src/search.rs", "search usage"),
    (
        "crates/orceld/src/secret_store.rs",
        "secret blobs and the earlier device key record",
    ),
    ("crates/orceld/src/trust.rs", "workspace trust"),
];

const ROOT_NAMES: [&str; 3] = ["root", "state", "state_root"];

fn is_word(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether what's passed to a `join(` starting at `rest` names a store: a string literal, a
/// `format!`, or a constant such as `MIGRATION_IN_PROGRESS` or `legacy::IN_PROGRESS`. A variable
/// passes, as do names built under a registered folder.
fn names_a_store(rest: &str) -> bool {
    let rest = rest.trim_start();
    if rest.starts_with('"') || rest.starts_with("format!") {
        return true;
    }
    let path: String = rest
        .chars()
        .take_while(|c| is_word(*c) || *c == ':')
        .collect();
    let last = path.rsplit("::").next().unwrap_or("");
    last.len() > 1
        && last.chars().any(|c| c.is_ascii_uppercase())
        && last
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Whether `text` ends with a root variable: `root`, `state` or `state_root`, as a whole word.
fn ends_with_a_root(text: &str) -> bool {
    ROOT_NAMES.iter().any(|name| {
        text.strip_suffix(name)
            .is_some_and(|before| !before.chars().next_back().is_some_and(is_word))
    })
}

/// A store named straight onto a state root, which skips the registry. It covers a variable named
/// exactly `root`, `state` or `state_root` (not `data_root`), with `.join(` on the same line or,
/// as rustfmt splits chains, the next one; and `Path::new(&...root).join(`. `previous` is the
/// line before.
fn joins_a_store_onto_a_root(line: &str, previous: &str) -> bool {
    let same_line = ROOT_NAMES.iter().any(|name| {
        let shape = format!("{name}.join(");
        line.match_indices(&shape).any(|(at, _)| {
            !line[..at].chars().next_back().is_some_and(is_word)
                && names_a_store(&line[at + shape.len()..])
        })
    });
    let split = line
        .trim_start()
        .strip_prefix(".join(")
        .is_some_and(|rest| ends_with_a_root(previous.trim_end()) && names_a_store(rest));
    let wrapped = (line.contains("Path::new(") || line.contains("PathBuf::from("))
        && line
            .match_indices("root).join(")
            .any(|(at, _)| names_a_store(&line[at + "root).join(".len()..]));
    same_line || split || wrapped
}

/// Production Rust: not a test file, a test module or an example. Unlike `is_test_file`, the
/// `sg000` files count, since orceld's real entry is one of them.
fn is_production_rust(relative: &str, test_modules: &[String]) -> bool {
    relative.ends_with(".rs")
        && (relative.starts_with("crates/") || relative.starts_with("apps/"))
        && !vendored(relative)
        && !relative.ends_with("tests.rs")
        && !relative.contains("/tests/")
        && !relative.contains("examples/")
        && !relative.contains("benches/")
        && !test_modules.iter().any(|module| module == relative)
}

#[test]
fn state_stores_are_named_only_through_the_registry() {
    let root = repo_root();
    let files = text_files(&root);
    let test_modules = test_only_modules(&files);
    let mut hits = Vec::new();
    let mut used = vec![false; STATE_ROOT_RESOLVERS.len()];
    for (relative, text) in &files {
        if !is_production_rust(relative, &test_modules) {
            continue;
        }
        let resolver = STATE_ROOT_RESOLVERS
            .iter()
            .position(|(path, _)| path == relative);
        let lifecycle = relative.starts_with("crates/orcel-lifecycle/src/");
        let mut previous = "";
        for (number, line) in non_test_lines(text) {
            if line.trim_start().starts_with("//") {
                continue;
            }
            let before = std::mem::replace(&mut previous, line);
            // A deliberate exception names the store it means, for review.
            let excepted = line.contains("// registry:");
            if ["state_root(", "state_root_from(", "state_root_for("]
                .iter()
                .any(|call| line.contains(call))
            {
                match resolver {
                    Some(index) => used[index] = true,
                    None => hits.push(format!(
                        "{relative}:{number}: resolves the state root outside the listed \
                         resolvers: {}",
                        line.trim()
                    )),
                }
            }
            if (resolver.is_some() || lifecycle)
                && !excepted
                && joins_a_store_onto_a_root(line, before)
            {
                hits.push(format!(
                    "{relative}:{number}: names a store without the registry: {}",
                    line.trim()
                ));
            }
            // A sibling name derived from a store's path, like `report-tasks.key`.
            if resolver.is_some() && !excepted && line.contains(".with_extension(") {
                hits.push(format!(
                    "{relative}:{number}: derives a store name without the registry: {}",
                    line.trim()
                ));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "state stores must come from orcel_platform::stores (#655):\n{}",
        hits.join("\n")
    );
    let stale: Vec<_> = STATE_ROOT_RESOLVERS
        .iter()
        .zip(&used)
        .filter(|(_, used)| !**used)
        .map(|((path, _), _)| *path)
        .collect();
    assert!(stale.is_empty(), "stale resolver entries: {stale:?}");
}

#[test]
fn the_store_guard_catches_the_shapes_it_claims() {
    let caught = [
        ("root.join(\"x\")", ""),
        ("layout.root.join(\"x\")", ""),
        ("root.join(SOME_STORE)", ""),
        ("state.join(legacy::IN_PROGRESS)", ""),
        ("root.join(format!(\"x{n}\"))", ""),
        ("    .join(\"x\");", "        .root"),
        ("Path::new(&layout.root).join(\"x\")", ""),
    ];
    for (line, previous) in caught {
        assert!(joins_a_store_onto_a_root(line, previous), "{line}");
    }
    let passed = [
        ("root.join(relative)", ""),
        ("data_root.join(\"x\")", ""),
        ("workspace_root.join(\"x\")", ""),
        ("authority_dir(root).join(KEY_FILE_NAME)", ""),
        ("    .join(\"x\");", "        .data_root"),
    ];
    for (line, previous) in passed {
        assert!(!joins_a_store_onto_a_root(line, previous), "{line}");
    }
    assert!(is_production_rust(
        "crates/orceld/src/sg000039_main.rs",
        &[]
    ));
    assert!(!is_production_rust(
        "crates/orceld/src/app_api/tests.rs",
        &[]
    ));
}

/// A workflow line without its YAML comment (a `#` at the start or after whitespace) and
/// without trailing whitespace.
fn yaml_code(line: &str) -> &str {
    let bytes = line.as_bytes();
    let cut = line
        .char_indices()
        .find(|&(i, c)| c == '#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t'))
        .map_or(line.len(), |(i, _)| i);
    line[..cut].trim_end()
}

/// A YAML scalar without surrounding whitespace and one layer of matching quotes.
fn unquote(value: &str) -> &str {
    let value = value.trim();
    for quote in ['"', '\''] {
        if let Some(inner) = value
            .strip_prefix(quote)
            .and_then(|rest| rest.strip_suffix(quote))
        {
            return inner.trim();
        }
    }
    value
}

fn indent_of(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// Every permission the lines grant, as (scope, level), whatever the spelling: `write-all`
/// and `read-all` (scope `*`), flow style `{contents: write}`, block style, quoted keys or
/// values, extra spaces. A `permissions` key is matched only as a key, never inside a value.
fn permission_grants(lines: &[&str]) -> Vec<(String, String)> {
    let mut grants = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let code = yaml_code(lines[i]);
        let indent = indent_of(code);
        i += 1;
        let entry = code.trim_start().trim_start_matches("- ");
        let Some((key, value)) = entry.split_once(':') else {
            continue;
        };
        if unquote(key) != "permissions" {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            while i < lines.len() {
                let item = yaml_code(lines[i]);
                if !item.trim().is_empty() {
                    if indent_of(item) <= indent {
                        break;
                    }
                    let (scope, level) = item.trim().split_once(':').unwrap_or((item, ""));
                    grants.push((unquote(scope).to_owned(), unquote(level).to_owned()));
                }
                i += 1;
            }
        } else if let Some(inner) = value.strip_prefix('{') {
            let inner = inner.trim_end().strip_suffix('}');
            assert!(
                inner.is_some(),
                "a flow-style permissions mapping is closed on its line: {code}"
            );
            for pair in inner.unwrap_or("").split(',') {
                if !pair.trim().is_empty() {
                    let (scope, level) = pair.split_once(':').unwrap_or((pair, ""));
                    grants.push((unquote(scope).to_owned(), unquote(level).to_owned()));
                }
            }
        } else {
            let level = match unquote(value) {
                "write-all" => "write",
                "read-all" => "read",
                other => other,
            };
            grants.push(("*".to_owned(), level.to_owned()));
        }
    }
    grants
}

/// Whether a `uses:` value is a local action or a remote one pinned by a full commit SHA.
fn pinned_action(value: &str) -> bool {
    if let Some(local) = value.strip_prefix("./") {
        return !local.contains("..");
    }
    let Some((action, sha)) = value.split_once('@') else {
        return false;
    };
    action.contains('/')
        && !action.contains(':')
        && sha.len() == 40
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Every `uses:` value in a workflow or action file.
fn uses_values(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let entry = yaml_code(line).trim_start().trim_start_matches("- ");
            entry.strip_prefix("uses:").map(|v| unquote(v).to_owned())
        })
        .collect()
}

/// Lines where a `${{ }}` expression reaches a `run:` script, on its first line or below it:
/// a script block runs until a line indented no deeper than its `run:` key.
fn expressions_in_scripts(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut script: Option<usize> = None;
    for line in text.lines() {
        let indent = indent_of(line);
        if let Some(depth) = script {
            if line.trim().is_empty() || indent > depth {
                if line.contains("${{") {
                    found.push(line.to_owned());
                }
                continue;
            }
            script = None;
        }
        // The key's own column: `- run:` puts it two past the dash.
        let trimmed = line.trim_start().trim_start_matches("- ");
        if let Some(rest) = trimmed.strip_prefix("run:") {
            if rest.contains("${{") {
                found.push(line.to_owned());
            }
            script = Some(line.len() - trimmed.len());
        }
    }
    found
}

/// Whether text names a secret or the workflow token.
fn names_a_secret(text: &str) -> bool {
    text.lines().map(yaml_code).any(|code| {
        code.contains("secrets.") || code.contains("secrets[") || code.contains("github.token")
    })
}

fn read_lf(path: &Path) -> String {
    // A Windows checkout may have CRLF line endings.
    assert!(path.is_file(), "{}", path.display());
    fs::read_to_string(path).unwrap().replace("\r\n", "\n")
}

/// The release workflow keeps building and publishing apart: jobs that run repository and
/// dependency code hold only `contents: read` and name no secret, so nothing they run holds
/// release write access or an OIDC token. The publish job runs no repository code and waits
/// for the `release` environment's approval. Only a `v*` tag push starts it, every action is
/// pinned by commit, and no workflow expression is written into a script, here or in the
/// composite actions.
#[test]
fn the_release_workflow_separates_building_from_publishing() {
    let root = repo_root();
    let text = read_lf(&root.join(".github/workflows/release.yml"));
    let (head, jobs) = text.split_once("\njobs:\n").expect("a jobs section");

    // Top level: only a `v*` tag push triggers it, and the default token reads only.
    let top_keys: Vec<&str> = text
        .lines()
        .map(yaml_code)
        .filter(|code| !code.is_empty() && indent_of(code) == 0)
        .map(|code| unquote(code.split_once(':').map_or(code, |(key, _)| key)))
        .collect();
    assert_eq!(
        top_keys,
        ["name", "on", "permissions", "jobs"],
        "{top_keys:?}"
    );
    let head_lines: Vec<&str> = head.lines().collect();
    let on_start = head_lines
        .iter()
        .position(|line| unquote(yaml_code(line).trim_end_matches(':')) == "on")
        .expect("an on: key");
    let triggers: Vec<String> = head_lines[on_start + 1..]
        .iter()
        .copied()
        .map(yaml_code)
        .filter(|code| !code.is_empty())
        .take_while(|code| indent_of(code) > 0)
        .map(|code| code.trim().replace(['"', '\''], ""))
        .collect();
    assert_eq!(triggers, ["push:", "tags:", "- v*"], "{triggers:?}");
    for trigger in [
        "pull_request",
        "workflow_dispatch",
        "workflow_run",
        "workflow_call",
        "schedule",
        "repository_dispatch",
    ] {
        assert!(
            !text
                .lines()
                .map(yaml_code)
                .any(|code| code.contains(trigger)),
            "release.yml must not mention {trigger}"
        );
    }
    let read_only = vec![("contents".to_owned(), "read".to_owned())];
    assert_eq!(
        permission_grants(&head_lines),
        read_only,
        "workflow default"
    );

    // Jobs, split at two-space keys; comments say what a job doesn't do, only its keys count.
    let mut sections: Vec<(String, Vec<&str>)> = Vec::new();
    for line in jobs.lines() {
        let code = yaml_code(line);
        if code.is_empty() {
            continue;
        }
        if indent_of(code) == 2 && code.ends_with(':') {
            sections.push((code.trim().trim_end_matches(':').to_owned(), Vec::new()));
        } else if let Some((_, body)) = sections.last_mut() {
            body.push(code);
        }
    }
    fn job<'a>(sections: &'a [(String, Vec<&'a str>)], name: &str) -> &'a [&'a str] {
        &sections
            .iter()
            .find(|(job, _)| job == name)
            .expect("a job")
            .1
    }
    let body = |name: &str| job(&sections, name);
    let names: Vec<&str> = sections.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        ["build-windows", "build-linux", "publish"],
        "{names:?}"
    );
    let mut local_actions: Vec<String> = Vec::new();
    for build in ["build-windows", "build-linux"] {
        let job = body(build);
        let grants = permission_grants(job);
        assert_eq!(grants, read_only, "{build} reads only");
        assert!(
            grants.iter().all(|(_, level)| !level.contains("write")),
            "{build} must hold no write permission"
        );
        let joined = job.join("\n");
        assert!(!names_a_secret(&joined), "{build} must name no secret");
        assert!(
            !job.iter()
                .any(|code| unquote(code.trim().split(':').next().unwrap_or("")) == "environment"),
            "{build} must not use an environment"
        );
        local_actions.extend(
            uses_values(&joined)
                .into_iter()
                .filter(|value| value.starts_with("./")),
        );
    }
    let publish = body("publish");
    let mut grants = permission_grants(publish);
    grants.sort();
    assert_eq!(
        grants,
        [
            ("attestations".to_owned(), "write".to_owned()),
            ("contents".to_owned(), "write".to_owned()),
            ("id-token".to_owned(), "write".to_owned()),
        ],
        "publish holds exactly what attesting and uploading need"
    );
    let publish = publish.join("\n");
    assert!(
        publish
            .lines()
            .any(|code| code.trim().replace(['"', '\''], "") == "environment: release"),
        "publish waits for approval"
    );
    assert!(
        !publish.contains("actions/checkout"),
        "publish runs no repository code"
    );
    assert!(
        uses_values(&publish).iter().all(|v| !v.starts_with("./")),
        "publish runs no local action"
    );
    assert!(
        !publish.contains("cargo ") && !publish.contains("npm "),
        "publish builds nothing"
    );
    assert!(
        publish.contains("attest-build-provenance"),
        "publish attests the assets"
    );
    assert!(
        publish.contains("[A-Za-z0-9._+-]") && publish.contains("uniq -d"),
        "publish admits only plain names each build's checksum list names, and none twice"
    );
    assert!(
        !publish.contains("|| true") && !publish.contains("2>/dev/null"),
        "publish hides no failure"
    );

    // The build jobs' composite actions, and every other one, follow the same script rule
    // and name no secret.
    local_actions.sort();
    local_actions.dedup();
    assert!(
        !local_actions.is_empty(),
        "the Windows build uses its actions"
    );
    let mut files = vec![(".github/workflows/release.yml".to_owned(), text.clone())];
    let mut action_dirs: Vec<String> = fs::read_dir(root.join(".github/actions"))
        .expect("the composite actions")
        .map(|entry| {
            format!(
                "./.github/actions/{}",
                entry.unwrap().file_name().to_string_lossy()
            )
        })
        .collect();
    action_dirs.sort();
    for action in &local_actions {
        assert!(
            action_dirs.contains(action),
            "{action} is a composite action"
        );
    }
    for action in &action_dirs {
        let path = format!("{}/action.yml", action.trim_start_matches("./"));
        let action_text = read_lf(&root.join(&path));
        assert!(
            action_text.contains("using: composite"),
            "{path} is a composite action"
        );
        assert!(!names_a_secret(&action_text), "{path} must name no secret");
        files.push((path, action_text));
    }
    for (path, file) in &files {
        let reached = expressions_in_scripts(file);
        assert!(
            reached.is_empty(),
            "{path}: an expression reaches a script; pass it through env: {reached:?}"
        );
        for value in uses_values(file) {
            assert!(
                pinned_action(&value),
                "{path}: {value} is not pinned by a full commit SHA"
            );
        }
    }
}

/// The release workflow sweep's parsers catch the spellings they claim, and a script that
/// merely mentions a permission is not a grant.
#[test]
fn the_release_sweep_parsers_catch_the_spellings_they_claim() {
    let grants = |text: &str| permission_grants(&text.lines().collect::<Vec<_>>());
    let pair = |scope: &str, level: &str| (scope.to_owned(), level.to_owned());
    assert_eq!(grants("    permissions: write-all"), [pair("*", "write")]);
    assert_eq!(grants("    permissions: 'read-all'"), [pair("*", "read")]);
    assert_eq!(
        grants("    permissions: { contents : write , \"id-token\": 'write' }"),
        [pair("contents", "write"), pair("id-token", "write")]
    );
    assert_eq!(
        grants("    permissions:\n      \"contents\" :  \"read\"  # x\n      packages: write\n    steps:"),
        [pair("contents", "read"), pair("packages", "write")]
    );
    let none: Vec<(String, String)> = Vec::new();
    assert_eq!(
        grants("      - run: echo contents: read\n      - run: echo permissions-less"),
        none
    );
    assert_eq!(grants("    permissions: {}"), none);
    assert!(pinned_action(
        "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
    ));
    assert!(pinned_action("./.github/actions/build-package-qualify"));
    assert!(!pinned_action("actions/checkout@v4"));
    assert!(!pinned_action(
        "actions/checkout@11D5960A326750D5838078E36CF38B85AF677262"
    ));
    assert!(!pinned_action("docker://alpine@sha256:abc"));
    assert!(!pinned_action("./../elsewhere"));
    assert_eq!(
        uses_values("      - uses: \"a/b@c\" # v1\n        uses: d/e@f"),
        ["a/b@c", "d/e@f"]
    );
    assert_eq!(
        expressions_in_scripts(
            "      - run: |\n          echo ${{ inputs.x }}\n        env:\n          X: ${{ inputs.x }}\n"
        ),
        ["          echo ${{ inputs.x }}"]
    );
    assert!(names_a_secret("        token: ${{ secrets.X }}"));
    assert!(names_a_secret("        GH_TOKEN: ${{ github.token }}"));
    assert!(!names_a_secret("        # secrets.X is never used"));
    assert_eq!(yaml_code("  a: b # c"), "  a: b");
    assert_eq!(yaml_code("  a: b#c"), "  a: b#c");
}

/// SG-000119 A1: the Control Room's app API client
/// (`crates/orcel-app-api-client`) never reaches a release binary. It is a
/// root workspace member only so its tests run on the root legs; no other
/// manifest may depend on it, except the shell's own src-tauri workspace (A2),
/// which is never in the release payload. Lock files are checked too: no
/// package in any of them may list it as a dependency, except that shell's.
#[test]
fn the_app_api_client_crate_reaches_no_release_binary() {
    const CRATE: &str = "orcel-app-api-client";
    const OWN: &str = "crates/orcel-app-api-client/Cargo.toml";
    const SHELL: &str = "apps/orcel-control-room/src-tauri/";
    let root = repo_root();
    let mut hits = Vec::new();
    let mut manifests = 0;
    // text_files skips lock files, so every Cargo.toml and Cargo.lock is
    // read here directly.
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                // `dist` folders are walked too: a manifest there is still
                // a manifest.
                if !matches!(name.as_str(), ".git" | "target" | "node_modules") {
                    stack.push(path);
                }
                continue;
            }
            if name != "Cargo.toml" && name != "Cargo.lock" {
                continue;
            }
            let relative = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if relative == OWN || relative.starts_with(SHELL) {
                continue;
            }
            manifests += 1;
            let text = fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
            if name == "Cargo.toml" {
                // The root manifest may name it only as a workspace member.
                for line in text.lines().filter(|line| line.contains(CRATE)) {
                    let member = relative == "Cargo.toml"
                        && line.trim() == "\"crates/orcel-app-api-client\",";
                    if !member {
                        hits.push(format!("{relative}: {}", line.trim()));
                    }
                }
            } else {
                // A dependency entry is ` "orcel-app-api-client",` or, when
                // several versions are locked, ` "orcel-app-api-client 0.2.0",`
                // inside another package's `dependencies = [...]`: match the
                // quoted prefix.
                for block in text.split("\n[[package]]\n") {
                    let own = block.starts_with(&format!("name = \"{CRATE}\"\n"));
                    if !own && block.contains(&format!(" \"{CRATE}")) {
                        hits.push(format!(
                            "{relative}: {}",
                            block.lines().next().unwrap_or_default()
                        ));
                    }
                }
            }
        }
    }
    assert!(manifests > 2, "found only {manifests} manifests");
    assert!(
        hits.is_empty(),
        "orcel-app-api-client must stay out of every release build:\n{}",
        hits.join("\n")
    );
}

/// SG-000119 A2 (founder decision 6, development builds only): the Control Room shell is never
/// published. Exactly one job, `control-room-shell` in `ci.yml`, builds it, and it uploads
/// nothing; no other job names `src-tauri` or the shell binary; only that job and the headless
/// `control-room` job (in its `npm --prefix` commands alone) name `apps/orcel-control-room`; no
/// upload step in any of the four workflows has a path covering `apps/orcel-control-room/**`;
/// and nothing under `distribution/` names any of them. Upload paths are decided, never
/// guessed: each line of a block path, `${{ env.NAME }}` expanded from the step, job and
/// workflow `env`, `${{ github.workspace }}` read as the checkout root, `${{ runner.temp }}`
/// and `/tmp` outside it; any other expression or a missing `env` name fails.
#[test]
fn the_control_room_shell_is_never_published() {
    const SHELL_JOB: &str = "control-room-shell";
    const HEADLESS_JOB: &str = "control-room";
    let root = repo_root();
    let mut shell_jobs = Vec::new();
    let mut decided = Vec::new();
    let mut hits = Vec::new();
    for workflow in ["ci.yml", "pages.yml", "release.yml", "review-gates.yml"] {
        let text = read_lf(&root.join(".github/workflows").join(workflow));
        let parsed = WorkflowJobs::parse(&text);
        for (number, code) in &parsed.head {
            if names_the_control_room(code) {
                hits.push(format!(
                    "{workflow}:{number}: outside every job: {}",
                    code.trim()
                ));
            }
        }
        for job in &parsed.jobs {
            if job.name == SHELL_JOB {
                shell_jobs.push(workflow);
            }
            for (number, code) in &job.lines {
                if job.name != SHELL_JOB
                    && names_the_control_room(code)
                    && !(job.name == HEADLESS_JOB && headless_npm_line(code))
                {
                    hits.push(format!(
                        "{workflow}:{number} (job {}): names the Control Room: {}",
                        job.name,
                        code.trim()
                    ));
                }
            }
            for step in job.upload_steps() {
                let at = format!("{workflow}:{} (job {})", step.line, job.name);
                if job.name == SHELL_JOB {
                    hits.push(format!("{at}: the shell job uploads"));
                }
                let (paths, problems) = upload_step_findings(&step, &job.env, &parsed.env);
                decided.extend(paths.iter().map(|path| format!("{workflow}: {path}")));
                hits.extend(problems.iter().map(|problem| format!("{at}: {problem}")));
            }
        }
    }
    assert_eq!(
        shell_jobs,
        ["ci.yml"],
        "exactly one {SHELL_JOB} job, in ci.yml"
    );
    for (relative, text) in text_files(&root) {
        // Composite actions belong to no job that may build the shell, and distribution
        // ships nothing of it.
        let action = relative.starts_with(".github/actions/")
            && (relative.ends_with("/action.yml") || relative.ends_with("/action.yaml"));
        if action {
            for (index, line) in text.replace("\r\n", "\n").lines().enumerate() {
                if names_the_control_room(yaml_code(line)) {
                    hits.push(format!(
                        "{relative}:{}: a composite action names the Control Room: {}",
                        index + 1,
                        line.trim()
                    ));
                }
            }
        }
        if relative.starts_with("distribution/") && names_the_control_room(&text) {
            hits.push(format!(
                "{relative}: distribution names the Control Room shell"
            ));
        }
    }
    println!("decided upload paths:\n{}", decided.join("\n"));
    assert!(!decided.is_empty(), "no upload path was decided");
    assert!(
        hits.is_empty(),
        "the Control Room shell must never be published:\n{}",
        hits.join("\n")
    );
}

const CONTROL_ROOM_APP: &str = "apps/orcel-control-room";

/// Any mention of the Control Room's tree or binary: the bare `orcel-control-room` (which the
/// app path and the shell binary's name both contain) or `src-tauri`.
fn names_the_control_room(text: &str) -> bool {
    text.contains("orcel-control-room") || text.contains("src-tauri")
}

/// One upload step decided: each path with where it points, and every problem with it (a path
/// covering the app, a path that cannot be decided, or paths that cannot be read at all).
fn upload_step_findings(
    step: &UploadStep,
    job_env: &BTreeMap<String, String>,
    workflow_env: &BTreeMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let mut decided = Vec::new();
    let mut problems = Vec::new();
    let paths = match step.paths() {
        Ok(paths) => paths,
        Err(reason) => {
            problems.push(format!("upload paths cannot be read: {reason}"));
            return (decided, problems);
        }
    };
    for path in paths {
        match decide_upload_path(&path, &[&step.env, job_env, workflow_env]) {
            Ok(place) => {
                if place.covers_the_control_room() {
                    problems.push(format!("upload path {path} covers {CONTROL_ROOM_APP}"));
                }
                decided.push(format!("{path} -> {place:?}"));
            }
            Err(reason) => problems.push(format!("upload path {path} cannot be decided: {reason}")),
        }
    }
    (decided, problems)
}

/// A headless `control-room` job line may name the app only as an `npm` command run with
/// `--prefix apps/orcel-control-room` (the prefix exactly, never a folder below it).
///
/// The headless job's three commands are pinned exactly (whitespace normalized), so no other
/// npm form (`exec`, `npx`, `run-script`, an extra argument naming another path) is exempt,
/// and every word naming `orcel-control-room` must be the app path itself.
fn headless_npm_line(code: &str) -> bool {
    const HEADLESS_COMMANDS: [&str; 3] = [
        "npm ci --prefix apps/orcel-control-room --ignore-scripts",
        "npm --prefix apps/orcel-control-room run typecheck",
        "npm --prefix apps/orcel-control-room test",
    ];
    let command = code.trim().trim_start_matches("- ");
    let command = command.strip_prefix("run:").unwrap_or(command).trim();
    let words: Vec<&str> = command.split_whitespace().collect();
    words
        .iter()
        .filter(|word| word.contains("orcel-control-room"))
        .all(|word| *word == CONTROL_ROOM_APP)
        && HEADLESS_COMMANDS.contains(&words.join(" ").as_str())
}

/// A workflow split into its head (before `jobs:`) and its jobs, comments removed; each line
/// keeps its 1-based number.
struct WorkflowJobs {
    head: Vec<(usize, String)>,
    env: BTreeMap<String, String>,
    jobs: Vec<WorkflowJob>,
}

struct WorkflowJob {
    name: String,
    lines: Vec<(usize, String)>,
    env: BTreeMap<String, String>,
}

struct UploadStep {
    line: usize,
    body: Vec<(usize, String)>,
    item_indent: usize,
    env: BTreeMap<String, String>,
}

/// The `key: value` pairs of the block under the line at `at` (a `key:` line at `indent`),
/// one level deeper.
fn block_map(lines: &[(usize, String)], at: usize, indent: usize) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    let mut child = None;
    for (_, code) in &lines[at + 1..] {
        if code.trim().is_empty() {
            continue;
        }
        let depth = indent_of(code);
        if depth <= indent {
            break;
        }
        let child_indent = *child.get_or_insert(depth);
        if depth == child_indent {
            if let Some((key, value)) = code.trim().split_once(':') {
                map.insert(unquote(key).to_owned(), unquote(value).to_owned());
            }
        }
    }
    map
}

/// The index of the `key:` line at exactly `indent` among `lines`, if any.
fn key_at(lines: &[(usize, String)], key: &str, indent: usize) -> Option<usize> {
    lines.iter().position(|(_, code)| {
        indent_of(code) == indent
            && code
                .trim()
                .split_once(':')
                .is_some_and(|(name, _)| unquote(name) == key)
    })
}

impl WorkflowJobs {
    fn parse(text: &str) -> WorkflowJobs {
        let numbered: Vec<(usize, String)> = text
            .lines()
            .enumerate()
            .map(|(index, line)| (index + 1, yaml_code(line).to_owned()))
            .collect();
        let jobs_at = numbered
            .iter()
            .position(|(_, code)| code == "jobs:")
            .expect("a jobs: key");
        let head: Vec<(usize, String)> = numbered[..jobs_at].to_vec();
        let env = key_at(&head, "env", 0)
            .map(|at| block_map(&head, at, 0))
            .unwrap_or_default();
        let mut jobs: Vec<WorkflowJob> = Vec::new();
        for (number, code) in &numbered[jobs_at + 1..] {
            if code.trim().is_empty() {
                continue;
            }
            let depth = indent_of(code);
            assert!(depth > 0, "a top-level key after jobs: at line {number}");
            if depth == 2 && code.ends_with(':') {
                jobs.push(WorkflowJob {
                    name: code.trim().trim_end_matches(':').to_owned(),
                    lines: Vec::new(),
                    env: BTreeMap::new(),
                });
            } else if let Some(job) = jobs.last_mut() {
                job.lines.push((*number, code.clone()));
            }
        }
        for job in &mut jobs {
            job.env = key_at(&job.lines, "env", 4)
                .map(|at| block_map(&job.lines, at, 4))
                .unwrap_or_default();
        }
        WorkflowJobs { head, env, jobs }
    }
}

impl WorkflowJob {
    /// Every step whose `uses:` is `actions/upload-artifact` or
    /// `actions/upload-pages-artifact`.
    fn upload_steps(&self) -> Vec<UploadStep> {
        let Some(steps_at) = key_at(&self.lines, "steps", 4) else {
            return Vec::new();
        };
        let rest = &self.lines[steps_at + 1..];
        let item_indent = rest
            .iter()
            .find(|(_, code)| !code.trim().is_empty())
            .map(|(_, code)| indent_of(code))
            .unwrap_or(0);
        let mut steps: Vec<UploadStep> = Vec::new();
        for (number, code) in rest {
            if code.trim().is_empty() {
                continue;
            }
            let depth = indent_of(code);
            if depth < item_indent {
                break;
            }
            if depth == item_indent && code.trim_start().starts_with("- ") {
                // The dash line's own key sits two columns in, as the step's other keys do.
                let key_line =
                    format!("{}{}", " ".repeat(item_indent + 2), &code.trim_start()[2..]);
                steps.push(UploadStep {
                    line: *number,
                    body: vec![(*number, key_line)],
                    item_indent,
                    env: BTreeMap::new(),
                });
            } else if let Some(step) = steps.last_mut() {
                step.body.push((*number, code.clone()));
            }
        }
        // Action references are matched without case: GitHub resolves `Actions/Upload-Artifact`
        // to the same action.
        steps.retain(|step| {
            step.value("uses").is_some_and(|uses| {
                let uses = uses.to_ascii_lowercase();
                uses.starts_with("actions/upload-artifact@")
                    || uses.starts_with("actions/upload-pages-artifact@")
            })
        });
        for step in &mut steps {
            step.env = key_at(&step.body, "env", step.item_indent + 2)
                .map(|at| block_map(&step.body, at, step.item_indent + 2))
                .unwrap_or_default();
        }
        steps
    }
}

impl UploadStep {
    fn value(&self, key: &str) -> Option<String> {
        let at = key_at(&self.body, key, self.item_indent + 2)?;
        let (_, value) = self.body[at].1.trim().split_once(':')?;
        Some(unquote(value).to_owned())
    }

    /// The `with: path:` entries: a scalar, or each line of a block scalar; a `!` line is an
    /// exclusion and can only remove files, so it is skipped. Fails closed: an upload step
    /// whose paths cannot be read in this block form (no `with:` block, inline `with:` content
    /// such as a flow mapping, no `path`, a flow or empty value, only exclusions) is an error,
    /// never an empty list.
    fn paths(&self) -> Result<Vec<String>, String> {
        let with_indent = self.item_indent + 2;
        let with_at = key_at(&self.body, "with", with_indent).ok_or("no `with:` block")?;
        let (_, inline) = self.body[with_at]
            .1
            .trim()
            .split_once(':')
            .unwrap_or(("", ""));
        if !inline.trim().is_empty() {
            return Err(format!(
                "inline `with:` content cannot be decided: {}",
                inline.trim()
            ));
        }
        let block: Vec<(usize, String)> = self.body[with_at + 1..]
            .iter()
            .take_while(|(_, code)| code.trim().is_empty() || indent_of(code) > with_indent)
            .cloned()
            .collect();
        let key_indent = block
            .iter()
            .find(|(_, code)| !code.trim().is_empty())
            .map(|(_, code)| indent_of(code))
            .ok_or("an empty `with:` block")?;
        let path_at = key_at(&block, "path", key_indent).ok_or("no `path` under `with:`")?;
        let (_, value) = block[path_at].1.trim().split_once(':').unwrap_or(("", ""));
        let value = value.trim();
        let lines: Vec<String> = if value.starts_with('|') || value.starts_with('>') {
            block[path_at + 1..]
                .iter()
                .take_while(|(_, code)| code.trim().is_empty() || indent_of(code) > key_indent)
                .map(|(_, code)| code.trim().to_owned())
                .filter(|line| !line.is_empty())
                .collect()
        } else if value.starts_with('[') || value.starts_with('{') {
            return Err(format!("a flow-style `path` cannot be decided: {value}"));
        } else {
            vec![unquote(value).to_owned()]
        };
        let paths: Vec<String> = lines
            .into_iter()
            .filter(|line| !line.is_empty() && !line.starts_with('!'))
            .collect();
        if paths.is_empty() {
            return Err("`path` names nothing to decide".to_owned());
        }
        Ok(paths)
    }
}

/// Where an upload path points.
#[derive(Debug, PartialEq)]
enum UploadPlace {
    /// Outside the checkout (`runner.temp`, `/tmp`, or a path that leaves the checkout).
    Outside,
    /// Checkout-relative, normalized (empty: the checkout root).
    Checkout(String),
}

impl UploadPlace {
    /// Whether the path covers `apps/orcel-control-room/**`: the root, `apps`, the app or
    /// anything under it, or a glob whose directory before the first `*`, `?` or `[` is one of
    /// those. Compared without case (Windows runners).
    fn covers_the_control_room(&self) -> bool {
        let UploadPlace::Checkout(path) = self else {
            return false;
        };
        let path = path.to_ascii_lowercase();
        let literal = match path.find(['*', '?', '[']) {
            Some(glob) => path[..glob].rsplit_once('/').map_or("", |(dir, _)| dir),
            None => path.as_str(),
        };
        literal.is_empty()
            || literal == "apps"
            || literal == CONTROL_ROOM_APP
            || literal.starts_with(&format!("{CONTROL_ROOM_APP}/"))
    }
}

const WORKSPACE_MARK: &str = "\u{1}workspace\u{1}";
const TEMP_MARK: &str = "\u{1}temp\u{1}";

/// Expands `${{ }}` expressions: `env.NAME` from the first scope that has it (decided again),
/// `github.workspace` and `runner.temp` to markers; anything else fails.
fn expand_upload_path(
    text: &str,
    scopes: &[&BTreeMap<String, String>],
    depth: usize,
) -> Result<String, String> {
    if depth > 8 {
        return Err("env expansion does not end".to_owned());
    }
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        let end = after.find("}}").ok_or("an unclosed expression")?;
        let inner = after[..end].trim();
        if let Some(name) = inner.strip_prefix("env.") {
            let value = scopes
                .iter()
                .find_map(|scope| scope.get(name))
                .ok_or(format!("env.{name} is set in no step, job or workflow env"))?;
            out.push_str(&expand_upload_path(value, scopes, depth + 1)?);
        } else if inner == "github.workspace" {
            out.push_str(WORKSPACE_MARK);
        } else if inner == "runner.temp" {
            out.push_str(TEMP_MARK);
        } else {
            return Err(format!(
                "the expression `{inner}` is not runner.temp, github.workspace or env"
            ));
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

fn decide_upload_path(
    path: &str,
    scopes: &[&BTreeMap<String, String>],
) -> Result<UploadPlace, String> {
    let expanded = expand_upload_path(path.trim(), scopes, 0)?;
    let (relative, from_workspace) = if let Some(rest) = expanded.strip_prefix(WORKSPACE_MARK) {
        (rest.to_owned(), true)
    } else if expanded.starts_with(TEMP_MARK) {
        return Ok(UploadPlace::Outside);
    } else {
        (expanded, false)
    };
    if relative.contains('\u{1}') {
        return Err("runner.temp or github.workspace inside a path".to_owned());
    }
    let unix = relative.replace('\\', "/");
    if !from_workspace {
        if unix.starts_with("/tmp/") || unix.starts_with("/var/tmp/") {
            return Ok(UploadPlace::Outside);
        }
        if unix.starts_with('/') || unix.starts_with('~') || unix.as_bytes().get(1) == Some(&b':') {
            return Err("an absolute path that may lie under the checkout".to_owned());
        }
    }
    let mut segments: Vec<&str> = Vec::new();
    for segment in unix.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Ok(UploadPlace::Outside);
                }
            }
            other => segments.push(other),
        }
    }
    Ok(UploadPlace::Checkout(segments.join("/")))
}

/// The no-publication parsers decide the shapes they claim.
#[test]
fn the_no_publication_parsers_decide_the_shapes_they_claim() {
    let env = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    };
    let step = env(&[("STEP", "apps/web/out")]);
    let job = env(&[
        ("DIST", "${{ github.workspace }}/macos-dist"),
        ("STEP", "apps"),
        ("LOOP", "${{ env.LOOP }}"),
    ]);
    let workflow = env(&[("APP", "apps/orcel-control-room/src-tauri/target")]);
    let scopes = [&step, &job, &workflow];
    let decide = |path: &str| decide_upload_path(path, &scopes);
    let checkout = |path: &str| Ok(UploadPlace::Checkout(path.to_owned()));
    // Today's shapes.
    assert_eq!(
        decide("${{ runner.temp }}/xp08-reports"),
        Ok(UploadPlace::Outside)
    );
    assert_eq!(decide("${{runner.temp}}/dist/*"), Ok(UploadPlace::Outside));
    assert_eq!(
        decide("target/release/examples/f4_journey.exe"),
        checkout("target/release/examples/f4_journey.exe")
    );
    assert_eq!(decide("${{ env.DIST }}/"), checkout("macos-dist"));
    assert_eq!(decide("apps/web/out"), checkout("apps/web/out"));
    assert_eq!(
        decide("/tmp/orcel-ocr-output/ocr-preview.json"),
        Ok(UploadPlace::Outside)
    );
    assert_eq!(decide("jev-review.json"), checkout("jev-review.json"));
    // The step's env wins over the job's; the workflow's is read last.
    assert_eq!(decide("${{ env.STEP }}"), checkout("apps/web/out"));
    assert_eq!(
        decide("${{ env.APP }}"),
        checkout("apps/orcel-control-room/src-tauri/target")
    );
    // Normalization; leaving the checkout is outside.
    assert_eq!(
        decide("./apps/../apps/./orcel-control-room/"),
        checkout("apps/orcel-control-room")
    );
    assert_eq!(decide("../elsewhere"), Ok(UploadPlace::Outside));
    assert_eq!(decide("${{ github.workspace }}"), checkout(""));
    assert_eq!(
        decide("${{ github.workspace }}/../x"),
        Ok(UploadPlace::Outside)
    );
    // What cannot be decided fails.
    assert!(decide("${{ env.MISSING }}/x").is_err());
    assert!(decide("${{ github.event.pull_request.head.sha }}/x").is_err());
    assert!(decide("${{ env.LOOP }}").is_err());
    assert!(decide("${{ steps.x.outputs.dir }}").is_err());
    assert!(decide("${{ runner.temp").is_err());
    assert!(decide("/home/runner/work/Orcel/Orcel/apps").is_err());
    assert!(decide("D:\\a\\Orcel\\Orcel\\apps").is_err());
    assert!(decide("x/${{ github.workspace }}").is_err());
    // Coverage.
    for covering in [
        "",
        "apps",
        "APPS/Orcel-Control-Room",
        "apps/orcel-control-room",
        "apps/orcel-control-room/src-tauri/target/debug",
        "*",
        "**",
        "a*",
        "apps/*",
        "apps/**",
        "apps/orcel-*",
        "apps/orcel-control-room/**/*.exe",
        "ap?s/x",
    ] {
        assert!(
            UploadPlace::Checkout(covering.to_owned()).covers_the_control_room(),
            "{covering}"
        );
    }
    for apart in [
        "apps/web/out",
        "apps/orcel-control-room-x",
        "apps/web/*",
        "macos-dist",
        "target/release/examples/f4_journey.exe",
        "jev-review.json",
    ] {
        assert!(
            !UploadPlace::Checkout(apart.to_owned()).covers_the_control_room(),
            "{apart}"
        );
    }
    assert!(!UploadPlace::Outside.covers_the_control_room());

    // Steps, block paths, exclusions and env scopes, from a workflow's text.
    let text = [
        "name: x",
        "on: push",
        "env:",
        "  TOP: apps",
        "jobs:",
        "  a:",
        "    runs-on: x",
        "    env:",
        "      DIST: ${{ github.workspace }}/out",
        "    steps:",
        "      - run: echo apps/orcel-control-room",
        "      - name: up",
        "        uses: actions/upload-artifact@0000000000000000000000000000000000000000 # v4",
        "        env:",
        "          MINE: apps/web",
        "        with:",
        "          name: n",
        "          path: |",
        "            ${{ env.DIST }}/a",
        "            !apps/orcel-control-room",
        "            ${{ env.MINE }}/b # c",
        "            ${{ env.TOP }}",
        "          retention-days: 3",
        "      - uses: actions/upload-pages-artifact@0000000000000000000000000000000000000000",
        "        with:",
        "          path: \"apps/web/out\"",
        "  control-room:",
        "    steps:",
        "      - run: npm --prefix apps/orcel-control-room test",
        "",
    ]
    .join("\n");
    let parsed = WorkflowJobs::parse(&text);
    assert_eq!(parsed.env.get("TOP").map(String::as_str), Some("apps"));
    let names: Vec<&str> = parsed.jobs.iter().map(|job| job.name.as_str()).collect();
    assert_eq!(names, ["a", "control-room"]);
    let job = &parsed.jobs[0];
    assert_eq!(
        job.env.get("DIST").map(String::as_str),
        Some("${{ github.workspace }}/out")
    );
    let steps = job.upload_steps();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].line, 12);
    assert_eq!(
        steps[0].env.get("MINE").map(String::as_str),
        Some("apps/web")
    );
    assert_eq!(
        steps[0].paths().unwrap(),
        ["${{ env.DIST }}/a", "${{ env.MINE }}/b", "${{ env.TOP }}"]
    );
    let decided: Vec<UploadPlace> = steps[0]
        .paths()
        .unwrap()
        .iter()
        .map(|path| decide_upload_path(path, &[&steps[0].env, &job.env, &parsed.env]).unwrap())
        .collect();
    assert_eq!(
        decided,
        [
            UploadPlace::Checkout("out/a".to_owned()),
            UploadPlace::Checkout("apps/web/b".to_owned()),
            UploadPlace::Checkout("apps".to_owned()),
        ]
    );
    assert!(decided[2].covers_the_control_room());
    assert_eq!(steps[1].paths().unwrap(), ["apps/web/out"]);
    let (_, problems) = upload_step_findings(&steps[0], &job.env, &parsed.env);
    assert_eq!(
        problems,
        ["upload path ${{ env.TOP }} covers apps/orcel-control-room"]
    );

    // Fail-closed shapes (security judge, A2): each upload step below is found, and each one
    // fails the rule instead of passing with no path.
    let shapes = [
        "  a:",
        "    steps:",
        // An action reference in another letter case is the same action.
        "      - uses: Actions/Upload-Artifact@0000000000000000000000000000000000000000",
        "        with:",
        "          path: apps",
        // Inline `with:` content (a flow mapping) is never read as having no path.
        "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000",
        "        with: { name: x, path: apps }",
        // No path at all.
        "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000",
        "        with:",
        "          name: x",
        // No `with:` at all.
        "      - uses: ACTIONS/UPLOAD-PAGES-ARTIFACT@0000000000000000000000000000000000000000",
        // A flow-style path, an empty path, and exclusions only.
        "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000",
        "        with:",
        "          path: [apps]",
        "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000",
        "        with:",
        "          path:",
        "      - uses: actions/upload-artifact@0000000000000000000000000000000000000000",
        "        with:",
        "          path: |",
        "            !apps/orcel-control-room",
        "      - run: echo done",
    ];
    let text = format!("name: x\non: push\njobs:\n{}\n", shapes.join("\n"));
    let parsed = WorkflowJobs::parse(&text);
    let job = &parsed.jobs[0];
    let steps = job.upload_steps();
    let lines: Vec<usize> = steps.iter().map(|step| step.line).collect();
    assert_eq!(
        lines,
        [6, 9, 11, 14, 15, 18, 21],
        "every upload step is found"
    );
    let problems: Vec<String> = steps
        .iter()
        .map(|step| {
            let (decided, problems) = upload_step_findings(step, &job.env, &parsed.env);
            assert!(
                !problems.is_empty(),
                "step at line {} passed: {decided:?}",
                step.line
            );
            problems.join("; ")
        })
        .collect();
    assert_eq!(
        problems,
        [
            "upload path apps covers apps/orcel-control-room",
            "upload paths cannot be read: inline `with:` content cannot be decided: \
             { name: x, path: apps }",
            "upload paths cannot be read: no `path` under `with:`",
            "upload paths cannot be read: no `with:` block",
            "upload paths cannot be read: a flow-style `path` cannot be decided: [apps]",
            "upload paths cannot be read: `path` names nothing to decide",
            "upload paths cannot be read: `path` names nothing to decide",
        ]
    );

    // The bare name is caught wherever it appears.
    assert!(names_the_control_room("cargo build -p orcel-control-room"));
    assert!(names_the_control_room(
        "cd apps/orcel-control-room && npm test"
    ));
    assert!(names_the_control_room("working-directory: x/src-tauri"));
    assert!(!names_the_control_room("npm --prefix apps/web test"));
    // The headless job's npm lines pass; anything else naming the app does not.
    assert!(headless_npm_line(
        "      - run: npm --prefix apps/orcel-control-room test"
    ));
    assert!(headless_npm_line(
        "        run: npm ci --prefix apps/orcel-control-room --ignore-scripts"
    ));
    assert!(!headless_npm_line(
        "        run: npm --prefix apps/orcel-control-room/src-tauri test"
    ));
    assert!(!headless_npm_line(
        "        run: cargo build --manifest-path apps/orcel-control-room/src-tauri/Cargo.toml"
    ));
    assert!(!headless_npm_line(
        "        working-directory: apps/orcel-control-room"
    ));
    assert!(!headless_npm_line(
        "        run: npm --prefix apps/orcel-control-room test && cargo test"
    ));
    assert!(headless_npm_line(
        "        run: npm   --prefix apps/orcel-control-room   run typecheck"
    ));
    // Re-judge (A2): only the three pinned commands are exempt.
    for refused in [
        "        run: npm --prefix apps/orcel-control-room exec -- tar czf x.tgz ../orcel-control-room",
        "        run: npm --prefix apps/orcel-control-room exec -- tar czf x.tgz .",
        "        run: npx --prefix apps/orcel-control-room tar czf x.tgz .",
        "        run: npm --prefix apps/orcel-control-room run-script typecheck",
        "        run: npm --prefix apps/orcel-control-room run build",
        "        run: npm --prefix apps/orcel-control-room test -- ../orcel-control-room-shell",
        "        run: npm --prefix apps/orcel-control-room test --workspace x",
        "        run: npm ci --prefix apps/orcel-control-room",
    ] {
        assert!(!headless_npm_line(refused), "{refused}");
    }
    assert!(names_the_control_room(
        "cargo build -p orcel-control-room-shell"
    ));
}
