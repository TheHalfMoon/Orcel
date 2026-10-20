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
                    || ((relative == "crates/orcel-browser-host/src/worker_launch_tests.rs"
                        || relative == "crates/orcel-browser-host/tests/sg000108_worker_host.rs"
                        || relative == "crates/orceld/src/live_browser.rs")
                        && line.contains(
                            "requires the built browser worker and Edge; run by npm run browser-launcher:native",
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
