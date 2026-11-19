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
//! source, Orcel's own native-host sources, the Node worker and the MCP
//! server): no production source calls the Autofill or WebAuthn domains,
//! opens the engine's credential, autofill or cookie stores, changes the
//! password-manager preferences, answers an HTTP authentication challenge,
//! types free text, records traffic, reads or writes cookies in bulk, reads
//! a request body outside the one gated submission path, or names a tool
//! that would fill a login. Comments may name them to say they are never
//! used. Inline Rust test modules (`#[cfg(test)] mod name { ... }`) are
//! left out, and only those: every other line is scanned (out-of-line test
//! files too), and each key file proves it.

use std::path::{Path, PathBuf};

type Outcome = Result<(), Box<dyn std::error::Error>>;

/// Calls and names that would let Orcel trigger, read, answer or store a
/// login.
const FORBIDDEN: &[&str] = &[
    // CDP domains: card and address autofill from caller data; a virtual
    // authenticator (excluded by SG-000135, never a passkey bypass).
    "Autofill.",
    "WebAuthn.",
    // The engine profile's credential, autofill and cookie stores.
    "Login Data",
    "Web Data",
    "\"Cookies\"",
    "/Cookies",
    "\\\\Cookies",
    "os_crypt",
    "encrypted_key",
    // Password-manager preferences.
    "credentials_enable_service",
    "password_manager",
    "PasswordManager",
    // HTTP authentication answered by Orcel (a credential in Orcel's hands).
    "httpCredentials",
    "setHTTPCredentials",
    "continueWithAuth",
    "ProvideCredentials",
    "handleAuthRequests",
    // Free typing into a page outside the guarded fill (Playwright's fill in
    // actions/form.ts, which refuses secret fields).
    "Input.insertText",
    "keyboard.type",
    "pressSequentially",
    // Recording traffic or page state (request bodies, cookies, fields).
    "recordHar",
    "tracing.start",
    // Bulk cookie reads and writes (a sign-in carried out of the browser).
    "getAllCookies",
    "Storage.getCookies",
    "Storage.setCookies",
    "Network.getCookies",
    "Network.setCookie",
    ".cookies(",
    "addCookies",
    "storageState",
    // Request bodies: only the gated submission path reads one.
    "postData",
    // Tool names a later packet must not add without a new decision.
    "browser_autofill",
    "browser_login",
    "browser_password",
    "browser_credential",
    "browser_sign_in",
];

/// The one place each token may appear, and why.
const ALLOWED: &[(&str, &str)] = &[
    // requestDetail describes a request's body; the worker sends it to the
    // host only while an approved form execution is armed (worker.ts
    // `withheldBody`), for Submission::check.
    ("postData", "apps/orcel-browser-worker/src/routing.ts"),
];

/// Production code each key file must have had scanned (its last
/// production item, or one near the end), so a test-module cut that
/// stopped early fails here.
const SCANNED_MARKERS: &[(&str, &str)] = &[
    (
        "crates/orceld/src/browser_broker.rs",
        "pub(crate) fn instance_id(",
    ),
    (
        "crates/orceld/src/browser_full.rs",
        "pub(crate) fn live_request(",
    ),
    (
        "crates/orceld/src/browser_profiles.rs",
        "fn engine_running(",
    ),
    (
        "crates/orceld/src/live_browser.rs",
        "pub fn shutdown(mut self)",
    ),
    (
        "crates/orceld/src/live_dispatch.rs",
        "fn tab_json(view: &TabView)",
    ),
    ("crates/orceld/src/takeover_gate.rs", "fn refused(refusal"),
    ("crates/orceld/src/human_input.rs", "pub(crate) fn in_job("),
    (
        "crates/orcel-browser-host/src/worker_launch.rs",
        "pub fn launch_worker(",
    ),
    (
        "crates/orcel-browser-host/src/worker_navigation.rs",
        "impl Submission {",
    ),
];

/// Every Rust file keeps at least this share of its lines after its test
/// modules are left out.
const MIN_SCANNED_SHARE: f64 = 0.2;

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

/// Whether `line` (indentation removed) opens an inline module:
/// `mod name {`, `pub mod name {` or `pub(...) mod name {`.
fn opens_module(line: &str) -> bool {
    let rest = line
        .strip_prefix("pub ")
        .or_else(|| {
            line.strip_prefix("pub(")
                .and_then(|after| after.split_once(") ").map(|(_, rest)| rest))
        })
        .unwrap_or(line);
    let Some(name) = rest
        .strip_prefix("mod ")
        .and_then(|after| after.strip_suffix(" {"))
    else {
        return false;
    };
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Whether an attribute line compiles its item only in tests: exactly
/// `#[cfg(test)]`, or `#[cfg(all(test, ...))]` (test and more).
fn is_test_cfg(line: &str) -> bool {
    line == "#[cfg(test)]" || (line.starts_with("#[cfg(all(test, ") && line.ends_with(")]"))
}

/// The lines of a Rust source outside its test modules, with their line
/// numbers. Only a test-only cfg (`is_test_cfg`) on an inline module is cut, from
/// the attribute to the module's closing brace at the module's own
/// indentation (rustfmt's layout). A `#[cfg(test)]` on anything else (a
/// function, a statement, a `use`, an out-of-line `mod name;`) cuts
/// nothing. If no closing brace is found, nothing is cut: the scan errs
/// toward reading more.
fn production_lines(text: &str) -> Vec<(usize, &str)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut keep = vec![true; lines.len()];
    let mut i = 0;
    while i < lines.len() {
        if is_test_cfg(lines[i].trim()) {
            let mut j = i + 1;
            while j < lines.len() && {
                let next = lines[j].trim();
                next.is_empty() || next.starts_with("#[")
            } {
                j += 1;
            }
            if let Some(line) = lines.get(j) {
                let rest = line.trim_start();
                let indent = &line[..line.len() - rest.len()];
                if opens_module(rest.trim_end()) {
                    let close = format!("{indent}}}");
                    if let Some(end) = (j + 1..lines.len()).find(|&k| lines[k].trim_end() == close)
                    {
                        keep[i..=end].iter_mut().for_each(|kept| *kept = false);
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    lines
        .into_iter()
        .enumerate()
        .filter(|(number, _)| keep[*number])
        .collect()
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn scan_line(file: &str, number: usize, line: &str, hits: &mut Vec<String>) {
    if is_comment(line) {
        return;
    }
    for call in FORBIDDEN {
        if line.contains(call)
            && !ALLOWED
                .iter()
                .any(|(token, allowed)| token == call && *allowed == file)
        {
            hits.push(format!("{file}:{}: {call}", number + 1));
        }
    }
}

#[test]
fn ob07b_production_lines_leave_out_test_modules_only() {
    let text = "fn a() {}\n#[cfg(test)]\nfn helper() { Autofill. }\n#[cfg(test)]\nuse x;\n\
                mod full {\n    #[cfg(test)]\n    mod tests {\n        fn t() {}\n    }\n    fn kept() {}\n}\n\
                #[cfg(test)]\n#[allow(dead_code)]\nmod tests {\n    fn t() { \"}\" }\n}\nfn last() {}\n\
                #[cfg(test)]\nmod unclosed {\n    fn t() {}\n";
    let kept: Vec<&str> = production_lines(text)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    // A cfg(test) function, a use and an unclosed module stay scanned.
    assert!(kept.contains(&"fn helper() { Autofill. }"));
    assert!(kept.contains(&"use x;"));
    assert!(kept.contains(&"    fn t() {}"));
    // Inline test modules, nested or not, are left out; what follows stays.
    assert!(!kept.contains(&"        fn t() {}"));
    assert!(!kept.contains(&"    fn t() { \"}\" }"));
    assert!(kept.contains(&"    fn kept() {}"));
    assert!(kept.contains(&"fn last() {}"));
    // A module only for tests and more is left out; a cfg that is not
    // test-only cuts nothing.
    let more = "#[cfg(all(test, windows))]\nmod native {\n    fn n() {}\n}\n\
                #[cfg(any(test, windows))]\nmod either {\n    fn e() {}\n}\n";
    let kept: Vec<&str> = production_lines(more)
        .into_iter()
        .map(|(_, line)| line)
        .collect();
    assert!(!kept.contains(&"    fn n() {}"));
    assert!(kept.contains(&"    fn e() {}"));
    assert!(opens_module("pub(crate) mod a_b {"));
    assert!(!opens_module("mod tests;"));
    assert!(!opens_module("fn mod_x() {"));
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
        // Orcel's own native host. Its vendored third_party donor code is a
        // separate desktop-automation surface outside the browser path, and
        // is not scanned here.
        "apps/orcel-native-host/src",
    ] {
        sources(&root.join(dir), "rs", &mut rust)?;
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
    let mut short = Vec::new();
    let mut markers: Vec<(&str, &str)> = SCANNED_MARKERS.to_vec();
    for file in &rust {
        let name = relative(&root, file);
        let text = std::fs::read_to_string(file)?;
        let total = text.lines().count();
        let kept = production_lines(&text);
        if total > 0 && (kept.len() as f64) < MIN_SCANNED_SHARE * total as f64 {
            short.push(format!("{name}: {} of {total} lines", kept.len()));
        }
        for (number, line) in &kept {
            scan_line(&name, *number, line, &mut hits);
        }
        markers.retain(|(marker_file, marker)| {
            !(*marker_file == name && kept.iter().any(|(_, line)| line.contains(marker)))
        });
    }
    for file in &typescript {
        let name = relative(&root, file);
        let text = std::fs::read_to_string(file)?;
        for (number, line) in text.lines().enumerate() {
            scan_line(&name, number, line, &mut hits);
        }
    }
    assert!(
        markers.is_empty(),
        "production code not scanned in: {markers:#?}"
    );
    assert!(short.is_empty(), "too little scanned: {short:#?}");
    assert!(
        hits.is_empty(),
        "saved-login handling on the browser path: {hits:#?}"
    );
    Ok(())
}

#[test]
fn ob07b_a_request_body_leaves_the_worker_only_for_an_armed_execution() -> Outcome {
    // The worker's only route question to the host goes through
    // `withheldBody`, armed only while an approved form execution runs, for
    // its top-level document (worker.test.ts tests the behaviour).
    let worker = std::fs::read_to_string(repo().join("apps/orcel-browser-worker/src/worker.ts"))?;
    assert!(worker.contains(
        "const detail = withheldBody(query.detail ?? { method: \"GET\", contentType: \"\", body: \"\", bodyBytes: 0 }, this.executing && query.kind === \"document\");"
    ));
    assert_eq!(worker.matches("frame: \"route_request\"").count(), 1);
    assert_eq!(worker.matches("this.executing = true;").count(), 1);
    Ok(())
}

/// The name parts of a URL-like key or field: the name is one of them or
/// ends with `_<part>` (`target_url`, `source_url`; also `latest_dated_link`,
/// a node id that the allowlist names).
const URL_LIKE: &[&str] = &["url", "href", "location", "link", "redirect"];

/// URL-like keys in orceld's sources that are not a page URL the agent
/// reads from a reply built here, each with its reason. Anything else must
/// be built by `agent_url` or `agent_url::bare`.
const URL_KEY_ALLOWED: &[(&str, &str, &str)] = &[
    (
        "crates/orceld/src/browser_full.rs",
        "url",
        "the live request a browser_full action maps onto (journal input built from the agent's own arguments), not a reply",
    ),
    (
        "crates/orceld/src/live_dispatch.rs",
        "latest_dated_link",
        "a node id (the host's typed selection, select_latest_dated_link), not a URL: the key only ends in a URL-like word",
    ),
    (
        "crates/orceld/src/search.rs",
        "url",
        "web search results from the search provider, not a browser page",
    ),
];

/// Whether `name` is URL-like.
fn url_like(name: &str) -> bool {
    URL_LIKE
        .iter()
        .any(|part| name == *part || name.ends_with(&format!("_{part}")))
}

/// The quoted keys on `line` that a value follows: `"key":` (a JSON object
/// key) and `insert("key"` (a map insert), with what follows each on the
/// line.
fn keyed_values(line: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (at, _) in line.match_indices("\":") {
        if let Some(open) = line[..at].rfind('"') {
            let key = &line[open + 1..at];
            if key.chars().all(|c| c.is_ascii_lowercase() || c == '_') {
                out.push((key.to_owned(), line[at + 2..].to_owned()));
            }
        }
    }
    for (at, _) in line.match_indices("insert(\"") {
        let rest = &line[at + 8..];
        if let Some(close) = rest.find('"') {
            out.push((rest[..close].to_owned(), rest[close + 1..].to_owned()));
        }
    }
    out
}

/// The field name a struct field line declares (`pub url: String,`).
fn field_name(line: &str) -> Option<&str> {
    let rest = line.trim_start();
    let rest = rest
        .strip_prefix("pub(crate) ")
        .or_else(|| rest.strip_prefix("pub(super) "))
        .or_else(|| rest.strip_prefix("pub "))
        .unwrap_or(rest);
    let (name, _) = rest.split_once(": ")?;
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        .then_some(name)
}

fn sanitized(value: &str) -> bool {
    value.contains("agent_url(") || value.contains("agent_url::bare")
}

/// Every URL-like key or serialized field in `text` that is not built by
/// the sanitizer and not allowed: (line number, key).
fn unsanitized_url_keys(file: &str, text: &str) -> (Vec<String>, usize) {
    let lines = production_lines(text);
    let mut out = Vec::new();
    let mut sanitized_count = 0;
    let allowed = |key: &str| {
        URL_KEY_ALLOWED
            .iter()
            .any(|(allowed_file, allowed_key, _)| *allowed_file == file && *allowed_key == key)
    };
    // A struct deriving Serialize: its URL-like fields would reach a reply
    // without passing a builder line.
    let mut serialize_pending = false;
    let mut in_serialized: Option<String> = None;
    for (index, (number, line)) in lines.iter().enumerate() {
        if is_comment(line) {
            continue;
        }
        let trimmed = line.trim();
        if let Some(close) = &in_serialized {
            if line.trim_end() == close {
                in_serialized = None;
            } else if let Some(name) = field_name(line) {
                if url_like(name) && !allowed(name) {
                    out.push(format!("{file}:{}: serialized field {name}", number + 1));
                }
            }
            continue;
        }
        if trimmed.starts_with("#[derive(") {
            serialize_pending = trimmed.contains("Serialize");
            continue;
        }
        if serialize_pending && trimmed.starts_with("#[") {
            continue;
        }
        if serialize_pending
            && (trimmed.contains("struct ") || trimmed.contains("enum "))
            && trimmed.ends_with('{')
        {
            let indent = &line[..line.len() - line.trim_start().len()];
            in_serialized = Some(format!("{indent}}}"));
            serialize_pending = false;
            continue;
        }
        serialize_pending = false;
        for (key, rest) in keyed_values(line) {
            if !url_like(&key) {
                continue;
            }
            // A value on the following line (a multi-line key).
            let value = if rest.trim().is_empty() {
                lines
                    .get(index + 1)
                    .map(|(_, next)| next.to_string())
                    .unwrap_or_default()
            } else {
                rest
            };
            if sanitized(&value) {
                sanitized_count += 1;
            } else if !allowed(&key) {
                out.push(format!("{file}:{}: {key}: {}", number + 1, trimmed));
            }
        }
    }
    (out, sanitized_count)
}

#[test]
fn ob07b_url_key_detection_covers_multi_line_inserts_and_serialized_fields() {
    let text = "fn reply() {\n    json!({\n        \"url\":\n            page.url,\n        \"target_url\": agent_url(&x),\n        \"href\": raw,\n    });\n    map.insert(\"location\", raw);\n    map.insert(\"redirect\".into(), agent_url(&y, false));\n    json!({\"name\": url, \"curl\": 1});\n}\n#[derive(Debug, Serialize)]\npub struct Reply {\n    pub url: String,\n    pub title: String,\n}\n#[derive(Debug)]\npub struct Internal {\n    pub url: String,\n}\n";
    let (hits, sanitized_count) = unsanitized_url_keys("x.rs", text);
    assert_eq!(sanitized_count, 2, "{hits:#?}");
    let joined = hits.join("\n");
    assert!(joined.contains("x.rs:3: url"), "{joined}");
    assert!(joined.contains("x.rs:6: href"), "{joined}");
    assert!(joined.contains("x.rs:8: location"), "{joined}");
    assert!(joined.contains("x.rs:14: serialized field url"), "{joined}");
    assert_eq!(hits.len(), 4, "{joined}");
}

#[test]
fn ob07b_every_agent_facing_url_goes_through_the_sanitizer() -> Outcome {
    // Every URL-like key (url, href, location, link, redirect, *_url, ...)
    // that a reply builder in orceld writes, on one line or the next, by a
    // JSON key or a map insert, and every URL-like field of a serialized
    // type, must be built by `agent_url` (the redacting sanitizer) or
    // `agent_url::bare` (tab lists), or be allowed above with its reason.
    // agent_url.rs tests the sanitizer, and live_browser.rs its strict mode
    // after a sign-in and `url_is`.
    let root = repo();
    let mut files = Vec::new();
    sources(&root.join("crates/orceld/src"), "rs", &mut files)?;
    assert!(files.len() > 40, "orceld's sources were found");
    let mut unsanitized = Vec::new();
    let mut sanitized_count = 0;
    for file in &files {
        let name = relative(&root, file);
        let text = std::fs::read_to_string(file)?;
        let (hits, count) = unsanitized_url_keys(&name, &text);
        unsanitized.extend(hits);
        sanitized_count += count;
    }
    assert!(
        unsanitized.is_empty(),
        "agent-facing URL fields without the sanitizer: {unsanitized:#?}"
    );
    // open, click, form action, verify (live shapes); open, click, form
    // action, verify, extract, tab navigation (browser_full); tab list; a
    // parsed download's source.
    assert!(
        sanitized_count >= 12,
        "only {sanitized_count} sanitized URL fields were found"
    );
    for (file, _, reason) in URL_KEY_ALLOWED {
        assert!(root.join(file).is_file(), "{file}");
        assert!(!reason.is_empty());
    }
    Ok(())
}

#[test]
fn ob07b_the_native_host_keeps_cuas_browser_tooling_compiled_out() -> Outcome {
    // The vendored cua-driver has its own CDP browser tooling (it types
    // with Input.insertText); Orcel builds it with `orcel-minimal`, which
    // compiles that out (P-03).
    let manifest = std::fs::read_to_string(repo().join("apps/orcel-native-host/Cargo.toml"))?;
    let line = manifest
        .lines()
        .find(|line| line.trim_start().starts_with("cua-driver-core = "))
        .ok_or("the native host depends on cua-driver-core")?;
    assert!(line.contains("default-features = false"), "{line}");
    assert!(line.contains("features = [\"orcel-minimal\"]"), "{line}");
    Ok(())
}
