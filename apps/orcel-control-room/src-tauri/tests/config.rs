//! SG-000119 A2 configuration test: `tauri.conf.json`, the capability file
//! and the manifest hold exactly what the prep packet records.

use serde_json::{json, Value};
use std::path::Path;

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
                   font-src 'self'; connect-src ipc: https://ipc.localhost; frame-src 'none'; \
                   object-src 'none'; base-uri 'none'; form-action 'none'";

fn read(relative: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
        .replace("\r\n", "\n")
}

fn json_file(relative: &str) -> Value {
    serde_json::from_str(&read(relative)).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

fn keys(value: &Value) -> Vec<&str> {
    let mut keys: Vec<&str> = value
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    keys
}

#[test]
fn the_configuration_is_exactly_the_recorded_one() {
    let config = json_file("tauri.conf.json");
    assert_eq!(
        keys(&config),
        [
            "app",
            "build",
            "bundle",
            "identifier",
            "productName",
            "version"
        ]
    );
    assert_eq!(config["identifier"], "ai.orcel.control-room");

    // Embedded assets only: no devUrl, no dev server, no build commands.
    assert_eq!(config["build"], json!({ "frontendDist": "ui" }));
    // No installer, updater or signing (founder decision 6).
    assert_eq!(config["bundle"], json!({ "active": false }));

    let app = &config["app"];
    assert_eq!(keys(app), ["security", "windows", "withGlobalTauri"]);
    assert_eq!(app["withGlobalTauri"], true);

    let security = &app["security"];
    assert_eq!(
        keys(security),
        [
            "assetProtocol",
            "capabilities",
            "csp",
            "dangerousDisableAssetCspModification",
            "freezePrototype"
        ]
    );
    assert_eq!(security["csp"], CSP);
    assert_eq!(security["dangerousDisableAssetCspModification"], false);
    assert_eq!(security["freezePrototype"], true);
    assert_eq!(security["assetProtocol"], json!({ "enable": false }));
    assert_eq!(security["capabilities"], json!(["main"]));

    let windows = app["windows"].as_array().expect("windows");
    assert_eq!(windows.len(), 1);
    let main = &windows[0];
    assert_eq!(main["label"], "main");
    assert_eq!(main["title"], "Orcel Control Room");
    // SG-000119 A4: the window first loads the script-free start page; the
    // shell navigates to the view (index.html) only after the WebView2
    // settings are applied and read back, so no page script runs before.
    assert_eq!(main["url"], "start.html");
    assert_eq!(
        main["create"], false,
        "the shell builds the window itself, hidden"
    );
    assert_eq!(main["visible"], false);
    assert_eq!(main["useHttpsScheme"], true);
    assert_eq!(main["dragDropEnabled"], false);
    assert_eq!(main["devtools"], false);
    assert_eq!(main["zoomHotkeysEnabled"], false);
    assert_eq!(main["browserExtensionsEnabled"], false);
    assert_eq!(
        main["additionalBrowserArgs"],
        orcel_control_room_shell::hardening::BROWSER_ARGS
    );
}

#[test]
fn the_csp_has_no_unsafe_or_remote_source() {
    for forbidden in [
        "'unsafe-inline'",
        "'unsafe-eval'",
        "'wasm-unsafe-eval'",
        "ws:",
        "wss:",
        "http:",
        "https:",
        "*",
        "data:",
        "blob:",
    ] {
        assert!(
            !CSP.split([' ', ';']).any(|token| token == forbidden),
            "{forbidden}"
        );
    }
    let connect = CSP
        .split(';')
        .map(str::trim)
        .find(|directive| directive.starts_with("connect-src"))
        .expect("connect-src");
    assert_eq!(connect, "connect-src ipc: https://ipc.localhost");
}

#[test]
fn the_capability_file_is_one_window_granting_the_five_commands() {
    let entries: Vec<String> =
        std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("capabilities"))
            .expect("capabilities")
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
    assert_eq!(entries, ["main.json"]);
    let capability = json_file("capabilities/main.json");
    assert_eq!(
        keys(&capability),
        [
            "description",
            "identifier",
            "local",
            "permissions",
            "windows"
        ]
    );
    assert_eq!(capability["identifier"], "main");
    assert_eq!(capability["local"], true);
    assert_eq!(capability["windows"], json!(["main"]));
    // A3: exactly the five commands' own generated allow permissions
    // (tests/acl.rs checks them against build.rs and the handler). No core
    // default, no remote section, no platform list, no webview wildcard.
    assert_eq!(
        capability["permissions"],
        json!([
            "allow-app-status",
            "allow-app-capabilities",
            "allow-app-events",
            "allow-app-tasks",
            "allow-app-task"
        ])
    );
    assert!(capability.get("remote").is_none());
    assert!(capability.get("platforms").is_none());
    assert!(capability.get("webviews").is_none());
}

#[test]
fn the_manifest_pins_tauri_lean_and_registers_no_plugin() {
    let manifest = read("Cargo.toml");
    assert!(manifest.contains(
        "tauri = { version = \"=2.12.5\", default-features = false, features = [\"wry\", \"custom-protocol\"] }"
    ));
    assert!(manifest.contains("tauri-build = { version = \"=2.7.4\", default-features = false }"));
    for forbidden in ["tauri-plugin", "devtools\"", "tiny_http", "tauri-driver"] {
        let hits: Vec<&str> = manifest
            .lines()
            .filter(|line| !line.trim_start().starts_with('#') && line.contains(forbidden))
            .collect();
        assert!(hits.is_empty(), "{forbidden}: {hits:?}");
    }
    // tauri's `test` feature (A3's ACL tests) appears exactly once, in
    // [dev-dependencies], on the same exact version; never in a normal or
    // build dependency table.
    let mut section = "";
    let mut test_feature = Vec::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line;
        } else if !line.starts_with('#') && line.contains("\"test\"") {
            test_feature.push((section, line));
        }
    }
    assert_eq!(
        test_feature,
        [(
            "[dev-dependencies]",
            "tauri = { version = \"=2.12.5\", default-features = false, features = [\"wry\", \"custom-protocol\", \"test\"] }"
        )]
    );
    // The native tests' hooks are a feature that is never a default; only
    // the native test target requires it.
    assert!(manifest.contains("[features]\ndefault = []\ntest-hooks = []\n"));
    assert!(manifest.contains("harness = false\nrequired-features = [\"test-hooks\"]\n"));
    let shell = read("src/shell.rs");
    let lines: Vec<&str> = shell.lines().map(str::trim).collect();
    for (index, line) in lines.iter().enumerate() {
        let hook = line.starts_with("pub after_apply")
            || line.starts_with("pub after_show")
            || line.starts_with("pub type AfterApply")
            || line.starts_with("pub type AfterShow")
            || line.contains("hooks.after_apply")
            || line.contains("hooks.after_show")
            || line.contains("after_show.take()");
        if hook {
            assert_eq!(
                lines[index - 1],
                "#[cfg(feature = \"test-hooks\")]",
                "src/shell.rs: {line} must be compiled only with test-hooks"
            );
        }
    }
    assert!(read("src/main.rs").contains("Hooks::default()"));
    // No plugin is registered anywhere in the shell's source.
    for file in [
        "src/shell.rs",
        "src/commands.rs",
        "src/lib.rs",
        "src/main.rs",
        "build.rs",
    ] {
        let source = read(file);
        assert!(!source.contains(".plugin("), "{file} registers a plugin");
        assert!(
            !source.contains("tauri_plugin"),
            "{file} names a plugin crate"
        );
    }
}

/// Every file of the frontendDist (`ui/`), as (path relative to `ui/`, text).
fn frontend_dist() -> Vec<(String, String)> {
    fn walk(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).expect("ui dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                walk(&path, base, out);
            } else {
                let name = path
                    .strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((name, std::fs::read_to_string(&path).expect("a text file")));
            }
        }
    }
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("ui");
    let mut out = Vec::new();
    walk(&base, &base, &mut out);
    out.sort();
    out
}

#[test]
fn the_start_page_runs_no_script_and_the_view_loads_one_external_module() {
    // SG-000119 A4. The start page is what the window holds before the
    // WebView2 settings are applied: no script of its own.
    let start = read("ui/start.html");
    assert!(!start.contains("<script"), "the start page runs no script");
    let index = read("ui/index.html");
    assert_eq!(index.matches("<script").count(), 1);
    assert!(
        index.contains(r#"<script type="module" src="js/view/main.js"></script>"#),
        "the view's one script is the embedded module, with no inline body"
    );
    for page in [&start, &index] {
        assert!(!has_inline_handler(page), "no inline event handler");
        assert!(!page.contains(" style="), "no inline style");
    }
}

/// Whether `page` has an attribute `on<letters>=` (an inline event handler)
/// inside any tag. The pages' prose may say "on", so only tags are read.
fn has_inline_handler(page: &str) -> bool {
    page.split('<').skip(1).any(|rest| {
        let tag = rest
            .split('>')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        tag.split(|c: char| c.is_whitespace())
            .skip(1)
            .any(|attribute| {
                attribute.strip_prefix("on").is_some_and(|name| {
                    let letters: String =
                        name.chars().take_while(char::is_ascii_alphabetic).collect();
                    !letters.is_empty() && name[letters.len()..].starts_with('=')
                })
            })
    })
}

#[test]
fn the_inline_handler_check_reads_tags_only() {
    assert!(has_inline_handler(r#"<p onclick="x()">"#));
    assert!(has_inline_handler(r#"<img src=x ONERROR=y>"#));
    assert!(!has_inline_handler(
        "<p>shown on this device, only once</p>"
    ));
    assert!(!has_inline_handler(r#"<p class="one">"#));
}

#[test]
fn the_built_frontend_dist_has_no_remote_url_eval_or_html_sink() {
    let files = frontend_dist();
    let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
    assert!(names.contains(&"index.html") && names.contains(&"js/view/main.js"));
    for (name, text) in &files {
        assert!(
            name.ends_with(".html") || name.ends_with(".css") || name.ends_with(".js"),
            "{name}: only pages, the stylesheet and compiled modules are embedded"
        );
        for forbidden in [
            "http://",
            "https://",
            "ws://",
            "wss://",
            "javascript:",
            "innerHTML",
            "outerHTML",
            "insertAdjacentHTML",
            "document.write",
            "eval(",
            "Function(",
            "srcdoc",
            "import(",
            "fetch(",
            "XMLHttpRequest",
            "WebSocket",
            "@import",
            "url(",
        ] {
            assert!(!text.contains(forbidden), "{name} contains {forbidden}");
        }
    }
}
