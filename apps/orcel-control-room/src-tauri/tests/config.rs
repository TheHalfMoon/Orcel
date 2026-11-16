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
    assert_eq!(main["url"], "index.html");
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

#[test]
fn the_page_has_no_script_and_no_inline_handler() {
    let page = read("ui/index.html");
    assert!(
        !page.contains("<script"),
        "the A2 page runs no script of its own"
    );
    assert!(!page.contains(" on"), "no inline event handler");
    assert!(
        !page.contains("http://") && !page.contains("https://"),
        "no remote reference"
    );
}
