//! Founder decision of 2026-11-23: Git is off until it runs confined. An
//! integration test links the provider as any other crate does, so what it
//! sees is what a shipped build does.

use orcel_contracts::FailureCode;
use orcel_provider_git::confinement::{require, OFF_MESSAGE};
use orcel_provider_git::push::{
    HardenedPushTransport, PushOperation, PushTransport, RemoteQuery, ResolvedCredential,
};
use orcel_provider_git::{GitProvider, GitProviderError};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

fn assert_off<T>(result: Result<T, GitProviderError>, what: &str) {
    match result {
        Ok(_) => unreachable!("{what} is not off"),
        Err(error) => {
            assert_eq!(error.code, FailureCode::ProviderUnavailable, "{what}");
            assert_eq!(error.message, OFF_MESSAGE, "{what}");
        }
    }
}

#[test]
fn a_dependent_crate_finds_git_off() {
    assert_eq!(OFF_MESSAGE, "Git is off until it runs confined");
    assert_off(require(), "require");
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    assert_off(GitProvider::new(here), "new");
    assert_off(GitProvider::new(here.join("no-such-folder")), "new");
    assert_off(GitProvider::with_program(here, "git"), "with_program");
    let program = std::env::current_exe().expect("exe");
    assert_off(GitProvider::with_program(here, program), "with_program");
    let pinned: IpAddr = "192.0.2.1".parse().expect("address");
    let credential = ResolvedCredential::anonymous();
    assert_off(
        HardenedPushTransport.query_remote_ref(&RemoteQuery {
            repo: here,
            url: "https://example.invalid/repo.git",
            hostname: "example.invalid",
            port: 443,
            pinned: &pinned,
            dest_ref: "refs/heads/main",
            credential: &credential,
        }),
        "query_remote_ref",
    );
    assert_off(
        HardenedPushTransport.send_push(&PushOperation {
            repo: here,
            url: "https://example.invalid/repo.git",
            hostname: "example.invalid",
            port: 443,
            pinned: &pinned,
            source_ref: "refs/heads/main",
            dest_ref: "refs/heads/main",
            credential: &credential,
        }),
        "send_push",
    );
}

/// A Rust source file without its trailing `#[cfg(test)] mod tests`.
fn shipped(path: &Path) -> String {
    let text = std::fs::read_to_string(path)
        .expect("source")
        .replace("\r\n", "\n");
    match text.find("#[cfg(test)]\nmod tests {") {
        Some(tests) => text[..tests].to_owned(),
        None => text,
    }
}

fn is_test_source(path: &Path) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    name.ends_with("tests.rs")
        || path
            .components()
            .any(|part| part.as_os_str() == "tests" || part.as_os_str() == "examples")
}

/// The whole text of the function whose signature holds `name`, up to `end`.
fn since_fn(text: &str, end: usize) -> &str {
    let start = [
        "\nfn ",
        "\n    fn ",
        "\npub fn ",
        "\n    pub fn ",
        "\npub(crate) fn ",
    ]
    .iter()
    .filter_map(|prefix| text[..end].rfind(prefix))
    .max()
    .expect("inside a function");
    &text[start..end]
}

/// Every place the provider starts a process asks [`require`] first, in the
/// same function, before anything else runs; so do the two constructors and
/// the push transport.
#[test]
fn every_git_spawn_site_requires_confinement() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sites = Vec::new();
    for entry in std::fs::read_dir(&src).expect("src") {
        let path = entry.expect("entry").path();
        if path.extension().is_none_or(|kind| kind != "rs") || is_test_source(&path) {
            continue;
        }
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let text = shipped(&path);
        for (at, _) in text.match_indices("Command::new(") {
            let body = since_fn(&text, at);
            assert!(
                body.contains("confinement::require()?;"),
                "{name}: a process is started without confinement::require():\n{body}"
            );
            sites.push(name.clone());
        }
        // No other way to start a process.
        assert_eq!(
            text.matches("command.spawn()").count(),
            text.matches("Command::new(").count(),
            "{name}"
        );
        for other in [
            ".output()",
            ".status()",
            "CreateProcess",
            "ShellExecute",
            "fork(",
        ] {
            assert!(!text.contains(other), "{name}: {other}");
        }
    }
    sites.sort();
    assert_eq!(sites, ["fetch.rs", "lib.rs", "push.rs"]);
    for (file, signature) in [
        ("lib.rs", "pub fn new(workspace_root"),
        ("lib.rs", "pub fn with_program("),
        ("lib.rs", "fn run_plain_full("),
    ] {
        first_statement_requires(&shipped(&src.join(file)), file, signature);
    }
    let push = shipped(&src.join("push.rs"));
    let transport = push
        .find("impl PushTransport for HardenedPushTransport")
        .expect("transport");
    for signature in ["fn query_remote_ref(", "fn send_push("] {
        first_statement_requires(&push[transport..], "push.rs", signature);
    }
}

fn first_statement_requires(text: &str, file: &str, signature: &str) {
    let at = text.find(signature).expect("signature");
    let body = &text[at..];
    let open = body.find("{\n").expect("body") + 2;
    let first = body[open..].lines().next().unwrap_or_default().trim();
    assert!(
        first == "confinement::require()?;" || first == "crate::confinement::require()?;",
        "{file}: {signature} starts with {first}"
    );
}

/// The switch is one compiled constant, and nothing at run time reaches it.
#[test]
fn the_switch_is_one_compiled_constant() {
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let code: String = shipped(&here.join("src").join("confinement.rs"))
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(code.contains("const PROCESS_CONFINED: bool = cfg!(test);"));
    assert_eq!(code.matches("PROCESS_CONFINED").count(), 2, "{code}");
    assert_eq!(code.matches("cfg!").count(), 1, "{code}");
    for other in ["env", "feature", "static", "Atomic", "std::"] {
        assert!(!code.contains(other), "{other}");
    }
    // A build with `test` set that is not this crate's own tests has no
    // dev-dependency, and does not compile.
    assert_eq!(code.matches("#[cfg").count(), 1, "{code}");
    assert!(code.contains("#[cfg(test)]\nuse serde as _;"), "{code}");
    let manifest = std::fs::read_to_string(here.join("Cargo.toml")).expect("manifest");
    assert!(!manifest.contains("[features]"), "{manifest}");
    let (normal, dev) = manifest
        .split_once("[dev-dependencies]")
        .expect("dev-dependencies");
    assert!(!normal.contains("\nserde."), "{normal}");
    assert!(dev.contains("\nserde."), "{dev}");
    assert!(!manifest.contains("build ="), "{manifest}");
    assert!(!here.join("build.rs").exists());
}

fn rust_sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !["target", "node_modules", "third_party"].contains(&name.as_str()) {
                rust_sources(&path, found);
            }
        } else if name.ends_with(".rs") && !is_test_source(&path) {
            found.push(path);
        }
    }
}

/// No other crate starts Git: the provider is the only way to it.
#[test]
fn no_other_crate_starts_git() {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let mut sources = Vec::new();
    rust_sources(&repo.join("crates"), &mut sources);
    rust_sources(&repo.join("apps"), &mut sources);
    assert!(sources.len() > 100, "{}", sources.len());
    let mut git_programs = 0;
    for path in &sources {
        let text = shipped(path);
        let compact: String = text.split_whitespace().collect();
        if !path
            .components()
            .any(|part| part.as_os_str() == "orcel-provider-git")
        {
            for program in ["\"git\"", "\"git.exe\"", "\"/usr/bin/git\""] {
                assert!(
                    !compact.contains(&format!("Command::new({program}")),
                    "{}",
                    path.display()
                );
            }
        }
        // orceld's own Git path goes only to `GitProvider::with_program`.
        let uses = compact.matches("git_program()").count();
        if uses > 0 {
            git_programs += uses;
            assert!(
                compact.contains("GitProvider::with_program(&root,git_program()?)"),
                "{}",
                path.display()
            );
        }
    }
    assert_eq!(git_programs, 2, "the function and its one caller");
}
