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

/// Whether the function around the process start at `start` asks for
/// confinement first: a statement of its own, at the top level of the
/// function's body (not in a comment, a string or a branch), with no process
/// started before it.
fn guarded(text: &str, start: usize) -> bool {
    let head = &text[..start];
    let mut function = None;
    let mut offset = 0;
    for line in head.split_inclusive('\n') {
        let code = line.trim_start();
        let is_fn = ["fn ", "pub fn ", "pub(crate) fn ", "pub(super) fn "]
            .iter()
            .any(|prefix| code.starts_with(prefix));
        if is_fn {
            function = Some((offset, line.len() - code.len()));
        }
        offset += line.len();
    }
    let Some((from, indent)) = function else {
        return false;
    };
    let body = &head[from..];
    let wanted = [
        format!("{}confinement::require()?;", " ".repeat(indent + 4)),
        format!("{}crate::confinement::require()?;", " ".repeat(indent + 4)),
    ];
    let mut asked = None;
    let mut offset = 0;
    for line in body.split_inclusive('\n') {
        if wanted.iter().any(|guard| guard == line.trim_end()) {
            asked = Some(offset);
            break;
        }
        offset += line.len();
    }
    asked.is_some_and(|at| {
        ["Command::new", "spawn(", ".output()", ".status()"]
            .iter()
            .all(|starts| !body[..at].contains(starts))
    })
}

/// The check itself tells a guard that comes first from one that does not.
#[test]
fn the_guard_check_wants_the_guard_before_the_start() {
    let check = |body: &str| {
        let text =
            format!("fn earlier() {{\n    confinement::require()?;\n}}\n\nfn run() {{\n{body}}}\n");
        let at = text.rfind("Command::new(").expect("start");
        guarded(&text, at)
    };
    assert!(check(
        "    confinement::require()?;\n    let c = Command::new(p);\n"
    ));
    assert!(check(
        "    crate::confinement::require()?;\n    let c = Command::new(p);\n"
    ));
    for unguarded in [
        "    let c = Command::new(p);\n",
        "    // confinement::require()?;\n    let c = Command::new(p);\n",
        "    if a {\n        confinement::require()?;\n    }\n    let c = Command::new(p);\n",
        "    let _ = confinement::require();\n    let c = Command::new(p);\n",
        "    c.spawn();\n    confinement::require()?;\n    let c = Command::new(p);\n",
        "    let c = Command::new(p);\n    confinement::require()?;\n    let d = Command::new(p);\n",
    ] {
        assert!(!check(unguarded), "{unguarded}");
    }
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
            assert!(
                guarded(&text, at),
                "{name}: a process starts before confinement::require()"
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

const SOURCE_KINDS: &[&str] = &[
    "rs", "ts", "tsx", "js", "mjs", "cjs", "py", "go", "cs", "ps1",
];

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = path
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if path.is_dir() {
            if !["target", "node_modules", "third_party", "dist", ".next"].contains(&name.as_str())
            {
                sources(&path, found);
            }
        } else if SOURCE_KINDS.contains(&kind.as_str())
            && !is_test_source(&path)
            && !name.contains(".test.")
        {
            found.push(path);
        }
    }
}

/// Every string in `text` that could name the Git program: `git` alone or
/// at the end of a path, with any program extension, in any case.
fn git_programs(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in text.lines() {
        let code = line.trim_start();
        if code.starts_with("//") || code.starts_with('#') || code.starts_with('*') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        for ending in ["git", "git.exe", "git.cmd", "git.bat", "git.com"] {
            for quote in ['"', '\'', '`'] {
                let needle = format!("{ending}{quote}");
                for (at, _) in lower.match_indices(&needle) {
                    let before = lower[..at].chars().next_back();
                    if before.is_some_and(|c| ['"', '\'', '`', '/', '\\'].contains(&c)) {
                        found.push(line.trim().to_owned());
                    }
                }
            }
        }
    }
    found
}

/// No other crate or app starts Git: the provider is the only way to it.
/// Outside the provider, the only strings that name the Git program are
/// where orceld looks for it, for `GitProvider::with_program`.
#[test]
fn no_other_crate_starts_git() {
    for named in [
        r#"Command::new("git")"#,
        r#"Path::new("GIT.EXE")"#,
        r#"x = r"C:\Program Files\Git\cmd\git.exe";"#,
        r#""/opt/homebrew/bin/git""#,
        r"spawn('git', args)",
        r#""git.cmd""#,
    ] {
        assert_eq!(git_programs(named).len(), 1, "{named}");
    }
    assert!(git_programs(r#""fc.git" "digit" "https://example.com/repo.git""#).is_empty());
    // Not through `..`: a path through this crate's folder would be skipped.
    let crates = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates");
    let repo = crates.parent().expect("repository");
    let mut found = Vec::new();
    sources(&repo.join("crates"), &mut found);
    sources(&repo.join("apps"), &mut found);
    assert!(found.len() > 200, "{}", found.len());
    let mut names = Vec::new();
    let mut lookups = 0;
    for path in &found {
        let text = if path.extension().is_some_and(|kind| kind == "rs") {
            shipped(path)
        } else {
            std::fs::read_to_string(path).unwrap_or_default()
        };
        if path
            .components()
            .any(|part| part.as_os_str() == "orcel-provider-git")
        {
            continue;
        }
        let file = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        names.extend(
            git_programs(&text)
                .into_iter()
                .map(|line| format!("{file}: {line}")),
        );
        // orceld's own Git path goes only to `GitProvider::with_program`.
        let compact: String = text.split_whitespace().collect();
        let uses = compact.matches("git_program()").count();
        if uses > 0 {
            lookups += uses;
            assert!(
                compact.contains("GitProvider::with_program(&root,git_program()?)"),
                "{}",
                path.display()
            );
        }
    }
    assert_eq!(lookups, 2, "the function and its one caller");
    names.sort();
    assert_eq!(
        names,
        [
            // Where orceld looks for Git.
            r#"fc_worker_exec.rs: "/opt/homebrew/bin/git","#,
            r#"fc_worker_exec.rs: "/usr/bin/git","#,
            r#"fc_worker_exec.rs: "/usr/local/bin/git","#,
            r#"fc_worker_exec.rs: ("LOCALAPPDATA", r"Programs\Git\cmd\git.exe"),"#,
            r#"fc_worker_exec.rs: ("ProgramFiles", r"Git\cmd\git.exe"),"#,
            r#"fc_worker_exec.rs: ("ProgramFiles(x86)", r"Git\cmd\git.exe"),"#,
            r#"fc_worker_exec.rs: ("ProgramW6432", r"Git\cmd\git.exe"),"#,
            // A name prefix refused as a program, a family's name and the
            // app API's capability id.
            r#"fc_worker_exec.rs: if REFUSED_PROGRAMS.contains(&stem.as_str()) || stem.starts_with("git") {"#,
            r#"full_control_dispatch.rs: Self::Git => "git","#,
            r#"sg000039_main.rs: Err(error) => json!({ "id": "git", "state": "unavailable", "reason": error.message }),"#,
            r#"sg000039_main.rs: Ok(()) => json!({ "id": "git", "state": "available", "reason": null }),"#,
        ]
    );
}
