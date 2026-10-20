//! Release-artifact qualification. Runs only when `ORCEL_RELEASE_DIR` names a
//! release directory produced by `scripts/package-release.mjs`, as the
//! release-qualification CI job does. It installs a 0.1.0-versioned image of
//! the packaged artifact, updates it to the candidate, drives MCP through
//! the installed runtime, and exercises further update, downgrade refusal,
//! rollback, failed-update recovery, and uninstall. The `fake_tunnel_client` example
//! stands in for the official OpenAI tunnel client only.
#![cfg(windows)]

use orcel_lifecycle::manifest::{sha256_bytes, MANIFEST_FILE};
use orcel_lifecycle::platform::find_node_on_path;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

const SECRET: &str = "sk-release-qualification-key-0123456789";
const TUNNEL_ID: &str = "tunnel_0123456789abcdefghijklmnopqrstuv";

/// What the fake tunnel's `tools/call system_status` must observe. #395:
/// the tunnel is a remote transport, so the call reaches `orceld` with the
/// tunnel's remote context and is refused by the remote-session lease gate.
/// Qualification cannot create a lease (that needs STRONG local presence),
/// so a successful call here would mean the lease gate was bypassed.
const TUNNEL_CALL_LEASE_GATED: &str =
    "fake-tunnel: mcp-call is_error=true orceld_answered=false remote_session_inactive=true";

/// The exact MCP tool set the tunnel serves: the remote `core` profile
/// (`REMOTE_TOOL_NAMES` in `apps/orcel-mcp/src/tool_contract.ts`).
///
/// #395: this list used to pin the local `desktop_structured` surface (the
/// eleven `desktop_*` tools, `clipboard_read`, `clipboard_write` and
/// `web_fetch`), which was the exposure bug itself. The tunnel is a remote
/// transport and serves only `core`; any other tool is exposure drift.
const TUNNEL_CORE_TOOLS: &[&str] = &[
    "system_status",
    "workspace_get",
    "fs_stat",
    "fs_list",
    "fs_read",
    "fs_search",
    "fs_write_preview",
    "fs_write",
    "fs_read_range",
    "fs_find",
    "fs_mkdir",
    "fs_move",
    "fs_remove",
    "fs_edit",
    "process_spawn",
    "git_status",
    "git_diff",
    "git_log",
    "git_branch_create",
    "git_stage",
    "git_unstage",
    "git_commit",
    "git_fetch_preview",
    "git_fetch",
    "git_push_preview",
    "git_push",
];

fn temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("orcel-rq-{label}-{}", orcel_lifecycle::nonce()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fake_tunnel() -> PathBuf {
    let deps = std::env::current_exe().unwrap();
    let profile = deps.parent().unwrap().parent().unwrap();
    let path = profile.join("examples").join("fake_tunnel_client.exe");
    assert!(
        path.is_file(),
        "build the fake_tunnel_client example first: {}",
        path.display()
    );
    path
}

/// Stops any runtime left by a failed assertion and removes the temporary
/// directories this test created (never the provided release directory).
struct Cleanup {
    local: PathBuf,
    dirs: std::cell::RefCell<Vec<PathBuf>>,
}

impl Cleanup {
    fn track(&self, dir: &Path) {
        self.dirs.borrow_mut().push(dir.to_path_buf());
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Surface the runtime's own logs before they are removed, so a
            // failure on a CI runner can be diagnosed.
            for log in ["tunnel.log", "supervisor.log", "lifecycle.log"] {
                let path = self.local.join("Orcel").join("logs").join(log);
                let text = fs::read_to_string(&path).unwrap_or_default();
                let tail = text.lines().rev().take(40).collect::<Vec<_>>();
                eprintln!("---- {log} (last {} lines) ----", tail.len());
                for line in tail.iter().rev() {
                    eprintln!("{line}");
                }
            }
        }
        let cli = self.local.join("Orcel").join("bin").join("orcel.exe");
        if cli.is_file() {
            let _ = Command::new(&cli)
                .args(["stop", "--json"])
                .env("LOCALAPPDATA", &self.local)
                .output();
        }
        for dir in self
            .dirs
            .borrow()
            .iter()
            .chain(std::iter::once(&self.local))
        {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

/// Copies a release under a new version, optionally replacing one payload
/// file, and rewrites the manifest to match.
fn derived_release(source: &Path, version: &str, replace: Option<(&str, &[u8])>) -> PathBuf {
    let dir = temp_dir(&format!("release-{version}"));
    copy_tree(source, &dir);
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(dir.join(MANIFEST_FILE)).unwrap()).unwrap();
    manifest["version"] = Value::from(version);
    if let Some((path, bytes)) = replace {
        fs::write(orcel_lifecycle::manifest::join_relative(&dir, path), bytes).unwrap();
        for file in manifest["files"].as_array_mut().unwrap() {
            if file["path"] == path {
                file["size"] = Value::from(bytes.len() as u64);
                file["sha256"] = Value::from(sha256_bytes(bytes));
            }
        }
    }
    fs::write(
        dir.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    dir
}

fn orcel(exe: &Path, local: &Path, args: &[&str]) -> Output {
    let output = Command::new(exe)
        .args(args)
        .env("LOCALAPPDATA", local)
        .output()
        .unwrap();
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !all.contains(SECRET),
        "runtime key leaked into `orcel {args:?}` output"
    );
    output
}

fn json_ok(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "status {:?}\nstdout {}\nstderr {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn wait_for_count(path: &Path, needle: &str, count: usize) -> String {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let text = fs::read_to_string(path).unwrap_or_default();
        if text.matches(needle).count() >= count {
            return text;
        }
        assert!(
            Instant::now() < deadline,
            "{needle} x{count} not logged; log:\n{text}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn bump_patch(version: &str, by: u64) -> String {
    let core = version.split('-').next().unwrap();
    let parts = core
        .split('.')
        .map(|p| p.parse::<u64>().unwrap())
        .collect::<Vec<_>>();
    format!("{}.{}.{}", parts[0], parts[1], parts[2] + by)
}

#[test]
#[ignore = "requires ORCEL_RELEASE_DIR; run by the release-qualification CI job"]
fn packaged_release_installs_runs_updates_recovers_and_uninstalls() {
    let release = PathBuf::from(
        std::env::var_os("ORCEL_RELEASE_DIR")
            .expect("ORCEL_RELEASE_DIR must name a packaged release"),
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(release.join(MANIFEST_FILE)).unwrap()).unwrap();
    let base_version = manifest["version"].as_str().unwrap().to_string();
    // XP-13b: the contained-tier helper ships beside orceld.exe, pinned by
    // orcel-contain.sha256, and both are manifest files.
    let helper =
        fs::read(release.join("orcel-contain.exe")).expect("orcel-contain.exe is packaged");
    let pin =
        fs::read_to_string(release.join("orcel-contain.sha256")).expect("its pin is packaged");
    assert_eq!(pin, format!("{}\n", sha256_bytes(&helper)));
    for name in ["orcel-contain.exe", "orcel-contain.sha256"] {
        assert!(
            manifest["files"]
                .as_array()
                .unwrap()
                .iter()
                .any(|file| file["path"] == name),
            "{name} is not a manifest file"
        );
    }
    let node = find_node_on_path().expect("Node.js is required on PATH");
    let tunnel = fake_tunnel();
    let local = temp_dir("local");
    let root = local.join("Orcel");
    let project = temp_dir("project");
    fs::write(project.join("hello.txt"), b"hello from the workspace").unwrap();
    let key_dir = temp_dir("key");
    let key_file = key_dir.join("runtime.key");
    let cleanup = Cleanup {
        local: local.clone(),
        dirs: std::cell::RefCell::new(vec![project.clone(), key_dir.clone()]),
    };
    fs::write(&key_file, SECRET).unwrap();
    let tunnel_log = root.join("logs").join("tunnel.log");

    // SG-000072: prove the 0.1.0 line updates cleanly to this candidate.
    // Install a 0.1.0-versioned image of the packaged payload first (same
    // config schema, previous release line), then update to the real
    // candidate and require the version record to show the transition.
    let previous_labeled = derived_release(&release, "0.1.0", None);
    cleanup.track(&previous_labeled);
    let installed = json_ok(&orcel(
        &previous_labeled.join("orcel.exe"),
        &local,
        &[
            "install",
            "--no-path",
            "--node",
            node.to_str().unwrap(),
            "--json",
        ],
    ));
    assert_eq!(installed["install"]["version"], "0.1.0");
    let upgraded = json_ok(&orcel(
        &previous_labeled.join("orcel.exe"),
        &local,
        &["update", "--source", release.to_str().unwrap(), "--json"],
    ));
    assert_eq!(upgraded["update"]["to"], base_version.as_str());
    let cli = root.join("bin").join("orcel.exe");
    let version = json_ok(&orcel(&cli, &local, &["version", "--json"]));
    assert_eq!(version["installed"], base_version.as_str());
    assert_eq!(version["previous"], "0.1.0");
    json_ok(&orcel(
        &cli,
        &local,
        &[
            "workspace",
            "add",
            "default",
            project.to_str().unwrap(),
            "--json",
        ],
    ));
    json_ok(&orcel(
        &cli,
        &local,
        &[
            "tunnel",
            "setup",
            "--client",
            tunnel.to_str().unwrap(),
            "--tunnel-id",
            TUNNEL_ID,
            "--key-file",
            key_file.to_str().unwrap(),
            "--json",
        ],
    ));

    // Start and drive MCP through the installed real app.
    let started = json_ok(&orcel(&cli, &local, &["start", "--json"]));
    assert_eq!(started["status"]["state"], "running", "{started}");
    let log = wait_for_count(&tunnel_log, "fake-tunnel: mcp-call", 1);
    assert!(
        log.contains("fake-tunnel: mcp-initialize server=orcel"),
        "{log}"
    );
    let tools_line = log
        .lines()
        .find(|line| line.contains("fake-tunnel: mcp-tools"))
        .unwrap()
        .to_string();
    // The tunnel's MCP surface must be exactly the remote `core` profile
    // (exact equality, never a subset): any added tool (desktop, clipboard,
    // network, browser, UI automation, trust, shell, ...) is exposure drift
    // and fails qualification.
    let listed = tools_line
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(names, _)| names.split(',').map(str::to_string).collect::<Vec<_>>())
        .unwrap();
    let mut listed_sorted = listed.clone();
    listed_sorted.sort();
    let mut core = TUNNEL_CORE_TOOLS
        .iter()
        .map(|name| name.to_string())
        .collect::<Vec<_>>();
    core.sort();
    assert_eq!(listed_sorted, core, "MCP exposure drift: {tools_line}");
    // WI-06: web_search is local-only; the tunnel must never serve it.
    assert!(
        !listed.iter().any(|name| name == "web_search"),
        "web_search must never be served through the tunnel: {tools_line}"
    );
    assert!(log.contains(TUNNEL_CALL_LEASE_GATED), "{log}");
    assert!(log.contains("fake-tunnel: env-clean=true"), "{log}");
    assert!(log.contains("api_key=[REDACTED]"), "{log}");

    let doctor = json_ok(&orcel(&cli, &local, &["doctor", "--json"]));
    assert_eq!(doctor["doctor"]["healthy"], true, "{doctor}");

    // Update while running: stopped, switched, verified by the new CLI, restarted.
    let next = bump_patch(&base_version, 1);
    let candidate = derived_release(&release, &next, None);
    cleanup.track(&candidate);
    let checked = json_ok(&orcel(
        &cli,
        &local,
        &[
            "update",
            "--source",
            candidate.to_str().unwrap(),
            "--check",
            "--json",
        ],
    ));
    assert_eq!(checked["update"]["direction"], "upgrade");
    let updated = json_ok(&orcel(
        &cli,
        &local,
        &["update", "--source", candidate.to_str().unwrap(), "--json"],
    ));
    assert_eq!(updated["update"]["to"], next.as_str());
    assert_eq!(updated["update"]["restarted"], true, "{updated}");
    wait_for_count(&tunnel_log, TUNNEL_CALL_LEASE_GATED, 2);
    let version = json_ok(&orcel(&cli, &local, &["version", "--json"]));
    assert_eq!(version["installed"], next.as_str());
    assert_eq!(version["previous"], base_version.as_str());

    // Downgrades are refused unless explicitly allowed.
    let downgrade = orcel(
        &cli,
        &local,
        &["update", "--source", release.to_str().unwrap(), "--json"],
    );
    assert_eq!(downgrade.status.code(), Some(6), "{downgrade:?}");

    // Rollback to the retained previous version.
    let rolled = json_ok(&orcel(&cli, &local, &["rollback", "--json"]));
    assert_eq!(rolled["rollback"]["to"], base_version.as_str());
    assert_eq!(rolled["rollback"]["restarted"], true);
    wait_for_count(&tunnel_log, TUNNEL_CALL_LEASE_GATED, 3);

    // A release whose CLI cannot verify itself must be rolled back automatically.
    let bad_version = bump_patch(&base_version, 2);
    let broken_cli = fs::read(&tunnel).unwrap();
    let broken = derived_release(&release, &bad_version, Some(("orcel.exe", &broken_cli)));
    cleanup.track(&broken);
    let failed = orcel(
        &cli,
        &local,
        &["update", "--source", broken.to_str().unwrap(), "--json"],
    );
    assert_eq!(failed.status.code(), Some(7), "{failed:?}");
    let failure = String::from_utf8_lossy(&failed.stdout);
    assert!(failure.contains("was restored"), "{failure}");
    let version = json_ok(&orcel(&cli, &local, &["version", "--json"]));
    assert_eq!(version["installed"], base_version.as_str());
    assert!(!root.join("versions").join(&bad_version).exists());
    let status = json_ok(&orcel(&cli, &local, &["status", "--json"]));
    assert_eq!(status["runtime"]["state"], "running", "{status}");
    let doctor = orcel(&cli, &local, &["doctor", "--json"]);
    let doctor_text = String::from_utf8_lossy(&doctor.stdout);
    assert!(doctor_text.contains("update_state"), "{doctor_text}");
    assert!(doctor_text.contains("was restored"), "{doctor_text}");

    // Stop and uninstall; user data is retained until purged.
    let stopped = json_ok(&orcel(&cli, &local, &["stop", "--json"]));
    assert_eq!(stopped["stop"]["outcome"], "stopped_verified");
    json_ok(&orcel(
        &release.join("orcel.exe"),
        &local,
        &["uninstall", "--json"],
    ));
    assert!(root.join("state").join("config.json").is_file());
    for log in ["tunnel.log", "supervisor.log", "lifecycle.log"] {
        let text = fs::read_to_string(root.join("logs").join(log)).unwrap_or_default();
        assert!(!text.contains(SECRET), "{log} contains the runtime key");
    }
    let transcript = fs::read_to_string(root.join("logs").join("lifecycle.log")).unwrap();
    assert!(
        transcript.contains("failed and was rolled back"),
        "{transcript}"
    );
    json_ok(&orcel(
        &release.join("orcel.exe"),
        &local,
        &["uninstall", "--purge-data", "--yes", "--json"],
    ));
    assert!(!root.exists());
}
