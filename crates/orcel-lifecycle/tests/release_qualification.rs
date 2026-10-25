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

// SG-000127 slice 2: the full installed app stays inside the founder's
// 400 MB budget (UI_UX_AND_APP_SIZE_BUDGET.md). Decimal megabytes, the
// stricter reading. Prerequisites that are not shipped are listed beside the
// total with their own size, never counted as zero and never folded in.
const INSTALLED_BUDGET_BYTES: u64 = 400_000_000;
// Allocated disk is estimated per file at this cluster size (the NTFS
// default); the apparent bytes are exact.
const CLUSTER_BYTES: u64 = 4096;

/// Apparent and allocated bytes of every regular file under `dir`, keyed by
/// the first two path components below `root` (for example `bin/orcel.exe`
/// or `versions/<version>`). Links and other non-regular entries are not
/// followed; they are collected in `skipped` so none can hide bytes.
fn inventory(
    root: &Path,
    dir: &Path,
    components: &mut std::collections::BTreeMap<String, (u64, u64, u64)>,
    skipped: &mut Vec<String>,
) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        let path = entry.path();
        if kind.is_dir() {
            inventory(root, &path, components, skipped);
        } else if kind.is_file() {
            let bytes = entry.metadata().unwrap().len();
            let key = path
                .strip_prefix(root)
                .unwrap()
                .components()
                .take(2)
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let slot = components.entry(key).or_default();
            slot.0 += bytes;
            slot.1 += bytes.div_ceil(CLUSTER_BYTES) * CLUSTER_BYTES;
            slot.2 += 1;
        } else {
            skipped.push(path.display().to_string());
        }
    }
}

#[test]
#[ignore = "requires ORCEL_RELEASE_DIR; run by the release-qualification CI job"]
fn installed_release_fits_the_400_mb_budget() {
    let release = PathBuf::from(
        std::env::var_os("ORCEL_RELEASE_DIR")
            .expect("ORCEL_RELEASE_DIR must name a packaged release"),
    );
    let manifest: Value =
        serde_json::from_slice(&fs::read(release.join(MANIFEST_FILE)).unwrap()).unwrap();
    let node = find_node_on_path().expect("Node.js is required on PATH");
    let local = temp_dir("size");
    let root = local.join("Orcel");
    let _cleanup = Cleanup {
        local: local.clone(),
        dirs: std::cell::RefCell::new(Vec::new()),
    };

    // A fresh per-user install of exactly this candidate: no previous
    // version, no rollback copy, no runtime state yet.
    let installed = json_ok(&orcel(
        &release.join("orcel.exe"),
        &local,
        &[
            "install",
            "--no-path",
            "--node",
            node.to_str().unwrap(),
            "--json",
        ],
    ));
    assert_eq!(installed["install"]["version"], manifest["version"]);

    let mut components = std::collections::BTreeMap::new();
    let mut skipped = Vec::new();
    inventory(&root, &root, &mut components, &mut skipped);
    // The installer creates only regular files and directories; a link or
    // reparse point would escape the inventory.
    assert!(
        skipped.is_empty(),
        "non-regular entries in the install root: {skipped:?}"
    );
    let (bytes, allocated, files) = components.values().fold((0, 0, 0), |sum, part| {
        (sum.0 + part.0, sum.1 + part.1, sum.2 + part.2)
    });
    assert!(
        files > 0,
        "the install root {} holds no files",
        root.display()
    );

    let node_version = Command::new(&node).arg("--version").output().unwrap();
    assert!(node_version.status.success());
    let report = serde_json::json!({
        "schema": "orcel-installed-size/1",
        "version": manifest["version"],
        "budget_bytes": INSTALLED_BUDGET_BYTES,
        "installed": {
            "bytes": bytes,
            "allocated_estimate_bytes": allocated,
            "cluster_bytes": CLUSTER_BYTES,
            "files": files,
        },
        "components": components
            .iter()
            .map(|(name, part)| serde_json::json!({
                "path": name,
                "bytes": part.0,
                "allocated_estimate_bytes": part.1,
                "files": part.2,
            }))
            .collect::<Vec<_>>(),
        // Not shipped and not counted in `installed`; listed so the budget
        // never hides what a user must also have.
        "prerequisites": [
            {
                "name": "Node.js",
                "version": String::from_utf8_lossy(&node_version.stdout).trim(),
                "executable_bytes": fs::metadata(&node).unwrap().len(),
                "counted": false,
            },
        ],
        // Release builds carry no live browser (SG-000108 is a
        // development-build feature only), so no browser is a prerequisite yet.
        "browser": { "required": false, "counted": false, "reason": "release builds carry no live browser" },
        // Not measured here: a fresh install has no cache yet. Never
        // reported as zero.
        "cache": { "measured": false, "counted": false, "reason": "none exists at a fresh install" },
        "not_shipped": ["live browser worker and runtime (SG-000127 slice 7)", "Windows app (apps/orcel-desktop-preview)"],
    });
    println!("installed-size-report: {report}");
    assert!(
        allocated < INSTALLED_BUDGET_BYTES,
        "installed app uses {allocated} allocated bytes ({bytes} apparent), over the {INSTALLED_BUDGET_BYTES} byte budget"
    );
}

/// One MCP session over `orcel mcp stdio`, the entrypoint every supported
/// local client configuration launches, driven one request at a time.
struct McpStdio {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    lines: std::sync::mpsc::Receiver<String>,
    stderr: PathBuf,
    next_id: u64,
}

/// How long one MCP answer may take before the test fails with the
/// session's standard error.
const MCP_ANSWER_TIMEOUT: Duration = Duration::from_secs(60);

impl McpStdio {
    fn start(cli: &Path, local: &Path, stderr: PathBuf) -> Self {
        let mut child = Command::new(cli)
            .args(["mcp", "stdio"])
            .env("LOCALAPPDATA", local)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(fs::File::create(&stderr).unwrap())
            .spawn()
            .expect("start orcel mcp stdio");
        let stdin = child.stdin.take();
        let stdout = std::io::BufReader::new(child.stdout.take().unwrap());
        // Read on a thread so a stalled server fails the test at a deadline
        // instead of hanging the job.
        let (sender, lines) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            use std::io::BufRead;
            for line in stdout.lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        let mut session = Self {
            child,
            stdin,
            lines,
            stderr,
            next_id: 0,
        };
        session.request(
            "initialize",
            serde_json::json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "orcel-release-qualification", "version": "1" }
            }),
        );
        session
            .send(&serde_json::json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        session
    }

    fn send(&mut self, message: &Value) {
        use std::io::Write;
        let stdin = self.stdin.as_mut().expect("the session is open");
        writeln!(stdin, "{message}").unwrap();
        stdin.flush().unwrap();
    }

    /// The result of one request; server notifications are skipped.
    fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(
            &serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }),
        );
        loop {
            let line = self
                .lines
                .recv_timeout(MCP_ANSWER_TIMEOUT)
                .unwrap_or_else(|_| {
                    panic!(
                        "orcel mcp stdio gave no answer to {method}; stderr: {}",
                        fs::read_to_string(&self.stderr).unwrap_or_default()
                    )
                });
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == id {
                assert!(message.get("error").is_none(), "{method}: {message}");
                return message["result"].clone();
            }
        }
    }

    /// A tool call's projected kernel answer: `(is_error, {result|error})`.
    fn call(&mut self, tool: &str, arguments: Value) -> (bool, Value) {
        let result = self.request(
            "tools/call",
            serde_json::json!({ "name": tool, "arguments": arguments }),
        );
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or("{}")
            .to_string();
        (
            result["isError"] == true,
            serde_json::from_str(&text).unwrap(),
        )
    }
}

impl McpStdio {
    /// Ends the session as a client does, by closing standard input, and
    /// waits for the handed-off session to exit; kills only as a fallback.
    /// The session's exit status, or `None` when it ignored the end of its
    /// input for 30 s and had to be killed.
    fn close(&mut self) -> Option<std::process::ExitStatus> {
        drop(self.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        None
    }
}

impl Drop for McpStdio {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

// SG-000127 slice 6: the report journey through the installed release and
// its supported local client entrypoint, `orcel mcp stdio`, up to every
// refusal orceld makes before it would ask for approval. No request here
// reaches the approval broker, so no platform dialog can appear; the
// approved commit needs a person at the prompt (slice 4).
#[test]
#[ignore = "requires ORCEL_RELEASE_DIR; run by the release-qualification CI job"]
fn installed_release_serves_the_report_task_to_a_local_client() {
    let release = PathBuf::from(
        std::env::var_os("ORCEL_RELEASE_DIR")
            .expect("ORCEL_RELEASE_DIR must name a packaged release"),
    );
    let node = find_node_on_path().expect("Node.js is required on PATH");
    let local = temp_dir("journey");
    let root = local.join("Orcel");
    let project = temp_dir("journey-project");
    let _cleanup = Cleanup {
        local: local.clone(),
        dirs: std::cell::RefCell::new(vec![project.clone()]),
    };
    fs::create_dir_all(project.join("data")).unwrap();
    fs::create_dir_all(project.join("reports")).unwrap();
    let q3 = "region,quarter,revenue_cents\nnorth,Q3,1250000\nsouth,Q3,980050\n";
    fs::write(project.join("data").join("q3.csv"), q3).unwrap();
    fs::write(project.join("reports").join("taken.md"), "the user's file").unwrap();

    json_ok(&orcel(
        &release.join("orcel.exe"),
        &local,
        &[
            "install",
            "--no-path",
            "--node",
            node.to_str().unwrap(),
            "--json",
        ],
    ));
    let cli = root.join("bin").join("orcel.exe");
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

    let mut mcp = McpStdio::start(&cli, &local, project.join("mcp-stderr.log"));
    let listed = mcp.request("tools/list", serde_json::json!({}));
    let names: Vec<&str> = listed["tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    for tool in ["report_start", "report_preview", "report_commit"] {
        assert!(names.contains(&tool), "{tool} is listed locally: {names:?}");
    }
    assert!(
        !names.iter().any(|name| name.starts_with("browser_")),
        "the release build serves no live browser tool: {names:?}"
    );

    let (failed, started) = mcp.call(
        "report_start",
        serde_json::json!({ "title": "Q3 revenue", "sources": ["data/q3.csv"], "folder": "reports" }),
    );
    assert!(!failed, "{started}");
    let task = started["result"]["task_id"].as_str().unwrap().to_string();
    assert_eq!(started["result"]["state"], "observed");
    assert_eq!(started["result"]["sources"][0]["text"], q3);

    let content = "# Q3 revenue\n\nnorth 1250000, south 980050\n";
    let (failed, preview) = mcp.call(
        "report_preview",
        serde_json::json!({ "task_id": task, "name": "q3.md", "content": content }),
    );
    assert!(!failed, "{preview}");
    let digest = preview["result"]["sha256"].as_str().unwrap().to_string();
    assert_eq!(digest, sha256_bytes(content.as_bytes()));

    // An existing destination is refused at preview, before any approval,
    // and the user's file is untouched. A commit of a report the last
    // preview did not return is refused before any approval too.
    let (failed, taken) = mcp.call(
        "report_preview",
        serde_json::json!({ "task_id": task, "name": "taken.md", "content": content }),
    );
    assert!(failed, "{taken}");
    let (failed, taken) = mcp.call(
        "report_commit",
        serde_json::json!({ "task_id": task, "name": "taken.md", "content": content, "expected_sha256": digest }),
    );
    assert!(failed, "{taken}");
    assert!(
        taken["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("the last preview of this task returned"),
        "{taken}"
    );

    // A changed source makes the task stale before any approval.
    fs::write(
        project.join("data").join("q3.csv"),
        "region,quarter,revenue_cents\nnorth,Q3,1\n",
    )
    .unwrap();
    let (failed, stale) = mcp.call(
        "report_commit",
        serde_json::json!({ "task_id": task, "name": "q3.md", "content": content, "expected_sha256": digest }),
    );
    assert!(failed, "{stale}");
    assert_eq!(stale["error"]["code"], "TARGET_STALE", "{stale}");
    assert!(
        stale["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("changed since the task observed it"),
        "the source change, not a missing preview, ends the task: {stale}"
    );
    let (failed, after) = mcp.call(
        "report_preview",
        serde_json::json!({ "task_id": task, "name": "q3.md", "content": content }),
    );
    assert!(failed, "a stale task stays stale: {after}");
    let stderr = project.join("mcp-stderr.log");
    let closed = mcp.close();
    let status = closed.unwrap_or_else(|| {
        panic!(
            "the session ignored the end of its input; stderr: {}",
            fs::read_to_string(&stderr).unwrap_or_default()
        )
    });
    assert!(
        status.success(),
        "the session ended with {status}; stderr: {}",
        fs::read_to_string(&stderr).unwrap_or_default()
    );
    drop(mcp);

    // SG-000120 RJ-02: the report task journal lives in the install root
    // beside the audit log, holds no task title, and passes the install's
    // owner-only ACL check: a second session verifies the whole tree first.
    let journal = root.join("report-tasks.jsonl");
    assert!(journal.is_file(), "the report task journal was written");
    assert!(
        !fs::read_to_string(&journal)
            .unwrap()
            .contains("Q3 revenue\""),
        "the planner title is never journaled"
    );
    let mut again = McpStdio::start(&cli, &local, project.join("mcp-stderr-2.log"));
    let listed = again.request("tools/list", serde_json::json!({}));
    assert!(listed["tools"]
        .as_array()
        .is_some_and(|tools| !tools.is_empty()));
    assert!(
        again.close().is_some_and(|status| status.success()),
        "a second session verifies the install tree, journal included"
    );
    drop(again);

    let mut reports: Vec<String> = fs::read_dir(project.join("reports"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    reports.sort();
    assert_eq!(reports, ["taken.md"], "nothing was written");
    assert_eq!(
        fs::read_to_string(project.join("reports").join("taken.md")).unwrap(),
        "the user's file"
    );

    json_ok(&orcel(
        &release.join("orcel.exe"),
        &local,
        &["uninstall", "--purge-data", "--yes", "--json"],
    ));
    assert!(
        !root.exists(),
        "uninstall leaves nothing under the install root"
    );
}
