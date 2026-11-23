//! MAC-M1-03 on the hosted macOS runner: the per-user install under
//! `~/Library/Application Support/Orcel`, through the real `Installer` and
//! the real macOS host operations (`MacosPlatform`), with the real `orcel`
//! and `orcel-mcp-host` binaries this package builds. `orceld` is the real
//! binary when `ORCEL_MACOS_ORCELD` names it (the CI step builds it), else a
//! stand-in file.
//!
//! Each test makes its own `HOME` in the temporary folder, so nothing touches
//! the runner user's own Application Support. With
//! `ORCEL_REQUIRE_MACOS_INSTALL=1` (CI), a missing prerequisite (Node.js, the
//! real `orceld`) fails instead of skipping.
//!
//! MAC-M1-07: one test also loads the per-user launchd agent, under its own
//! label, folder and socket, in the runner user's `gui/<uid>` domain, asks
//! the `orceld` it starts for `system.status`, and unloads it through
//! uninstall.
//!
//! `host_platform()` still refuses these commands on macOS until the macOS
//! M1 grain is activated; these tests are the hosted-runner evidence the
//! plan asks for before then. Real Mac hardware: UNVERIFIED.
#![cfg(target_os = "macos")]

use orcel_lifecycle::install::{InstallOptions, Installer, UninstallOptions};
use orcel_lifecycle::layout::Layout;
use orcel_lifecycle::manifest::{
    sha256_bytes, ConfigSchemaRange, Manifest, ManifestFile, MANIFEST_FILE, MANIFEST_SCHEMA,
    REQUIRED_FILES,
};
use orcel_lifecycle::platform::find_node_on_path;
use orcel_lifecycle::unix_install::{AgentTarget, MacosPlatform};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const VERSION: &str = "0.2.0";

fn required() -> bool {
    std::env::var_os("ORCEL_REQUIRE_MACOS_INSTALL").is_some()
}

fn unique(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "orcel-mac-m1-03-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

/// A fresh `HOME` and the Orcel root inside it, where XP-01 puts it on macOS.
fn home_and_root(label: &str) -> (PathBuf, PathBuf) {
    let home = unique(label);
    let root = home
        .join("Library")
        .join("Application Support")
        .join("Orcel");
    let resolved = orcel_platform::paths::state_root_from(&|name| match name {
        "HOME" => Some(home.clone().into_os_string()),
        _ => None,
    })
    .unwrap();
    assert_eq!(
        resolved, root,
        "XP-01 puts the macOS root in Application Support"
    );
    (home, root)
}

fn node() -> Option<PathBuf> {
    let node = find_node_on_path();
    if node.is_none() {
        assert!(!required(), "Node.js is required on this runner");
        eprintln!("MAC-M1-03 skipped: no Node.js on PATH");
    }
    node
}

fn orceld_bytes() -> Vec<u8> {
    match std::env::var_os("ORCEL_MACOS_ORCELD") {
        Some(path) => fs::read(&path).expect("read ORCEL_MACOS_ORCELD"),
        None => {
            assert!(!required(), "ORCEL_MACOS_ORCELD must name the built orceld");
            b"orceld stand-in".to_vec()
        }
    }
}

/// A release folder with this OS's required files (real `orcel` and
/// `orcel-mcp-host`) and a matching manifest.
fn release(label: &str) -> PathBuf {
    let dir = unique(label).join("release");
    fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    let mut paths = REQUIRED_FILES
        .iter()
        .map(|path| path.to_string())
        .collect::<Vec<_>>();
    paths.push("app/orcel-mcp/node_modules/zod/package.json".into());
    for path in paths {
        let contents = match path.as_str() {
            "orcel" => fs::read(env!("CARGO_BIN_EXE_orcel")).unwrap(),
            "orcel-mcp-host" => fs::read(env!("CARGO_BIN_EXE_orcel-mcp-host")).unwrap(),
            "orceld" => orceld_bytes(),
            other => format!("{other} for {VERSION}").into_bytes(),
        };
        let target = dir.join(&path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, &contents).unwrap();
        if matches!(path.as_str(), "orcel" | "orcel-mcp-host" | "orceld") {
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        }
        files.push(ManifestFile {
            path,
            size: contents.len() as u64,
            sha256: sha256_bytes(&contents),
        });
    }
    let manifest = Manifest {
        schema: MANIFEST_SCHEMA.into(),
        version: VERSION.into(),
        config_schema: ConfigSchemaRange { min: 1, max: 1 },
        files,
    };
    fs::write(
        dir.join(MANIFEST_FILE),
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();
    dir
}

fn options(node: PathBuf) -> InstallOptions {
    InstallOptions {
        node: Some(node),
        add_to_path: false,
    }
}

fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::MetadataExt;
    fs::symlink_metadata(path).unwrap().mode() & 0o777
}

/// Installs a fresh release and returns the root.
fn installed(label: &str) -> Option<(PathBuf, PathBuf)> {
    let node = node()?;
    let (home, root) = home_and_root(label);
    let platform = MacosPlatform::without_agent();
    Installer::new(Layout::new(&root), &platform)
        .install(&release(label), &options(node))
        .expect("install");
    Some((home, root))
}

fn verify(root: &Path) -> Result<(), String> {
    let platform = MacosPlatform::without_agent();
    Installer::new(Layout::new(root), &platform)
        .verify()
        .map(|_| ())
        .map_err(|error| error.message)
}

#[test]
fn install_verify_run_and_uninstall_round_trip() {
    let Some(node) = node() else { return };
    let (home, root) = home_and_root("roundtrip");
    let platform = MacosPlatform::without_agent();
    let installer = Installer::new(Layout::new(&root), &platform);
    let report = installer
        .install(&release("roundtrip"), &options(node))
        .expect("install");
    assert_eq!(report.version, VERSION);
    assert!(!report.path_entry_added, "macOS PATH is never edited");
    let state = installer.verify().expect("verify");
    assert_eq!(state.active.version, VERSION);
    let version_dir = root.join("versions").join(VERSION);
    assert_eq!(mode(&root), 0o700);
    assert_eq!(mode(&version_dir.join("orceld")), 0o700);
    assert!(!version_dir.join("orceld.exe").exists());
    let cli = root.join("bin").join("orcel");
    assert_eq!(mode(&cli), 0o700);

    // The installed CLI copy runs and reads this layout through XP-01.
    let output = std::process::Command::new(&cli)
        .arg("version")
        .env_clear()
        .env("HOME", &home)
        .output()
        .expect("run the installed orcel");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(
        stdout.contains(&format!("installed: {VERSION}")),
        "{stdout}"
    );
    println!(
        "MAC-M1-03-EVIDENCE install root={} version={} files={} root_mode={:o} cli_mode={:o} installed_cli_ran=true",
        root.display(),
        state.active.version,
        state.manifest.files.len(),
        mode(&root),
        mode(&cli)
    );

    let uninstall = installer
        .uninstall(&UninstallOptions::default())
        .expect("uninstall");
    assert!(uninstall.residual.is_empty(), "{:?}", uninstall.residual);
    for gone in ["versions", "bin", "current.json", "install.json"] {
        assert!(!root.join(gone).exists(), "{gone} remains after uninstall");
    }
    let error = installer.verify().unwrap_err();
    assert_eq!(error.kind, orcel_lifecycle::ErrorKind::NotInstalled);
    println!(
        "MAC-M1-03-EVIDENCE uninstall removed={} residual=0 payload_left=false",
        uninstall.removed.len()
    );
}

#[test]
fn a_tampered_or_extra_payload_file_fails_verification() {
    let Some((_, root)) = installed("tamper") else {
        return;
    };
    let version_dir = root.join("versions").join(VERSION);
    fs::write(version_dir.join("orceld"), b"tampered").unwrap();
    let error = verify(&root).unwrap_err();
    assert!(error.contains("mismatch"), "{error}");

    let Some((_, root)) = installed("unlisted") else {
        return;
    };
    let version_dir = root.join("versions").join(VERSION);
    fs::write(version_dir.join("extra"), b"x").unwrap();
    fs::set_permissions(version_dir.join("extra"), fs::Permissions::from_mode(0o600)).unwrap();
    let error = verify(&root).unwrap_err();
    assert!(error.contains("unlisted"), "{error}");
    println!("MAC-M1-03-EVIDENCE refused tampered=true unlisted=true");
}

#[test]
fn links_in_the_install_or_the_release_fail_closed() {
    let Some((_, root)) = installed("symlink") else {
        return;
    };
    let version_dir = root.join("versions").join(VERSION);
    std::os::unix::fs::symlink("/usr/bin/true", version_dir.join("link")).unwrap();
    assert!(verify(&root).is_err());

    let Some((_, root)) = installed("hardlink") else {
        return;
    };
    let outside = unique("hardlink-outside").join("orceld-alias");
    fs::hard_link(root.join("versions").join(VERSION).join("orceld"), outside).unwrap();
    let error = verify(&root).unwrap_err();
    assert!(error.contains("hard link"), "{error}");

    let Some(node) = node() else { return };
    let (_, root) = home_and_root("release-link");
    let source = release("release-link");
    std::os::unix::fs::symlink("/usr/bin/true", source.join("link")).unwrap();
    let platform = MacosPlatform::without_agent();
    assert!(Installer::new(Layout::new(&root), &platform)
        .install(&source, &options(node))
        .is_err());
    assert!(!root.join("current.json").exists());
    println!("MAC-M1-03-EVIDENCE refused symlink=true hardlink=true release_link=true");
}

#[test]
fn group_or_other_access_fails_verification() {
    let Some((_, root)) = installed("perm-file") else {
        return;
    };
    let cli = root.join("bin").join("orcel");
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o720)).unwrap();
    assert!(verify(&root).is_err(), "a group-writable bin/orcel");

    let Some((_, root)) = installed("perm-root") else {
        return;
    };
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(verify(&root).is_err(), "a readable install root");
    println!("MAC-M1-03-EVIDENCE refused group_writable_file=true readable_root=true");
}

#[test]
fn a_root_under_an_admin_writable_folder_installs_nothing() {
    let Some(node) = node() else { return };
    // The shape of /Applications (root:admin 0775).
    let shared = unique("admin-writable");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o775)).unwrap();
    let root = shared.join("Orcel");
    let platform = MacosPlatform::without_agent();
    let error = Installer::new(Layout::new(&root), &platform)
        .install(&release("admin-writable"), &options(node))
        .unwrap_err();
    assert!(!root.join("current.json").exists(), "{}", error.message);
    assert!(!root.join("versions").join(VERSION).exists());
    println!("MAC-M1-03-EVIDENCE refused admin_writable_ancestor=true");
}

#[test]
fn a_release_with_windows_names_is_not_installable_on_macos() {
    let Some(node) = node() else { return };
    let (_, root) = home_and_root("windows-names");
    let source = release("windows-names");
    let manifest_path = source.join(MANIFEST_FILE);
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    for file in &mut manifest.files {
        if file.path == "orceld" {
            fs::rename(source.join("orceld"), source.join("orceld.exe")).unwrap();
            file.path = "orceld.exe".into();
        }
    }
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let platform = MacosPlatform::without_agent();
    let error = Installer::new(Layout::new(&root), &platform)
        .install(&source, &options(node))
        .unwrap_err();
    assert!(
        error.message.contains("missing required file orceld"),
        "{}",
        error.message
    );
}

/// Unloads the test's agent however the test ends.
struct Bootout(String);

impl Drop for Bootout {
    fn drop(&mut self) {
        let uid = orcel_platform::session::effective_uid().unwrap_or(0);
        let _ = std::process::Command::new("/bin/launchctl")
            .args(["bootout", &format!("gui/{uid}/{}", self.0)])
            .output();
    }
}

fn agent_loaded(label: &str) -> bool {
    let uid = orcel_platform::session::effective_uid().unwrap();
    std::process::Command::new("/bin/launchctl")
        .args(["print", &format!("gui/{uid}/{label}")])
        .output()
        .unwrap()
        .status
        .success()
}

fn system_status(socket: &Path) -> serde_json::Value {
    use std::io::{BufRead, BufReader, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).expect("connect");
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(60)))
        .unwrap();
    let request = serde_json::json!({
        "version": 1,
        "request_id": "mac-m1-07",
        "client_session_id": "mac-m1-07",
        "workspace_id": "ci",
        "capability": "system.status",
        "operation": "get",
        "target": null,
        "arguments": {},
    });
    let mut line = request.to_string();
    line.push('\n');
    stream.write_all(line.as_bytes()).unwrap();
    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer).unwrap();
    serde_json::from_str(&answer).unwrap_or_else(|error| panic!("{error}: {answer:?}"))
}

#[test]
fn the_launch_agent_starts_orceld_per_connection_and_uninstall_removes_it() {
    let Some(node) = node() else { return };
    if std::env::var_os("ORCEL_MACOS_ORCELD").is_none() {
        assert!(!required(), "ORCEL_MACOS_ORCELD must name the built orceld");
        eprintln!("MAC-M1-07 skipped: needs the real orceld");
        return;
    }
    let (home, root) = home_and_root("agent");
    let workspace = home.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    orcel_lifecycle::config::Config {
        workspaces: vec![orcel_lifecycle::config::WorkspaceEntry {
            id: "ci".into(),
            root: workspace,
        }],
        ..orcel_lifecycle::config::Config::default()
    }
    .save(&Layout::new(&root))
    .unwrap();
    let label = format!("ai.orcel.orceld.ci{}", std::process::id());
    let _guard = Bootout(label.clone());
    let plist_dir = home.join("Library").join("LaunchAgents");
    let socket = unique("s").join("orcel").join("orceld.sock");
    let platform = MacosPlatform {
        agent: AgentTarget::Custom {
            plist_dir: plist_dir.clone(),
            label: label.clone(),
            socket: socket.clone(),
            extra_environment: std::collections::BTreeMap::from([(
                "HOME".to_owned(),
                home.to_str().unwrap().to_owned(),
            )]),
        },
    };
    let installer = Installer::new(Layout::new(&root), &platform);
    installer
        .install(&release("agent"), &options(node))
        .expect("install");
    let plist = plist_dir.join(format!("{label}.plist"));
    assert_eq!(mode(&plist), 0o600);
    let text = fs::read_to_string(&plist).unwrap();
    let program = root.join("versions").join(VERSION).join("orceld");
    assert!(text.contains(&format!("<string>{}</string>", program.display())));
    assert!(agent_loaded(&label), "launchctl print gui/<uid>/{label}");
    {
        use std::os::unix::fs::FileTypeExt;
        let metadata = fs::symlink_metadata(&socket).expect("launchd made the socket");
        assert!(metadata.file_type().is_socket());
    }
    assert_eq!(mode(&socket), 0o600);
    assert_eq!(mode(socket.parent().unwrap()), 0o700);

    // A log over the bound is moved aside when launchd next starts orceld,
    // and one an earlier version left 0644 is made owner-only.
    let log = root.join("logs").join("orceld-agent.log");
    let oversized = orcel_lifecycle::launchd::MAX_STDERR_LOG as usize + 1;
    fs::write(&log, vec![b'x'; oversized]).unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();

    for _ in 0..2 {
        let response = system_status(&socket);
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["result"]["name"], "orceld", "{response}");
        assert_eq!(response["result"]["os"], "macos", "{response}");
    }
    // orceld's standard error (its readiness line) went to the log file, not
    // the connection: launchd's inetd mode puts stderr on the socket too.
    let rotated = fs::metadata(root.join("logs").join("orceld-agent.log.1"))
        .expect("the oversized log was moved aside");
    assert_eq!(rotated.len() as usize, oversized);
    assert_eq!(mode(&root.join("logs").join("orceld-agent.log.1")), 0o600);
    let logged = fs::read_to_string(&log).expect("the agent's stderr log");
    assert_eq!(
        logged.matches("orceld ready:").count(),
        2,
        "one readiness line per connection, in the log:\n{logged}"
    );
    assert_eq!(mode(&log), 0o600);
    // One orceld per connection: none outlives its client.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let running = std::process::Command::new("/usr/bin/pgrep")
        .args(["-f", program.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        !running.status.success(),
        "an orceld outlived its connection: {}",
        String::from_utf8_lossy(&running.stdout)
    );
    println!(
        "MAC-M1-07-EVIDENCE agent loaded=true domain=gui label={label} socket_mode=600 socket_dir_mode=700 plist_mode=600 answered=2 stderr_to_log=2 rotated_on_start=true lingering=0"
    );

    let report = installer
        .uninstall(&UninstallOptions::default())
        .expect("uninstall");
    assert!(report.removed.contains(&plist), "{:?}", report.removed);
    assert!(!plist.exists());
    assert!(!agent_loaded(&label), "the agent is still loaded");
    assert!(fs::symlink_metadata(&socket).is_err(), "the socket remains");
    println!("MAC-M1-07-EVIDENCE bootout loaded=false plist_left=false socket_left=false");
}

/// MAC-M1-08: the path emergency revoke takes on macOS once activated: the
/// `orceld` of the verified install (from `Installer::verify`, never a
/// sibling of `orcel`), with the configured workspaces. With nobody at the
/// runner, and the donor's two bypass variables set, its STRONG check fails
/// closed, nothing is revoked, and the refusal is in its audit log. This test
/// starts that `orceld` itself, with this test's `HOME`, as `ipc::call` does.
#[test]
fn the_installed_orceld_refuses_emergency_revoke_headless() {
    let Some(node) = node() else { return };
    if std::env::var_os("ORCEL_MACOS_ORCELD").is_none() {
        assert!(!required(), "ORCEL_MACOS_ORCELD must name the built orceld");
        eprintln!("MAC-M1-08 skipped: needs the real orceld");
        return;
    }
    let (home, root) = home_and_root("revoke");
    let workspace = home.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    let config = orcel_lifecycle::config::Config {
        workspaces: vec![orcel_lifecycle::config::WorkspaceEntry {
            id: "ci".into(),
            root: workspace,
        }],
        ..orcel_lifecycle::config::Config::default()
    };
    config.save(&Layout::new(&root)).unwrap();
    let platform = MacosPlatform::without_agent();
    let installer = Installer::new(Layout::new(&root), &platform);
    installer
        .install(&release("revoke"), &options(node))
        .expect("install");
    let state = installer.verify().expect("verify");
    let orceld = root
        .join("versions")
        .join(&state.active.version)
        .join("orceld");

    let request = orcel_lifecycle::ipc::request(
        "ci",
        "trust.revoke_emergency",
        "revoke",
        serde_json::json!({}),
    );
    let mut line = request.to_string();
    line.push('\n');
    let started = std::time::Instant::now();
    let mut child = std::process::Command::new(&orceld)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("ORCEL_WORKSPACES_JSON", config.workspaces_json())
        .env("ORCEL_DEFAULT_WORKSPACE", "ci")
        .env("CUA_ENV_SKIP_SENSITIVE_AUTH", "1")
        .env("CUA_ENV_ALLOW_UNVERIFIED_SENSITIVE_EXPORT", "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start the installed orceld");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(line.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let response: serde_json::Value =
        serde_json::from_str(stdout.lines().next().unwrap_or_default())
            .unwrap_or_else(|error| panic!("{error}: {stdout}"));
    assert_eq!(response["ok"], false, "{response}");
    let code = response["error"]["code"].as_str().unwrap_or("").to_owned();
    assert!(code.starts_with("APPROVAL_"), "{response}");

    let audit = fs::read_to_string(root.join("audit.jsonl")).expect("audit log");
    let lines: Vec<&str> = audit
        .lines()
        .filter(|line| line.contains("trust.revoke_emergency"))
        .collect();
    assert!(!lines.is_empty(), "{audit}");
    assert!(
        !lines.iter().any(|line| line.contains("\"SUCCESS\"")),
        "{audit}"
    );
    println!(
        "MAC-M1-08-EVIDENCE installed_orceld code={code} revoked=false audited={} bypass_env_ignored=true seconds={}",
        lines.len(),
        started.elapsed().as_secs()
    );
}
