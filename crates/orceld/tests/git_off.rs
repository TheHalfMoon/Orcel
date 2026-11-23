//! Founder decision of 2026-11-23: Git is off until it runs confined. A real
//! `orceld` refuses every Git operation, Safe and Full Control, with one
//! clear message: no child process starts, nothing is asked or journaled,
//! and the repository does not change. The requests are ones orceld would
//! otherwise act on (a real repository, its HEAD, configured destinations),
//! so the refusal is the switch and not the request's form.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const OFF: &str = "Git is off until it runs confined";

fn unique(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "orcel-git-off-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn private_dir(path: &Path) {
    std::fs::create_dir_all(path).expect("create dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }
}

/// Git for the test's own setup and checks.
fn git(cwd: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn files(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            files(&path, found);
        } else {
            found.push(path);
        }
    }
}

/// What the repository is: every file's bytes, its Git data included.
fn contents(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    files(dir, &mut found);
    found.sort();
    found
        .into_iter()
        .map(|path| {
            let bytes = std::fs::read(&path).expect("read");
            (path, bytes)
        })
        .collect()
}

/// Whether `child` ever started another process. Windows counts the
/// processes of a Job Object it is put in before its first request. On Unix a
/// `git` ahead of every other on its PATH leaves a mark.
#[cfg(windows)]
mod children {
    use super::Child;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;
    use std::process::Command;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectBasicAccountingInformation,
        QueryInformationJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    };

    pub struct Watch(Option<OwnedHandle>);

    impl Watch {
        pub fn prepare(_dir: &Path, _command: &mut Command) -> Self {
            Self(None)
        }

        pub fn started(&mut self, child: &Child) {
            // SAFETY: no attributes and no name; the result is checked.
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            assert!(job != 0, "job");
            // SAFETY: a live handle this function just made and owns.
            let job = unsafe { OwnedHandle::from_raw_handle(job as _) };
            // SAFETY: both handles are live for the call.
            let assigned = unsafe {
                AssignProcessToJobObject(job.as_raw_handle() as _, child.as_raw_handle() as _)
            };
            assert!(assigned != 0, "assign");
            self.0 = Some(job);
        }

        pub fn none_started(&self) {
            let job = self.0.as_ref().expect("watched");
            // SAFETY: an all-zero accounting structure is valid.
            let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
            // SAFETY: the buffer is the structure this class fills.
            let read = unsafe {
                QueryInformationJobObject(
                    job.as_raw_handle() as _,
                    JobObjectBasicAccountingInformation,
                    std::ptr::from_mut(&mut info).cast(),
                    std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    std::ptr::null_mut(),
                )
            };
            assert!(read != 0, "accounting");
            assert_eq!(info.TotalProcesses, 1, "orceld and nothing it started");
        }
    }
}

#[cfg(unix)]
mod children {
    use super::Child;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    pub struct Watch(PathBuf);

    impl Watch {
        pub fn prepare(dir: &Path, command: &mut Command) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let bin = dir.join("bin");
            super::private_dir(&bin);
            let mark = dir.join("git-started");
            let program = bin.join("git");
            std::fs::write(
                &program,
                format!("#!/bin/sh\necho started >> '{}'\n", mark.display()),
            )
            .expect("program");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755))
                .expect("chmod");
            // Positive control: the mark is left when it does start.
            assert!(Command::new(&program).status().expect("control").success());
            assert!(mark.exists(), "control");
            std::fs::remove_file(&mark).expect("control");
            let mut path = vec![bin];
            path.extend(std::env::split_paths(
                &std::env::var_os("PATH").expect("PATH"),
            ));
            command.env("PATH", std::env::join_paths(path).expect("PATH"));
            Self(mark)
        }

        pub fn started(&mut self, _child: &Child) {}

        pub fn none_started(&self) {
            assert!(!self.0.exists(), "Git was started");
        }
    }
}

fn request(id: &str, capability: &str, operation: &str, arguments: Value) -> Value {
    let target = if capability.starts_with("git.") {
        json!(".")
    } else {
        Value::Null
    };
    json!({
        "version": 1,
        "request_id": id,
        "client_session_id": "git-off",
        "workspace_id": "default",
        "capability": capability,
        "operation": operation,
        "target": target,
        "arguments": arguments,
    })
}

fn remote() -> Value {
    json!({
        "principal": "rp-182110eb5d85d5ccd3f34df5dba41e1a",
        "remoteConnectionId": "rc-8d11a8282860ff1df26aeee0949a7bf9",
        "connectionId": "tunnel-0123456789abcdef0123456789abcdef",
        "deviceId": "dev-0872269746857073deab118978d116a0",
        "deviceEpoch": 1,
        "providerKind": "openai",
        "clientProfileId": "chatgpt-secure-mcp-tunnel",
        "clientProfileRevision": 1,
        "toolSurfaceProfile": "core",
        "scopes": ["orcel.read", "orcel.write", "orcel.execute"],
    })
}

#[test]
fn a_real_orceld_refuses_every_git_operation_and_starts_and_asks_nothing() {
    let dir = unique("state");
    let state = dir.join("home");
    let workspace = dir.join("workspace");
    for path in [&dir, &state, &workspace] {
        private_dir(path);
    }
    git(&workspace, &["init", "-q", "-b", "main"]);
    git(&workspace, &["config", "user.name", "Orcel Test"]);
    git(
        &workspace,
        &["config", "user.email", "orcel@example.invalid"],
    );
    std::fs::write(workspace.join("a.txt"), "one\n").expect("a");
    git(&workspace, &["add", "a.txt"]);
    git(&workspace, &["commit", "-q", "-m", "initial"]);
    let head = git(&workspace, &["rev-parse", "HEAD"]);
    std::fs::write(workspace.join("a.txt"), "two\n").expect("a");
    let before = contents(&workspace);

    let repository = workspace.display().to_string();
    let safe = [
        ("git.status", "status", json!({})),
        ("git.diff", "diff", json!({"staged": false})),
        ("git.log", "log", json!({"max_count": 5})),
        (
            "git.branch.create",
            "create",
            json!({"expected_head": head, "branch": "topic"}),
        ),
        (
            "git.stage",
            "stage",
            json!({"expected_head": head, "paths": ["a.txt"]}),
        ),
        (
            "git.unstage",
            "unstage",
            json!({"expected_head": head, "paths": ["a.txt"]}),
        ),
        (
            "git.commit",
            "commit",
            json!({"expected_head": head, "message": "change"}),
        ),
        (
            "git.fetch.preview",
            "preview",
            json!({"policy_id": "origin", "branch": "main"}),
        ),
        (
            "git.fetch",
            "fetch",
            json!({"policy_id": "origin", "branch": "main", "expected_head": head, "expected_prior": "ABSENT"}),
        ),
        (
            "git.push.preview",
            "preview",
            json!({"policy_id": "origin", "source_branch": "main", "dest_branch": "main", "credential_reference": "anonymous"}),
        ),
        (
            "git.push",
            "push",
            json!({"policy_id": "origin", "source_branch": "main", "dest_branch": "main", "expected_head": head, "expected_prior": "ABSENT", "credential_reference": "anonymous"}),
        ),
    ];
    let full = [
        ("git_status", json!({"repository": repository})),
        (
            "git_diff",
            json!({"repository": repository, "staged": false}),
        ),
        ("git_log", json!({"repository": repository, "max_count": 5})),
        (
            "git_add",
            json!({"repository": repository, "paths": ["a.txt"]}),
        ),
        (
            "git_unstage",
            json!({"repository": repository, "paths": ["a.txt"]}),
        ),
        (
            "git_commit",
            json!({"repository": repository, "message": "change"}),
        ),
        (
            "git_branch_create",
            json!({"repository": repository, "branch": "topic"}),
        ),
    ];
    let mut requests = Vec::new();
    for (capability, operation, arguments) in &safe {
        requests.push(request(
            &format!("{capability}/{operation}"),
            capability,
            operation,
            arguments.clone(),
        ));
        // A remote caller is told the same, before any lease is looked for.
        let mut from_remote = request(
            &format!("remote {capability}/{operation}"),
            capability,
            operation,
            arguments.clone(),
        );
        from_remote["remote"] = remote();
        requests.push(from_remote);
    }
    for (operation, fields) in &full {
        let mut arguments = fields.clone();
        arguments["op"] = json!(operation);
        requests.push(request(
            &format!("fc.git/{operation}"),
            "fc.git",
            operation,
            arguments,
        ));
    }
    assert_eq!(requests.len(), 2 * 11 + 7);

    let destination = json!([{
        "workspace_id": "default",
        "id": "origin",
        "url": "https://example.com/repo.git",
        "credential_reference": "anonymous",
    }])
    .to_string();
    let mut command = Command::new(env!("CARGO_BIN_EXE_orceld"));
    command
        .env("ORCEL_WORKSPACE_ROOT", &workspace)
        .env("ORCEL_WORKSPACE_ID", "default")
        .env("ORCEL_APP_API", "off")
        .env("ORCEL_AUDIT_PATH", state.join("audit").join("audit.jsonl"))
        .env("ORCEL_GIT_FETCH_DESTINATIONS_JSON", &destination)
        .env("ORCEL_GIT_PUSH_DESTINATIONS_JSON", &destination)
        // Names a switch might have had: nothing in the environment is one.
        .env("ORCEL_GIT_CONFINED", "1")
        .env("ORCEL_GIT_ENABLED", "1")
        .env("PROCESS_CONFINED", "1")
        .env_remove("ORCEL_WORKSPACES_JSON")
        .env_remove("ORCEL_APPROVAL_HISTORY_PATH")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if cfg!(windows) {
        command.env("USERPROFILE", &state);
    } else if cfg!(target_os = "linux") {
        command.env("XDG_STATE_HOME", &state);
    } else {
        command.env("HOME", &state);
    }
    let mut watch = children::Watch::prepare(&dir, &mut command);
    let mut child = command.spawn().expect("spawn orceld");
    watch.started(&child);
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut stderr = child.stderr.take().expect("stderr");
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let (send, replies) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    // One at a time, each answered at once: a prompt would wait for a person.
    for request in &requests {
        writeln!(stdin, "{request}").expect("write request");
        let Ok(line) = replies.recv_timeout(Duration::from_secs(60)) else {
            let _ = child.kill();
            let _ = child.wait();
            unreachable!(
                "no answer to {}: {}",
                request["request_id"],
                errors.join().unwrap_or_default()
            );
        };
        let response: Value = serde_json::from_str(&line).expect("response json");
        assert_eq!(response["request_id"], request["request_id"]);
        assert_eq!(response["ok"], false, "{response}");
        assert_eq!(
            response["error"]["code"], "PROVIDER_UNAVAILABLE",
            "{response}"
        );
        assert_eq!(response["error"]["message"], OFF, "{response}");
    }
    drop(stdin);
    child.wait().expect("wait");
    watch.none_started();

    assert_eq!(contents(&workspace), before, "the repository is unchanged");
    // Nothing was asked and nothing was journaled: orceld records a prompt's
    // decision in the approval history and a change in the mutation journal.
    let mut kept = Vec::new();
    files(&state, &mut kept);
    assert!(
        kept.iter().any(|path| path.ends_with("audit.jsonl")),
        "{kept:?}"
    );
    for path in &kept {
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let text = String::from_utf8_lossy(&std::fs::read(path).expect("read")).into_owned();
        assert!(
            !name.contains("approval-history") || text.trim().is_empty(),
            "{name}: {text}"
        );
        assert!(
            !name.contains("mutation") || !text.contains("git."),
            "{name}: {text}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
