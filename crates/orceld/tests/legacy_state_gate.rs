//! The real `orceld` binary and state left at the earlier Windows root: it refuses to start until
//! a person has decided, and it doesn't touch that state. Windows only: no other layout moved.
#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const DECISION: &str = "orcel-legacy-state-decision-v1\nkept-separate\n";

struct Sandbox {
    base: PathBuf,
}

impl Sandbox {
    fn new(label: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "orceld-legacy-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(base.join("profile")).unwrap();
        fs::create_dir_all(base.join("local").join("Orcel")).unwrap();
        fs::create_dir_all(base.join("workspace")).unwrap();
        Self { base }
    }

    fn legacy(&self) -> PathBuf {
        self.base.join("local").join("Orcel")
    }

    fn root(&self) -> PathBuf {
        self.base.join("profile").join(".orcel")
    }

    /// Runs `orceld` with stdin closed, so one that starts exits again. Returns its success and
    /// its stderr.
    fn run(&self) -> (bool, String) {
        let output = Command::new(env!("CARGO_BIN_EXE_orceld"))
            .env_clear()
            .env("USERPROFILE", self.base.join("profile"))
            .env("LOCALAPPDATA", self.base.join("local"))
            .env("SystemRoot", std::env::var_os("SystemRoot").unwrap())
            .env("TEMP", self.base.join("workspace"))
            .env("TMP", self.base.join("workspace"))
            .env("ORCEL_WORKSPACE_ROOT", self.base.join("workspace"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("orceld runs");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.base);
    }
}

fn seed(legacy: &Path) {
    fs::create_dir_all(legacy.join("state")).unwrap();
    fs::write(legacy.join("trust.jsonl"), "trust").unwrap();
    fs::write(legacy.join("state").join("config.json"), "{}").unwrap();
}

#[test]
fn nothing_earlier_starts_and_creates_the_private_root() {
    let sandbox = Sandbox::new("empty");
    let (started, stderr) = sandbox.run();
    assert!(started, "{stderr}");
    assert!(stderr.contains("orceld ready"), "{stderr}");
    assert!(sandbox.root().is_dir());
}

#[test]
fn empty_folders_and_transient_runs_are_not_data() {
    let sandbox = Sandbox::new("transient");
    let runs = sandbox.legacy().join("contained-runs").join("old");
    fs::create_dir_all(&runs).unwrap();
    fs::write(runs.join("left"), "x").unwrap();
    fs::create_dir_all(sandbox.legacy().join("secrets")).unwrap();
    let (started, stderr) = sandbox.run();
    assert!(started, "{stderr}");
}

#[test]
fn undecided_data_refuses_before_anything_is_created() {
    let sandbox = Sandbox::new("undecided");
    seed(&sandbox.legacy());
    let (started, stderr) = sandbox.run();
    assert!(!started, "{stderr}");
    assert!(stderr.contains("nobody has decided"), "{stderr}");
    assert!(stderr.contains("orcel state migrate"), "{stderr}");
    assert!(
        !sandbox.root().exists(),
        "state was created before the gate"
    );
    assert_eq!(
        fs::read(sandbox.legacy().join("trust.jsonl")).unwrap(),
        b"trust"
    );
}

#[test]
fn a_decision_opens_the_gate_a_junk_one_does_not_and_restarts_hold() {
    let sandbox = Sandbox::new("decided");
    // A first start makes the private root the decision lives in.
    assert!(sandbox.run().0);
    let state = sandbox.root().join("state");
    fs::create_dir_all(&state).unwrap();
    seed(&sandbox.legacy());

    fs::write(state.join("legacy-state-decision.txt"), "junk").unwrap();
    let (started, stderr) = sandbox.run();
    assert!(!started, "{stderr}");
    assert!(stderr.contains("nobody has decided"), "{stderr}");

    fs::write(state.join("legacy-state-decision.txt"), DECISION).unwrap();
    for _ in 0..3 {
        let (started, stderr) = sandbox.run();
        assert!(started, "{stderr}");
    }
    assert_eq!(
        fs::read(sandbox.legacy().join("trust.jsonl")).unwrap(),
        b"trust"
    );
}
