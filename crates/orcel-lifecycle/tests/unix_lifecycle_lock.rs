//! The real `orcel` takes the lifecycle lock on Linux and macOS: a command
//! that changes state waits for the one that holds it.
#![cfg(unix)]

use orcel_lifecycle::layout::Layout;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn a_state_changing_command_waits_for_the_lock() {
    let home = std::env::temp_dir().join(format!("orcel-lifecycle-lock-{}", std::process::id()));
    let workspace = home.join("workspace");
    fs::create_dir_all(&workspace).unwrap();
    fs::set_permissions(&home, fs::Permissions::from_mode(0o755)).unwrap();
    let layout = Layout::from_lookup(&|name| (name == "HOME").then(|| home.clone().into()))
        .expect("the state root under this HOME");
    let lock = orcel_lifecycle::lifecycle::lock(&layout).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_orcel"))
        .args(["workspace", "add", "ci"])
        .arg(&workspace)
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_secs(2));
    let early = command.try_wait().unwrap();
    let saved_early = layout.config_file().exists();
    drop(lock);
    let deadline = Instant::now() + Duration::from_secs(30);
    while command.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = command.kill();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = command.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(early.is_none(), "it did not wait: {early:?} {stderr}");
    assert!(!saved_early, "it changed the configuration while waiting");
    assert!(output.status.success(), "{:?} {stderr}", output.status);
    assert!(layout.config_file().is_file());
    let _ = fs::remove_dir_all(&home);
}
