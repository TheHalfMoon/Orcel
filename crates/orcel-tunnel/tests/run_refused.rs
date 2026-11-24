//! SG-000135 OB-09: `orcel-tunnel run` starts nothing, configured or not.

use std::process::Command;

#[test]
fn orcel_tunnel_run_starts_nothing_and_names_orcel_start() {
    let dir = std::env::temp_dir().join(format!("orcel-tunnel-run-{}", std::process::id()));
    let workspace = dir.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let key = dir.join("key");
    std::fs::write(&key, "sk-test").unwrap();
    let health = dir.join("health.url");
    // A complete configuration, whose client is this test's own binary: were
    // it started, it would fail on the arguments and not with this message.
    let own = std::env::current_exe().unwrap();
    let configured = [
        ("ORCEL_TUNNEL_CLIENT", own.clone()),
        ("ORCEL_TUNNEL_KEY_FILE", key),
        ("ORCEL_MCP_COMMAND", own),
        ("ORCEL_TUNNEL_HEALTH_URL_FILE", health),
        ("ORCEL_WORKSPACE_ROOT", workspace),
        (
            "ORCEL_TUNNEL_ID",
            "tunnel_0123456789abcdefghijklmnopqrstuv".into(),
        ),
    ];
    for with_configuration in [true, false] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_orcel-tunnel"));
        command.arg("run");
        for (name, value) in &configured {
            if with_configuration {
                command.env(name, value);
            } else {
                command.env_remove(name);
            }
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let said = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(said.contains("use `orcel start`"), "{said}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
