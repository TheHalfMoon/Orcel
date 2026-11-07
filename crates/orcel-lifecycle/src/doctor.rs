//! `orcel doctor`: inspects real installation, configuration, runtime, and
//! state. Every check reports what was actually observed; a check that could
//! not run is `unknown`, never `pass`. Doctor does not change configuration,
//! approvals, or trust. Its IPC probe is an ordinary read-only
//! `system.status/get` request and is recorded in the audit log like any
//! other request.

use crate::config::{self, Config};
use crate::install::Installer;
use crate::layout::{InstallRecord, Layout};
use crate::platform::{Platform, MIN_NODE_MAJOR, MIN_WINDOWS_BUILD};
use serde::Serialize;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: &'static str,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub healthy: bool,
    pub checks: Vec<Check>,
}

fn check(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Check {
    Check {
        name,
        status,
        detail: detail.into(),
    }
}

/// Checks that every line of a JSONL state file parses. This is a parse
/// check only; checksum chains are verified by `orceld` when it loads them.
fn jsonl_parses(path: &Path) -> Result<usize, String> {
    let text = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    let mut count = 0;
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        serde_json::from_str::<serde_json::Value>(line)
            .map_err(|error| format!("line {}: {error}", index + 1))?;
        count += 1;
    }
    Ok(count)
}

/// Verifies the approval ledger's whole hash chain, not just its JSON syntax.
/// Whether earlier state is waiting on a person's decision, which stops `orceld` from starting.
fn legacy_state(layout: &Layout) -> Check {
    use orcel_platform::legacy::{examine, legacy_root_from, LegacyState};
    let Some(legacy) = legacy_root_from(&|name| std::env::var_os(name)) else {
        return check(
            "legacy_state",
            CheckStatus::Pass,
            "no earlier state location",
        );
    };
    match examine(&legacy, &layout.root) {
        LegacyState::None => check("legacy_state", CheckStatus::Pass, "no earlier state to decide on"),
        LegacyState::Decided(decision) => {
            check("legacy_state", CheckStatus::Pass, format!("decided: {decision}"))
        }
        LegacyState::Undecided(_) => check(
            "legacy_state",
            CheckStatus::Fail,
            format!(
                "earlier state is at {}, undecided, so orceld won't start; run `orcel state status`",
                legacy.display()
            ),
        ),
        LegacyState::Unreadable(path, error) => check(
            "legacy_state",
            CheckStatus::Fail,
            format!("{} can't be read: {error}; run `orcel state status`", path.display()),
        ),
    }
}

fn approval_history(path: &Path) -> Check {
    use orcel_approval::ApprovalLedgerStatus;
    let inspection = orcel_approval::inspect_approval_ledger(path);
    match inspection.status {
        ApprovalLedgerStatus::Missing => {
            check("approval_history", CheckStatus::Pass, "no records yet")
        }
        ApprovalLedgerStatus::Verified => check(
            "approval_history",
            CheckStatus::Pass,
            format!("{} record(s) verify", inspection.verified_records),
        ),
        ApprovalLedgerStatus::Corrupt => check(
            "approval_history",
            CheckStatus::Fail,
            format!("approvals are blocked: {}", inspection.detail),
        ),
        ApprovalLedgerStatus::Busy => check(
            "approval_history",
            CheckStatus::Warn,
            "another Orcel process held the approval ledger; rerun doctor",
        ),
        ApprovalLedgerStatus::Unreadable => check(
            "approval_history",
            CheckStatus::Fail,
            format!("the approval ledger cannot be read: {}", inspection.detail),
        ),
    }
}

/// Runs every check with the approval ledger at its layout-relative path
/// (tests only; the CLI passes the brokers' ledger path).
#[cfg(test)]
pub fn run(layout: &Layout, platform: &dyn Platform) -> DoctorReport {
    run_with_approval_history(
        layout,
        platform,
        &layout.root.join("approval-history.jsonl"),
    )
}

/// Runs every check, verifying the approval ledger at `approval_path` (the
/// CLI passes the brokers' `default_approval_history_path`).
pub fn run_with_approval_history(
    layout: &Layout,
    platform: &dyn Platform,
    approval_path: &Path,
) -> DoctorReport {
    let mut checks = Vec::new();

    checks.push(match platform.windows_build() {
        Ok(build) if build >= MIN_WINDOWS_BUILD => check(
            "platform",
            CheckStatus::Pass,
            format!("Windows build {build}"),
        ),
        Ok(build) => check(
            "platform",
            CheckStatus::Fail,
            format!("Windows build {build} is older than {MIN_WINDOWS_BUILD}"),
        ),
        Err(error) => check("platform", CheckStatus::Fail, error.message),
    });
    checks.push(match platform.is_avoidably_elevated() {
        Ok(false) => check("elevation", CheckStatus::Pass, "no avoidable elevation"),
        Ok(true) => check(
            "elevation",
            CheckStatus::Fail,
            "running elevated from a split-token administrator; use a normal prompt",
        ),
        Err(error) => check("elevation", CheckStatus::Unknown, error.message),
    });

    let installed = Installer::new(layout.clone(), platform).verify();
    let active_version = match &installed {
        Ok(state) => {
            checks.push(check(
                "install_integrity",
                CheckStatus::Pass,
                format!(
                    "Orcel {} verified: pointer, {} payload files, CLI copy, owner-only ACL",
                    state.active.version,
                    state.manifest.files.len()
                ),
            ));
            Some(state.active.version.clone())
        }
        Err(error) => {
            checks.push(check(
                "install_integrity",
                CheckStatus::Fail,
                error.message.clone(),
            ));
            None
        }
    };
    let cli = env!("CARGO_PKG_VERSION");
    checks.push(match &active_version {
        Some(active) if active == cli => check(
            "version_consistency",
            CheckStatus::Pass,
            format!("CLI {cli}"),
        ),
        Some(active) => check(
            "version_consistency",
            CheckStatus::Warn,
            format!("this orcel CLI is {cli} but the installed version is {active}"),
        ),
        None => check("version_consistency", CheckStatus::Unknown, "not installed"),
    });

    let record: Option<InstallRecord> = crate::layout::read_install(layout).ok().flatten();
    checks.push(match &record {
        Some(record) => match platform.node_version(Path::new(&record.node_path)) {
            Ok(version) if version.major >= MIN_NODE_MAJOR => check(
                "node_runtime",
                CheckStatus::Pass,
                format!("Node.js {version} at {}", record.node_path),
            ),
            Ok(version) => check(
                "node_runtime",
                CheckStatus::Fail,
                format!("Node.js {version} is older than {MIN_NODE_MAJOR}"),
            ),
            Err(error) => check("node_runtime", CheckStatus::Fail, error.message),
        },
        None => check("node_runtime", CheckStatus::Unknown, "no install record"),
    });

    let config = Config::load(layout);
    let workspaces_ok = match &config {
        Ok(config) => match config.check_workspaces_with_policy() {
            Ok(()) => {
                checks.push(check(
                    "workspaces",
                    CheckStatus::Pass,
                    format!(
                        "{} workspace(s) admitted by the policy kernel",
                        config.workspaces.len()
                    ),
                ));
                true
            }
            Err(error) => {
                checks.push(check("workspaces", CheckStatus::Fail, error.message));
                false
            }
        },
        Err(error) => {
            checks.push(check(
                "configuration",
                CheckStatus::Fail,
                error.message.clone(),
            ));
            false
        }
    };

    checks.push(match (&config, &active_version) {
        (Ok(config), Some(version)) => match config::tunnel_config(layout, config, version) {
            Ok(tunnel) => check(
                "tunnel_configuration",
                CheckStatus::Pass,
                format!(
                    "tunnel {} with client {}; runtime key supplied by file reference",
                    tunnel.tunnel_id,
                    tunnel.tunnel_client.display()
                ),
            ),
            Err(error) => check("tunnel_configuration", CheckStatus::Fail, error.message),
        },
        _ => check(
            "tunnel_configuration",
            CheckStatus::Unknown,
            "requires a verified install and a readable configuration",
        ),
    });

    match crate::lifecycle::status(layout) {
        Ok(status) => {
            let (process, health) = match status.state {
                crate::lifecycle::RunState::Running => (CheckStatus::Pass, CheckStatus::Pass),
                crate::lifecycle::RunState::Degraded => (CheckStatus::Warn, CheckStatus::Warn),
                crate::lifecycle::RunState::NotRunning => (CheckStatus::Warn, CheckStatus::Unknown),
            };
            checks.push(check("process_health", process, status.detail.clone()));
            checks.push(check(
                "tunnel_health",
                health,
                match (&status.health_url, status.health_status) {
                    (Some(url), Some(code)) => format!("{url} answered {code}"),
                    (Some(url), None) => format!("{url} did not answer"),
                    _ => "no health URL published".into(),
                },
            ));
            if let Some(last) = status.last_exit {
                checks.push(check(
                    "last_exit",
                    CheckStatus::Warn,
                    format!("{} (exit code {:?})", last.reason, last.exit_code),
                ));
            }
        }
        Err(error) => checks.push(check("process_health", CheckStatus::Unknown, error.message)),
    }

    checks.push(match (&config, &active_version, workspaces_ok) {
        (Ok(config), Some(version), true) => {
            let orceld = layout.version_dir(version).join("orceld.exe");
            let workspace = config.default_workspace().unwrap_or("default").to_string();
            let request =
                crate::ipc::request(&workspace, "system.status", "get", serde_json::json!({}));
            match crate::ipc::call(&orceld, config, &request, Duration::from_secs(20)) {
                Ok(response) => match crate::ipc::expect_ok(&response) {
                    Ok(result) if result.get("name").and_then(|v| v.as_str()) == Some("orceld") => {
                        check(
                            "ipc",
                            CheckStatus::Pass,
                            format!(
                                "orceld {} answered system.status",
                                result
                                    .get("version")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("?")
                            ),
                        )
                    }
                    Ok(_) => check("ipc", CheckStatus::Fail, "unexpected system.status result"),
                    Err(error) => check("ipc", CheckStatus::Fail, error.message),
                },
                Err(error) => check("ipc", CheckStatus::Fail, error.message),
            }
        }
        _ => check(
            "ipc",
            CheckStatus::Unknown,
            "requires a verified install and admitted workspaces",
        ),
    });

    checks.push(approval_surface());

    // The supervised runtime and every orceld probe receive the sanitized
    // environment, which drops state-path overrides, so the runtime always
    // uses the default files inspected below.
    let overrides = orcel_policy::protected_state::PROTECTED_STATE_OVERRIDES
        .iter()
        .filter(|name| std::env::var_os(name).is_some())
        .copied()
        .collect::<Vec<_>>();
    checks.push(if overrides.is_empty() {
        check("state_locations", CheckStatus::Pass, "default Orcel state files")
    } else {
        check(
            "state_locations",
            CheckStatus::Warn,
            format!(
                "{} set in this shell; the supervised runtime does not receive these overrides and uses the default files checked below",
                overrides.join(", ")
            ),
        )
    });

    checks.push(legacy_state(layout));
    checks.push(approval_history(approval_path));
    for (name, file) in [("trust_state", "trust.jsonl"), ("audit_log", "audit.jsonl")] {
        let path = layout.root.join(file);
        checks.push(if !path.exists() {
            check(name, CheckStatus::Pass, "no records yet")
        } else {
            match jsonl_parses(&path) {
                Ok(count) => check(name, CheckStatus::Pass, format!("{count} record(s) parse")),
                Err(error) => check(name, CheckStatus::Fail, error),
            }
        });
    }

    checks.push(match crate::update::read_marker(layout) {
        Ok(None) => check("update_state", CheckStatus::Pass, "no pending or failed update"),
        Ok(Some(marker)) => match marker.state {
            crate::update::UpdateState::Pending => check(
                "update_state",
                CheckStatus::Fail,
                format!(
                    "an update from {} to {} was interrupted; the active version is verified above; run `orcel rollback` or repeat `orcel update`",
                    marker.from, marker.to
                ),
            ),
            crate::update::UpdateState::Failed => check(
                "update_state",
                CheckStatus::Warn,
                format!(
                    "the update from {} to {} failed and {} was restored: {}",
                    marker.from,
                    marker.to,
                    marker.from,
                    marker.reason.unwrap_or_default()
                ),
            ),
        },
        Err(error) => check("update_state", CheckStatus::Fail, error.message),
    });

    checks.push(match &record {
        Some(record) => match &record.previous {
            Some(previous) if layout.version_dir(previous).is_dir() => check(
                "recovery",
                CheckStatus::Pass,
                format!("previous version {previous} retained for rollback"),
            ),
            Some(previous) => check(
                "recovery",
                CheckStatus::Warn,
                format!("previous version {previous} is recorded but missing"),
            ),
            None => check(
                "recovery",
                CheckStatus::Pass,
                "no previous version recorded",
            ),
        },
        None => check("recovery", CheckStatus::Unknown, "no install record"),
    });

    // SG-000070 client integration readiness. These checks only read state:
    // they never print credentials, tokens, or keys, and never change
    // configuration, trust, or remote authority.
    checks.push(match crate::mcp::resolve_stdio_launch(layout, platform) {
        Ok((launch, _)) if launch.script.is_file() && launch.orceld.is_file() => check(
            "mcp_stdio_entrypoint",
            CheckStatus::Pass,
            "`orcel mcp stdio` resolves to the verified MCP server and orceld for local clients (Claude, Codex, Vibe Code, generic MCP)",
        ),
        Ok(_) => check(
            "mcp_stdio_entrypoint",
            CheckStatus::Fail,
            "the verified install is missing the MCP server or orceld",
        ),
        Err(error) => check("mcp_stdio_entrypoint", CheckStatus::Fail, error.message),
    });
    checks.push(remote_integration_check(layout));

    let retained = layout
        .retained_data()
        .into_iter()
        .filter(|path| path.exists())
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    checks.push(check(
        "retained_data",
        CheckStatus::Pass,
        if retained.is_empty() {
            "none".to_string()
        } else {
            retained.join("; ")
        },
    ));

    DoctorReport {
        healthy: !checks.iter().any(|check| check.status == CheckStatus::Fail),
        checks,
    }
}

/// Reports whether remote access is enabled and paired, naming only the
/// relay origin. It never reads or prints the device key or any token.
fn remote_integration_check(layout: &Layout) -> Check {
    let uplink = crate::remote::uplink_config_path(layout);
    if !uplink.exists() {
        return check(
            "remote_integration",
            CheckStatus::Pass,
            "remote access is not enabled; only local clients can connect",
        );
    }
    let parsed = std::fs::read(&uplink)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    match parsed {
        Some(record) => {
            let origin = record
                .get("relayOrigin")
                .and_then(serde_json::Value::as_str)
                .filter(|origin| {
                    origin.starts_with("https://") || origin.starts_with("http://127.0.0.1:")
                })
                .unwrap_or("an unrecognized relay");
            let paired = record
                .get("connections")
                .and_then(serde_json::Value::as_array)
                .map(|connections| !connections.is_empty())
                .unwrap_or(false);
            check(
                "remote_integration",
                if paired {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Warn
                },
                if paired {
                    format!("remote access is paired with {origin}; every remote call still needs a local remote-session lease")
                } else {
                    format!("remote access is enabled for {origin} but no connection is paired yet")
                },
            )
        }
        None => check(
            "remote_integration",
            CheckStatus::Fail,
            "the remote uplink record is unreadable; re-enable remote access",
        ),
    }
}

#[cfg(windows)]
fn approval_surface() -> Check {
    // Only presence availability is queried; the real approval ledger is not
    // loaded.
    let broker = orcel_approval::LocalApprovalBroker::with_path(
        std::env::temp_dir().join(format!("orcel-doctor-{}.jsonl", crate::nonce())),
    );
    if broker.presence_available() {
        check(
            "approval_surface",
            CheckStatus::Pass,
            format!(
                "SOFT prompts use the interactive desktop; STRONG presence via {} is available",
                broker.presence_method()
            ),
        )
    } else {
        check(
            "approval_surface",
            CheckStatus::Warn,
            format!(
                "STRONG presence via {} is unavailable; STRONG-class operations will fail closed",
                broker.presence_method()
            ),
        )
    }
}

#[cfg(not(windows))]
fn approval_surface() -> Check {
    check(
        "approval_surface",
        CheckStatus::Unknown,
        "the approval surface is available on Windows only",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{temp_dir, FakePlatform};

    #[test]
    fn remote_integration_reports_state_without_secrets() {
        let layout = Layout::new(temp_dir("doctor-remote"));
        let absent = remote_integration_check(&layout);
        assert_eq!(absent.status, CheckStatus::Pass);
        assert!(absent.detail.contains("not enabled"));

        let path = crate::remote::uplink_config_path(&layout);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let secret = "PRIVATE-KEY-MATERIAL-MUST-NOT-PRINT";
        std::fs::write(
            &path,
            format!(
                r#"{{"relayOrigin":"https://relay.example.com","identity":{{}},"privateKeyJwkBase64":"{secret}","connections":[]}}"#
            ),
        )
        .unwrap();
        let unpaired = remote_integration_check(&layout);
        assert_eq!(unpaired.status, CheckStatus::Warn);
        assert!(unpaired.detail.contains("https://relay.example.com"));
        assert!(!unpaired.detail.contains(secret));

        std::fs::write(
            &path,
            format!(
                r#"{{"relayOrigin":"https://relay.example.com","identity":{{}},"privateKeyJwkBase64":"{secret}","connections":[{{"remoteConnectionId":"rc"}}]}}"#
            ),
        )
        .unwrap();
        let paired = remote_integration_check(&layout);
        assert_eq!(paired.status, CheckStatus::Pass);
        assert!(paired.detail.contains("remote-session lease"));
        assert!(!paired.detail.contains(secret));

        std::fs::write(
            &path,
            format!(r#"{{"relayOrigin":"javascript:{secret}","connections":[1]}}"#),
        )
        .unwrap();
        let odd = remote_integration_check(&layout);
        assert!(odd.detail.contains("an unrecognized relay"));
        assert!(!odd.detail.contains(secret));

        std::fs::write(&path, b"not json").unwrap();
        assert_eq!(remote_integration_check(&layout).status, CheckStatus::Fail);
    }

    #[test]
    fn uninstalled_root_fails_integrity_without_claiming_health() {
        let layout = Layout::new(temp_dir("doctor").join("Orcel"));
        let report = run(&layout, &FakePlatform::default());
        assert!(!report.healthy);
        let integrity = report
            .checks
            .iter()
            .find(|check| check.name == "install_integrity")
            .unwrap();
        assert_eq!(integrity.status, CheckStatus::Fail);
        let ipc = report
            .checks
            .iter()
            .find(|check| check.name == "ipc")
            .unwrap();
        assert_eq!(ipc.status, CheckStatus::Unknown);
        assert!(!report
            .checks
            .iter()
            .any(|check| check.name == "ipc" && check.status == CheckStatus::Pass));
    }

    #[test]
    fn approval_history_check_verifies_the_chain_not_just_json() {
        let layout = Layout::new(temp_dir("doctor-approvals").join("Orcel"));
        let path = layout.root.join("approval-history.jsonl");
        assert_eq!(approval_history(&path).status, CheckStatus::Pass);
        std::fs::create_dir_all(&layout.root).unwrap();
        // Well-formed JSON that is not a verifiable approval chain.
        std::fs::write(&path, b"{\"schema\":\"orcel-approval-ledger-v3\"}\n").unwrap();
        let corrupt = approval_history(&path);
        assert_eq!(corrupt.status, CheckStatus::Fail);
        assert!(corrupt.detail.contains("orcel approvals recover"));
    }

    #[test]
    fn corrupt_state_files_fail() {
        let layout = Layout::new(temp_dir("doctor-state").join("Orcel"));
        std::fs::create_dir_all(&layout.root).unwrap();
        std::fs::write(layout.root.join("trust.jsonl"), b"{\"a\":1}\nnot-json\n").unwrap();
        let report = run(&layout, &FakePlatform::default());
        let trust = report
            .checks
            .iter()
            .find(|check| check.name == "trust_state")
            .unwrap();
        assert_eq!(trust.status, CheckStatus::Fail);
        assert!(trust.detail.contains("line 2"));
    }
}
