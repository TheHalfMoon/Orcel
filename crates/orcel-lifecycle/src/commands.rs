//! Runtime, configuration, and trust commands of the `orcel` CLI.

use crate::{Args, Output};
use orcel_lifecycle::config::{self, Config};
use orcel_lifecycle::doctor::{self, CheckStatus};
use orcel_lifecycle::install::Installer;
use orcel_lifecycle::layout::Layout;
use orcel_lifecycle::lifecycle::{self, RunState, StopOutcome};
use orcel_lifecycle::{host_platform, ipc, LifecycleError};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

const RESTART_HINT: &str =
    "Restart Orcel (`orcel stop` then `orcel start`) for running sessions to pick up the change.\n";

fn active_version(layout: &Layout) -> Result<String, LifecycleError> {
    let platform = host_platform();
    Ok(Installer::new(layout.clone(), platform.as_ref())
        .verify()?
        .active
        .version)
}

pub fn workspace(args: &mut Args) -> Result<Output, LifecycleError> {
    let layout = Layout::for_current_user()?;
    let action = args.positional("workspace action (add, remove, list, trust, untrust)")?;
    match action.as_str() {
        "add" => {
            let id = args.positional("workspace id")?;
            let dir = PathBuf::from(args.positional("workspace directory")?);
            args.finish()?;
            let mut config = Config::load(&layout)?;
            let entry = config.add_workspace(&id, &dir)?;
            config.save(&layout)?;
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Workspace {} added: {}\nIt is not trusted for STRONG-gated operations until `orcel workspace trust {}`.\n{RESTART_HINT}",
                    entry.id,
                    entry.root.display(),
                    entry.id
                ),
                json: json!({"ok": true, "workspace": entry}),
            })
        }
        "remove" => {
            let id = args.positional("workspace id")?;
            args.finish()?;
            let mut config = Config::load(&layout)?;
            let entry = config.remove_workspace(&id)?;
            config.save(&layout)?;
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Workspace {} removed from configuration. Files in {} were not touched.\n{RESTART_HINT}",
                    entry.id,
                    entry.root.display()
                ),
                json: json!({"ok": true, "removed": entry}),
            })
        }
        "list" => {
            args.finish()?;
            let config = Config::load(&layout)?;
            let version = active_version(&layout).ok();
            let mut rows = Vec::new();
            let mut human = String::new();
            for entry in &config.workspaces {
                let trust = version.as_ref().and_then(|version| {
                    let orceld = layout.version_dir(version).join("orceld.exe");
                    let request = ipc::request(&entry.id, "workspace.trust.get", "get", json!({}));
                    ipc::call(&orceld, &config, &request, Duration::from_secs(20))
                        .ok()
                        .and_then(|response| ipc::expect_ok(&response).ok().cloned())
                });
                let trusted = trust
                    .as_ref()
                    .and_then(|trust| trust.get("trusted"))
                    .and_then(Value::as_bool);
                human.push_str(&format!(
                    "{:<20} {:<9} {}\n",
                    entry.id,
                    match trusted {
                        Some(true) => "trusted",
                        Some(false) => "untrusted",
                        None => "unknown",
                    },
                    entry.root.display()
                ));
                rows.push(json!({"id": entry.id, "root": entry.root, "trust": trust}));
            }
            if rows.is_empty() {
                human.push_str("No workspaces configured. Add one with `orcel workspace add <id> <directory>`.\n");
            }
            Ok(Output {
                exit_code: 0,
                human,
                json: json!({"ok": true, "workspaces": rows}),
            })
        }
        "trust" | "untrust" => {
            let id = args.positional("workspace id")?;
            args.finish()?;
            let config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            if !config
                .workspaces
                .iter()
                .any(|entry| entry.id.eq_ignore_ascii_case(&id))
            {
                return Err(LifecycleError::usage(format!(
                    "workspace {id} is not configured"
                )));
            }
            let version = active_version(&layout)?;
            let orceld = layout.version_dir(&version).join("orceld.exe");
            let (capability, operation) = if action == "trust" {
                ("workspace.trust.grant", "grant")
            } else {
                ("workspace.trust.revoke", "revoke")
            };
            eprintln!("Confirm with Windows Hello when prompted. This is a STRONG approval and cannot be granted by an agent.");
            let configured = config
                .workspaces
                .iter()
                .find(|entry| entry.id.eq_ignore_ascii_case(&id))
                .map(|entry| entry.id.clone())
                .unwrap_or(id);
            let request = ipc::request(&configured, capability, operation, json!({}));
            let response = ipc::call(&orceld, &config, &request, Duration::from_secs(180))?;
            let result = ipc::expect_ok(&response)?.clone();
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Workspace {configured} is now {} (trust revision {}).\n",
                    if result.get("trusted").and_then(Value::as_bool) == Some(true) {
                        "trusted"
                    } else {
                        "untrusted"
                    },
                    result
                        .get("revision")
                        .and_then(Value::as_u64)
                        .unwrap_or_default()
                ),
                json: json!({"ok": true, "trust": result}),
            })
        }
        other => Err(LifecycleError::usage(format!(
            "unknown workspace action {other:?}; run `orcel help`"
        ))),
    }
}

pub fn tunnel(args: &mut Args) -> Result<Output, LifecycleError> {
    let layout = Layout::for_current_user()?;
    let action = args.positional("tunnel action (setup, show)")?;
    match action.as_str() {
        "setup" => {
            let client = PathBuf::from(args.value("--client")?.ok_or_else(|| {
                LifecycleError::usage("--client <tunnel-client.exe> is required")
            })?);
            let tunnel_id = args
                .value("--tunnel-id")?
                .ok_or_else(|| LifecycleError::usage("--tunnel-id <tunnel_...> is required"))?;
            let key_file = args.value("--key-file")?.map(PathBuf::from);
            args.finish()?;
            config::validate_tunnel_id(&tunnel_id)?;
            if !client.is_absolute() || !client.is_file() {
                return Err(LifecycleError::usage(
                    "--client must be the absolute path of the official tunnel-client executable",
                ));
            }
            let version = active_version(&layout)?;
            let mut config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            let key = match &key_file {
                Some(path) => std::fs::read_to_string(path)
                    .map_err(|error| LifecycleError::io("read --key-file", error))?
                    .trim()
                    .to_string(),
                None => orcel_lifecycle::console::read_secret_line(
                    "Tunnel runtime key (input hidden): ",
                )?,
            };
            config::validate_runtime_key(&key)?;
            let previous = config.clone();
            config.tunnel = Some(config::TunnelSettings {
                client: client.clone(),
                tunnel_id: tunnel_id.clone(),
            });
            // Key and configuration change together: any failure after the key
            // is written restores both the previous key and configuration.
            let previous_key = std::fs::read(layout.runtime_key_file()).ok();
            config::store_runtime_key(&layout, &key)?;
            drop(key);
            let platform = host_platform();
            let committed = config::tunnel_config(&layout, &config, &version)
                .and_then(|_| config.save(&layout))
                .and_then(|()| platform.verify_tree_acl(&layout.root));
            if let Err(error) = committed {
                let restored_key = match previous_key {
                    Some(bytes) => orcel_lifecycle::layout::write_bytes_atomic(
                        &layout.runtime_key_file(),
                        &bytes,
                    ),
                    None => std::fs::remove_file(layout.runtime_key_file())
                        .or_else(|error| match error.kind() {
                            std::io::ErrorKind::NotFound => Ok(()),
                            _ => Err(error),
                        })
                        .map_err(|error| LifecycleError::io("remove new runtime key", error)),
                };
                let restored_config = previous.save(&layout);
                return Err(match (restored_key, restored_config) {
                    (Ok(()), Ok(())) => error,
                    _ => LifecycleError::state(format!(
                        "tunnel setup failed ({}) and the previous key or configuration could not be fully restored; rerun `orcel tunnel setup`",
                        error.message
                    )),
                });
            }
            let mut human = format!(
                "Tunnel {tunnel_id} configured with client {}.\nThe runtime key is stored in {} (owner-only) and is passed to the tunnel client by file reference only.\n",
                client.display(),
                layout.runtime_key_file().display()
            );
            if let Some(path) = &key_file {
                human.push_str(&format!(
                    "You may now delete the key file you supplied: {}\n",
                    path.display()
                ));
            }
            human.push_str("Next: `orcel start`, then `orcel status` or `orcel doctor`.\n");
            Ok(Output {
                exit_code: 0,
                human,
                json: json!({"ok": true, "tunnel_id": tunnel_id, "client": client, "key_file": layout.runtime_key_file()}),
            })
        }
        "show" => {
            args.finish()?;
            let config = Config::load(&layout)?;
            let key_present = std::fs::metadata(layout.runtime_key_file())
                .map(|metadata| metadata.len() > 0)
                .unwrap_or(false);
            let human = match &config.tunnel {
                Some(tunnel) => format!(
                    "tunnel id: {}\nclient: {}\nruntime key: {} (value never displayed)\n",
                    tunnel.tunnel_id,
                    tunnel.client.display(),
                    if key_present { "present" } else { "missing" }
                ),
                None => "The tunnel is not configured. Run `orcel tunnel setup`.\n".into(),
            };
            Ok(Output {
                exit_code: 0,
                human,
                json: json!({"ok": true, "tunnel": config.tunnel, "runtime_key_present": key_present}),
            })
        }
        other => Err(LifecycleError::usage(format!(
            "unknown tunnel action {other:?}; run `orcel help`"
        ))),
    }
}

fn wait_seconds(args: &mut Args, default: u64) -> Result<Duration, LifecycleError> {
    match args.value("--wait")? {
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|seconds| (1..=600).contains(seconds))
            .map(Duration::from_secs)
            .ok_or_else(|| LifecycleError::usage("--wait takes 1-600 seconds")),
        None => Ok(Duration::from_secs(default)),
    }
}

fn describe(status: &lifecycle::RuntimeStatus) -> String {
    let state = match status.state {
        RunState::Running => "running",
        RunState::Degraded => "degraded",
        RunState::NotRunning => "not running",
    };
    let mut text = format!("Orcel is {state}: {}\n", status.detail);
    if let Some(pid) = status.supervisor_pid {
        text.push_str(&format!("  supervisor pid: {pid}\n"));
    }
    if let Some(pid) = status.tunnel_client_pid {
        text.push_str(&format!("  tunnel client pid: {pid}\n"));
    }
    if let Some(url) = &status.health_url {
        text.push_str(&format!("  health URL: {url}\n"));
    }
    if let Some(last) = &status.last_exit {
        text.push_str(&format!(
            "  last exit: {} (exit code {:?})\n",
            last.reason, last.exit_code
        ));
    }
    text
}

pub fn start(args: &mut Args) -> Result<Output, LifecycleError> {
    let wait = wait_seconds(args, 20)?;
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    let status = lifecycle::start(&layout, platform.as_ref(), wait)?;
    Ok(Output {
        exit_code: 0,
        human: describe(&status),
        json: json!({"ok": status.state != RunState::NotRunning, "status": status}),
    })
}

pub fn stop(args: &mut Args) -> Result<Output, LifecycleError> {
    let wait = wait_seconds(args, 20)?;
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let report = lifecycle::stop(&layout, wait)?;
    let human = match report.outcome {
        StopOutcome::NotRunning => "Orcel is not running.\n".to_string(),
        StopOutcome::StaleRecordRemoved => format!("Orcel was not running; {}.\n", report.detail),
        StopOutcome::StoppedVerified => format!("Orcel stopped (verified): {}.\n", report.detail),
        StopOutcome::SupervisorTerminated => format!("Orcel stopped: {}.\n", report.detail),
    };
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "stop": report}),
    })
}

pub fn status(args: &mut Args) -> Result<Output, LifecycleError> {
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let installed: Option<orcel_lifecycle::layout::CurrentRecord> =
        orcel_lifecycle::layout::read_current(&layout)?;
    let config = Config::load(&layout);
    let runtime = lifecycle::status(&layout)?;
    let mut human = match &installed {
        Some(current) => format!("installed: Orcel {}\n", current.version),
        None => "installed: no\n".to_string(),
    };
    match &config {
        Ok(config) => human.push_str(&format!(
            "configured: {} workspace(s); tunnel {}\n",
            config.workspaces.len(),
            if config.tunnel.is_some() {
                "configured"
            } else {
                "not configured"
            }
        )),
        Err(error) => human.push_str(&format!("configured: error: {}\n", error.message)),
    }
    human.push_str(&describe(&runtime));
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({
            "ok": true,
            "installed": installed.map(|current| current.version),
            "workspaces": config.as_ref().map(|config| config.workspaces.len()).ok(),
            "tunnel_configured": config.as_ref().map(|config| config.tunnel.is_some()).ok(),
            "runtime": runtime,
        }),
    })
}

pub fn doctor(args: &mut Args) -> Result<Output, LifecycleError> {
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    // The exact ledger the brokers and `orcel approvals recover` use.
    let report =
        doctor::run_with_approval_history(&layout, platform.as_ref(), &approval_history_path()?);
    let mut human = String::new();
    for check in &report.checks {
        let mark = match check.status {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warn => "WARN",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Unknown => "????",
        };
        human.push_str(&format!("[{mark}] {:<22} {}\n", check.name, check.detail));
    }
    human.push_str(if report.healthy {
        "No failing checks.\n"
    } else {
        "One or more checks failed.\n"
    });
    Ok(Output {
        exit_code: if report.healthy {
            0
        } else {
            orcel_lifecycle::ErrorKind::State.exit_code()
        },
        human,
        json: json!({"ok": report.healthy, "doctor": report}),
    })
}

pub fn approvals(args: &mut Args) -> Result<Output, LifecycleError> {
    if args.flag("recover") {
        args.finish()?;
        return approvals_recover(&approval_history_path()?);
    }
    let limit = match args.value("--limit")? {
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|limit| (1..=100).contains(limit))
            .ok_or_else(|| LifecycleError::usage("--limit takes 1-100"))?,
        None => 20,
    };
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let config = Config::load(&layout)?;
    config.check_workspaces_with_policy()?;
    let version = active_version(&layout)?;
    let workspace = config.default_workspace().unwrap_or("default").to_string();
    let request = ipc::request(
        &workspace,
        "approval.history.query",
        "query",
        json!({"limit": limit}),
    );
    let response = ipc::call(
        &layout.version_dir(&version).join("orceld.exe"),
        &config,
        &request,
        Duration::from_secs(20),
    )?;
    let result = ipc::expect_ok(&response)?.clone();
    let mut human = String::new();
    for entry in result
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
    {
        human.push_str(&format!(
            "{} {:<8} {:<7} workspace={} consumed={}\n",
            entry
                .get("decided_at_ms")
                .and_then(Value::as_u64)
                .unwrap_or_default(),
            entry.get("decision").and_then(Value::as_str).unwrap_or("?"),
            entry
                .get("approval_class")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            entry
                .get("workspace_id")
                .and_then(Value::as_str)
                .unwrap_or("?"),
            entry
                .get("consumed")
                .map(Value::to_string)
                .unwrap_or_default(),
        ));
    }
    if human.is_empty() {
        human.push_str("No approval history.\n");
    }
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "approvals": result}),
    })
}

fn approval_history_path() -> Result<std::path::PathBuf, LifecycleError> {
    orcel_approval::default_approval_history_path()
        .map_err(|error| LifecycleError::state(format!("approval history: {error}")))
}

/// Quarantines an approval ledger that fails verification and starts a new
/// one. Runs locally, without the daemon, under the ledger's writer lock.
fn approvals_recover(path: &std::path::Path) -> Result<Output, LifecycleError> {
    let recovery = orcel_approval::recover_approval_ledger(path).map_err(|error| {
        let message = format!("approval ledger recovery: {}", error.message);
        // "Nothing to recover" is a state; busy and I/O failures are retryable.
        match error.code {
            orcel_approval::FailureCode::InvalidRequest => LifecycleError::state(message),
            _ => LifecycleError::new(orcel_lifecycle::ErrorKind::Io, message),
        }
    })?;
    // Quarantine already happened: never fail (or panic) while reporting it.
    let quarantined_to = recovery.quarantined_to.to_string_lossy().into_owned();
    Ok(Output {
        exit_code: 0,
        human: format!(
            "Approval ledger quarantined to {} ({} bytes, sha256 {}).\nA new ledger was started; earlier approvals no longer authorize anything, so request fresh approvals. Running Orcel processes switch to the new ledger on their next approval.\n",
            quarantined_to,
            recovery.quarantined_bytes,
            recovery.quarantined_sha256
        ),
        json: json!({
            "ok": true,
            "quarantined_to": quarantined_to,
            "quarantined_bytes": recovery.quarantined_bytes,
            "quarantined_sha256": recovery.quarantined_sha256,
        }),
    })
}

pub fn emergency_revoke(args: &mut Args) -> Result<Output, LifecycleError> {
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let config = Config::load(&layout)?;
    config.check_workspaces_with_policy()?;
    let version = active_version(&layout)?;
    let workspace = config.default_workspace().unwrap_or("default").to_string();
    eprintln!(
        "Confirm with Windows Hello when prompted. Every pending approval will be invalidated."
    );
    let request = ipc::request(&workspace, "trust.revoke_emergency", "revoke", json!({}));
    let response = ipc::call(
        &layout.version_dir(&version).join("orceld.exe"),
        &config,
        &request,
        Duration::from_secs(180),
    )?;
    let result = ipc::expect_ok(&response)?.clone();
    Ok(Output {
        exit_code: 0,
        human: format!(
            "Emergency revoke recorded (revoke epoch {}). Pending approvals are invalid.\n",
            result
                .get("revoke_epoch")
                .map(Value::to_string)
                .unwrap_or_default()
        ),
        json: json!({"ok": true, "revoke": result}),
    })
}

pub fn full_control(args: &mut Args) -> Result<Output, LifecycleError> {
    let action = args.positional("full-control action (grant, revoke, status)")?;
    let layout = Layout::for_current_user()?;
    match action.as_str() {
        "grant" => {
            let minutes = match args.value("--minutes")? {
                Some(value) => value
                    .parse::<u64>()
                    .map_err(|_| LifecycleError::usage("--minutes must be from 1 to 720"))?,
                None => 30,
            };
            args.finish()?;
            let config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            let workspace = config.default_workspace().unwrap_or("default").to_string();
            eprintln!(
                "Confirm with Windows Hello when prompted. Full User desktop control is bound to this exact live Orcel runtime session and expires automatically."
            );
            let lease =
                orcel_lifecycle::full_control::grant_full_user(&layout, &workspace, minutes)?;
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Full User desktop control granted for {minutes} minute(s); lease {} expires at {}. Full Admin, remote full control, elevation, recording, shell, filesystem, browser, and network authority were not enabled.\n",
                    lease.lease_id, lease.expires_at_ms
                ),
                json: json!({"ok": true, "lease": lease}),
            })
        }
        "revoke" => {
            args.finish()?;
            let epoch = orcel_lifecycle::full_control::revoke_full_user(&layout)?;
            Ok(Output {
                exit_code: 0,
                human: match epoch {
                    Some(epoch) => format!(
                        "Full User desktop control revoked. Authority epoch is now {epoch}.\n"
                    ),
                    None => "Full User desktop control is already Safe; no authority key exists.\n"
                        .into(),
                },
                json: json!({"ok": true, "revoked": epoch.is_some(), "authority_epoch": epoch}),
            })
        }
        "status" => {
            args.finish()?;
            let status = orcel_lifecycle::full_control::status(&layout)?;
            let human = if status["active"].as_bool() == Some(true) {
                format!(
                    "Full User desktop control is active for session {} until {} (authority epoch {}).\n",
                    status["session_id"].as_str().unwrap_or("?"),
                    status["expires_at_ms"],
                    status["authority_epoch"]
                )
            } else {
                format!(
                    "Desktop control is Safe/inactive (authority epoch {}): {}.\n",
                    status["authority_epoch"],
                    status["reason"]
                        .as_str()
                        .unwrap_or("no valid Full User lease")
                )
            };
            Ok(Output {
                exit_code: 0,
                human,
                json: json!({"ok": true, "full_control": status}),
            })
        }
        other => Err(LifecycleError::usage(format!(
            "unknown full-control action {other:?}; run orcel help"
        ))),
    }
}

pub fn update(args: &mut Args) -> Result<Output, LifecycleError> {
    let source = PathBuf::from(
        args.value("--source")?
            .ok_or_else(|| LifecycleError::usage("--source <release-dir> is required"))?,
    );
    let options = orcel_lifecycle::update::UpdateOptions {
        check_only: args.flag("--check"),
        allow_downgrade: args.flag("--allow-downgrade"),
        reinstall: args.flag("--reinstall"),
    };
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    let report = orcel_lifecycle::update::Updater::new(layout, platform.as_ref())
        .update(&source, &options)?;
    let human = match report.outcome {
        orcel_lifecycle::update::UpdateOutcome::Checked => format!(
            "Installed {}; candidate {} ({}). Compatible with the current configuration. Nothing was changed.\n",
            report.from, report.to, report.direction
        ),
        orcel_lifecycle::update::UpdateOutcome::AlreadyCurrent => format!(
            "Orcel {} is already installed; pass --reinstall to repair it from this release.\n",
            report.to
        ),
        orcel_lifecycle::update::UpdateOutcome::Updated => format!(
            "Orcel updated from {} to {} ({}){}. The previous version is kept for `orcel rollback`.\n",
            report.from,
            report.to,
            report.direction,
            if report.restarted { " and restarted" } else { "" }
        ),
    };
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "update": report}),
    })
}

pub fn rollback(args: &mut Args) -> Result<Output, LifecycleError> {
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    let report = orcel_lifecycle::update::Updater::new(layout, platform.as_ref()).rollback()?;
    Ok(Output {
        exit_code: 0,
        human: format!(
            "Rolled back from {} to {}{}.\n",
            report.from,
            report.to,
            if report.restarted {
                " and restarted"
            } else {
                "; Orcel is not running, start it with `orcel start`"
            }
        ),
        json: json!({"ok": true, "rollback": report}),
    })
}

/// Local MCP entrypoint (`orcel mcp stdio`, `orcel mcp serve`). This takes
/// over standard I/O for the session, so it returns the child exit code
/// instead of `Output`. Anything else fails closed as usage.
pub fn mcp(args: &mut Args) -> Result<i32, LifecycleError> {
    let action = args.positional("mcp action (stdio, serve)")?;
    let port = match args.value("--port")? {
        Some(value) => Some(value.parse::<u16>().map_err(|_| {
            LifecycleError::usage("orcel mcp serve --port must be from 1 to 65535")
        })?),
        None => None,
    };
    args.finish()?;
    orcel_lifecycle::mcp::run_action(&action, port)
}

/// `orcel remote allow|revoke|status`: local remote-session leases.
pub fn remote(args: &mut Args) -> Result<Output, LifecycleError> {
    use orcel_lifecycle::remote;
    let action =
        args.positional("remote action (allow, revoke, status, connect, migrate-secrets)")?;
    let layout = Layout::for_current_user()?;
    match action.as_str() {
        "allow" => {
            let connection = args.value("--connection")?.ok_or_else(|| {
                LifecycleError::usage("--connection <remote connection id> is required")
            })?;
            let workspaces = args.value("--workspaces")?;
            let scopes = args.value("--scopes")?;
            let minutes = match args.value("--minutes")? {
                Some(value) => value
                    .parse::<u64>()
                    .map_err(|_| LifecycleError::usage("--minutes must be from 1 to 15"))?,
                None => remote::MAX_LEASE_MINUTES,
            };
            let read_mode = args
                .value("--read-mode")?
                .unwrap_or_else(|| "session".into());
            args.finish()?;
            let config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            let workspaces: Vec<String> = match workspaces {
                Some(list) => list.split(',').map(|s| s.trim().to_owned()).collect(),
                None => vec![config.default_workspace().unwrap_or("default").to_owned()],
            };
            let options = remote::AllowOptions {
                remote_connection_id: connection.clone(),
                workspaces: workspaces.clone(),
                scopes: scopes.map(|list| list.split(',').map(|s| s.trim().to_owned()).collect()),
                minutes,
                read_mode,
            };
            let (device_id, device_epoch) =
                remote::device_identity(&remote::device_key_path(&layout))?;
            let paired =
                remote::paired_connection(&remote::uplink_config_path(&layout), &connection)?;
            let arguments = remote::lease_arguments(&options, &paired, &device_id, device_epoch)?;
            let version = active_version(&layout)?;
            eprintln!("Confirm with Windows Hello when prompted. A remote session lease is a STRONG approval and cannot be granted remotely or by an agent.");
            let request = ipc::request(&workspaces[0], "remote.lease.create", "create", arguments);
            let response = ipc::call(
                &layout.version_dir(&version).join("orceld.exe"),
                &config,
                &request,
                Duration::from_secs(180),
            )?;
            let lease = ipc::expect_ok(&response)?.clone();
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Remote session allowed for {connection} on {} for {minutes} minute(s). It never extends itself; run `orcel remote revoke` to end it early.\n",
                    workspaces.join(", ")
                ),
                json: json!({"ok": true, "lease": lease}),
            })
        }
        "revoke" => {
            let connection = args.value("--connection")?;
            args.finish()?;
            let config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            let workspace = config.default_workspace().unwrap_or("default").to_string();
            let version = active_version(&layout)?;
            let request = ipc::request(
                &workspace,
                "remote.lease.revoke",
                "revoke",
                json!({ "remote_connection_id": connection }),
            );
            let response = ipc::call(
                &layout.version_dir(&version).join("orceld.exe"),
                &config,
                &request,
                Duration::from_secs(30),
            )?;
            let result = ipc::expect_ok(&response)?.clone();
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Revoked {} remote session lease(s).\n",
                    result
                        .get("revoked")
                        .map(Value::to_string)
                        .unwrap_or_default()
                ),
                json: json!({"ok": true, "revoke": result}),
            })
        }
        "status" => {
            args.finish()?;
            let config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            let workspace = config.default_workspace().unwrap_or("default").to_string();
            let version = active_version(&layout)?;
            let request = ipc::request(&workspace, "remote.lease.status", "get", json!({}));
            let response = ipc::call(
                &layout.version_dir(&version).join("orceld.exe"),
                &config,
                &request,
                Duration::from_secs(30),
            )?;
            let result = ipc::expect_ok(&response)?.clone();
            let leases = result
                .get("leases")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let mut human = String::new();
            for lease in &leases {
                human.push_str(&format!(
                    "{} active={} workspaces={} scopes={} expires_at_ms={}\n",
                    lease["remote_connection_id"].as_str().unwrap_or("?"),
                    lease["active"],
                    lease["workspaces"],
                    lease["scope_ceiling"],
                    lease["expires_at_ms"]
                ));
            }
            if leases.is_empty() {
                human.push_str(
                    "No remote session leases. Remote requests fail with REMOTE_SESSION_INACTIVE.\n",
                );
            }
            Ok(Output {
                exit_code: 0,
                human,
                json: json!({"ok": true, "leases": leases}),
            })
        }
        "migrate-secrets" => {
            args.finish()?;
            let config = Config::load(&layout)?;
            config.check_workspaces_with_policy()?;
            let workspace = config.default_workspace().unwrap_or("default").to_string();
            let version = active_version(&layout)?;
            let mut request = ipc::request(&workspace, "secret", "migrate", json!({}));
            request["target"] = json!(remote::DEVICE_KEY_SECRET);
            let response = ipc::call(
                &layout.version_dir(&version).join("orceld.exe"),
                &config,
                &request,
                Duration::from_secs(60),
            )?;
            let result = ipc::expect_ok(&response)?.clone();
            let migration = result
                .get("migration")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let backend = result
                .get("backend")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let human = match migration.as_str() {
                "migrated" => format!("Moved the device key into the {backend} secret store and removed the plaintext copy.
"),
                "already_stored" => format!("The device key was already in the {backend} secret store; removed the plaintext copy.
"),
                _ => "No plaintext device key to migrate.
".to_string(),
            };
            Ok(Output {
                exit_code: 0,
                human,
                json: json!({"ok": true, "migration": migration, "backend": backend}),
            })
        }
        other => Err(LifecycleError::usage(format!(
            "unknown remote action {other:?}; run `orcel help`"
        ))),
    }
}

/// `orcel exec add|remove|list`: the SG-000060 protected executable registry.
pub fn exec(args: &mut Args) -> Result<Output, LifecycleError> {
    let action = args.positional("exec action (add, remove, list)")?;
    let layout = Layout::for_current_user()?;
    let split = |value: Option<String>| -> Vec<String> {
        value
            .map(|list| {
                list.split(',')
                    .map(|s| s.trim().to_owned())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };
    let (capability, operation, arguments, timeout) = match action.as_str() {
        "add" => {
            let id = args.positional("executable id")?;
            let path = args.positional("executable path")?;
            let subcommands = split(args.value("--subcommands")?);
            let denied_args = split(args.value("--deny-args")?);
            let max_args = match args.value("--max-args")? {
                Some(value) => value
                    .parse::<u64>()
                    .map_err(|_| LifecycleError::usage("--max-args must be from 0 to 64"))?,
                None => 16,
            };
            eprintln!("Confirm with Windows Hello when prompted. Registering an executable is a STRONG approval and cannot be granted by an agent.");
            (
                "executable.registry.add",
                "add",
                json!({ "id": id, "path": path, "subcommands": subcommands, "denied_args": denied_args, "max_args": max_args }),
                Duration::from_secs(180),
            )
        }
        "remove" => {
            let id = args.positional("executable id")?;
            (
                "executable.registry.remove",
                "remove",
                json!({ "id": id }),
                Duration::from_secs(30),
            )
        }
        "list" => (
            "executable.registry.list",
            "get",
            json!({}),
            Duration::from_secs(30),
        ),
        other => {
            return Err(LifecycleError::usage(format!(
                "unknown exec action {other:?}; run `orcel help`"
            )))
        }
    };
    args.finish()?;
    let config = Config::load(&layout)?;
    config.check_workspaces_with_policy()?;
    let workspace = config.default_workspace().unwrap_or("default").to_string();
    let version = active_version(&layout)?;
    let request = ipc::request(&workspace, capability, operation, arguments);
    let response = ipc::call(
        &layout.version_dir(&version).join("orceld.exe"),
        &config,
        &request,
        timeout,
    )?;
    let result = ipc::expect_ok(&response)?.clone();
    let human = match action.as_str() {
        "add" => format!(
            "Registered {} ({}) sha256 {}.\n",
            result["id"].as_str().unwrap_or("?"),
            result["path"].as_str().unwrap_or("?"),
            result["sha256"].as_str().unwrap_or("?")
        ),
        "remove" => format!("Removed {} executable(s).\n", result["removed"]),
        _ => {
            let mut text = String::new();
            for entry in result["executables"]
                .as_array()
                .cloned()
                .unwrap_or_default()
            {
                text.push_str(&format!(
                    "{} {} subcommands={} max_args={}\n",
                    entry["id"].as_str().unwrap_or("?"),
                    entry["path"].as_str().unwrap_or("?"),
                    entry["subcommands"],
                    entry["max_args"]
                ));
            }
            if text.is_empty() {
                text.push_str(
                    "No registered executables. process_spawn admits only the built-in baseline.\n",
                );
            }
            text
        }
    };
    Ok(Output {
        exit_code: 0,
        human,
        json: json!({"ok": true, "result": result}),
    })
}

/// `orcel remote enable|pair`: STRONG-gated device enrollment.
pub fn remote_enroll(args: &mut Args, action: &str) -> Result<i32, LifecycleError> {
    let relay = args.value("--relay")?;
    let workspace = args.value("--workspace")?;
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    orcel_lifecycle::remote::run_enrollment(&layout, platform.as_ref(), action, relay, workspace)
}

/// `orcel remote connect`: run the outbound-only device uplink.
pub fn remote_connect(args: &mut Args) -> Result<i32, LifecycleError> {
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    let (launch, config) =
        orcel_lifecycle::remote::resolve_uplink_launch(&layout, platform.as_ref())?;
    Ok(orcel_lifecycle::remote::run_uplink(&launch, &config))
}

/// Internal: verifies the installation with this binary's own code. Used by
/// `update` to confirm a newly activated version can verify itself.
pub fn self_check(args: &mut Args) -> Result<Output, LifecycleError> {
    args.finish()?;
    let layout = Layout::for_current_user()?;
    let platform = host_platform();
    let state = Installer::new(layout, platform.as_ref()).verify()?;
    let cli = env!("CARGO_PKG_VERSION");
    Ok(Output {
        exit_code: 0,
        human: format!("Orcel {} verified by CLI {cli}.\n", state.active.version),
        json: json!({"ok": true, "active": state.active.version, "cli": cli}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approvals_recover_quarantines_only_an_unverifiable_ledger() {
        let path = std::env::temp_dir()
            .join(format!(
                "orcel-approvals-recover-{}",
                orcel_lifecycle::nonce()
            ))
            .join("approval-history.jsonl");
        assert!(approvals_recover(&path).is_err(), "nothing to recover");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{\"torn\":").unwrap();
        let output = approvals_recover(&path).expect("recover");
        assert_eq!(output.exit_code, 0);
        let quarantined = output.json["quarantined_to"].as_str().unwrap();
        assert_eq!(std::fs::read(quarantined).unwrap(), b"{\"torn\":");
        assert!(output.human.contains("request fresh approvals"));
        assert!(approvals_recover(&path).is_err(), "the new ledger verifies");
    }
}
