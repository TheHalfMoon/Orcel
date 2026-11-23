//! SG-000132 slice 2: `orcel authority`, `orcel browser` and the
//! service path of `orcel full-control` (the desktop lease migration step).

use crate::{Args, Output};
use orcel_authority::client::{service_installed, AuthorityClient};
#[cfg(windows)]
use orcel_authority::lease::SignedLease;
use orcel_authority::lease::{LeaseScope, DEFAULT_LEASE_MINUTES, MAX_LEASE_MINUTES};
use orcel_lifecycle::authority_grant::{self, GrantRequest};
use orcel_lifecycle::LifecycleError;
use serde_json::{json, Value};

fn installed_client() -> Result<AuthorityClient, LifecycleError> {
    AuthorityClient::installed().map_err(|error| {
        LifecycleError::prerequisite(format!(
            "the Orcel authority service is not available ({error}); install it per docs/orcel/implementation-readiness/prep/SG132_INSTALL_RUNBOOK.md"
        ))
    })
}

fn minutes(args: &mut Args) -> Result<u64, LifecycleError> {
    match args.value("--minutes")? {
        Some(value) => value
            .parse::<u64>()
            .ok()
            .filter(|minutes| (1..=MAX_LEASE_MINUTES).contains(minutes))
            .ok_or_else(|| LifecycleError::usage("--minutes must be from 1 to 720")),
        None => Ok(DEFAULT_LEASE_MINUTES),
    }
}

fn values(args: &mut Args, name: &str) -> Result<Vec<String>, LifecycleError> {
    let mut out = Vec::new();
    while let Some(value) = args.value(name)? {
        out.push(value);
    }
    Ok(out)
}

#[cfg(windows)]
fn progress(line: &str) {
    eprintln!("{line}");
}

#[cfg(windows)]
fn lease_output(lease: &SignedLease) -> Output {
    Output {
        exit_code: 0,
        human: format!(
            "Granted by the Orcel authority service: lease {} ({}), expires at {} ms, authority epoch {}.\n",
            lease.body.lease_id,
            lease.body.scope.describe(),
            lease.body.expires_at_ms,
            lease.body.authority_epoch
        ),
        json: json!({ "ok": true, "lease": lease }),
    }
}

/// The Hello key the service has enrolled for this user (matched by its
/// fingerprint across our key slots).
#[cfg(windows)]
fn hello_signer(client: &AuthorityClient) -> Result<authority_grant::hello::Hello, LifecycleError> {
    let status = client
        .status()
        .map_err(|error| LifecycleError::state(error.to_string()))?;
    let fingerprint = status["caller_key_fingerprint"].as_str().ok_or_else(|| {
        LifecycleError::prerequisite(
            "no Windows Hello key is enrolled for this user; run the elevated `orcel authority enroll` first",
        )
    })?;
    authority_grant::hello::open_enrolled(fingerprint)
        .map(|(key, _)| key)
        .map_err(|error| {
            LifecycleError::prerequisite(format!(
                "the enrolled Windows Hello key could not be opened ({error}); a process running as you can delete Hello keys, so enroll again (`orcel authority enroll --replace`, elevated)"
            ))
        })
}

/// Review F1 (c): an elevated command started directly (Start-Process
/// -Verb RunAs) keeps its window until Enter, so its output can be read.
fn pause_if(pause: bool) {
    if pause {
        eprintln!("Press Enter to close this window.");
        let mut line = String::new();
        let _ = std::io::stdin().read_line(&mut line);
    }
}

/// The service grant shared by `full-control grant` and `browser grant`.
#[cfg(windows)]
fn service_grant(request: &GrantRequest) -> Result<Output, LifecycleError> {
    let client = installed_client()?;
    let signer = hello_signer(&client)?;
    let lease = authority_grant::run_grant(&client, request, &signer, &mut progress)?;
    Ok(lease_output(&lease))
}

#[cfg(not(windows))]
fn service_grant(_request: &GrantRequest) -> Result<Output, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "the Orcel authority service is Windows only in this slice",
    ))
}

/// `orcel full-control grant` when the service is installed: the narrow
/// default scope unless `--executors`, `--root` or `--shells` widen it.
pub fn full_control_grant(args: &mut Args) -> Result<Output, LifecycleError> {
    let minutes = minutes(args)?;
    let executors = match args.value("--executors")? {
        Some(list) => Some(authority_grant::parse_executors(&list)?),
        None => None,
    };
    let roots = values(args, "--root")?;
    let shells = args.flag("--shells");
    let client = args
        .value("--client")?
        .unwrap_or_else(|| "orcel-owner".to_owned());
    let task = args
        .value("--task")?
        .unwrap_or_else(|| "desktop control".to_owned());
    args.finish()?;
    let scope = authority_grant::desktop_scope(executors, roots, shells)?;
    service_grant(&GrantRequest {
        scope,
        minutes,
        principal_id: client,
        task,
    })
}

/// WP1-14: `orcel full-control standing grant|revoke|status` (spec 4.15).
/// Owner-only at the PC: a grant goes through the service's own gate (the
/// installed CLI's image, the observed unlock, the service's box, Windows
/// Hello); revoke and status reach only this Windows user's and logon
/// session's approvals, as the service binds them. Approvals stay with
/// the service's box and Windows Hello: nothing here approves anything.
pub fn full_control_standing(args: &mut Args) -> Result<Output, LifecycleError> {
    let action = args.positional("full-control standing action (grant, revoke, status)")?;
    match action.as_str() {
        "grant" => standing_grant(args),
        "revoke" => {
            let only = args.value("--id")?;
            args.finish()?;
            let client = installed_client()?;
            let mut revoked = Vec::new();
            for entry in authority_grant::standing_approvals(&client)? {
                let Some(id) = entry["approval"]["id"].as_str() else {
                    continue;
                };
                if entry["state"].as_str() != Some("active")
                    || only.as_deref().is_some_and(|only| only != id)
                {
                    continue;
                }
                client
                    .standing_revoke(id)
                    .map_err(|error| LifecycleError::state(error.to_string()))?;
                revoked.push(id.to_owned());
            }
            if let Some(only) = &only {
                if revoked.is_empty() {
                    return Err(LifecycleError::state(format!(
                        "no active standing approval {only} of this logon session"
                    )));
                }
            }
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Standing approvals revoked by the Orcel authority service: {}. Their leases stay; revoke those with `orcel full-control revoke`.\n",
                    json!(revoked)
                ),
                json: json!({ "ok": true, "revoked": revoked }),
            })
        }
        "status" => {
            args.finish()?;
            let client = installed_client()?;
            let status = client
                .status()
                .map_err(|error| LifecycleError::state(error.to_string()))?;
            let standing = authority_grant::standing_approvals(&client)?;
            let indicator = status["standing_approvals"]["indicator_alive"] == Value::Bool(true);
            let active = standing
                .iter()
                .filter(|entry| entry["state"].as_str() == Some("active"))
                .count();
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Standing approvals of this logon session: {active} active of {} listed; indicator heartbeat {}.{}\n",
                    standing.len(),
                    if indicator { "live" } else { "not live" },
                    if indicator {
                        ""
                    } else {
                        " Without a live indicator (WP1-12) no standing approval is granted or used: every action keeps its own approval."
                    }
                ),
                json: json!({
                    "ok": true,
                    "indicator_alive": indicator,
                    "standing": standing,
                }),
            })
        }
        other => Err(LifecycleError::usage(format!(
            "unknown full-control standing action {other:?}; use grant, revoke or status"
        ))),
    }
}

/// `orcel full-control standing grant --client <cl-ref> --task <label>
/// --root <path>... --operations <list> --folder <path>... [--program
/// <exe>]... [--minutes <n>] [--standing-minutes <n>]`.
fn standing_grant(args: &mut Args) -> Result<Output, LifecycleError> {
    let minutes = minutes(args)?;
    let client_ref = args.value("--client")?.ok_or_else(|| {
        LifecycleError::usage(
            "--client <cl-...> names the one client the standing approval is for (fc_status shows it)",
        )
    })?;
    let task = args
        .value("--task")?
        .ok_or_else(|| LifecycleError::usage("--task <label> declares the task"))?;
    let roots = values(args, "--root")?;
    let operations = args
        .value("--operations")?
        .ok_or_else(|| {
            LifecycleError::usage(
                "--operations <list> names what does not ask: run, git_add, git_unstage, git_commit, git_branch_create",
            )
        })
        .and_then(|list| authority_grant::parse_operations(&list))?;
    let folders = values(args, "--folder")?;
    let programs = values(args, "--program")?;
    let standing_minutes = match args.value("--standing-minutes")? {
        Some(value) => Some(
            value
                .parse::<u64>()
                .map_err(|_| LifecycleError::usage("--standing-minutes is a number of minutes"))?,
        ),
        None => None,
    };
    args.finish()?;
    let request = authority_grant::standing_request(
        client_ref,
        task,
        roots,
        minutes,
        orcel_authority::core::standing::StandingScope {
            executors: vec![orcel_contracts::ExecutorClass::ShellProcess],
            operations,
            roots: folders,
            origins: Vec::new(),
            commands: (!programs.is_empty()).then_some(programs),
            minutes: standing_minutes,
        },
    )?;
    service_standing_grant(&request)
}

#[cfg(windows)]
fn service_standing_grant(
    request: &authority_grant::StandingRequest,
) -> Result<Output, LifecycleError> {
    let client = installed_client()?;
    let signer = hello_signer(&client)?;
    let (lease, standing) =
        authority_grant::run_standing_grant(&client, request, &signer, &mut progress)?;
    Ok(Output {
        exit_code: 0,
        human: format!(
            "Granted by the Orcel authority service: lease {} ({}), and standing approval {} for client {} and task {:?}: {} do not ask inside [{}] until {} ms. It ends with Stop, locking the PC, sign-out, revoke or the lease's end.\n",
            lease.body.lease_id,
            lease.body.scope.describe(),
            standing.id,
            standing.principal_id,
            standing.task,
            standing.operations.join(", "),
            standing.roots.join(", "),
            standing.expires_at_ms
        ),
        json: json!({ "ok": true, "lease": lease, "standing": standing }),
    })
}

#[cfg(not(windows))]
fn service_standing_grant(
    _request: &authority_grant::StandingRequest,
) -> Result<Output, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "the Orcel authority service is Windows only in this slice",
    ))
}

/// `orcel full-control revoke` when the service is installed: every
/// active desktop lease of this logon session is revoked.
pub fn full_control_revoke() -> Result<Value, LifecycleError> {
    let client = installed_client()?;
    let mut revoked = Vec::new();
    for lease in authority_grant::active_leases(&client)? {
        if matches!(lease.body.scope, LeaseScope::DesktopFullUser { .. }) {
            client
                .revoke(&lease.body.lease_id)
                .map_err(|error| LifecycleError::state(error.to_string()))?;
            revoked.push(lease.body.lease_id);
        }
    }
    Ok(json!({ "revoked": revoked }))
}

/// `orcel full-control status` when the service is installed.
pub fn full_control_status() -> Result<Value, LifecycleError> {
    let client = installed_client()?;
    let status = client
        .status()
        .map_err(|error| LifecycleError::state(error.to_string()))?;
    let leases: Vec<Value> = authority_grant::active_leases(&client)?
        .iter()
        .map(|lease| {
            json!({
                "lease_id": lease.body.lease_id,
                "scope": lease.body.scope.describe(),
                "expires_at_ms": lease.body.expires_at_ms,
            })
        })
        .collect();
    Ok(json!({
        "authority": "service",
        "epoch": status["epoch"],
        "enrolled": status["caller_enrolled"],
        "key_fingerprint": status["caller_key_fingerprint"],
        "active_leases": leases,
    }))
}

/// Whether the service path applies (installed), announced once.
pub fn use_service() -> bool {
    service_installed()
}

/// `orcel authority status|enroll|reset`.
pub fn authority(args: &mut Args) -> Result<Output, LifecycleError> {
    let action = args.positional("authority action (status, enroll, reset)")?;
    match action.as_str() {
        "status" => {
            args.finish()?;
            let status = installed_client()?
                .status()
                .map_err(|error| LifecycleError::state(error.to_string()))?;
            Ok(Output {
                exit_code: 0,
                human: format!(
                    "Orcel authority service: mode {}, epoch {}, key id {}, enrolled {}, enrollment available {}.\n",
                    status["mode"], status["epoch"], status["key_id"], status["caller_enrolled"], status["enrollment_available"]
                ),
                json: json!({ "ok": true, "authority": status }),
            })
        }
        "enroll" => {
            let replace = args.flag("--replace");
            let pause = args.flag("--pause");
            args.finish()?;
            let result = enroll(replace);
            if let Err(error) = &result {
                eprintln!("orcel authority enroll: {error}");
            }
            pause_if(pause);
            result
        }
        "reset" => {
            let pause = args.flag("--pause");
            args.finish()?;
            let result = reset();
            if let Err(error) = &result {
                eprintln!("orcel authority reset: {error}");
            }
            pause_if(pause);
            result
        }
        other => Err(LifecycleError::usage(format!(
            "unknown authority action {other:?}; run orcel help"
        ))),
    }
}

#[cfg(windows)]
fn enroll(replace: bool) -> Result<Output, LifecycleError> {
    use authority_grant::hello;
    if !hello::this_process_is_elevated() {
        return Err(LifecycleError::prerequisite(
            "start `orcel authority enroll` elevated, directly (Start-Process -Verb RunAs on %ProgramFiles%\\Orcel\\orcel.exe): the UAC prompt on the secure desktop is the human gate for enrollment",
        ));
    }
    let client = installed_client()?;
    let status = client
        .status()
        .map_err(|error| LifecycleError::state(error.to_string()))?;
    if status["enrollment_available"].as_bool() != Some(true) {
        return Err(LifecycleError::prerequisite(
            "the authority service cannot verify TPM attestations on this PC, so enrollment is refused (fail closed)",
        ));
    }
    // Never replace the enrolled key in the Hello container unless asked.
    if status["caller_enrolled"].as_bool() == Some(true) && !replace {
        return Err(LifecycleError::conflict(
            "a key is already enrolled for this user; use `orcel authority enroll --replace` to replace it",
        ));
    }
    progress("Windows Hello asks you to create the Orcel Authority key.");
    // Review F6: the new key goes into the slot that does not hold the
    // enrolled key, so a refused or unanswered box leaves the enrolled key
    // untouched; only after the service enrolled the new key are the others
    // deleted.
    let (key, slot) = hello::create_beside(status["caller_key_fingerprint"].as_str(), replace)
        .map_err(|error| LifecycleError::state(format!("create the key: {error}")))?;
    let enrolled = authority_grant::run_enroll(&client, &key, replace, &mut progress)?;
    let removed = hello::delete_others(Some(slot));
    progress(&format!(
        "Removed {removed} earlier Orcel Authority key(s) from Windows Hello."
    ));
    Ok(Output {
        exit_code: 0,
        human: format!(
            "Enrolled the Windows Hello key {} for Orcel Full Control grants.\n",
            enrolled["key_fingerprint"].as_str().unwrap_or("?")
        ),
        json: json!({ "ok": true, "enrollment": enrolled }),
    })
}

#[cfg(not(windows))]
fn enroll(_replace: bool) -> Result<Output, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "the Orcel authority service is Windows only in this slice",
    ))
}

#[cfg(windows)]
fn reset() -> Result<Output, LifecycleError> {
    use authority_grant::hello;
    if !hello::this_process_is_elevated() {
        return Err(LifecycleError::prerequisite(
            "run `orcel authority reset` from an elevated terminal",
        ));
    }
    let client = installed_client()?;
    authority_grant::run_reset(&client, &mut progress)?;
    let removed_locally = hello::delete_others(None) > 0;
    Ok(Output {
        exit_code: 0,
        human: format!(
            "The enrolled key was removed from the Orcel authority service{}.\n",
            if removed_locally {
                " and from Windows Hello"
            } else {
                " (the local Windows Hello key could not be deleted)"
            }
        ),
        json: json!({ "ok": true, "reset": true, "deleted_locally": removed_locally }),
    })
}

#[cfg(not(windows))]
fn reset() -> Result<Output, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "the Orcel authority service is Windows only in this slice",
    ))
}

/// WP1-03 `orcel audit reset-anchor [--pause]`: the owner's recovery for a
/// lost or replaced audit chain (SG132_INSTALL_RUNBOOK.md).
pub fn audit(args: &mut Args) -> Result<Output, LifecycleError> {
    let action = args.positional("audit action (reset-anchor)")?;
    match action.as_str() {
        "reset-anchor" => {
            let pause = args.flag("--pause");
            args.finish()?;
            let result = reset_anchor();
            if let Err(error) = &result {
                eprintln!("orcel audit reset-anchor: {error}");
            }
            pause_if(pause);
            result
        }
        other => Err(LifecycleError::usage(format!(
            "unknown audit action {other:?}; run orcel help"
        ))),
    }
}

#[cfg(windows)]
fn reset_anchor() -> Result<Output, LifecycleError> {
    use authority_grant::hello;
    if !hello::this_process_is_elevated() {
        return Err(LifecycleError::prerequisite(
            "start `orcel audit reset-anchor` elevated, directly (Start-Process -Verb RunAs on %ProgramFiles%\\Orcel\\orcel.exe): the UAC prompt on the secure desktop is the human gate",
        ));
    }
    let chain = orcel_audit::default_audit_path()
        .map(|plain| orcel_audit::chain_path_for(&plain))
        .map_err(|error| LifecycleError::state(format!("resolve the audit chain: {error}")))?;
    let client = installed_client()?;
    // Resume: a reset the service already reports (an earlier run confirmed
    // it but stopped before opening the file) goes straight to the file.
    let earlier = client
        .anchor_status(orcel_audit::ORCELD_LOG)
        .map_err(|error| LifecycleError::state(error.to_string()))?;
    let status = if earlier["reset"]["event_digest"].is_string() {
        progress(
            "The service already reports an anchor reset for this log; opening its chain file.",
        );
        earlier
    } else {
        authority_grant::run_anchor_reset(&client, orcel_audit::ORCELD_LOG, &mut progress)?
    };
    let opened = authority_grant::open_reset_chain(&chain, &status)?;
    // Anchor the new file's opening record now (the service accepts this
    // from the owner CLI in the reset state only), so no other file naming
    // the same reset can be adopted; orceld anchors it first otherwise.
    let anchored = authority_grant::opening_anchor(&chain).and_then(|opening| {
        client
            .anchor(
                &opening,
                None,
                status["reset"]["event_digest"].as_str().map(str::to_owned),
            )
            .map_err(|error| LifecycleError::state(error.to_string()))
    });
    if let Err(error) = &anchored {
        progress(&format!(
            "The new file's opening record could not be anchored now ({error}); orceld anchors it before its first record."
        ));
    }
    Ok(Output {
        exit_code: 0,
        human: format!(
            "The Orcel authority service reset its audit anchor of orceld's chain (record {}). A new first chain file was opened at {}; it is reported as reset_by_owner by `orceld audit-verify`. Restart orceld so it writes to the new file.\n",
            status["reset"]["event_digest"].as_str().unwrap_or("?"),
            chain.display()
        ),
        json: json!({
            "ok": true,
            "anchor_reset": opened,
            "opening_anchored": anchored.is_ok(),
        }),
    })
}

#[cfg(not(windows))]
fn reset_anchor() -> Result<Output, LifecycleError> {
    Err(LifecycleError::prerequisite(
        "the Orcel authority service is Windows only in this slice",
    ))
}

/// `orcel browser grant|leases|revoke` (SG-000135 Full Access through the
/// service only).
pub fn browser(args: &mut Args) -> Result<Output, LifecycleError> {
    let action = args.positional("browser action (grant, leases, revoke)")?;
    match action.as_str() {
        "grant" => {
            let session = args
                .value("--session")?
                .ok_or_else(|| LifecycleError::usage("--session <bs-...> is required"))?;
            let client_ref = args
                .value("--client-ref")?
                .ok_or_else(|| LifecycleError::usage("--client-ref <cl-...> is required"))?;
            let origins = values(args, "--origin")?;
            let families = match args.value("--families")? {
                Some(list) => authority_grant::parse_families(&list)?,
                None => authority_grant::parse_families("navigate,click,type,select,tabs")?,
            };
            let label = args.value("--task")?;
            let minutes = minutes(args)?;
            args.finish()?;
            let scope = authority_grant::browser_scope(
                session,
                client_ref.clone(),
                origins,
                families,
                label.clone(),
            )?;
            service_grant(&GrantRequest {
                scope: Some(scope),
                minutes,
                principal_id: client_ref,
                task: label.unwrap_or_else(|| "browser Full Access".to_owned()),
            })
        }
        "leases" => {
            args.finish()?;
            let client = installed_client()?;
            let leases: Vec<Value> = authority_grant::active_leases(&client)?
                .iter()
                .filter(|lease| matches!(lease.body.scope, LeaseScope::BrowserFullAccess { .. }))
                .map(|lease| {
                    json!({
                        "lease_id": lease.body.lease_id,
                        "scope": lease.body.scope.describe(),
                        "expires_at_ms": lease.body.expires_at_ms,
                    })
                })
                .collect();
            Ok(Output {
                exit_code: 0,
                human: format!("{} active browser lease(s).\n", leases.len()),
                json: json!({ "ok": true, "leases": leases }),
            })
        }
        "revoke" => {
            let lease_id = args.positional("lease id")?;
            args.finish()?;
            installed_client()?
                .revoke(&lease_id)
                .map_err(|error| LifecycleError::state(error.to_string()))?;
            Ok(Output {
                exit_code: 0,
                human: format!("Browser lease {lease_id} revoked.\n"),
                json: json!({ "ok": true, "revoked": lease_id }),
            })
        }
        other => Err(LifecycleError::usage(format!(
            "unknown browser action {other:?}; run orcel help"
        ))),
    }
}
