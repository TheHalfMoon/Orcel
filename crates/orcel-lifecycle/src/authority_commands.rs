//! SG-000132 slice 2: `orcel authority`, `orcel browser` and the
//! service path of `orcel full-control` (the desktop lease migration step).

use crate::{Args, Output};
use orcel_authority::client::{service_installed, AuthorityClient};
use orcel_authority::lease::{LeaseScope, SignedLease, DEFAULT_LEASE_MINUTES, MAX_LEASE_MINUTES};
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

fn progress(line: &str) {
    eprintln!("{line}");
}

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

#[cfg(windows)]
fn hello_signer() -> Result<authority_grant::hello::Hello, LifecycleError> {
    authority_grant::hello::open().map_err(|error| {
        LifecycleError::prerequisite(format!(
            "the enrolled Windows Hello key could not be opened ({error}); run `orcel authority enroll` from an elevated terminal first"
        ))
    })
}

/// The service grant shared by `full-control grant` and `browser grant`.
#[cfg(windows)]
fn service_grant(request: &GrantRequest) -> Result<Output, LifecycleError> {
    let client = installed_client()?;
    let signer = hello_signer()?;
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
            args.finish()?;
            enroll(replace)
        }
        "reset" => {
            args.finish()?;
            reset()
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
            "run `orcel authority enroll` from an elevated terminal: the UAC prompt on the secure desktop is the human gate for enrollment",
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
    // Past the check above, either nothing is enrolled (a key left in the
    // Hello container by an unfinished enrollment is stale) or --replace was
    // asked: the container's key of this name is replaced either way.
    let key = hello::create(true)
        .map_err(|error| LifecycleError::state(format!("create the key: {error}")))?;
    let enrolled = authority_grant::run_enroll(&client, &key, replace, &mut progress)?;
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
    let removed_locally = hello::delete().is_ok();
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
