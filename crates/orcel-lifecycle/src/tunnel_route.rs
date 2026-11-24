//! #395: the remote route of the ChatGPT Secure MCP Tunnel.
//!
//! The tunnel is a remote transport: a ChatGPT workspace drives the MCP host
//! through OpenAI's tunnel client. Its requests therefore carry an SG-000055
//! remote context, exactly like the relay, so `orceld` checks every request
//! against a local remote-session lease and the remote scope map. The tunnel
//! has no paired device record, so its route identifiers are derived from the
//! locally configured tunnel id. Nothing a remote peer sends can change them,
//! and a lease for the tunnel is created only by `orcel tunnel allow`, under
//! the same STRONG local presence as `orcel remote allow`.
//!
//! SG-000135 OB-09: a tunnel serves one tool-surface profile, chosen by the
//! owner at `orcel tunnel setup --profile` on the PC: `core` (the default,
//! unchanged) or `browser_full` (the remote-safe Orcel Browser tools). A
//! `browser_full` tunnel has its own derived remote connection id and client
//! profile, so a core lease never covers it and its own lease needs its own
//! STRONG `orcel tunnel allow`; a tunnel never serves both profiles.

use crate::config::Config;
use crate::lifecycle::Observed;
use crate::LifecycleError;
use orcel_policy::remote_session::{
    REMOTE_PROFILE_BROWSER_FULL, REMOTE_PROFILE_CORE, REMOTE_SCOPES,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Environment variable naming the MCP host's transport. `orcel-mcp-host`
/// always sets it to [`TUNNEL_TRANSPORT`]; local launches never set it.
pub const TRANSPORT_ENV: &str = "ORCEL_MCP_TRANSPORT";
/// The only value of [`TRANSPORT_ENV`].
pub const TUNNEL_TRANSPORT: &str = "tunnel";
/// Environment variable carrying the tunnel route (see [`route`]).
pub const ROUTE_ENV: &str = "ORCEL_TUNNEL_ROUTE_JSON";
/// Provider kind of the tunnel: ChatGPT, mapped to `core` (or, when the
/// owner set the tunnel up for it, `browser_full`).
pub const PROVIDER_KIND: &str = "openai";
/// Client profile of the tunnel route.
pub const CLIENT_PROFILE_ID: &str = "chatgpt-secure-mcp-tunnel";
pub const CLIENT_PROFILE_REVISION: u64 = 1;
/// The tunnel has no device key; its route epoch is fixed.
pub const DEVICE_EPOCH: u64 = 1;
/// SG-000135 OB-09: the client profile of a `browser_full` tunnel route.
pub const BROWSER_FULL_CLIENT_PROFILE_ID: &str =
    orcel_policy::remote_session::TUNNEL_BROWSER_FULL_CLIENT_PROFILE;
/// SG-000135 OB-09: the profiles a tunnel may serve (one per tunnel).
pub const TUNNEL_PROFILES: [&str; 2] = [REMOTE_PROFILE_CORE, REMOTE_PROFILE_BROWSER_FULL];
/// SG-000135 OB-09: a `browser_full` tunnel's scope ceiling: reads and
/// browser actions, never `orcel.write`.
pub const BROWSER_FULL_SCOPES: [&str; 2] = orcel_policy::remote_session::BROWSER_FULL_SCOPES;

/// Whether `profile` is one a tunnel may serve.
pub fn is_tunnel_profile(profile: &str) -> bool {
    TUNNEL_PROFILES.contains(&profile)
}

/// The route derivation orceld also checks (SG-000135 OB-09): one copy, in
/// the policy crate.
fn derived_id(prefix: &str, label: &str, tunnel_id: &str) -> String {
    orcel_policy::remote_session::tunnel_derived_id(prefix, label, tunnel_id)
}

/// The tunnel's remote route for `tunnel_id`, in the paired-connection shape
/// the device uplink uses, plus the derived device identity. The scope
/// ceiling is the full remote vocabulary; the lease narrows it.
pub fn route(tunnel_id: &str) -> Value {
    json!({
        "principal": derived_id("rp-", "principal", tunnel_id),
        "remoteConnectionId": derived_id("rc-", "remote_connection", tunnel_id),
        "deviceId": derived_id("dev-", "device", tunnel_id),
        "deviceEpoch": DEVICE_EPOCH,
        "providerKind": PROVIDER_KIND,
        "clientProfileId": CLIENT_PROFILE_ID,
        "clientProfileRevision": CLIENT_PROFILE_REVISION,
        "toolSurfaceProfile": REMOTE_PROFILE_CORE,
        "scopeCeiling": REMOTE_SCOPES,
    })
}

/// The remote connection id `orcel tunnel allow` leases for `tunnel_id`.
pub fn remote_connection_id(tunnel_id: &str) -> String {
    derived_id("rc-", "remote_connection", tunnel_id)
}

/// SG-000135 OB-09: the tunnel's route for `profile` (`None` for a profile
/// a tunnel may not serve). `core` is exactly [`route`].
pub fn route_for(tunnel_id: &str, profile: &str) -> Option<Value> {
    match profile {
        REMOTE_PROFILE_CORE => Some(route(tunnel_id)),
        REMOTE_PROFILE_BROWSER_FULL => Some(json!({
            "principal": derived_id("rp-", "principal", tunnel_id),
            "remoteConnectionId": remote_connection_id_for(tunnel_id, profile)?,
            "deviceId": derived_id("dev-", "device", tunnel_id),
            "deviceEpoch": DEVICE_EPOCH,
            "providerKind": PROVIDER_KIND,
            "clientProfileId": BROWSER_FULL_CLIENT_PROFILE_ID,
            "clientProfileRevision": CLIENT_PROFILE_REVISION,
            "toolSurfaceProfile": REMOTE_PROFILE_BROWSER_FULL,
            "scopeCeiling": BROWSER_FULL_SCOPES,
        })),
        _ => None,
    }
}

/// SG-000135 OB-09: the remote connection id `orcel tunnel allow` leases
/// for `tunnel_id` serving `profile`; `core` is exactly
/// [`remote_connection_id`].
pub fn remote_connection_id_for(tunnel_id: &str, profile: &str) -> Option<String> {
    match profile {
        REMOTE_PROFILE_CORE => Some(remote_connection_id(tunnel_id)),
        REMOTE_PROFILE_BROWSER_FULL => Some(derived_id(
            "rc-",
            "remote_connection/browser_full",
            tunnel_id,
        )),
        _ => None,
    }
}

/// One connection a tunnel id derives: the profile and its connection id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConnection {
    pub profile: &'static str,
    pub connection_id: String,
}

/// SG-000135 OB-09: every remote connection `tunnel_id` derives, one per
/// profile it may serve. Revoking a tunnel revokes all of them, so a lease
/// left from the profile it served before never outlives the revoke.
pub fn all_connections(tunnel_id: &str) -> Vec<TunnelConnection> {
    TUNNEL_PROFILES
        .iter()
        .filter_map(|profile| {
            Some(TunnelConnection {
                profile,
                connection_id: remote_connection_id_for(tunnel_id, profile)?,
            })
        })
        .collect()
}

/// SG-000135 OB-09: the connections `orcel tunnel setup` revokes: every one
/// of the previous tunnel's when the tunnel id or the profile changes, none
/// otherwise. `previous` is the previous tunnel id and profile.
pub fn connections_revoked_by_setup(
    previous: Option<(&str, &str)>,
    tunnel_id: &str,
    profile: &str,
) -> Vec<TunnelConnection> {
    match previous {
        Some((old_id, old_profile)) if old_id != tunnel_id || old_profile != profile => {
            all_connections(old_id)
        }
        _ => Vec::new(),
    }
}

/// SG-000135 OB-09: whether `orcel tunnel setup` changes what a running tunnel
/// client was launched with: the tunnel id, the profile or the runtime key. A
/// first setup does. `previous` is the previous tunnel id and profile.
pub fn setup_changes(
    previous: Option<(&str, &str)>,
    tunnel_id: &str,
    profile: &str,
    previous_key: Option<&[u8]>,
    key: &str,
) -> bool {
    previous != Some((tunnel_id, profile)) || previous_key != Some(key.as_bytes())
}

/// SG-000135 OB-09: refuses a setup that [`setup_changes`] while the
/// supervisor or its tunnel client runs, or when that cannot be told. The old
/// client would stay connected to the old tunnel and start its next
/// `orcel-mcp-host` under the new setup.
pub fn setup_allowed(
    changes: bool,
    observe: impl FnOnce() -> Result<Observed, LifecycleError>,
) -> Result<(), LifecycleError> {
    if !changes {
        return Ok(());
    }
    const THEN: &str = "Nothing was changed. Run `orcel stop`, then `orcel tunnel setup` again";
    match observe() {
        Ok(Observed::Gone) => Ok(()),
        Ok(Observed::Live) => Err(LifecycleError::conflict(format!(
            "the ChatGPT tunnel is running, so its tunnel id, profile and runtime key cannot be changed. {THEN}"
        ))),
        Ok(Observed::Unknown) => Err(LifecycleError::conflict(format!(
            "Orcel could not tell whether the ChatGPT tunnel is running, so its tunnel id, profile and runtime key cannot be changed. {THEN}"
        ))),
        Err(error) => Err(LifecycleError::new(
            error.kind,
            format!(
                "Orcel could not tell whether the ChatGPT tunnel is running, so its tunnel id, profile and runtime key cannot be changed: {}. {THEN}",
                error.message
            ),
        )),
    }
}

const PIN_LABEL: &str = "orcel/tunnel-launch-pin/v1";

fn pin_digest(salt: &str, tunnel_id: &str, profile: &str, key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    for part in [
        PIN_LABEL.as_bytes(),
        salt.as_bytes(),
        tunnel_id.as_bytes(),
        profile.as_bytes(),
        key,
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    format!("{:x}", hasher.finalize())
}

/// The configured tunnel id and profile and the stored runtime key, which a
/// launch pin covers.
fn pinned_parts<'a>(
    config: &'a Config,
    key: Option<&'a [u8]>,
) -> Result<(&'a str, &'a str, &'a [u8]), LifecycleError> {
    let tunnel = config.tunnel.as_ref().ok_or_else(|| {
        LifecycleError::state("the tunnel is not configured; orcel-mcp-host serves only the tunnel")
    })?;
    let key = key.ok_or_else(|| {
        LifecycleError::state("the tunnel runtime key is missing; run `orcel tunnel setup`")
    })?;
    Ok((&tunnel.tunnel_id, &tunnel.profile, key))
}

/// SG-000135 OB-09: the pin of one tunnel client launch: a digest of the
/// setup it was launched with (tunnel id, profile, runtime key). The key
/// itself is not in it; `nonce` makes each launch's pin its own.
pub fn launch_pin(
    config: &Config,
    key: Option<&[u8]>,
    nonce: &str,
) -> Result<String, LifecycleError> {
    let (tunnel_id, profile, key) = pinned_parts(config, key)?;
    let salt = format!("{:x}", Sha256::digest(nonce.as_bytes()));
    let digest = pin_digest(&salt, tunnel_id, profile, key);
    Ok(format!("{salt}.{digest}"))
}

/// SG-000135 OB-09: refuses unless `pin` (what the tunnel client was launched
/// with) is the pin of the setup saved now. No pin is a refusal: a client
/// that the supervisor did not launch is not served.
pub fn check_launch_pin(
    config: &Config,
    key: Option<&[u8]>,
    pin: Option<&str>,
) -> Result<(), LifecycleError> {
    let (tunnel_id, profile, key) = pinned_parts(config, key)?;
    let matches = pin
        .and_then(|pin| pin.split_once('.'))
        .is_some_and(|(salt, digest)| digest == pin_digest(salt, tunnel_id, profile, key));
    if matches {
        return Ok(());
    }
    Err(LifecycleError::state(match pin {
        Some(_) => "the saved tunnel setup is not the one this tunnel client was started with; run `orcel stop`, then `orcel start`",
        None => "this tunnel client was not started by `orcel start`; run `orcel stop`, then `orcel start`",
    }))
}

/// Why a connection's revoke is not known to have happened.
#[derive(Debug)]
pub enum RevokeFailure {
    /// orceld answered that it did not revoke.
    Refused(LifecycleError),
    /// No answer, an unreadable one, or an internal error: the revoke may or
    /// may not have happened.
    Unconfirmed(LifecycleError),
}

impl RevokeFailure {
    fn error(&self) -> &LifecycleError {
        match self {
            Self::Refused(error) | Self::Unconfirmed(error) => error,
        }
    }
}

/// orceld's answer to a `remote.lease.revoke`, as a revoke reads it. Only a
/// typed refusal other than an internal error says that nothing was revoked.
/// Everything else that is not a count is unconfirmed.
pub fn revoke_reply(response: Result<Value, LifecycleError>) -> Result<u64, RevokeFailure> {
    let response = response.map_err(RevokeFailure::Unconfirmed)?;
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        return response
            .pointer("/result/revoked")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                RevokeFailure::Unconfirmed(LifecycleError::state(
                    "orceld did not say how many leases it revoked",
                ))
            });
    }
    let code = response.pointer("/error/code").and_then(Value::as_str);
    let error = LifecycleError::state(format!(
        "orceld {}: {}",
        code.unwrap_or("UNKNOWN"),
        response
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("unspecified failure")
    ));
    let refused = response.get("ok").and_then(Value::as_bool) == Some(false)
        && code.is_some_and(|code| code != "INTERNAL_ERROR");
    Err(if refused {
        RevokeFailure::Refused(error)
    } else {
        RevokeFailure::Unconfirmed(error)
    })
}

/// Adds what to do when `error` is about orceld's audit chain: a chain that
/// does not verify refuses every dispatch, a lease revoke included.
pub fn with_audit_remedy(error: LifecycleError, orceld: &Path) -> LifecycleError {
    if !error.message.to_ascii_lowercase().contains("audit") {
        return error;
    }
    LifecycleError::new(
        error.kind,
        format!(
            "{} This is about orceld's audit chain, which it must write before it revokes a lease. `orceld audit-verify` says whether and where the chain does not verify, and `orceld audit-move-aside` keeps that file and opens a new one linked to it; then run this command again. orceld is {}",
            error.message,
            orceld.display()
        ),
    )
}

/// What revoking a tunnel's connections did: how many unexpired leases each
/// one's revoke ended, and which revokes failed.
#[derive(Debug, Default)]
pub struct RevokeReport {
    pub ended: Vec<(TunnelConnection, u64)>,
    pub failed: Vec<(TunnelConnection, RevokeFailure)>,
}

impl RevokeReport {
    /// How many leases were ended; one that had expired is not counted.
    pub fn revoked(&self) -> u64 {
        self.ended.iter().map(|(_, count)| count).sum()
    }

    /// The connection ids whose revoke failed or is unconfirmed.
    pub fn failed_ids(&self) -> Vec<&str> {
        self.failed
            .iter()
            .map(|(connection, _)| connection.connection_id.as_str())
            .collect()
    }

    /// Exactly what ended, what did not and what is not known, one sentence
    /// each.
    pub fn describe(&self) -> String {
        const EXPIRY: &str =
            "may still be active until it expires (at most 15 minutes after it was allowed).";
        let mut out = Vec::new();
        for (connection, count) in &self.ended {
            out.push(format!(
                "{} ({}): {count} lease(s) ended.",
                connection.connection_id, connection.profile
            ));
        }
        for (connection, failure) in &self.failed {
            let what = match failure {
                RevokeFailure::Refused(error) => format!("NOT revoked ({})", error.message),
                RevokeFailure::Unconfirmed(error) => {
                    format!("could not be confirmed as revoked ({})", error.message)
                }
            };
            out.push(format!(
                "{} ({}): {what}; a lease on it {EXPIRY}",
                connection.connection_id, connection.profile
            ));
        }
        out.join(" ")
    }

    /// An error naming what ended and what did not, when any revoke failed.
    pub fn check(&self) -> Result<(), LifecycleError> {
        match self.failed.first() {
            None => Ok(()),
            Some((_, first)) => Err(LifecycleError::new(
                first.error().kind,
                format!(
                    "{} Run `orcel tunnel revoke` again, or `orcel remote revoke` to end every remote session lease.",
                    self.describe()
                ),
            )),
        }
    }
}

/// Revoke every connection with `revoke` (which returns how many leases it
/// revoked). A failure does not stop the rest.
pub fn revoke_each(
    connections: &[TunnelConnection],
    mut revoke: impl FnMut(&str) -> Result<u64, RevokeFailure>,
) -> RevokeReport {
    let mut report = RevokeReport::default();
    for connection in connections {
        match revoke(&connection.connection_id) {
            Ok(count) => report.ended.push((connection.clone(), count)),
            Err(failure) => report.failed.push((connection.clone(), failure)),
        }
    }
    report
}

/// SG-000135 OB-09: what a failed `orcel tunnel setup` says: whether the
/// previous setup is in place (`restored`), and what happened to the previous
/// route's leases. It never says both "kept" and "not restored".
pub fn setup_failure(
    error: LifecycleError,
    report: &RevokeReport,
    restored: bool,
) -> LifecycleError {
    let kind = if restored {
        error.kind
    } else {
        crate::ErrorKind::State
    };
    let state = if restored {
        "the key and configuration are as they were before"
    } else {
        "the previous key or configuration could not be fully restored; rerun `orcel tunnel setup`"
    };
    let leases = if report.failed.is_empty() && !report.ended.is_empty() {
        // A failed revoke's own error already says this.
        format!("; the previous route's leases: {}", report.describe())
    } else {
        String::new()
    };
    LifecycleError::new(
        kind,
        format!("tunnel setup failed: {} ({state}{leases})", error.message),
    )
}

/// SG-000135 OB-09: change a tunnel's route. The old route's leases are
/// revoked first, while the saved setup still names it, so a failure or a
/// crash before `save` leaves the old id reachable by `orcel tunnel revoke`
/// and by a rerun; `save` runs only when every revoke succeeded. An
/// `orcel tunnel allow` cannot run in between: every `orcel tunnel` command
/// holds the lifecycle lock for its whole run, its approval prompt included
/// (Windows: a mutex of this logon session; Linux and macOS: an advisory lock
/// on `lifecycle.lock`, which a person can defeat by deleting the file). A
/// `remote.lease.create` sent to orceld some other way (it needs the same
/// approval) is not ordered by that lock.
pub fn change_route(
    replaced: &[TunnelConnection],
    revoke: impl FnMut(&str) -> Result<u64, RevokeFailure>,
    save: impl FnOnce() -> Result<(), LifecycleError>,
) -> (RevokeReport, Result<(), LifecycleError>) {
    let report = revoke_each(replaced, revoke);
    let result = report.check().and_then(|()| save());
    (report, result)
}

/// The derived device identity of the tunnel route.
pub fn device_identity(tunnel_id: &str) -> (String, u64) {
    (derived_id("dev-", "device", tunnel_id), DEVICE_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_contracts::RemoteContext;
    use orcel_policy::remote_session::validate_remote_context;

    const TUNNEL: &str = "tunnel_0123456789abcdefghijklmnopqrstuv";

    fn context(route: &Value) -> RemoteContext {
        let text = |name: &str| route[name].as_str().unwrap().to_owned();
        RemoteContext {
            principal: text("principal"),
            remote_connection_id: text("remoteConnectionId"),
            connection_id: "tunnel-0123456789abcdef".into(),
            device_id: text("deviceId"),
            device_epoch: route["deviceEpoch"].as_u64().unwrap(),
            provider_kind: text("providerKind"),
            client_profile_id: text("clientProfileId"),
            client_profile_revision: route["clientProfileRevision"].as_u64().unwrap(),
            tool_surface_profile: text("toolSurfaceProfile"),
            scopes: route["scopeCeiling"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect(),
        }
    }

    #[test]
    fn route_is_a_valid_core_remote_context_and_is_stable() {
        let route = route(TUNNEL);
        validate_remote_context(&context(&route)).unwrap();
        assert_eq!(route["toolSurfaceProfile"], "core");
        assert_eq!(route, super::route(TUNNEL));
        assert_eq!(
            route["remoteConnectionId"].as_str().unwrap(),
            remote_connection_id(TUNNEL)
        );
        let (device, epoch) = device_identity(TUNNEL);
        assert_eq!(route["deviceId"].as_str().unwrap(), device);
        assert_eq!(route["deviceEpoch"].as_u64().unwrap(), epoch);
    }

    #[test]
    fn route_values_are_pinned_across_languages() {
        // apps/orcel-mcp/src/tunnel-transport.test.ts and
        // crates/orceld/tests/fix395_tunnel_remote.rs use these values.
        let route = route(TUNNEL);
        assert_eq!(route["principal"], "rp-182110eb5d85d5ccd3f34df5dba41e1a");
        assert_eq!(
            route["remoteConnectionId"],
            "rc-8d11a8282860ff1df26aeee0949a7bf9"
        );
        assert_eq!(route["deviceId"], "dev-0872269746857073deab118978d116a0");
        assert_eq!(
            route["scopeCeiling"],
            json!(["orcel.read", "orcel.write", "orcel.execute"])
        );
    }

    #[test]
    fn lease_from_tunnel_allow_admits_only_core_shapes_of_the_tunnel() {
        use crate::remote::{lease_arguments, AllowOptions};
        use orcel_contracts::{FailureCode, RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
        use orcel_policy::remote_session::{
            build_lease, check_remote_dispatch, GateEnvironment, LeaseRequest, ReadMode,
            WorkstationBinding, WorkstationState,
        };
        // `orcel tunnel allow` arguments for this route...
        let route = route(TUNNEL);
        let (device, epoch) = device_identity(TUNNEL);
        let options = AllowOptions {
            tunnel_id: None,
            remote_connection_id: remote_connection_id(TUNNEL),
            workspaces: vec!["default".into()],
            scopes: Some(vec!["orcel.read".into()]),
            minutes: 15,
            read_mode: "session".into(),
        };
        let args = lease_arguments(&options, &route, &device, epoch).unwrap();
        let text = |name: &str| args[name].as_str().unwrap().to_owned();
        // ...as orceld parses them into a lease.
        let request = LeaseRequest {
            principal: text("principal"),
            remote_connection_id: text("remote_connection_id"),
            device_id: text("device_id"),
            device_epoch: args["device_epoch"].as_u64().unwrap(),
            provider_kind: text("provider_kind"),
            client_profile_id: text("client_profile_id"),
            client_profile_revision: args["client_profile_revision"].as_u64().unwrap(),
            tool_surface_profile: text("tool_surface_profile"),
            scope_ceiling: vec!["orcel.read".into()],
            workspace_ids: vec!["default".into()],
            read_mode: ReadMode::Session,
            duration_ms: 15 * 60 * 1000,
            tunnel_id: args["tunnel_id"].as_str().map(str::to_owned),
        };
        let workstation = WorkstationBinding {
            session_id: 1,
            logon_id: 7,
        };
        let trust = |_: &str| Some(1);
        let env = GateEnvironment {
            now_ms: 1_000,
            policy_revision: "rev",
            workspace_set_digest: "digest",
            workstation: WorkstationState::Unlocked(workstation),
            trust_revision: &trust,
        };
        let lease = build_lease(&request, "lease-1".into(), &env, &["default".into()]).unwrap();
        let envelope = |capability: &str, operation: &str| RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments: json!({}),
        };
        let remote = context(&route);
        // No lease: inactive.
        let denied = check_remote_dispatch(&[], &envelope("fs.read", "read"), &remote, &env);
        assert_eq!(denied.unwrap_err().code, FailureCode::RemoteSessionInactive);
        // The tunnel's lease admits a core read in its ceiling...
        check_remote_dispatch(
            std::slice::from_ref(&lease),
            &envelope("fs.read", "read"),
            &remote,
            &env,
        )
        .unwrap();
        // ...but no shape outside the ceiling or outside `core`.
        for (capability, operation) in [
            ("fs.write", "write"),
            ("clipboard", "read"),
            ("clipboard", "write"),
            ("network", "fetch"),
        ] {
            let error = check_remote_dispatch(
                std::slice::from_ref(&lease),
                &envelope(capability, operation),
                &remote,
                &env,
            )
            .unwrap_err();
            assert_eq!(
                error.code,
                FailureCode::RemoteSessionInactive,
                "{capability}"
            );
        }
    }

    #[test]
    fn different_tunnels_get_different_routes() {
        let other = route("tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        let route = route(TUNNEL);
        for field in ["principal", "remoteConnectionId", "deviceId"] {
            assert_ne!(route[field], other[field], "{field}");
        }
    }

    /// SG-000135 OB-09: a tunnel revoke reaches the core and browser_full
    /// connections, and a failed one never keeps the other from being
    /// revoked.
    #[test]
    fn ob09_a_tunnel_revoke_covers_both_derived_connections() {
        let connections = all_connections(TUNNEL);
        let ids: Vec<&str> = connections
            .iter()
            .map(|connection| connection.connection_id.as_str())
            .collect();
        let browser = remote_connection_id_for(TUNNEL, "browser_full").unwrap();
        assert_eq!(ids, [remote_connection_id(TUNNEL).as_str(), &browser]);
        let mut seen = Vec::new();
        let report = revoke_each(&connections, |connection| {
            seen.push(connection.to_owned());
            Ok(1)
        });
        assert_eq!((report.revoked(), seen.len()), (2, 2));
        assert!(report.failed_ids().is_empty() && report.check().is_ok());
        // A failed revoke, first or second: the other is still revoked, and
        // the report and the error say exactly which is which.
        for bad in 0..2 {
            let mut calls = 0;
            let report = revoke_each(&connections, |_| {
                calls += 1;
                if calls - 1 == bad {
                    Err(RevokeFailure::Refused(LifecycleError::state("said no")))
                } else {
                    Ok(1)
                }
            });
            assert_eq!(calls, 2);
            assert_eq!(report.revoked(), 1);
            assert_eq!(report.failed_ids(), [ids[bad]]);
            let message = report.check().unwrap_err().message;
            assert!(message.contains(&format!("{} (", ids[bad])), "{message}");
            let (live, ended) = (ids[bad], ids[1 - bad]);
            let says = |id: &str, what: &str| {
                message
                    .split(id)
                    .nth(1)
                    .is_some_and(|rest| rest.split('.').next().unwrap_or("").contains(what))
            };
            assert!(says(ended, "1 lease(s) ended"), "{message}");
            assert!(says(live, "NOT revoked (said no)"), "{message}");
            assert!(message.contains("may still be active"), "{message}");
        }
    }

    /// SG-000135 OB-09: the leases both connections hold are revoked in the
    /// store orceld keeps, and another tunnel's lease is not.
    #[test]
    fn ob09_the_revoke_ends_both_leases_and_no_other_tunnels() {
        use orcel_policy::remote_session::{
            build_lease, revoke_leases, GateEnvironment, LeaseRequest, ReadMode,
            WorkstationBinding, WorkstationState,
        };
        let trust = |_: &str| Some(1);
        let env = GateEnvironment {
            now_ms: 1_000,
            policy_revision: "rev",
            workspace_set_digest: "digest",
            workstation: WorkstationState::Unlocked(WorkstationBinding {
                session_id: 1,
                logon_id: 7,
            }),
            trust_revision: &trust,
        };
        let lease = |tunnel: &str, profile: &str| {
            let route = route_for(tunnel, profile).unwrap();
            let text = |name: &str| route[name].as_str().unwrap().to_owned();
            let request = LeaseRequest {
                principal: text("principal"),
                remote_connection_id: text("remoteConnectionId"),
                device_id: text("deviceId"),
                device_epoch: DEVICE_EPOCH,
                provider_kind: text("providerKind"),
                client_profile_id: text("clientProfileId"),
                client_profile_revision: CLIENT_PROFILE_REVISION,
                tool_surface_profile: text("toolSurfaceProfile"),
                scope_ceiling: vec!["orcel.read".into()],
                workspace_ids: vec!["default".into()],
                read_mode: ReadMode::Session,
                duration_ms: 15 * 60 * 1000,
                tunnel_id: (profile == "browser_full").then(|| tunnel.to_owned()),
            };
            build_lease(
                &request,
                format!("{tunnel}-{profile}"),
                &env,
                &["default".into()],
            )
            .unwrap()
        };
        let other = "tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let mut leases = vec![
            lease(TUNNEL, "core"),
            lease(TUNNEL, "browser_full"),
            lease(other, "core"),
        ];
        let report = revoke_each(&all_connections(TUNNEL), |connection| {
            let (next, count) = revoke_leases(&leases, Some(connection), 1_000);
            leases = next;
            Ok(count as u64)
        });
        assert!(report.check().is_ok());
        assert_eq!(report.revoked(), 2);
        let revoked: Vec<bool> = leases.iter().map(|lease| lease.revoked).collect();
        assert_eq!(revoked, [true, true, false]);
    }

    /// SG-000135 OB-09: a setup that changes the profile or the tunnel id
    /// revokes the previous route's leases; a first or an unchanged setup
    /// revokes nothing.
    #[test]
    fn ob09_a_setup_that_changes_the_route_revokes_the_old_one() {
        let other = "tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let none: Vec<TunnelConnection> = Vec::new();
        assert_eq!(connections_revoked_by_setup(None, TUNNEL, "core"), none);
        for profile in TUNNEL_PROFILES {
            assert_eq!(
                connections_revoked_by_setup(Some((TUNNEL, profile)), TUNNEL, profile),
                none
            );
            // The tunnel id changed: the old tunnel's routes.
            assert_eq!(
                connections_revoked_by_setup(Some((TUNNEL, profile)), other, profile),
                all_connections(TUNNEL)
            );
        }
        // Only the profile changed, either way.
        for (old, new) in [("core", "browser_full"), ("browser_full", "core")] {
            let revoked = connections_revoked_by_setup(Some((TUNNEL, old)), TUNNEL, new);
            assert!(revoked.iter().any(|connection| {
                Some(&connection.connection_id) == remote_connection_id_for(TUNNEL, old).as_ref()
            }));
            assert_eq!(revoked, all_connections(TUNNEL));
        }
    }

    /// SG-000135 OB-09: a setup that changes the id, the profile or the key is
    /// refused unless the supervisor has certainly gone; an unchanged one is
    /// not, and does not ask.
    #[test]
    fn ob09_a_changing_setup_needs_the_supervisor_gone() {
        let other = "tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let same = Some((TUNNEL, "core"));
        let key: Option<&[u8]> = Some(b"key");
        assert!(!setup_changes(same, TUNNEL, "core", key, "key"));
        for changed in [
            setup_changes(None, TUNNEL, "core", key, "key"),
            setup_changes(same, other, "core", key, "key"),
            setup_changes(same, TUNNEL, "browser_full", key, "key"),
            setup_changes(same, TUNNEL, "core", key, "key2"),
            setup_changes(same, TUNNEL, "core", Some(b"key\n"), "key"),
            setup_changes(same, TUNNEL, "core", None, "key"),
        ] {
            assert!(changed);
        }
        let unreadable = || Err(LifecycleError::state("the record is not readable"));
        assert!(setup_allowed(true, || Ok(Observed::Gone)).is_ok());
        for observed in [Observed::Live, Observed::Unknown] {
            let error = setup_allowed(true, || Ok(observed)).unwrap_err();
            assert_eq!(error.kind, crate::ErrorKind::Conflict);
            for said in [
                "Nothing was changed",
                "`orcel stop`",
                "`orcel tunnel setup`",
            ] {
                assert!(error.message.contains(said), "{}", error.message);
            }
            assert_eq!(
                error.message.contains("could not tell"),
                observed == Observed::Unknown
            );
        }
        let error = setup_allowed(true, unreadable).unwrap_err();
        assert!(error.message.contains("the record is not readable"));
        assert!(error.message.contains("Nothing was changed"));
        // Unchanged: whatever runs.
        let asked = std::cell::Cell::new(false);
        assert!(setup_allowed(false, || {
            asked.set(true);
            unreadable()
        })
        .is_ok());
        assert!(!asked.get());
    }

    fn configured(tunnel_id: &str, profile: &str) -> Config {
        Config {
            tunnel: Some(crate::config::TunnelSettings {
                client: std::path::PathBuf::from("/fake/tunnel-client"),
                tunnel_id: tunnel_id.into(),
                profile: profile.into(),
            }),
            ..Config::default()
        }
    }

    /// SG-000135 OB-09: a launch pin matches only the setup it was made for:
    /// the same tunnel id, profile and key. None, a malformed one and one of
    /// another launch's parts refuse; the key is not in it.
    #[test]
    fn ob09_a_launch_pin_matches_only_its_own_setup() {
        let other = "tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let config = configured(TUNNEL, "core");
        let key: Option<&[u8]> = Some(b"sk-key");
        let pin = launch_pin(&config, key, "n1").unwrap();
        assert!(check_launch_pin(&config, key, Some(&pin)).is_ok());
        let second = launch_pin(&config, key, "n2").unwrap();
        assert_ne!(pin, second);
        assert!(check_launch_pin(&config, key, Some(&second)).is_ok());
        assert!(!pin.contains("sk-key"));
        let says = |config: &Config, key: Option<&[u8]>, pin: Option<&str>| {
            let message = check_launch_pin(config, key, pin).unwrap_err().message;
            assert!(!message.contains("sk-key"), "{message}");
            message
        };
        for (config, key) in [
            (configured(other, "core"), key),
            (configured(TUNNEL, "browser_full"), key),
            (config.clone(), Some(&b"sk-key2"[..])),
            (config.clone(), Some(&b"sk-key\n"[..])),
        ] {
            let said = says(&config, key, Some(&pin));
            assert!(said.contains("is not the one"), "{said}");
            assert!(said.contains("`orcel stop`"), "{said}");
        }
        let (salt, digest) = pin.split_once('.').unwrap();
        let (other_salt, _) = second.split_once('.').unwrap();
        for bad in [
            "",
            ".",
            salt,
            digest,
            &format!("{salt}."),
            &format!(".{digest}"),
            &format!("{other_salt}.{digest}"),
            &format!("{pin}0"),
            &pin.to_ascii_uppercase(),
        ] {
            says(&config, key, Some(bad));
        }
        assert!(says(&config, key, None).contains("not started by `orcel start`"));
        assert!(says(&config, None, Some(&pin)).contains("key is missing"));
        assert!(says(&Config::default(), key, Some(&pin)).contains("not configured"));
        assert!(launch_pin(&config, None, "n").is_err());
        assert!(launch_pin(&Config::default(), key, "n").is_err());
        // The parts are told apart: moving bytes between them is a change.
        assert_ne!(
            pin_digest("s", TUNNEL, "core", b"x"),
            pin_digest("s", &format!("{TUNNEL}c"), "ore", b"x")
        );
    }

    /// SG-000135 OB-09: a revoke that orceld's audit chain refuses says which
    /// orceld commands to run, whether orceld answers or does not start; any
    /// other failure is left as it is.
    #[test]
    fn ob09_a_broken_audit_chain_names_the_way_back() {
        let orceld = Path::new("/x/Orcel/versions/0.1.0/orceld");
        let broken = orcel_audit::chain::ChainError::Broken {
            seq: 3,
            reason: "digest".into(),
        };
        let answered = revoke_reply(Ok(json!({"ok": false, "error": {
            "code": "INTERNAL_ERROR",
            "message": format!("audit write failed before dispatch; nothing was dispatched: {broken}"),
        }})));
        let not_started = revoke_reply(Err(LifecycleError::state(
            "orceld exited without a response (orceld: orceld fatal: initialize audit log: busy)",
        )));
        for reply in [answered, not_started] {
            let mut reply = Some(reply);
            let report = revoke_each(&all_connections(TUNNEL)[..1], |_| {
                reply.take().unwrap_or(Ok(0))
            });
            let error = report.check().unwrap_err();
            for error in [
                with_audit_remedy(setup_failure(error.clone(), &report, true), orceld),
                with_audit_remedy(error, orceld),
            ] {
                for said in [
                    "`orceld audit-verify` says",
                    "`orceld audit-move-aside` keeps",
                    &orceld.display().to_string(),
                ] {
                    assert!(error.message.contains(said), "{}", error.message);
                }
            }
        }
        let other = LifecycleError::state("orceld POLICY_DENIED: no");
        assert_eq!(
            with_audit_remedy(other.clone(), orceld).message,
            other.message
        );
    }

    /// SG-000135 OB-09: the old route is revoked before the new one is saved,
    /// and nothing is saved when a revoke fails, so the old id stays
    /// reachable; a failed save leaves the revoke done and reported.
    #[test]
    fn ob09_the_old_route_is_revoked_before_the_new_one_is_saved() {
        use std::cell::RefCell;
        let replaced = all_connections(TUNNEL);
        let steps = RefCell::new(Vec::new());
        let (report, result) = change_route(
            &replaced,
            |_| {
                steps.borrow_mut().push("revoke");
                Ok(1)
            },
            || {
                steps.borrow_mut().push("save");
                Ok(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(report.revoked(), 2);
        assert_eq!(*steps.borrow(), ["revoke", "revoke", "save"]);
        // One revoke fails: both were tried, nothing is saved.
        let calls = RefCell::new(0);
        let (report, result) = change_route(
            &replaced,
            |_| {
                *calls.borrow_mut() += 1;
                if *calls.borrow() == 1 {
                    Err(RevokeFailure::Refused(LifecycleError::state("said no")))
                } else {
                    Ok(0)
                }
            },
            || Err(LifecycleError::internal("saved after a failed revoke")),
        );
        assert_eq!(*calls.borrow(), 2);
        assert_eq!(report.failed_ids().len(), 1);
        assert!(result.unwrap_err().message.contains("NOT revoked"));
        // The save fails: the revoke is done, and the report says so.
        let (report, result) =
            change_route(&replaced, |_| Ok(1), || Err(LifecycleError::state("disk")));
        assert_eq!(report.revoked(), 2);
        assert_eq!(result.unwrap_err().message, "disk");
    }

    /// SG-000135 OB-09: a revoke with no answer, an unreadable one or an
    /// internal error is reported as not confirmed, never as refused and
    /// never as done; a typed refusal is reported as not revoked.
    #[test]
    fn ob09_an_unconfirmed_revoke_is_never_called_refused_or_done() {
        let text = |reply: Result<Value, LifecycleError>| {
            let mut reply = Some(reply);
            let one = &all_connections(TUNNEL)[..1];
            let report = revoke_each(one, |_| match reply.take() {
                Some(reply) => revoke_reply(reply),
                None => Ok(0),
            });
            (report.describe(), report.check().is_ok())
        };
        let timeout = || LifecycleError::state("orceld did not respond within the time limit");
        let unreadable = || LifecycleError::state("orceld response is not JSON: expected value");
        for reply in [
            Err(timeout()),
            Err(unreadable()),
            Ok(json!({})),
            Ok(json!({"ok": true, "result": {}})),
            Ok(json!({"ok": false})),
            Ok(json!({"error": {"code": "CAPABILITY_DENIED"}})),
            Ok(json!({"ok": false, "error": {"code": "INTERNAL_ERROR", "message": "replace"}})),
        ] {
            let shown = format!("{reply:?}");
            let (said, ok) = text(reply);
            assert!(!ok, "{shown}");
            assert!(
                said.contains("could not be confirmed as revoked"),
                "{shown}: {said}"
            );
            assert!(said.contains("may still be active"), "{said}");
            assert!(
                !said.contains("NOT revoked") && !said.contains("ended."),
                "{said}"
            );
        }
        let (said, ok) = text(Ok(
            json!({"ok": false, "error": {"code": "POLICY_DENIED", "message": "no"}}),
        ));
        assert!(!ok && said.contains("NOT revoked (orceld POLICY_DENIED: no)"));
        assert!(!said.contains("could not be confirmed"));
        let (said, ok) = text(Ok(json!({"ok": true, "result": {"revoked": 2}})));
        assert!(ok && said.contains("2 lease(s) ended."));
    }

    /// SG-000135 OB-09: a failed setup says once whether the previous setup
    /// is in place and what happened to its leases.
    #[test]
    fn ob09_a_setup_failure_says_what_was_kept_and_never_contradicts_itself() {
        let connections = all_connections(TUNNEL);
        let ended = revoke_each(&connections, |_| Ok(1));
        let failed = revoke_each(&connections, |_| {
            Err(RevokeFailure::Unconfirmed(LifecycleError::state("timeout")))
        });
        let none = RevokeReport::default();
        for (report, error) in [
            (&ended, LifecycleError::state("disk")),
            (&failed, failed.check().unwrap_err()),
            (&none, LifecycleError::state("disk")),
        ] {
            for restored in [true, false] {
                let said = setup_failure(error.clone(), report, restored).message;
                assert_eq!(said.contains("as they were before"), restored, "{said}");
                assert_eq!(
                    said.contains("could not be fully restored"),
                    !restored,
                    "{said}"
                );
                assert!(!said.contains("was not changed"), "{said}");
                for connection in report
                    .ended
                    .iter()
                    .map(|(connection, _)| connection)
                    .chain(report.failed.iter().map(|(connection, _)| connection))
                {
                    let id = &connection.connection_id;
                    assert_eq!(said.matches(id.as_str()).count(), 1, "{said}");
                }
            }
        }
    }

    /// SG-000135 OB-09: a `browser_full` tunnel route is a valid remote
    /// context under its own connection id and client profile, its lease
    /// (from `orcel tunnel allow`) admits the remote-safe broker shapes only,
    /// and the core route and lease are unchanged.
    #[test]
    fn ob09_a_browser_full_tunnel_route_is_separate_and_admits_only_broker_shapes() {
        use crate::remote::{lease_arguments, AllowOptions};
        use orcel_contracts::{RequestEnvelope, INTERNAL_PROTOCOL_VERSION};
        use orcel_policy::remote_session::{
            build_lease, check_remote_dispatch, GateEnvironment, LeaseRequest, ReadMode,
            WorkstationBinding, WorkstationState,
        };
        assert_eq!(route_for(TUNNEL, "core"), Some(route(TUNNEL)));
        assert_eq!(
            remote_connection_id_for(TUNNEL, "core"),
            Some(remote_connection_id(TUNNEL))
        );
        for unmapped in ["browser_structured", "desktop_structured", "", "Core"] {
            assert_eq!(route_for(TUNNEL, unmapped), None);
            assert!(!is_tunnel_profile(unmapped));
        }
        let browser = route_for(TUNNEL, "browser_full").unwrap();
        validate_remote_context(&context(&browser)).unwrap();
        let core = route(TUNNEL);
        assert_eq!(browser["toolSurfaceProfile"], "browser_full");
        assert_eq!(
            browser["scopeCeiling"],
            json!(["orcel.read", "orcel.execute"])
        );
        assert_ne!(browser["remoteConnectionId"], core["remoteConnectionId"]);
        assert_ne!(browser["clientProfileId"], core["clientProfileId"]);
        assert_eq!(browser["deviceId"], core["deviceId"]);
        assert_eq!(
            browser["remoteConnectionId"].as_str(),
            remote_connection_id_for(TUNNEL, "browser_full").as_deref()
        );
        // `orcel tunnel allow` on a browser_full tunnel...
        let (device, epoch) = device_identity(TUNNEL);
        let options = AllowOptions {
            tunnel_id: Some(TUNNEL.into()),
            remote_connection_id: remote_connection_id_for(TUNNEL, "browser_full").unwrap(),
            workspaces: vec!["default".into()],
            scopes: None,
            minutes: 15,
            read_mode: "session".into(),
        };
        let args = lease_arguments(&options, &browser, &device, epoch).unwrap();
        let text = |name: &str| args[name].as_str().unwrap().to_owned();
        let request = LeaseRequest {
            principal: text("principal"),
            remote_connection_id: text("remote_connection_id"),
            device_id: text("device_id"),
            device_epoch: args["device_epoch"].as_u64().unwrap(),
            provider_kind: text("provider_kind"),
            client_profile_id: text("client_profile_id"),
            client_profile_revision: args["client_profile_revision"].as_u64().unwrap(),
            tool_surface_profile: text("tool_surface_profile"),
            scope_ceiling: vec!["orcel.read".into(), "orcel.execute".into()],
            workspace_ids: vec!["default".into()],
            read_mode: ReadMode::Session,
            duration_ms: 15 * 60 * 1000,
            tunnel_id: args["tunnel_id"].as_str().map(str::to_owned),
        };
        assert_eq!(request.tool_surface_profile, "browser_full");
        let trust = |_: &str| Some(1);
        let env = GateEnvironment {
            now_ms: 1_000,
            policy_revision: "rev",
            workspace_set_digest: "digest",
            workstation: WorkstationState::Unlocked(WorkstationBinding {
                session_id: 1,
                logon_id: 7,
            }),
            trust_revision: &trust,
        };
        let lease = build_lease(&request, "lease-b".into(), &env, &["default".into()]).unwrap();
        let envelope = |capability: &str, operation: &str| RequestEnvelope {
            version: INTERNAL_PROTOCOL_VERSION,
            request_id: "r".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments: json!({}),
        };
        let remote = context(&browser);
        // ...admits a browser read and action...
        for operation in ["snapshot", "click"] {
            assert!(check_remote_dispatch(
                std::slice::from_ref(&lease),
                &envelope("browser.session", operation),
                &remote,
                &env
            )
            .is_ok());
        }
        // ...but no core shape and no persistent profile shape, and the core
        // route's context never uses it.
        for (capability, operation) in [
            ("fs.read", "read"),
            ("process.spawn", "spawn"),
            ("browser.session", "profile_delete"),
        ] {
            assert!(check_remote_dispatch(
                std::slice::from_ref(&lease),
                &envelope(capability, operation),
                &remote,
                &env
            )
            .is_err());
        }
        assert!(check_remote_dispatch(
            std::slice::from_ref(&lease),
            &envelope("browser.session", "snapshot"),
            &context(&core),
            &env
        )
        .is_err());
    }
}
