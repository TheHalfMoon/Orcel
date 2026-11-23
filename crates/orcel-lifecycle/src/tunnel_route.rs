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

use crate::LifecycleError;
use orcel_policy::remote_session::{
    REMOTE_PROFILE_BROWSER_FULL, REMOTE_PROFILE_CORE, REMOTE_SCOPES,
};
use serde_json::{json, Value};

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

/// SG-000135 OB-09: every remote connection id `tunnel_id` derives, one per
/// profile it may serve. Revoking a tunnel revokes all of them, so a lease
/// left from the profile it served before never outlives the revoke.
pub fn all_connections(tunnel_id: &str) -> Vec<String> {
    TUNNEL_PROFILES
        .iter()
        .filter_map(|profile| remote_connection_id_for(tunnel_id, profile))
        .collect()
}

/// SG-000135 OB-09: the connections `orcel tunnel setup` revokes: every one
/// of the previous tunnel's when the tunnel id or the profile changes, none
/// otherwise. `previous` is the previous tunnel id and profile.
pub fn connections_revoked_by_setup(
    previous: Option<(&str, &str)>,
    tunnel_id: &str,
    profile: &str,
) -> Vec<String> {
    match previous {
        Some((old_id, old_profile)) if old_id != tunnel_id || old_profile != profile => {
            all_connections(old_id)
        }
        _ => Vec::new(),
    }
}

/// Revoke every connection with `revoke` (which returns how many leases it
/// revoked), and add them up. A failure does not stop the rest; the first
/// one is returned after every connection was tried.
pub fn revoke_each(
    connections: &[String],
    mut revoke: impl FnMut(&str) -> Result<u64, LifecycleError>,
) -> Result<u64, LifecycleError> {
    let mut total = 0;
    let mut failed = None;
    for connection in connections {
        match revoke(connection) {
            Ok(count) => total += count,
            Err(error) => {
                failed.get_or_insert(error);
            }
        }
    }
    match failed {
        Some(error) => Err(error),
        None => Ok(total),
    }
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
        assert_eq!(
            connections,
            [
                remote_connection_id(TUNNEL),
                remote_connection_id_for(TUNNEL, "browser_full").unwrap()
            ]
        );
        let mut seen = Vec::new();
        let total = revoke_each(&connections, |connection| {
            seen.push(connection.to_owned());
            Ok(1)
        })
        .unwrap();
        assert_eq!((total, seen), (2, connections.clone()));
        let mut seen = Vec::new();
        let failed = revoke_each(&connections, |connection| {
            seen.push(connection.to_owned());
            if seen.len() == 1 {
                Err(LifecycleError::state("the first one failed"))
            } else {
                Ok(1)
            }
        })
        .unwrap_err();
        assert!(failed.message.contains("the first one failed"));
        assert_eq!(seen, connections, "the second was still revoked");
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
        let total = revoke_each(&all_connections(TUNNEL), |connection| {
            let (next, count) = revoke_leases(&leases, Some(connection));
            leases = next;
            Ok(count as u64)
        })
        .unwrap();
        assert_eq!(total, 2);
        let revoked: Vec<bool> = leases.iter().map(|lease| lease.revoked).collect();
        assert_eq!(revoked, [true, true, false]);
    }

    /// SG-000135 OB-09: a setup that changes the profile or the tunnel id
    /// revokes the previous route's leases; a first or an unchanged setup
    /// revokes nothing.
    #[test]
    fn ob09_a_setup_that_changes_the_route_revokes_the_old_one() {
        let other = "tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let none: Vec<String> = Vec::new();
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
            assert!(revoked.contains(&remote_connection_id_for(TUNNEL, old).unwrap()));
            assert_eq!(revoked, all_connections(TUNNEL));
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
