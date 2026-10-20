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

use orcel_policy::remote_session::{REMOTE_PROFILE_CORE, REMOTE_SCOPES};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Environment variable naming the MCP host's transport. `orcel-mcp-host`
/// always sets it to [`TUNNEL_TRANSPORT`]; local launches never set it.
pub const TRANSPORT_ENV: &str = "ORCEL_MCP_TRANSPORT";
/// The only value of [`TRANSPORT_ENV`].
pub const TUNNEL_TRANSPORT: &str = "tunnel";
/// Environment variable carrying the tunnel route (see [`route`]).
pub const ROUTE_ENV: &str = "ORCEL_TUNNEL_ROUTE_JSON";
/// Provider kind of the tunnel: ChatGPT, mapped to `core`.
pub const PROVIDER_KIND: &str = "openai";
/// Client profile of the tunnel route.
pub const CLIENT_PROFILE_ID: &str = "chatgpt-secure-mcp-tunnel";
pub const CLIENT_PROFILE_REVISION: u64 = 1;
/// The tunnel has no device key; its route epoch is fixed.
pub const DEVICE_EPOCH: u64 = 1;

fn derived_id(prefix: &str, label: &str, tunnel_id: &str) -> String {
    let mut hasher = Sha256::new();
    for field in ["ORCEL_TUNNEL_ROUTE_V1", label, tunnel_id] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    let digest = hasher.finalize();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}{hex}")
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
}
