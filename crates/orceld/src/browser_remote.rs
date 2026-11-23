//! SG-000135 OB-09: who a `browser_full` request comes from.
//!
//! A local request (stdio, loopback) is the MCP session it names. A remote
//! one came through the ChatGPT Secure MCP Tunnel (the relay serves `core`
//! only), passed the SG-000055 STRONG remote-session lease for the `browser_full`
//! profile (`remote_lease::gate_remote`) and carries the authenticated
//! remote context. Its broker client is bound to that context: the paired
//! connection, the principal and its own MCP session. So a remote client can
//! never name a local session or another remote client's session. Its client
//! reference is its own kind (`cl-remote-...`), which no Full Access lease
//! can name (`orcel_policy::browser_lease::client_ref`).
//!
//! What changes for a remote caller is recorded here and in
//! `browser_lease::FullAccess::for_remote_caller`: the session's receipts
//! name the remote origin, a persistent Orcel-managed profile is never used
//! remotely, and no Full Access lease ever covers an action (founder
//! decision 2026-11-23). Every approval the remote
//! request raises goes to the Windows dialog on the PC, marked remote
//! (`OriginStamp`); nothing the remote caller sends can answer one.

use orcel_contracts::{FailureCode, RemoteContext};
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};

/// The prefix of a remote caller's broker client. A local request whose
/// MCP session id starts with it is refused (`check_local_client`).
pub(crate) const REMOTE_CLIENT_PREFIX: &str =
    orcel_policy::browser_lease::REMOTE_BROKER_CLIENT_PREFIX;

/// Where a `browser_full` request comes from.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) enum Caller {
    /// A local MCP session (stdio or loopback).
    #[default]
    Local,
    /// A remote caller admitted by the SG-000055 remote-session lease.
    Remote(RemoteCaller),
}

/// The authenticated remote context a remote request carried, as orceld
/// keeps it for the session (never the request's own text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteCaller {
    pub provider: String,
    pub device: String,
    /// The paired (stable) remote connection.
    pub connection: String,
    pub principal: String,
}

impl Caller {
    /// The caller of a request with this remote context (`None`: local).
    pub(crate) fn of(remote: Option<&RemoteContext>) -> Self {
        match remote {
            None => Self::Local,
            Some(remote) => Self::Remote(RemoteCaller {
                provider: remote.provider_kind.clone(),
                device: remote.device_id.clone(),
                connection: remote.remote_connection_id.clone(),
                principal: remote.principal.clone(),
            }),
        }
    }

    pub(crate) fn is_remote(&self) -> bool {
        matches!(self, Self::Remote(_))
    }

    /// The broker client a request with MCP session `client_session_id`
    /// acts as: the session id itself locally; remotely, the session id
    /// bound to the paired connection and the principal.
    pub(crate) fn broker_client(&self, client_session_id: &str) -> String {
        match self {
            Self::Local => client_session_id.to_owned(),
            Self::Remote(remote) => format!(
                "{REMOTE_CLIENT_PREFIX}{}:{}:{client_session_id}",
                remote.connection, remote.principal
            ),
        }
    }

    /// What an intent and a receipt record of the caller: `local`, or the
    /// remote provider, device and paired connection (ids only).
    pub(crate) fn to_json(&self) -> Value {
        match self {
            Self::Local => json!({"kind": "local"}),
            Self::Remote(remote) => json!({
                "kind": "remote",
                "provider": remote.provider,
                "device": remote.device,
                "connection": remote.connection,
            }),
        }
    }
}

/// Refuse a local request whose MCP session id would read as a remote
/// caller's broker client (the profile gate's answer form).
pub(crate) fn check_local_client(
    client_session_id: &str,
) -> Result<(), (FailureCode, &'static str)> {
    if client_session_id.starts_with(REMOTE_CLIENT_PREFIX) {
        return Err((
            FailureCode::InvalidRequest,
            "a local MCP session id may not start with the remote caller prefix",
        ));
    }
    Ok(())
}

/// SG-000135 OB-09: refuse what a remote caller may never do in a
/// `browser_full` session, whatever its remote-session lease says: use or
/// manage a persistent Orcel-managed profile (it may be signed in to the
/// owner's accounts). The profile gate refuses the same before this.
pub(crate) fn refuse_remote_profile(
    caller: &Caller,
    action: &crate::browser_full::FullAction,
) -> Result<(), ProviderError> {
    use crate::browser_full::FullAction;
    if !caller.is_remote() {
        return Ok(());
    }
    let refused = match action {
        FullAction::Create { profile, .. } => profile.is_some(),
        FullAction::Profiles
        | FullAction::ProfileCreate { .. }
        | FullAction::ProfileDelete { .. } => true,
        _ => false,
    };
    if refused {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "SG-000135 OB-09: persistent Orcel-managed browser profiles are local-only; a remote caller gets an ephemeral session",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser_broker::SessionMode;
    use crate::browser_full::FullAction;

    fn remote() -> RemoteContext {
        RemoteContext {
            principal: format!("rp-{}", "a".repeat(32)),
            remote_connection_id: format!("rc-{}", "b".repeat(32)),
            connection_id: "cn-1".into(),
            device_id: format!("dev-{}", "c".repeat(32)),
            device_epoch: 1,
            provider_kind: "openai".into(),
            client_profile_id: "chatgpt".into(),
            client_profile_revision: 1,
            tool_surface_profile: "browser_full".into(),
            scopes: vec!["orcel.read".into(), "orcel.execute".into()],
        }
    }

    #[test]
    fn ob09_local_callers_are_unchanged() {
        let local = Caller::of(None);
        assert_eq!(local, Caller::Local);
        assert!(!local.is_remote());
        assert_eq!(local.broker_client("mcp-session-1"), "mcp-session-1");
        assert_eq!(local.to_json(), json!({"kind": "local"}));
        assert!(check_local_client("mcp-session-1").is_ok());
        assert!(check_local_client("remote:rc-x:rp-y:s").is_err());
        let create = FullAction::Create {
            task: None,
            mode: SessionMode::Shadow,
            profile: Some("work".into()),
            continue_from: None,
        };
        assert!(refuse_remote_profile(&local, &create).is_ok());
        assert!(refuse_remote_profile(&local, &FullAction::Profiles).is_ok());
    }

    #[test]
    fn ob09_a_remote_client_is_bound_to_its_connection_and_principal() {
        let caller = Caller::of(Some(&remote()));
        assert!(caller.is_remote());
        let client = caller.broker_client("s1");
        assert!(client.starts_with(REMOTE_CLIENT_PREFIX));
        assert!(client.contains(&remote().remote_connection_id));
        assert!(client.contains(&remote().principal));
        // Never a local session's id, and never another remote client's.
        assert_ne!(client, Caller::Local.broker_client("s1"));
        let mut other = remote();
        other.remote_connection_id = format!("rc-{}", "d".repeat(32));
        assert_ne!(client, Caller::of(Some(&other)).broker_client("s1"));
        let mut other = remote();
        other.principal = format!("rp-{}", "e".repeat(32));
        assert_ne!(client, Caller::of(Some(&other)).broker_client("s1"));
        // A local caller cannot name it.
        assert!(check_local_client(&client).is_err());
        // The client reference is the remote kind, which no lease can name.
        let reference = orcel_policy::browser_lease::client_ref(&client);
        assert_ne!(reference, orcel_policy::browser_lease::client_ref("s1"));
        assert!(orcel_policy::browser_lease::is_remote_client_ref(
            &reference
        ));
        assert!(!orcel_policy::browser_lease::is_client_ref(&reference));
    }

    #[test]
    fn ob09_receipts_name_the_remote_origin() {
        let caller = Caller::of(Some(&remote()));
        assert_eq!(
            caller.to_json(),
            json!({
                "kind": "remote",
                "provider": "openai",
                "device": remote().device_id,
                "connection": remote().remote_connection_id,
            })
        );
    }

    #[test]
    fn ob09_a_remote_caller_never_uses_a_persistent_profile() {
        let caller = Caller::of(Some(&remote()));
        let named = FullAction::Create {
            task: None,
            mode: SessionMode::Shadow,
            profile: Some("work".into()),
            continue_from: None,
        };
        let ephemeral = FullAction::Create {
            task: Some("Book a table".into()),
            mode: SessionMode::Visible,
            profile: None,
            continue_from: None,
        };
        for refused in [
            named,
            FullAction::Profiles,
            FullAction::ProfileCreate {
                name: "work".into(),
            },
            FullAction::ProfileDelete {
                name: "work".into(),
            },
        ] {
            let error = refuse_remote_profile(&caller, &refused).unwrap_err();
            assert_eq!(error.code, FailureCode::CapabilityDenied);
        }
        assert!(refuse_remote_profile(&caller, &ephemeral).is_ok());
    }
}
