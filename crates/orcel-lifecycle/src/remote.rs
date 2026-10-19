//! SG-000055 local remote-session commands (`orcel remote ...`).
//!
//! `allow` asks `orceld` to create a finite remote-session lease for one
//! locally paired connection; `orceld` requires STRONG platform presence
//! (Windows Hello) and the remote side can never satisfy it. `revoke` and
//! `status` are authority-reducing or read-only. `connect` starts the
//! outbound-only device uplink, which opens no listener.
//!
//! The uplink configuration and the device key record live under the Orcel
//! state directory. Only public fields (route identifiers, device identifier,
//! epoch) are read here; the private device key is never read, printed, or
//! logged by the lifecycle CLI. Since XP-19 the private key lives in the OS
//! secret store behind `orceld` (`secret` capability, name
//! [`DEVICE_KEY_SECRET`]); `orcel remote migrate-secrets` moves a key that an
//! earlier version left in the record into it.

use crate::config::Config;
use crate::install::Installer;
use crate::layout::Layout;
use crate::platform::MIN_NODE_MAJOR;
use crate::LifecycleError;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const UPLINK_SCHEMA: &str = "orcel-uplink/1";
pub const MAX_LEASE_MINUTES: u64 = 15;
/// XP-19 fixed secret name of the device private key in `orceld`.
pub const DEVICE_KEY_SECRET: &str = "device.key";

pub fn uplink_config_path(layout: &Layout) -> PathBuf {
    layout.state_dir().join("remote").join("uplink.json")
}

pub fn device_key_path(layout: &Layout) -> PathBuf {
    layout.state_dir().join("device").join("device_key.json")
}

pub fn device_revocations_path(layout: &Layout) -> PathBuf {
    layout.state_dir().join("device").join("revocations.json")
}

fn read_json(path: &Path, what: &str) -> Result<Value, LifecycleError> {
    let bytes = std::fs::read(path).map_err(|_| {
        LifecycleError::state(format!(
            "{what} is not configured; pair a remote connection first (PAIRING_REQUIRED)"
        ))
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|_| LifecycleError::state(format!("{what} is corrupt (PAIRING_REQUIRED)")))
}

/// Public device identity fields from the protected device key record.
pub fn device_identity(path: &Path) -> Result<(String, u64), LifecycleError> {
    let record = read_json(path, "the device key")?;
    let device_id = record
        .get("deviceId")
        .and_then(Value::as_str)
        .filter(|id| {
            id.len() == 36
                && id.starts_with("dev-")
                && id[4..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| LifecycleError::state("the device key record is malformed"))?;
    let epoch = record
        .get("epoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch >= 1)
        .ok_or_else(|| LifecycleError::state("the device key record is malformed"))?;
    Ok((device_id.to_owned(), epoch))
}

/// One paired connection from the uplink configuration.
pub fn paired_connection(path: &Path, remote_connection_id: &str) -> Result<Value, LifecycleError> {
    let uplink = read_json(path, "the remote uplink configuration")?;
    if uplink.get("schema").and_then(Value::as_str) != Some(UPLINK_SCHEMA) {
        return Err(LifecycleError::state(
            "the remote uplink configuration has an unexpected schema",
        ));
    }
    uplink
        .get("connections")
        .and_then(Value::as_array)
        .and_then(|connections| {
            connections.iter().find(|connection| {
                connection.get("remoteConnectionId").and_then(Value::as_str)
                    == Some(remote_connection_id)
            })
        })
        .cloned()
        .ok_or_else(|| {
            LifecycleError::usage(format!(
                "remote connection {remote_connection_id} is not paired on this device"
            ))
        })
}

/// Options for `orcel remote allow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowOptions {
    pub remote_connection_id: String,
    pub workspaces: Vec<String>,
    pub scopes: Option<Vec<String>>,
    pub minutes: u64,
    pub read_mode: String,
}

/// Build the `remote.lease.create` arguments. Scopes default to the paired
/// ceiling and may only narrow it; the lease never exceeds 15 minutes.
pub fn lease_arguments(
    options: &AllowOptions,
    paired: &Value,
    device_id: &str,
    device_epoch: u64,
) -> Result<Value, LifecycleError> {
    if options.minutes == 0 || options.minutes > MAX_LEASE_MINUTES {
        return Err(LifecycleError::usage(
            "--minutes must be from 1 to 15; remote sessions are always finite",
        ));
    }
    if !matches!(
        options.read_mode.as_str(),
        "session" | "per_request" | "disabled"
    ) {
        return Err(LifecycleError::usage(
            "--read-mode must be session, per_request, or disabled",
        ));
    }
    if options.workspaces.is_empty() {
        return Err(LifecycleError::usage(
            "at least one --workspaces entry is required",
        ));
    }
    let field = |name: &str| -> Result<Value, LifecycleError> {
        paired
            .get(name)
            .cloned()
            .ok_or_else(|| LifecycleError::state(format!("paired connection lacks {name}")))
    };
    let ceiling: Vec<String> = paired
        .get("scopeCeiling")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let scopes = match &options.scopes {
        None => ceiling.clone(),
        Some(requested) => {
            if requested.is_empty() || !requested.iter().all(|scope| ceiling.contains(scope)) {
                return Err(LifecycleError::usage(
                    "--scopes may only narrow the paired scope ceiling",
                ));
            }
            requested.clone()
        }
    };
    Ok(json!({
        "principal": field("principal")?,
        "remote_connection_id": options.remote_connection_id,
        "device_id": device_id,
        "device_epoch": device_epoch,
        "provider_kind": field("providerKind")?,
        "client_profile_id": field("clientProfileId")?,
        "client_profile_revision": field("clientProfileRevision")?,
        "tool_surface_profile": field("toolSurfaceProfile")?,
        "scope_ceiling": scopes,
        "workspaces": options.workspaces,
        "read_mode": options.read_mode,
        "duration_seconds": options.minutes * 60,
    }))
}

/// Resolved launch for the outbound-only device uplink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UplinkLaunch {
    pub node: PathBuf,
    pub script: PathBuf,
    pub orceld: PathBuf,
    pub uplink_config: PathBuf,
    pub device_key: PathBuf,
    pub revocations: PathBuf,
}

pub fn resolve_uplink_launch(
    layout: &Layout,
    platform: &dyn crate::platform::Platform,
) -> Result<(UplinkLaunch, Config), LifecycleError> {
    let state = Installer::new(layout.clone(), platform).verify()?;
    let version_dir = layout.version_dir(&state.active.version);
    let node = PathBuf::from(&state.record.node_path);
    let node_version = platform.node_version(&node)?;
    if node_version.major < MIN_NODE_MAJOR {
        return Err(LifecycleError::prerequisite(format!(
            "Node.js {node_version} is older than the required {MIN_NODE_MAJOR}"
        )));
    }
    let config = Config::load(layout)?;
    config.check_workspaces_with_policy()?;
    let uplink_config = uplink_config_path(layout);
    let device_key = device_key_path(layout);
    device_identity(&device_key)?;
    read_json(&uplink_config, "the remote uplink configuration")?;
    Ok((
        UplinkLaunch {
            node,
            script: version_dir
                .join("app")
                .join("orcel-mcp")
                .join("dist")
                .join("entrypoints")
                .join("relay_device.js"),
            orceld: version_dir.join("orceld.exe"),
            uplink_config,
            device_key,
            revocations: device_revocations_path(layout),
        },
        config,
    ))
}

/// Run the uplink with inherited standard error and return its exit code.
pub fn run_uplink(launch: &UplinkLaunch, config: &Config) -> i32 {
    let mut env = crate::ipc::child_environment(config);
    env.insert(
        "ORCEL_DAEMON".into(),
        launch.orceld.to_string_lossy().into_owned(),
    );
    env.insert(
        "ORCEL_UPLINK_CONFIG".into(),
        launch.uplink_config.to_string_lossy().into_owned(),
    );
    env.insert(
        "ORCEL_DEVICE_KEY_PATH".into(),
        launch.device_key.to_string_lossy().into_owned(),
    );
    env.insert(
        "ORCEL_DEVICE_REVOCATIONS_PATH".into(),
        launch.revocations.to_string_lossy().into_owned(),
    );
    match Command::new(&launch.node)
        .arg(&launch.script)
        .env_clear()
        .envs(env)
        .status()
    {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("orcel remote connect: start Node.js: {error}");
            2
        }
    }
}

/// Relay origin recorded by `orcel remote enable`.
pub fn recorded_relay_origin(path: &Path) -> Result<String, LifecycleError> {
    let uplink = read_json(path, "the remote uplink configuration")?;
    uplink
        .get("relayOrigin")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| LifecycleError::state("the remote uplink configuration lacks relayOrigin"))
}

/// Validates the `--relay` origin shape before anything is authorized.
pub fn validate_relay_origin(origin: &str) -> Result<(), LifecycleError> {
    let ok_https = origin.starts_with("https://")
        && origin.len() > "https://".len()
        && !origin["https://".len()..].contains(['/', '?', '#', '@', ' ']);
    let ok_loopback = ["http://127.0.0.1:", "http://[::1]:"].iter().any(|prefix| {
        origin
            .strip_prefix(prefix)
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()))
    });
    if ok_https || ok_loopback {
        Ok(())
    } else {
        Err(LifecycleError::usage(
            "--relay must be an https origin (or an exact loopback http origin) with no path",
        ))
    }
}

/// `orcel remote enable|pair`: STRONG presence through `orceld`, then the
/// interactive enrollment entrypoint with inherited console I/O.
pub fn run_enrollment(
    layout: &Layout,
    platform: &dyn crate::platform::Platform,
    action: &str,
    relay: Option<String>,
    workspace: Option<String>,
) -> Result<i32, LifecycleError> {
    let state = Installer::new(layout.clone(), platform).verify()?;
    let version_dir = layout.version_dir(&state.active.version);
    let node = PathBuf::from(&state.record.node_path);
    let node_version = platform.node_version(&node)?;
    if node_version.major < MIN_NODE_MAJOR {
        return Err(LifecycleError::prerequisite(format!(
            "Node.js {node_version} is older than the required {MIN_NODE_MAJOR}"
        )));
    }
    let config = Config::load(layout)?;
    config.check_workspaces_with_policy()?;
    let relay_origin = match (action, relay) {
        ("enable", Some(origin)) => origin,
        ("enable", None) => return Err(LifecycleError::usage("--relay <origin> is required")),
        ("pair", None) => recorded_relay_origin(&uplink_config_path(layout))?,
        ("pair", Some(_)) => {
            return Err(LifecycleError::usage(
                "orcel remote pair uses the relay recorded by orcel remote enable",
            ))
        }
        _ => return Err(LifecycleError::usage("unknown remote enrollment action")),
    };
    validate_relay_origin(&relay_origin)?;
    let workspace = workspace
        .or_else(|| config.default_workspace().map(str::to_owned))
        .unwrap_or_else(|| "default".into());
    let orceld = version_dir.join("orceld.exe");
    eprintln!("Confirm with Windows Hello when prompted. Remote enrollment is a STRONG approval and cannot be granted remotely or by an agent.");
    let request = crate::ipc::request(
        &workspace,
        "remote.enrollment.authorize",
        "authorize",
        json!({ "action": action, "relay_origin": relay_origin }),
    );
    let response = crate::ipc::call(
        &orceld,
        &config,
        &request,
        std::time::Duration::from_secs(180),
    )?;
    crate::ipc::expect_ok(&response)?;
    let mut env = crate::ipc::child_environment(&config);
    // XP-19: the enrollment entrypoint stores the new private key through
    // this orceld; it never writes the key to a file.
    env.insert("ORCEL_DAEMON".into(), orceld.to_string_lossy().into_owned());
    env.insert(
        "ORCEL_DEVICE_KEY_PATH".into(),
        device_key_path(layout).to_string_lossy().into_owned(),
    );
    env.insert(
        "ORCEL_UPLINK_CONFIG".into(),
        uplink_config_path(layout).to_string_lossy().into_owned(),
    );
    let script = version_dir
        .join("app")
        .join("orcel-mcp")
        .join("dist")
        .join("entrypoints")
        .join("remote_admin.js");
    let mut command = Command::new(&node);
    command.arg(&script).arg(action);
    if action == "enable" {
        command
            .arg("--relay")
            .arg(&relay_origin)
            .arg("--workspace")
            .arg(&workspace);
    }
    match command.env_clear().envs(env).status() {
        Ok(status) => Ok(status.code().unwrap_or(1)),
        Err(error) => Err(LifecycleError::state(format!("start Node.js: {error}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_dir;

    fn paired() -> Value {
        json!({
            "principal": format!("rp-{}", "a".repeat(32)),
            "remoteConnectionId": format!("rc-{}", "b".repeat(32)),
            "providerKind": "generic",
            "clientProfileId": "profile-1",
            "clientProfileRevision": 1,
            "toolSurfaceProfile": "core",
            "scopeCeiling": ["orcel.read", "orcel.write"],
        })
    }

    fn options() -> AllowOptions {
        AllowOptions {
            remote_connection_id: format!("rc-{}", "b".repeat(32)),
            workspaces: vec!["default".into()],
            scopes: None,
            minutes: 15,
            read_mode: "session".into(),
        }
    }

    #[test]
    fn lease_arguments_default_to_the_paired_ceiling_and_cap_duration() {
        let device = format!("dev-{}", "c".repeat(32));
        let args = lease_arguments(&options(), &paired(), &device, 1).unwrap();
        assert_eq!(args["duration_seconds"], 900);
        assert_eq!(args["scope_ceiling"], json!(["orcel.read", "orcel.write"]));
        assert_eq!(args["device_id"], device);
        let mut narrowed = options();
        narrowed.scopes = Some(vec!["orcel.read".into()]);
        assert_eq!(
            lease_arguments(&narrowed, &paired(), &device, 1).unwrap()["scope_ceiling"],
            json!(["orcel.read"])
        );
        let mut widened = options();
        widened.scopes = Some(vec!["orcel.execute".into()]);
        assert!(lease_arguments(&widened, &paired(), &device, 1).is_err());
        let mut long = options();
        long.minutes = 16;
        assert!(lease_arguments(&long, &paired(), &device, 1).is_err());
        let mut zero = options();
        zero.minutes = 0;
        assert!(lease_arguments(&zero, &paired(), &device, 1).is_err());
        let mut mode = options();
        mode.read_mode = "forever".into();
        assert!(lease_arguments(&mode, &paired(), &device, 1).is_err());
    }

    #[test]
    fn relay_origins_are_https_or_exact_loopback_without_paths() {
        assert!(validate_relay_origin("https://relay.example.com").is_ok());
        assert!(validate_relay_origin("http://127.0.0.1:8787").is_ok());
        assert!(validate_relay_origin("http://[::1]:8787").is_ok());
        for bad in [
            "http://relay.example.com",
            "https://relay.example.com/path",
            "https://user@relay.example.com",
            "http://localhost:8787",
            "http://127.0.0.1:",
            "socks5://relay.example.com",
            "",
        ] {
            assert!(validate_relay_origin(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn device_identity_and_pairing_records_fail_closed() {
        let dir = temp_dir("remote-state");
        let key = dir.join("device_key.json");
        assert!(device_identity(&key).is_err());
        std::fs::write(&key, b"{").unwrap();
        assert!(device_identity(&key).is_err());
        std::fs::write(
            &key,
            serde_json::to_vec(&json!({"deviceId": format!("dev-{}", "c".repeat(32)), "epoch": 2, "privateKeyJwkBase64": "secret"})).unwrap(),
        )
        .unwrap();
        assert_eq!(device_identity(&key).unwrap().1, 2);
        let uplink = dir.join("uplink.json");
        assert!(paired_connection(&uplink, "rc-x").is_err());
        std::fs::write(
            &uplink,
            serde_json::to_vec(&json!({"schema": UPLINK_SCHEMA, "relayOrigin": "https://relay.example", "defaultWorkspace": "default", "connections": [paired()]})).unwrap(),
        )
        .unwrap();
        assert!(paired_connection(&uplink, &format!("rc-{}", "b".repeat(32))).is_ok());
        assert!(paired_connection(&uplink, &format!("rc-{}", "f".repeat(32))).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
