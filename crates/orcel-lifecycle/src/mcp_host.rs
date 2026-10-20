//! `orcel-mcp-host`: the stdio command the official tunnel client runs. It
//! resolves the install from its own location, verifies the whole installed
//! payload and the recorded Node.js runtime for every session, refuses to run
//! from an inactive version, and runs the compiled `orcel-mcp` app with the
//! validated Node.js runtime, the matching `orceld`, the configured
//! workspaces, and the sanitized environment. It never writes to stdout
//! itself, because stdout is the MCP channel.
//!
//! #395: this host serves only the tunnel, a remote transport. It always
//! launches the app as the `tunnel` transport with the tunnel's remote route
//! (`core` profile, remote context on every `orceld` request) and a closed
//! environment; nothing inherited from the tunnel client can select a local
//! profile or carry local authority such as the runtime session binding.

use crate::config::Config;
use crate::install::Installer;
use crate::layout::Layout;
use crate::platform::{Platform, MIN_NODE_MAJOR};
use crate::tunnel_route;
use crate::LifecycleError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The only `ORCEL_*` variables the tunnel host passes on from its own
/// sanitized environment. Everything else `ORCEL_*` (a local tool-surface
/// profile, the runtime session binding, provider configuration, a daemon
/// override) is dropped; the host then sets its own values.
const TUNNEL_HOST_ORCEL_ENV: [&str; 2] = ["ORCEL_WORKSPACES_JSON", "ORCEL_DEFAULT_WORKSPACE"];

/// The resolved launch for one MCP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLaunch {
    pub node: PathBuf,
    pub script: PathBuf,
    pub orceld: PathBuf,
}

/// Resolves and verifies the launch for a host binary located at `exe`.
pub fn resolve(
    exe: &Path,
    platform: &dyn Platform,
) -> Result<(HostLaunch, Config), LifecycleError> {
    let version_dir = exe
        .parent()
        .ok_or_else(|| LifecycleError::state("orcel-mcp-host has no parent directory"))?;
    let versions = version_dir
        .parent()
        .filter(|dir| dir.file_name().is_some_and(|name| name == "versions"))
        .ok_or_else(|| {
            LifecycleError::state("orcel-mcp-host is not inside an installed version")
        })?;
    let root = versions
        .parent()
        .ok_or_else(|| LifecycleError::state("install root not found"))?;
    let layout = Layout::new(root);
    let state = Installer::new(layout.clone(), platform).verify()?;
    if layout.version_dir(&state.active.version) != version_dir {
        return Err(LifecycleError::state(
            "orcel-mcp-host belongs to an inactive version; restart Orcel",
        ));
    }
    let node = PathBuf::from(&state.record.node_path);
    let node_version = platform.node_version(&node)?;
    if node_version.major < MIN_NODE_MAJOR {
        return Err(LifecycleError::prerequisite(format!(
            "Node.js {node_version} is older than the required {MIN_NODE_MAJOR}"
        )));
    }
    let config = Config::load(&layout)?;
    config.check_workspaces_with_policy()?;
    let launch = HostLaunch {
        node,
        script: version_dir
            .join("app")
            .join("orcel-mcp")
            .join("dist")
            .join("index.js"),
        orceld: version_dir.join("orceld.exe"),
    };
    Ok((launch, config))
}

/// The closed environment of the tunnel host's Node.js app, built from the
/// sanitized child environment `base`: OS execution variables, the
/// configured workspaces, the matching `orceld`, the `tunnel` transport, and
/// the tunnel's remote route. Fails closed when no tunnel is configured.
pub fn tunnel_environment(
    config: &Config,
    launch: &HostLaunch,
    mut base: BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, LifecycleError> {
    let tunnel = config.tunnel.as_ref().ok_or_else(|| {
        LifecycleError::state("the tunnel is not configured; orcel-mcp-host serves only the tunnel")
    })?;
    base.retain(|name, _| {
        let upper = name.to_ascii_uppercase();
        !upper.starts_with("ORCEL_") || TUNNEL_HOST_ORCEL_ENV.contains(&name.as_str())
    });
    base.insert(
        "ORCEL_DAEMON".into(),
        launch.orceld.to_string_lossy().into_owned(),
    );
    base.insert(
        tunnel_route::TRANSPORT_ENV.into(),
        tunnel_route::TUNNEL_TRANSPORT.into(),
    );
    base.insert(
        tunnel_route::ROUTE_ENV.into(),
        tunnel_route::route(&tunnel.tunnel_id).to_string(),
    );
    Ok(base)
}

/// Runs the MCP app for the current process and returns its exit code.
pub fn run() -> i32 {
    let platform = crate::host_platform();
    let outcome = std::env::current_exe()
        .map_err(|error| LifecycleError::io("locate orcel-mcp-host", error))
        .and_then(|exe| resolve(&exe, platform.as_ref()));
    let (launch, config) = match outcome {
        Ok(resolved) => resolved,
        Err(error) => {
            eprintln!("orcel-mcp-host: {}", error.message);
            return 2;
        }
    };
    let env = match tunnel_environment(&config, &launch, crate::ipc::child_environment(&config)) {
        Ok(env) => env,
        Err(error) => {
            eprintln!("orcel-mcp-host: {}", error.message);
            return 2;
        }
    };
    let status = Command::new(&launch.node)
        .arg(&launch.script)
        .env_clear()
        .envs(env)
        .status();
    match status {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("orcel-mcp-host: start Node.js: {error}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkspaceEntry;
    use crate::install::InstallOptions;
    use crate::test_support::{release_dir, temp_dir, FakePlatform};

    fn install(version: &str, platform: &FakePlatform) -> (Layout, PathBuf) {
        let base = temp_dir("mcp-host");
        let layout = Layout::new(base.join("Orcel"));
        Installer::new(layout.clone(), platform)
            .install(
                &release_dir(version),
                &InstallOptions {
                    node: Some(PathBuf::from("/fake/node")),
                    add_to_path: false,
                },
            )
            .unwrap();
        let project = base.join("project");
        std::fs::create_dir_all(&project).unwrap();
        Config {
            workspaces: vec![WorkspaceEntry {
                id: "default".into(),
                root: project,
            }],
            ..Config::default()
        }
        .save(&layout)
        .unwrap();
        let exe = layout.version_dir(version).join("orcel-mcp-host.exe");
        (layout, exe)
    }

    #[test]
    fn resolves_the_active_verified_version_payload() {
        let platform = FakePlatform::default();
        let (layout, exe) = install("0.2.0", &platform);
        let (launch, config) = resolve(&exe, &platform).unwrap();
        assert_eq!(
            launch.orceld,
            layout.version_dir("0.2.0").join("orceld.exe")
        );
        assert_eq!(config.default_workspace(), Some("default"));
    }

    #[test]
    fn tampered_payload_fails_closed_for_each_session() {
        let platform = FakePlatform::default();
        let (layout, exe) = install("0.2.0", &platform);
        std::fs::write(
            layout
                .version_dir("0.2.0")
                .join("app/orcel-mcp/dist/index.js"),
            b"replaced",
        )
        .unwrap();
        assert!(resolve(&exe, &platform).is_err());
    }

    fn tunnel_launch() -> HostLaunch {
        HostLaunch {
            node: PathBuf::from("/fake/node"),
            script: PathBuf::from("/fake/index.js"),
            orceld: PathBuf::from("/fake/orceld.exe"),
        }
    }

    fn tunnel_config() -> Config {
        Config {
            tunnel: Some(crate::config::TunnelSettings {
                client: PathBuf::from("/fake/tunnel-client"),
                tunnel_id: "tunnel_0123456789abcdefghijklmnopqrstuv".into(),
            }),
            ..Config::default()
        }
    }

    #[test]
    fn tunnel_host_is_always_the_remote_tunnel_transport() {
        // #395: whatever the tunnel client passed down, the host launches the
        // app as the `tunnel` transport with the derived route, and drops
        // every inherited variable that could widen it.
        let inherited = BTreeMap::from([
            ("PATH".to_string(), "bin".to_string()),
            ("ORCEL_WORKSPACES_JSON".to_string(), "[]".to_string()),
            ("ORCEL_DEFAULT_WORKSPACE".to_string(), "default".to_string()),
            (
                "ORCEL_TOOL_SURFACE_PROFILE".to_string(),
                "desktop_structured".to_string(),
            ),
            ("ORCEL_MCP_TRANSPORT".to_string(), "stdio".to_string()),
            ("orcel_mcp_transport".to_string(), "stdio".to_string()),
            ("ORCEL_ORCEL_SESSION_ID".to_string(), "session".to_string()),
            ("ORCEL_SEARCH_PROVIDERS_JSON".to_string(), "{}".to_string()),
            ("ORCEL_DAEMON".to_string(), "/elsewhere/orceld".to_string()),
            ("ORCEL_TUNNEL_ROUTE_JSON".to_string(), "{}".to_string()),
        ]);
        let env = tunnel_environment(&tunnel_config(), &tunnel_launch(), inherited).unwrap();
        let orcel: Vec<&str> = env
            .keys()
            .filter(|name| name.to_ascii_uppercase().starts_with("ORCEL_"))
            .map(String::as_str)
            .collect();
        assert_eq!(
            orcel,
            [
                "ORCEL_DAEMON",
                "ORCEL_DEFAULT_WORKSPACE",
                "ORCEL_MCP_TRANSPORT",
                "ORCEL_TUNNEL_ROUTE_JSON",
                "ORCEL_WORKSPACES_JSON",
            ]
        );
        assert_eq!(env["ORCEL_MCP_TRANSPORT"], "tunnel");
        assert_eq!(env["ORCEL_DAEMON"], "/fake/orceld.exe");
        assert_eq!(env["PATH"], "bin");
        let route: serde_json::Value =
            serde_json::from_str(&env["ORCEL_TUNNEL_ROUTE_JSON"]).unwrap();
        assert_eq!(
            route,
            tunnel_route::route("tunnel_0123456789abcdefghijklmnopqrstuv")
        );
        assert_eq!(route["toolSurfaceProfile"], "core");
    }

    #[test]
    fn tunnel_host_without_a_configured_tunnel_fails_closed() {
        let error =
            tunnel_environment(&Config::default(), &tunnel_launch(), BTreeMap::new()).unwrap_err();
        assert!(error.message.contains("not configured"));
    }

    #[test]
    fn inactive_version_foreign_location_and_old_node_fail_closed() {
        let platform = FakePlatform::default();
        let (layout, _) = install("0.2.0", &platform);
        let stale = layout.version_dir("0.1.0").join("orcel-mcp-host.exe");
        assert!(resolve(&stale, &platform).is_err());
        assert!(resolve(&std::env::temp_dir().join("orcel-mcp-host.exe"), &platform).is_err());
        let (_, exe) = install("0.2.0", &platform);
        let old_node = FakePlatform {
            node_major: 18,
            ..FakePlatform::default()
        };
        assert!(resolve(&exe, &old_node).is_err());
    }

    #[test]
    fn missing_workspaces_fail_closed() {
        let platform = FakePlatform::default();
        let (layout, exe) = install("0.2.0", &platform);
        Config::default().save(&layout).unwrap();
        assert!(resolve(&exe, &platform).is_err());
    }
}
