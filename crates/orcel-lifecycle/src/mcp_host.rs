//! `orcel-mcp-host`: the stdio command the official tunnel client runs. It
//! resolves the install from its own location, verifies the whole installed
//! payload and the recorded Node.js runtime for every session, refuses to run
//! from an inactive version, and runs the compiled `orcel-mcp` app with the
//! validated Node.js runtime, the matching `orceld`, the configured
//! workspaces, and the sanitized environment. It never writes to stdout
//! itself, because stdout is the MCP channel.

use crate::config::Config;
use crate::install::Installer;
use crate::layout::Layout;
use crate::platform::{Platform, MIN_NODE_MAJOR};
use crate::LifecycleError;
use std::path::{Path, PathBuf};
use std::process::Command;

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

/// WI-06: the marker that tells the edge and orceld they serve the tunnel.
pub const MCP_HOST_ENV: &str = "ORCEL_MCP_HOST";

/// The Node.js environment for one tunnel session: the sanitized child
/// environment, the matching `orceld`, the tunnel marker, and never the
/// search provider configuration. Tunnel requests carry no remote context,
/// so web search must not be reachable on this path (the edge hides
/// `web_search` and orceld refuses `search/*` under the marker).
pub fn host_environment(
    config: &Config,
    orceld: &Path,
) -> std::collections::BTreeMap<String, String> {
    let mut env = crate::ipc::child_environment(config);
    env.remove("ORCEL_SEARCH_PROVIDERS_JSON");
    env.insert("ORCEL_DAEMON".into(), orceld.to_string_lossy().into_owned());
    env.insert(MCP_HOST_ENV.into(), "tunnel".into());
    env
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
    let env = host_environment(&config, &launch.orceld);
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
    fn wi06_tunnel_host_marks_the_launch_and_drops_search_configuration() {
        let config = Config::default();
        let env = host_environment(&config, Path::new("/x/orceld.exe"));
        assert_eq!(env.get(MCP_HOST_ENV).map(String::as_str), Some("tunnel"));
        assert!(!env.contains_key("ORCEL_SEARCH_PROVIDERS_JSON"));
        assert_eq!(
            env.get("ORCEL_DAEMON").map(String::as_str),
            Some("/x/orceld.exe")
        );
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
