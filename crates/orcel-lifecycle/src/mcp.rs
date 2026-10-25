//! Supported local stdio entrypoint (`orcel mcp stdio`).
//!
//! This command launches the authoritative Orcel MCP server for local AI
//! clients without requiring any tunnel. It resolves the active verified
//! install, enforces the same per-session checks as `orcel-mcp-host`
//! (payload verification, Node.js floor, workspace policy), and spawns the
//! identical verified launch (recorded Node.js runtime plus
//! `app/orcel-mcp/dist/index.js` with the sanitized environment and the
//! matching `orceld`). Standard input and output are inherited untouched
//! because stdout is the MCP channel. No tool, schema, capability,
//! approval, or network authority is added here.
//!
//! On Windows a session binds a full-control runtime session, which only
//! the active installed `versions/<version>/orcel.exe` may hold. Clients
//! launch `orcel` from `bin` (on PATH), so that copy hands the session to
//! the verified active version's executable, as `orcel start` hands the
//! supervisor to it, with standard I/O and the environment inherited
//! (SG-000127 slice 6: `orcel mcp stdio` from `bin` failed every session
//! since SG-000095).

use crate::config::Config;
use crate::install::Installer;
use crate::layout::Layout;
use crate::mcp_host::HostLaunch;
use crate::platform::MIN_NODE_MAJOR;
use crate::LifecycleError;
use std::path::PathBuf;
use std::process::Command;

/// Resolves the stdio launch for the active verified install.
pub fn resolve_stdio_launch(
    layout: &Layout,
    platform: &dyn crate::platform::Platform,
) -> Result<(HostLaunch, Config), LifecycleError> {
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
    Ok((
        HostLaunch {
            node,
            script: version_dir
                .join("app")
                .join("orcel-mcp")
                .join("dist")
                .join("index.js"),
            orceld: version_dir.join("orceld.exe"),
        },
        config,
    ))
}

/// Runs one stdio MCP session over inherited standard I/O and returns the
/// child exit code. This function does not return normally with output;
/// callers must exit the process with the returned code.
pub fn run_stdio_session(launch: &HostLaunch, config: &Config) -> i32 {
    let layout = match Layout::for_current_user() {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("orcel mcp stdio: {}", error.message);
            return 2;
        }
    };
    let session = match crate::full_control::begin_runtime_session(&layout) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("orcel mcp stdio: {}", error.message);
            return 2;
        }
    };
    let mut env = crate::ipc::child_environment(config);
    env.insert(
        "ORCEL_DAEMON".into(),
        launch.orceld.to_string_lossy().into_owned(),
    );
    env.insert(
        crate::full_control::RUNTIME_SESSION_ENV.into(),
        session.session_id.clone(),
    );
    let status = Command::new(&launch.node)
        .arg(&launch.script)
        .env_clear()
        .envs(env)
        .status();
    crate::full_control::end_runtime_session(&layout, &session.session_id);
    match status {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("orcel mcp stdio: start Node.js: {error}");
            2
        }
    }
}

/// Handles the `stdio` and `serve` actions. `stdio` runs one MCP session
/// over inherited standard I/O; `serve` starts the loopback HTTP listener.
/// Returns the child exit code. Unknown actions fail closed as usage errors
/// without touching stdio or opening any socket.
pub fn run_action(action: &str, port: Option<u16>) -> Result<i32, LifecycleError> {
    match action {
        "stdio" => {
            if port.is_some() {
                return Err(LifecycleError::usage(
                    "orcel mcp stdio takes no --port; run `orcel help`",
                ));
            }
            let layout = Layout::for_current_user()?;
            let platform = crate::host_platform();
            let (launch, config) =
                resolve_stdio_launch(&layout, platform.as_ref()).map_err(|error| {
                    LifecycleError::state(format!("orcel mcp stdio: {}", error.message))
                })?;
            if let Some(code) = delegate_to_active(&layout, &launch.orceld, &["mcp", "stdio"])? {
                return Ok(code);
            }
            Ok(run_stdio_session(&launch, &config))
        }
        "serve" => {
            let layout = Layout::for_current_user()?;
            let platform = crate::host_platform();
            let token = std::env::var("ORCEL_LOOPBACK_TOKEN").unwrap_or_default();
            let (launch, config) = resolve_serve_launch(&layout, platform.as_ref(), port, &token)
                .map_err(|error| {
                if error.kind == crate::ErrorKind::Usage {
                    error
                } else {
                    LifecycleError::state(format!("orcel mcp serve: {}", error.message))
                }
            })?;
            let port_text = port.map(|port| port.to_string());
            let mut forwarded = vec!["mcp", "serve"];
            if let Some(port) = port_text.as_deref() {
                forwarded.extend(["--port", port]);
            }
            if let Some(code) = delegate_to_active(&layout, &launch.orceld, &forwarded)? {
                return Ok(code);
            }
            Ok(run_serve_session(&launch, &config))
        }
        _ => Err(LifecycleError::usage(
            "unknown mcp action; run `orcel help`",
        )),
    }
}

/// Set on the handed-off child so a second hand-off fails instead of looping.
const DELEGATED_ENV: &str = "ORCEL_MCP_DELEGATED";

/// When this process is not the active installed `orcel.exe` (Windows
/// only), runs that verified executable with `args`, inheriting standard
/// I/O and the environment, and returns its exit code. `verified_orceld` is
/// the verified launch's `orceld`, so its directory is the active version
/// directory that `Installer::verify` just checked. `None` means this
/// process is already that executable and runs the session itself.
fn delegate_to_active(
    layout: &Layout,
    verified_orceld: &std::path::Path,
    args: &[&str],
) -> Result<Option<i32>, LifecycleError> {
    if !cfg!(windows) {
        return Ok(None);
    }
    let current = std::env::current_exe()
        .map_err(|error| LifecycleError::io("resolve the running orcel executable", error))?;
    if crate::lifecycle::is_installed_cli(layout, &current) {
        return Ok(None);
    }
    if std::env::var_os(DELEGATED_ENV).is_some() {
        return Err(LifecycleError::state(
            "the handed-off MCP session is not the active installed orcel executable",
        ));
    }
    let target = verified_orceld.with_file_name("orcel.exe");
    if !crate::lifecycle::is_installed_cli(layout, &target) || !target.is_file() {
        return Err(LifecycleError::state(
            "the active installed orcel executable is missing",
        ));
    }
    let status = Command::new(&target)
        .args(args)
        .env(DELEGATED_ENV, "1")
        .status()
        .map_err(|error| {
            LifecycleError::io("start the active installed orcel executable", error)
        })?;
    Ok(Some(status.code().unwrap_or(1)))
}

/// The resolved launch for one loopback HTTP listener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeLaunch {
    pub node: PathBuf,
    pub script: PathBuf,
    pub orceld: PathBuf,
    pub port: Option<u16>,
    pub token: String,
}

/// Minimum loopback credential length in characters. Mirrors the Node
/// transport floor so both layers fail closed on the same weak secrets.
pub const MIN_LOOPBACK_TOKEN_CHARS: usize = 32;

/// Resolves the loopback listener launch for the active verified install.
/// The credential comes only from the caller's environment and is never
/// generated, stored, or logged here. There is no bind-address option:
/// the Node transport always binds `127.0.0.1`.
pub fn resolve_serve_launch(
    layout: &Layout,
    platform: &dyn crate::platform::Platform,
    port: Option<u16>,
    token: &str,
) -> Result<(ServeLaunch, Config), LifecycleError> {
    if port.is_some_and(|port| port == 0) {
        return Err(LifecycleError::usage(
            "orcel mcp serve --port must be from 1 to 65535",
        ));
    }
    if token.chars().count() < MIN_LOOPBACK_TOKEN_CHARS {
        return Err(LifecycleError::usage(
            "ORCEL_LOOPBACK_TOKEN of at least 32 characters is required to serve loopback MCP",
        ));
    }
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
    Ok((
        ServeLaunch {
            node,
            script: version_dir
                .join("app")
                .join("orcel-mcp")
                .join("dist")
                .join("entrypoints")
                .join("loopback_http.js"),
            orceld: version_dir.join("orceld.exe"),
            port,
            token: token.to_string(),
        },
        config,
    ))
}

/// Runs the loopback listener with inherited standard I/O and returns the
/// child exit code. The bound URL is reported on standard error only.
pub fn run_serve_session(launch: &ServeLaunch, config: &Config) -> i32 {
    let layout = match Layout::for_current_user() {
        Ok(layout) => layout,
        Err(error) => {
            eprintln!("orcel mcp serve: {}", error.message);
            return 2;
        }
    };
    let session = match crate::full_control::begin_runtime_session(&layout) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("orcel mcp serve: {}", error.message);
            return 2;
        }
    };
    let mut env = crate::ipc::child_environment(config);
    env.insert(
        "ORCEL_DAEMON".into(),
        launch.orceld.to_string_lossy().into_owned(),
    );
    env.insert(
        crate::full_control::RUNTIME_SESSION_ENV.into(),
        session.session_id.clone(),
    );
    env.insert("ORCEL_LOOPBACK_TOKEN".into(), launch.token.clone());
    if let Some(port) = launch.port {
        env.insert("ORCEL_LOOPBACK_PORT".into(), port.to_string());
    }
    let status = Command::new(&launch.node)
        .arg(&launch.script)
        .env_clear()
        .envs(env)
        .status();
    crate::full_control::end_runtime_session(&layout, &session.session_id);
    match status {
        Ok(status) => status.code().unwrap_or(1),
        Err(error) => {
            eprintln!("orcel mcp serve: start Node.js: {error}");
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

    fn install(version: &str, platform: &FakePlatform) -> Layout {
        let base = temp_dir("mcp-stdio");
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
        layout
    }

    #[test]
    fn stdio_launch_matches_the_tunnel_host_launch() {
        let platform = FakePlatform::default();
        let layout = install("0.2.0", &platform);
        let (launch, config) = resolve_stdio_launch(&layout, &platform).unwrap();
        let version_dir = layout.version_dir("0.2.0");
        assert_eq!(
            launch.script,
            version_dir
                .join("app")
                .join("orcel-mcp")
                .join("dist")
                .join("index.js")
        );
        assert_eq!(launch.orceld, version_dir.join("orceld.exe"));
        assert_eq!(config.default_workspace(), Some("default"));
        let exe = version_dir.join("orcel-mcp-host.exe");
        let (host_launch, _) = crate::mcp_host::resolve(&exe, &platform).unwrap();
        assert_eq!(launch, host_launch);
    }

    #[test]
    fn tampered_payload_fails_closed() {
        let platform = FakePlatform::default();
        let layout = install("0.2.0", &platform);
        std::fs::write(
            layout
                .version_dir("0.2.0")
                .join("app/orcel-mcp/dist/index.js"),
            b"replaced",
        )
        .unwrap();
        assert!(resolve_stdio_launch(&layout, &platform).is_err());
    }

    #[test]
    fn missing_workspaces_and_old_node_fail_closed() {
        let platform = FakePlatform::default();
        let layout = install("0.2.0", &platform);
        Config::default().save(&layout).unwrap();
        assert!(resolve_stdio_launch(&layout, &platform).is_err());
        let layout = install("0.2.0", &platform);
        let old_node = FakePlatform {
            node_major: 18,
            ..FakePlatform::default()
        };
        assert!(resolve_stdio_launch(&layout, &old_node).is_err());
    }

    #[test]
    fn unknown_action_fails_closed_as_usage() {
        let error = run_action("http", None).unwrap_err();
        assert_eq!(error.kind, crate::ErrorKind::Usage);
    }

    #[test]
    fn serve_launch_points_at_the_loopback_entrypoint() {
        let platform = FakePlatform::default();
        let layout = install("0.2.0", &platform);
        let token = "0123456789abcdef0123456789abcdef";
        let (launch, _) = resolve_serve_launch(&layout, &platform, Some(8080), token).unwrap();
        assert_eq!(
            launch.script,
            layout
                .version_dir("0.2.0")
                .join("app/orcel-mcp/dist/entrypoints/loopback_http.js")
        );
        assert_eq!(
            launch.orceld,
            layout.version_dir("0.2.0").join("orceld.exe")
        );
        assert_eq!(launch.port, Some(8080));
        assert_eq!(launch.token, token);
    }

    #[test]
    fn serve_without_credential_zero_port_or_tampering_fails_closed() {
        let platform = FakePlatform::default();
        let layout = install("0.2.0", &platform);
        let token = "0123456789abcdef0123456789abcdef";
        assert!(resolve_serve_launch(&layout, &platform, None, "").is_err());
        assert!(resolve_serve_launch(&layout, &platform, None, "short").is_err());
        assert!(resolve_serve_launch(&layout, &platform, Some(0), token).is_err());
        std::fs::write(
            layout
                .version_dir("0.2.0")
                .join("app/orcel-mcp/dist/index.js"),
            b"replaced",
        )
        .unwrap();
        assert!(resolve_serve_launch(&layout, &platform, None, token).is_err());
    }
}
