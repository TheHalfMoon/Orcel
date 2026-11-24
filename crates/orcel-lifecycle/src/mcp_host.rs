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
//!
//! SG-000135 OB-09: it serves only a tunnel client that the supervisor
//! launched for the setup saved now (tunnel id, profile, runtime key): the
//! launch pin it was started with must match, or it refuses. The client starts
//! a refusing host again and again, so the refusal is recorded for `orcel
//! status` and `orcel doctor`.

use crate::config::Config;
use crate::install::Installer;
use crate::layout::Layout;
use crate::platform::{Platform, MIN_NODE_MAJOR};
use crate::tunnel_route;
use crate::LifecycleError;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The only `ORCEL_*` variables the tunnel host passes on from its own
/// sanitized environment. Everything else `ORCEL_*` (a local tool-surface
/// profile, the runtime session binding, provider configuration, a daemon
/// override) is dropped; the host then sets its own values.
const TUNNEL_HOST_ORCEL_ENV: [&str; 3] = [
    "ORCEL_WORKSPACES_JSON",
    "ORCEL_DEFAULT_WORKSPACE",
    // The person's approval preview choice, so remote requests' prompts follow it too.
    "ORCEL_APPROVAL_PREVIEWS",
];

/// The resolved launch for one MCP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLaunch {
    pub node: PathBuf,
    pub script: PathBuf,
    pub orceld: PathBuf,
}

/// The install layout and version folder of a host binary at `exe`.
fn install_of(exe: &Path) -> Result<(Layout, &Path), LifecycleError> {
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
    Ok((Layout::new(root), version_dir))
}

/// Resolves and verifies the launch for a host binary located at `exe`.
pub fn resolve(
    exe: &Path,
    platform: &dyn Platform,
) -> Result<(HostLaunch, Config), LifecycleError> {
    let (layout, version_dir) = install_of(exe)?;
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
        orceld: version_dir.join(crate::per_os::orceld_file_name()),
    };
    Ok((launch, config))
}

/// The closed environment of the tunnel host's Node.js app, built from the
/// sanitized child environment `base`: OS execution variables, the
/// configured workspaces, the matching `orceld`, the `tunnel` transport, and
/// the tunnel's remote route. Fails closed when no tunnel is configured, and
/// when `pin`, what the tunnel client was launched with, is not the pin of
/// this configuration and `setup_id`.
pub fn tunnel_environment(
    config: &Config,
    launch: &HostLaunch,
    mut base: BTreeMap<String, String>,
    setup_id: Option<&str>,
    pin: Option<&str>,
) -> Result<BTreeMap<String, String>, LifecycleError> {
    let tunnel = config.tunnel.as_ref().ok_or_else(|| {
        LifecycleError::state("the tunnel is not configured; orcel-mcp-host serves only the tunnel")
    })?;
    tunnel_route::check_launch_pin(config, setup_id, pin)?;
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
        tunnel_route::route_for(&tunnel.tunnel_id, &tunnel.profile)
            .ok_or_else(|| LifecycleError::state("tunnel profile must be core or browser_full"))?
            .to_string(),
    );
    Ok(base)
}

/// The verified launch and its environment, for a host binary at `exe` that a
/// tunnel client with `pin` started.
fn prepare(
    exe: &Path,
    platform: &dyn Platform,
    pin: Option<&str>,
) -> Result<(HostLaunch, BTreeMap<String, String>), LifecycleError> {
    let (launch, config) = resolve(exe, platform)?;
    let (layout, _) = install_of(exe)?;
    let setup_id = crate::config::read_setup_id(&layout)?;
    let base = crate::ipc::child_environment(&config);
    let env = tunnel_environment(&config, &launch, base, setup_id.as_deref(), pin)?;
    Ok((launch, env))
}

/// The launch pin among the host's `args`: nothing, or exactly
/// [`orcel_tunnel::LAUNCH_PIN_ARG`] and its value.
fn pin_argument(args: &[OsString]) -> Result<Option<&str>, LifecycleError> {
    match args {
        [] => Ok(None),
        [name, value] if name == orcel_tunnel::LAUNCH_PIN_ARG => value
            .to_str()
            .map(Some)
            .ok_or_else(|| LifecycleError::usage("the launch pin is not text")),
        _ => Err(LifecycleError::usage(format!(
            "orcel-mcp-host takes {} <pin> and nothing else",
            orcel_tunnel::LAUNCH_PIN_ARG
        ))),
    }
}

/// [`prepare`] with the process's arguments. A refusal is recorded in the
/// install's state, and serving forgets it.
fn serve(
    exe: &Path,
    platform: &dyn Platform,
    args: &[OsString],
) -> Result<(HostLaunch, BTreeMap<String, String>), LifecycleError> {
    let (layout, _) = install_of(exe)?;
    let outcome = pin_argument(args).and_then(|pin| prepare(exe, platform, pin));
    match &outcome {
        Ok(_) => crate::lifecycle::clear_host_refusal(&layout),
        Err(error) => crate::lifecycle::record_host_refusal(&layout, &error.message),
    }
    outcome
}

/// Runs the MCP app for the current process and returns its exit code.
pub fn run() -> i32 {
    let platform = crate::host_platform();
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let outcome = std::env::current_exe()
        .map_err(|error| LifecycleError::io("locate orcel-mcp-host", error))
        .and_then(|exe| serve(&exe, platform.as_ref(), &args));
    let (launch, env) = match outcome {
        Ok(prepared) => prepared,
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
        let exe = layout
            .version_dir(version)
            .join(crate::per_os::mcp_host_file_name());
        (layout, exe)
    }

    #[test]
    fn resolves_the_active_verified_version_payload() {
        let platform = FakePlatform::default();
        let (layout, exe) = install("0.2.0", &platform);
        let (launch, config) = resolve(&exe, &platform).unwrap();
        assert_eq!(
            launch.orceld,
            layout.version_dir("0.2.0").join(if cfg!(windows) {
                "orceld.exe"
            } else {
                "orceld"
            })
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
                profile: "core".into(),
            }),
            ..Config::default()
        }
    }

    const SETUP_ID: &str = "setup-id";

    fn pin_of(config: &Config) -> String {
        tunnel_route::launch_pin(config, Some(SETUP_ID)).unwrap()
    }

    /// SG-000135 OB-09: with an installed payload, the host serves only a
    /// client launched for the setup on disk. A changed tunnel id or profile,
    /// a renewed setup id (as for a new key), a missing or unreadable id, no
    /// pin and any other argument refuse; putting the setup back serves again.
    /// A refusal is recorded and serving forgets it.
    #[test]
    fn ob09_the_host_refuses_a_client_of_another_setup() {
        use crate::lifecycle::host_refusal;
        let platform = FakePlatform::default();
        let (layout, exe) = install("0.2.0", &platform);
        let workspaces = Config::load(&layout).unwrap().workspaces;
        let save = |tunnel_id: &str, profile: &str| {
            let config = Config {
                workspaces: workspaces.clone(),
                tunnel: Some(crate::config::TunnelSettings {
                    client: std::env::temp_dir().join("tunnel-client"),
                    tunnel_id: tunnel_id.into(),
                    profile: profile.into(),
                }),
                ..Config::default()
            };
            config.save(&layout).unwrap();
            config
        };
        let a = "tunnel_0123456789abcdefghijklmnopqrstuv";
        let b = "tunnel_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let id = crate::config::renew_setup_id(&layout).unwrap();
        let pin = tunnel_route::launch_pin(&save(a, "core"), Some(&id)).unwrap();
        let args = |args: &[&str]| args.iter().map(OsString::from).collect::<Vec<_>>();
        let pinned = args(&["--launch-pin", &pin]);
        let serves = |args: &[OsString]| {
            let outcome = serve(&exe, &platform, args);
            let recorded = host_refusal(&layout).map(|refusal| refusal.reason);
            let refused = outcome.map(|_| ()).map_err(|error| error.message).err();
            assert_eq!(recorded, refused, "recorded as refused, or forgotten");
            refused
        };
        assert_eq!(serves(&pinned), None);
        let said = serves(&[]).unwrap();
        assert!(said.contains("without its launch pin"), "{said}");
        assert_eq!(serves(&pinned), None);
        for other in [
            args(&["--launch-pin"]),
            args(&[&pin]),
            args(&["--launch-pin", &pin, "x"]),
            args(&["--pin", &pin]),
            args(&[&format!("--launch-pin={pin}")]),
        ] {
            let said = serves(&other).unwrap();
            assert!(said.contains("nothing else"), "{said}");
        }
        for (tunnel_id, profile) in [(b, "core"), (a, "browser_full")] {
            save(tunnel_id, profile);
            let said = serves(&pinned).unwrap();
            assert!(said.contains("is not the one"), "{said}");
        }
        save(a, "core");
        assert_eq!(serves(&pinned), None);
        crate::config::renew_setup_id(&layout).unwrap();
        assert!(serves(&pinned).unwrap().contains("is not the one"));
        std::fs::remove_file(layout.tunnel_setup_id()).unwrap();
        assert!(serves(&pinned).unwrap().contains("has no id yet"));
        std::fs::create_dir(layout.tunnel_setup_id()).unwrap();
        assert!(serves(&pinned)
            .unwrap()
            .contains("read the tunnel setup id"));
        // The runtime key is not read for any of this.
        assert!(!layout.runtime_key_file().exists());
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
        let config = tunnel_config();
        let pin = pin_of(&config);
        let env = tunnel_environment(
            &config,
            &tunnel_launch(),
            inherited,
            Some(SETUP_ID),
            Some(&pin),
        )
        .unwrap();
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
        let pin = pin_of(&tunnel_config());
        let error = tunnel_environment(
            &Config::default(),
            &tunnel_launch(),
            BTreeMap::new(),
            Some(SETUP_ID),
            Some(&pin),
        )
        .unwrap_err();
        assert!(error.message.contains("not configured"));
    }

    #[test]
    fn inactive_version_foreign_location_and_old_node_fail_closed() {
        let platform = FakePlatform::default();
        let (layout, _) = install("0.2.0", &platform);
        let stale = layout
            .version_dir("0.1.0")
            .join(crate::per_os::mcp_host_file_name());
        assert!(resolve(&stale, &platform).is_err());
        assert!(resolve(
            &std::env::temp_dir().join(crate::per_os::mcp_host_file_name()),
            &platform
        )
        .is_err());
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
