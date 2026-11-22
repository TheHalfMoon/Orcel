//! MAC-M1-07: the per-user launchd agent that starts `orceld` on demand on
//! macOS, the counterpart of XP-17's `orceld.socket` on Linux.
//!
//! launchd listens on an owner-only Unix socket and, for each connection,
//! starts one `orceld` with the connection as its standard input and output
//! (`inetdCompatibility` with `Wait` false), like `Accept=yes` on Linux. The
//! socket is `<DARWIN_USER_TEMP_DIR>/orcel/orceld.sock`, in the same 0700
//! per-user directory as orceld's app API socket. Nothing runs at load and
//! nothing is kept alive: with no connection there is no process. It opens
//! no network listener, and the socket grants no new authority: only the
//! same user can connect, and that user could start `orceld` directly.
//!
//! In that mode launchd connects standard error to the socket too, where
//! orceld's log lines would break the JSON-lines stream (seen on the hosted
//! runner). So the agent runs `/bin/sh -c 'umask 077; exec 2>>"$1"; exec "$0"'`
//! with the `orceld` path and a log file under the install's `logs` folder:
//! standard error goes to that file, created 0600, and the shell then becomes
//! `orceld`, as `StandardError=journal` keeps it off the socket on Linux. The
//! script sets the umask itself because the plist's `Umask` key did not take
//! effect on the hosted runner (the log came out 0644); the key stays as well.
//! Like `UMask=0077` on Linux, it applies to everything orceld creates.
//!
//! The plist is generated here, from pure inputs, so its content is tested on
//! every OS. Writing, loading and unloading it is macOS only
//! ([`crate::unix_install`]), and nothing calls that on a person's Mac until
//! the macOS M1 grain is activated: `host_platform()` still refuses the
//! lifecycle commands there.

use crate::config::{ApprovalPreviews, Config};
use crate::LifecycleError;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The agent's launchd label.
pub const LABEL: &str = "ai.orcel.orceld";
/// The socket's file name inside the per-user runtime directory.
pub const SOCKET_FILE: &str = "orceld.sock";
/// `sun_path` holds 104 bytes on macOS, the terminating NUL included.
const MAX_SOCKET_PATH: usize = 103;
/// The shell, by absolute path, and its script: standard error to the log
/// file (`$1`) with an owner-only umask, then become `orceld` (`$0`).
const SHELL: &str = "/bin/sh";
const SHELL_SCRIPT: &str = r#"umask 077; exec 2>>"$1"; exec "$0""#;
/// The agent's standard error log inside the install's `logs` folder.
pub const STDERR_LOG: &str = "orceld-agent.log";

/// What one agent is: its label, the `orceld` it starts, its socket, the
/// file its standard error goes to, and the environment `orceld` gets (the
/// workspaces among it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentSpec {
    pub label: String,
    pub program: PathBuf,
    pub socket: PathBuf,
    pub stderr_log: PathBuf,
    pub environment: BTreeMap<String, String>,
}

impl AgentSpec {
    /// The plist's file name: `<label>.plist`.
    pub fn plist_file_name(&self) -> String {
        format!("{}.plist", self.label)
    }
}

/// `~/Library/LaunchAgents` under `home`.
pub fn launch_agents_dir(home: &Path) -> PathBuf {
    home.join("Library").join("LaunchAgents")
}

/// The socket path under the per-user runtime directory.
pub fn socket_path(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("orcel").join(SOCKET_FILE)
}

/// The agent's environment, from the saved configuration alone: the
/// workspaces, the default workspace and the saved preview choice, as
/// [`crate::ipc::child_environment`] sets them. Nothing comes from the
/// installing shell's environment (such as `ORCEL_DAEMON` or a session id),
/// because the plist outlives it; launchd gives the agent the user's `HOME`
/// and a fixed `PATH`.
pub fn agent_environment(config: &Config) -> BTreeMap<String, String> {
    let mut environment =
        BTreeMap::from([("ORCEL_WORKSPACES_JSON".to_owned(), config.workspaces_json())]);
    if let Some(default) = config.default_workspace() {
        environment.insert("ORCEL_DEFAULT_WORKSPACE".to_owned(), default.to_owned());
    }
    if config.approval_previews == Some(ApprovalPreviews::Sizes) {
        environment.insert("ORCEL_APPROVAL_PREVIEWS".to_owned(), "sizes".to_owned());
    }
    environment
}

fn text(what: &str, path: &Path) -> Result<String, LifecycleError> {
    // A macOS path: absolute means it starts at `/` (checked as text, so the
    // generator is tested the same way on every OS).
    if !path.to_str().is_some_and(|text| text.starts_with('/')) {
        return Err(LifecycleError::state(format!(
            "the launchd agent's {what} must be an absolute path: {}",
            path.display()
        )));
    }
    path.to_str().map(str::to_owned).ok_or_else(|| {
        LifecycleError::state(format!(
            "the launchd agent's {what} is not valid UTF-8: {}",
            path.display()
        ))
    })
}

fn escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 128
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
}

/// The agent's property list. Refuses a relative or non-UTF-8 path, a socket
/// path too long for `sun_path`, a label outside `[A-Za-z0-9.-]`, and an
/// environment name that is not `[A-Z0-9_]`.
pub fn plist(spec: &AgentSpec) -> Result<String, LifecycleError> {
    if !valid_label(&spec.label) {
        return Err(LifecycleError::state(format!(
            "invalid launchd label {:?}",
            spec.label
        )));
    }
    let program = text("program", &spec.program)?;
    let socket = text("socket", &spec.socket)?;
    let stderr_log = text("log file", &spec.stderr_log)?;
    if socket.len() > MAX_SOCKET_PATH {
        return Err(LifecycleError::state(format!(
            "the launchd agent's socket path is longer than {MAX_SOCKET_PATH} bytes: {socket}"
        )));
    }
    let mut environment = String::new();
    for (name, value) in &spec.environment {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(LifecycleError::state(format!(
                "invalid environment name {name:?} for the launchd agent"
            )));
        }
        environment.push_str(&format!(
            "    <key>{}</key>\n    <string>{}</string>\n",
            escape(name),
            escape(value)
        ));
    }
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{shell}</string>
    <string>-c</string>
    <string>{script}</string>
    <string>{program}</string>
    <string>{stderr_log}</string>
  </array>
  <key>inetdCompatibility</key>
  <dict>
    <key>Wait</key>
    <false/>
  </dict>
  <key>Sockets</key>
  <dict>
    <key>Listeners</key>
    <dict>
      <key>SockFamily</key>
      <string>Unix</string>
      <key>SockType</key>
      <string>stream</string>
      <key>SockPathName</key>
      <string>{socket}</string>
      <key>SockPathMode</key>
      <integer>384</integer>
    </dict>
  </dict>
  <key>EnvironmentVariables</key>
  <dict>
{environment}  </dict>
  <key>Umask</key>
  <integer>63</integer>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
"#,
        label = escape(&spec.label),
        shell = SHELL,
        script = escape(SHELL_SCRIPT),
        program = escape(&program),
        stderr_log = escape(&stderr_log),
        socket = escape(&socket),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> AgentSpec {
        AgentSpec {
            label: LABEL.into(),
            program: PathBuf::from(
                "/Users/ana/Library/Application Support/Orcel/versions/0.2.0/orceld",
            ),
            socket: PathBuf::from("/var/folders/ab/xyz/T/orcel/orceld.sock"),
            stderr_log: PathBuf::from(
                "/Users/ana/Library/Application Support/Orcel/logs/orceld-agent.log",
            ),
            environment: BTreeMap::from([(
                "ORCEL_WORKSPACES_JSON".to_owned(),
                r#"[{"id":"a&b","root":"/Users/ana/<p>"}]"#.to_owned(),
            )]),
        }
    }

    #[test]
    fn the_plist_starts_one_orceld_per_connection_on_an_owner_only_socket() {
        let text = plist(&spec()).unwrap();
        for needle in [
            "<key>Label</key>\n  <string>ai.orcel.orceld</string>",
            // Standard error to the log file, never the socket; then orceld.
            "<array>\n    <string>/bin/sh</string>\n    <string>-c</string>\n    <string>umask 077; exec 2&gt;&gt;&quot;$1&quot;; exec &quot;$0&quot;</string>\n    <string>/Users/ana/Library/Application Support/Orcel/versions/0.2.0/orceld</string>\n    <string>/Users/ana/Library/Application Support/Orcel/logs/orceld-agent.log</string>\n  </array>",
            "<key>inetdCompatibility</key>\n  <dict>\n    <key>Wait</key>\n    <false/>",
            "<key>SockFamily</key>\n      <string>Unix</string>",
            "<key>SockPathName</key>\n      <string>/var/folders/ab/xyz/T/orcel/orceld.sock</string>",
            // 0600: only this user can connect.
            "<key>SockPathMode</key>\n      <integer>384</integer>",
            // 0077: what orceld creates is owner-only, as UMask=0077 on Linux.
            "<key>Umask</key>\n  <integer>63</integer>",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in\n{text}");
        }
        // On demand only: nothing runs at load or is kept alive, no network.
        for absent in [
            "RunAtLoad",
            "KeepAlive",
            "SockNodeName",
            "SockServiceName",
            "UserName",
        ] {
            assert!(!text.contains(absent), "{absent} in\n{text}");
        }
    }

    #[test]
    fn values_are_escaped() {
        let text = plist(&spec()).unwrap();
        assert!(text.contains(
            "<string>[{&quot;id&quot;:&quot;a&amp;b&quot;,&quot;root&quot;:&quot;/Users/ana/&lt;p&gt;&quot;}]</string>"
        ));
        assert!(!text.contains("<p>"));
    }

    #[test]
    fn unsafe_inputs_are_refused() {
        let mut relative = spec();
        relative.program = PathBuf::from("orceld");
        assert!(plist(&relative).is_err());
        let mut log = spec();
        log.stderr_log = PathBuf::from("logs/orceld-agent.log");
        assert!(plist(&log).is_err());
        let mut long = spec();
        long.socket = PathBuf::from(format!("/{}/orceld.sock", "x".repeat(100)));
        assert!(plist(&long).is_err());
        for label in ["", "ai orcel", "ai/orcel", "ai.orcel<x>"] {
            let mut bad = spec();
            bad.label = label.into();
            assert!(plist(&bad).is_err(), "{label:?}");
        }
        let mut name = spec();
        name.environment.insert("bad name".into(), "x".into());
        assert!(plist(&name).is_err());
    }

    /// The plist's environment comes from the configuration alone: a stray
    /// `ORCEL_*` variable in the installing shell is never written into it.
    #[test]
    fn the_agent_environment_comes_from_the_configuration_alone() {
        let stray = "ORCEL_DAEMON";
        // The test process's own environment, as the installing shell's.
        std::env::set_var(stray, "/tmp/elsewhere/orceld");
        let config = Config {
            workspaces: vec![crate::config::WorkspaceEntry {
                id: "a".into(),
                root: PathBuf::from("/Users/ana/work"),
            }],
            approval_previews: Some(ApprovalPreviews::Sizes),
            ..Config::default()
        };
        let environment = agent_environment(&config);
        assert_eq!(
            environment.keys().collect::<Vec<_>>(),
            vec![
                "ORCEL_APPROVAL_PREVIEWS",
                "ORCEL_DEFAULT_WORKSPACE",
                "ORCEL_WORKSPACES_JSON"
            ]
        );
        assert_eq!(
            environment["ORCEL_WORKSPACES_JSON"],
            config.workspaces_json()
        );
        assert_eq!(environment["ORCEL_DEFAULT_WORKSPACE"], "a");
        assert_eq!(environment["ORCEL_APPROVAL_PREVIEWS"], "sizes");
        let text = plist(&AgentSpec {
            environment,
            ..spec()
        })
        .unwrap();
        assert!(!text.contains(stray), "{text}");
        std::env::remove_var(stray);
        // Without a saved preview choice, no preview variable.
        let plain = agent_environment(&Config {
            approval_previews: None,
            ..config
        });
        assert!(!plain.contains_key("ORCEL_APPROVAL_PREVIEWS"));
    }

    #[test]
    fn locations_are_the_launch_agents_folder_and_the_runtime_directory() {
        assert_eq!(
            launch_agents_dir(Path::new("/Users/ana")),
            PathBuf::from("/Users/ana/Library/LaunchAgents")
        );
        assert_eq!(
            socket_path(Path::new("/var/folders/ab/xyz/T")),
            PathBuf::from("/var/folders/ab/xyz/T/orcel/orceld.sock")
        );
        assert_eq!(spec().plist_file_name(), "ai.orcel.orceld.plist");
    }
}
