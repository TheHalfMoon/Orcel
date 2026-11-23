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
//! runner). So the agent runs `/bin/sh -c` with a constant script that ends
//! by becoming `orceld` (`exec "$0"`) with standard error in a log file under
//! the install's `logs` folder, as `StandardError=journal` keeps it off the
//! socket on Linux. The file is created 0600, and one already there with
//! wider permissions is made 0600 at each start, when it is the user's own.
//!
//! When the name is a link, a folder, a FIFO or anything else but a plain
//! file as the script checks it, or the file cannot be opened (no `logs`
//! folder, for example), that start's standard error goes to `/dev/null`
//! and the script still becomes `orceld`. The check is of the name, just
//! before the open: something put there in between is opened as it is, and
//! a FIFO nobody reads would then hold that start.
//!
//! The script sets the umask itself because the plist's `Umask` key did not
//! take effect on the hosted runner (the log came out 0644); the key stays as
//! well. Like `UMask=0077` on Linux, it applies to everything orceld creates.
//!
//! launchd's own `StandardErrorPath` was tried instead of the shell (PR #840,
//! one run on macOS 15 and 26): the socket stayed clean and the readiness
//! line reached the file, but the file was again 0644 under `Umask` 63, and
//! there is no hook to bound the log when launchd starts `orceld`. So the
//! shell stays.
//!
//! The log's size is checked, not capped while it is written: when it is
//! over [`MAX_STDERR_LOG`] it is moved to `orceld-agent.log.1` (replacing an
//! older one), both when the agent is written ([`rotate_log`], at install,
//! update and rollback, where a log that cannot be moved is noted in the
//! lifecycle log and nothing fails for it) and by the shell each time launchd
//! starts `orceld`. The shell looks at the size again after the move. If the
//! log is still over the limit (`orceld-agent.log.1` is a link, a folder or
//! anything else but a plain file, or another name of the same file, or the
//! move fails), that start logs to `/dev/null` instead of adding to it.
//!
//! What one `orceld` writes while it runs is not limited, and one that is
//! running when the log is moved keeps writing to the moved file. Two starts
//! at once may both find the log oversized: the later move can then replace
//! the `.1` just made with a nearly empty log, so older lines are lost. The
//! checks are on names, in the install's own 0700 `logs` folder: they are
//! not a defense against another program of the same user. The shell's own
//! standard error goes to `/dev/null` first, so nothing it might print
//! reaches the socket.
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
/// The shell, by absolute path, and its script: an owner-only umask, and the
/// shell's own standard error to `/dev/null`. A log (`$1`) that is not a plain
/// file is left alone (`$1` becomes `/dev/null`). Another is made 0600 and,
/// over 1 MiB, moved to `$1.1` when that is a plain file or free; one that is
/// still over 1 MiB is left alone too. Then the script becomes `orceld` (`$0`)
/// with standard error in the log. The log is opened once, as a redirection of
/// a group: when that fails the shell goes on to the last command and becomes
/// `orceld` with standard error in `/dev/null` (a failed redirection of `exec`
/// itself would end the shell). `chmod`, `stat` and `mv` by absolute path;
/// constant, with positional paths only.
const SHELL: &str = "/bin/sh";
const SHELL_SCRIPT: &str = r#"umask 077; exec 2>/dev/null; plain() { [ ! -L "$1" ] && { [ ! -e "$1" ] || [ -f "$1" ]; }; }; big() { [ "$(/usr/bin/stat -f %z "$1")" -gt 1048576 ]; }; if plain "$1"; then /bin/chmod 600 "$1"; if big "$1"; then if plain "$1.1"; then /bin/mv -f "$1" "$1.1"; fi; if big "$1"; then set -- /dev/null; fi; fi; else set -- /dev/null; fi; { exec "$0"; } 2>>"$1"; exec "$0""#;
/// The agent's standard error log inside the install's `logs` folder.
pub const STDERR_LOG: &str = "orceld-agent.log";
/// The size over which the log is moved aside (the shell script's 1048576).
pub const MAX_STDERR_LOG: u64 = 1024 * 1024;

/// Whether `result` did its work: `false` when the file was gone, because an
/// agent that is starting moved the same log aside first.
fn unless_gone(result: std::io::Result<()>) -> std::io::Result<bool> {
    match result {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Moves `log` to `<log>.1`, replacing an older one, when it is over `limit`
/// bytes; returns whether it did. A log that is missing, or that a starting
/// agent moves aside meanwhile, is nothing to do. Only a regular file is
/// moved: anything else there is an error, left in place, and so is a log
/// that is still over `limit` after the move (`<log>.1` was another name of
/// the same file). On Unix a file that is moved is made 0600 first; one under
/// the limit keeps its mode here and is made 0600 by the script at the next
/// start.
pub fn rotate_log(log: &Path, limit: u64) -> Result<bool, LifecycleError> {
    let metadata = match std::fs::symlink_metadata(log) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(LifecycleError::io(
                format!("inspect {}", log.display()),
                error,
            ))
        }
    };
    if !metadata.is_file() {
        return Err(LifecycleError::state(format!(
            "{} is not a regular file and was left in place",
            log.display()
        )));
    }
    if metadata.len() <= limit {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let owner_only = std::fs::Permissions::from_mode(0o600);
        if !unless_gone(std::fs::set_permissions(log, owner_only))
            .map_err(|error| LifecycleError::io(format!("protect {}", log.display()), error))?
        {
            return Ok(false);
        }
    }
    let mut aside = log.as_os_str().to_owned();
    aside.push(".1");
    if !unless_gone(std::fs::rename(log, PathBuf::from(&aside)))
        .map_err(|error| LifecycleError::io(format!("rotate {}", log.display()), error))?
    {
        return Ok(false);
    }
    if std::fs::symlink_metadata(log).is_ok_and(|after| after.len() > limit) {
        return Err(LifecycleError::state(format!(
            "{} could not be moved aside and was left in place",
            log.display()
        )));
    }
    Ok(true)
}

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
            "<array>\n    <string>/bin/sh</string>\n    <string>-c</string>\n    <string>umask 077; exec 2&gt;/dev/null; plain() { [ ! -L &quot;$1&quot; ] &amp;&amp; { [ ! -e &quot;$1&quot; ] || [ -f &quot;$1&quot; ]; }; }; big() { [ &quot;$(/usr/bin/stat -f %z &quot;$1&quot;)&quot; -gt 1048576 ]; }; if plain &quot;$1&quot;; then /bin/chmod 600 &quot;$1&quot;; if big &quot;$1&quot;; then if plain &quot;$1.1&quot;; then /bin/mv -f &quot;$1&quot; &quot;$1.1&quot;; fi; if big &quot;$1&quot;; then set -- /dev/null; fi; fi; else set -- /dev/null; fi; { exec &quot;$0&quot;; } 2&gt;&gt;&quot;$1&quot;; exec &quot;$0&quot;</string>\n    <string>/Users/ana/Library/Application Support/Orcel/versions/0.2.0/orceld</string>\n    <string>/Users/ana/Library/Application Support/Orcel/logs/orceld-agent.log</string>\n  </array>",
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
    fn the_shell_bound_matches_the_rotation_limit() {
        assert!(SHELL_SCRIPT.contains(&format!("-gt {MAX_STDERR_LOG} ]")));
        // Nothing the shell prints can reach the socket: its stderr goes to
        // /dev/null before anything else runs.
        let quiet = SHELL_SCRIPT.find("exec 2>/dev/null").unwrap();
        assert!(quiet < SHELL_SCRIPT.find("plain()").unwrap());
    }

    #[test]
    fn the_log_is_moved_aside_only_when_over_the_limit() {
        let dir = crate::test_support::temp_dir("launchd-rotate");
        let log = dir.join(STDERR_LOG);
        assert!(!rotate_log(&log, 8).unwrap(), "a missing log");
        std::fs::write(&log, b"12345678").unwrap();
        assert!(!rotate_log(&log, 8).unwrap(), "at the limit");
        std::fs::write(dir.join("orceld-agent.log.1"), b"older").unwrap();
        std::fs::write(&log, b"123456789").unwrap();
        assert!(rotate_log(&log, 8).unwrap());
        assert!(!log.exists());
        assert_eq!(
            std::fs::read(dir.join("orceld-agent.log.1")).unwrap(),
            b"123456789"
        );
        std::fs::create_dir(&log).unwrap();
        assert!(rotate_log(&log, 0).is_err(), "a folder is left in place");
    }

    /// A log that is moved aside is owner-only afterwards, whatever its mode.
    #[cfg(unix)]
    #[test]
    fn a_log_moved_aside_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = crate::test_support::temp_dir("launchd-rotate-mode");
        let log = dir.join(STDERR_LOG);
        let set = |mode| {
            std::fs::set_permissions(&log, std::fs::Permissions::from_mode(mode)).unwrap();
        };
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        std::fs::write(&log, b"123456789").unwrap();
        set(0o644);
        assert!(!rotate_log(&log, 9).unwrap(), "at the limit");
        assert_eq!(mode(&log), 0o644, "left for the script's next start");
        assert!(rotate_log(&log, 8).unwrap());
        assert_eq!(mode(&dir.join("orceld-agent.log.1")), 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_log_that_is_gone_meanwhile_is_nothing_to_do() {
        use std::io::{Error, ErrorKind};
        assert!(unless_gone(Ok(())).unwrap());
        assert!(!unless_gone(Err(Error::from(ErrorKind::NotFound))).unwrap());
        assert!(unless_gone(Err(Error::from(ErrorKind::PermissionDenied))).is_err());
    }

    /// A `.1` that is another name of the log: the rename changes nothing.
    #[cfg(unix)]
    #[test]
    fn a_log_that_is_still_over_the_limit_is_an_error() {
        let dir = crate::test_support::temp_dir("launchd-rotate-linked");
        let log = dir.join(STDERR_LOG);
        std::fs::write(&log, b"123456789").unwrap();
        std::fs::hard_link(&log, dir.join("orceld-agent.log.1")).unwrap();
        assert!(rotate_log(&log, 8).is_err());
        assert_eq!(std::fs::read(&log).unwrap(), b"123456789");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The script itself, run as launchd runs it, under a path with a space
    /// and quotes: what it does with a log that is missing, 0644, oversized,
    /// a link (dangling too), a FIFO, a folder, or one it cannot open, and
    /// with an `.1` it cannot replace.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_shell_script_writes_only_to_a_plain_owner_only_log() {
        use std::os::unix::fs::PermissionsExt;
        let base = crate::test_support::temp_dir("launchd-script");
        let dir = base.join("it's a \"quoted\" folder");
        std::fs::create_dir(&dir).unwrap();
        let program = dir.join("orceld");
        std::fs::write(&program, "#!/bin/sh\necho ready >&2\necho answer\n").unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
        let log = dir.join(STDERR_LOG);
        let aside = dir.join("orceld-agent.log.1");
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let run_with = |log: &Path| {
            let mut child = std::process::Command::new(SHELL)
                .arg("-c")
                .arg(SHELL_SCRIPT)
                .arg(&program)
                .arg(log)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            // Bounded: opening a FIFO nobody reads would wait forever.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while child.try_wait().unwrap().is_none() {
                let late = std::time::Instant::now() > deadline;
                if late {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                assert!(!late, "the script did not finish for {}", log.display());
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let output = child.wait_with_output().unwrap();
            assert!(output.status.success(), "{output:?}");
            // Nothing but the program's answer, and nothing on stderr.
            assert_eq!(output.stdout, b"answer\n");
            assert_eq!(output.stderr, b"");
        };
        let run = || run_with(&log);
        run();
        assert_eq!(std::fs::read(&log).unwrap(), b"ready\n");
        assert_eq!(mode(&log), 0o600, "created owner-only");
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        run();
        assert_eq!(mode(&log), 0o600, "an earlier 0644 log");
        assert_eq!(std::fs::read(&log).unwrap(), b"ready\nready\n");

        let oversized = vec![b'x'; MAX_STDERR_LOG as usize + 1];
        std::fs::write(&log, &oversized).unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        run();
        assert_eq!(std::fs::read(&aside).unwrap(), oversized);
        assert_eq!(mode(&aside), 0o600);
        assert_eq!(std::fs::read(&log).unwrap(), b"ready\n");

        // An oversized log that cannot be moved aside is not added to: its
        // `.1` is a folder, a link, a dangling link, a FIFO or another name
        // of the log itself.
        let elsewhere = dir.join("elsewhere");
        std::fs::write(&elsewhere, b"kept").unwrap();
        let nowhere = dir.join("nowhere");
        let fifo = |path: &Path| {
            let made = std::process::Command::new("/usr/bin/mkfifo")
                .arg(path)
                .status()
                .unwrap();
            assert!(made.success());
        };
        std::fs::remove_file(&aside).unwrap();
        for case in ["folder", "link", "dangling link", "fifo", "hard link"] {
            std::fs::write(&log, &oversized).unwrap();
            match case {
                "folder" => std::fs::create_dir(&aside).unwrap(),
                "link" => std::os::unix::fs::symlink(&elsewhere, &aside).unwrap(),
                "dangling link" => std::os::unix::fs::symlink(&nowhere, &aside).unwrap(),
                "fifo" => fifo(&aside),
                _ => std::fs::hard_link(&log, &aside).unwrap(),
            }
            run();
            assert_eq!(std::fs::read(&log).unwrap(), oversized, "{case}");
            assert_eq!(std::fs::read(&elsewhere).unwrap(), b"kept", "{case}");
            assert!(!nowhere.exists(), "{case}");
            if case == "folder" {
                assert_eq!(std::fs::read_dir(&aside).unwrap().count(), 0);
                std::fs::remove_dir(&aside).unwrap();
            } else {
                std::fs::remove_file(&aside).unwrap();
            }
        }

        // A log that is a link, a FIFO or a folder is never opened.
        std::fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &log).unwrap();
        run();
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"kept");
        std::fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(&nowhere, &log).unwrap();
        run();
        assert!(!nowhere.exists(), "a dangling link's target is not made");
        std::fs::remove_file(&log).unwrap();
        fifo(&log);
        run();
        std::fs::remove_file(&log).unwrap();
        std::fs::create_dir(&log).unwrap();
        run();
        assert_eq!(std::fs::read_dir(&log).unwrap().count(), 0);

        // A log that cannot be opened does not keep orceld from starting: no
        // folder, a file where the folder should be (which stops root too),
        // and a folder this user cannot write (root can, so not as root).
        let missing = dir.join("no-logs-folder");
        run_with(&missing.join(STDERR_LOG));
        assert!(!missing.exists());
        run_with(&elsewhere.join(STDERR_LOG));
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"kept");
        if orcel_platform::session::effective_uid() != Some(0) {
            let closed = dir.join("closed");
            std::fs::create_dir(&closed).unwrap();
            let set = |mode| {
                std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(mode)).unwrap();
            };
            set(0o500);
            run_with(&closed.join(STDERR_LOG));
            assert_eq!(std::fs::read_dir(&closed).unwrap().count(), 0);
            set(0o700);
        }
        let _ = std::fs::remove_dir_all(&base);
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
