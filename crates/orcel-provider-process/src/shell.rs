//! SG-000096: ordinary current-user ("Full User") shell and process launch.
//!
//! orceld is the only caller and the only authority. It checks the protected
//! Full User lease and a fresh per-action SOFT approval, then derives an
//! [`ExpectedNativeOwner`] from that verified state and calls this module.
//! This module never grants anything: it refuses a launch whose native
//! identity differs from the expectation, and it supervises what it starts.
//!
//! Launch order on Windows: the expected owner process is reopened and its
//! token checked; the executable and cwd are pinned by handle (share-read
//! only, no reparse component, the executable hashed through its handle and
//! compared with the approved identity); the child is created suspended with
//! an exact inherited-handle list; it is put in a kill-on-close Job with a
//! process limit; then, before `ResumeThread`, the Job membership, the
//! child's token (SID, logon LUID, session, not elevated, not AppContainer),
//! its creation generation and its image file are checked again. Any failure
//! before resume terminates the child and proves it gone; the child never
//! runs. After resume, an unclear outcome is reported as unknown and is never
//! retried.
//!
//! A Full User process has the user's ambient filesystem and network power.
//! The Job Object bounds its lifetime and process count; it is not a
//! filesystem or network sandbox. Full Admin (elevated tokens) is refused.
//!
//! macOS and Linux have no Full User shell in SG-000096: the lease binds a
//! Windows SID and logon session. Those hosts keep the Safe and contained
//! tiers, and this module returns [`ShellFailure::Unavailable`] there.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MAX_ARGUMENTS: usize = 64;
pub const MAX_ARGUMENT_BYTES: usize = 8192;
/// CreateProcessW takes at most 32,767 UTF-16 units, NUL included.
pub const MAX_COMMAND_LINE_UNITS: usize = 32_767;
pub const MIN_TIMEOUT: Duration = Duration::from_secs(1);
pub const MAX_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const MAX_STDOUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_STDERR_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROCESSES: u32 = 64;
const MAX_ENV_ENTRIES: usize = 64;
const MAX_ENV_VALUE_BYTES: usize = 32 * 1024;

/// The identity orceld expects the launch to run as. Every value comes from
/// orceld's verified authority state: the user SID and logon LUID from the
/// MAC-verified Full User lease, the owner PID and creation generation from
/// the validated runtime session record. A caller never supplies them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedNativeOwner {
    pub user_sid: String,
    pub logon_luid: u64,
    pub owner_pid: u32,
    pub owner_creation: u64,
}

/// The executable identity a user approved: a pinned path, its SHA-256 and
/// its native file identity, all measured through one held handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableIdentity {
    pub path: PathBuf,
    pub sha256: [u8; 32],
    pub volume_serial: u32,
    pub file_index: u64,
}

impl ExecutableIdentity {
    pub fn sha256_hex(&self) -> String {
        self.sha256
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    /// The most processes the launch's Job may hold at once.
    pub max_processes: u32,
}

/// An exact launch: executable identity, argv (argv[0] is the executable,
/// these are the arguments after it), cwd and an allowlisted environment.
/// There is no shell interpretation here; a PowerShell or cmd script is the
/// argv orceld built for the fixed system interpreter the user approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommand {
    pub executable: ExecutableIdentity,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub limits: ShellLimits,
}

/// The native identity of a launched child, read from its own handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeProcessIdentity {
    pub pid: u32,
    pub creation_generation: u64,
    pub user_sid: String,
    pub logon_luid: u64,
    pub session_id: u32,
}

/// One output stream. `bytes` holds at most the stream's limit, from the
/// start; `dropped_bytes` counts what came after it. `complete` is true only
/// when the end of the stream was observed, so output is never reported as
/// complete when it might not be.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub total_bytes: u64,
    pub dropped_bytes: u64,
    pub complete: bool,
}

impl CapturedStream {
    #[cfg_attr(not(windows), allow(dead_code))]
    pub(crate) fn push(&mut self, chunk: &[u8], limit: usize) {
        self.total_bytes = self.total_bytes.saturating_add(chunk.len() as u64);
        let room = limit.saturating_sub(self.bytes.len());
        let kept = room.min(chunk.len());
        self.bytes.extend_from_slice(&chunk[..kept]);
        self.dropped_bytes = self
            .dropped_bytes
            .saturating_add((chunk.len() - kept) as u64);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OneShotEnd {
    /// The primary process exited with this native exit code.
    Exited { exit_code: u32 },
    /// The timeout fired; the whole Job was terminated and proven empty.
    /// No exit status is reported because none was produced.
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneShotOutcome {
    pub process: NativeProcessIdentity,
    pub end: OneShotEnd,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    /// Processes were still in the Job when the primary exited or timed out,
    /// and they were terminated: nothing outlives a launch.
    pub descendants_terminated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellFailure {
    /// The command is malformed or out of bounds. Nothing was created.
    Invalid(String),
    /// An identity check failed. Nothing was created, or the child was
    /// terminated before it ran any code and its exit was proven.
    Denied(String),
    /// The platform or a native API cannot launch. Nothing is running.
    Unavailable(String),
    /// A process could not be proven gone. Treat its effects as unknown.
    TerminationUnverified(String),
    /// The child was resumed but its outcome cannot be established. The
    /// operation may have had effects and must never be retried.
    OutcomeUnknown(String),
}

impl ShellFailure {
    pub fn message(&self) -> &str {
        match self {
            Self::Invalid(message)
            | Self::Denied(message)
            | Self::Unavailable(message)
            | Self::TerminationUnverified(message)
            | Self::OutcomeUnknown(message) => message,
        }
    }
}

fn invalid(message: impl Into<String>) -> ShellFailure {
    ShellFailure::Invalid(message.into())
}

/// Whether `name` may be passed to a Full User child. The same allowlist as
/// Safe, and no secret-like or Orcel-internal name.
pub fn environment_name_allowed(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    !name.is_empty()
        && !name.contains(['=', '\0'])
        && crate::allowed_execution_env(name)
        && !crate::SECRETISH.iter().any(|needle| upper.contains(needle))
        && !crate::FORBIDDEN_ORCEL_ENV.contains(&upper.as_str())
}

/// Checks bounds and shape before any native work. Never silently drops an
/// environment entry: an entry that would not be passed is refused, so what
/// was approved is exactly what runs.
pub fn validate_command(command: &ShellCommand) -> Result<(), ShellFailure> {
    if !command.executable.path.is_absolute() || !command.cwd.is_absolute() {
        return Err(invalid("shell executable and cwd must be absolute"));
    }
    if command.argv.len() > MAX_ARGUMENTS
        || command
            .argv
            .iter()
            .any(|arg| arg.len() > MAX_ARGUMENT_BYTES || arg.contains('\0'))
    {
        return Err(invalid("shell arguments are out of bounds"));
    }
    if command.env.len() > MAX_ENV_ENTRIES {
        return Err(invalid("shell environment has too many entries"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in &command.env {
        if !environment_name_allowed(name) {
            return Err(invalid(format!(
                "environment variable {name:?} may not be passed to a shell"
            )));
        }
        if !seen.insert(name.to_ascii_uppercase()) {
            return Err(invalid("duplicate case-insensitive environment variable"));
        }
        if value.contains('\0') || value.len() > MAX_ENV_VALUE_BYTES {
            return Err(invalid("shell environment value is out of bounds"));
        }
    }
    let limits = &command.limits;
    if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&limits.timeout)
        || !(1..=MAX_STDOUT_BYTES).contains(&limits.stdout_bytes)
        || !(1..=MAX_STDERR_BYTES).contains(&limits.stderr_bytes)
        || !(1..=MAX_PROCESSES).contains(&limits.max_processes)
    {
        return Err(invalid("shell resource limits are out of bounds"));
    }
    Ok(())
}

pub fn validate_owner(owner: &ExpectedNativeOwner) -> Result<(), ShellFailure> {
    if !owner.user_sid.starts_with("S-1-")
        || owner.user_sid.len() > 184
        || owner.logon_luid == 0
        || owner.owner_pid == 0
        || owner.owner_creation == 0
    {
        return Err(ShellFailure::Denied(
            "expected native owner is absent or malformed".into(),
        ));
    }
    Ok(())
}

/// Pins `path` by handle and returns the identity a user can approve.
#[cfg(windows)]
pub fn measure_executable(path: &Path) -> Result<ExecutableIdentity, ShellFailure> {
    crate::windows_contained_launch::shell::measure_executable(path)
}

#[cfg(not(windows))]
pub fn measure_executable(_path: &Path) -> Result<ExecutableIdentity, ShellFailure> {
    Err(unavailable())
}

/// Runs one approved command to completion or timeout and returns its
/// bounded, separated output. See the module docs for the launch order.
#[cfg(windows)]
pub fn run_one_shot(
    command: &ShellCommand,
    owner: &ExpectedNativeOwner,
) -> Result<OneShotOutcome, ShellFailure> {
    crate::windows_contained_launch::shell::run_one_shot(command, owner)
}

#[cfg(not(windows))]
pub fn run_one_shot(
    command: &ShellCommand,
    owner: &ExpectedNativeOwner,
) -> Result<OneShotOutcome, ShellFailure> {
    validate_command(command)?;
    validate_owner(owner)?;
    Err(unavailable())
}

#[cfg(not(windows))]
fn unavailable() -> ShellFailure {
    ShellFailure::Unavailable(
        "SG-000096 Full User shells are Windows-only; this host keeps the Safe and contained tiers"
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command() -> ShellCommand {
        ShellCommand {
            executable: ExecutableIdentity {
                path: std::env::temp_dir().join("tool"),
                sha256: [7; 32],
                volume_serial: 1,
                file_index: 2,
            },
            argv: vec!["--version".into()],
            cwd: std::env::temp_dir(),
            env: BTreeMap::from([("PATH".into(), "x".into())]),
            limits: ShellLimits {
                timeout: Duration::from_secs(5),
                stdout_bytes: 1024,
                stderr_bytes: 1024,
                max_processes: 4,
            },
        }
    }

    #[test]
    fn sg000096_shell_command_bounds_are_enforced() {
        assert_eq!(validate_command(&command()), Ok(()));
        type Mutation = Box<dyn Fn(&mut ShellCommand)>;
        let cases: Vec<Mutation> = vec![
            Box::new(|c| c.executable.path = PathBuf::from("tool")),
            Box::new(|c| c.cwd = PathBuf::from("rel")),
            Box::new(|c| c.argv = vec![String::new(); MAX_ARGUMENTS + 1]),
            Box::new(|c| c.argv = vec!["a\0b".into()]),
            Box::new(|c| c.argv = vec!["x".repeat(MAX_ARGUMENT_BYTES + 1)]),
            Box::new(|c| c.limits.timeout = Duration::from_millis(10)),
            Box::new(|c| c.limits.timeout = MAX_TIMEOUT + Duration::from_secs(1)),
            Box::new(|c| c.limits.stdout_bytes = 0),
            Box::new(|c| c.limits.stdout_bytes = MAX_STDOUT_BYTES + 1),
            Box::new(|c| c.limits.stderr_bytes = MAX_STDERR_BYTES + 1),
            Box::new(|c| c.limits.max_processes = 0),
            Box::new(|c| c.limits.max_processes = MAX_PROCESSES + 1),
            Box::new(|c| {
                c.env.insert("Path".into(), "y".into());
            }),
            Box::new(|c| {
                c.env.insert("TEMP".into(), "a\0".into());
            }),
        ];
        for (index, mutate) in cases.iter().enumerate() {
            let mut candidate = command();
            mutate(&mut candidate);
            assert!(
                matches!(validate_command(&candidate), Err(ShellFailure::Invalid(_))),
                "case {index}"
            );
        }
    }

    #[test]
    fn sg000096_shell_environment_refuses_secrets_and_orcel_internals() {
        for name in [
            "ORCEL_DAEMON",
            "ORCEL_TUNNEL_KEY_FILE",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "FOO",
            "",
            "A=B",
        ] {
            let mut candidate = command();
            candidate.env.insert(name.into(), "value".into());
            assert!(
                matches!(validate_command(&candidate), Err(ShellFailure::Invalid(_))),
                "{name:?} must be refused, not dropped"
            );
        }
        for name in ["PATH", "SystemRoot", "TEMP", "TMP", "LOCALAPPDATA"] {
            assert!(environment_name_allowed(name), "{name}");
        }
    }

    #[test]
    fn sg000096_expected_owner_must_be_complete() {
        let owner = ExpectedNativeOwner {
            user_sid: "S-1-5-21-1".into(),
            logon_luid: 9,
            owner_pid: 4,
            owner_creation: 5,
        };
        assert_eq!(validate_owner(&owner), Ok(()));
        for mutate in [
            |o: &mut ExpectedNativeOwner| o.user_sid = "admin".into(),
            |o: &mut ExpectedNativeOwner| o.logon_luid = 0,
            |o: &mut ExpectedNativeOwner| o.owner_pid = 0,
            |o: &mut ExpectedNativeOwner| o.owner_creation = 0,
        ] {
            let mut candidate = owner.clone();
            mutate(&mut candidate);
            assert!(matches!(
                validate_owner(&candidate),
                Err(ShellFailure::Denied(_))
            ));
        }
    }

    #[test]
    fn sg000096_captured_stream_counts_every_dropped_byte() {
        let mut stream = CapturedStream::default();
        stream.push(b"abc", 4);
        stream.push(b"defg", 4);
        stream.push(b"", 4);
        assert_eq!(stream.bytes, b"abcd");
        assert_eq!(stream.total_bytes, 7);
        assert_eq!(stream.dropped_bytes, 3);
        assert!(!stream.complete);
    }

    #[cfg(not(windows))]
    #[test]
    fn sg000096_full_user_shell_is_unavailable_off_windows() {
        let owner = ExpectedNativeOwner {
            user_sid: "S-1-5-21-1".into(),
            logon_luid: 9,
            owner_pid: 4,
            owner_creation: 5,
        };
        assert!(matches!(
            run_one_shot(&command(), &owner),
            Err(ShellFailure::Unavailable(_))
        ));
        assert!(matches!(
            measure_executable(Path::new("/bin/sh")),
            Err(ShellFailure::Unavailable(_))
        ));
    }
}
