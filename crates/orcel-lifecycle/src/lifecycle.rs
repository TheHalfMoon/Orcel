//! `orcel start`, `stop`, `status`, and the internal `supervise` mode.
//!
//! `start` launches a detached supervisor from the active verified version.
//! The supervisor creates a kill-on-close Job Object, launches the official
//! tunnel client suspended, assigns it to the job, and only then resumes it,
//! so every descendant (the MCP host, Node.js, and `orceld`) is bound to the
//! supervisor's lifetime. `stop` signals the supervisor, which terminates the
//! job and records whether the job was observed empty. No state is reported
//! as verified unless it was observed.

use crate::config::{self, Config};
use crate::layout::Layout;
use crate::platform::Platform;
use crate::LifecycleError;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const SUPERVISOR_SCHEMA: &str = "orcel-supervisor-v1";

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

/// A recorded process identity (pid, creation time, image path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedProcess {
    pub pid: u32,
    pub creation_time: u64,
    pub image: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorRecord {
    pub schema: String,
    pub version: String,
    pub supervisor: RecordedProcess,
    pub tunnel_client: RecordedProcess,
    pub started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StopResult {
    pub job_empty: bool,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LastExit {
    pub reason: String,
    pub exit_code: Option<i32>,
    /// `Some` only when the job was actually observed; `None` when the
    /// supervisor failed before or without observing it.
    pub job_empty: Option<bool>,
    pub at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    /// Supervisor identity verified, tunnel client identity verified, and the
    /// loopback health endpoint answered.
    Running,
    /// Supervisor and tunnel client are alive but health was not verified.
    Degraded,
    NotRunning,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimeStatus {
    pub state: RunState,
    pub supervisor_pid: Option<u32>,
    pub tunnel_client_pid: Option<u32>,
    pub health_url: Option<String>,
    pub health_status: Option<u16>,
    pub detail: String,
    pub last_exit: Option<LastExit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopOutcome {
    NotRunning,
    StaleRecordRemoved,
    /// The supervisor exited after confirming its job contained no process.
    StoppedVerified,
    /// The supervisor did not answer; it was terminated and its exit was
    /// observed. Descendants were terminated by the kill-on-close job; the
    /// tunnel client's exit was observed, other descendants were not
    /// individually observed.
    SupervisorTerminated,
}

#[derive(Debug, Clone, Serialize)]
pub struct StopReport {
    pub outcome: StopOutcome,
    pub detail: String,
}

/// Loads a configuration that is complete enough to run.
pub fn runnable_config(
    layout: &Layout,
    active_version: &str,
) -> Result<(Config, orcel_tunnel::TunnelConfig), LifecycleError> {
    let config = Config::load(layout)?;
    config.check_workspaces_with_policy()?;
    let tunnel = config::tunnel_config(layout, &config, active_version)?;
    Ok((config, tunnel))
}

#[cfg(windows)]
fn health_of(layout: &Layout) -> (Option<String>, Option<u16>) {
    let Ok(text) = std::fs::read_to_string(layout.health_url_file()) else {
        return (None, None);
    };
    let url = text.trim().to_string();
    let status = crate::health::parse_health_url(&url)
        .ok()
        .and_then(|parsed| crate::health::probe(&parsed, Duration::from_secs(3)).ok());
    (Some(url), status)
}

/// Whether `image` is `versions\<version>\orcel.exe` beneath the install
/// root (case-insensitive, component-wise).
pub fn is_installed_cli(layout: &Layout, image: &std::path::Path) -> bool {
    let Some(version_dir) = image.parent() else {
        return false;
    };
    image
        .file_name()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("orcel.exe"))
        && version_dir.parent().is_some_and(|versions| {
            orcel_policy::protected_state::path_within(versions, &layout.versions_dir())
                && orcel_policy::protected_state::path_within(&layout.versions_dir(), versions)
        })
}

#[cfg(windows)]
mod imp {
    use super::*;
    use crate::install::Installer;
    use crate::layout::{read_json, write_json_atomic};
    use crate::logs::BoundedLog;
    use crate::runtime::{self, Job, ProcessIdentity, StopEvent};
    use std::io::BufRead;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use windows_sys::Win32::System::Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED};

    fn to_identity(recorded: &RecordedProcess) -> ProcessIdentity {
        ProcessIdentity {
            pid: recorded.pid,
            creation_time: recorded.creation_time,
            image: recorded.image.clone(),
        }
    }

    fn to_recorded(identity: &ProcessIdentity) -> RecordedProcess {
        RecordedProcess {
            pid: identity.pid,
            creation_time: identity.creation_time,
            image: identity.image.clone(),
        }
    }

    fn remove(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
    }

    /// Reads the supervisor record and refuses one whose supervisor image is
    /// not an installed `versions\<version>\orcel.exe` beneath the install
    /// root, so a tampered record can never direct `stop` at another process.
    fn read_supervisor_record(layout: &Layout) -> Result<Option<SupervisorRecord>, LifecycleError> {
        let record: Option<SupervisorRecord> = read_json(&layout.supervisor_record())?;
        if let Some(record) = &record {
            if record.schema != SUPERVISOR_SCHEMA {
                return Err(LifecycleError::state(
                    "the supervisor record has an unsupported schema; inspect and remove run/supervisor.json",
                ));
            }
            if !is_installed_cli(layout, std::path::Path::new(&record.supervisor.image)) {
                return Err(LifecycleError::state(
                    "the supervisor record names a process outside the Orcel install; inspect and remove run/supervisor.json",
                ));
            }
        }
        Ok(record)
    }

    pub fn status(layout: &Layout) -> Result<RuntimeStatus, LifecycleError> {
        let last_exit: Option<LastExit> = read_json(&layout.last_exit()).ok().flatten();
        let record = read_supervisor_record(layout)?;
        let Some(record) = record else {
            return Ok(RuntimeStatus {
                state: RunState::NotRunning,
                supervisor_pid: None,
                tunnel_client_pid: None,
                health_url: None,
                health_status: None,
                detail: "no supervisor record".into(),
                last_exit,
            });
        };
        let supervisor = runtime::open_verified(&to_identity(&record.supervisor));
        let tunnel = runtime::open_verified(&to_identity(&record.tunnel_client));
        if supervisor.is_none() {
            return Ok(RuntimeStatus {
                state: RunState::NotRunning,
                supervisor_pid: None,
                tunnel_client_pid: None,
                health_url: None,
                health_status: None,
                detail: "stale supervisor record: the recorded supervisor process is not running"
                    .into(),
                last_exit,
            });
        }
        let (health_url, health_status) = health_of(layout);
        let (state, detail) = match (&tunnel, health_status) {
            (None, _) => (
                RunState::Degraded,
                "supervisor alive but the recorded tunnel client is not running".to_string(),
            ),
            (Some(_), Some(code)) if (200..300).contains(&code) => (
                RunState::Running,
                format!("tunnel client alive; loopback health endpoint answered {code}"),
            ),
            (Some(_), Some(code)) => (
                RunState::Degraded,
                format!("tunnel client alive; health endpoint answered {code}"),
            ),
            (Some(_), None) => (
                RunState::Degraded,
                "tunnel client alive; health endpoint not verified".to_string(),
            ),
        };
        Ok(RuntimeStatus {
            state,
            supervisor_pid: Some(record.supervisor.pid),
            tunnel_client_pid: tunnel.map(|live| live.identity.pid),
            health_url,
            health_status,
            detail,
            last_exit,
        })
    }

    pub fn start(
        layout: &Layout,
        platform: &dyn Platform,
        wait: Duration,
    ) -> Result<RuntimeStatus, LifecycleError> {
        if platform.is_avoidably_elevated()? {
            return Err(LifecycleError::prerequisite(
                "start Orcel from a non-elevated prompt; the runtime must not run with avoidable elevation",
            ));
        }
        // A pending update may have activated a version that has not yet
        // verified itself; nothing starts until the update finishes.
        if let Some(marker) = crate::update::read_marker(layout)? {
            if marker.state == crate::update::UpdateState::Pending {
                return Err(LifecycleError::conflict(format!(
                    "an update from {} to {} is in progress or was interrupted; finish it or run `orcel rollback` before starting",
                    marker.from, marker.to
                )));
            }
        }
        let state = Installer::new(layout.clone(), platform).verify()?;
        runnable_config(layout, &state.active.version)?;
        let current = status(layout)?;
        if current.supervisor_pid.is_some() {
            return Err(LifecycleError::conflict(format!(
                "Orcel is already running (supervisor pid {})",
                current.supervisor_pid.unwrap_or_default()
            )));
        }
        for path in [
            layout.supervisor_record(),
            layout.stop_result(),
            layout.last_exit(),
            layout.health_url_file(),
        ] {
            remove(&path);
        }
        std::fs::create_dir_all(layout.logs_dir())
            .map_err(|error| LifecycleError::io("create logs directory", error))?;
        let exe = layout.version_dir(&state.active.version).join("orcel.exe");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(layout.supervisor_log())
            .map_err(|error| LifecycleError::io("open supervisor log", error))?;
        let child = runtime::spawn_detached(
            &exe,
            &["supervise"],
            &orcel_tunnel::sanitized_env(&crate::ipc::host_environment()),
            &log,
        )?;

        let deadline = std::time::Instant::now() + wait;
        loop {
            if let Some(exit) = child.exit_code() {
                let last: Option<LastExit> = read_json(&layout.last_exit()).ok().flatten();
                let tail = crate::logs::tail(&layout.supervisor_log(), 5).join(" | ");
                return Err(LifecycleError::state(format!(
                    "the supervisor exited during start (exit code {exit}); {}; supervisor log: {tail}",
                    last.map(|last| last.reason)
                        .unwrap_or_else(|| "no exit record".into())
                )));
            }
            if layout.supervisor_record().exists() && layout.health_url_file().exists() {
                let current = status(layout)?;
                if current.state == RunState::Running || std::time::Instant::now() >= deadline {
                    return Ok(current);
                }
            }
            if std::time::Instant::now() >= deadline {
                let current = status(layout)?;
                if current.state == RunState::NotRunning {
                    return Err(LifecycleError::state(format!(
                        "the supervisor did not become ready within the wait limit: {}",
                        current.detail
                    )));
                }
                return Ok(current);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    pub fn stop(layout: &Layout, wait: Duration) -> Result<StopReport, LifecycleError> {
        let record = read_supervisor_record(layout)?;
        let Some(record) = record else {
            return Ok(StopReport {
                outcome: StopOutcome::NotRunning,
                detail: "no supervisor record".into(),
            });
        };
        let Some(supervisor) = runtime::open_verified(&to_identity(&record.supervisor)) else {
            let tunnel_alive =
                runtime::open_verified(&to_identity(&record.tunnel_client)).is_some();
            if tunnel_alive {
                return Err(LifecycleError::state(
                    "the supervisor is gone but the recorded tunnel client is still running; it was not started by a live supervisor and is left untouched",
                ));
            }
            remove(&layout.supervisor_record());
            return Ok(StopReport {
                outcome: StopOutcome::StaleRecordRemoved,
                detail: "the recorded supervisor and tunnel client are not running".into(),
            });
        };
        remove(&layout.stop_result());
        let signalled = StopEvent::signal(&runtime::stop_event_name(&layout.root));
        if signalled && supervisor.wait(wait) {
            let result: Option<StopResult> = read_json(&layout.stop_result())?;
            return match result {
                Some(result) if result.job_empty => Ok(StopReport {
                    outcome: StopOutcome::StoppedVerified,
                    detail: "the supervisor confirmed its job was empty and exited".into(),
                }),
                Some(_) => Err(LifecycleError::state(
                    "the supervisor exited but could not confirm that its job was empty",
                )),
                None => Err(LifecycleError::state(
                    "the supervisor exited without recording a stop result",
                )),
            };
        }
        if !supervisor.terminate() || !supervisor.wait(Duration::from_secs(10)) {
            return Err(LifecycleError::state(
                "the supervisor did not stop and its termination could not be observed",
            ));
        }
        let tunnel_gone = {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            loop {
                match runtime::open_verified(&to_identity(&record.tunnel_client)) {
                    None => break true,
                    Some(_) if std::time::Instant::now() >= deadline => break false,
                    Some(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        };
        if !tunnel_gone {
            return Err(LifecycleError::state(
                "the supervisor was terminated but the tunnel client exit was not observed",
            ));
        }
        remove(&layout.supervisor_record());
        remove(&layout.health_url_file());
        Ok(StopReport {
            outcome: StopOutcome::SupervisorTerminated,
            detail: "the supervisor did not answer the stop request and was terminated; its exit and the tunnel client's exit were observed; other descendants were terminated by the kill-on-close job".into(),
        })
    }

    /// The detached supervisor. Returns the process exit code.
    pub fn supervise(layout: &Layout) -> i32 {
        match supervise_inner(layout) {
            Ok(code) => code,
            Err(error) => {
                eprintln!("orcel supervise: {}", error.message);
                let _ = write_json_atomic(
                    &layout.last_exit(),
                    &LastExit {
                        reason: error.message,
                        exit_code: None,
                        job_empty: None,
                        at_ms: now_ms(),
                    },
                );
                2
            }
        }
    }

    fn supervise_inner(layout: &Layout) -> Result<i32, LifecycleError> {
        // Re-verify here rather than trusting `start`'s preflight: the
        // supervisor may be invoked directly, or the install may change between
        // the preflight and this launch.
        let platform = crate::host_platform();
        let current = Installer::new(layout.clone(), platform.as_ref())
            .verify()?
            .active;
        let (_, tunnel) = runnable_config(layout, &current.version)?;
        let session = crate::full_control::begin_runtime_session(layout)?;
        let event = StopEvent::create(&runtime::stop_event_name(&layout.root))?;
        runtime::disinherit_standard_handles();
        let job = Job::kill_on_close()?;
        // #395: the runtime session binding stays local. The tunnel is a
        // remote transport, and its launch plan carries no Orcel variable.
        let host_env = crate::ipc::host_environment();
        let plan = match tunnel.launch_plan(&host_env) {
            Ok(plan) => plan,
            Err(message) => {
                crate::full_control::end_runtime_session(layout, &session.session_id);
                return Err(LifecycleError::state(format!(
                    "tunnel launch plan: {message}"
                )));
            }
        };
        let mut child = Command::new(&plan.program)
            .args(&plan.args)
            .env_clear()
            .envs(&plan.env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
            .spawn()
            .map_err(|error| LifecycleError::state(format!("start tunnel client: {error}")))?;
        if let Err(error) = job.assign(runtime::child_handle(&child)) {
            let _ = child.kill();
            return Err(error);
        }
        let tunnel_identity = runtime::identify(child.id())
            .ok_or_else(|| LifecycleError::state("the tunnel client identity could not be read"))?;
        let log = Arc::new(Mutex::new(
            BoundedLog::open(&layout.tunnel_log())
                .map_err(|error| LifecycleError::io("open tunnel log", error))?,
        ));
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let mut reader = std::io::BufReader::new(stream);
                let mut buffer = Vec::new();
                while matches!(reader.read_until(b'\n', &mut buffer), Ok(read) if read > 0) {
                    let line = String::from_utf8_lossy(&buffer);
                    if let Ok(mut log) = log.lock() {
                        let _ = log.write_line(line.trim_end_matches(['\r', '\n']));
                    }
                    buffer.clear();
                }
            });
        }
        runtime::resume_process(child.id())?;
        let own = runtime::identify(std::process::id())
            .ok_or_else(|| LifecycleError::state("the supervisor identity could not be read"))?;
        write_json_atomic(
            &layout.supervisor_record(),
            &SupervisorRecord {
                schema: SUPERVISOR_SCHEMA.into(),
                version: current.version.clone(),
                supervisor: to_recorded(&own),
                tunnel_client: to_recorded(&tunnel_identity),
                started_at_ms: now_ms(),
            },
        )?;

        let handles = [event.raw(), runtime::child_handle(&child)];
        let signalled = loop {
            if let Some(index) = runtime::wait_any(&handles, Duration::from_secs(3600)) {
                break index;
            }
        };
        let job_empty = job.terminate_and_confirm_empty(Duration::from_secs(10))?;
        let exit_code = child
            .try_wait()
            .ok()
            .flatten()
            .and_then(|status| status.code());
        remove(&layout.health_url_file());
        crate::full_control::end_runtime_session(layout, &session.session_id);
        if signalled == 0 {
            write_json_atomic(
                &layout.stop_result(),
                &StopResult {
                    job_empty,
                    at_ms: now_ms(),
                },
            )?;
            remove(&layout.supervisor_record());
            Ok(if job_empty { 0 } else { 4 })
        } else {
            write_json_atomic(
                &layout.last_exit(),
                &LastExit {
                    reason: "the tunnel client exited".into(),
                    exit_code,
                    job_empty: Some(job_empty),
                    at_ms: now_ms(),
                },
            )?;
            remove(&layout.supervisor_record());
            Ok(3)
        }
    }
}

#[cfg(windows)]
pub use imp::{start, status, stop, supervise};

#[cfg(not(windows))]
fn windows_only() -> LifecycleError {
    LifecycleError::prerequisite("the Orcel runtime is supported on Windows only")
}

#[cfg(not(windows))]
pub fn status(_layout: &Layout) -> Result<RuntimeStatus, LifecycleError> {
    Err(windows_only())
}

#[cfg(not(windows))]
pub fn start(
    _layout: &Layout,
    _platform: &dyn Platform,
    _wait: Duration,
) -> Result<RuntimeStatus, LifecycleError> {
    Err(windows_only())
}

#[cfg(not(windows))]
pub fn stop(_layout: &Layout, _wait: Duration) -> Result<StopReport, LifecycleError> {
    Err(windows_only())
}

#[cfg(not(windows))]
pub fn supervise(_layout: &Layout) -> i32 {
    eprintln!("orcel supervise: {}", windows_only().message);
    2
}

/// Held by every state-changing lifecycle command so install, update,
/// rollback, start, stop, uninstall, and configuration changes never
/// interleave across processes.
pub struct LockGuard {
    #[cfg(windows)]
    _lock: crate::runtime::LifecycleLock,
}

#[cfg(windows)]
pub fn lock(layout: &Layout) -> Result<LockGuard, LifecycleError> {
    Ok(LockGuard {
        _lock: crate::runtime::LifecycleLock::acquire(&layout.root, Duration::from_secs(60))?,
    })
}

#[cfg(not(windows))]
pub fn lock(_layout: &Layout) -> Result<LockGuard, LifecycleError> {
    Ok(LockGuard {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    #[test]
    fn only_installed_version_cli_images_are_accepted() {
        let layout = Layout::new(PathBuf::from("/x/Orcel"));
        assert!(is_installed_cli(
            &layout,
            Path::new("/x/Orcel/versions/0.1.0/orcel.exe")
        ));
        for image in [
            "/x/Orcel/bin/orcel.exe",
            "/x/Orcel/versions/0.1.0/orceld.exe",
            "/x/Orcel/versions/0.1.0/sub/orcel.exe",
            "/x/Orcel/versions/orcel.exe",
            "/y/Orcel/versions/0.1.0/orcel.exe",
            "/x/Windows/System32/cmd.exe",
        ] {
            assert!(!is_installed_cli(&layout, Path::new(image)), "{image}");
        }
    }
}
