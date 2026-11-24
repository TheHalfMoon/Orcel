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
    /// Why the MCP host last refused to serve, since the last start and since
    /// it last served. A client that keeps running is no sign that it serves:
    /// it starts its host again and again.
    pub host_refusal: Option<HostRefusal>,
}

/// `run\mcp-host-refusal.json`: `orcel-mcp-host` refused to serve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRefusal {
    pub reason: String,
    pub at_ms: u64,
}

/// Records a refusal of the MCP host, for `orcel status` and `orcel doctor`.
/// A record that cannot be written is left out: the host refuses either way.
pub fn record_host_refusal(layout: &Layout, reason: &str) {
    let refusal = HostRefusal {
        reason: crate::logs::redact_line(reason),
        at_ms: now_ms(),
    };
    let _ = std::fs::create_dir_all(layout.run_dir());
    let _ = crate::layout::write_json_atomic(&layout.host_refusal(), &refusal);
}

/// Forgets the last refusal: the host serves, or a new start begins.
pub fn clear_host_refusal(layout: &Layout) {
    let _ = std::fs::remove_file(layout.host_refusal());
}

/// The last refusal. A record that cannot be read is one too: something
/// refused and why is not known.
pub fn host_refusal(layout: &Layout) -> Option<HostRefusal> {
    crate::layout::read_json(&layout.host_refusal()).unwrap_or_else(|error| {
        Some(HostRefusal {
            reason: error.message,
            at_ms: 0,
        })
    })
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

/// SG-000135 OB-09: [`runnable_config`] for a launch, pinned to exactly this
/// setup. The setup id is read first, so a setup that is being saved meanwhile
/// leaves the launch pinned to an id that is not the saved one.
pub fn pinned_config(
    layout: &Layout,
    active_version: &str,
) -> Result<orcel_tunnel::TunnelConfig, LifecycleError> {
    let setup_id = config::read_setup_id(layout)?;
    let (config, mut tunnel) = runnable_config(layout, active_version)?;
    let pin = crate::tunnel_route::launch_pin(&config, setup_id.as_deref())?;
    tunnel.launch_pin = Some(pin);
    Ok(tunnel)
}

/// What a process or the supervisor was observed to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observed {
    Live,
    Gone,
    /// It could not be told, so it is not taken as gone.
    Unknown,
}

impl Observed {
    /// Of several things that must all have gone: live when any one is, gone
    /// only when every one is.
    pub fn all(of: impl IntoIterator<Item = Self>) -> Self {
        of.into_iter().fold(Self::Gone, |so_far, next| {
            if so_far == Self::Live || next == Self::Live {
                Self::Live
            } else if next == Self::Unknown {
                Self::Unknown
            } else {
                so_far
            }
        })
    }
}

/// Whether anything of the supervised tunnel runs, and what ends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub observed: Observed,
    /// What to do about it; empty when everything has gone.
    pub remedy: String,
}

impl Observation {
    /// An error that names the remedy, unless everything has certainly gone.
    pub fn gone(self) -> Result<(), LifecycleError> {
        match self.observed {
            Observed::Gone => Ok(()),
            Observed::Live | Observed::Unknown => Err(LifecycleError::conflict(self.remedy)),
        }
    }
}

/// One recorded process and what it was observed to be.
pub type ObservedProcess = (RecordedProcess, Observed);

/// Puts together what was observed of the recorded supervisor and tunnel
/// client (if there is a record) and of the supervisor's stop event. Each
/// remedy is one that works for what it names; none is a command that refuses.
pub fn observation(
    layout: &Layout,
    record: Option<(&ObservedProcess, &ObservedProcess)>,
    event: Observed,
) -> Observation {
    let supervisor = record.map(|(supervisor, _)| supervisor);
    let client = record.map(|(_, client)| client);
    let is = |process: Option<&ObservedProcess>, what: Observed| {
        process.is_some_and(|(_, observed)| *observed == what)
    };
    let observed = Observed::all(
        supervisor
            .iter()
            .chain(client.iter())
            .map(|(_, observed)| *observed)
            .chain([event]),
    );
    let remedy = if observed == Observed::Gone {
        String::new()
    } else if is(supervisor, Observed::Live) {
        "Run `orcel stop`".into()
    } else if event == Observed::Live {
        format!(
            "A supervisor without a record is running. Run `orcel stop`; if it does not stop, {}",
            end_unrecorded(layout)
        )
    } else if let Some(((process, _), _)) = client
        .filter(|(_, observed)| *observed == Observed::Live)
        .map(|client| (client, ()))
    {
        format!(
            "The tunnel client runs without its supervisor. End process {} ({}): `Stop-Process -Id {}`",
            process.pid, process.image, process.pid
        )
    } else if let Some((process, _)) = [supervisor, client]
        .into_iter()
        .flatten()
        .find(|(_, observed)| *observed == Observed::Unknown)
    {
        format!(
            "Process {} could not be inspected. If it is {} (Task Manager shows it), end it; if it is another program, delete {}",
            process.pid,
            process.image,
            layout.supervisor_record().display()
        )
    } else {
        "The supervisor's stop event could not be checked. Sign out of Windows and in again".into()
    };
    Observation { observed, remedy }
}

/// How to end a supervisor that has no record and does not stop: no other
/// `orcel` process runs from a version folder.
fn end_unrecorded(layout: &Layout) -> String {
    format!(
        "end the `orcel` process whose path is under {} (`Get-Process orcel | Select-Object Id,Path`)",
        layout.versions_dir().display()
    )
}

/// What [`stop_if_observed`] stopped.
pub struct Stopped {
    /// A supervisor or its client ran; not only a record was left.
    pub was_live: bool,
    pub report: StopReport,
}

/// For an update, rollback or uninstall: stops whatever runs, and is sure that
/// it has gone. `None` when nothing was there.
pub fn stop_if_observed(
    layout: &Layout,
    wait: Duration,
) -> Result<Option<Stopped>, LifecycleError> {
    let before = observe(layout)?;
    if before.observed == Observed::Gone && !layout.supervisor_record().exists() {
        return Ok(None);
    }
    // Only Windows has a supervisor to stop.
    if !cfg!(windows) {
        return Err(LifecycleError::conflict(before.remedy));
    }
    let report = stop(layout, wait)?;
    observe(layout)?.gone()?;
    Ok(Some(Stopped {
        was_live: before.observed == Observed::Live,
        report,
    }))
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

/// Whether `image` is `versions\<version>\orcel.exe` (`orcel` off Windows)
/// beneath the install root (case-insensitive, component-wise).
pub fn is_installed_cli(layout: &Layout, image: &std::path::Path) -> bool {
    let Some(version_dir) = image.parent() else {
        return false;
    };
    image.file_name().is_some_and(|name| {
        name.to_string_lossy()
            .eq_ignore_ascii_case(&crate::per_os::cli_file_name())
    }) && version_dir.parent().is_some_and(|versions| {
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
        let path = layout.supervisor_record();
        // What to do about a record that can't be trusted, with its full path.
        let fix = |problem: &str| {
            LifecycleError::state(format!(
                "{problem}. Close MCP clients using Orcel, check that no orcel.exe under {} is \
                 running (`Get-Process orcel | Select-Object Id,Path`), then delete {}",
                layout.root.display(),
                path.display()
            ))
        };
        let record: Option<SupervisorRecord> =
            read_json(&path).map_err(|error| match error.kind {
                crate::ErrorKind::State => fix(&error.message),
                _ => error,
            })?;
        if let Some(record) = &record {
            if record.schema != SUPERVISOR_SCHEMA {
                return Err(fix("the supervisor record has an unsupported schema"));
            }
            if !is_installed_cli(layout, std::path::Path::new(&record.supervisor.image)) {
                return Err(fix(
                    "the supervisor record names a process outside the Orcel install",
                ));
            }
        }
        Ok(record)
    }

    /// Whether a supervisor or its tunnel client runs for this install: the
    /// recorded processes, and the stop event a supervisor holds from before
    /// it reads the configuration (so one that has no record yet counts). An
    /// unreadable record is an error.
    pub fn observe(layout: &Layout) -> Result<Observation, LifecycleError> {
        let record = read_supervisor_record(layout)?;
        let event = StopEvent::observe(&runtime::stop_event_name(&layout.root));
        Ok(observe_record(layout, record.as_ref(), event))
    }

    fn observe_record(
        layout: &Layout,
        record: Option<&SupervisorRecord>,
        event: Observed,
    ) -> Observation {
        let look = |process: &RecordedProcess| {
            let observed = runtime::observe(&to_identity(process));
            (process.clone(), observed)
        };
        let record = record.map(|record| (look(&record.supervisor), look(&record.tunnel_client)));
        observation(
            layout,
            record
                .as_ref()
                .map(|(supervisor, client)| (supervisor, client)),
            event,
        )
    }

    /// The status when no recorded supervisor runs: one without a record may.
    fn without_supervisor(
        layout: &Layout,
        detail: &str,
        last_exit: Option<LastExit>,
        host_refusal: Option<HostRefusal>,
    ) -> Result<RuntimeStatus, LifecycleError> {
        let seen = observe(layout)?;
        let (state, detail) = match seen.observed {
            Observed::Gone => (RunState::NotRunning, detail.to_string()),
            _ => (RunState::Degraded, format!("{detail}. {}", seen.remedy)),
        };
        Ok(RuntimeStatus {
            state,
            supervisor_pid: None,
            tunnel_client_pid: None,
            health_url: None,
            health_status: None,
            detail,
            last_exit,
            host_refusal,
        })
    }

    pub fn status(layout: &Layout) -> Result<RuntimeStatus, LifecycleError> {
        let last_exit: Option<LastExit> = read_json(&layout.last_exit()).ok().flatten();
        let record = read_supervisor_record(layout)?;
        let host_refusal = host_refusal(layout);
        let Some(record) = record else {
            return without_supervisor(layout, "no supervisor record", last_exit, host_refusal);
        };
        let supervisor = runtime::open_verified(&to_identity(&record.supervisor));
        let tunnel = runtime::open_verified(&to_identity(&record.tunnel_client));
        if supervisor.is_none() {
            return without_supervisor(
                layout,
                "stale supervisor record: the recorded supervisor process is not running",
                last_exit,
                host_refusal,
            );
        }
        let (health_url, health_status) = health_of(layout);
        let (mut state, mut detail) = match (&tunnel, health_status) {
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
        if let Some(refusal) = &host_refusal {
            state = RunState::Degraded;
            detail = format!(
                "{detail}; orcel-mcp-host refused to serve: {}",
                refusal.reason
            );
        }
        Ok(RuntimeStatus {
            state,
            supervisor_pid: Some(record.supervisor.pid),
            tunnel_client_pid: tunnel.map(|live| live.identity.pid),
            health_url,
            health_status,
            detail,
            last_exit,
            host_refusal,
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
        let seen = observe(layout)?;
        if seen.observed != Observed::Gone {
            return Err(LifecycleError::conflict(format!(
                "Orcel cannot start while something of an earlier start may run. {}. Then run `orcel start` again",
                seen.remedy
            )));
        }
        // Nothing runs, so nothing is pinned to an id that is replaced here.
        config::ensure_setup_id(layout)?;
        for path in [
            layout.supervisor_record(),
            layout.stop_result(),
            layout.last_exit(),
            layout.health_url_file(),
            layout.host_refusal(),
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
                if current.supervisor_pid.is_none() {
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

    /// Stops a supervisor that has no record (one that is still starting, or
    /// whose record was deleted): it holds the stop event.
    fn stop_unrecorded(layout: &Layout, wait: Duration) -> Result<StopReport, LifecycleError> {
        let name = runtime::stop_event_name(&layout.root);
        // A result from an earlier run says nothing about this one.
        remove(&layout.stop_result());
        StopEvent::signal(&name);
        let deadline = std::time::Instant::now() + wait;
        while StopEvent::observe(&name) != Observed::Gone {
            if std::time::Instant::now() >= deadline {
                return Err(LifecycleError::state(format!(
                    "a supervisor without a record is running and did not stop in time; {}",
                    end_unrecorded(layout)
                )));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        match read_json::<StopResult>(&layout.stop_result())? {
            Some(result) if result.job_empty => Ok(StopReport {
                outcome: StopOutcome::StoppedVerified,
                detail: "a supervisor without a record confirmed its job was empty and exited"
                    .into(),
            }),
            _ => Err(LifecycleError::state(
                "a supervisor without a record exited without confirming that its job was empty; `orcel status` says what still runs",
            )),
        }
    }

    /// [`stop`] when no recorded supervisor runs: one without a record is
    /// stopped, and a leftover record is removed only when both its processes
    /// have certainly gone.
    fn stop_without_supervisor(
        layout: &Layout,
        record: Option<&SupervisorRecord>,
        wait: Duration,
    ) -> Result<StopReport, LifecycleError> {
        let event = StopEvent::observe(&runtime::stop_event_name(&layout.root));
        let unrecorded = match event {
            Observed::Live => Some(stop_unrecorded(layout, wait)?),
            _ => None,
        };
        let event = if unrecorded.is_some() {
            Observed::Gone
        } else {
            event
        };
        let left = observe_record(layout, record, event);
        if left.observed != Observed::Gone {
            return Err(LifecycleError::state(format!(
                "the supervisor is gone or could not be opened, and what is left is untouched. {}",
                left.remedy
            )));
        }
        if record.is_some() {
            remove(&layout.supervisor_record());
        }
        Ok(match (unrecorded, record) {
            (Some(report), _) => report,
            (None, Some(_)) => StopReport {
                outcome: StopOutcome::StaleRecordRemoved,
                detail: "the recorded supervisor and tunnel client are not running".into(),
            },
            (None, None) => StopReport {
                outcome: StopOutcome::NotRunning,
                detail: "no supervisor record".into(),
            },
        })
    }

    pub fn stop(layout: &Layout, wait: Duration) -> Result<StopReport, LifecycleError> {
        let Some(record) = read_supervisor_record(layout)? else {
            return stop_without_supervisor(layout, None, wait);
        };
        let Some(supervisor) = runtime::open_verified(&to_identity(&record.supervisor)) else {
            return stop_without_supervisor(layout, Some(&record), wait);
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
        // Held from before the configuration is read, so an `orcel tunnel
        // setup` that begins now sees this supervisor. One that has passed its
        // check already may still be saving, and this supervisor may read some
        // of the old setup and some of the new: setup renews the setup id
        // before it changes anything and again after, so the launch is pinned
        // to an id that is not the saved one and no host serves it.
        let event = StopEvent::create(&runtime::stop_event_name(&layout.root))?;
        // Re-verify here rather than trusting `start`'s preflight: the
        // supervisor may be invoked directly, or the install may change between
        // the preflight and this launch.
        let platform = crate::host_platform();
        let current = Installer::new(layout.clone(), platform.as_ref())
            .verify()?
            .active;
        let tunnel = pinned_config(layout, &current.version)?;
        let session = crate::full_control::begin_runtime_session(layout)?;
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
pub use imp::{observe, start, status, stop, supervise};

#[cfg(not(windows))]
fn windows_only() -> LifecycleError {
    LifecycleError::prerequisite("the Orcel runtime is supported on Windows only")
}

/// No supervisor runs on this OS; a supervisor record is not one of ours.
#[cfg(not(windows))]
pub fn observe(layout: &Layout) -> Result<Observation, LifecycleError> {
    let record = layout.supervisor_record();
    Ok(match std::fs::symlink_metadata(&record) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Observation {
            observed: Observed::Gone,
            remedy: String::new(),
        },
        _ => Observation {
            observed: Observed::Unknown,
            remedy: format!(
                "No supervisor runs on this OS, so {} is a leftover or another program's: delete it or move it away",
                record.display()
            ),
        },
    })
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

/// How long a command waits for the lifecycle lock.
#[cfg(any(windows, unix))]
const LOCK_WAIT: Duration = Duration::from_secs(60);

/// What a command that waited in vain is told.
#[cfg(any(windows, unix))]
pub(crate) const LOCK_BUSY: &str =
    "another Orcel lifecycle command is running for this install; try again when it finishes";

/// Held by every state-changing lifecycle command so install, update,
/// rollback, start, stop, uninstall, and configuration changes never
/// interleave across processes: a named mutex on Windows, a locked file on
/// Linux and macOS (`unix_lock`).
pub struct LockGuard {
    #[cfg(windows)]
    _lock: crate::runtime::LifecycleLock,
    #[cfg(unix)]
    _lock: crate::unix_lock::LifecycleLock,
}

#[cfg(windows)]
pub fn lock(layout: &Layout) -> Result<LockGuard, LifecycleError> {
    Ok(LockGuard {
        _lock: crate::runtime::LifecycleLock::acquire(&layout.root, LOCK_WAIT)?,
    })
}

#[cfg(unix)]
pub fn lock(layout: &Layout) -> Result<LockGuard, LifecycleError> {
    Ok(LockGuard {
        _lock: crate::unix_lock::LifecycleLock::acquire(layout, LOCK_WAIT)?,
    })
}

#[cfg(not(any(windows, unix)))]
pub fn lock(_layout: &Layout) -> Result<LockGuard, LifecycleError> {
    Err(windows_only())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// SG-000135 OB-09: everything must be gone; one live thing is live, and
    /// one that cannot be told is not gone.
    #[test]
    fn ob09_only_all_gone_is_gone() {
        use Observed::{Gone, Live, Unknown};
        for (of, expected) in [
            (vec![], Gone),
            (vec![Gone, Gone, Gone], Gone),
            (vec![Live, Gone, Gone], Live),
            (vec![Gone, Live, Gone], Live),
            (vec![Gone, Gone, Live], Live),
            (vec![Unknown, Live, Gone], Live),
            (vec![Live, Unknown, Gone], Live),
            (vec![Unknown, Gone, Gone], Unknown),
            (vec![Gone, Unknown, Gone], Unknown),
            (vec![Gone, Gone, Unknown], Unknown),
        ] {
            assert_eq!(Observed::all(of.clone()), expected, "{of:?}");
        }
    }

    /// SG-000135 OB-09: each thing that is left names what ends it, and what
    /// cannot be inspected names the record to delete.
    #[test]
    fn ob09_every_remedy_is_for_what_is_there() {
        use Observed::{Gone, Live, Unknown};
        let layout = Layout::new(PathBuf::from("/x/Orcel"));
        let process = |pid: u32, image: &str, observed: Observed| {
            let process = RecordedProcess {
                pid,
                creation_time: 1,
                image: image.into(),
            };
            (process, observed)
        };
        let said = |record: Option<(Observed, Observed)>, event: Observed| {
            let record = record.map(|(supervisor, client)| {
                (
                    process(11, "sup.exe", supervisor),
                    process(22, "client.exe", client),
                )
            });
            let record = record.as_ref().map(|(a, b)| (a, b));
            let seen = observation(&layout, record, event);
            (seen.observed, seen.remedy)
        };
        assert_eq!(said(None, Gone), (Gone, String::new()));
        assert_eq!(said(Some((Gone, Gone)), Gone), (Gone, String::new()));
        let record = layout.supervisor_record().display().to_string();
        let versions = layout.versions_dir().display().to_string();
        for (what, event, observed, has, not) in [
            (Some((Live, Live)), Live, Live, vec!["`orcel stop`"], "End"),
            (Some((Live, Gone)), Live, Live, vec!["`orcel stop`"], "End"),
            (
                None,
                Live,
                Live,
                vec!["without a record", "`orcel stop`", &*versions],
                "sup.exe",
            ),
            (
                Some((Gone, Gone)),
                Live,
                Live,
                vec!["without a record", &*versions],
                "sup.exe",
            ),
            (
                Some((Gone, Live)),
                Gone,
                Live,
                vec!["process 22 (client.exe)", "Stop-Process -Id 22"],
                "`orcel stop`",
            ),
            (
                Some((Unknown, Gone)),
                Gone,
                Unknown,
                vec!["Process 11", "sup.exe", &*record],
                "`orcel stop`",
            ),
            (
                Some((Gone, Unknown)),
                Gone,
                Unknown,
                vec!["Process 22", "client.exe", &*record],
                "`orcel stop`",
            ),
            (None, Unknown, Unknown, vec!["Sign out"], "`orcel stop`"),
        ] {
            let (got, remedy) = said(what, event);
            assert_eq!(got, observed, "{what:?} {event:?}");
            let seen = Observation {
                observed,
                remedy: remedy.clone(),
            };
            assert_eq!(seen.gone().unwrap_err().message, remedy);
            for has in has {
                assert!(remedy.contains(has), "{has}: {remedy}");
            }
            assert!(!remedy.contains(not), "{remedy}");
        }
    }

    /// SG-000135 OB-09: off Windows no supervisor runs; a record that is there
    /// anyway is not taken as gone, and the file is named.
    #[cfg(not(windows))]
    #[test]
    fn ob09_a_leftover_record_is_named_off_windows() {
        let dir = crate::test_support::temp_dir("observe");
        let layout = Layout::new(dir.join("Orcel"));
        assert_eq!(observe(&layout).unwrap().observed, Observed::Gone);
        std::fs::create_dir_all(layout.run_dir()).unwrap();
        std::fs::write(layout.supervisor_record(), b"{}").unwrap();
        let seen = observe(&layout).unwrap();
        assert_eq!(seen.observed, Observed::Unknown);
        let name = layout.supervisor_record().display().to_string();
        assert!(seen.remedy.contains(&name), "{}", seen.remedy);
        let refused = stop_if_observed(&layout, Duration::from_secs(1));
        let message = refused.map(|_| ()).unwrap_err().message;
        assert!(message.contains(&name), "{message}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(windows)]
    fn record_of(layout: &Layout, supervisor: RecordedProcess, tunnel_client: RecordedProcess) {
        std::fs::create_dir_all(layout.run_dir()).unwrap();
        crate::layout::write_json_atomic(
            &layout.supervisor_record(),
            &SupervisorRecord {
                schema: SUPERVISOR_SCHEMA.into(),
                version: "0.1.0".into(),
                supervisor,
                tunnel_client,
                started_at_ms: 1,
            },
        )
        .unwrap();
    }

    /// The supervisor's side of a stop: waits for the event, then says whether
    /// its job is empty (or, for `None`, nothing) and lets the event go.
    #[cfg(windows)]
    fn answering(layout: &Layout, job_empty: Option<bool>) -> std::thread::JoinHandle<()> {
        use crate::runtime::{stop_event_name, wait_any, StopEvent};
        let event = StopEvent::create(&stop_event_name(&layout.root)).unwrap();
        let result = layout.stop_result();
        std::thread::spawn(move || {
            wait_any(&[event.raw()], Duration::from_secs(10));
            if let Some(job_empty) = job_empty {
                let stopped = StopResult {
                    job_empty,
                    at_ms: 1,
                };
                crate::layout::write_json_atomic(&result, &stopped).unwrap();
            }
            drop(event);
        })
    }

    /// SG-000135 OB-09: a supervisor that has no record yet is seen by the
    /// stop event it holds, a record that cannot be trusted is an error, and
    /// a record of processes that are gone is gone.
    #[cfg(windows)]
    #[test]
    fn ob09_the_supervisor_is_observed_with_and_without_its_record() {
        use crate::runtime::{stop_event_name, StopEvent};
        let dir = crate::test_support::temp_dir("observe");
        let layout = Layout::new(dir.join("Orcel"));
        let observed = || observe(&layout).unwrap().observed;
        assert_eq!(observed(), Observed::Gone);
        assert_eq!(status(&layout).unwrap().state, RunState::NotRunning);
        let event = StopEvent::create(&stop_event_name(&layout.root)).unwrap();
        assert_eq!(observed(), Observed::Live);
        let shown = status(&layout).unwrap();
        assert_eq!(shown.state, RunState::Degraded);
        assert!(
            shown.detail.contains("without a record"),
            "{}",
            shown.detail
        );
        // `orcel stop` signals it, and does not say it is not running. One
        // that hangs is named by where it runs from.
        let error = stop(&layout, Duration::from_millis(200)).unwrap_err();
        assert!(error.message.contains("did not stop"), "{}", error.message);
        let versions = layout.versions_dir().display().to_string();
        assert!(error.message.contains(&versions), "{}", error.message);
        assert_eq!(
            crate::runtime::wait_any(&[event.raw()], Duration::from_secs(1)),
            Some(0)
        );
        assert!(stop_if_observed(&layout, Duration::from_millis(200)).is_err());
        drop(event);
        assert_eq!(
            stop(&layout, Duration::from_secs(1)).unwrap().outcome,
            StopOutcome::NotRunning
        );
        assert!(stop_if_observed(&layout, Duration::from_secs(1))
            .unwrap()
            .is_none());

        let own = crate::runtime::identify(std::process::id()).unwrap();
        let process = |creation_time: u64, image: &str| RecordedProcess {
            pid: own.pid,
            creation_time,
            image: image.into(),
        };
        let cli = layout.version_dir("0.1.0").join("orcel.exe");
        // This pid with another creation time: gone. The tunnel client's is
        // looked at as well.
        let gone = || process(1, &cli.to_string_lossy());
        let live = || process(own.creation_time, &own.image);
        record_of(&layout, gone(), gone());
        assert_eq!(observed(), Observed::Gone);
        record_of(&layout, gone(), live());
        assert_eq!(observed(), Observed::Live);
        assert_eq!(status(&layout).unwrap().state, RunState::Degraded);
        // Not an installed `orcel`, or not readable: an error.
        record_of(&layout, live(), live());
        assert!(observe(&layout).is_err());
        std::fs::write(layout.supervisor_record(), b"{").unwrap();
        assert!(observe(&layout).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SG-000135 OB-09: a supervisor without a record is stopped, beside a
    /// leftover record too, and only its own answer counts: not a result that
    /// an earlier run left. A client that outlived its supervisor is named and
    /// its record is kept.
    #[cfg(windows)]
    #[test]
    fn ob09_stop_covers_what_has_no_recorded_supervisor() {
        let dir = crate::test_support::temp_dir("stop");
        let layout = Layout::new(dir.join("Orcel"));
        std::fs::create_dir_all(layout.run_dir()).unwrap();
        let own = crate::runtime::identify(std::process::id()).unwrap();
        let cli = layout.version_dir("0.1.0").join("orcel.exe");
        let gone = || RecordedProcess {
            pid: own.pid,
            creation_time: 1,
            image: cli.to_string_lossy().into_owned(),
        };
        for leftover in [false, true] {
            for (answer, stopped) in [(Some(true), true), (Some(false), false), (None, false)] {
                // An earlier run's result, which must not count.
                let stale = StopResult {
                    job_empty: true,
                    at_ms: 1,
                };
                crate::layout::write_json_atomic(&layout.stop_result(), &stale).unwrap();
                if leftover {
                    record_of(&layout, gone(), gone());
                }
                let supervisor = answering(&layout, answer);
                let report = stop(&layout, Duration::from_secs(10));
                supervisor.join().unwrap();
                assert_eq!(
                    report.ok().map(|report| report.outcome),
                    stopped.then_some(StopOutcome::StoppedVerified),
                    "{leftover} {answer:?}"
                );
                assert_eq!(layout.supervisor_record().exists(), leftover && !stopped);
                let _ = std::fs::remove_file(layout.supervisor_record());
            }
        }
        // An update, rollback or uninstall stops it, and says it ran.
        let supervisor = answering(&layout, Some(true));
        let stopped = stop_if_observed(&layout, Duration::from_secs(10)).unwrap();
        supervisor.join().unwrap();
        assert!(stopped.is_some_and(|stopped| stopped.was_live));
        // A leftover record alone is removed, and nothing ran.
        record_of(&layout, gone(), gone());
        let stopped = stop_if_observed(&layout, Duration::from_secs(1)).unwrap();
        let stopped = stopped.unwrap();
        assert!(!stopped.was_live);
        assert_eq!(stopped.report.outcome, StopOutcome::StaleRecordRemoved);
        // A client without its supervisor (here this process).
        let client = RecordedProcess {
            pid: own.pid,
            creation_time: own.creation_time,
            image: own.image.clone(),
        };
        record_of(&layout, gone(), client);
        for refused in [
            stop(&layout, Duration::from_secs(1)).map(|_| ()),
            stop_if_observed(&layout, Duration::from_secs(1)).map(|_| ()),
        ] {
            let message = refused.unwrap_err().message;
            let named = format!("Stop-Process -Id {}", own.pid);
            assert!(message.contains(&named), "{message}");
        }
        assert!(layout.supervisor_record().exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SG-000135 OB-09: the supervisor takes its stop event before it reads
    /// anything of the install: on a root with no install, the first thing it
    /// finds is that another supervisor holds the event.
    #[cfg(windows)]
    #[test]
    fn ob09_a_supervisor_takes_its_event_before_it_reads_the_setup() {
        use crate::runtime::{stop_event_name, StopEvent};
        let dir = crate::test_support::temp_dir("supervise");
        let layout = Layout::new(dir.join("Orcel"));
        std::fs::create_dir_all(layout.run_dir()).unwrap();
        let reason = || {
            assert_eq!(supervise(&layout), 2);
            let exit: LastExit = crate::layout::read_json(&layout.last_exit())
                .unwrap()
                .unwrap();
            exit.reason
        };
        let event = StopEvent::create(&stop_event_name(&layout.root)).unwrap();
        let held = reason();
        assert!(held.contains("already running"), "{held}");
        drop(event);
        let free = reason();
        assert!(!free.contains("already running"), "{free}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SG-000135 OB-09: a launch is pinned to the setup id read before the
    /// configuration, and needs one.
    #[test]
    fn ob09_a_launch_is_pinned_to_the_saved_setup_id() {
        let dir = crate::test_support::temp_dir("pinned");
        let layout = Layout::new(dir.join("Orcel"));
        layout.ensure_private_root().unwrap();
        let project = dir.join("project");
        let version = layout.version_dir("0.1.0");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&version).unwrap();
        let client = dir.join("client");
        std::fs::write(&client, b"x").unwrap();
        std::fs::write(version.join(crate::per_os::mcp_host_file_name()), b"x").unwrap();
        let config = Config {
            workspaces: vec![config::WorkspaceEntry {
                id: "default".into(),
                root: project,
            }],
            tunnel: Some(config::TunnelSettings {
                client,
                tunnel_id: "tunnel_0123456789abcdefghijklmnopqrstuv".into(),
                profile: "core".into(),
            }),
            ..Config::default()
        };
        config.save(&layout).unwrap();
        config::store_runtime_key(&layout, "key").unwrap();
        let error = pinned_config(&layout, "0.1.0").unwrap_err();
        assert!(error.message.contains("`orcel start`"), "{}", error.message);
        let id = config::renew_setup_id(&layout).unwrap();
        let pin = pinned_config(&layout, "0.1.0").unwrap().launch_pin;
        crate::tunnel_route::check_launch_pin(&config, Some(&id), pin.as_deref()).unwrap();
        // The key is not in it: another key gives the same pin, another id not.
        config::store_runtime_key(&layout, "key-2").unwrap();
        assert_eq!(pinned_config(&layout, "0.1.0").unwrap().launch_pin, pin);
        config::renew_setup_id(&layout).unwrap();
        assert_ne!(pinned_config(&layout, "0.1.0").unwrap().launch_pin, pin);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// SG-000135 OB-09: the last refusal of the MCP host is kept until it
    /// serves or a new start, and an unreadable one is not "none".
    #[test]
    fn ob09_the_hosts_last_refusal_is_kept_and_cleared() {
        let dir = crate::test_support::temp_dir("refusal");
        let layout = Layout::new(dir.join("Orcel"));
        assert_eq!(host_refusal(&layout), None);
        record_host_refusal(&layout, "because");
        assert_eq!(host_refusal(&layout).unwrap().reason, "because");
        #[cfg(windows)]
        assert!(status(&layout).unwrap().host_refusal.is_some());
        clear_host_refusal(&layout);
        assert_eq!(host_refusal(&layout), None);
        std::fs::write(layout.host_refusal(), b"{").unwrap();
        assert!(host_refusal(&layout).is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_installed_version_cli_images_are_accepted() {
        let layout = Layout::new(PathBuf::from("/x/Orcel"));
        // Windows names unchanged; macOS and Linux names have no suffix.
        let (cli, daemon) = if cfg!(windows) {
            ("orcel.exe", "orceld.exe")
        } else {
            ("orcel", "orceld")
        };
        assert!(is_installed_cli(
            &layout,
            Path::new(&format!("/x/Orcel/versions/0.1.0/{cli}"))
        ));
        for image in [
            format!("/x/Orcel/bin/{cli}"),
            format!("/x/Orcel/versions/0.1.0/{daemon}"),
            format!("/x/Orcel/versions/0.1.0/sub/{cli}"),
            format!("/x/Orcel/versions/{cli}"),
            format!("/y/Orcel/versions/0.1.0/{cli}"),
            "/x/Windows/System32/cmd.exe".to_owned(),
        ] {
            assert!(!is_installed_cli(&layout, Path::new(&image)), "{image}");
        }
    }
}
