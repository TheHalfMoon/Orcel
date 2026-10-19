//! orcel-contain: Orcel's one-shot launcher for the contained execution tier
//! (XP-13).
//!
//! orceld starts this helper from a pinned, digest-verified path with an empty
//! environment, writes one closed, bounded spec on stdin (`spec.rs`), and keeps
//! stdin open. The helper installs every boundary the platform advertises
//! (`containment.rs`), runs the child, relays its bounded stdout and stderr and
//! its exit, writes one result on stdout, and exits. It has no listener, reads
//! no environment variable and takes no argument.
//!
//! Parent death is covered twice: end of file on stdin (orceld closed it or
//! died) kills the child's tree, and on Linux the helper also arms
//! `PR_SET_PDEATHSIG` before it reads the spec. If the helper itself is killed,
//! the child dies through its own boundary: `PR_SET_PDEATHSIG` (Linux), the
//! sentinel pipe (macOS) or the kill-on-close Job Object (Windows).

mod containment;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod spec;
#[cfg(unix)]
mod unix;
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod unsupported;
#[cfg(windows)]
mod windows;

use std::io::{Read as _, Write as _};
use std::process::ExitCode;
use std::time::Duration;

use containment::{ContainmentLimits, RunBounds, RunOutcome, Stream};

/// The helper ran the child and wrote its result.
const EXIT_RAN: u8 = 0;
/// The helper refused before launching anything and wrote the refusal.
const EXIT_REFUSED: u8 = 3;

fn main() -> ExitCode {
    let launcher = arm_parent_death();
    let mut stdin = std::io::stdin();
    let spec = match spec::read_spec(&mut stdin) {
        Ok(spec) => spec,
        Err(error) => return refuse(error.kind(), error.message(), None),
    };
    if let Some(launcher) = launcher {
        // The death signal is armed against whoever started the helper. That
        // must be the supervisor the spec names, or the guarantee is about the
        // wrong process (or the supervisor already died).
        if launcher != spec.parent {
            return refuse(
                "invalid_spec",
                "the helper was not started by the supervisor the spec names",
                None,
            );
        }
    }

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => return refuse("launch_failed", "failed to start the helper runtime", None),
    };
    let (gone, parent_gone) = tokio::sync::oneshot::channel::<()>();
    // The supervisor writes nothing after `end`; end of file or any byte at
    // all means it is gone or misbehaving, and either way the run stops.
    let watcher = std::thread::Builder::new()
        .name("orcel-contain-parent".to_owned())
        .spawn(move || {
            let mut byte = [0_u8; 1];
            let _ = stdin.read(&mut byte);
            let _ = gone.send(());
        });
    if watcher.is_err() {
        return refuse("launch_failed", "failed to watch the supervisor", None);
    }

    let limits = ContainmentLimits {
        max_memory_bytes: spec.memory_bytes,
        max_cpu_time: Duration::from_secs(spec.cpu_seconds),
        max_open_files: u32::try_from(spec.open_files).unwrap_or(u32::MAX),
        additional_writable_paths: spec.write.clone(),
        additional_readable_paths: spec.read.clone(),
    };
    let bounds = RunBounds {
        timeout: Duration::from_millis(spec.timeout_ms),
        stdout_bytes: usize::try_from(spec.stdout_bytes).unwrap_or(usize::MAX),
        stderr_bytes: usize::try_from(spec.stderr_bytes).unwrap_or(usize::MAX),
    };
    let result = runtime.block_on(containment::run(
        &spec.executable,
        &spec.args,
        &spec.workdir,
        &limits,
        bounds,
        async {
            let _ = parent_gone.await;
        },
    ));
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let detail = error.detail.as_deref();
            return refuse(error.code.as_str(), &error.message, detail);
        }
    };
    let (outcome, code) = match result.outcome {
        RunOutcome::Exited(code) => ("exited", code),
        RunOutcome::Signaled(signal) => ("signaled", signal),
        RunOutcome::ResourceLimit => ("resource_limit", 0),
        RunOutcome::TimedOut => ("timed_out", 0),
        RunOutcome::OutputLimit(Stream::Stdout) => ("stdout_limit", 0),
        RunOutcome::OutputLimit(Stream::Stderr) => ("stderr_limit", 0),
        RunOutcome::ParentGone => ("parent_gone", 0),
    };
    let header = spec::result_header(
        outcome,
        code,
        result.stdout.len(),
        result.stderr.len(),
        None,
    );
    write_result(&header, &result.stdout, &result.stderr, EXIT_RAN)
}

fn refuse(kind: &str, message: &str, detail: Option<&str>) -> ExitCode {
    let text = match detail {
        Some(detail) => format!("{kind}: {message} ({detail})"),
        None => format!("{kind}: {message}"),
    };
    let header = spec::result_header("refused", 0, 0, 0, Some(&text));
    write_result(&header, &[], &[], EXIT_REFUSED)
}

fn write_result(header: &str, stdout: &[u8], stderr: &[u8], status: u8) -> ExitCode {
    let mut out = std::io::stdout().lock();
    let written = out
        .write_all(header.as_bytes())
        .and_then(|()| out.write_all(stdout))
        .and_then(|()| out.write_all(stderr))
        .and_then(|()| out.flush());
    match written {
        Ok(()) => ExitCode::from(status),
        // The supervisor is gone; there is no one to report to.
        Err(_) => ExitCode::from(EXIT_REFUSED),
    }
}

/// Arm `PR_SET_PDEATHSIG` for the helper itself and return the pid it is armed
/// against. The parent may already have exited between our start and the
/// prctl; the caller compares the pid with the spec, which catches that.
#[cfg(target_os = "linux")]
fn arm_parent_death() -> Option<u32> {
    // SAFETY: prctl and getppid have no memory preconditions.
    unsafe {
        if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
            libc::_exit(i32::from(EXIT_REFUSED));
        }
        u32::try_from(libc::getppid()).ok()
    }
}

/// macOS has no death signal; the supervisor's stdin and the child's sentinel
/// cover parent death. The launcher pid is still checked against the spec.
#[cfg(target_os = "macos")]
fn arm_parent_death() -> Option<u32> {
    // SAFETY: getppid has no preconditions.
    u32::try_from(unsafe { libc::getppid() }).ok()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn arm_parent_death() -> Option<u32> {
    None
}
