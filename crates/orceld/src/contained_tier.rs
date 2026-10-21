//! XP-13b: the opt-in contained tier for registered executables.
//!
//! A registry entry chooses its tier when it is registered, under the same
//! STRONG approval (`executable.registry.add` with `"tier": "contained"`).
//! `process.spawn` keeps its policy, approval and pre-launch identity check.
//! The approval digest also binds the tier, and only the launch differs:
//!
//! - the pinned `orcel-contain` helper runs the executable (`run_contained`):
//!   no network, no process creation, the CPU, memory and descriptor limits;
//! - the requested cwd is granted read-only; the child's own working
//!   directory is a fresh private scratch directory under the state root,
//!   removed after the run; nothing else of the user's is writable;
//! - a contained entry never falls back to the Safe tier. A missing helper,
//!   a missing or malformed pin, or a helper that refuses is an error.
//!
//! The helper is resolved only next to orceld's own executable (the signed
//! install root, no `PATH` lookup, no environment override):
//! `orcel-contain[.exe]` and its pin, `orcel-contain.sha256`, which every
//! package installs beside it. On Windows both are part of the
//! manifest-verified payload; on Linux both are root-owned under
//! `/usr/lib/orcel`.

use orcel_contracts::FailureCode;
use orcel_policy::executable_registry::ExecutionTier;
use orcel_provider_fs::ProviderError;
use orcel_provider_process::contained::{
    run_contained, ContainedError, ContainedLimits, ContainedOutcome, ContainedSpec,
    ContainedStream, HelperPin, RefusalKind,
};
use orcel_provider_process::ExecutionPlan;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub const HELPER_NAME: &str = if cfg!(windows) {
    "orcel-contain.exe"
} else {
    "orcel-contain"
};
pub const PIN_NAME: &str = "orcel-contain.sha256";

const MEMORY_BYTES: u64 = 1 << 30;
const OPEN_FILES: u32 = 256;

fn unavailable(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::ProviderUnavailable, message)
}

/// The registered tier of the plan's executable, read before approval so the
/// approval can bind it. The Windows `whoami.exe` baseline is Safe.
pub fn registered_tier(plan: &ExecutionPlan) -> Result<ExecutionTier, ProviderError> {
    #[cfg(windows)]
    if let Some(system_root) = std::env::var_os("SystemRoot") {
        let baseline = std::fs::canonicalize(
            PathBuf::from(system_root)
                .join("System32")
                .join("whoami.exe"),
        );
        if baseline.as_ref().is_ok_and(|path| *path == plan.executable) {
            return Ok(ExecutionTier::Safe);
        }
    }
    let registry_path = orcel_policy::executable_registry::default_registry_path()
        .map_err(|error| unavailable(format!("executable registry is unavailable: {error}")))?;
    let entries = orcel_policy::executable_registry::load_registry(&registry_path);
    orcel_policy::executable_registry::check_spawn(&entries, &plan.executable, &plan.argv)
        .map(|entry| entry.tier)
        .map_err(|error| ProviderError::new(error.code, error.message))
}

/// Tests only: a pin to use instead of the install directory's (the root
/// workspace cannot build the helper, so the end-to-end test is handed one).
#[cfg(test)]
pub(crate) static TEST_PIN: std::sync::Mutex<Option<HelperPin>> = std::sync::Mutex::new(None);

/// The helper beside the running orceld.
pub fn installed_helper_pin() -> Result<HelperPin, ProviderError> {
    #[cfg(test)]
    if let Some(pin) = TEST_PIN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
    {
        return Ok(pin);
    }
    let exe = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(|error| unavailable(format!("orceld cannot resolve its own path: {error}")))?;
    let dir = exe
        .parent()
        .ok_or_else(|| unavailable("orceld has no install directory"))?;
    helper_pin_in(dir)
}

/// `dir/orcel-contain[.exe]`, pinned by the single lowercase SHA-256 line in
/// `dir/orcel-contain.sha256`.
///
/// The pin is only as trustworthy as the directory holding it: whoever can
/// write there can replace the helper and its pin together. Both files, and
/// every directory above them, must therefore pass
/// `check_owned_executable_location`, or the tier is unavailable: owned by
/// the user or root and not writable by group or others (no write-granting
/// ACL entry on macOS); on Windows, owned by the user, SYSTEM,
/// Administrators or TrustedInstaller with no DACL entry that lets anyone
/// else change them (#384 item 4).
pub fn helper_pin_in(dir: &Path) -> Result<HelperPin, ProviderError> {
    let helper = dir.join(HELPER_NAME);
    for file in [dir.join(PIN_NAME), helper.clone()] {
        if file.exists() {
            orcel_platform::paths::check_owned_executable_location(&file).map_err(|reason| {
                unavailable(format!(
                    "the contained-tier helper or its pin could be replaced by another user: {reason}"
                ))
            })?;
        }
    }
    let pin = std::fs::read(dir.join(PIN_NAME)).map_err(|error| {
        unavailable(format!(
            "the contained tier is not installed ({PIN_NAME}: {error})"
        ))
    })?;
    let digest = parse_pin_named(&pin, PIN_NAME)?;
    HelperPin::new(helper, digest).map_err(|error| {
        unavailable(format!(
            "the contained-tier helper cannot be pinned: {error:?}"
        ))
    })
}

/// The single lowercase SHA-256 line of a pin file named `name` (this
/// helper's, or WI-05's document parser's).
pub(crate) fn parse_pin_named<'a>(bytes: &'a [u8], name: &str) -> Result<&'a str, ProviderError> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| unavailable(format!("{name} is not text")))?;
    let digest = text.strip_suffix('\n').unwrap_or(text);
    let digest = digest.strip_suffix('\r').unwrap_or(digest);
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(unavailable(format!(
            "{name} must hold one lowercase SHA-256"
        )));
    }
    Ok(digest)
}

/// A fresh, private, canonical scratch directory for one run, removed on
/// drop.
struct Scratch(PathBuf);

impl Scratch {
    fn create(request_digest: &str) -> Result<Self, ProviderError> {
        let root = orcel_platform::paths::state_root()
            .map_err(|error| unavailable(format!("state root is unavailable: {error}")))?;
        let runs = root.join("contained-runs");
        private_dir_builder(true)
            .create(&runs)
            .map_err(|error| unavailable(format!("contained scratch root: {error}")))?;
        orcel_platform::paths::ensure_private_dir(&runs)
            .map_err(|error| unavailable(format!("contained scratch root: {error}")))?;
        let dir = runs.join(format!("{}-{request_digest}", std::process::id()));
        // A leftover from a crashed run with the same name is not reused.
        let _ = std::fs::remove_dir_all(&dir);
        private_dir_builder(false)
            .create(&dir)
            .map_err(|error| unavailable(format!("contained scratch directory: {error}")))?;
        let canonical = std::fs::canonicalize(&dir)
            .map_err(|error| unavailable(format!("contained scratch directory: {error}")))?;
        Ok(Self(canonical))
    }
}

/// Directories created owner-only (0700) off Windows, where the state root's
/// private-directory check requires it.
pub(crate) fn private_dir_builder(recursive: bool) -> std::fs::DirBuilder {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(recursive);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The spec the helper receives for an approved, identity-checked plan. It
/// carries the registered digest, which the helper checks through the
/// descriptor it executes (#384 item 2); a plan without one is refused.
pub fn spec_for(plan: &ExecutionPlan, workdir: PathBuf) -> Result<ContainedSpec, ProviderError> {
    let executable_sha256 = plan.registered_sha256.clone().ok_or_else(|| {
        ProviderError::new(
            FailureCode::TargetStale,
            "a contained run needs the executable's registered digest; nothing was launched",
        )
    })?;
    Ok(ContainedSpec {
        executable: plan.executable.clone(),
        executable_sha256,
        argv: plan.argv.clone(),
        workdir,
        readable: vec![plan.cwd.clone()],
        writable: Vec::new(),
        limits: ContainedLimits {
            timeout: plan.limits.timeout,
            stdout_bytes: plan.limits.stdout_bytes,
            stderr_bytes: plan.limits.stderr_bytes,
            memory_bytes: MEMORY_BYTES,
            cpu_seconds: plan.limits.timeout.as_secs().max(1),
            open_files: OPEN_FILES,
        },
    })
}

/// Run an approved, identity-checked plan through the pinned helper.
pub fn execute(
    plan: &ExecutionPlan,
    pin: &HelperPin,
    request_digest: &str,
) -> Result<Value, ProviderError> {
    let scratch = Scratch::create(request_digest)?;
    let spec = spec_for(plan, scratch.0.clone())?;
    let run = run_contained(pin, &spec).map_err(map_contained_error)?;
    let exit_code = match run.outcome {
        ContainedOutcome::Exited(code) => code,
        ContainedOutcome::Signaled(signal) => 128 + signal,
        ContainedOutcome::TimedOut => {
            return Err(ProviderError::new(
                FailureCode::ProcessTimeout,
                "contained process exceeded the approved timeout and the helper ended its tree",
            ))
        }
        ContainedOutcome::ResourceLimit => {
            return Err(ProviderError::new(
                FailureCode::ProcessTimeout,
                "contained process reached its CPU or memory ceiling and was ended",
            ))
        }
        ContainedOutcome::OutputLimit(stream) => {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                match stream {
                    ContainedStream::Stdout => {
                        "contained process stdout exceeded the approved bound and was ended"
                    }
                    ContainedStream::Stderr => {
                        "contained process stderr exceeded the approved bound and was ended"
                    }
                },
            ))
        }
    };
    Ok(json!({
        "exit_code": exit_code,
        "stdout": String::from_utf8_lossy(&run.stdout),
        "stderr": String::from_utf8_lossy(&run.stderr),
        "execution_tier": ExecutionTier::Contained.as_str(),
        "stdin_policy": "null",
        "network_class": "NONE"
    }))
}

pub(crate) fn map_contained_error(error: ContainedError) -> ProviderError {
    match error {
        ContainedError::InvalidSpec(message) => ProviderError::new(
            FailureCode::InvalidRequest,
            format!("contained spec refused: {message}"),
        ),
        ContainedError::SpecTooLarge => ProviderError::new(
            FailureCode::InvalidRequest,
            "contained spec exceeds the helper's bound",
        ),
        ContainedError::HelperTampered => ProviderError::new(
            FailureCode::TargetStale,
            "the contained-tier helper does not match its pin; nothing was launched",
        ),
        ContainedError::Refused {
            kind: RefusalKind::ExecutableChanged,
            ..
        } => ProviderError::new(
            FailureCode::TargetStale,
            "the executable no longer matches its registered digest when the helper opened it; nothing was launched",
        ),
        ContainedError::Refused { kind, message } => unavailable(format!(
            "the contained-tier helper refused ({}): {message}",
            match kind {
                RefusalKind::UnsupportedPlatform => "unsupported_platform",
                RefusalKind::LaunchFailed => "launch_failed",
                RefusalKind::ResourceLimitExceeded => "resource_limit_exceeded",
                RefusalKind::Crashed => "crashed",
                RefusalKind::SpecTooLarge => "spec_too_large",
                RefusalKind::InvalidSpec => "invalid_spec",
                RefusalKind::ExecutableChanged => "executable_changed",
            }
        )),
        other => unavailable(format!("the contained-tier helper failed: {other:?}")),
    }
}

#[cfg(test)]
#[path = "contained_tier_tests.rs"]
mod tests;
