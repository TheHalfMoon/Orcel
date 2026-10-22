use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// XP-13: the contained tier (no network, exact read/write allowlist, no
/// process creation), run through the pinned `orcel-contain` helper.
pub mod contained;
/// WI-05: the confined document parser's spec and output frame.
pub mod document_parser;
/// SG-000096: ordinary current-user (Full User) shell processes. Never
/// reachable from Safe; orceld gates every launch on its own authority.
pub mod shell;
/// SG-000096 T03: bounded interactive Full User sessions.
pub mod shell_session;

/// XP-13b: the Safe tier on Linux and macOS (process group, pidfd or
/// kqueue, cgroup v2 when delegated, rlimits, owned cleanup).
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
mod unix;

const SECRETISH: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "CREDENTIAL",
    "API_KEY",
    "PRIVATE_KEY",
    "TUNNEL_KEY",
];

const FORBIDDEN_ORCEL_ENV: &[&str] = &[
    "ORCEL_TUNNEL_ID",
    "ORCEL_TUNNEL_CLIENT",
    "ORCEL_TUNNEL_KEY_FILE",
    "ORCEL_TUNNEL_HEALTH_URL_FILE",
    "ORCEL_DAEMON",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub timeout: Duration,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            stdout_bytes: 2 * 1024 * 1024,
            stderr_bytes: 256 * 1024,
        }
    }
}

impl ExecutionLimits {
    pub fn validate(&self) -> Result<(), ExecutionPlanError> {
        if self.timeout.is_zero() || self.timeout > Duration::from_secs(30 * 60) {
            return Err(ExecutionPlanError::new(
                "timeout must be between 1 second and 30 minutes",
            ));
        }
        if self.stdout_bytes == 0 || self.stdout_bytes > 16 * 1024 * 1024 {
            return Err(ExecutionPlanError::new(
                "stdout limit must be between 1 byte and 16 MiB",
            ));
        }
        if self.stderr_bytes == 0 || self.stderr_bytes > 4 * 1024 * 1024 {
            return Err(ExecutionPlanError::new(
                "stderr limit must be between 1 byte and 4 MiB",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    pub executable: PathBuf,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub limits: ExecutionLimits,
    /// XP-13b: the registered SHA-256 (lower-case hex) the caller verified.
    /// On Linux and macOS the Safe tier hashes the file it opens against
    /// it and runs that same open file. `None` (the default from
    /// [`build_execution_plan`]) skips the digest, not the location check.
    pub registered_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlanError {
    pub message: String,
}

impl ExecutionPlanError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

pub fn build_execution_plan(
    workspace_root: impl AsRef<Path>,
    executable: impl AsRef<Path>,
    argv: &[String],
    requested_cwd: impl AsRef<Path>,
    source_env: &BTreeMap<String, String>,
    limits: ExecutionLimits,
) -> Result<ExecutionPlan, ExecutionPlanError> {
    limits.validate()?;

    let workspace_root = canonical_dir(workspace_root.as_ref(), "workspace root")?;
    let executable = executable.as_ref();
    if !executable.is_absolute() {
        return Err(ExecutionPlanError::new(
            "execution executable must be an absolute path",
        ));
    }
    let executable = canonical_file(executable, "execution executable")?;

    for arg in argv {
        if arg.contains('\0') {
            return Err(ExecutionPlanError::new("argv contains a NUL byte"));
        }
    }

    let requested_cwd = requested_cwd.as_ref();
    let cwd = if requested_cwd.as_os_str().is_empty() || requested_cwd == Path::new(".") {
        workspace_root.clone()
    } else if requested_cwd.is_absolute() {
        canonical_dir(requested_cwd, "execution cwd")?
    } else {
        canonical_dir(&workspace_root.join(requested_cwd), "execution cwd")?
    };
    if cwd != workspace_root && !cwd.starts_with(&workspace_root) {
        return Err(ExecutionPlanError::new(
            "execution cwd resolves outside the trusted workspace",
        ));
    }

    Ok(ExecutionPlan {
        executable,
        argv: argv.to_vec(),
        cwd,
        env: sanitized_execution_env(source_env),
        registered_sha256: None,
        limits,
    })
}

pub fn sanitized_execution_env(source: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (name, value) in source {
        let upper = name.to_ascii_uppercase();
        if SECRETISH.iter().any(|needle| upper.contains(needle)) {
            continue;
        }
        if FORBIDDEN_ORCEL_ENV
            .iter()
            .any(|forbidden| upper == *forbidden)
        {
            continue;
        }
        if allowed_execution_env(name) {
            out.insert(name.clone(), value.clone());
        }
    }
    out
}

fn allowed_execution_env(name: &str) -> bool {
    // Windows environment names are case-insensitive, but the provider only
    // receives the exact allowlisted vocabulary, regardless of letter case.
    matches!(
        name.to_ascii_uppercase().as_str(),
        "PATH"
            | "PATHEXT"
            | "COMSPEC"
            | "SYSTEMROOT"
            | "WINDIR"
            | "TEMP"
            | "TMP"
            | "HOME"
            | "USERPROFILE"
            | "LOCALAPPDATA"
            | "APPDATA"
            | "PROGRAMDATA"
            | "PROGRAMFILES"
            | "PROGRAMFILES(X86)"
            | "LANG"
            | "LC_ALL"
    )
}

fn canonical_dir(path: &Path, label: &str) -> Result<PathBuf, ExecutionPlanError> {
    let resolved = fs::canonicalize(path)
        .map_err(|error| ExecutionPlanError::new(format!("resolve {label}: {error}")))?;
    if !resolved.is_dir() {
        return Err(ExecutionPlanError::new(format!(
            "{label} is not a directory"
        )));
    }
    Ok(resolved)
}

fn canonical_file(path: &Path, label: &str) -> Result<PathBuf, ExecutionPlanError> {
    let resolved = fs::canonicalize(path)
        .map_err(|error| ExecutionPlanError::new(format!("resolve {label}: {error}")))?;
    if !resolved.is_file() {
        return Err(ExecutionPlanError::new(format!("{label} is not a file")));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("orcel-process-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create root");
        root
    }

    fn executable(root: &Path) -> PathBuf {
        let path = root.join("tool.bin");
        fs::write(&path, b"test").expect("seed executable");
        path
    }

    #[test]
    fn creates_bounded_plan_inside_workspace() {
        let workspace = root("ok");
        let work = workspace.join("project");
        fs::create_dir_all(&work).unwrap();
        let exe = executable(&workspace);
        let env = BTreeMap::from([
            ("PATH".to_owned(), "bin".to_owned()),
            ("OPENAI_API_KEY".to_owned(), "secret".to_owned()),
            ("ORCEL_TUNNEL_KEY_FILE".to_owned(), "secret-path".to_owned()),
        ]);

        let plan = build_execution_plan(
            &workspace,
            &exe,
            &["--version".into()],
            "project",
            &env,
            ExecutionLimits::default(),
        )
        .unwrap();

        assert_eq!(plan.cwd, fs::canonicalize(work).unwrap());
        assert_eq!(plan.env.get("PATH").map(String::as_str), Some("bin"));
        assert!(!plan.env.contains_key("OPENAI_API_KEY"));
        assert!(!plan.env.contains_key("ORCEL_TUNNEL_KEY_FILE"));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn case_insensitive_system_environment_keeps_secrets_denied() {
        let source = BTreeMap::from([
            ("SYSTEMROOT".to_owned(), "C:\\Windows".to_owned()),
            ("comspec".to_owned(), "cmd.exe".to_owned()),
            (
                "programfiles(x86)".to_owned(),
                "Program Files (x86)".to_owned(),
            ),
            ("SYSTEMROOT_API_KEY".to_owned(), "secret".to_owned()),
            ("orcel_tunnel_key_file".to_owned(), "secret".to_owned()),
            ("malicious".to_owned(), "no".to_owned()),
        ]);
        let cleaned = sanitized_execution_env(&source);
        assert_eq!(
            cleaned.get("SYSTEMROOT").map(String::as_str),
            Some("C:\\Windows")
        );
        assert_eq!(cleaned.get("comspec").map(String::as_str), Some("cmd.exe"));
        assert!(cleaned.contains_key("programfiles(x86)"));
        assert!(!cleaned.contains_key("SYSTEMROOT_API_KEY"));
        assert!(!cleaned.contains_key("orcel_tunnel_key_file"));
        assert!(!cleaned.contains_key("malicious"));
    }

    #[test]
    fn rejects_relative_executable() {
        let workspace = root("relative-exe");
        let error = build_execution_plan(
            &workspace,
            "tool.exe",
            &[],
            ".",
            &BTreeMap::new(),
            ExecutionLimits::default(),
        )
        .unwrap_err();
        assert!(error.message.contains("absolute path"));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn rejects_cwd_escape() {
        let workspace = root("workspace");
        let outside = root("outside");
        let exe = executable(&workspace);
        let error = build_execution_plan(
            &workspace,
            &exe,
            &[],
            &outside,
            &BTreeMap::new(),
            ExecutionLimits::default(),
        )
        .unwrap_err();
        assert!(error.message.contains("outside the trusted workspace"));
        let _ = fs::remove_dir_all(workspace);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn rejects_nul_argv() {
        let workspace = root("nul");
        let exe = executable(&workspace);
        let error = build_execution_plan(
            &workspace,
            &exe,
            &["bad\0arg".into()],
            ".",
            &BTreeMap::new(),
            ExecutionLimits::default(),
        )
        .unwrap_err();
        assert!(error.message.contains("NUL"));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn validates_appcontainer_profile_names() {
        assert!(validate_appcontainer_name("Orcel.Probe.123").is_ok());
        assert!(validate_appcontainer_name("").is_err());
        assert!(validate_appcontainer_name("Orcel/Probe").is_err());
        assert!(validate_appcontainer_name(&"a".repeat(65)).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_appcontainer_profile_lifecycle_is_available() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let name = format!("Orcel.Probe.{}.{}", std::process::id(), suffix);
        let result = probe_appcontainer_profile(&name).expect("AppContainer lifecycle");
        assert!(result.profile_created);
        assert!(result.sid_derived);
        assert!(result.profile_deleted);
    }

    #[test]
    fn private_qualification_plan_rejects_non_allowlisted_environment() {
        let workspace = root("private-env");
        let exe = executable(&workspace);
        let mut source = BTreeMap::new();
        source.insert("PATH".to_owned(), "safe".to_owned());
        source.insert("ORCEL_TUNNEL_KEY_FILE".to_owned(), "secret".to_owned());
        source.insert("API_KEY".to_owned(), "secret".to_owned());
        let plan = build_execution_plan(
            &workspace,
            &exe,
            &[],
            ".",
            &source,
            ExecutionLimits::default(),
        )
        .expect("plan");
        assert!(!plan
            .env
            .keys()
            .any(|key| key.contains("ORCEL") || key.contains("API")));
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn private_qualification_plan_rejects_nul_and_parent_cwd() {
        let workspace = root("private-invalid");
        let exe = executable(&workspace);
        assert!(build_execution_plan(
            &workspace,
            &exe,
            &["bad\0arg".into()],
            ".",
            &BTreeMap::new(),
            ExecutionLimits::default(),
        )
        .is_err());
        assert!(build_execution_plan(
            &workspace,
            &exe,
            &[],
            "..",
            &BTreeMap::new(),
            ExecutionLimits::default(),
        )
        .is_err());
        let _ = fs::remove_dir_all(workspace);
    }

    #[test]
    fn rejects_unbounded_limits() {
        let workspace = root("limits");
        let exe = executable(&workspace);
        let error = build_execution_plan(
            &workspace,
            &exe,
            &[],
            ".",
            &BTreeMap::new(),
            ExecutionLimits {
                timeout: Duration::from_secs(31 * 60),
                stdout_bytes: 1,
                stderr_bytes: 1,
            },
        )
        .unwrap_err();
        assert!(error.message.contains("30 minutes"));
        let _ = fs::remove_dir_all(workspace);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppContainerProbe {
    pub profile_created: bool,
    pub sid_derived: bool,
    pub profile_deleted: bool,
}

pub fn validate_appcontainer_name(name: &str) -> Result<(), ExecutionPlanError> {
    if name.is_empty() || name.encode_utf16().count() > 64 {
        return Err(ExecutionPlanError::new(
            "AppContainer name must contain 1..=64 UTF-16 code units",
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | ' '))
    {
        return Err(ExecutionPlanError::new(
            "AppContainer name contains a character outside the Windows allowed set",
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn probe_appcontainer_profile(name: &str) -> Result<AppContainerProbe, ExecutionPlanError> {
    windows_appcontainer::probe(name)
}

#[cfg(not(windows))]
pub fn probe_appcontainer_profile(_name: &str) -> Result<AppContainerProbe, ExecutionPlanError> {
    Err(ExecutionPlanError::new(
        "AppContainer probing is available only on Windows",
    ))
}

#[cfg(windows)]
mod windows_appcontainer {
    use super::{validate_appcontainer_name, AppContainerProbe, ExecutionPlanError};
    use core::ffi::c_void;
    use std::ptr;

    type Hresult = i32;
    type Psid = *mut c_void;

    #[repr(C)]
    struct SidAndAttributes {
        sid: Psid,
        attributes: u32,
    }

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn CreateAppContainerProfile(
            app_container_name: *const u16,
            display_name: *const u16,
            description: *const u16,
            capabilities: *const SidAndAttributes,
            capability_count: u32,
            app_container_sid: *mut Psid,
        ) -> Hresult;

        fn DeriveAppContainerSidFromAppContainerName(
            app_container_name: *const u16,
            app_container_sid: *mut Psid,
        ) -> Hresult;

        fn DeleteAppContainerProfile(app_container_name: *const u16) -> Hresult;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn FreeSid(sid: Psid) -> *mut c_void;
    }

    pub(super) fn probe(name: &str) -> Result<AppContainerProbe, ExecutionPlanError> {
        validate_appcontainer_name(name)?;
        let name = wide(name);
        let display = wide("Orcel execution probe");
        let description = wide("Temporary Orcel AppContainer capability probe");

        let mut created_sid: Psid = ptr::null_mut();
        let create_hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                ptr::null(),
                0,
                &mut created_sid,
            )
        };
        if create_hr != 0 {
            return Err(hresult_error("CreateAppContainerProfile", create_hr));
        }

        if !created_sid.is_null() {
            unsafe {
                FreeSid(created_sid);
            }
        }

        let mut derived_sid: Psid = ptr::null_mut();
        let derive_hr =
            unsafe { DeriveAppContainerSidFromAppContainerName(name.as_ptr(), &mut derived_sid) };
        if derive_hr != 0 {
            let _ = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
            return Err(hresult_error(
                "DeriveAppContainerSidFromAppContainerName",
                derive_hr,
            ));
        }

        if !derived_sid.is_null() {
            unsafe {
                FreeSid(derived_sid);
            }
        }

        let delete_hr = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
        if delete_hr != 0 {
            let _ = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
            return Err(hresult_error("DeleteAppContainerProfile", delete_hr));
        }

        Ok(AppContainerProbe {
            profile_created: true,
            sid_derived: true,
            profile_deleted: true,
        })
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn hresult_error(operation: &str, code: Hresult) -> ExecutionPlanError {
        ExecutionPlanError::new(format!(
            "{operation} failed with HRESULT 0x{:08X}",
            code as u32
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobObjectProbe {
    pub job_created: bool,
    pub kill_on_close_set: bool,
    pub handle_closed: bool,
}

#[cfg(windows)]
pub fn probe_job_object_kill_on_close() -> Result<JobObjectProbe, ExecutionPlanError> {
    windows_job_object::probe()
}

#[cfg(not(windows))]
pub fn probe_job_object_kill_on_close() -> Result<JobObjectProbe, ExecutionPlanError> {
    Err(ExecutionPlanError::new(
        "Job Object probing is available only on Windows",
    ))
}

#[cfg(windows)]
mod windows_job_object {
    use super::{ExecutionPlanError, JobObjectProbe};
    use core::ffi::c_void;
    use std::mem;
    use std::ptr;

    type Handle = *mut c_void;

    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateJobObjectW(job_attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            information_class: i32,
            information: *const c_void,
            information_length: u32,
        ) -> i32;
        fn CloseHandle(object: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    pub(super) fn probe() -> Result<JobObjectProbe, ExecutionPlanError> {
        let job = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if job.is_null() {
            return Err(last_error("CreateJobObjectW"));
        }

        let mut information = JobObjectExtendedLimitInformation::default();
        information.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let configured = unsafe {
            SetInformationJobObject(
                job,
                JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                (&information as *const JobObjectExtendedLimitInformation).cast(),
                mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
            )
        };

        if configured == 0 {
            let error = last_error("SetInformationJobObject");
            unsafe {
                CloseHandle(job);
            }
            return Err(error);
        }

        let closed = unsafe { CloseHandle(job) };
        if closed == 0 {
            return Err(last_error("CloseHandle"));
        }

        Ok(JobObjectProbe {
            job_created: true,
            kill_on_close_set: true,
            handle_closed: true,
        })
    }

    fn last_error(operation: &str) -> ExecutionPlanError {
        let code = unsafe { GetLastError() };
        ExecutionPlanError::new(format!("{operation} failed with Win32 error {code}"))
    }
}

#[cfg(all(test, windows))]
mod job_object_tests {
    use super::*;

    #[test]
    fn windows_job_object_kill_on_close_is_available() {
        let result = probe_job_object_kill_on_close().expect("Job Object lifecycle");
        assert!(result.job_created);
        assert!(result.kill_on_close_set);
        assert!(result.handle_closed);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainedLaunchProbe {
    pub profile_created: bool,
    pub process_created_suspended: bool,
    pub appcontainer_token_verified: bool,
    pub assigned_to_job_before_resume: bool,
    pub resumed: bool,
    pub child_completed: bool,
    pub exit_code: u32,
    pub profile_deleted: bool,
}

#[cfg(windows)]
pub fn probe_contained_appcontainer_job_launch(
    name: &str,
) -> Result<ContainedLaunchProbe, ExecutionPlanError> {
    windows_contained_launch::probe(name)
}

#[cfg(not(windows))]
pub fn probe_contained_appcontainer_job_launch(
    _name: &str,
) -> Result<ContainedLaunchProbe, ExecutionPlanError> {
    Err(ExecutionPlanError::new(
        "contained AppContainer launch probing is available only on Windows",
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateExecutionResult {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub appcontainer_verified: bool,
    pub assigned_to_job_before_resume: bool,
    pub job_quiescent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrivateExecutionFailure {
    InvalidPlan(String),
    Provider(String),
    ProcessTimeout,
    OutputLimit(OutputStream),
    TerminationUnverified,
    /// XP-13b: the executable could be replaced by another local user (its
    /// file or a directory above it is shared-writable or foreign-owned).
    ExecutableRejected(String),
    /// XP-13b: the file opened for launch does not match the registered
    /// digest, or changed between the check and the launch.
    IdentityChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PrivateExecutionMode {
    Public,
    Success,
    Timeout,
    StdoutLimit,
    StderrLimit,
    DescendantDrain,
    /// XP-13b: a descendant in the job that holds none of the run's pipes and
    /// outlives the primary; owned cleanup must end it.
    DetachedDescendant,
}

#[cfg(windows)]
pub fn execute_contained(
    plan: ExecutionPlan,
    profile_name: &str,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    qualify_private_execution_mode(plan, profile_name, PrivateExecutionMode::Public)
}

/// Linux and macOS: the profile name names a Windows AppContainer and is
/// unused. The result's `appcontainer_verified` is false;
/// `assigned_to_job_before_resume` and `job_quiescent` report the process
/// group (and cgroup, when delegated) set before exec and seen empty after
/// the run. See `unix.rs`.
#[cfg(all(
    any(target_os = "linux", target_os = "macos"),
    target_pointer_width = "64"
))]
pub fn execute_contained(
    plan: ExecutionPlan,
    _profile_name: &str,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    unix::execute(plan)
}

#[cfg(not(any(
    windows,
    all(
        any(target_os = "linux", target_os = "macos"),
        target_pointer_width = "64"
    )
)))]
pub fn execute_contained(
    _plan: ExecutionPlan,
    _profile_name: &str,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    Err(PrivateExecutionFailure::Provider(
        "registered executable execution is not available on this platform".into(),
    ))
}

#[cfg(windows)]
pub fn qualify_private_execution(
    plan: ExecutionPlan,
    profile_name: &str,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    qualify_private_execution_mode(plan, profile_name, PrivateExecutionMode::Success)
}

#[cfg(windows)]
pub(crate) fn qualify_private_execution_mode(
    plan: ExecutionPlan,
    profile_name: &str,
    mode: PrivateExecutionMode,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    windows_contained_launch::qualify_private_execution(plan, profile_name, mode)
}

#[cfg(not(windows))]
pub fn qualify_private_execution(
    _plan: ExecutionPlan,
    _profile_name: &str,
) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
    Err(PrivateExecutionFailure::Provider(
        "private contained execution qualification is available only on Windows".into(),
    ))
}

/// SG-000096: handle-pinned executable and cwd identity.
#[cfg(windows)]
mod native_path_identity_windows;

#[cfg(windows)]
mod windows_contained_launch {
    use super::{
        allowed_execution_env, validate_appcontainer_name, ContainedLaunchProbe, ExecutionPlan,
        ExecutionPlanError, OutputStream, PrivateExecutionFailure, PrivateExecutionMode,
        PrivateExecutionResult, FORBIDDEN_ORCEL_ENV, SECRETISH,
    };
    use core::ffi::c_void;
    use std::ffi::{OsStr, OsString};
    use std::mem;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr;

    type Handle = *mut c_void;
    type Psid = *mut c_void;
    type Hresult = i32;

    /// SG-000096: the ordinary current-user launch (no AppContainer).
    pub(crate) mod shell;
    /// SG-000096 T03: supervised interactive sessions on that launch.
    pub(crate) mod shell_session;

    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_UNICODE_ENVIRONMENT: u32 = 0x0000_0400;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x0008_0000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 131_081;
    const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 131_074;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 1;
    const FILE_SHARE_WRITE: u32 = 2;
    const OPEN_EXISTING: u32 = 3;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    const JOB_OBJECT_LIMIT_ACTIVE_PROCESS: u32 = 0x0000_0008;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS: i32 = 9;
    const TOKEN_QUERY: u32 = 0x0008;
    const TOKEN_IS_APP_CONTAINER: i32 = 29;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_FAILED: u32 = u32::MAX;
    const RESUME_FAILED: u32 = u32::MAX;
    const PROBE_TIMEOUT_MS: u32 = 15_000;
    const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;
    const JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS: i32 = 1;
    const ERROR_BROKEN_PIPE: u32 = 109;
    const QUIESCENCE_POLL_MS: u64 = 10;
    const QUIESCENCE_TIMEOUT_MS: u64 = 5_000;
    const POST_EXIT_DRAIN_TIMEOUT_MS: u64 = 500;
    const POST_TERMINATION_DRAIN_TIMEOUT_MS: u64 = 1_000;

    #[repr(C)]
    struct SidAndAttributes {
        sid: Psid,
        attributes: u32,
    }

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    struct SecurityCapabilities {
        app_container_sid: Psid,
        capabilities: *mut SidAndAttributes,
        capability_count: u32,
        reserved: u32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *mut u16,
        lp_desktop: *mut u16,
        lp_title: *mut u16,
        dw_x: u32,
        dw_y: u32,
        dw_x_size: u32,
        dw_y_size: u32,
        dw_x_count_chars: u32,
        dw_y_count_chars: u32,
        dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        cb_reserved_2: u16,
        lp_reserved_2: *mut u8,
        h_std_input: Handle,
        h_std_output: Handle,
        h_std_error: Handle,
    }

    #[repr(C)]
    struct StartupInfoExW {
        startup_info: StartupInfoW,
        attribute_list: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct NativeFileTime {
        low: u32,
        high: u32,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: Handle,
        thread: Handle,
        process_id: u32,
        thread_id: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct JobObjectBasicAccountingInformation {
        total_user_time: i64,
        total_kernel_time: i64,
        this_period_total_user_time: i64,
        this_period_total_kernel_time: i64,
        total_page_fault_count: u32,
        total_processes: u32,
        active_processes: u32,
        total_terminated_processes: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct JobObjectBasicLimitInformation {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: u32,
        minimum_working_set_size: usize,
        maximum_working_set_size: usize,
        active_process_limit: u32,
        affinity: usize,
        priority_class: u32,
        scheduling_class: u32,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct IoCounters {
        read_operation_count: u64,
        write_operation_count: u64,
        other_operation_count: u64,
        read_transfer_count: u64,
        write_transfer_count: u64,
        other_transfer_count: u64,
    }

    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default)]
    struct JobObjectExtendedLimitInformation {
        basic_limit_information: JobObjectBasicLimitInformation,
        io_info: IoCounters,
        process_memory_limit: usize,
        job_memory_limit: usize,
        peak_process_memory_used: usize,
        peak_job_memory_used: usize,
    }

    #[link(name = "userenv")]
    unsafe extern "system" {
        fn CreateAppContainerProfile(
            app_container_name: *const u16,
            display_name: *const u16,
            description: *const u16,
            capabilities: *const SidAndAttributes,
            capability_count: u32,
            app_container_sid: *mut Psid,
        ) -> Hresult;
        fn DeleteAppContainerProfile(app_container_name: *const u16) -> Hresult;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn FreeSid(sid: Psid) -> *mut c_void;
        fn OpenProcessToken(
            process_handle: Handle,
            desired_access: u32,
            token_handle: *mut Handle,
        ) -> i32;
        fn GetTokenInformation(
            token_handle: Handle,
            token_information_class: i32,
            token_information: *mut c_void,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn EqualSid(left: Psid, right: Psid) -> i32;
        fn ConvertSidToStringSidW(sid: Psid, text: *mut *mut u16) -> i32;
        fn ConvertStringSidToSidW(text: *const u16, sid: *mut Psid) -> i32;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn InitializeProcThreadAttributeList(
            attribute_list: *mut c_void,
            attribute_count: u32,
            flags: u32,
            size: *mut usize,
        ) -> i32;
        fn UpdateProcThreadAttribute(
            attribute_list: *mut c_void,
            flags: u32,
            attribute: usize,
            value: *mut c_void,
            size: usize,
            previous_value: *mut c_void,
            return_size: *mut usize,
        ) -> i32;
        fn DeleteProcThreadAttributeList(attribute_list: *mut c_void);
        fn GetProcessHeap() -> Handle;
        fn HeapAlloc(heap: Handle, flags: u32, bytes: usize) -> *mut c_void;
        fn HeapFree(heap: Handle, flags: u32, memory: *mut c_void) -> i32;
        fn CreateProcessW(
            application_name: *const u16,
            command_line: *mut u16,
            process_attributes: *const c_void,
            thread_attributes: *const c_void,
            inherit_handles: i32,
            creation_flags: u32,
            environment: *mut c_void,
            current_directory: *const u16,
            startup_info: *const StartupInfoW,
            process_information: *mut ProcessInformation,
        ) -> i32;
        fn CreateJobObjectW(job_attributes: *const c_void, name: *const u16) -> Handle;
        fn SetInformationJobObject(
            job: Handle,
            information_class: i32,
            information: *const c_void,
            information_length: u32,
        ) -> i32;
        fn AssignProcessToJobObject(job: Handle, process: Handle) -> i32;
        fn IsProcessInJob(process: Handle, job: Handle, result: *mut i32) -> i32;
        fn ResumeThread(thread: Handle) -> u32;
        fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        fn GetExitCodeProcess(process: Handle, exit_code: *mut u32) -> i32;
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
        #[cfg(test)]
        fn GetCurrentProcess() -> Handle;
        fn GetProcessTimes(
            process: Handle,
            creation: *mut NativeFileTime,
            exit: *mut NativeFileTime,
            kernel: *mut NativeFileTime,
            user: *mut NativeFileTime,
        ) -> i32;
        fn LocalFree(memory: Handle) -> Handle;
        fn CreatePipe(
            read_pipe: *mut Handle,
            write_pipe: *mut Handle,
            attributes: *const c_void,
            size: u32,
        ) -> i32;
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *const c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn SetHandleInformation(handle: *mut core::ffi::c_void, mask: u32, flags: u32) -> i32;
        fn PeekNamedPipe(
            pipe: Handle,
            buffer: *mut c_void,
            size: u32,
            read: *mut u32,
            available: *mut u32,
            left: *mut u32,
        ) -> i32;
        fn ReadFile(
            pipe: Handle,
            buffer: *mut c_void,
            size: u32,
            read: *mut u32,
            overlapped: *mut c_void,
        ) -> i32;
        fn QueryInformationJobObject(
            job: Handle,
            information_class: i32,
            information: *mut c_void,
            length: u32,
            return_length: *mut u32,
        ) -> i32;
        fn TerminateJobObject(job: Handle, exit_code: u32) -> i32;
        fn Sleep(milliseconds: u32);
        fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
        fn CloseHandle(object: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    struct OwnedHandle(Handle);

    impl OwnedHandle {
        fn new(handle: Handle, operation: &str) -> Result<Self, ExecutionPlanError> {
            if handle.is_null() || handle as isize == -1 {
                Err(last_error(operation))
            } else {
                Ok(Self(handle))
            }
        }

        fn raw(&self) -> Handle {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    struct AppContainerProfile {
        name: Vec<u16>,
        sid: Psid,
        deleted: bool,
    }

    impl AppContainerProfile {
        fn create(name: &str) -> Result<Self, ExecutionPlanError> {
            validate_appcontainer_name(name)?;
            let name_wide = wide(OsStr::new(name));
            let display = wide(OsStr::new("Orcel contained launch probe"));
            let description = wide(OsStr::new(
                "Temporary zero-capability Orcel AppContainer launch probe",
            ));
            let mut sid: Psid = ptr::null_mut();

            let result = unsafe {
                CreateAppContainerProfile(
                    name_wide.as_ptr(),
                    display.as_ptr(),
                    description.as_ptr(),
                    ptr::null(),
                    0,
                    &mut sid,
                )
            };
            if result != 0 {
                return Err(hresult_error("CreateAppContainerProfile", result));
            }
            if sid.is_null() {
                let _ = unsafe { DeleteAppContainerProfile(name_wide.as_ptr()) };
                return Err(ExecutionPlanError::new(
                    "CreateAppContainerProfile returned a null SID",
                ));
            }

            Ok(Self {
                name: name_wide,
                sid,
                deleted: false,
            })
        }

        fn sid(&self) -> Psid {
            self.sid
        }

        fn delete(&mut self) -> Result<(), ExecutionPlanError> {
            if self.deleted {
                return Ok(());
            }
            let result = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
            if result != 0 {
                return Err(hresult_error("DeleteAppContainerProfile", result));
            }
            self.deleted = true;
            Ok(())
        }
    }

    impl Drop for AppContainerProfile {
        fn drop(&mut self) {
            if !self.deleted {
                unsafe {
                    DeleteAppContainerProfile(self.name.as_ptr());
                }
            }
            if !self.sid.is_null() {
                unsafe {
                    FreeSid(self.sid);
                }
            }
        }
    }

    struct AttributeList {
        heap: Handle,
        list: *mut c_void,
        _handle_list: Vec<Handle>,
    }

    impl AttributeList {
        fn with_security_capabilities(
            security: &mut SecurityCapabilities,
            handles: &[Handle],
        ) -> Result<Self, ExecutionPlanError> {
            let heap = unsafe { GetProcessHeap() };
            if heap.is_null() {
                return Err(last_error("GetProcessHeap"));
            }
            let attribute_count = if handles.is_empty() { 1 } else { 2 };
            let mut bytes = 0usize;
            unsafe {
                InitializeProcThreadAttributeList(ptr::null_mut(), attribute_count, 0, &mut bytes);
            }
            if bytes == 0 {
                return Err(last_error("InitializeProcThreadAttributeList(size)"));
            }
            let list = unsafe { HeapAlloc(heap, 0, bytes) };
            if list.is_null() {
                return Err(last_error("HeapAlloc(attribute list)"));
            }
            if unsafe { InitializeProcThreadAttributeList(list, attribute_count, 0, &mut bytes) }
                == 0
            {
                let error = last_error("InitializeProcThreadAttributeList");
                unsafe {
                    HeapFree(heap, 0, list);
                }
                return Err(error);
            }
            let updated = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                    (security as *mut SecurityCapabilities).cast(),
                    mem::size_of::<SecurityCapabilities>(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if updated == 0 {
                let error = last_error("UpdateProcThreadAttribute(SECURITY_CAPABILITIES)");
                unsafe {
                    DeleteProcThreadAttributeList(list);
                    HeapFree(heap, 0, list);
                }
                return Err(error);
            }
            let mut handle_list = handles.to_vec();
            if !handle_list.is_empty() {
                let listed = unsafe {
                    UpdateProcThreadAttribute(
                        list,
                        0,
                        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                        handle_list.as_mut_ptr().cast(),
                        mem::size_of::<Handle>() * handle_list.len(),
                        ptr::null_mut(),
                        ptr::null_mut(),
                    )
                };
                if listed == 0 {
                    let error = last_error("UpdateProcThreadAttribute(HANDLE_LIST)");
                    unsafe {
                        DeleteProcThreadAttributeList(list);
                        HeapFree(heap, 0, list);
                    }
                    return Err(error);
                }
            }
            Ok(Self {
                heap,
                list,
                _handle_list: handle_list,
            })
        }

        /// SG-000096: an ordinary current-user child gets no security
        /// capabilities, only the exact list of handles it may inherit.
        fn with_handle_list(handles: &[Handle]) -> Result<Self, ExecutionPlanError> {
            if handles.is_empty() {
                return Err(ExecutionPlanError::new("a handle list must not be empty"));
            }
            let heap = unsafe { GetProcessHeap() };
            if heap.is_null() {
                return Err(last_error("GetProcessHeap"));
            }
            let mut bytes = 0usize;
            unsafe {
                InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes);
            }
            if bytes == 0 {
                return Err(last_error("InitializeProcThreadAttributeList(size)"));
            }
            let list = unsafe { HeapAlloc(heap, 0, bytes) };
            if list.is_null() {
                return Err(last_error("HeapAlloc(attribute list)"));
            }
            if unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut bytes) } == 0 {
                let error = last_error("InitializeProcThreadAttributeList");
                unsafe {
                    HeapFree(heap, 0, list);
                }
                return Err(error);
            }
            let mut handle_list = handles.to_vec();
            let listed = unsafe {
                UpdateProcThreadAttribute(
                    list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    handle_list.as_mut_ptr().cast(),
                    mem::size_of::<Handle>() * handle_list.len(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if listed == 0 {
                let error = last_error("UpdateProcThreadAttribute(HANDLE_LIST)");
                unsafe {
                    DeleteProcThreadAttributeList(list);
                    HeapFree(heap, 0, list);
                }
                return Err(error);
            }
            Ok(Self {
                heap,
                list,
                _handle_list: handle_list,
            })
        }

        fn raw(&self) -> *mut c_void {
            self.list
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            if !self.list.is_null() {
                unsafe {
                    DeleteProcThreadAttributeList(self.list);
                    HeapFree(self.heap, 0, self.list);
                }
            }
        }
    }

    struct JobObject {
        handle: OwnedHandle,
    }

    impl JobObject {
        fn kill_on_close() -> Result<Self, ExecutionPlanError> {
            Self::kill_on_close_with_process_limit(None)
        }

        /// SG-000096: a shell Job also bounds how many processes its tree may
        /// hold at once. Breakaway is never permitted (the flag is not set).
        fn kill_on_close_with_process_limit(
            active_process_limit: Option<u32>,
        ) -> Result<Self, ExecutionPlanError> {
            let handle = OwnedHandle::new(
                unsafe { CreateJobObjectW(ptr::null(), ptr::null()) },
                "CreateJobObjectW",
            )?;

            let mut information = JobObjectExtendedLimitInformation::default();
            information.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Some(limit) = active_process_limit {
                if limit == 0 {
                    return Err(ExecutionPlanError::new("Job process limit must be nonzero"));
                }
                information.basic_limit_information.limit_flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                information.basic_limit_information.active_process_limit = limit;
            }
            let configured = unsafe {
                SetInformationJobObject(
                    handle.raw(),
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION_CLASS,
                    (&information as *const JobObjectExtendedLimitInformation).cast(),
                    mem::size_of::<JobObjectExtendedLimitInformation>() as u32,
                )
            };
            if configured == 0 {
                return Err(last_error("SetInformationJobObject"));
            }

            Ok(Self { handle })
        }

        fn terminate(&self) -> Result<(), ExecutionPlanError> {
            if unsafe { TerminateJobObject(self.handle.raw(), 1) } == 0 {
                return Err(last_error("TerminateJobObject"));
            }
            Ok(())
        }

        fn wait_for_quiescence(&self) -> Result<bool, ExecutionPlanError> {
            let deadline =
                std::time::Instant::now() + std::time::Duration::from_millis(QUIESCENCE_TIMEOUT_MS);
            loop {
                if self.active_processes()? == 0 {
                    return Ok(true);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                unsafe {
                    Sleep(QUIESCENCE_POLL_MS as u32);
                }
            }
        }

        fn active_processes(&self) -> Result<u32, ExecutionPlanError> {
            let mut information = JobObjectBasicAccountingInformation::default();
            let queried = unsafe {
                QueryInformationJobObject(
                    self.handle.raw(),
                    JOB_OBJECT_BASIC_ACCOUNTING_INFORMATION_CLASS,
                    (&mut information as *mut JobObjectBasicAccountingInformation).cast(),
                    mem::size_of::<JobObjectBasicAccountingInformation>() as u32,
                    ptr::null_mut(),
                )
            };
            if queried == 0 {
                return Err(last_error("QueryInformationJobObject"));
            }
            Ok(information.active_processes)
        }

        fn assign_before_resume(&self, child: &ChildProcess) -> Result<(), ExecutionPlanError> {
            let assigned =
                unsafe { AssignProcessToJobObject(self.handle.raw(), child.process.raw()) };
            if assigned == 0 {
                return Err(last_error("AssignProcessToJobObject"));
            }

            let mut in_job = 0i32;
            let checked =
                unsafe { IsProcessInJob(child.process.raw(), self.handle.raw(), &mut in_job) };
            if checked == 0 {
                return Err(last_error("IsProcessInJob"));
            }
            if in_job == 0 {
                return Err(ExecutionPlanError::new(
                    "child process was not associated with the Orcel Job Object",
                ));
            }
            Ok(())
        }

        // Recheck against the *exact* owned Job immediately before native
        // ResumeThread. A separate Job must never authorize a child.
        fn verify_member_before_resume(
            &self,
            child: &ChildProcess,
        ) -> Result<(), ExecutionPlanError> {
            let mut in_job = 0i32;
            if unsafe { IsProcessInJob(child.process.raw(), self.handle.raw(), &mut in_job) } == 0 {
                return Err(last_error("IsProcessInJob(pre-resume qualification)"));
            }
            if in_job == 0 {
                return Err(ExecutionPlanError::new(
                    "suspended child not a member of its expected Job Object",
                ));
            }
            Ok(())
        }

        // Never return an ordinary Job-assignment error while leaving a child
        // suspended outside the Job. Termination must be observed, or its
        // unverified outcome must replace the original assignment failure.
        fn assign_or_terminate(&self, child: &mut ChildProcess) -> Result<(), ExecutionPlanError> {
            if let Err(assignment_error) = self.assign_before_resume(child) {
                child.terminate_verified().map_err(|_| {
                    ExecutionPlanError::new(
                        "unverified suspended-child termination after failed Job assignment",
                    )
                })?;
                return Err(assignment_error);
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    struct NativeOwnerSnapshot {
        sid: String,
        logon_luid: u64,
        session_id: u32,
        elevation: u32,
        creation_generation: u64,
    }

    fn native_sid_equal(actual: &str, expected: &str) -> Result<bool, ExecutionPlanError> {
        fn parsed(text: &str) -> Result<Psid, ExecutionPlanError> {
            let wide = wide(OsStr::new(text));
            let mut sid: Psid = ptr::null_mut();
            if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 {
                return Err(last_error("ConvertStringSidToSidW(native expectation)"));
            }
            Ok(sid)
        }
        let actual_sid = parsed(actual)?;
        let expected_sid = match parsed(expected) {
            Ok(sid) => sid,
            Err(error) => {
                unsafe {
                    LocalFree(actual_sid);
                }
                return Err(error);
            }
        };
        let equal = unsafe { EqualSid(actual_sid, expected_sid) != 0 };
        unsafe {
            LocalFree(actual_sid);
            LocalFree(expected_sid);
        }
        Ok(equal)
    }

    struct ChildProcess {
        process: OwnedHandle,
        thread: OwnedHandle,
        completed: bool,
    }

    impl ChildProcess {
        // Centralize post-CreateProcessW ownership: CloseHandle alone does not
        // terminate a newly created suspended child that has no Job yet.
        fn from_created_process(
            information: ProcessInformation,
        ) -> Result<Self, ExecutionPlanError> {
            let process = match OwnedHandle::new(information.process, "CreateProcessW process") {
                Ok(process) => process,
                Err(error) => {
                    // The process handle is unusable; at least close the returned
                    // thread handle instead of leaking it on this failed path.
                    if !information.thread.is_null() && information.thread as isize != -1 {
                        unsafe {
                            CloseHandle(information.thread);
                        }
                    }
                    return Err(error);
                }
            };
            let thread = match OwnedHandle::new(information.thread, "CreateProcessW thread") {
                Ok(thread) => thread,
                Err(error) => {
                    let killed = unsafe { TerminateProcess(process.raw(), 1) };
                    let waited = unsafe { WaitForSingleObject(process.raw(), 5_000) };
                    if killed == 0 || waited != WAIT_OBJECT_0 {
                        return Err(ExecutionPlanError::new(
                            "unverified termination after suspended thread-handle failure",
                        ));
                    }
                    return Err(error);
                }
            };
            Ok(Self {
                process,
                thread,
                completed: false,
            })
        }

        fn create_suspended(profile_sid: Psid) -> Result<Self, ExecutionPlanError> {
            let executable = fixed_system_executable()?;

            let mut security = SecurityCapabilities {
                app_container_sid: profile_sid,
                capabilities: ptr::null_mut(),
                capability_count: 0,
                reserved: 0,
            };
            let attributes = AttributeList::with_security_capabilities(&mut security, &[])?;

            let mut startup: StartupInfoExW = unsafe { mem::zeroed() };
            startup.startup_info.cb = mem::size_of::<StartupInfoExW>() as u32;
            startup.attribute_list = attributes.raw();

            let application = wide(executable.as_os_str());
            let mut command_line = command_line_for_cmd(&executable);
            let mut environment = filtered_environment_block()?;

            let mut process_information: ProcessInformation = unsafe { mem::zeroed() };
            let created = unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    CREATE_SUSPENDED
                        | CREATE_UNICODE_ENVIRONMENT
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_NO_WINDOW,
                    environment.as_mut_ptr().cast(),
                    ptr::null(),
                    (&startup as *const StartupInfoExW).cast(),
                    &mut process_information,
                )
            };
            if created == 0 {
                return Err(last_error("CreateProcessW(AppContainer suspended)"));
            }

            Self::from_created_process(process_information)
        }

        // T02 qualification only: prove that an ordinary current-user child
        // can be attached to the owned Job before any user code runs. This
        // method is intentionally absent from production builds until the
        // independent lease + one-shot approval dispatcher is qualified.
        #[cfg(test)]
        fn create_suspended_current_user_fixture(
            simulate_invalid_thread: bool,
        ) -> Result<Self, ExecutionPlanError> {
            let executable = fixed_system_executable()?;
            let application = wide(executable.as_os_str());
            let mut command_line = command_line_for_cmd(&executable);
            let mut environment = filtered_environment_block()?;
            let mut startup: StartupInfoW = unsafe { mem::zeroed() };
            startup.cb = mem::size_of::<StartupInfoW>() as u32;
            let mut information: ProcessInformation = unsafe { mem::zeroed() };
            let created = unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                    environment.as_mut_ptr().cast(),
                    ptr::null(),
                    &startup,
                    &mut information,
                )
            };
            if created == 0 {
                return Err(last_error("CreateProcessW(current-user fixture)"));
            }

            if simulate_invalid_thread {
                // Simulates an unwrappable thread after a *successful* suspended
                // creation. The process handle must be terminated and drained
                // before this function returns; retain the raw thread solely
                // to close it in this test-only fault injection.
                let raw_thread = information.thread;
                information.thread = ptr::null_mut();
                let result = Self::from_created_process(information);
                unsafe {
                    CloseHandle(raw_thread);
                }
                return result;
            }
            Self::from_created_process(information)
        }

        fn fixture_token_data(
            token: &OwnedHandle,
            information_class: i32,
            minimum_bytes: u32,
        ) -> Result<Vec<usize>, ExecutionPlanError> {
            let mut required = 0u32;
            unsafe {
                GetTokenInformation(
                    token.raw(),
                    information_class,
                    ptr::null_mut(),
                    0,
                    &mut required,
                );
            }
            if required < minimum_bytes || required > 64 * 1024 {
                return Err(ExecutionPlanError::new(
                    "unexpected token-information size in disposable fixture",
                ));
            }
            // usize-backed storage provides the alignment needed for TOKEN_USER,
            // which begins with a pointer-sized SID field.
            let words = (required as usize).div_ceil(mem::size_of::<usize>());
            let mut bytes = vec![0usize; words];
            let mut returned = 0u32;
            if unsafe {
                GetTokenInformation(
                    token.raw(),
                    information_class,
                    bytes.as_mut_ptr().cast(),
                    required,
                    &mut returned,
                )
            } == 0
                || returned < minimum_bytes
                || returned > required
            {
                return Err(last_error("GetTokenInformation(disposable fixture)"));
            }
            Ok(bytes)
        }

        #[cfg(test)]
        fn verify_current_user_fixture_token(&self) -> Result<(), ExecutionPlanError> {
            const TOKEN_USER: i32 = 1;
            const TOKEN_STATISTICS: i32 = 10;
            const TOKEN_SESSION_ID: i32 = 12;
            const TOKEN_ELEVATION: i32 = 20;

            let mut raw_child: Handle = ptr::null_mut();
            if unsafe { OpenProcessToken(self.process.raw(), TOKEN_QUERY, &mut raw_child) } == 0 {
                return Err(last_error("OpenProcessToken(child fixture)"));
            }
            let child = OwnedHandle::new(raw_child, "OpenProcessToken(child fixture)")?;

            let mut raw_parent: Handle = ptr::null_mut();
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_parent) } == 0 {
                return Err(last_error("OpenProcessToken(parent fixture)"));
            }
            let parent = OwnedHandle::new(raw_parent, "OpenProcessToken(parent fixture)")?;

            let container = Self::fixture_token_data(&child, TOKEN_IS_APP_CONTAINER, 4)?;
            if container[0] != 0 {
                return Err(ExecutionPlanError::new(
                    "ordinary current-user fixture unexpectedly received an AppContainer token",
                ));
            }

            let child_user = Self::fixture_token_data(
                &child,
                TOKEN_USER,
                mem::size_of::<SidAndAttributes>() as u32,
            )?;
            let parent_user = Self::fixture_token_data(
                &parent,
                TOKEN_USER,
                mem::size_of::<SidAndAttributes>() as u32,
            )?;
            let child_sid = unsafe { (*(child_user.as_ptr().cast::<SidAndAttributes>())).sid };
            let parent_sid = unsafe { (*(parent_user.as_ptr().cast::<SidAndAttributes>())).sid };
            if child_sid.is_null()
                || parent_sid.is_null()
                || unsafe { EqualSid(child_sid, parent_sid) } == 0
            {
                return Err(ExecutionPlanError::new(
                    "ordinary current-user fixture SID differs from its parent",
                ));
            }

            // The AuthenticationId LUID is the second eight-byte field in
            // TOKEN_STATISTICS. Compare the actual child/parent logon LUIDs.
            let child_stats = Self::fixture_token_data(&child, TOKEN_STATISTICS, 16)?;
            let parent_stats = Self::fixture_token_data(&parent, TOKEN_STATISTICS, 16)?;
            let child_stats_bytes =
                unsafe { std::slice::from_raw_parts(child_stats.as_ptr().cast::<u8>(), 16) };
            let parent_stats_bytes =
                unsafe { std::slice::from_raw_parts(parent_stats.as_ptr().cast::<u8>(), 16) };
            if child_stats_bytes[8..16] != parent_stats_bytes[8..16] {
                return Err(ExecutionPlanError::new(
                    "ordinary current-user fixture logon LUID differs from its parent",
                ));
            }

            for (kind, label) in [
                (TOKEN_SESSION_ID, "session ID"),
                (TOKEN_ELEVATION, "elevation state"),
            ] {
                let actual = Self::fixture_token_data(&child, kind, 4)?;
                let expected = Self::fixture_token_data(&parent, kind, 4)?;
                if actual[0] != expected[0] {
                    return Err(ExecutionPlanError::new(format!(
                        "ordinary current-user fixture {label} differs from its parent",
                    )));
                }
            }
            Ok(())
        }

        // The native token identity of a process: SID, logon LUID, session,
        // elevation and creation generation. SG-000096 compares it with an
        // expected owner that orceld derives from the protected Full User
        // lease and runtime session record, never from caller input.
        fn snapshot_native_owner(
            process: Handle,
        ) -> Result<NativeOwnerSnapshot, ExecutionPlanError> {
            const TOKEN_USER: i32 = 1;
            const TOKEN_STATISTICS: i32 = 10;
            const TOKEN_SESSION_ID: i32 = 12;
            const TOKEN_ELEVATION: i32 = 20;
            let mut raw_token: Handle = ptr::null_mut();
            if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw_token) } == 0 {
                return Err(last_error("OpenProcessToken(native owner snapshot)"));
            }
            let token = OwnedHandle::new(raw_token, "OpenProcessToken(native owner snapshot)")?;
            let user = Self::fixture_token_data(
                &token,
                TOKEN_USER,
                mem::size_of::<SidAndAttributes>() as u32,
            )?;
            let sid_ptr = unsafe { (*(user.as_ptr().cast::<SidAndAttributes>())).sid };
            if sid_ptr.is_null() {
                return Err(ExecutionPlanError::new("null native TokenUser SID"));
            }
            let mut text_ptr: *mut u16 = ptr::null_mut();
            if unsafe { ConvertSidToStringSidW(sid_ptr, &mut text_ptr) } == 0 {
                return Err(last_error("ConvertSidToStringSidW"));
            }
            let sid_result = (|| {
                let mut len = 0usize;
                while len < 192 && unsafe { *text_ptr.add(len) } != 0 {
                    len += 1;
                }
                if len == 192 {
                    return Err(ExecutionPlanError::new("overlong native token SID"));
                }
                String::from_utf16(unsafe { std::slice::from_raw_parts(text_ptr, len) })
                    .map_err(|_| ExecutionPlanError::new("invalid native token SID UTF-16"))
            })();
            unsafe {
                LocalFree(text_ptr.cast());
            }
            let sid = sid_result?;
            let stats = Self::fixture_token_data(&token, TOKEN_STATISTICS, 16)?;
            let stats_bytes =
                unsafe { std::slice::from_raw_parts(stats.as_ptr().cast::<u8>(), 16) };
            let mut luid = [0u8; 8];
            luid.copy_from_slice(&stats_bytes[8..16]);
            let value = |kind: i32| -> Result<u32, ExecutionPlanError> {
                let raw = Self::fixture_token_data(&token, kind, 4)?;
                let bytes = unsafe { std::slice::from_raw_parts(raw.as_ptr().cast::<u8>(), 4) };
                Ok(u32::from_le_bytes(bytes.try_into().expect("four bytes")))
            };
            let mut created = NativeFileTime::default();
            let mut exited = NativeFileTime::default();
            let mut kernel = NativeFileTime::default();
            let mut user_time = NativeFileTime::default();
            if unsafe {
                GetProcessTimes(
                    process,
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user_time,
                )
            } == 0
            {
                return Err(last_error("GetProcessTimes(native owner snapshot)"));
            }
            let creation_generation = u64::from(created.high) << 32 | u64::from(created.low);
            if creation_generation == 0 {
                return Err(ExecutionPlanError::new(
                    "missing native process creation generation",
                ));
            }
            Ok(NativeOwnerSnapshot {
                sid,
                logon_luid: u64::from_le_bytes(luid),
                session_id: value(TOKEN_SESSION_ID)?,
                elevation: value(TOKEN_ELEVATION)?,
                creation_generation,
            })
        }

        #[cfg(test)]
        fn verify_expected_native_owner(
            &self,
            expected: &NativeOwnerSnapshot,
        ) -> Result<(), ExecutionPlanError> {
            let actual = Self::snapshot_native_owner(self.process.raw())?;
            if !native_sid_equal(&actual.sid, &expected.sid)? {
                return Err(ExecutionPlanError::new("expected native SID mismatch"));
            }
            if expected.logon_luid != actual.logon_luid {
                return Err(ExecutionPlanError::new(
                    "expected native logon LUID mismatch",
                ));
            }
            if expected.session_id != actual.session_id {
                return Err(ExecutionPlanError::new("expected native session mismatch"));
            }
            if expected.elevation != actual.elevation {
                return Err(ExecutionPlanError::new(
                    "expected native elevation mismatch",
                ));
            }
            if expected.creation_generation != actual.creation_generation {
                return Err(ExecutionPlanError::new(
                    "expected native process generation mismatch",
                ));
            }
            Ok(())
        }

        fn create_suspended_with_pipes(
            profile_sid: Psid,
            plan: &ExecutionPlan,
            stdout: &OwnedHandle,
            stderr: &OwnedHandle,
        ) -> Result<Self, ExecutionPlanError> {
            let stdin = null_input()?;
            let handles = [stdin.raw(), stdout.raw(), stderr.raw()];
            let mut security = SecurityCapabilities {
                app_container_sid: profile_sid,
                capabilities: ptr::null_mut(),
                capability_count: 0,
                reserved: 0,
            };
            let attributes = AttributeList::with_security_capabilities(&mut security, &handles)?;
            let mut startup: StartupInfoExW = unsafe { mem::zeroed() };
            startup.startup_info.cb = mem::size_of::<StartupInfoExW>() as u32;
            startup.startup_info.h_std_input = stdin.raw();
            startup.startup_info.h_std_output = stdout.raw();
            startup.startup_info.h_std_error = stderr.raw();
            startup.startup_info.dw_flags = 0x0000_0100;
            startup.attribute_list = attributes.raw();
            let process_executable = path_for_process_api(&plan.executable);
            let application = wide(process_executable.as_os_str());
            let mut command_line = command_line_for_paths(&process_executable, &plan.argv);
            let mut environment = environment_from_plan(plan)?;
            let process_cwd = path_for_process_api(&plan.cwd);
            let current_directory = wide(process_cwd.as_os_str());
            let mut information: ProcessInformation = unsafe { mem::zeroed() };
            let created = unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    1,
                    CREATE_SUSPENDED
                        | CREATE_UNICODE_ENVIRONMENT
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_NO_WINDOW,
                    environment.as_mut_ptr().cast(),
                    current_directory.as_ptr(),
                    (&startup as *const StartupInfoExW).cast(),
                    &mut information,
                )
            };
            if created == 0 {
                return Err(last_error("CreateProcessW(contained execution)"));
            }
            Self::from_created_process(information)
        }

        fn verify_appcontainer_token(&self) -> Result<(), ExecutionPlanError> {
            let mut raw_token: Handle = ptr::null_mut();
            let opened =
                unsafe { OpenProcessToken(self.process.raw(), TOKEN_QUERY, &mut raw_token) };
            if opened == 0 {
                return Err(last_error("OpenProcessToken"));
            }
            let token = OwnedHandle::new(raw_token, "OpenProcessToken handle")?;

            let mut is_appcontainer = 0u32;
            let mut returned = 0u32;
            let queried = unsafe {
                GetTokenInformation(
                    token.raw(),
                    TOKEN_IS_APP_CONTAINER,
                    (&mut is_appcontainer as *mut u32).cast(),
                    mem::size_of::<u32>() as u32,
                    &mut returned,
                )
            };
            if queried == 0 {
                return Err(last_error("GetTokenInformation(TokenIsAppContainer)"));
            }
            if is_appcontainer == 0 {
                return Err(ExecutionPlanError::new(
                    "contained child token is not marked as AppContainer",
                ));
            }
            Ok(())
        }

        fn resume(&self) -> Result<(), ExecutionPlanError> {
            let previous = unsafe { ResumeThread(self.thread.raw()) };
            if previous == RESUME_FAILED {
                return Err(last_error("ResumeThread"));
            }
            Ok(())
        }

        fn wait_for_completion(&mut self) -> Result<u32, ExecutionPlanError> {
            let wait = unsafe { WaitForSingleObject(self.process.raw(), PROBE_TIMEOUT_MS) };
            match wait {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => {
                    self.terminate_best_effort();
                    return Err(ExecutionPlanError::new(
                        "contained child did not exit before the probe timeout",
                    ));
                }
                WAIT_FAILED => {
                    let error = last_error("WaitForSingleObject");
                    self.terminate_best_effort();
                    return Err(error);
                }
                other => {
                    self.terminate_best_effort();
                    return Err(ExecutionPlanError::new(format!(
                        "WaitForSingleObject returned unexpected status {other}"
                    )));
                }
            }

            let mut exit_code = 0u32;
            let read = unsafe { GetExitCodeProcess(self.process.raw(), &mut exit_code) };
            if read == 0 {
                return Err(last_error("GetExitCodeProcess"));
            }
            self.completed = true;
            Ok(exit_code)
        }

        // Unlike best effort Drop cleanup, security-sensitive pre-resume
        // failure paths must verify exit before returning the original error.
        fn terminate_verified(&mut self) -> Result<(), ExecutionPlanError> {
            unsafe {
                TerminateProcess(self.process.raw(), 1);
            }
            let waited = unsafe { WaitForSingleObject(self.process.raw(), 5_000) };
            if waited != WAIT_OBJECT_0 {
                return Err(ExecutionPlanError::new(
                    "child termination was not verified by a signaled process handle",
                ));
            }
            self.completed = true;
            Ok(())
        }

        fn terminate_best_effort(&mut self) {
            // Never mark an unverified termination as completed. A caller
            // needing strict cleanup must use terminate_verified directly.
            let _ = self.terminate_verified();
        }
    }

    impl Drop for ChildProcess {
        fn drop(&mut self) {
            if !self.completed {
                self.terminate_best_effort();
            }
        }
    }

    pub(super) fn probe(name: &str) -> Result<ContainedLaunchProbe, ExecutionPlanError> {
        let mut profile = AppContainerProfile::create(name)?;
        let job = JobObject::kill_on_close()?;
        let mut child = ChildProcess::create_suspended(profile.sid())?;

        job.assign_or_terminate(&mut child)?;

        child.verify_appcontainer_token()?;
        child.resume()?;
        let exit_code = child.wait_for_completion()?;
        profile.delete()?;

        Ok(ContainedLaunchProbe {
            profile_created: true,
            process_created_suspended: true,
            appcontainer_token_verified: true,
            assigned_to_job_before_resume: true,
            resumed: true,
            child_completed: true,
            exit_code,
            profile_deleted: true,
        })
    }

    struct PrivatePipe {
        read: OwnedHandle,
    }

    impl PrivatePipe {
        fn create() -> Result<(Self, OwnedHandle), ExecutionPlanError> {
            let mut read = ptr::null_mut();
            let mut write = ptr::null_mut();
            let attributes = SecurityAttributes {
                length: mem::size_of::<SecurityAttributes>() as u32,
                security_descriptor: ptr::null_mut(),
                inherit_handle: 1,
            };
            if unsafe {
                CreatePipe(
                    &mut read,
                    &mut write,
                    (&attributes as *const SecurityAttributes).cast(),
                    0,
                )
            } == 0
            {
                return Err(last_error("CreatePipe"));
            }
            let read = OwnedHandle::new(read, "CreatePipe read")?;
            let write = OwnedHandle::new(write, "CreatePipe write")?;
            if unsafe { SetHandleInformation(read.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(last_error("SetHandleInformation"));
            }
            Ok((Self { read }, write))
        }

        /// SG-000096 T03: a stdin pipe. The child's read end is inheritable;
        /// the Orcel write end is not, so no other child can hold it open.
        fn create_input() -> Result<(OwnedHandle, OwnedHandle), ExecutionPlanError> {
            let (pipe, write) = Self::create()?;
            // `create` made the read end private and the write end inheritable;
            // swap that so the child reads and Orcel writes.
            if unsafe { SetHandleInformation(write.raw(), HANDLE_FLAG_INHERIT, 0) } == 0 {
                return Err(last_error("SetHandleInformation(stdin write)"));
            }
            if unsafe {
                SetHandleInformation(pipe.read.raw(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)
            } == 0
            {
                return Err(last_error("SetHandleInformation(stdin read)"));
            }
            Ok((pipe.read, write))
        }
    }

    fn null_input() -> Result<OwnedHandle, ExecutionPlanError> {
        let name = wide(OsStr::new("NUL"));
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        let attributes = SecurityAttributes {
            length: mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: ptr::null_mut(),
            inherit_handle: 1,
        };
        OwnedHandle::new(
            unsafe {
                CreateFileW(
                    name.as_ptr(),
                    GENERIC_READ,
                    share,
                    (&attributes as *const SecurityAttributes).cast(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    ptr::null_mut(),
                )
            },
            "CreateFileW(NUL)",
        )
    }

    fn quote_arg(arg: &str) -> Vec<u16> {
        let mut out = Vec::new();
        out.push('"' as u16);
        let mut backslashes = 0usize;
        for ch in arg.encode_utf16() {
            if ch == '\\' as u16 {
                backslashes += 1;
            } else if ch == '"' as u16 {
                out.extend(std::iter::repeat_n('\\' as u16, backslashes * 2 + 1));
                out.push(ch);
                backslashes = 0;
            } else {
                out.extend(std::iter::repeat_n('\\' as u16, backslashes));
                out.push(ch);
                backslashes = 0;
            }
        }
        out.extend(std::iter::repeat_n('\\' as u16, backslashes * 2));
        out.push('"' as u16);
        out
    }

    fn path_for_process_api(path: &Path) -> PathBuf {
        let raw: Vec<u16> = path.as_os_str().encode_wide().collect();
        if raw.starts_with(&[0x5c, 0x5c, 0x3f, 0x5c]) {
            let mut stripped = raw[4..].to_vec();
            if stripped.starts_with(&[b'U' as u16, b'N' as u16, b'C' as u16, 0x5c]) {
                stripped.drain(0..3);
                stripped.insert(0, 0x5c);
            }
            return PathBuf::from(OsString::from_wide(&stripped));
        }
        path.to_path_buf()
    }

    fn command_line_for_paths(executable: &Path, argv: &[String]) -> Vec<u16> {
        let mut command = quote_arg(&executable.to_string_lossy());
        for arg in argv {
            command.push(' ' as u16);
            command.extend(quote_arg(arg));
        }
        command.push(0);
        command
    }

    fn environment_from_plan(plan: &ExecutionPlan) -> Result<Vec<u16>, ExecutionPlanError> {
        environment_block(&plan.env)
    }

    /// The allowlisted, secret-free environment block of a plan; SG-000096
    /// shell launches reuse it so they get no wider an environment than Safe.
    fn environment_block(
        env: &std::collections::BTreeMap<String, String>,
    ) -> Result<Vec<u16>, ExecutionPlanError> {
        let mut entries = Vec::new();
        for (key, value) in env {
            if key.is_empty() || key.contains('\0') || value.contains('\0') || key.contains('=') {
                return Err(ExecutionPlanError::new("invalid environment entry"));
            }
            let upper = key.to_ascii_uppercase();
            if SECRETISH.iter().any(|needle| upper.contains(needle))
                || FORBIDDEN_ORCEL_ENV
                    .iter()
                    .any(|forbidden| upper == *forbidden)
                || !allowed_execution_env(key)
            {
                continue;
            }
            entries.push((key.clone(), value.clone()));
        }
        for required in ["LOCALAPPDATA", "SystemRoot", "TEMP", "TMP"] {
            if !entries
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(required))
            {
                return Err(ExecutionPlanError::new(format!(
                    "required execution environment variable is unavailable: {required}"
                )));
            }
        }
        entries.sort_by_key(|entry| entry.0.to_ascii_lowercase());
        let mut block = Vec::new();
        for (key, value) in entries {
            block.extend(key.encode_utf16());
            block.push('=' as u16);
            block.extend(value.encode_utf16());
            block.push(0);
        }
        block.push(0);
        Ok(block)
    }

    enum PipeRead {
        Open,
        Closed,
        LimitExceeded,
    }

    fn read_pipe(
        pipe: &PrivatePipe,
        output: &mut Vec<u8>,
        limit: usize,
    ) -> Result<PipeRead, ExecutionPlanError> {
        let mut available = 0u32;
        let peeked = unsafe {
            PeekNamedPipe(
                pipe.read.raw(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        };
        if peeked == 0 {
            let code = unsafe { GetLastError() };
            if code == ERROR_BROKEN_PIPE {
                return Ok(PipeRead::Closed);
            }
            return Err(last_error("PeekNamedPipe"));
        }
        if available == 0 {
            return Ok(PipeRead::Open);
        }
        let remaining = limit.saturating_sub(output.len());
        if available as usize > remaining {
            return Ok(PipeRead::LimitExceeded);
        }
        let mut buffer = vec![0u8; available as usize];
        let mut read = 0u32;
        if unsafe {
            ReadFile(
                pipe.read.raw(),
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            let code = unsafe { GetLastError() };
            if code == ERROR_BROKEN_PIPE {
                return Ok(PipeRead::Closed);
            }
            return Err(last_error("ReadFile"));
        }
        buffer.truncate(read as usize);
        output.extend_from_slice(&buffer);
        Ok(PipeRead::Open)
    }

    #[cfg(windows)]
    pub(crate) enum DestructiveEvent {
        Timeout,
        OutputLimit(OutputStream),
    }

    #[cfg(windows)]
    pub(crate) fn classify_termination(
        event: DestructiveEvent,
        verified: bool,
    ) -> PrivateExecutionFailure {
        if !verified {
            return PrivateExecutionFailure::TerminationUnverified;
        }
        match event {
            DestructiveEvent::Timeout => PrivateExecutionFailure::ProcessTimeout,
            DestructiveEvent::OutputLimit(stream) => PrivateExecutionFailure::OutputLimit(stream),
        }
    }

    fn terminate_and_verify(job: &JobObject, event: DestructiveEvent) -> PrivateExecutionFailure {
        if job.terminate().is_err() {
            return PrivateExecutionFailure::TerminationUnverified;
        }
        let verified = matches!(job.wait_for_quiescence(), Ok(true));
        classify_termination(event, verified)
    }

    enum PostExitDrain {
        Complete,
        OutputLimit(OutputStream),
        Deadline,
    }

    fn drain_pipes_until(
        stdout_pipe: &PrivatePipe,
        stderr_pipe: &PrivatePipe,
        stdout: &mut Vec<u8>,
        stderr: &mut Vec<u8>,
        stdout_limit: usize,
        stderr_limit: usize,
        deadline: std::time::Instant,
    ) -> Result<PostExitDrain, PrivateExecutionFailure> {
        let mut stdout_closed = false;
        let mut stderr_closed = false;
        loop {
            if !stdout_closed {
                match read_pipe(stdout_pipe, stdout, stdout_limit) {
                    Ok(PipeRead::Closed) => stdout_closed = true,
                    Ok(PipeRead::Open) => {}
                    Ok(PipeRead::LimitExceeded) => {
                        return Ok(PostExitDrain::OutputLimit(OutputStream::Stdout));
                    }
                    Err(error) => {
                        return Err(PrivateExecutionFailure::Provider(error.message));
                    }
                }
            }
            if !stderr_closed {
                match read_pipe(stderr_pipe, stderr, stderr_limit) {
                    Ok(PipeRead::Closed) => stderr_closed = true,
                    Ok(PipeRead::Open) => {}
                    Ok(PipeRead::LimitExceeded) => {
                        return Ok(PostExitDrain::OutputLimit(OutputStream::Stderr));
                    }
                    Err(error) => {
                        return Err(PrivateExecutionFailure::Provider(error.message));
                    }
                }
            }
            if stdout_closed && stderr_closed {
                return Ok(PostExitDrain::Complete);
            }
            if std::time::Instant::now() >= deadline {
                return Ok(PostExitDrain::Deadline);
            }
            unsafe {
                Sleep(QUIESCENCE_POLL_MS as u32);
            }
        }
    }

    pub(super) fn qualify_private_execution(
        plan: ExecutionPlan,
        profile_name: &str,
        mode: PrivateExecutionMode,
    ) -> Result<PrivateExecutionResult, PrivateExecutionFailure> {
        let expected_executable = match mode {
            PrivateExecutionMode::Public => plan.executable.clone(),
            PrivateExecutionMode::Success => fixed_system_executable()
                .map(|cmd| cmd.parent().map(|parent| parent.join("whoami.exe")))
                .map_err(|error| PrivateExecutionFailure::InvalidPlan(error.message))?
                .ok_or_else(|| {
                    PrivateExecutionFailure::InvalidPlan("system directory is unavailable".into())
                })?,
            PrivateExecutionMode::Timeout
            | PrivateExecutionMode::StdoutLimit
            | PrivateExecutionMode::StderrLimit
            | PrivateExecutionMode::DescendantDrain
            | PrivateExecutionMode::DetachedDescendant => std::env::current_exe()
                .map_err(|error| PrivateExecutionFailure::InvalidPlan(error.to_string()))?,
        };
        let expected_executable = std::fs::canonicalize(expected_executable)
            .map_err(|error| PrivateExecutionFailure::InvalidPlan(error.to_string()))?;
        let expected_argv: Vec<String> = match mode {
            PrivateExecutionMode::Public => plan.argv.clone(),
            PrivateExecutionMode::Success => Vec::new(),
            PrivateExecutionMode::Timeout => vec![
                "--exact".into(),
                "contained_launch_tests::private_timeout_fixture_child".into(),
                "--nocapture".into(),
            ],
            PrivateExecutionMode::StdoutLimit => vec![
                "--exact".into(),
                "contained_launch_tests::private_stdout_fixture_child".into(),
                "--nocapture".into(),
            ],
            PrivateExecutionMode::StderrLimit => vec![
                "--exact".into(),
                "contained_launch_tests::private_stderr_fixture_child".into(),
                "--nocapture".into(),
            ],
            PrivateExecutionMode::DescendantDrain | PrivateExecutionMode::DetachedDescendant => {
                vec![
                    "--exact".into(),
                    "contained_launch_tests::private_descendant_primary_child".into(),
                    "--nocapture".into(),
                ]
            }
        };
        if expected_executable != plan.executable || expected_argv != plan.argv {
            return Err(PrivateExecutionFailure::InvalidPlan(
                "contained executor received an executable or arguments outside the normalized plan".into(),
            ));
        }
        let mut profile = AppContainerProfile::create(profile_name)
            .map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
        let job =
            JobObject::kill_on_close().map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
        let (stdout_pipe, stdout_write) =
            PrivatePipe::create().map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
        let (stderr_pipe, stderr_write) =
            PrivatePipe::create().map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
        let mut child = match ChildProcess::create_suspended_with_pipes(
            profile.sid(),
            &plan,
            &stdout_write,
            &stderr_write,
        ) {
            Ok(child) => child,
            Err(error) => return Err(PrivateExecutionFailure::Provider(error.message)),
        };
        // Keeps a detached descendant's pipe read ends open for the run.
        let mut _detached_pipes = None;
        let mut descendant = if matches!(
            mode,
            PrivateExecutionMode::Timeout
                | PrivateExecutionMode::StdoutLimit
                | PrivateExecutionMode::StderrLimit
                | PrivateExecutionMode::DescendantDrain
                | PrivateExecutionMode::DetachedDescendant
        ) {
            let descendant_argv = match mode {
                PrivateExecutionMode::Timeout | PrivateExecutionMode::DetachedDescendant => vec![
                    "--exact".to_owned(),
                    "contained_launch_tests::private_timeout_descendant".to_owned(),
                    "--nocapture".to_owned(),
                ],
                PrivateExecutionMode::StdoutLimit
                | PrivateExecutionMode::StderrLimit
                | PrivateExecutionMode::DescendantDrain => vec![
                    "--exact".to_owned(),
                    "contained_launch_tests::private_output_descendant".to_owned(),
                    "--nocapture".to_owned(),
                ],
                PrivateExecutionMode::Public | PrivateExecutionMode::Success => unreachable!(),
            };
            let mut descendant_plan = plan.clone();
            descendant_plan.argv = descendant_argv;
            // A detached descendant writes to pipes of its own, so the run's
            // output closes when the primary exits.
            let (descendant_stdout, descendant_stderr) =
                if mode == PrivateExecutionMode::DetachedDescendant {
                    let (reader, writer) = PrivatePipe::create()
                        .map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
                    let (error_reader, error_writer) = PrivatePipe::create()
                        .map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
                    _detached_pipes = Some((reader, error_reader));
                    (Some(writer), Some(error_writer))
                } else {
                    (None, None)
                };
            Some(
                match ChildProcess::create_suspended_with_pipes(
                    profile.sid(),
                    &descendant_plan,
                    descendant_stdout.as_ref().unwrap_or(&stdout_write),
                    descendant_stderr.as_ref().unwrap_or(&stderr_write),
                ) {
                    Ok(descendant) => descendant,
                    Err(error) => return Err(PrivateExecutionFailure::Provider(error.message)),
                },
            )
        } else {
            None
        };
        drop(stdout_write);
        drop(stderr_write);
        if let Err(error) = job.assign_or_terminate(&mut child) {
            return Err(PrivateExecutionFailure::Provider(error.message));
        }
        if let Some(descendant_process) = descendant.as_mut() {
            if let Err(error) = job.assign_or_terminate(descendant_process) {
                child.terminate_best_effort();
                return Err(PrivateExecutionFailure::Provider(error.message));
            }
        }
        if let Err(error) = child.verify_appcontainer_token() {
            child.terminate_best_effort();
            return Err(PrivateExecutionFailure::Provider(error.message));
        }
        if let Some(descendant_process) = descendant.as_mut() {
            if let Err(error) = descendant_process.verify_appcontainer_token() {
                child.terminate_best_effort();
                descendant_process.terminate_best_effort();
                return Err(PrivateExecutionFailure::Provider(error.message));
            }
        }
        if let Err(error) = child.resume() {
            child.terminate_best_effort();
            return Err(PrivateExecutionFailure::Provider(error.message));
        }
        if let Some(descendant_process) = descendant.as_mut() {
            if let Err(error) = descendant_process.resume() {
                child.terminate_best_effort();
                descendant_process.terminate_best_effort();
                return Err(PrivateExecutionFailure::Provider(error.message));
            }
        }
        let started = std::time::Instant::now();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut destructive_event = None;
        loop {
            match read_pipe(&stdout_pipe, &mut stdout, plan.limits.stdout_bytes) {
                Ok(PipeRead::LimitExceeded) if destructive_event.is_none() => {
                    destructive_event = Some(DestructiveEvent::OutputLimit(OutputStream::Stdout));
                }
                Ok(PipeRead::Open) | Ok(PipeRead::Closed) | Ok(PipeRead::LimitExceeded) => {}
                Err(error) => return Err(PrivateExecutionFailure::Provider(error.message)),
            }
            match read_pipe(&stderr_pipe, &mut stderr, plan.limits.stderr_bytes) {
                Ok(PipeRead::LimitExceeded) if destructive_event.is_none() => {
                    destructive_event = Some(DestructiveEvent::OutputLimit(OutputStream::Stderr));
                }
                Ok(PipeRead::Open) | Ok(PipeRead::Closed) | Ok(PipeRead::LimitExceeded) => {}
                Err(error) => return Err(PrivateExecutionFailure::Provider(error.message)),
            }
            if destructive_event.is_some() {
                break;
            }
            let wait = unsafe { WaitForSingleObject(child.process.raw(), 0) };
            if wait == WAIT_OBJECT_0 {
                break;
            }
            if started.elapsed() >= plan.limits.timeout {
                destructive_event = Some(DestructiveEvent::Timeout);
                break;
            }
            unsafe {
                Sleep(10);
            }
        }
        if let Some(event) = destructive_event {
            return Err(terminate_and_verify(&job, event));
        }
        let exit_code = child
            .wait_for_completion()
            .map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
        let drain_deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(POST_EXIT_DRAIN_TIMEOUT_MS);
        match drain_pipes_until(
            &stdout_pipe,
            &stderr_pipe,
            &mut stdout,
            &mut stderr,
            plan.limits.stdout_bytes,
            plan.limits.stderr_bytes,
            drain_deadline,
        )? {
            PostExitDrain::Complete => {}
            PostExitDrain::OutputLimit(stream) => {
                return Err(terminate_and_verify(
                    &job,
                    DestructiveEvent::OutputLimit(stream),
                ));
            }
            PostExitDrain::Deadline => {
                let active = job
                    .active_processes()
                    .map_err(|_| PrivateExecutionFailure::TerminationUnverified)?;
                if active == 0 || job.terminate().is_err() {
                    return Err(PrivateExecutionFailure::TerminationUnverified);
                }
                if !matches!(job.wait_for_quiescence(), Ok(true)) {
                    return Err(PrivateExecutionFailure::TerminationUnverified);
                }
                if let Some(descendant_process) = descendant.as_mut() {
                    descendant_process.completed = true;
                }
                let cleanup_deadline = std::time::Instant::now()
                    + std::time::Duration::from_millis(POST_TERMINATION_DRAIN_TIMEOUT_MS);
                match drain_pipes_until(
                    &stdout_pipe,
                    &stderr_pipe,
                    &mut stdout,
                    &mut stderr,
                    plan.limits.stdout_bytes,
                    plan.limits.stderr_bytes,
                    cleanup_deadline,
                )? {
                    PostExitDrain::Complete => {}
                    PostExitDrain::OutputLimit(stream) => {
                        return Err(classify_termination(
                            DestructiveEvent::OutputLimit(stream),
                            true,
                        ));
                    }
                    PostExitDrain::Deadline => {
                        return Err(PrivateExecutionFailure::TerminationUnverified);
                    }
                }
            }
        }
        // XP-13b: owned cleanup, as on Linux and macOS. A descendant still
        // running once the primary has exited and its output is drained is
        // ended with the job, not waited on.
        let active = job
            .active_processes()
            .map_err(|_| PrivateExecutionFailure::TerminationUnverified)?;
        if active > 0 && job.terminate().is_err() {
            return Err(PrivateExecutionFailure::TerminationUnverified);
        }
        let quiescent = job
            .wait_for_quiescence()
            .map_err(|_| PrivateExecutionFailure::TerminationUnverified)?;
        profile
            .delete()
            .map_err(|e| PrivateExecutionFailure::Provider(e.message))?;
        if !quiescent {
            return Err(PrivateExecutionFailure::TerminationUnverified);
        }
        Ok(PrivateExecutionResult {
            exit_code,
            stdout,
            stderr,
            appcontainer_verified: true,
            assigned_to_job_before_resume: true,
            job_quiescent: true,
        })
    }

    // Test-owned one-shot fixture only. Neither this proof nor a valid intent
    // exposes a callable Full User shell executor to production or MCP.
    #[cfg(test)]
    pub(super) fn qualify_current_user_job_fixture(
        invalid_thread: bool,
    ) -> Result<(), ExecutionPlanError> {
        let job = JobObject::kill_on_close()?;
        let mut child = match ChildProcess::create_suspended_current_user_fixture(invalid_thread) {
            Ok(child) if !invalid_thread => child,
            Ok(mut child) => {
                child.terminate_best_effort();
                return Err(ExecutionPlanError::new(
                    "invalid-thread fault injection unexpectedly created a usable child",
                ));
            }
            Err(error) if invalid_thread => {
                // The specific wrapper error is returned only after verified
                // TerminateProcess + WaitForSingleObject on the suspended child.
                if !error.message.contains("CreateProcessW thread") {
                    return Err(error);
                }
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if let Err(error) = child.verify_current_user_fixture_token() {
            child.terminate_best_effort();
            return Err(error);
        }
        job.assign_or_terminate(&mut child)?;
        if let Err(error) = child.resume() {
            child.terminate_best_effort();
            return Err(error);
        }
        if child.wait_for_completion()? != 0 {
            return Err(ExecutionPlanError::new(
                "ordinary current-user disposable fixture did not exit successfully",
            ));
        }
        if !job.wait_for_quiescence()? {
            return Err(ExecutionPlanError::new(
                "ordinary current-user fixture Job remained nonquiescent",
            ));
        }
        Ok(())
    }

    // Test-only native negative path: force a real AssignProcessToJobObject
    // failure after successfully creating a suspended ordinary-user child.
    // The shared production failure handler must verify child termination
    // before returning the assignment error.
    #[cfg(test)]
    pub(super) fn qualify_failed_job_assignment_cleanup() -> Result<(), ExecutionPlanError> {
        let mut child = ChildProcess::create_suspended_current_user_fixture(false)?;
        if let Err(error) = child.verify_current_user_fixture_token() {
            child.terminate_verified()?;
            return Err(error);
        }
        let unusable_job = JobObject {
            handle: OwnedHandle(ptr::null_mut()),
        };
        let result = unusable_job.assign_or_terminate(&mut child);
        if result.is_ok() {
            child.terminate_verified()?;
            return Err(ExecutionPlanError::new(
                "invalid Job handle unexpectedly accepted the suspended child",
            ));
        }
        if !child.completed
            || unsafe { WaitForSingleObject(child.process.raw(), 0) } != WAIT_OBJECT_0
        {
            return Err(ExecutionPlanError::new(
                "child termination was not verified after real Job assignment failure",
            ));
        }
        if result
            .err()
            .is_some_and(|error| error.message.contains("unverified"))
        {
            return Err(ExecutionPlanError::new(
                "Job assignment failure yielded unverified child termination",
            ));
        }
        Ok(())
    }

    // Fault-inject a missing or foreign Job association and a native token
    // inspection failure while holding the actual disposable child suspended.
    // Denial is complete only after child exit and owned-Job quiescence.
    #[cfg(test)]
    pub(super) fn qualify_pre_resume_inspection_case(case: u8) -> Result<(), ExecutionPlanError> {
        let job = JobObject::kill_on_close()?;
        let mut child = ChildProcess::create_suspended_current_user_fixture(false)?;
        job.assign_or_terminate(&mut child)?;

        let inspection = match case {
            0 => job
                .verify_member_before_resume(&child)
                .and_then(|_| ChildProcess::snapshot_native_owner(child.process.raw()).map(|_| ())),
            1 => {
                let unrelated_job = JobObject::kill_on_close()?;
                unrelated_job.verify_member_before_resume(&child)
            }
            2 => ChildProcess::snapshot_native_owner(ptr::null_mut()).map(|_| ()),
            3 => {
                let mut in_job = 0i32;
                let checked =
                    unsafe { IsProcessInJob(child.process.raw(), 1usize as Handle, &mut in_job) };
                if checked == 0 {
                    Err(last_error("IsProcessInJob(invalid native Job handle)"))
                } else {
                    Ok(()) // An unexpectedly accepted invalid handle fails the negative fixture.
                }
            }
            _ => Err(ExecutionPlanError::new(
                "unrecognized native inspection case",
            )),
        };
        if case == 0 {
            if let Err(error) = inspection {
                child.terminate_verified()?;
                return Err(error);
            }
            if let Err(error) = child.resume() {
                child.terminate_verified()?;
                return Err(error);
            }
            let exit = match child.wait_for_completion() {
                Ok(exit) => exit,
                Err(error) => {
                    child.terminate_verified()?;
                    return Err(error);
                }
            };
            if exit != 0 || !job.wait_for_quiescence()? {
                return Err(ExecutionPlanError::new(
                    "native pre-resume positive case did not quiesce",
                ));
            }
            return Ok(());
        }

        let rejected = inspection.is_err();
        child.terminate_verified()?;
        if !rejected || !job.wait_for_quiescence()? {
            return Err(ExecutionPlanError::new(
                "native pre-resume inspection failed to deny with verified Job cleanup",
            ));
        }
        Ok(())
    }

    // Every mismatch uses a *real* suspended, Job-attached disposable child.
    // No native thread is resumed on the rejection path.
    #[cfg(test)]
    pub(super) fn qualify_expected_owner_case(case: u8) -> Result<(), ExecutionPlanError> {
        let job = JobObject::kill_on_close()?;
        let mut child = ChildProcess::create_suspended_current_user_fixture(false)?;
        job.assign_or_terminate(&mut child)?;
        let mut expected = ChildProcess::snapshot_native_owner(unsafe { GetCurrentProcess() })?;
        expected.creation_generation =
            ChildProcess::snapshot_native_owner(child.process.raw())?.creation_generation;
        match case {
            0 => {}
            1 => {
                expected.sid = if expected.sid == "S-1-5-18" {
                    "S-1-5-19".into()
                } else {
                    "S-1-5-18".into()
                }
            }
            2 => expected.logon_luid ^= 1,
            3 => expected.session_id ^= 1,
            4 => expected.elevation ^= 1,
            5 => expected.creation_generation ^= 1,
            6 => expected.sid = "not-a-native-SID".into(),
            _ => {
                child.terminate_verified()?;
                return Err(ExecutionPlanError::new("unknown owner qualification case"));
            }
        }
        let result = child.verify_expected_native_owner(&expected);
        if case == 0 {
            if let Err(error) = result {
                child.terminate_verified()?;
                return Err(error);
            }
            child.resume()?;
            if child.wait_for_completion()? != 0 || !job.wait_for_quiescence()? {
                return Err(ExecutionPlanError::new(
                    "expected-owner positive fixture not quiescent",
                ));
            }
            return Ok(());
        }
        // Even malformed expected SIDs and native conversion errors must not
        // leak a child suspended outside the caller's expected authority.
        let rejected = result.is_err();
        child.terminate_verified()?;
        if !job.wait_for_quiescence()? || !rejected {
            return Err(ExecutionPlanError::new(
                "expected owner mismatch did not deny and verify native cleanup",
            ));
        }
        Ok(())
    }

    // Native, test-only integration proof that a child token is checked
    // against a MAC-authenticated local Full User lease, not just its parent.
    // This is NOT a ShellProcess approval or production execution route.
    #[cfg(test)]
    pub(super) fn qualify_protected_expected_owner_case(
        case: u8,
    ) -> Result<(), ExecutionPlanError> {
        use orcel_policy::full_control::{
            check_full_control, AuthorityContext, AuthorityMode, ElevationState,
        };
        use orcel_policy::full_control_store;
        use std::time::{SystemTime, UNIX_EPOCH};

        struct DisposableStore(std::path::PathBuf);
        impl Drop for DisposableStore {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let parent = ChildProcess::snapshot_native_owner(unsafe { GetCurrentProcess() })?;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| {
                ExecutionPlanError::new("system clock unavailable for native qualification")
            })?
            .as_millis() as u64;
        let root = std::env::temp_dir().join(format!(
            "orcel-sg96-protected-native-{}-{now_ms}-{case}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).map_err(|error| {
            ExecutionPlanError::new(format!("create disposable authority root: {error}"))
        })?;
        let _root = DisposableStore(root.clone());
        let store_path = root.join("full-control.json");
        let key = [0x5au8; 32];
        let live_identity =
            orcel_lifecycle::runtime::identify(std::process::id()).ok_or_else(|| {
                ExecutionPlanError::new("disposable native owner identity unavailable")
            })?;
        if live_identity.creation_time != parent.creation_generation {
            return Err(ExecutionPlanError::new(
                "disposable lifecycle/native owner creation generations differ",
            ));
        }
        let orcel_session_id = format!(
            "orcel-session-{}-{:016x}-0123456789abcdef0123456789abcdef",
            live_identity.pid, live_identity.creation_time
        );
        let runtime_path = root.join("runtime-session.json");
        let mut recorded_owner = orcel_lifecycle::full_control::RuntimeSessionRecord {
            schema: orcel_lifecycle::full_control::RUNTIME_SESSION_SCHEMA.into(),
            session_id: orcel_session_id.clone(),
            owner_pid: live_identity.pid,
            owner_creation_time: live_identity.creation_time,
            owner_image: live_identity.image,
            started_at_ms: now_ms,
        };
        match case {
            10 => recorded_owner.owner_creation_time ^= 1,
            11 => recorded_owner.owner_image.push_str(".forged"),
            12 => {
                recorded_owner.session_id.pop();
                recorded_owner.session_id.push('e');
            }
            13 => recorded_owner.owner_pid ^= 1,
            15 => recorded_owner.schema = "untrusted-runtime-schema".into(),
            _ => {}
        }
        if case != 14 {
            std::fs::write(
                &runtime_path,
                serde_json::to_vec(&recorded_owner).map_err(|error| {
                    ExecutionPlanError::new(format!("serialize disposable runtime record: {error}"))
                })?,
            )
            .map_err(|error| {
                ExecutionPlanError::new(format!("write disposable runtime record: {error}"))
            })?;
        }
        let original_lease = full_control_store::grant_local(
            &store_path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            parent.sid.clone(),
            parent.logon_luid,
            orcel_session_id.clone(),
            now_ms,
        )
        .map_err(|error| ExecutionPlanError::new(error.message))?;

        if case == 1 {
            let mut envelope = std::fs::read(&store_path).map_err(|error| {
                ExecutionPlanError::new(format!("read disposable signed store: {error}"))
            })?;
            let marker = b"\"mac\": \"";
            let offset = envelope
                .windows(marker.len())
                .position(|window| window == marker)
                .ok_or_else(|| ExecutionPlanError::new("signed store MAC field is missing"))?
                + marker.len();
            envelope[offset] = if envelope[offset] == b'0' { b'1' } else { b'0' };
            std::fs::write(&store_path, envelope).map_err(|error| {
                ExecutionPlanError::new(format!("tamper disposable signed store: {error}"))
            })?;
        } else if case == 2 {
            full_control_store::revoke(&store_path, &key)
                .map_err(|error| ExecutionPlanError::new(error.message))?;
        }

        let validated = (|| -> Result<_, ExecutionPlanError> {
            let record: orcel_lifecycle::full_control::RuntimeSessionRecord =
                serde_json::from_slice(&std::fs::read(&runtime_path).map_err(|error| {
                    ExecutionPlanError::new(format!(
                        "read independently persisted owner record: {error}"
                    ))
                })?)
                .map_err(|error| {
                    ExecutionPlanError::new(format!("decode owner record: {error}"))
                })?;
            if record.schema != orcel_lifecycle::full_control::RUNTIME_SESSION_SCHEMA
                || record.owner_pid != std::process::id()
                || record.owner_creation_time != parent.creation_generation
                || record.session_id != orcel_session_id
            {
                return Err(ExecutionPlanError::new(
                    "persisted owner record has inconsistent schema, PID, generation or nonce",
                ));
            }
            let verified_identity = orcel_lifecycle::runtime::ProcessIdentity {
                pid: record.owner_pid,
                creation_time: record.owner_creation_time,
                image: record.owner_image.clone(),
            };
            let _verified_live_owner =
                orcel_lifecycle::runtime::open_verified(&verified_identity).ok_or_else(|| {
                    ExecutionPlanError::new(
                        "persisted runtime owner PID, process creation or executable image not live",
                    )
                })?;
            full_control_store::validate_runtime_session(&record.session_id)
                .map_err(|error| ExecutionPlanError::new(error.message))?;
            let stored = full_control_store::load_store(&store_path, &key)
                .map_err(|error| ExecutionPlanError::new(error.message))?;
            let lease = stored.lease.ok_or_else(|| {
                ExecutionPlanError::new("disposable Full User lease is absent or revoked")
            })?;
            let device_id = full_control_store::derive_device_id(&key);
            let expected_sid = if case == 5 {
                if parent.sid == "S-1-5-18" {
                    "S-1-5-19"
                } else {
                    "S-1-5-18"
                }
            } else {
                &parent.sid
            };
            let context = AuthorityContext {
                windows_user_sid: expected_sid,
                logon_session_id: if case == 6 {
                    parent.logon_luid ^ 1
                } else {
                    parent.logon_luid
                },
                device_id: if case == 7 {
                    "wrong-local-device"
                } else {
                    &device_id
                },
                orcel_session_id: &record.session_id,
                policy_revision: orcel_policy::POLICY_REVISION,
                authority_epoch: if case == 4 {
                    stored.authority_epoch.saturating_add(1)
                } else {
                    stored.authority_epoch
                },
                now_ms: if case == 3 {
                    original_lease.expires_at_ms.saturating_add(1)
                } else {
                    now_ms
                },
                elevation_state: ElevationState::Standard,
                elevation_proof_id: None,
            };
            check_full_control(&lease, &context)
                .map_err(|error| ExecutionPlanError::new(error.message))?;
            if lease.mode != AuthorityMode::FullUser
                || lease.windows_user_sid != parent.sid
                || lease.logon_session_id != parent.logon_luid
                || lease.authority_epoch != stored.authority_epoch
                || lease.orcel_session_id != record.session_id
            {
                return Err(ExecutionPlanError::new(
                    "protected lease does not match the separately observed live native owner",
                ));
            }
            Ok((lease, record.owner_creation_time))
        })();

        if (1..=7).contains(&case) || (10..=15).contains(&case) {
            if validated.is_ok() {
                return Err(ExecutionPlanError::new(
                    "invalid protected native authority was unexpectedly accepted",
                ));
            }
            // No child is created at all when protected authority verification denies.
            return Ok(());
        }
        let (lease, persisted_owner_generation) = validated?;
        let expected_owner_generation = if case == 8 {
            persisted_owner_generation ^ 1
        } else {
            persisted_owner_generation
        };
        let observed_owner_generation =
            ChildProcess::snapshot_native_owner(unsafe { GetCurrentProcess() })?
                .creation_generation;
        if expected_owner_generation != observed_owner_generation {
            if case == 8 {
                return Ok(());
            }
            return Err(ExecutionPlanError::new(
                "local owner process generation changed",
            ));
        }
        if case == 8 {
            return Err(ExecutionPlanError::new(
                "changed native owner generation was unexpectedly accepted",
            ));
        }

        let job = JobObject::kill_on_close()?;
        let mut child = ChildProcess::create_suspended_current_user_fixture(false)?;
        job.assign_or_terminate(&mut child)?;
        let child_generation =
            ChildProcess::snapshot_native_owner(child.process.raw())?.creation_generation;
        let expected = NativeOwnerSnapshot {
            sid: lease.windows_user_sid,
            logon_luid: lease.logon_session_id,
            session_id: parent.session_id,
            elevation: parent.elevation,
            creation_generation: if case == 9 {
                child_generation ^ 1
            } else {
                child_generation
            },
        };
        let result = child.verify_expected_native_owner(&expected);
        if case == 9 {
            let rejected = result.is_err();
            child.terminate_verified()?;
            if !rejected || !job.wait_for_quiescence()? {
                return Err(ExecutionPlanError::new(
                    "changed child generation did not reject and verify cleanup",
                ));
            }
            return Ok(());
        }
        if let Err(error) = result {
            child.terminate_verified()?;
            return Err(error);
        }
        if let Err(error) = child.resume() {
            child.terminate_verified()?;
            return Err(error);
        }
        if child.wait_for_completion()? != 0 || !job.wait_for_quiescence()? {
            return Err(ExecutionPlanError::new(
                "protected-lease native child failed clean completion",
            ));
        }
        Ok(())
    }

    // Disposable authorization-contract integration only: no real user
    // approval is simulated as production evidence, and no process is launched.
    // A synthetic broker cannot mint STRONG authority or enable ShellProcess.
    #[cfg(test)]
    pub(super) fn qualify_soft_action_gate_case(case: u8) -> Result<(), ExecutionPlanError> {
        use orcel_approval::test_support::FixedApprovalBroker;
        use orcel_approval::{
            ApprovalBroker, ApprovalClass, ApprovalDecision, ApprovalPrompt, ConsumeExpectation,
        };
        use orcel_policy::full_control::{
            check_full_control, AuthorityContext, AuthorityMode, ElevationState,
        };
        use orcel_policy::full_control_store;
        use orcel_policy::shell_session::{
            authorize_shell_session_t01, shell_intent_approval_digest, verify_shell_intent_binding,
            ExpectedShellBinding, ShellIntentPhase, ShellKind, ShellOperation, ShellSessionIntent,
            ShellSessionLimits, SHELL_SESSION_INTENT_SCHEMA,
        };

        struct DisposableApprovalState(std::path::PathBuf);
        impl Drop for DisposableApprovalState {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let now = orcel_approval::now_ms();
        let root = std::env::temp_dir().join(format!(
            "orcel-sg96-soft-action-{}-{now}-{case}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).map_err(|error| {
            ExecutionPlanError::new(format!("create synthetic SOFT gate root: {error}"))
        })?;
        let _cleanup = DisposableApprovalState(root.clone());
        let key = [0x39u8; 32];
        let native = orcel_policy::full_control::current_windows_identity()
            .map_err(|error| ExecutionPlanError::new(error.message))?;
        let owner = orcel_lifecycle::runtime::identify(std::process::id())
            .ok_or_else(|| ExecutionPlanError::new("live approval owner unavailable"))?;
        let session_id = format!(
            "orcel-session-{}-{:016x}-0123456789abcdef0123456789abcdef",
            owner.pid, owner.creation_time
        );
        let authority_path = root.join("synthetic-authority.json");
        full_control_store::grant_local(
            &authority_path,
            &key,
            AuthorityMode::FullUser,
            60_000,
            native.windows_user_sid.clone(),
            native.logon_session_id,
            session_id.clone(),
            now,
        )
        .map_err(|error| ExecutionPlanError::new(error.message))?;
        let stored = full_control_store::load_store(&authority_path, &key)
            .map_err(|error| ExecutionPlanError::new(error.message))?;
        let lease = stored.lease.ok_or_else(|| {
            ExecutionPlanError::new("synthetic Full User authority lease missing")
        })?;
        let device = full_control_store::derive_device_id(&key);
        let authority = AuthorityContext {
            windows_user_sid: &native.windows_user_sid,
            logon_session_id: native.logon_session_id,
            device_id: &device,
            orcel_session_id: &session_id,
            policy_revision: orcel_policy::POLICY_REVISION,
            authority_epoch: stored.authority_epoch,
            now_ms: now,
            elevation_state: ElevationState::Standard,
            elevation_proof_id: None,
        };
        check_full_control(&lease, &authority)
            .map_err(|error| ExecutionPlanError::new(error.message))?;
        if lease.mode != AuthorityMode::FullUser {
            return Err(ExecutionPlanError::new("test authority is not Full User"));
        }

        // The file hash/path are merely valid proposed bytes, NOT proof of
        // any native executable or directory identity and never dispatched.
        let mut intent = ShellSessionIntent {
            schema: SHELL_SESSION_INTENT_SCHEMA.into(),
            phase: ShellIntentPhase::Proposed,
            operation: ShellOperation::Spawn,
            session_handle: "sh_0123456789abcdef0123456789abcdef".into(),
            shell_kind: ShellKind::Direct,
            executable_path: r"C:\Windows\System32\cmd.exe".into(),
            executable_sha256: "a".repeat(64),
            argv: vec!["/d".into(), "/c".into(), "exit 0".into()],
            command: String::new(),
            cwd: r"C:\work\repo".into(),
            environment_value_digests: std::collections::BTreeMap::new(),
            limits: ShellSessionLimits {
                timeout_ms: 1_000,
                stdout_bytes: 1024,
                stderr_bytes: 1024,
                stdin_bytes: 1024,
            },
            workspace_id: "synthetic-workspace".into(),
            policy_revision: orcel_policy::POLICY_REVISION.into(),
            windows_user_sid: lease.windows_user_sid.clone(),
            logon_session_id: lease.logon_session_id,
            device_id: device.clone(),
            orcel_session_id: session_id.clone(),
            authority_epoch: stored.authority_epoch,
            owner_process_generation: owner.creation_time,
            session_generation: 1,
            expected_process_generation: 1,
            approval_nonce: "0123456789abcdef0123456789abcdef".into(),
        };
        let trusted = intent.clone();
        let digest = shell_intent_approval_digest(&trusted)
            .map_err(|error| ExecutionPlanError::new(error.message))?;
        match case {
            1 => intent.argv.push("changed-argument".into()),
            2 => intent.approval_nonce = "f".repeat(32),
            7 => intent.operation = ShellOperation::WriteStdin,
            10 => intent.expected_process_generation += 1,
            _ => {}
        }
        let expected_binding = ExpectedShellBinding {
            session_handle: &trusted.session_handle,
            workspace_id: &trusted.workspace_id,
            policy_revision: &trusted.policy_revision,
            windows_user_sid: &trusted.windows_user_sid,
            logon_session_id: trusted.logon_session_id,
            device_id: &trusted.device_id,
            orcel_session_id: &trusted.orcel_session_id,
            authority_epoch: trusted.authority_epoch,
            owner_process_generation: trusted.owner_process_generation,
            session_generation: trusted.session_generation,
            expected_process_generation: trusted.expected_process_generation,
            approval_nonce: &trusted.approval_nonce,
            operation: trusted.operation,
            approval_digest: &digest,
        };
        let intent_verification = verify_shell_intent_binding(&intent, &expected_binding);
        if matches!(case, 1 | 2 | 7 | 10) {
            if intent_verification.is_ok() {
                return Err(ExecutionPlanError::new(
                    "changed intent/nonce/generation wrongly passed exact binding",
                ));
            }
            return Ok(());
        }
        intent_verification.map_err(|error| ExecutionPlanError::new(error.message))?;

        let prompt = ApprovalPrompt::new_with_clock(
            &trusted.workspace_id,
            &trusted.policy_revision,
            "one-shot synthetic local Full User shell proposal",
            &trusted.session_handle,
            "test-only exact shell session digest; execution remains unarmed",
            &digest,
            now,
        );
        let broker = FixedApprovalBroker(ApprovalDecision::Approved);
        if case == 6 {
            let strong = ApprovalPrompt::new_strong_with_clock(
                &trusted.workspace_id,
                &trusted.policy_revision,
                "synthetic strong request must fail",
                &trusted.session_handle,
                "no real user presence",
                &digest,
                now,
            );
            if broker.request_token(&strong).is_ok() {
                return Err(ExecutionPlanError::new(
                    "test SOFT broker unlawfully minted STRONG presence",
                ));
            }
            return Ok(());
        }
        let mut token = broker
            .request_token(&prompt)
            .map_err(|error| ExecutionPlanError::new(error.message))?;
        let mut expected = ConsumeExpectation::new(
            digest.clone(),
            trusted.workspace_id.clone(),
            trusted.policy_revision.clone(),
        );
        let at = match case {
            3 => {
                expected.workspace_id.push_str("-foreign");
                now
            }
            4 => prompt.expires_at_ms.saturating_add(1),
            5 => {
                expected.approval_class = ApprovalClass::Strong;
                now
            }
            8 => {
                expected.digest = "b".repeat(64);
                now
            }
            9 => {
                token.nonce = "f".repeat(64);
                now
            }
            _ => now,
        };
        let consumed = broker.consume(&token, &expected, at);
        if matches!(case, 3 | 4 | 5 | 8 | 9) {
            if consumed.is_ok() {
                return Err(ExecutionPlanError::new(
                    "invalid synthetic SOFT approval was consumed",
                ));
            }
            return Ok(());
        }
        consumed.map_err(|error| ExecutionPlanError::new(error.message))?;
        // An approved SOFT nonce can authorize exactly one operation in the
        // synthetic ledger, but it never enables production T01 shell dispatch.
        if broker.consume(&token, &expected, at).is_ok() {
            return Err(ExecutionPlanError::new(
                "replayed synthetic SOFT approval was accepted",
            ));
        }
        if authorize_shell_session_t01(&trusted, Some(&lease), &authority, &expected_binding)
            .is_ok()
        {
            return Err(ExecutionPlanError::new(
                "T01 production ShellProcess erroneously enabled by synthetic approval",
            ));
        }
        Ok(())
    }

    fn command_line_for_cmd(executable: &Path) -> Vec<u16> {
        let mut command = Vec::new();
        command.push('"' as u16);
        command.extend(executable.as_os_str().encode_wide());
        command.push('"' as u16);
        command.extend(" /d /q /c exit 0".encode_utf16());
        command.push(0);
        command
    }

    fn filtered_environment_block() -> Result<Vec<u16>, ExecutionPlanError> {
        const SAFE_KEYS: &[&str] = &[
            "APPDATA",
            "ComSpec",
            "HOMEDRIVE",
            "HOMEPATH",
            "LOCALAPPDATA",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "PATH",
            "PATHEXT",
            "PROCESSOR_ARCHITECTURE",
            "SystemDrive",
            "SystemRoot",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "WINDIR",
        ];

        let mut entries = Vec::<(String, std::ffi::OsString)>::new();
        for key in SAFE_KEYS {
            if let Some(value) = std::env::var_os(key) {
                entries.push(((*key).to_owned(), value));
            }
        }

        for required in ["LOCALAPPDATA", "SystemRoot", "TEMP", "TMP"] {
            if !entries
                .iter()
                .any(|(key, _)| key.eq_ignore_ascii_case(required))
            {
                return Err(ExecutionPlanError::new(format!(
                    "required Windows launch environment variable is unavailable: {required}"
                )));
            }
        }

        entries.sort_by(|left, right| {
            left.0
                .to_ascii_lowercase()
                .cmp(&right.0.to_ascii_lowercase())
        });

        let mut environment = Vec::<u16>::new();
        for (key, value) in entries {
            environment.extend(key.encode_utf16());
            environment.push('=' as u16);
            environment.extend(value.encode_wide());
            environment.push(0);
        }
        environment.push(0);
        Ok(environment)
    }

    pub(super) fn fixed_system_executable() -> Result<std::path::PathBuf, ExecutionPlanError> {
        const INITIAL_BUFFER_CHARS: usize = 260;
        const MAX_SYSTEM_DIRECTORY_CHARS: usize = 32_767;

        let mut buffer = vec![0u16; INITIAL_BUFFER_CHARS];
        let copied =
            unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), INITIAL_BUFFER_CHARS as u32) };
        let copied = if copied == 0 {
            return Err(last_error("GetSystemDirectoryW"));
        } else if copied < INITIAL_BUFFER_CHARS as u32 {
            usize::try_from(copied).map_err(|_| {
                ExecutionPlanError::new("GetSystemDirectoryW returned an invalid length")
            })?
        } else {
            let capacity = usize::try_from(copied)
                .ok()
                .filter(|capacity| *capacity <= MAX_SYSTEM_DIRECTORY_CHARS)
                .ok_or_else(|| {
                    ExecutionPlanError::new("GetSystemDirectoryW returned an invalid size")
                })?;
            buffer.resize(capacity, 0);
            let copied = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), capacity as u32) };
            if copied == 0 {
                return Err(last_error("GetSystemDirectoryW(resized)"));
            }
            let copied = usize::try_from(copied).map_err(|_| {
                ExecutionPlanError::new("GetSystemDirectoryW returned an invalid length")
            })?;
            if copied + 1 > capacity {
                return Err(ExecutionPlanError::new(
                    "GetSystemDirectoryW returned an invalid length",
                ));
            }
            copied
        };
        buffer.truncate(copied);

        let executable = Path::new(OsString::from_wide(&buffer).as_os_str()).join("cmd.exe");
        if !executable.is_file() {
            return Err(ExecutionPlanError::new(format!(
                "contained probe executable does not exist: {}",
                executable.display()
            )));
        }
        Ok(executable)
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn last_error(operation: &str) -> ExecutionPlanError {
        let code = unsafe { GetLastError() };
        ExecutionPlanError::new(format!("{operation} failed with Win32 error {code}"))
    }

    fn hresult_error(operation: &str, code: Hresult) -> ExecutionPlanError {
        ExecutionPlanError::new(format!(
            "{operation} failed with HRESULT 0x{:08X}",
            code as u32
        ))
    }
}

#[cfg(all(test, windows))]
mod contained_launch_tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    pub(crate) static ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    struct EnvironmentVarGuard {
        key: &'static str,
        original: Option<std::ffi::OsString>,
    }

    impl EnvironmentVarGuard {
        fn replace(key: &'static str, value: &str) -> Self {
            let original = std::env::var_os(key);
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, original }
        }
    }

    impl Drop for EnvironmentVarGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.original {
                    Some(value) => std::env::set_var(self.key, value),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn fixed_system_executable_ignores_caller_controlled_system_root() {
        let _environment_lock = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let expected = windows_contained_launch::fixed_system_executable()
            .expect("resolve fixed system executable");
        let _environment = EnvironmentVarGuard::replace("SystemRoot", r"C:\caller-controlled");
        let actual = windows_contained_launch::fixed_system_executable()
            .expect("resolve fixed system executable");
        assert_eq!(actual, expected);
    }

    fn bounded_child_diagnostic(label: &str, bytes: &[u8]) -> String {
        let mut text = String::new();
        for byte in bytes.iter().copied().take(512) {
            match byte {
                b'\n' => text.push_str("\\n"),
                b'\r' => text.push_str("\\r"),
                b'\t' => text.push_str("\\t"),
                0x20..=0x7e => text.push(char::from(byte)),
                _ => text.push_str(&format!("\\x{byte:02x}")),
            }
        }
        let lower = text.to_ascii_lowercase();
        for marker in [
            "password",
            "token",
            "secret",
            "credential",
            "api_key",
            "private_key",
        ] {
            if lower.contains(marker) {
                return format!("{label}=<redacted:{}>", bytes.len());
            }
        }
        format!("{label}[{}]={text}", bytes.len())
    }

    fn private_qualification_env() -> std::collections::BTreeMap<String, String> {
        let mut env = std::collections::BTreeMap::new();
        for key in [
            "LOCALAPPDATA",
            "SystemRoot",
            "TEMP",
            "TMP",
            "PATH",
            "ComSpec",
        ] {
            env.insert(
                key.to_owned(),
                std::env::var(key).expect("required qualification environment"),
            );
        }
        env
    }

    #[test]
    fn windows_private_qualification_executes_bounded_fixed_child_with_quiescent_job() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let workspace = std::env::temp_dir().join(format!("Orcel.Private.Exec.{suffix}"));
        std::fs::create_dir_all(&workspace).expect("qualification workspace");
        let executable = windows_contained_launch::fixed_system_executable()
            .expect("system executable")
            .parent()
            .expect("system directory")
            .join("whoami.exe");
        let env = private_qualification_env();
        let plan = build_execution_plan(
            &workspace,
            &executable,
            &[],
            ".",
            &env,
            ExecutionLimits::default(),
        )
        .expect("bounded private plan");
        let profile = format!("Orcel.Private.Exec.{suffix}");
        let result = qualify_private_execution(plan, &profile).expect("private execution");
        assert!(result.appcontainer_verified);
        assert!(result.assigned_to_job_before_resume);
        assert!(result.job_quiescent);
        assert_eq!(
            result.exit_code,
            0,
            "private fixture diagnostic: {} {}",
            bounded_child_diagnostic("stdout", &result.stdout),
            bounded_child_diagnostic("stderr", &result.stderr),
        );
        assert!(!result.stdout.is_empty());
        assert!(result.stderr.is_empty());
        let _ = std::fs::remove_dir_all(workspace);
    }

    fn private_fixture_plan(
        suffix: u128,
        test_name: &str,
        limits: ExecutionLimits,
    ) -> (PathBuf, ExecutionPlan) {
        let workspace = std::env::temp_dir().join(format!("Orcel.Private.Failure.{suffix}"));
        std::fs::create_dir_all(&workspace).expect("qualification workspace");
        let executable = std::env::current_exe().expect("fixture executable");
        let plan = build_execution_plan(
            &workspace,
            &executable,
            &[
                "--exact".to_owned(),
                test_name.to_owned(),
                "--nocapture".to_owned(),
            ],
            ".",
            &private_qualification_env(),
            limits,
        )
        .expect("bounded private plan");
        (workspace, plan)
    }

    #[test]
    fn private_timeout_fixture_child() {
        if std::env::args().any(|argument| argument == "--exact") {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn private_timeout_descendant() {
        if std::env::args().any(|argument| argument == "--exact") {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn private_stdout_fixture_child() {
        if std::env::args().any(|argument| argument == "--exact") {
            let mut stdout = std::io::stdout().lock();
            use std::io::Write;
            let _ = stdout.write_all(&vec![b'x'; 4096]);
            let _ = stdout.flush();
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn private_stderr_fixture_child() {
        if std::env::args().any(|argument| argument == "--exact") {
            let mut stderr = std::io::stderr().lock();
            use std::io::Write;
            let _ = stderr.write_all(&vec![b'x'; 4096]);
            let _ = stderr.flush();
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn private_descendant_primary_child() {}

    #[test]
    fn private_output_descendant() {
        if std::env::args().any(|argument| argument == "--exact") {
            std::thread::sleep(Duration::from_secs(30));
        }
    }

    #[test]
    fn windows_private_timeout_is_verified_and_typed() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(1),
            stdout_bytes: 1024,
            stderr_bytes: 1024,
        };
        let (workspace, plan) = private_fixture_plan(
            suffix,
            "contained_launch_tests::private_timeout_fixture_child",
            limits,
        );
        let result = qualify_private_execution_mode(
            plan,
            &format!("Orcel.Private.Timeout.{suffix}"),
            PrivateExecutionMode::Timeout,
        );
        assert_eq!(result, Err(PrivateExecutionFailure::ProcessTimeout));
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn windows_private_stdout_limit_is_stream_typed_and_verified() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(5),
            stdout_bytes: 1,
            stderr_bytes: 1024,
        };
        let (workspace, plan) = private_fixture_plan(
            suffix,
            "contained_launch_tests::private_stdout_fixture_child",
            limits,
        );
        let result = qualify_private_execution_mode(
            plan,
            &format!("Orcel.Private.Stdout.{suffix}"),
            PrivateExecutionMode::StdoutLimit,
        );
        assert_eq!(
            result,
            Err(PrivateExecutionFailure::OutputLimit(OutputStream::Stdout))
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn windows_private_stderr_limit_is_stream_typed_and_verified() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(5),
            stdout_bytes: 1024,
            stderr_bytes: 1,
        };
        let (workspace, plan) = private_fixture_plan(
            suffix,
            "contained_launch_tests::private_stderr_fixture_child",
            limits,
        );
        let result = qualify_private_execution_mode(
            plan,
            &format!("Orcel.Private.Stderr.{suffix}"),
            PrivateExecutionMode::StderrLimit,
        );
        assert_eq!(
            result,
            Err(PrivateExecutionFailure::OutputLimit(OutputStream::Stderr))
        );
        let _ = std::fs::remove_dir_all(workspace);
    }

    /// XP-13b, the card's negative test on Windows: a descendant in the
    /// run's job that outlives the primary and holds none of its pipes. The
    /// run completes and owned cleanup ends the descendant with the job; if
    /// it were waited on instead, the run would end `TerminationUnverified`
    /// after the 5 s quiescence wait. The harness creates the descendant
    /// into the job, as the other descendant tests do: on the hosted runner
    /// an AppContainer child is refused process creation outright (Access
    /// denied even for System32's cmd.exe), so the child cannot be the one
    /// to start it there. A descendant the child itself creates is therefore
    /// not exercised on hosted runners: that path relies on Windows placing
    /// every child process in its parent's job, which holds because the job
    /// never sets `JOB_OBJECT_LIMIT_BREAKAWAY_OK` (or
    /// `SILENT_BREAKAWAY_OK`), so no descendant can leave it.
    #[test]
    fn xp13b_windows_a_descendant_that_outlives_the_child_is_cleaned_up() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(20),
            stdout_bytes: 16 * 1024,
            stderr_bytes: 16 * 1024,
        };
        let (workspace, plan) = private_fixture_plan(
            suffix,
            "contained_launch_tests::private_descendant_primary_child",
            limits,
        );
        let started = std::time::Instant::now();
        let result = qualify_private_execution_mode(
            plan,
            &format!("Orcel.Private.DetachedDescendant.{suffix}"),
            PrivateExecutionMode::DetachedDescendant,
        )
        .expect("a run whose descendant outlives the primary completes");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(result.exit_code, 0);
        assert!(result.job_quiescent);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn windows_private_descendant_retained_stdio_is_bounded_and_quiescent() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(5),
            stdout_bytes: 16 * 1024,
            stderr_bytes: 16 * 1024,
        };
        let (workspace, plan) = private_fixture_plan(
            suffix,
            "contained_launch_tests::private_descendant_primary_child",
            limits,
        );
        let started = std::time::Instant::now();
        let result = qualify_private_execution_mode(
            plan,
            &format!("Orcel.Private.DescendantDrain.{suffix}"),
            PrivateExecutionMode::DescendantDrain,
        )
        .expect("bounded descendant drain");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(result.exit_code, 0);
        assert!(result.appcontainer_verified);
        assert!(result.assigned_to_job_before_resume);
        assert!(result.job_quiescent);
        let _ = std::fs::remove_dir_all(workspace);
    }

    #[test]
    fn windows_private_unverified_termination_never_promotes_timeout_or_output_limit() {
        assert_eq!(
            windows_contained_launch::classify_termination(
                windows_contained_launch::DestructiveEvent::Timeout,
                false,
            ),
            PrivateExecutionFailure::TerminationUnverified
        );
        assert_eq!(
            windows_contained_launch::classify_termination(
                windows_contained_launch::DestructiveEvent::OutputLimit(OutputStream::Stdout),
                false,
            ),
            PrivateExecutionFailure::TerminationUnverified
        );
        assert_eq!(
            windows_contained_launch::classify_termination(
                windows_contained_launch::DestructiveEvent::OutputLimit(OutputStream::Stderr),
                false,
            ),
            PrivateExecutionFailure::TerminationUnverified
        );
    }

    #[test]
    fn sg000096_current_user_disposable_child_is_job_assigned_before_resume() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        windows_contained_launch::qualify_current_user_job_fixture(false).expect(
            "a native ordinary-user fixture must be suspended, verified, Job-bound and drained",
        );
    }

    #[test]
    fn sg000096_suspended_thread_handle_failure_terminates_before_return() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        windows_contained_launch::qualify_current_user_job_fixture(true)
            .expect("a failed thread wrapper must terminate its suspended child and verify exit");
    }

    #[test]
    fn sg000096_real_job_assignment_failure_verifies_unassigned_child_exit() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        windows_contained_launch::qualify_failed_job_assignment_cleanup()
            .expect("failed native Job attachment must terminate and verify the suspended child");
    }

    #[test]
    fn sg000096_native_pre_resume_inspection_failure_verifies_job_cleanup() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        for case in 0..=3 {
            windows_contained_launch::qualify_pre_resume_inspection_case(case).expect(
                "suspended native inspection case must deny or finish with verified cleanup",
            );
        }
    }

    #[test]
    fn sg000096_expected_native_owner_mismatches_fail_closed_before_resume() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        for case in 0..=6 {
            windows_contained_launch::qualify_expected_owner_case(case)
                .expect("native expected-owner case must deny or complete with verified cleanup");
        }
    }

    #[test]
    fn sg000096_protected_lease_and_one_shot_soft_action_stay_unarmed() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        for case in 0..=10 {
            windows_contained_launch::qualify_soft_action_gate_case(case)
                .expect("synthetic protected lease and one-shot SOFT case must fail closed");
        }
    }

    #[test]
    fn sg000096_protected_full_user_lease_binds_native_expected_owner() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let tmp = std::env::temp_dir().to_string_lossy().into_owned();
        let _tmp = EnvironmentVarGuard::replace("TMP", &tmp);
        for case in 0..=15 {
            windows_contained_launch::qualify_protected_expected_owner_case(case)
                .expect("protected native owner case must deny or verify clean completion");
        }
    }

    #[test]
    fn windows_appcontainer_child_is_job_assigned_before_resume() {
        let _guard = ENVIRONMENT_LOCK.lock().expect("environment lock");
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let name = format!("Orcel.Contained.{}.{}", std::process::id(), suffix);

        let result =
            probe_contained_appcontainer_job_launch(&name).expect("contained child launch");
        assert!(result.profile_created);
        assert!(result.process_created_suspended);
        assert!(result.appcontainer_token_verified);
        assert!(result.assigned_to_job_before_resume);
        assert!(result.resumed);
        assert!(result.child_completed);
        assert_eq!(result.exit_code, 0);
        assert!(result.profile_deleted);
    }
}
