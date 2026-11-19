//! SG-000132 WP1-10 launch, WP1-15 operations (SG-000096, SG-000097): the
//! process and git operations of `orceld fc-worker`. They run only in the
//! worker, which runs only inside the dispatch's service-made Job Object;
//! every program they start inherits that job (no breakaway is allowed, and
//! nothing here asks for it), so the service's terminate, Stop or the
//! outcome ends the whole tree.
//!
//! Process (`run`): the caller names the program as an absolute path and
//! the worker resolves it; there is no program search, no shell and no
//! command string. The program must be a `.exe` inside the lease's roots
//! (resolved, so a junction or link out of the roots is refused), have one
//! name (a hard link inside the roots can name a file outside them, and
//! in-box Windows programs are hard-linked into WinSxS), and not be one of
//! [`REFUSED_PROGRAMS`]: shells, script hosts, launchers that start
//! programs outside the job on request, and Git (which runs only through
//! the hardened git operations), nor lie under a Git installation. It is
//! held open without write or delete sharing from its checks until it has
//! started, and re-resolved right before the start (same path, same volume
//! serial and file index). The arguments are an argument vector,
//! quoted for `CreateProcessW` by the standard library; a `.exe` never
//! reinterprets them through `cmd.exe`. The working folder is an existing
//! folder inside the roots. The environment is [`CHILD_ENVIRONMENT`] only.
//! stdin is the null device; stdout and stderr are captured to a bound; the
//! run has a timeout and reports the exit code.
//!
//! Git (`git_*`): the existing provider (`orcel-provider-git`, SG-000097
//! "git through the existing provider") with the lease root that holds the
//! repository as its workspace root, so the repository's Git directory and
//! common directory must lie inside that root too, and with the Git program
//! resolved by the worker from fixed install locations ([`git_program`]).
//! The operations are structured (no free argument list reaches Git):
//! status, diff, log, add, unstage, commit and branch creation. Fetch,
//! push, remote, config, credential, clone, submodule, checkout of other
//! commits and hook installation are not offered. The provider runs Git
//! with an empty environment except PATH, PATHEXT, SystemRoot, WINDIR, TEMP
//! and TMP, no system or global configuration (`GIT_CONFIG_NOSYSTEM`,
//! `GIT_CONFIG_GLOBAL` the null device), no terminal prompt, no askpass, no
//! credential helper, no transport (`GIT_ALLOW_PROTOCOL` empty), the null
//! device as editor, hooks pointed at an empty folder it just made,
//! fsmonitor off, no external diff or textconv, no signing, and every
//! configured filter driver emptied; `safe.directory` is never set, so
//! Git's ownership check stays on. Before any Git command runs, the
//! provider's configuration gate (review of #824) reads the repository's
//! `.git` pointer and configuration files itself and refuses hooks defined
//! in configuration (`hook.*`, which `core.hooksPath` and `--no-verify` do
//! not turn off), aliases, includes, credential, transport, proxy, editor,
//! pager, diff, merge and signing programs, URL and HTTP rewrites, and any
//! value or `gitdir:` naming a network share or device; discovery stops at
//! the lease root (`GIT_CEILING_DIRECTORIES`) and implicit bare
//! repositories are refused (`safe.bareRepository=explicit`).

use super::{existing, failure, io_failure, refuse_hard_links, resolved_roots};
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use orcel_provider_git::{GitProvider, GitProviderError};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

/// The most arguments one run passes.
pub(crate) const MAX_PROCESS_ARGS: usize = 64;
/// The longest argument, and the longest command line (CreateProcessW
/// accepts 32767 characters).
pub(crate) const MAX_ARG_CHARS: usize = 8 * 1024;
pub(crate) const MAX_COMMAND_LINE_CHARS: usize = 32_000;
/// The longest a run may take (the worker itself is ended at 60 s).
pub(crate) const MAX_PROCESS_TIMEOUT_MS: u64 = 50_000;
/// The most bytes of stdout, and of stderr, a run returns (each). With
/// JSON escaping both fit the worker's reply frame.
pub(crate) const MAX_PROCESS_OUTPUT_BYTES: usize = 64 * 1024;
/// How long the worker waits, after the program exited, for its output
/// pipes to close (a descendant that inherited them keeps them open; it is
/// in the job and ends with it).
const OUTPUT_DRAIN: Duration = Duration::from_secs(2);
/// The most commits `git_log` returns (the provider's own bound).
pub(crate) const MAX_GIT_LOG: usize = 100;

/// Program file names (without `.exe`, lowercase) the process family never
/// runs: shells and script hosts, programs that start other programs
/// outside the job on request (Task Scheduler, WMI, the shell, BITS, the
/// COM surrogate, services, `runas`), the shells and tools Git for Windows
/// ships, and Git itself (every name starting with `git`, which runs only
/// through the hardened git operations; anything under a Git installation
/// is refused as well). A cheap mitigation, not a boundary: a renamed
/// copy, or any program that can run code (an interpreter, a build tool),
/// can still ask those brokers (SG132_SLICE4.md, residuals).
pub(crate) const REFUSED_PROGRAMS: &[&str] = &[
    "cmd",
    "powershell",
    "powershell_ise",
    "pwsh",
    "wsl",
    "wslhost",
    "bash",
    "sh",
    "wscript",
    "cscript",
    "mshta",
    "rundll32",
    "regsvr32",
    "schtasks",
    "at",
    "wmic",
    "explorer",
    "bitsadmin",
    "dllhost",
    "sc",
    "runas",
    "pcalua",
    "forfiles",
    "cmstp",
    "wt",
    "winrs",
    "conhost",
    "dash",
    "env",
    "perl",
    "busybox",
    "mintty",
    "winpty",
    "scalar",
    "tig",
];

/// Environment variables a started program receives, when orceld has them
/// (compared without regard to case). Nothing else is inherited: no
/// tokens, keys, `GIT_*`, `SSH_*`, proxy or Orcel variables.
pub(crate) const CHILD_ENVIRONMENT: &[&str] = &[
    "SystemRoot",
    "SystemDrive",
    "windir",
    "PATH",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "CommonProgramFiles",
    "CommonProgramFiles(x86)",
    "CommonProgramW6432",
    "NUMBER_OF_PROCESSORS",
    "PROCESSOR_ARCHITECTURE",
    "OS",
    "USERNAME",
];

/// `\\?\C:\x` as `C:\x` (canonicalized paths are verbatim on Windows; a
/// working folder or program path in that form confuses some programs).
pub(crate) fn plain(path: &Path) -> PathBuf {
    match path.to_str().and_then(|text| text.strip_prefix(r"\\?\")) {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

/// The environment a started program receives, from `parent`'s.
pub(crate) fn child_environment(
    parent: impl Iterator<Item = (OsString, OsString)>,
) -> Vec<(OsString, OsString)> {
    parent
        .filter(|(name, _)| {
            name.to_str().is_some_and(|name| {
                CHILD_ENVIRONMENT
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name))
            })
        })
        .collect()
}

/// A resolved program, held open from its checks until it has started.
pub(crate) struct ResolvedProgram {
    pub(crate) path: PathBuf,
    /// Opened without write or delete sharing: while it is held, the file
    /// cannot be written, renamed, deleted or replaced. Kept, not read.
    #[allow(dead_code)]
    pub(crate) held: std::fs::File,
    /// Volume serial and file index (device and inode elsewhere).
    pub(crate) identity: String,
}

/// The file's identity: volume serial number and file index on Windows,
/// device and inode elsewhere.
#[cfg(windows)]
pub(crate) fn file_identity(file: &std::fs::File) -> Result<String, ProviderError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: a zeroed BY_HANDLE_FILE_INFORMATION is a valid out-parameter.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: an open file handle and a live out-parameter.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(io_failure(
            "read the program's identity",
            &std::io::Error::last_os_error(),
        ));
    }
    Ok(format!(
        "{:08x}-{:08x}{:08x}",
        info.dwVolumeSerialNumber, info.nFileIndexHigh, info.nFileIndexLow
    ))
}

#[cfg(unix)]
pub(crate) fn file_identity(file: &std::fs::File) -> Result<String, ProviderError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|error| io_failure("read the program's identity", &error))?;
    Ok(format!("{:x}-{:x}", metadata.dev(), metadata.ino()))
}

/// Opens `path` for reading, sharing read access only (Windows).
fn open_held(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ);
    }
    options.open(path)
}

/// The Git installations' folders (`...\Git` above each `cmd\git.exe`
/// candidate) that exist, resolved. Nothing under them runs through `run`.
fn git_install_folders() -> Vec<PathBuf> {
    git_candidates()
        .iter()
        .filter_map(|candidate| candidate.parent()?.parent().map(Path::to_path_buf))
        .filter_map(|folder| std::fs::canonicalize(folder).ok())
        .collect()
}

impl ResolvedProgram {
    /// Right before the start: the path still resolves to the same place
    /// and the file there is the one held (same identity). The held handle
    /// keeps the file itself from changing; this catches a folder on the
    /// path swapped since the checks.
    pub(crate) fn reverify(&self) -> Result<(), ProviderError> {
        let again = std::fs::canonicalize(&self.path)
            .map_err(|error| io_failure("resolve the program again", &error))?;
        let reopened =
            open_held(&again).map_err(|error| io_failure("open the program again", &error))?;
        if plain(&again) != self.path || file_identity(&reopened)? != self.identity {
            return Err(failure(
                FailureCode::TargetStale,
                "the program changed between its checks and its start",
            ));
        }
        Ok(())
    }
}

/// The program a run names, resolved: an existing `.exe` with one name,
/// inside the resolved roots, not a refused program and not under a Git
/// installation, held open (no write or delete sharing) with its identity.
pub(crate) fn resolve_program(
    program: &str,
    roots: &[String],
) -> Result<ResolvedProgram, ProviderError> {
    let refused_name = |path: &Path| -> Result<(), ProviderError> {
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        if !extension.eq_ignore_ascii_case("exe") {
            return Err(failure(
                FailureCode::CapabilityDenied,
                "the program is a .exe (no batch file, script, shortcut or installer: those run through a shell or a broker)",
            ));
        }
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if REFUSED_PROGRAMS.contains(&stem.as_str()) || stem.starts_with("git") {
            return Err(failure(
                FailureCode::CapabilityDenied,
                format!(
                    "{stem}.exe is a shell, script host, launcher or Git; Full Control runs it only through its own operation"
                ),
            ));
        }
        Ok(())
    };
    refused_name(Path::new(program))?;
    let resolved = existing(program, roots)?;
    refused_name(&resolved)?;
    // Review of #824: Git's installation carries shells, Perl, `scalar`,
    // the upload and receive packs and more; none of it runs through `run`.
    if git_install_folders()
        .iter()
        .any(|folder| resolved.starts_with(folder))
    {
        return Err(failure(
            FailureCode::CapabilityDenied,
            "programs under the Git installation run only through the git operations",
        ));
    }
    let file = open_held(&resolved).map_err(|error| io_failure("open the program", &error))?;
    let metadata = file
        .metadata()
        .map_err(|error| io_failure("read the program's metadata", &error))?;
    if !metadata.is_file() {
        return Err(failure(
            FailureCode::InvalidRequest,
            "the program is not a file",
        ));
    }
    refuse_hard_links(&file)?;
    let identity = file_identity(&file)?;
    Ok(ResolvedProgram {
        path: plain(&resolved),
        held: file,
        identity,
    })
}

/// An existing folder inside the resolved roots.
pub(crate) fn resolve_folder(path: &str, roots: &[String]) -> Result<PathBuf, ProviderError> {
    let resolved = existing(path, roots)?;
    if !resolved.is_dir() {
        return Err(failure(
            FailureCode::InvalidRequest,
            "the working folder is not a folder",
        ));
    }
    Ok(resolved)
}

/// What one reader captured.
#[derive(Default)]
struct Capture {
    kept: Vec<u8>,
    total: u64,
}

/// Reads `reader` to its end in a thread, keeping the first `max` bytes.
fn capture(
    mut reader: impl Read + Send + 'static,
    max: usize,
) -> (Arc<Mutex<Capture>>, mpsc::Receiver<()>) {
    let shared = Arc::new(Mutex::new(Capture::default()));
    let (done, finished) = mpsc::channel();
    let writer = Arc::clone(&shared);
    std::thread::spawn(move || {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    let Ok(mut capture) = writer.lock() else {
                        break;
                    };
                    capture.total += count as u64;
                    let room = max.saturating_sub(capture.kept.len());
                    let take = room.min(count);
                    capture.kept.extend_from_slice(&buffer[..take]);
                }
            }
        }
        let _ = done.send(());
    });
    (shared, finished)
}

fn captured(shared: &Arc<Mutex<Capture>>) -> (String, u64, bool) {
    match shared.lock() {
        Ok(capture) => (
            String::from_utf8_lossy(&capture.kept).into_owned(),
            capture.total,
            capture.total > capture.kept.len() as u64,
        ),
        Err(_) => (String::new(), 0, true),
    }
}

/// The process family: runs `program` with `args` in `cwd`.
/// The bounds of a run's own arguments, checked before anything is
/// resolved: here in the worker and, SG132_SLICE8.md, by orceld before the
/// person is asked (`WorkerOp::check_arguments`).
pub(crate) fn check_run_arguments(
    program: &str,
    args: &[String],
    timeout_ms: u64,
    max_output_bytes: usize,
) -> Result<(), ProviderError> {
    if timeout_ms == 0 || timeout_ms > MAX_PROCESS_TIMEOUT_MS {
        return Err(failure(
            FailureCode::InvalidRequest,
            "timeout_ms is 1 to 50000",
        ));
    }
    if max_output_bytes == 0 || max_output_bytes > MAX_PROCESS_OUTPUT_BYTES {
        return Err(failure(
            FailureCode::InvalidRequest,
            "max_output_bytes is 1 to 65536",
        ));
    }
    if args.len() > MAX_PROCESS_ARGS {
        return Err(failure(
            FailureCode::InvalidRequest,
            "a run passes at most 64 arguments",
        ));
    }
    let mut line = program.chars().count() + 2;
    for arg in args {
        let chars = arg.chars().count();
        if chars > MAX_ARG_CHARS || arg.contains('\0') {
            return Err(failure(
                FailureCode::InvalidRequest,
                "an argument is at most 8192 characters and has no NUL",
            ));
        }
        // Worst case: every character escaped, plus quotes and a space.
        line += 2 * chars + 3;
    }
    if line > MAX_COMMAND_LINE_CHARS {
        return Err(failure(
            FailureCode::InvalidRequest,
            "the command line would exceed 32000 characters",
        ));
    }
    Ok(())
}

pub(crate) fn run_program(
    program: &str,
    args: &[String],
    cwd: &str,
    timeout_ms: u64,
    max_output_bytes: usize,
    roots: &[String],
) -> Result<Value, ProviderError> {
    check_run_arguments(program, args, timeout_ms, max_output_bytes)?;
    let resolved = resolve_program(program, roots)?;
    let folder = plain(&resolve_folder(cwd, roots)?);
    let mut command = Command::new(&resolved.path);
    command
        .args(args)
        .current_dir(&folder)
        .env_clear()
        .envs(child_environment(std::env::vars_os()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // No console window; never CREATE_BREAKAWAY_FROM_JOB (the job
        // refuses it anyway) and never DETACHED_PROCESS-style launches
        // outside the job: CreateProcessW puts the child in this job.
        command.creation_flags(windows_sys::Win32::System::Threading::CREATE_NO_WINDOW);
    }
    // Review of #824: the program started is the one checked.
    resolved.reverify()?;
    let mut child = command
        .spawn()
        .map_err(|error| io_failure("start the program", &error))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| failure(FailureCode::ProviderUnavailable, "no stdout pipe"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| failure(FailureCode::ProviderUnavailable, "no stderr pipe"))?;
    let (out, out_done) = capture(stdout, max_output_bytes);
    let (err, err_done) = capture(stderr, max_output_bytes);
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                // The program's descendants are in the dispatch's job and
                // end when the service terminates it with the outcome.
                let _ = child.kill();
                let _ = child.wait();
                return Err(failure(
                    FailureCode::ProcessTimeout,
                    format!("the program did not exit within {timeout_ms} ms and was ended"),
                ));
            }
            Err(error) => {
                let _ = child.kill();
                return Err(io_failure("wait for the program", &error));
            }
        }
    };
    let drain = Instant::now() + OUTPUT_DRAIN;
    let mut complete = true;
    for done in [&out_done, &err_done] {
        let left = drain.saturating_duration_since(Instant::now());
        if done.recv_timeout(left).is_err() {
            complete = false;
        }
    }
    let (stdout, stdout_bytes, stdout_truncated) = captured(&out);
    let (stderr, stderr_bytes, stderr_truncated) = captured(&err);
    Ok(json!({
        "program": resolved.path.display().to_string(),
        "program_identity": resolved.identity,
        "exit_code": status.code(),
        "stdout": stdout,
        "stderr": stderr,
        "stdout_bytes": stdout_bytes,
        "stderr_bytes": stderr_bytes,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        // false when a descendant still held the output pipes after the
        // program exited; it runs in the job until the outcome ends it.
        "output_complete": complete,
    }))
}

/// Where the worker looks for Git: the Git for Windows launcher under the
/// Program Files folders (administrator-installed), then a per-user
/// install; on other systems the usual absolute locations. No program
/// search through PATH and nothing from the request.
pub(crate) fn git_candidates() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let mut candidates = Vec::new();
        for (variable, tail) in [
            ("ProgramW6432", r"Git\cmd\git.exe"),
            ("ProgramFiles", r"Git\cmd\git.exe"),
            ("ProgramFiles(x86)", r"Git\cmd\git.exe"),
            ("LOCALAPPDATA", r"Programs\Git\cmd\git.exe"),
        ] {
            if let Some(base) = std::env::var_os(variable) {
                let base = PathBuf::from(base);
                if base.is_absolute() {
                    candidates.push(base.join(tail));
                }
            }
        }
        candidates
    }
    #[cfg(not(windows))]
    {
        [
            "/usr/bin/git",
            "/usr/local/bin/git",
            "/opt/homebrew/bin/git",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect()
    }
}

/// The Git program the git operations run (the first candidate that is a
/// file).
pub(crate) fn git_program() -> Result<PathBuf, ProviderError> {
    git_candidates()
        .into_iter()
        .find(|candidate| candidate.is_file())
        .ok_or_else(|| {
            failure(
                FailureCode::ProviderUnavailable,
                "Git is not installed in a known location (Program Files\\Git)",
            )
        })
}

pub(crate) fn git_error(error: GitProviderError) -> ProviderError {
    ProviderError::new(error.code, error.message)
}

/// The provider for the lease root that holds `repository`, and the
/// repository's path relative to it.
fn git_provider(
    repository: &str,
    roots: &[String],
) -> Result<(GitProvider, String), ProviderError> {
    let repo = resolve_folder(repository, roots)?;
    let root = resolved_roots(roots)
        .into_iter()
        .filter(|root| repo.starts_with(root))
        .max_by_key(|root| root.as_os_str().len())
        .ok_or_else(|| {
            failure(
                FailureCode::PathEscape,
                "the repository lies outside the lease's roots",
            )
        })?;
    let relative = repo
        .strip_prefix(&root)
        .map_err(|_| {
            failure(
                FailureCode::PathEscape,
                "the repository is not under its root",
            )
        })?
        .to_str()
        .ok_or_else(|| {
            failure(
                FailureCode::InvalidRequest,
                "the repository path is not UTF-8",
            )
        })?
        .to_owned();
    let relative = if relative.is_empty() {
        ".".to_owned()
    } else {
        relative
    };
    let provider = GitProvider::with_program(&root, git_program()?).map_err(git_error)?;
    Ok((provider, relative))
}

/// One git operation.
pub(crate) enum GitAction<'a> {
    Status,
    Diff { staged: bool },
    Log { max_count: usize },
    Add { paths: &'a [String] },
    Unstage { paths: &'a [String] },
    Commit { message: &'a str },
    BranchCreate { branch: &'a str },
}

/// The git family: one structured operation on the repository at
/// `repository`. A mutation reads the repository's state and acts only if
/// it is still that state (the provider's own check).
pub(crate) fn run_git(
    repository: &str,
    action: GitAction<'_>,
    roots: &[String],
) -> Result<Value, ProviderError> {
    if let GitAction::Log { max_count } = action {
        if max_count == 0 || max_count > MAX_GIT_LOG {
            return Err(failure(
                FailureCode::InvalidRequest,
                "max_count is 1 to 100",
            ));
        }
    }
    let (provider, relative) = git_provider(repository, roots)?;
    let relative = relative.as_str();
    let result = match action {
        GitAction::Status => provider.status(relative),
        GitAction::Diff { staged } => provider.diff(relative, staged),
        GitAction::Log { max_count } => provider.log(relative, max_count),
        GitAction::Add { paths } => provider
            .path_state(relative, paths)
            .and_then(|state| provider.stage(relative, paths, &state)),
        GitAction::Unstage { paths } => provider
            .unstage_state(relative, paths)
            .and_then(|state| provider.unstage(relative, paths, &state)),
        GitAction::Commit { message } => provider
            .staged_state(relative)
            .and_then(|state| provider.commit(relative, message, &state)),
        GitAction::BranchCreate { branch } => provider
            .branch_state(relative)
            .and_then(|state| provider.create_branch(relative, branch, &state)),
    };
    result.map_err(git_error)
}
