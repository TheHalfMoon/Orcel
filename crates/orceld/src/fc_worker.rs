//! SG-000132 WP1-10: `orceld fc-worker`, the child process that performs a
//! Full Control filesystem, process or git operation inside the dispatch's
//! service-made Job Object, so the long-lived orceld never performs it in
//! its own process.
//!
//! Launch (Windows, [`JobLauncher`]): `Authorize` duplicated an assign-only
//! handle to the dispatch's unnamed job into this process. orceld starts its
//! own image as `orceld fc-worker` suspended, with inheritance limited to
//! the worker's stdin, stdout and a `NUL` stderr, assigns it to the job with
//! that handle, closes the handle, asks the service `DispatchActive` (a
//! revoke, Stop or expiry since `Authorize` refuses: the worker is
//! terminated without having run), and only then resumes it. Jobs have no
//! names, so nothing can be pre-created, squatted or reopened by name.
//!
//! IPC: one JSON request on the worker's stdin and one JSON reply on its
//! stdout, both anonymous pipes. There is no listener, no named pipe and no
//! network. The request carries a per-launch random token that the reply
//! must echo, so a reply is bound to its launch. The worker refuses to act
//! unless it is in some Job Object (`IsProcessInJob` with no job handle: a
//! sanity check, not a boundary; the boundary is orceld assigning it before
//! it runs), resolves each path and the lease's roots (junctions and links
//! included) and acts only inside them, refuses any file with more than
//! one name (a hard link), and exits.
//!
//! Operations (WP1-15, SG-000097 and SG-000096): the filesystem family
//! (`stat`, `list`, `read_text`, `write_text`, `mkdir`; SG132_SLICE3.md),
//! the process family (`run`) and the git family (`git_status`, `git_diff`,
//! `git_log`, `git_add`, `git_unstage`, `git_commit`, `git_branch_create`)
//! in [`exec`] (SG132_SLICE4.md). The worker's own stdin, stdout and stderr
//! are made non-inheritable before it acts, so a program it starts (and that
//! program's descendants) can never hold orceld's reply pipe.

use crate::full_control_dispatch::Family;
use orcel_contracts::FailureCode;
use orcel_provider_fs::ProviderError;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The request and reply contract.
pub(crate) const WORKER_CONTRACT: &str = "orcel.fc-worker/1";
/// The largest request the worker reads and reply orceld reads (a git
/// diff is up to 2 MiB before JSON escaping).
pub(crate) const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
/// The most bytes `read_text` returns and `write_text` writes.
pub(crate) const MAX_TEXT_BYTES: usize = 256 * 1024;
/// The most entries `list` returns.
pub(crate) const MAX_LIST_ENTRIES: usize = 1_000;

#[path = "fc_worker_exec.rs"]
pub(crate) mod exec;

/// One Full Control filesystem, process or git operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum WorkerOp {
    Stat {
        path: String,
    },
    List {
        path: String,
        max_entries: usize,
    },
    ReadText {
        path: String,
        max_bytes: usize,
    },
    WriteText {
        path: String,
        text: String,
        create_new: bool,
    },
    Mkdir {
        path: String,
    },
    /// The process family: an absolute `.exe` inside the roots, an
    /// argument vector, a working folder inside the roots.
    Run {
        program: String,
        args: Vec<String>,
        cwd: String,
        timeout_ms: u64,
        max_output_bytes: usize,
    },
    GitStatus {
        repository: String,
    },
    GitDiff {
        repository: String,
        staged: bool,
    },
    GitLog {
        repository: String,
        max_count: usize,
    },
    GitAdd {
        repository: String,
        paths: Vec<String>,
    },
    GitUnstage {
        repository: String,
        paths: Vec<String>,
    },
    GitCommit {
        repository: String,
        message: String,
    },
    GitBranchCreate {
        repository: String,
        branch: String,
    },
}

impl WorkerOp {
    pub(crate) fn family(&self) -> Family {
        match self {
            Self::Stat { .. }
            | Self::List { .. }
            | Self::ReadText { .. }
            | Self::WriteText { .. }
            | Self::Mkdir { .. } => Family::Filesystem,
            Self::Run { .. } => Family::Process,
            Self::GitStatus { .. }
            | Self::GitDiff { .. }
            | Self::GitLog { .. }
            | Self::GitAdd { .. }
            | Self::GitUnstage { .. }
            | Self::GitCommit { .. }
            | Self::GitBranchCreate { .. } => Family::Git,
        }
    }

    /// Whether the operation needs the person's fresh per-action approval
    /// before Authorize (SG-000096 A3: every new process; git operations
    /// that change the repository), on every call: standing approvals
    /// (WP1-14) do not exist yet.
    ///
    /// Founder decision of 2026-11-19 (SG132_SLICE8.md, amending decision 2
    /// of FC_TOOL_SURFACE_OPTIONS.md for these two operations only): the
    /// Full Control file writes, `write_text` and `mkdir`, are covered by
    /// the lease the person granted with Windows Hello and ask nothing per
    /// call; their roots, link and `.git` checks, the service's
    /// audit-first `Authorize` and the dispatch job still apply. Reads
    /// (filesystem and git) ask nothing, like the Safe-mode read tools.
    ///
    /// The match is exhaustive on purpose: a new operation (a delete, a
    /// move) does not compile until someone decides whether it asks.
    pub(crate) fn needs_approval(&self) -> bool {
        match self {
            Self::Run { .. }
            | Self::GitAdd { .. }
            | Self::GitUnstage { .. }
            | Self::GitCommit { .. }
            | Self::GitBranchCreate { .. } => true,
            // Founder amendment of 2026-11-19: lease-covered file writes.
            Self::WriteText { .. } | Self::Mkdir { .. } => false,
            // Reads.
            Self::Stat { .. }
            | Self::List { .. }
            | Self::ReadText { .. }
            | Self::GitStatus { .. }
            | Self::GitDiff { .. }
            | Self::GitLog { .. } => false,
        }
    }

    /// SG132_SLICE8.md: the operation's own argument bounds, the same
    /// rules the worker and the Git provider apply, checked by orceld
    /// before the person is asked, so a malformed request never costs a
    /// prompt (`INVALID_REQUEST`; an oversized write is `OUTPUT_LIMIT`, as
    /// in the worker). Paths are checked by the dispatcher and the worker;
    /// nothing here reads the disk.
    pub(crate) fn check_arguments(&self) -> Result<(), ProviderError> {
        match self {
            Self::Stat { .. } | Self::Mkdir { .. } => Ok(()),
            Self::List { max_entries, .. } => {
                if *max_entries == 0 || *max_entries > MAX_LIST_ENTRIES {
                    return Err(failure(
                        FailureCode::InvalidRequest,
                        "max_entries is 1 to 1000",
                    ));
                }
                Ok(())
            }
            Self::ReadText { max_bytes, .. } => {
                if *max_bytes == 0 || *max_bytes > MAX_TEXT_BYTES {
                    return Err(failure(
                        FailureCode::InvalidRequest,
                        "max_bytes is 1 to 262144",
                    ));
                }
                Ok(())
            }
            Self::WriteText { text, .. } => {
                if text.len() > MAX_TEXT_BYTES {
                    return Err(failure(
                        FailureCode::OutputLimit,
                        "write_text writes at most 262144 bytes",
                    ));
                }
                Ok(())
            }
            Self::Run {
                program,
                args,
                timeout_ms,
                max_output_bytes,
                ..
            } => exec::check_run_arguments(program, args, *timeout_ms, *max_output_bytes),
            Self::GitStatus { .. } | Self::GitDiff { .. } => Ok(()),
            Self::GitLog { max_count, .. } => {
                if *max_count == 0 || *max_count > exec::MAX_GIT_LOG {
                    return Err(failure(
                        FailureCode::InvalidRequest,
                        "max_count is 1 to 100",
                    ));
                }
                Ok(())
            }
            Self::GitAdd { paths, .. } | Self::GitUnstage { paths, .. } => {
                orcel_provider_git::validate_mutation_paths(paths)
                    .map(|_| ())
                    .map_err(exec::git_error)
            }
            Self::GitCommit { message, .. } => {
                orcel_provider_git::validate_commit_message(message).map_err(exec::git_error)
            }
            Self::GitBranchCreate { branch, .. } => {
                orcel_provider_git::validate_branch_input(branch).map_err(exec::git_error)
            }
        }
    }

    /// The operation's name, as the request's `operation` must state it.
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::Stat { .. } => "stat",
            Self::List { .. } => "list",
            Self::ReadText { .. } => "read_text",
            Self::WriteText { .. } => "write_text",
            Self::Mkdir { .. } => "mkdir",
            Self::Run { .. } => "run",
            Self::GitStatus { .. } => "git_status",
            Self::GitDiff { .. } => "git_diff",
            Self::GitLog { .. } => "git_log",
            Self::GitAdd { .. } => "git_add",
            Self::GitUnstage { .. } => "git_unstage",
            Self::GitCommit { .. } => "git_commit",
            Self::GitBranchCreate { .. } => "git_branch_create",
        }
    }

    /// The paths the operation touches (checked against the roots by the
    /// dispatcher, the service and the worker): the path, the working
    /// folder and the program of a run, the repository of a git operation.
    pub(crate) fn paths(&self) -> Vec<String> {
        match self {
            Self::Stat { path }
            | Self::List { path, .. }
            | Self::ReadText { path, .. }
            | Self::WriteText { path, .. }
            | Self::Mkdir { path } => vec![path.clone()],
            Self::Run { program, cwd, .. } => vec![cwd.clone(), program.clone()],
            Self::GitStatus { repository }
            | Self::GitDiff { repository, .. }
            | Self::GitLog { repository, .. }
            | Self::GitAdd { repository, .. }
            | Self::GitUnstage { repository, .. }
            | Self::GitCommit { repository, .. }
            | Self::GitBranchCreate { repository, .. } => vec![repository.clone()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerRequest {
    pub contract: String,
    pub token: String,
    pub roots: Vec<String>,
    pub op: WorkerOp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerReply {
    pub contract: String,
    pub token: String,
    pub ok: bool,
    #[serde(default)]
    pub result: Value,
    #[serde(default)]
    pub code: Option<FailureCode>,
    #[serde(default)]
    pub message: Option<String>,
}

impl WorkerReply {
    /// The result, or the worker's error. A reply for another launch is
    /// refused.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn into_result(self, token: &str) -> Result<Value, ProviderError> {
        if self.contract != WORKER_CONTRACT || self.token != token {
            return Err(ProviderError::new(
                FailureCode::InternalError,
                "the fc-worker reply does not belong to this launch",
            ));
        }
        if self.ok {
            Ok(self.result)
        } else {
            Err(ProviderError::new(
                self.code.unwrap_or(FailureCode::InternalError),
                self.message.unwrap_or_default(),
            ))
        }
    }
}

fn failure(code: FailureCode, message: impl Into<String>) -> ProviderError {
    ProviderError::new(code, message)
}

fn io_failure(context: &str, error: &std::io::Error) -> ProviderError {
    failure(
        FailureCode::ProviderUnavailable,
        format!("{context}: {error}"),
    )
}

/// The lease's roots that exist, resolved.
fn resolved_roots(roots: &[String]) -> Vec<PathBuf> {
    roots
        .iter()
        .filter_map(|root| std::fs::canonicalize(root).ok())
        .collect()
}

fn inside(path: &Path, roots: &[PathBuf]) -> Result<(), ProviderError> {
    if roots.iter().any(|root| path.starts_with(root)) {
        Ok(())
    } else {
        Err(failure(
            FailureCode::PathEscape,
            "the resolved path lies outside the lease's roots",
        ))
    }
}

fn lexical(path: &str, roots: &[String]) -> Result<(), ProviderError> {
    orcel_authority::lease::check_dispatch_path(path)
        .map_err(|error| failure(error.code, error.message))?;
    if !orcel_authority::lease::path_within_roots(path, roots) {
        return Err(failure(
            FailureCode::PathEscape,
            "the path lies outside the lease's roots",
        ));
    }
    Ok(())
}

/// An existing path, resolved, inside the resolved roots.
fn existing(path: &str, roots: &[String]) -> Result<PathBuf, ProviderError> {
    lexical(path, roots)?;
    let resolved =
        std::fs::canonicalize(path).map_err(|error| io_failure("resolve the path", &error))?;
    inside(&resolved, &resolved_roots(roots))?;
    Ok(resolved)
}

/// A path to create: its parent resolved inside the roots, the name plain,
/// and no link or junction already at the name.
fn creatable(path: &str, roots: &[String]) -> Result<PathBuf, ProviderError> {
    lexical(path, roots)?;
    let target = Path::new(path);
    let (Some(parent), Some(name)) = (target.parent(), target.file_name()) else {
        return Err(failure(
            FailureCode::InvalidRequest,
            "the path names no entry to create",
        ));
    };
    let parent =
        std::fs::canonicalize(parent).map_err(|error| io_failure("resolve the parent", &error))?;
    inside(&parent, &resolved_roots(roots))?;
    let resolved = parent.join(name);
    // Review of #824: a Git repository's own folder (its configuration,
    // hooks and pointers) is never written or created through Full
    // Control's filesystem operations, so they cannot plant a hook or a
    // configuration Git would follow. The names are resolved, so a short
    // name (`GIT~1`) of the parent arrives here as `.git`.
    // An existing entry is resolved too, so a short name (`GIT~1`) for an
    // existing `.git` file is caught as well.
    let existing_name = std::fs::canonicalize(&resolved).ok();
    if std::iter::once(&resolved)
        .chain(existing_name.as_ref())
        .flat_map(|path| path.components())
        .any(|component| component.as_os_str().eq_ignore_ascii_case(".git"))
    {
        return Err(failure(
            FailureCode::CapabilityDenied,
            "Full Control does not write inside a .git folder or create a .git entry",
        ));
    }
    if let Ok(metadata) = std::fs::symlink_metadata(&resolved) {
        if metadata.file_type().is_symlink() {
            return Err(failure(
                FailureCode::PathEscape,
                "the path is a link or junction",
            ));
        }
    }
    Ok(resolved)
}

fn kind(file_type: std::fs::FileType) -> &'static str {
    if file_type.is_symlink() {
        "link"
    } else if file_type.is_dir() {
        "dir"
    } else if file_type.is_file() {
        "file"
    } else {
        "other"
    }
}

/// How many names (hard links) the open file has.
#[cfg(windows)]
fn link_count(file: &std::fs::File) -> Result<u32, ProviderError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };
    // SAFETY: a zeroed BY_HANDLE_FILE_INFORMATION is a valid out-parameter.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: an open file handle and a live out-parameter.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, &mut info) } == 0 {
        return Err(io_failure(
            "read the file's link count",
            &std::io::Error::last_os_error(),
        ));
    }
    Ok(info.nNumberOfLinks)
}

#[cfg(unix)]
fn link_count(file: &std::fs::File) -> Result<u32, ProviderError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file
        .metadata()
        .map_err(|error| io_failure("read the file's link count", &error))?;
    Ok(u32::try_from(metadata.nlink()).unwrap_or(u32::MAX))
}

/// A hard link inside the roots can name a file outside them, so a file
/// with more than one name is never read, written or described.
fn refuse_hard_links(file: &std::fs::File) -> Result<(), ProviderError> {
    if link_count(file)? > 1 {
        return Err(failure(
            FailureCode::PathEscape,
            "the file has more than one name (a hard link); it is not used",
        ));
    }
    Ok(())
}

/// Performs one operation inside `roots`.
pub(crate) fn perform(op: &WorkerOp, roots: &[String]) -> Result<Value, ProviderError> {
    match op {
        WorkerOp::Stat { path } => {
            let resolved = existing(path, roots)?;
            let metadata = std::fs::metadata(&resolved)
                .map_err(|error| io_failure("read the metadata", &error))?;
            if metadata.is_file() {
                let file = std::fs::File::open(&resolved)
                    .map_err(|error| io_failure("open the file", &error))?;
                refuse_hard_links(&file)?;
            }
            Ok(json!({
                "kind": kind(metadata.file_type()),
                "len": metadata.len(),
                "readonly": metadata.permissions().readonly(),
            }))
        }
        WorkerOp::List { path, max_entries } => {
            if *max_entries == 0 || *max_entries > MAX_LIST_ENTRIES {
                return Err(failure(
                    FailureCode::InvalidRequest,
                    "max_entries is 1 to 1000",
                ));
            }
            let resolved = existing(path, roots)?;
            let mut entries = Vec::new();
            let reader = std::fs::read_dir(&resolved)
                .map_err(|error| io_failure("list the folder", &error))?;
            for entry in reader {
                let entry = entry.map_err(|error| io_failure("read an entry", &error))?;
                let file_type = entry
                    .file_type()
                    .map_err(|error| io_failure("read an entry's type", &error))?;
                entries.push((
                    entry.file_name().to_string_lossy().into_owned(),
                    kind(file_type),
                ));
            }
            entries.sort();
            let truncated = entries.len() > *max_entries;
            entries.truncate(*max_entries);
            let entries: Vec<Value> = entries
                .into_iter()
                .map(|(name, kind)| json!({ "name": name, "kind": kind }))
                .collect();
            Ok(json!({ "entries": entries, "truncated": truncated }))
        }
        WorkerOp::ReadText { path, max_bytes } => {
            if *max_bytes == 0 || *max_bytes > MAX_TEXT_BYTES {
                return Err(failure(
                    FailureCode::InvalidRequest,
                    "max_bytes is 1 to 262144",
                ));
            }
            let resolved = existing(path, roots)?;
            let file = std::fs::File::open(&resolved)
                .map_err(|error| io_failure("open the file", &error))?;
            refuse_hard_links(&file)?;
            let mut bytes = Vec::new();
            file.take(*max_bytes as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| io_failure("read the file", &error))?;
            let truncated = bytes.len() > *max_bytes;
            bytes.truncate(*max_bytes);
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(error) if truncated && error.utf8_error().error_len().is_none() => {
                    let valid = error.utf8_error().valid_up_to();
                    let mut bytes = error.into_bytes();
                    bytes.truncate(valid);
                    String::from_utf8(bytes).map_err(|_| {
                        failure(FailureCode::InvalidRequest, "the file is not UTF-8 text")
                    })?
                }
                Err(_) => {
                    return Err(failure(
                        FailureCode::InvalidRequest,
                        "the file is not UTF-8 text",
                    ))
                }
            };
            Ok(json!({ "text": text, "truncated": truncated }))
        }
        WorkerOp::WriteText {
            path,
            text,
            create_new,
        } => {
            if text.len() > MAX_TEXT_BYTES {
                return Err(failure(
                    FailureCode::OutputLimit,
                    "write_text writes at most 262144 bytes",
                ));
            }
            let resolved = creatable(path, roots)?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true);
            if *create_new {
                options.create_new(true);
            } else {
                // Not truncated on open: the link count is checked first.
                options.create(true).truncate(false);
            }
            let mut file = options
                .open(&resolved)
                .map_err(|error| io_failure("open the file for writing", &error))?;
            // Review: a hard link inside the roots can name a file outside
            // them; a file with more than one name is never written.
            refuse_hard_links(&file)?;
            file.set_len(0)
                .map_err(|error| io_failure("truncate the file", &error))?;
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|error| io_failure("write the file", &error))?;
            Ok(json!({ "bytes": text.len() }))
        }
        WorkerOp::Mkdir { path } => {
            let resolved = creatable(path, roots)?;
            std::fs::create_dir(&resolved)
                .map_err(|error| io_failure("create the folder", &error))?;
            Ok(json!({ "created": true }))
        }
        WorkerOp::Run {
            program,
            args,
            cwd,
            timeout_ms,
            max_output_bytes,
        } => exec::run_program(program, args, cwd, *timeout_ms, *max_output_bytes, roots),
        WorkerOp::GitStatus { repository } => {
            exec::run_git(repository, exec::GitAction::Status, roots)
        }
        WorkerOp::GitDiff { repository, staged } => {
            exec::run_git(repository, exec::GitAction::Diff { staged: *staged }, roots)
        }
        WorkerOp::GitLog {
            repository,
            max_count,
        } => exec::run_git(
            repository,
            exec::GitAction::Log {
                max_count: *max_count,
            },
            roots,
        ),
        WorkerOp::GitAdd { repository, paths } => {
            exec::run_git(repository, exec::GitAction::Add { paths }, roots)
        }
        WorkerOp::GitUnstage { repository, paths } => {
            exec::run_git(repository, exec::GitAction::Unstage { paths }, roots)
        }
        WorkerOp::GitCommit {
            repository,
            message,
        } => exec::run_git(repository, exec::GitAction::Commit { message }, roots),
        WorkerOp::GitBranchCreate { repository, branch } => {
            exec::run_git(repository, exec::GitAction::BranchCreate { branch }, roots)
        }
    }
}

/// Whether this process runs inside a Job Object.
#[cfg(windows)]
fn in_a_job() -> bool {
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    let mut result = 0;
    // SAFETY: the pseudo handle needs no closing; NULL asks about any job.
    unsafe { IsProcessInJob(GetCurrentProcess(), 0, &mut result) != 0 && result != 0 }
}

#[cfg(not(windows))]
fn in_a_job() -> bool {
    false
}

/// Serves one request read from `input`, writing one reply to `output`.
/// Returns the exit code.
pub(crate) fn serve(input: &mut impl Read, output: &mut impl Write, in_job: bool) -> i32 {
    let mut bytes = Vec::new();
    let read = input
        .take(MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes);
    let request: Result<WorkerRequest, String> = match read {
        Ok(_) if bytes.len() > MAX_FRAME_BYTES => Err("the request is too large".to_owned()),
        Ok(_) => serde_json::from_slice(&bytes).map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    let request = match request {
        Ok(request) if request.contract == WORKER_CONTRACT => request,
        Ok(_) => {
            let _ = writeln!(output, "{}", json!({"error": "unknown contract"}));
            return 2;
        }
        Err(error) => {
            let _ = writeln!(output, "{}", json!({"error": error}));
            return 2;
        }
    };
    let result = if in_job {
        perform(&request.op, &request.roots)
    } else {
        Err(failure(
            FailureCode::CapabilityDenied,
            "fc-worker acts only inside a Job Object",
        ))
    };
    let reply = match &result {
        Ok(value) => WorkerReply {
            contract: WORKER_CONTRACT.to_owned(),
            token: request.token.clone(),
            ok: true,
            result: value.clone(),
            code: None,
            message: None,
        },
        Err(error) => WorkerReply {
            contract: WORKER_CONTRACT.to_owned(),
            token: request.token.clone(),
            ok: false,
            result: Value::Null,
            code: Some(error.code.clone()),
            message: Some(error.message.clone()),
        },
    };
    let (encoded, result) = match serde_json::to_string(&reply) {
        Ok(line) if line.len() >= MAX_FRAME_BYTES => {
            let limit = failure(
                FailureCode::OutputLimit,
                "the operation's result exceeds the worker's reply limit",
            );
            let reply = WorkerReply {
                contract: WORKER_CONTRACT.to_owned(),
                token: request.token.clone(),
                ok: false,
                result: Value::Null,
                code: Some(limit.code.clone()),
                message: Some(limit.message.clone()),
            };
            (serde_json::to_string(&reply), Err(limit))
        }
        other => (other, result),
    };
    let written = encoded
        .map_err(|error| std::io::Error::other(error.to_string()))
        .and_then(|line| writeln!(output, "{line}"))
        .and_then(|()| output.flush());
    match (written, result) {
        (Err(_), _) => 2,
        (Ok(()), Ok(_)) => 0,
        (Ok(()), Err(_)) => 1,
    }
}

/// `orceld fc-worker`. `None` when `args` is not that command.
pub(crate) fn run_cli(args: &[String]) -> Option<i32> {
    if args.first().map(String::as_str) != Some("fc-worker") {
        return None;
    }
    if args.len() != 1 {
        eprintln!("usage: orceld fc-worker (started by orceld inside a Job Object)");
        return Some(2);
    }
    keep_standard_handles_private();
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    Some(serve(&mut stdin.lock(), &mut stdout.lock(), in_a_job()))
}

/// Makes the worker's stdin, stdout and stderr non-inheritable, so a
/// program the worker starts never inherits orceld's request or reply pipe
/// (the standard library makes its own child pipes inheritable only for the
/// child they belong to).
#[cfg(windows)]
fn keep_standard_handles_private() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    for handle in [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ] {
        if handle.is_null() {
            continue;
        }
        // SAFETY: this process's own standard handle; clearing its inherit
        // flag changes nothing else about it (an invalid value just fails).
        unsafe { SetHandleInformation(handle as _, HANDLE_FLAG_INHERIT, 0) };
    }
}

#[cfg(not(windows))]
fn keep_standard_handles_private() {}

#[cfg(windows)]
#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use launch::JobLauncher;
#[cfg(windows)]
pub(crate) use launch::{start_suspended_in_job, Launch};

#[cfg(windows)]
#[cfg_attr(not(test), allow(dead_code))]
mod launch {
    use super::{WorkerOp, WorkerReply, WorkerRequest, MAX_FRAME_BYTES, WORKER_CONTRACT};
    use crate::full_control_dispatch::{JobGrant, WorkerLauncher};
    use orcel_authority::core::Entropy;
    use orcel_authority::win::Owned;
    use orcel_contracts::FailureCode;
    use orcel_provider_fs::ProviderError;
    use serde_json::Value;
    use std::ffi::{c_void, OsString};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::path::{Path, PathBuf};
    use std::ptr;
    use std::time::Duration;
    use windows_sys::Win32::Foundation::{
        SetHandleInformation, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    /// How long one worker operation may run.
    pub(crate) const WORKER_TIMEOUT: Duration = Duration::from_secs(60);

    fn platform(context: &str) -> ProviderError {
        ProviderError::new(
            FailureCode::ProviderUnavailable,
            format!("{context}: {}", std::io::Error::last_os_error()),
        )
    }

    fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
        text.encode_wide().chain(Some(0)).collect()
    }

    fn owned(handle: HANDLE, context: &str) -> Result<Owned, ProviderError> {
        if handle == 0 || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(platform(context));
        }
        Ok(Owned(handle))
    }

    fn inheritable() -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        }
    }

    /// An anonymous pipe: (the child's inheritable end, orceld's end).
    fn pipe(child_reads: bool) -> Result<(Owned, Owned), ProviderError> {
        let attributes = inheritable();
        let mut read: HANDLE = 0;
        let mut write: HANDLE = 0;
        // SAFETY: valid out-pointers; the attributes outlive the call.
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(platform("CreatePipe"));
        }
        let (read, write) = (Owned(read), Owned(write));
        let (child, host) = if child_reads {
            (read, write)
        } else {
            (write, read)
        };
        // SAFETY: a valid handle; clears only orceld's end's inherit flag.
        if unsafe { SetHandleInformation(host.0, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(platform("SetHandleInformation"));
        }
        Ok((child, host))
    }

    fn null_output() -> Result<Owned, ProviderError> {
        let attributes = inheritable();
        let name = wide(std::ffi::OsStr::new("NUL"));
        // SAFETY: a NUL-terminated name and valid attributes.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                OPEN_EXISTING,
                0,
                0,
            )
        };
        owned(handle, "CreateFileW(NUL)")
    }

    struct AttributeList(Vec<u64>);

    impl AttributeList {
        fn handle_list(handles: &[HANDLE]) -> Result<Self, ProviderError> {
            let mut size = 0usize;
            // SAFETY: a size query with a null list is the documented first call.
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size) };
            if size == 0 {
                return Err(platform("InitializeProcThreadAttributeList size"));
            }
            let mut list = Self(vec![0u64; size.div_ceil(8)]);
            // SAFETY: the buffer holds `size` bytes, 8-byte aligned.
            if unsafe { InitializeProcThreadAttributeList(list.raw(), 1, 0, &mut size) } == 0 {
                list.0.clear();
                return Err(platform("InitializeProcThreadAttributeList"));
            }
            // SAFETY: `handles` outlives CreateProcessW (the caller keeps it).
            if unsafe {
                UpdateProcThreadAttribute(
                    list.raw(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    handles.as_ptr() as *const c_void,
                    std::mem::size_of_val(handles),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(platform("UpdateProcThreadAttribute(HANDLE_LIST)"));
            }
            Ok(list)
        }

        fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.0.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            if !self.0.is_empty() {
                // SAFETY: an initialized list, deleted once.
                unsafe { DeleteProcThreadAttributeList(self.raw()) };
            }
        }
    }

    /// Starts `orceld fc-worker` into dispatch jobs.
    pub(crate) struct JobLauncher {
        program: PathBuf,
        timeout: Duration,
    }

    impl JobLauncher {
        /// This orceld's own image.
        pub(crate) fn this_orceld() -> Result<Self, ProviderError> {
            let program = std::env::current_exe().map_err(|error| {
                ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    format!("orceld's own image: {error}"),
                )
            })?;
            Ok(Self::with_program(program))
        }

        /// A given orceld image (tests use the built `orceld.exe`).
        pub(crate) fn with_program(program: PathBuf) -> Self {
            Self {
                program,
                timeout: WORKER_TIMEOUT,
            }
        }

        fn token() -> Result<String, ProviderError> {
            let mut bytes = [0u8; 32];
            orcel_authority::win::crypto::SystemEntropy
                .fill(&mut bytes)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(orcel_authority::hex(&bytes))
        }

        /// Starts the worker suspended in `job` ([`start_suspended_in_job`]).
        fn start(
            &self,
            job: Owned,
            confirm: &dyn Fn() -> Result<(), ProviderError>,
        ) -> Result<(Owned, File, File), ProviderError> {
            start_suspended_in_job(
                &Launch {
                    program: &self.program,
                    arguments: "fc-worker",
                    environment: None,
                    no_window: true,
                },
                job,
                confirm,
            )
        }
    }

    /// One process start into a service-made Job Object.
    pub(crate) struct Launch<'a> {
        /// The image, started by its absolute path (no search).
        pub program: &'a Path,
        /// What follows the quoted program on the command line.
        pub arguments: &'a str,
        /// The whole environment (sorted by name here), or `None` to
        /// inherit orceld's.
        pub environment: Option<&'a [(OsString, OsString)]>,
        /// `CREATE_NO_WINDOW` (the worker); the computer host keeps
        /// orceld's console, as the standard library's start did.
        pub no_window: bool,
    }

    /// A UTF-16 environment block: `NAME=VALUE` entries sorted by name
    /// (case-insensitively), each NUL-terminated, then a final NUL.
    fn environment_block(environment: &[(OsString, OsString)]) -> Vec<u16> {
        let mut entries: Vec<&(OsString, OsString)> = environment.iter().collect();
        entries.sort_by_key(|(name, _)| name.to_string_lossy().to_uppercase());
        let mut block = Vec::new();
        for (name, value) in entries {
            block.extend(name.encode_wide());
            block.push(u16::from(b'='));
            block.extend(value.encode_wide());
            block.push(0);
        }
        if block.is_empty() {
            block.push(0);
        }
        block.push(0);
        block
    }

    /// Starts `launch` suspended (inheritance limited by
    /// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST` to its stdin, stdout and a `NUL`
    /// stderr), assigns it to `job`, closes the job handle, asks `confirm`,
    /// and resumes it only if that succeeds (terminating it otherwise).
    /// Returns the process and orceld's ends of its stdin and stdout.
    /// Used for `orceld fc-worker` (one dispatch) and, SG132_SLICE5.md, for
    /// the computer host (one lease).
    pub(crate) fn start_suspended_in_job(
        launch: &Launch<'_>,
        job: Owned,
        confirm: &dyn Fn() -> Result<(), ProviderError>,
    ) -> Result<(Owned, File, File), ProviderError> {
        let (child_stdin, host_stdin) = pipe(true)?;
        let (child_stdout, host_stdout) = pipe(false)?;
        let child_stderr = null_output()?;
        let inherited = [child_stdin.0, child_stdout.0, child_stderr.0];
        let mut attributes = AttributeList::handle_list(&inherited)?;
        let program = launch.program.as_os_str();
        let mut command: Vec<u16> =
            format!("\"{}\" {}", program.to_string_lossy(), launch.arguments)
                .trim_end()
                .encode_utf16()
                .chain(Some(0))
                .collect();
        let application = wide(program);
        let environment = launch.environment.map(environment_block);
        let mut flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED;
        if launch.no_window {
            flags |= CREATE_NO_WINDOW;
        }
        if environment.is_some() {
            flags |= CREATE_UNICODE_ENVIRONMENT;
        }
        // SAFETY: a zeroed STARTUPINFOEXW is valid before the fields are set.
        let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = child_stdin.0;
        startup.StartupInfo.hStdOutput = child_stdout.0;
        startup.StartupInfo.hStdError = child_stderr.0;
        startup.lpAttributeList = attributes.raw();
        // SAFETY: a zeroed PROCESS_INFORMATION is a valid out-parameter.
        let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: every buffer is NUL-terminated and outlives the call (the
        // environment block ends with two NULs); inheritance is limited to
        // `inherited`, which is alive.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                flags,
                environment
                    .as_ref()
                    .map_or(ptr::null(), |block| block.as_ptr() as *const c_void),
                ptr::null(),
                &startup.StartupInfo,
                &mut info,
            )
        };
        drop(attributes);
        if created == 0 {
            return Err(platform("CreateProcessW(suspended, for a Job Object)"));
        }
        let process = Owned(info.hProcess);
        let thread = Owned(info.hThread);
        drop((child_stdin, child_stdout, child_stderr));
        // SAFETY: valid handles; the process is still suspended.
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            let error = platform("AssignProcessToJobObject");
            // SAFETY: the suspended process's own handle.
            unsafe { TerminateProcess(process.0, 1) };
            return Err(error);
        }
        // Only the service holds the job from here on.
        drop(job);
        // Review of 291e045e: the process is in the job but has not run; it
        // runs only if the authorization still stands now. A revoke, Stop or
        // expiry from here on terminates the job, process included.
        if let Err(error) = confirm() {
            // SAFETY: the suspended process's own handle.
            unsafe { TerminateProcess(process.0, 1) };
            return Err(error);
        }
        // SAFETY: the suspended process's primary thread.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = platform("ResumeThread");
            // SAFETY: the process's own handle.
            unsafe { TerminateProcess(process.0, 1) };
            return Err(error);
        }
        // SAFETY: orceld's ends are owned here and move into `File`.
        let stdin = unsafe { File::from_raw_handle(host_stdin.0 as _) };
        std::mem::forget(host_stdin);
        // SAFETY: as above.
        let stdout = unsafe { File::from_raw_handle(host_stdout.0 as _) };
        std::mem::forget(host_stdout);
        Ok((process, stdin, stdout))
    }

    impl WorkerLauncher for JobLauncher {
        fn run(
            &self,
            job: &JobGrant,
            roots: &[String],
            op: &WorkerOp,
            confirm: &dyn Fn() -> Result<(), ProviderError>,
        ) -> Result<Value, ProviderError> {
            // The assign-only handle the service duplicated into this
            // process for this dispatch: owned from here, closed on every
            // path.
            let job = Owned(job.handle as HANDLE);
            let token = Self::token()?;
            let request = serde_json::to_vec(&WorkerRequest {
                contract: WORKER_CONTRACT.to_owned(),
                token: token.clone(),
                roots: roots.to_vec(),
                op: op.clone(),
            })
            .map_err(|error| ProviderError::new(FailureCode::InternalError, error.to_string()))?;
            let (process, mut stdin, stdout) = self.start(job, confirm)?;
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let read = stdout
                    .take(MAX_FRAME_BYTES as u64 + 1)
                    .read_to_end(&mut bytes);
                let _ = sender.send(read.map(|_| bytes));
            });
            let written = stdin.write_all(&request).and_then(|()| stdin.flush());
            drop(stdin);
            let millis = u32::try_from(self.timeout.as_millis()).unwrap_or(u32::MAX - 1);
            // SAFETY: a valid process handle.
            let exited = unsafe { WaitForSingleObject(process.0, millis) } == WAIT_OBJECT_0;
            if !exited {
                // SAFETY: the worker's own handle; the service ends its job
                // with the outcome as well.
                unsafe { TerminateProcess(process.0, 1) };
                return Err(ProviderError::new(
                    FailureCode::ProcessTimeout,
                    "the fc-worker operation did not finish in time and was ended",
                ));
            }
            written.map_err(|error| {
                ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    format!("send the fc-worker request: {error}"),
                )
            })?;
            let bytes = receiver
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| {
                    ProviderError::new(
                        FailureCode::ProviderUnavailable,
                        "the fc-worker reply did not arrive",
                    )
                })?
                .map_err(|error| {
                    ProviderError::new(
                        FailureCode::ProviderUnavailable,
                        format!("read the fc-worker reply: {error}"),
                    )
                })?;
            if bytes.len() > MAX_FRAME_BYTES {
                return Err(ProviderError::new(
                    FailureCode::OutputLimit,
                    "the fc-worker reply is too large",
                ));
            }
            let line = String::from_utf8_lossy(&bytes);
            let reply: WorkerReply = serde_json::from_str(line.trim()).map_err(|error| {
                ProviderError::new(
                    FailureCode::ProviderUnavailable,
                    format!("a malformed fc-worker reply: {error}"),
                )
            })?;
            reply.into_result(&token)
        }
    }
}
