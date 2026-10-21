pub mod fetch;
mod mutation;
pub mod push;

pub use fetch::{
    destination_ref, parse_destination, source_ref, ApprovedFetch, FetchPreview,
    GitFetchDestination, SystemResolver,
};
pub use mutation::GitMutationState;

use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_STDOUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_STDERR_BYTES: usize = 128 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct GitProviderError {
    pub code: FailureCode,
    pub message: String,
}

impl GitProviderError {
    fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GitProvider {
    workspace_root: PathBuf,
}

#[derive(Debug)]
struct CommandOutput {
    stdout: String,
    stdout_truncated: bool,
}

impl GitProvider {
    pub fn new(workspace_root: impl AsRef<Path>) -> Result<Self, GitProviderError> {
        let root = std::fs::canonicalize(workspace_root.as_ref()).map_err(|error| {
            GitProviderError::new(
                FailureCode::WorkspaceDenied,
                format!("resolve Git workspace root: {error}"),
            )
        })?;
        if !root.is_dir() {
            return Err(GitProviderError::new(
                FailureCode::WorkspaceDenied,
                "Git workspace root is not a directory",
            ));
        }
        Ok(Self {
            workspace_root: root,
        })
    }

    pub fn status(&self, relative: &str) -> Result<Value, GitProviderError> {
        let repo = self.repository_root(relative)?;
        let output = self.run_git(
            &repo,
            &[
                "status",
                "--porcelain=v2",
                "--branch",
                "--untracked-files=all",
            ],
        )?;
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "porcelain_v2": output.stdout,
            "truncated": output.stdout_truncated
        }))
    }

    pub fn diff(&self, relative: &str, staged: bool) -> Result<Value, GitProviderError> {
        let repo = self.repository_root(relative)?;
        let mut args = vec![
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--unified=3",
        ];
        if staged {
            args.push("--cached");
        }
        let output = self.run_git(&repo, &args)?;
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "staged": staged,
            "diff": output.stdout,
            "truncated": output.stdout_truncated
        }))
    }

    pub fn log(&self, relative: &str, max_count: usize) -> Result<Value, GitProviderError> {
        let repo = self.repository_root(relative)?;
        let count = max_count.clamp(1, 100);
        let count_arg = format!("--max-count={count}");
        let args = [
            "log",
            count_arg.as_str(),
            "--date=iso-strict",
            "--format=%H%x09%h%x09%an%x09%aI%x09%s",
            "--no-decorate",
        ];
        let output = self.run_git(&repo, &args)?;
        let commits: Vec<Value> = output
            .stdout
            .lines()
            .filter_map(|line| {
                let mut fields = line.splitn(5, '\t');
                Some(json!({
                    "sha": fields.next()?,
                    "short_sha": fields.next()?,
                    "author": fields.next()?,
                    "authored_at": fields.next()?,
                    "subject": fields.next()?
                }))
            })
            .collect();
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "commits": commits,
            "truncated": output.stdout_truncated
        }))
    }

    fn repository_root(&self, relative: &str) -> Result<PathBuf, GitProviderError> {
        let candidate =
            std::fs::canonicalize(self.workspace_root.join(relative)).map_err(|error| {
                GitProviderError::new(
                    FailureCode::InvalidRequest,
                    format!("resolve Git target: {error}"),
                )
            })?;
        self.ensure_within(&candidate)?;
        if !candidate.is_dir() {
            return Err(GitProviderError::new(
                FailureCode::InvalidRequest,
                "Git target is not a directory",
            ));
        }

        let output = self.run_git_raw(&candidate, &["rev-parse", "--show-toplevel"])?;
        let reported = output.stdout.trim();
        if reported.is_empty() {
            return Err(GitProviderError::new(
                FailureCode::InvalidRequest,
                "Git did not report a repository root",
            ));
        }
        let repo = std::fs::canonicalize(reported).map_err(|error| {
            GitProviderError::new(
                FailureCode::InvalidRequest,
                format!("resolve reported repository root: {error}"),
            )
        })?;
        self.ensure_within(&repo)?;
        Ok(repo)
    }

    fn ensure_within(&self, candidate: &Path) -> Result<(), GitProviderError> {
        if candidate != self.workspace_root && !candidate.starts_with(&self.workspace_root) {
            return Err(GitProviderError::new(
                FailureCode::PathEscape,
                "Git target resolves outside the trusted workspace",
            ));
        }
        Ok(())
    }

    fn relative_display(&self, path: &Path) -> String {
        path.strip_prefix(&self.workspace_root)
            .unwrap_or(path)
            .to_string_lossy()
            .to_string()
    }

    fn run_git(&self, repo: &Path, args: &[&str]) -> Result<CommandOutput, GitProviderError> {
        self.run_git_raw(repo, args)
    }

    fn run_git_raw(&self, cwd: &Path, args: &[&str]) -> Result<CommandOutput, GitProviderError> {
        let mut command = Command::new("git");
        command
            .args(["-c", "core.fsmonitor=false", "-c", "core.pager=cat"])
            .args(args)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();

        copy_env_if_present(&mut command, "PATH");
        copy_env_if_present(&mut command, "Path");
        copy_env_if_present(&mut command, "PATHEXT");
        copy_env_if_present(&mut command, "SystemRoot");
        copy_env_if_present(&mut command, "WINDIR");
        copy_env_if_present(&mut command, "TEMP");
        copy_env_if_present(&mut command, "TMP");

        command
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_PAGER", "cat")
            .env("GIT_EDITOR", null_device())
            .env("GIT_SEQUENCE_EDITOR", null_device())
            .env("GIT_ALLOW_PROTOCOL", "")
            .env("GCM_INTERACTIVE", "Never")
            .env("GIT_OPTIONAL_LOCKS", "0");

        let mut child = command.spawn().map_err(|error| {
            GitProviderError::new(
                FailureCode::ProviderUnavailable,
                format!("start git: {error}"),
            )
        })?;

        let stdout = child.stdout.take().ok_or_else(|| {
            GitProviderError::new(FailureCode::ProviderUnavailable, "git stdout unavailable")
        })?;
        let stderr = child.stderr.take().ok_or_else(|| {
            GitProviderError::new(FailureCode::ProviderUnavailable, "git stderr unavailable")
        })?;

        let stdout_thread = thread::spawn(move || read_bounded(stdout, MAX_STDOUT_BYTES));
        let stderr_thread = thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES));

        let deadline = Instant::now() + COMMAND_TIMEOUT;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(25));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(GitProviderError::new(
                        FailureCode::ProviderUnavailable,
                        "git command exceeded 30 second timeout",
                    ));
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_thread.join();
                    let _ = stderr_thread.join();
                    return Err(GitProviderError::new(
                        FailureCode::ProviderUnavailable,
                        format!("wait for git: {error}"),
                    ));
                }
            }
        };

        let (stdout_bytes, stdout_truncated) = stdout_thread.join().map_err(|_| {
            GitProviderError::new(FailureCode::InternalError, "git stdout reader panicked")
        })??;
        let (stderr_bytes, _stderr_truncated) = stderr_thread.join().map_err(|_| {
            GitProviderError::new(FailureCode::InternalError, "git stderr reader panicked")
        })??;

        let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();

        if !status.success() {
            return Err(GitProviderError::new(
                FailureCode::InvalidRequest,
                format!(
                    "git exited with {}: {}",
                    status
                        .code()
                        .map_or_else(|| "signal".into(), |code| code.to_string()),
                    stderr.trim()
                ),
            ));
        }

        Ok(CommandOutput {
            stdout,
            stdout_truncated,
        })
    }
}

fn read_bounded(reader: impl Read, max_bytes: usize) -> Result<(Vec<u8>, bool), GitProviderError> {
    read_bounded_inner(reader, max_bytes)
}

pub(crate) fn read_bounded_for_fetch(
    reader: impl Read,
) -> Result<(Vec<u8>, bool), GitProviderError> {
    read_bounded_inner(reader, MAX_STDOUT_BYTES)
}

fn read_bounded_inner(
    mut reader: impl Read,
    max_bytes: usize,
) -> Result<(Vec<u8>, bool), GitProviderError> {
    let mut kept = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut buffer = [0u8; 16 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).map_err(|error| {
            GitProviderError::new(
                FailureCode::ProviderUnavailable,
                format!("read git output: {error}"),
            )
        })?;
        if count == 0 {
            break;
        }
        if kept.len() < max_bytes {
            let remaining = max_bytes - kept.len();
            let take = remaining.min(count);
            kept.extend_from_slice(&buffer[..take]);
            if take < count {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((kept, truncated))
}

fn copy_env_if_present(command: &mut Command, name: &str) {
    if let Some(value) = std::env::var_os(name) {
        command.env(name, value);
    }
}

/// Value for `GIT_CONFIG_GLOBAL` that makes git read no global config. Git
/// for Windows maps `/dev/null` to the null device for files it opens itself,
/// and 2.56 rejects `NUL` here. Use it only for config: commands such as
/// `GIT_EDITOR` and files opened by libcurl do not get that mapping.
pub(crate) const NULL_GIT_CONFIG: &str = "/dev/null";

/// Null device for editor/ssh commands, which must never resolve to a file
/// that could be created (`/dev/null` would resolve to `\dev\null` on the
/// current drive).
#[cfg(windows)]
fn null_device() -> OsString {
    OsString::from("NUL")
}

#[cfg(not(windows))]
fn null_device() -> OsString {
    OsString::from("/dev/null")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn temp_root(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let suffix = format!("{suffix}-{}", next_temp_sequence());
        let root = std::env::temp_dir().join(format!("orcel-git-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp root");
        root
    }

    fn git(cwd: &Path, args: &[&str]) {
        let status = Command::new("git")
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
            .status()
            .expect("start git test helper");
        assert!(status.success(), "git helper failed: {args:?}");
    }

    fn repository() -> PathBuf {
        let root = temp_root("repo");
        git(&root, &["init"]);
        git(&root, &["config", "user.email", "orcel@example.invalid"]);
        git(&root, &["config", "user.name", "Orcel Test"]);
        fs::write(root.join("a.txt"), "one\n").unwrap();
        git(&root, &["add", "a.txt"]);
        git(&root, &["commit", "-m", "initial"]);
        root
    }

    #[test]
    fn provider_git_reads_no_global_or_system_config() {
        // Git 2.56 for Windows rejects `NUL` as GIT_CONFIG_GLOBAL; the
        // isolated invocation must still run and see no user configuration.
        let root = repository();
        let provider = GitProvider::new(&root).unwrap();
        let global = provider
            .run_git_raw(&root, &["config", "--global", "--list"])
            .expect("isolated git accepts its null global config");
        assert_eq!(global.stdout.trim(), "");
        let origins = provider
            .run_git_raw(&root, &["config", "--list", "--show-origin"])
            .expect("list effective config");
        assert!(
            origins
                .stdout
                .lines()
                .all(|line| line.starts_with("file:.git/config")
                    || line.starts_with("command line:")),
            "only repository and command-line config may apply:\n{}",
            origins.stdout
        );

        // A real global config that git would otherwise read (control run)
        // is ignored under NULL_GIT_CONFIG.
        let home = temp_root("decoy-home");
        fs::write(home.join(".gitconfig"), "[decoy]\n\tleaked = yes\n").unwrap();
        let read_global = |isolated: bool| {
            let mut command = Command::new("git");
            command
                .args(["config", "--global", "--get", "decoy.leaked"])
                .current_dir(&root)
                .env("HOME", &home)
                .env("USERPROFILE", &home)
                .env("GIT_CONFIG_NOSYSTEM", "1");
            if isolated {
                command.env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG);
            } else {
                command.env_remove("GIT_CONFIG_GLOBAL");
            }
            let output = command.output().expect("run git");
            (
                output.status.code(),
                String::from_utf8_lossy(&output.stdout).trim().to_owned(),
            )
        };
        assert_eq!(
            read_global(false),
            (Some(0), String::from("yes")),
            "control: git reads the decoy"
        );
        // Exit 1 is "key not found": git accepted the value and found nothing
        // (exit 128 would mean it rejected the value, as 2.56 does for NUL).
        assert_eq!(
            read_global(true),
            (Some(1), String::new()),
            "NULL_GIT_CONFIG ignores it"
        );
        let _ = fs::remove_dir_all(home);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn status_diff_and_log_are_read_only_and_bounded() {
        let root = repository();
        fs::write(root.join("a.txt"), "two\n").unwrap();
        let provider = GitProvider::new(&root).unwrap();

        let status = provider.status(".").unwrap();
        assert!(status["porcelain_v2"].as_str().unwrap().contains("a.txt"));

        let diff = provider.diff(".", false).unwrap();
        assert!(diff["diff"].as_str().unwrap().contains("-one"));
        assert!(diff["diff"].as_str().unwrap().contains("+two"));

        let log = provider.log(".", 5).unwrap();
        assert_eq!(log["commits"].as_array().unwrap().len(), 1);

        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "two\n");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn non_repository_is_rejected() {
        let root = temp_root("not-repo");
        let provider = GitProvider::new(&root).unwrap();
        let error = provider.status(".").unwrap_err();
        assert_eq!(error.code, FailureCode::InvalidRequest);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;
        let workspace = temp_root("workspace");
        let outside = repository();
        symlink(&outside, workspace.join("escape")).unwrap();
        let provider = GitProvider::new(&workspace).unwrap();
        let error = provider.status("escape").unwrap_err();
        assert_eq!(error.code, FailureCode::PathEscape);
        let _ = fs::remove_dir_all(workspace);
        let _ = fs::remove_dir_all(outside);
    }
}
