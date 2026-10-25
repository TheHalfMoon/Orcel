pub mod fetch;
mod mutation;
pub mod push;

pub use fetch::{
    destination_ref, parse_destination, source_ref, ApprovedFetch, FetchPreview,
    GitFetchDestination, SystemResolver,
};
pub use mutation::{normalized_commit_message, BranchTip, GitMutationState};

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
        let neutral = neutralizing_args(cwd)?;
        let mut all: Vec<&str> = neutral.iter().map(String::as_str).collect();
        all.extend_from_slice(args);
        run_plain(cwd, &all)
    }
}

/// `-c` overrides that keep a repository's own configuration from making a
/// Git command run a program: hooks, automatic maintenance, alternate-ref
/// commands and every configured filter driver (clean, smudge and
/// long-running process filters run while Git refreshes the index, even
/// for `status`). Fails closed when the configuration cannot be read in
/// full or a driver name cannot be overridden on a command line.
pub(crate) fn neutralizing_args(cwd: &Path) -> Result<Vec<String>, GitProviderError> {
    let listed = run_plain(cwd, &["config", "--list", "-z"])?;
    if listed.stdout_truncated {
        return Err(GitProviderError::new(
            FailureCode::ProviderUnavailable,
            "Git configuration exceeded the bounded output limit",
        ));
    }
    let mut args = vec![
        "-c".to_owned(),
        format!("core.hooksPath={}", null_device().to_string_lossy()),
        "-c".to_owned(),
        "gc.auto=0".to_owned(),
        "-c".to_owned(),
        "maintenance.auto=false".to_owned(),
        "-c".to_owned(),
        "core.alternateRefsCommand=".to_owned(),
    ];
    let mut drivers: Vec<&str> = Vec::new();
    for entry in listed.stdout.split('\0') {
        let key = entry.split('\n').next().unwrap_or_default();
        // Section and variable names are case-insensitive; the driver
        // (subsection) name is kept as written.
        if key.len() < 7 || !key[..7].eq_ignore_ascii_case("filter.") {
            continue;
        }
        let Some((driver, _)) = key[7..].rsplit_once('.') else {
            continue;
        };
        if driver.is_empty() || driver.contains('=') {
            return Err(GitProviderError::new(
                FailureCode::CapabilityDenied,
                "the repository configures a Git filter driver whose name cannot be neutralized",
            ));
        }
        if !drivers.contains(&driver) {
            drivers.push(driver);
        }
    }
    for driver in drivers {
        for (variable, value) in [
            ("clean", ""),
            ("smudge", ""),
            ("process", ""),
            ("required", "false"),
        ] {
            args.push("-c".to_owned());
            args.push(format!("filter.{driver}.{variable}={value}"));
        }
    }
    Ok(args)
}

/// Runs Git with the hardened environment only; callers add
/// [`neutralizing_args`] unless they are reading the configuration itself.
fn run_plain(cwd: &Path, args: &[&str]) -> Result<CommandOutput, GitProviderError> {
    let mut command = Command::new("git");
    command
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.pager=cat",
            // Repository config must not make a read run a program.
            "-c",
            "log.showSignature=false",
        ])
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

    /// A hostile repository's filter drivers (defined directly and through
    /// an included file), hooks and automatic maintenance never run for the
    /// provider's reads, its ref updates or the configuration probe.
    #[test]
    fn reads_never_run_repository_filters_or_hooks() {
        let root = repository();
        let marker = root.join("marker");
        let marker_text = marker.to_string_lossy().replace('\\', "/");
        let program = root.join("evil.sh");
        fs::write(
            &program,
            format!("#!/bin/sh\necho ran >> '{marker_text}'\ncat\n"),
        )
        .unwrap();
        let hook = root
            .join(".git")
            .join("hooks")
            .join("reference-transaction");
        fs::create_dir_all(hook.parent().unwrap()).unwrap();
        fs::write(&hook, format!("#!/bin/sh\necho hook >> '{marker_text}'\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&program, &hook] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let program_text = program.to_string_lossy().replace('\\', "/");
        fs::create_dir_all(root.join(".git").join("info")).unwrap();
        fs::write(
            root.join(".git").join("info").join("attributes"),
            "a.txt filter=evil\nb.txt filter=other.name\n",
        )
        .unwrap();
        git(&root, &["config", "filter.evil.clean", &program_text]);
        git(&root, &["config", "filter.evil.process", &program_text]);
        fs::write(
            root.join("extra.gitconfig"),
            format!("[filter \"other.name\"]\n\tclean = {program_text}\n"),
        )
        .unwrap();
        git(&root, &["config", "include.path", "../extra.gitconfig"]);
        git(&root, &["config", "gc.auto", "1"]);
        fs::write(root.join("b.txt"), "b\n").unwrap();
        let touch = || {
            // A changed timestamp makes Git re-read (and filter) the files.
            let later = SystemTime::now() + std::time::Duration::from_secs(5);
            for name in ["a.txt", "b.txt"] {
                fs::File::options()
                    .write(true)
                    .open(root.join(name))
                    .unwrap()
                    .set_modified(later)
                    .unwrap();
            }
        };
        // Positive controls: unhardened Git runs both.
        touch();
        git(&root, &["status", "--porcelain"]);
        git(&root, &["update-ref", "refs/heads/control", "HEAD"]);
        let control = fs::read_to_string(&marker).unwrap_or_default();
        assert!(control.contains("ran"), "the filter must fire unhardened");
        assert!(control.contains("hook"), "the hook must fire unhardened");
        fs::remove_file(&marker).unwrap();

        touch();
        let provider = GitProvider::new(&root).unwrap();
        provider.status(".").unwrap();
        provider.diff(".", false).unwrap();
        provider.log(".", 5).unwrap();
        provider.branch_tip(".", "control").unwrap();
        let repo = provider.repository_root(".").unwrap();
        provider
            .run_git(&repo, &["update-ref", "refs/heads/evidence", "HEAD"])
            .unwrap();
        assert!(
            !marker.exists(),
            "a provider command ran a repository-configured program: {}",
            fs::read_to_string(&marker).unwrap_or_default()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_filter_driver_name_that_cannot_be_overridden_refuses() {
        let root = repository();
        let config = root.join(".git").join("config");
        let text = fs::read_to_string(&config).unwrap();
        fs::write(&config, text + "[filter \"a=b\"]\n\tclean = x\n").unwrap();
        let provider = GitProvider::new(&root).unwrap();
        let error = provider.status(".").unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn commit_messages_are_normalized_as_git_cleans_them() {
        assert_eq!(normalized_commit_message("subject  \n"), "subject");
        assert_eq!(
            normalized_commit_message("\n\nsubject\r\n\r\n\r\n\nbody\t\n\n"),
            "subject\n\nbody"
        );
        assert_eq!(
            normalized_commit_message("# kept\nsubject"),
            "# kept\nsubject",
            "-m keeps comment-like lines"
        );
        assert_eq!(normalized_commit_message(" \n\t\n"), "");
    }

    /// SG-000120 RJ-02 judge: repository config naming a signature
    /// program must not make a read (the startup reconcile's `branch_tip`,
    /// or `log`) run it.
    #[test]
    fn reads_never_run_a_repository_configured_signature_program() {
        let root = repository();
        let output = |args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(&root)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
                .output()
                .expect("git");
            String::from_utf8_lossy(&output.stdout).trim().to_owned()
        };
        let tree = output(&["rev-parse", "HEAD^{tree}"]);
        let parent = output(&["rev-parse", "HEAD"]);
        let object = root.join("signed-commit.txt");
        fs::write(
            &object,
            format!(
                "tree {tree}\nparent {parent}\nauthor a <a@b> 1 +0000\ncommitter a <a@b> 1 +0000\n\
                 gpgsig -----BEGIN PGP SIGNATURE-----\n \n abc\n -----END PGP SIGNATURE-----\n\nsigned\n"
            ),
        )
        .unwrap();
        let signed = output(&["hash-object", "-t", "commit", "-w", "signed-commit.txt"]);
        git(&root, &["update-ref", "refs/heads/signed", signed.as_str()]);
        let marker = root.join("marker");
        let program = root.join("evil.sh");
        let marker_text = marker.to_string_lossy().replace('\\', "/");
        fs::write(
            &program,
            format!("#!/bin/sh\necho ran > '{marker_text}'\nexit 1\n"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).unwrap();
        }
        git(&root, &["config", "log.showSignature", "true"]);
        git(
            &root,
            &[
                "config",
                "gpg.program",
                &program.to_string_lossy().replace('\\', "/"),
            ],
        );
        // Positive control: an unhardened read does run it here.
        output(&["show", "-s", "--format=%P", signed.as_str()]);
        let control = marker.exists();
        let _ = fs::remove_file(&marker);

        let provider = GitProvider::new(&root).unwrap();
        let tip = provider.branch_tip(".", "signed").unwrap().unwrap();
        assert_eq!(tip.head, signed);
        assert_eq!(tip.parents, vec![parent]);
        assert_eq!(tip.message, "signed");
        git(&root, &["switch", "-q", "signed"]);
        provider.log(".", 5).unwrap();
        assert!(!marker.exists(), "a read ran the configured program");
        assert!(
            control,
            "the hostile configuration must fire for an unhardened read"
        );
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
