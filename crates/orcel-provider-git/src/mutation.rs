use super::{CommandOutput, GitProvider, GitProviderError};
use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_MUTATION_PATHS: usize = 128;
const MAX_MUTATION_PATH_BYTES: usize = 4_096;
const MAX_COMMIT_MESSAGE_BYTES: usize = 8 * 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitMutationState {
    pub repository_root: String,
    pub head: String,
    pub branch: Option<String>,
    pub material: String,
}

impl GitMutationState {
    pub fn to_json(&self) -> Value {
        json!({
            "repository_root": self.repository_root,
            "head": self.head,
            "branch": self.branch,
            "material": self.material,
        })
    }
}

/// The tip of a local branch, read to reconcile an approved branch
/// creation or commit after a crash (SG-000120 RJ-02).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchTip {
    pub head: String,
    pub parents: Vec<String>,
    /// The tip's message, normalized by [`normalized_commit_message`].
    /// Callers compare it and must not record it.
    pub message: String,
}

/// A commit message as Git's default whitespace cleanup leaves it: lines
/// without trailing whitespace, no leading or trailing blank lines, and
/// runs of blank lines collapsed to one.
pub fn normalized_commit_message(message: &str) -> String {
    let mut lines: Vec<&str> = Vec::new();
    for line in message.lines().map(str::trim_end) {
        if line.is_empty() && lines.last().is_none_or(|last| last.is_empty()) {
            continue;
        }
        lines.push(line);
    }
    while lines.last().is_some_and(|last| last.is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

struct DisabledHooksDir(PathBuf);

impl DisabledHooksDir {
    fn create() -> Result<Self, GitProviderError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| provider_error(format!("read clock for hooks isolation: {error}")))?
            .as_nanos();
        for attempt in 0..16u32 {
            let path = std::env::temp_dir().join(format!(
                "orcel-git-disabled-hooks-{}-{nonce}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    let path = fs::canonicalize(&path).map_err(|error| {
                        provider_error(format!("canonicalize disabled hooks directory: {error}"))
                    })?;
                    return Ok(Self(path));
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(provider_error(format!(
                        "create disabled hooks directory: {error}"
                    )))
                }
            }
        }
        Err(provider_error(
            "could not allocate a unique disabled hooks directory",
        ))
    }

    fn display(&self) -> String {
        self.0.to_string_lossy().into_owned()
    }
}

impl Drop for DisabledHooksDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

impl GitProvider {
    pub fn branch_state(&self, relative: &str) -> Result<GitMutationState, GitProviderError> {
        let repo = self.repository_root(relative)?;
        self.base_state(&repo, String::new())
    }

    pub fn path_state(
        &self,
        relative: &str,
        paths: &[String],
    ) -> Result<GitMutationState, GitProviderError> {
        let repo = self.repository_root(relative)?;
        let paths = validate_paths(paths)?;
        self.ensure_no_external_filters(&repo, &paths)?;
        let material = self.path_material(&repo, &paths)?;
        self.base_state(&repo, material)
    }

    pub fn unstage_state(
        &self,
        relative: &str,
        paths: &[String],
    ) -> Result<GitMutationState, GitProviderError> {
        let repo = self.repository_root(relative)?;
        self.ensure_supported_repository_state(&repo)?;
        let paths = validate_paths(paths)?;
        self.staged_paths_state(&repo, &paths)
    }

    pub fn staged_state(&self, relative: &str) -> Result<GitMutationState, GitProviderError> {
        let repo = self.repository_root(relative)?;
        self.ensure_supported_repository_state(&repo)?;
        let changed = self.run_git(
            &repo,
            &[
                "diff",
                "--cached",
                "--name-only",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
            ],
        )?;
        if changed.stdout.trim().is_empty() {
            return Err(invalid("git.commit requires a non-empty staged change set"));
        }
        if changed.stdout_truncated {
            return Err(provider_error(
                "staged path evidence exceeded the bounded output limit",
            ));
        }
        let index = self.run_git(&repo, &["ls-files", "--stage", "-z"])?;
        if index.stdout_truncated {
            return Err(provider_error(
                "Git index evidence exceeded the bounded output limit",
            ));
        }
        self.base_state(&repo, index.stdout)
    }

    pub fn create_branch(
        &self,
        relative: &str,
        branch: &str,
        expected: &GitMutationState,
    ) -> Result<Value, GitProviderError> {
        validate_branch_input(branch)?;
        let repo = self.repository_root(relative)?;
        self.ensure_supported_repository_state(&repo)?;
        let current = self.base_state(&repo, String::new())?;
        require_state(&current, expected)?;
        self.run_secure_git(&repo, &["check-ref-format", "--branch", branch])?;
        self.run_secure_git(&repo, &["switch", "-c", branch, expected.head.as_str()])?;
        let result = self.base_state(&repo, String::new())?;
        if result.head != expected.head || result.branch.as_deref() != Some(branch) {
            return Err(postcondition(
                "Git branch creation postcondition did not match the approved state",
            ));
        }
        Ok(json!({
            "repository_root": result.repository_root,
            "head": result.head,
            "branch": result.branch,
            "created": branch,
        }))
    }

    pub fn stage(
        &self,
        relative: &str,
        paths: &[String],
        expected: &GitMutationState,
    ) -> Result<Value, GitProviderError> {
        let repo = self.repository_root(relative)?;
        self.ensure_supported_repository_state(&repo)?;
        let paths = validate_paths(paths)?;
        self.ensure_no_external_filters(&repo, &paths)?;
        let current = self.base_state(&repo, self.path_material(&repo, &paths)?)?;
        require_state(&current, expected)?;
        let literal = literal_pathspecs(&paths);
        let mut args = vec!["add".to_owned(), "--".to_owned()];
        args.extend(literal);
        self.run_secure_owned(&repo, &args)?;
        let result = self.index_evidence(&repo, &paths)?;
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "head": self.head(&repo)?,
            "branch": self.branch(&repo)?,
            "paths": paths,
            "index_entries": result,
        }))
    }

    pub fn unstage(
        &self,
        relative: &str,
        paths: &[String],
        expected: &GitMutationState,
    ) -> Result<Value, GitProviderError> {
        let repo = self.repository_root(relative)?;
        self.ensure_supported_repository_state(&repo)?;
        let paths = validate_paths(paths)?;
        let current = self.staged_paths_state(&repo, &paths)?;
        require_state(&current, expected)?;
        let literal = literal_pathspecs(&paths);
        let mut args = vec!["restore".to_owned(), "--staged".to_owned(), "--".to_owned()];
        args.extend(literal);
        self.run_secure_owned(&repo, &args)?;
        let result = self.index_evidence(&repo, &paths)?;
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "head": self.head(&repo)?,
            "branch": self.branch(&repo)?,
            "paths": paths,
            "index_entries": result,
        }))
    }

    pub fn commit(
        &self,
        relative: &str,
        message: &str,
        expected: &GitMutationState,
    ) -> Result<Value, GitProviderError> {
        validate_commit_message(message)?;
        let repo = self.repository_root(relative)?;
        self.ensure_supported_repository_state(&repo)?;
        let current = self.staged_state(relative)?;
        require_state(&current, expected)?;
        let branch = current
            .branch
            .clone()
            .ok_or_else(|| invalid("git.commit requires an attached local branch"))?;
        self.require_local_identity(&repo)?;
        self.run_secure_git(
            &repo,
            &["commit", "--no-gpg-sign", "--no-verify", "-m", message],
        )?;
        let new_head = self.head(&repo)?;
        if new_head == expected.head {
            return Err(postcondition("git.commit did not advance HEAD"));
        }
        let parent = self
            .run_git(&repo, &["rev-parse", "--verify", "HEAD^"])?
            .stdout
            .trim()
            .to_owned();
        if parent != expected.head {
            return Err(postcondition(
                "git.commit parent does not match the approved expected HEAD",
            ));
        }
        let result_branch = self.branch(&repo)?;
        if result_branch.as_deref() != Some(branch.as_str()) {
            return Err(postcondition(
                "git.commit changed the current branch unexpectedly",
            ));
        }
        Ok(json!({
            "repository_root": self.relative_display(&repo),
            "previous_head": expected.head,
            "head": new_head,
            "branch": result_branch,
            "parent": parent,
        }))
    }

    /// The tip of `refs/heads/<branch>` in the repository at `relative`;
    /// `None` when the branch does not exist. Read-only.
    pub fn branch_tip(
        &self,
        relative: &str,
        branch: &str,
    ) -> Result<Option<BranchTip>, GitProviderError> {
        validate_branch_input(branch)?;
        let repo = self.repository_root(relative)?;
        let full = format!("refs/heads/{branch}");
        // for-each-ref exits 0 when nothing matches, so a missing branch is
        // told apart from a failure; the exact name is matched below.
        let refs = self.run_git(
            &repo,
            &[
                "for-each-ref",
                "--format=%(refname)%00%(objectname)",
                full.as_str(),
            ],
        )?;
        if refs.stdout_truncated {
            return Err(provider_error("Git ref evidence exceeded its bound"));
        }
        let Some(head) = refs.stdout.lines().find_map(|line| {
            let (name, object) = line.split_once('\0')?;
            (name == full).then(|| object.trim().to_ascii_lowercase())
        }) else {
            return Ok(None);
        };
        if head.len() != 40 || !head.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_error("Git returned an invalid branch object id"));
        }
        let parents = self.run_git(&repo, &["show", "-s", "--format=%P", head.as_str()])?;
        let message = self.run_git(&repo, &["show", "-s", "--format=%B", head.as_str()])?;
        if parents.stdout_truncated || message.stdout_truncated {
            return Err(provider_error("Git commit evidence exceeded its bound"));
        }
        Ok(Some(BranchTip {
            parents: parents
                .stdout
                .split_whitespace()
                .map(str::to_ascii_lowercase)
                .collect(),
            message: normalized_commit_message(&message.stdout),
            head,
        }))
    }

    fn staged_paths_state(
        &self,
        repo: &Path,
        paths: &[String],
    ) -> Result<GitMutationState, GitProviderError> {
        let material = self.index_evidence(repo, paths)?;
        self.base_state(repo, material)
    }

    fn base_state(
        &self,
        repo: &Path,
        material: String,
    ) -> Result<GitMutationState, GitProviderError> {
        Ok(GitMutationState {
            repository_root: self.relative_display(repo),
            head: self.head(repo)?,
            branch: self.branch(repo)?,
            material,
        })
    }

    fn head(&self, repo: &Path) -> Result<String, GitProviderError> {
        let output = self.run_git(repo, &["rev-parse", "--verify", "HEAD"])?;
        let value = output.stdout.trim();
        if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(provider_error("Git returned an invalid HEAD object id"));
        }
        Ok(value.to_ascii_lowercase())
    }

    fn branch(&self, repo: &Path) -> Result<Option<String>, GitProviderError> {
        let output = self.run_git(repo, &["branch", "--show-current"])?;
        let branch = output.stdout.trim();
        Ok((!branch.is_empty()).then(|| branch.to_owned()))
    }

    fn path_material(&self, repo: &Path, paths: &[String]) -> Result<String, GitProviderError> {
        let mut material = String::new();
        for path in paths {
            let literal = literal_pathspec(path);
            let index = self.run_git(repo, &["ls-files", "--stage", "--", literal.as_str()])?;
            if index.stdout_truncated {
                return Err(provider_error("Git index evidence exceeded its bound"));
            }
            material.push_str("PATH\0");
            material.push_str(path);
            material.push_str("\0INDEX\0");
            material.push_str(&index.stdout);
            material.push_str("\0WORKTREE\0");
            let disk_path = repo.join(path);
            match fs::symlink_metadata(&disk_path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(invalid("Git mutation does not accept symlink paths"));
                }
                Ok(metadata) if metadata.is_dir() => {
                    return Err(invalid("Git mutation accepts file paths only"));
                }
                Ok(metadata) if metadata.is_file() => {
                    let hash =
                        self.run_git(repo, &["hash-object", "--no-filters", "--", path.as_str()])?;
                    material.push_str(hash.stdout.trim());
                }
                Ok(_) => return Err(invalid("unsupported filesystem object for Git mutation")),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    if index.stdout.trim().is_empty() {
                        return Err(invalid(
                            "Git mutation path is neither an existing file nor a tracked deletion",
                        ));
                    }
                    material.push_str("MISSING_TRACKED");
                }
                Err(error) => {
                    return Err(provider_error(format!(
                        "inspect Git mutation path {path}: {error}"
                    )))
                }
            }
            material.push('\0');
        }
        Ok(material)
    }

    fn index_evidence(&self, repo: &Path, paths: &[String]) -> Result<String, GitProviderError> {
        let literal = literal_pathspecs(paths);
        let mut args = vec![
            "ls-files".to_owned(),
            "--stage".to_owned(),
            "-z".to_owned(),
            "--".to_owned(),
        ];
        args.extend(literal);
        let output = self.run_owned(repo, &args)?;
        if output.stdout_truncated {
            return Err(provider_error("Git index evidence exceeded its bound"));
        }
        Ok(output.stdout)
    }

    fn ensure_no_external_filters(
        &self,
        repo: &Path,
        paths: &[String],
    ) -> Result<(), GitProviderError> {
        for path in paths {
            let output = self.run_git(repo, &["check-attr", "filter", "--", path.as_str()])?;
            let value = output
                .stdout
                .trim_end()
                .rsplit_once(": filter: ")
                .map(|(_, value)| value.trim())
                .ok_or_else(|| provider_error("could not parse git check-attr output"))?;
            if value != "unspecified" && value != "unset" {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    format!(
                        "Git mutation path {path} has a configured filter driver; external filters are not allowed"
                    ),
                ));
            }
        }
        Ok(())
    }

    fn ensure_supported_repository_state(&self, repo: &Path) -> Result<(), GitProviderError> {
        for marker in [
            "MERGE_HEAD",
            "CHERRY_PICK_HEAD",
            "REVERT_HEAD",
            "BISECT_LOG",
            "rebase-merge",
            "rebase-apply",
            "sequencer",
        ] {
            let output = self.run_git(repo, &["rev-parse", "--git-path", marker])?;
            let reported = output.stdout.trim();
            let path = Path::new(reported);
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                repo.join(path)
            };
            if path.exists() {
                return Err(GitProviderError::new(
                    FailureCode::CapabilityDenied,
                    format!("Git mutation is unavailable while repository state {marker} exists"),
                ));
            }
        }
        Ok(())
    }

    fn require_local_identity(&self, repo: &Path) -> Result<(), GitProviderError> {
        for key in ["user.name", "user.email"] {
            let output = self.run_git(repo, &["config", "--local", "--get", key])?;
            if output.stdout.trim().is_empty() {
                return Err(invalid(format!(
                    "git.commit requires repository-local {key}"
                )));
            }
        }
        Ok(())
    }

    fn run_secure_git(
        &self,
        repo: &Path,
        args: &[&str],
    ) -> Result<CommandOutput, GitProviderError> {
        let args = args
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>();
        self.run_secure_owned(repo, &args)
    }

    fn run_secure_owned(
        &self,
        repo: &Path,
        subcommand: &[String],
    ) -> Result<CommandOutput, GitProviderError> {
        let hooks = DisabledHooksDir::create()?;
        let mut args = vec![
            "-c".to_owned(),
            format!("core.hooksPath={}", hooks.display()),
            "-c".to_owned(),
            "commit.gpgSign=false".to_owned(),
            "-c".to_owned(),
            "tag.gpgSign=false".to_owned(),
            "-c".to_owned(),
            "credential.helper=".to_owned(),
            "-c".to_owned(),
            "core.askPass=".to_owned(),
        ];
        args.extend(subcommand.iter().cloned());
        self.run_owned(repo, &args)
    }

    fn run_owned(&self, repo: &Path, args: &[String]) -> Result<CommandOutput, GitProviderError> {
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        self.run_git_raw(repo, &refs)
    }
}

fn validate_paths(paths: &[String]) -> Result<Vec<String>, GitProviderError> {
    if paths.is_empty() || paths.len() > MAX_MUTATION_PATHS {
        return Err(invalid(format!(
            "Git mutation requires 1..={MAX_MUTATION_PATHS} explicit paths"
        )));
    }
    let mut seen = BTreeSet::new();
    let mut validated = Vec::with_capacity(paths.len());
    for value in paths {
        if value.is_empty() || value.len() > MAX_MUTATION_PATH_BYTES {
            return Err(invalid("Git mutation path is empty or too large"));
        }
        if value
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r' | '\t'))
            || value.starts_with(':')
        {
            return Err(invalid(
                "Git mutation path contains control data or pathspec magic",
            ));
        }
        let path = Path::new(value);
        if path.is_absolute() {
            return Err(invalid("Git mutation path must be repository-relative"));
        }
        for component in path.components() {
            match component {
                Component::Normal(name) => {
                    if name.to_string_lossy().eq_ignore_ascii_case(".git") {
                        return Err(invalid("Git control paths are not mutable"));
                    }
                }
                Component::CurDir => {}
                Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                    return Err(invalid("Git mutation path escapes the repository"));
                }
            }
        }
        if value.eq_ignore_ascii_case(".gitmodules") {
            return Err(invalid("submodule metadata mutation is not allowed"));
        }
        if !seen.insert(value.clone()) {
            return Err(invalid("Git mutation path list contains duplicates"));
        }
        validated.push(value.clone());
    }
    Ok(validated)
}

fn validate_branch_input(branch: &str) -> Result<(), GitProviderError> {
    if branch.is_empty()
        || branch.len() > 255
        || branch
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r' | '\t'))
        || branch.starts_with('-')
    {
        return Err(invalid("Git branch name is empty, unsafe, or too large"));
    }
    Ok(())
}

fn validate_commit_message(message: &str) -> Result<(), GitProviderError> {
    if message.trim().is_empty()
        || message.len() > MAX_COMMIT_MESSAGE_BYTES
        || message.contains('\0')
    {
        return Err(invalid("Git commit message is empty, unsafe, or too large"));
    }
    Ok(())
}

fn literal_pathspec(path: &str) -> String {
    format!(":(literal){path}")
}

fn literal_pathspecs(paths: &[String]) -> Vec<String> {
    paths.iter().map(|path| literal_pathspec(path)).collect()
}

fn require_state(
    current: &GitMutationState,
    expected: &GitMutationState,
) -> Result<(), GitProviderError> {
    if current != expected {
        return Err(GitProviderError::new(
            FailureCode::TargetStale,
            "Git repository state changed after approval material was prepared",
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::InvalidRequest, message)
}

fn provider_error(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::ProviderUnavailable, message)
}

fn postcondition(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::PostconditionFailed, message)
}
