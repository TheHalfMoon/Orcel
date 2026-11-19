//! Follow-up to #824 (SG-000132): untracked nested repositories.
//!
//! Git's untracked-file walk (`status` in every untracked mode but `no`,
//! `ls-files --others`, and the walk `add` makes towards a path) treats a
//! folder with a `.git` entry as a nested repository: it reads that `.git`
//! file and checks the folder its `gitdir:` names (`HEAD`, `objects`,
//! `refs`, `commondir`). A `gitdir:` naming `\\host\share` would make Git
//! open an SMB connection, which sends the user's NTLM credentials, from a
//! plain status read. Verified locally with folders only: the output of
//! `status -uall`, `status -unormal` and `ls-files --others` depends on
//! whether the target exists; `status -uno` reads nothing.
//!
//! So before any Git command that may walk (every operation resolves its
//! repository first), the provider walks the working tree itself, the way
//! Git would: from the repository root, skipping the repository's own
//! `.git`, never following links or junctions, not descending into a
//! folder the repository's exclude rules ignore unless the index tracks
//! something under it (Git walks those), though an ignored folder's own
//! `.git` is still checked (Git asks whether the ignored folder itself is
//! a repository before it skips it). For each nested folder with a
//! `.git` entry it refuses a `.git` that is a link, a `gitdir:` or
//! `commondir` naming a share, a device, a link or a place outside the
//! workspace, and does not descend further. The walk is bounded
//! ([`MAX_ENTRIES`] entries, [`MAX_DEPTH`] levels); past either bound the
//! repository is refused (fail closed). Every other command runs with
//! `status.showUntrackedFiles=no`.

use crate::repo_config::{pointed_folder, read_bounded};
use crate::GitProviderError;
use orcel_contracts::FailureCode;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf, Prefix};

/// The most entries the walk reads before it refuses.
pub(crate) const MAX_ENTRIES: usize = 200_000;
/// The deepest folder level the walk reaches before it refuses.
pub(crate) const MAX_DEPTH: usize = 64;

type Lookup<'a> = dyn FnMut(&[String]) -> Result<BTreeSet<String>, GitProviderError> + 'a;

fn escape(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::PathEscape, message)
}

fn bounded(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::CapabilityDenied, message)
}

/// `path` with `.` and `..` resolved lexically and a drive prefix in one
/// form; `None` for any other prefix (UNC, device, verbatim UNC).
fn lexical(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
                    out.push(format!("{}:\\", (drive as char).to_ascii_uppercase()));
                }
                _ => return None,
            },
            Component::RootDir => {
                if out.as_os_str().is_empty() {
                    out.push(Component::RootDir.as_os_str());
                }
            }
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            Component::Normal(name) => out.push(name),
        }
    }
    Some(out)
}

fn key(path: &Path) -> String {
    let text = path.to_string_lossy().replace('/', "\\");
    if cfg!(windows) {
        text.to_lowercase()
    } else {
        text
    }
}

/// `target` lies inside `root` (lexically), and no existing folder or file
/// from `root` down to it is a link or junction.
fn inside_without_links(root: &Path, target: &Path, what: &str) -> Result<(), GitProviderError> {
    let (Some(root), Some(target)) = (lexical(root), lexical(target)) else {
        return Err(escape(format!("{what} names a share or device")));
    };
    let root_key = key(&root);
    let target_key = key(&target);
    let within = target_key == root_key
        || target_key
            .strip_prefix(root_key.trim_end_matches('\\'))
            .is_some_and(|rest| rest.starts_with('\\'));
    if !within {
        return Err(escape(format!("{what} lies outside the workspace")));
    }
    let mut current = target.as_path();
    while key(current) != root_key {
        if std::fs::symlink_metadata(current).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(escape(format!("{what} passes through a link or junction")));
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }
    Ok(())
}

/// A nested repository's Git folder: its `commondir` and `HEAD` checked.
fn check_git_folder(root: &Path, git_dir: &Path) -> Result<(), GitProviderError> {
    if std::fs::symlink_metadata(git_dir.join("HEAD")).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(escape("a nested repository's HEAD is a link"));
    }
    if let Some(bytes) = read_bounded(&git_dir.join("commondir"), "nested commondir")? {
        let text = String::from_utf8(bytes)
            .map_err(|_| escape("a nested repository's commondir is not UTF-8"))?;
        let common = pointed_folder(&text, git_dir, "nested repository's commondir")?;
        inside_without_links(root, &common, "a nested repository's commondir")?;
    }
    Ok(())
}

/// One nested folder's `.git` entry.
fn check_nested_entry(root: &Path, folder: &Path, dot_git: &Path) -> Result<(), GitProviderError> {
    let metadata = std::fs::symlink_metadata(dot_git)
        .map_err(|error| escape(format!("a nested .git cannot be read: {error}")))?;
    if metadata.file_type().is_symlink() {
        return Err(escape("a nested folder's .git is a link or junction"));
    }
    if metadata.is_dir() {
        return check_git_folder(root, dot_git);
    }
    let bytes = read_bounded(dot_git, "nested .git file")?.unwrap_or_default();
    let text = String::from_utf8(bytes).map_err(|_| escape("a nested .git file is not UTF-8"))?;
    let Some(pointed) = text
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("gitdir:"))
    else {
        // Git ignores a .git file without gitdir: (the folder is walked
        // as ordinary files).
        return Ok(());
    };
    let target = pointed_folder(pointed, folder, "nested .git file's gitdir")?;
    inside_without_links(root, &target, "a nested .git file's gitdir")?;
    if target.is_dir() {
        check_git_folder(root, &target)?;
    }
    Ok(())
}

/// The walk (see the module documentation). `ignored` answers which of the
/// given repository-relative folders the exclude rules ignore; `tracked`
/// which of them hold tracked entries.
pub(crate) fn check_nested(
    workspace_root: &Path,
    repo: &Path,
    ignored: &mut Lookup<'_>,
    tracked: &mut Lookup<'_>,
) -> Result<(), GitProviderError> {
    let mut level: Vec<(PathBuf, String)> = vec![(repo.to_path_buf(), String::new())];
    let mut seen = 0usize;
    for depth in 0..=MAX_DEPTH {
        if level.is_empty() {
            return Ok(());
        }
        if depth == MAX_DEPTH {
            return Err(bounded(format!(
                "the working tree is deeper than {MAX_DEPTH} folders; nested repositories cannot be checked"
            )));
        }
        let mut children: Vec<(PathBuf, String)> = Vec::new();
        for (folder, relative) in &level {
            let reader = std::fs::read_dir(folder)
                .map_err(|error| escape(format!("list a working-tree folder: {error}")))?;
            let mut subfolders = Vec::new();
            let mut nested_git = None;
            for entry in reader {
                let entry =
                    entry.map_err(|error| escape(format!("read a working-tree entry: {error}")))?;
                seen += 1;
                if seen > MAX_ENTRIES {
                    return Err(bounded(format!(
                        "the working tree has more than {MAX_ENTRIES} entries outside ignored folders; nested repositories cannot be checked"
                    )));
                }
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    return Err(escape("a working-tree name is not Unicode"));
                };
                if name.eq_ignore_ascii_case(".git") {
                    if !relative.is_empty() {
                        nested_git = Some(entry.path());
                    }
                    continue;
                }
                let file_type = entry
                    .file_type()
                    .map_err(|error| escape(format!("read an entry's type: {error}")))?;
                if file_type.is_dir() && !file_type.is_symlink() {
                    let child = if relative.is_empty() {
                        name.to_owned()
                    } else {
                        format!("{relative}/{name}")
                    };
                    subfolders.push((entry.path(), child));
                }
            }
            if let Some(dot_git) = nested_git {
                // A nested repository: Git stops here, and so does the walk.
                check_nested_entry(workspace_root, folder, &dot_git)?;
                continue;
            }
            children.extend(subfolders);
        }
        let names: Vec<String> = children.iter().map(|(_, name)| name.clone()).collect();
        let ignored_now = ignored(&names)?;
        let ignored_names: Vec<String> = names
            .iter()
            .filter(|name| ignored_now.contains(*name))
            .cloned()
            .collect();
        let tracked_now = tracked(&ignored_names)?;
        let (walked, pruned): (Vec<_>, Vec<_>) = children
            .into_iter()
            .partition(|(_, name)| !ignored_now.contains(name) || tracked_now.contains(name));
        // Git does not descend into an ignored folder, but it still asks
        // whether that folder is itself a nested repository (it reads the
        // folder's `.git`), so those are checked too.
        for (folder, _) in &pruned {
            let dot_git = folder.join(".git");
            if std::fs::symlink_metadata(&dot_git).is_ok() {
                check_nested_entry(workspace_root, folder, &dot_git)?;
            }
        }
        level = walked;
    }
    Ok(())
}
