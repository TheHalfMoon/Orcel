//! The repository configuration gate (SG-000132 slice 4 review, shared by
//! the Safe-mode provider and Full Control's `orceld fc-worker`).
//!
//! Overriding the keys Git would use to run a program is not enough: Git
//! 2.36 and later also run hooks defined in configuration
//! (`hook.<name>.command` with `hook.<name>.event`), which neither
//! `core.hooksPath` nor `--no-verify` turns off, and new command-valued keys
//! keep appearing. So a repository whose own configuration names a hook, an
//! alias, a credential helper, a transport or proxy command, an editor,
//! pager, diff or merge program, a signing program, an include, or a URL or
//! HTTP rewrite is refused before any Git command runs in it. Filter
//! drivers stay neutralized rather than refused (every driver's `clean`,
//! `smudge` and `process` are emptied on every command, and adding a file a
//! filter attribute names is refused), so repositories set up for Git LFS
//! keep working.
//!
//! The gate reads the configuration files itself, before Git runs: a `.git`
//! file's `gitdir:`, a worktree's `commondir`, and the `config` and
//! `config.worktree` files they lead to. A path or value that names a
//! network share or a device (`\\host\share`, `//host/share`, `\\?\`,
//! `\\.\`) is refused there, because Git would open it (an SMB connection
//! sends the user's NTLM credentials). Includes are refused, so those files
//! are the whole repository configuration (system and global configuration
//! are never read). Git's own listing is checked again against the same
//! rules before every command (`check_listed`), a backstop for hooks and
//! command-valued keys in case this parser and Git's ever read a file
//! differently. It is no backstop for includes: Git follows `include.path`
//! while it starts up even under `--no-includes`, so this parser's refusal
//! of `include` and `includeIf` is the only defence for the paths they
//! name. Submodules fail closed: a `.gitmodules` entry or a `modules`
//! folder in the Git directory refuses the repository (a submodule's own
//! configuration and filters are outside this gate).
//!
//! Review of #847: a repository extension can move what Git uses to another
//! place while `rev-parse` still reports this repository
//! (`extensions.refStorage = files://<another>/.git` moves HEAD, the refs
//! and the reflogs), so only the extensions known here, with the values
//! known here, are accepted ([`extension_allowed`]); any other, also one a
//! later Git adds, refuses the repository. The parts of the Git folder Git
//! writes through are not links or junctions ([`WRITTEN_THROUGH`],
//! [`check_git_folder`]).

use crate::GitProviderError;
use orcel_contracts::FailureCode;
use std::path::{Component, Path, PathBuf};

/// The largest configuration or pointer file the gate reads.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// One `section.subsection.name = value` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    /// Lowercase.
    pub(crate) section: String,
    /// As written (case-sensitive), when present.
    pub(crate) subsection: Option<String>,
    /// Lowercase.
    pub(crate) name: String,
    pub(crate) value: Option<String>,
}

fn refused(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(FailureCode::CapabilityDenied, message)
}

fn unreadable(message: impl Into<String>) -> GitProviderError {
    GitProviderError::new(
        FailureCode::CapabilityDenied,
        format!(
            "the repository configuration cannot be read safely: {}",
            message.into()
        ),
    )
}

/// Sections whose every key names a program, a transport, a rewrite, an
/// include or credentials.
const REFUSED_SECTIONS: &[&str] = &[
    "hook",
    "alias",
    "include",
    "includeif",
    "credential",
    "protocol",
    "url",
    "http",
    "https",
    "uploadpack",
    "receivepack",
    "sequence",
    "gpg",
    "pager",
    "difftool",
    "mergetool",
    "guitool",
    "browser",
    "man",
    "instaweb",
    "sendemail",
    "trace2",
];

/// `core.*` keys that name a program, a hooks folder, a proxy or another
/// worktree.
const REFUSED_CORE: &[&str] = &[
    "sshcommand",
    "gitproxy",
    "fsmonitor",
    "editor",
    "pager",
    "askpass",
    "hookspath",
    "alternaterefscommand",
    "worktree",
];

/// Whether a repository extension (`extensions.<name>`, lowercase) has a
/// value known to keep everything Git uses where the gate looked. Values
/// are compared as Git compares them; booleans as Git reads them.
fn extension_allowed(name: &str, value: Option<&str>) -> bool {
    let boolean = || match value {
        // A key without `=` is true.
        None => true,
        Some(value) => ["true", "false", "yes", "no", "on", "off", "1", "0", ""]
            .iter()
            .any(|known| value.eq_ignore_ascii_case(known)),
    };
    match name {
        // Ignored by Git.
        "noop" => true,
        // `config.worktree` beside `config` (the gate reads both), no
        // pruning, and relative `gitdir` links (the gate resolves them).
        "worktreeconfig" | "preciousobjects" | "relativeworktrees" => boolean(),
        "objectformat" => matches!(value, Some("sha1" | "sha256")),
        // Loose and packed refs in the Git folder, without a place
        // (`files://...`); not reftable.
        "refstorage" => value == Some("files"),
        // A remote's name. Git fetches nothing for it: lazy fetching is off
        // and no transport is allowed.
        "partialclone" => value.is_some_and(|remote| {
            !remote.is_empty()
                && !remote.starts_with(['-', '.'])
                && remote
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        }),
        _ => false,
    }
}

/// Why an entry is refused, or `None`.
pub(crate) fn refusal(entry: &Entry) -> Option<String> {
    let key = match &entry.subsection {
        Some(subsection) => format!("{}.{subsection}.{}", entry.section, entry.name),
        None => format!("{}.{}", entry.section, entry.name),
    };
    let section = entry.section.as_str();
    let name = entry.name.as_str();
    let sub = entry.subsection.is_some();
    let denied = REFUSED_SECTIONS.contains(&section)
        || (section == "core" && !sub && REFUSED_CORE.contains(&name))
        || (section == "diff" && !sub && name == "external")
        || (section == "diff" && sub && matches!(name, "command" | "textconv"))
        || (section == "merge" && sub && name == "driver")
        || (section == "remote"
            && sub
            && matches!(name, "uploadpack" | "receivepack" | "vcs" | "proxy"))
        || (section == "submodule" && sub && name == "update");
    if denied {
        return Some(format!(
            "the repository configuration sets {key}, which can make Git run a program, follow an include or use a transport; Orcel does not run Git in it"
        ));
    }
    if section == "extensions" && (sub || !extension_allowed(name, entry.value.as_deref())) {
        return Some(format!(
            "the repository configuration sets {key} to a value that is not known to keep Git inside the repository; Orcel does not run Git in it"
        ));
    }
    if entry.value.as_deref().is_some_and(names_a_share_or_device) {
        return Some(format!(
            "the repository configuration's {key} names a network share or a device path"
        ));
    }
    None
}

/// Whether `text` names a UNC share, a `//host` path or a device path
/// (after Git's `:(optional)` prefix and surrounding whitespace or quotes).
pub(crate) fn names_a_share_or_device(text: &str) -> bool {
    let text = text.trim().trim_matches('"').trim();
    let text = text.strip_prefix(":(optional)").unwrap_or(text);
    let bytes = text.as_bytes();
    let slash = |b: u8| b == b'\\' || b == b'/';
    (bytes.len() >= 2 && slash(bytes[0]) && slash(bytes[1]))
        || text.starts_with(r"\??\")
        || text.contains(r"\\?\")
        || text.contains(r"\\.\")
}

/// Parses Git's configuration file syntax: `[section]`,
/// `[section "subsection"]`, the old `[section.subsection]`, `name`,
/// `name = value`, quotes, escapes, `\` line continuations and `#`/`;`
/// comments. Anything it cannot parse is an error (the gate then refuses).
pub(crate) fn parse(bytes: &[u8]) -> Result<Vec<Entry>, String> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    let mut entries = Vec::new();
    let mut section: Option<(String, Option<String>)> = None;
    let mut at = 0;
    let len = bytes.len();
    while at < len {
        let c = bytes[at];
        if c.is_ascii_whitespace() {
            at += 1;
        } else if c == b'#' || c == b';' {
            while at < len && bytes[at] != b'\n' {
                at += 1;
            }
        } else if c == b'[' {
            at += 1;
            let start = at;
            while at < len
                && (bytes[at].is_ascii_alphanumeric() || matches!(bytes[at], b'-' | b'.'))
            {
                at += 1;
            }
            let name = std::str::from_utf8(&bytes[start..at])
                .map_err(|_| "a section name is not text".to_owned())?
                .to_owned();
            if name.is_empty() {
                return Err("an empty section name".to_owned());
            }
            let mut subsection = None;
            if at < len && matches!(bytes[at], b' ' | b'\t') {
                while at < len && matches!(bytes[at], b' ' | b'\t') {
                    at += 1;
                }
                if at >= len || bytes[at] != b'"' {
                    return Err("a section header without a quoted subsection".to_owned());
                }
                at += 1;
                let mut value = Vec::new();
                loop {
                    if at >= len || bytes[at] == b'\n' {
                        return Err("an unterminated subsection".to_owned());
                    }
                    match bytes[at] {
                        b'"' => {
                            at += 1;
                            break;
                        }
                        b'\\' if at + 1 < len && bytes[at + 1] != b'\n' => {
                            value.push(bytes[at + 1]);
                            at += 2;
                        }
                        other => {
                            value.push(other);
                            at += 1;
                        }
                    }
                }
                subsection = Some(String::from_utf8_lossy(&value).into_owned());
            }
            if at >= len || bytes[at] != b']' {
                return Err("a section header without ']'".to_owned());
            }
            at += 1;
            let lower = name.to_ascii_lowercase();
            section = Some(match (subsection, lower.split_once('.')) {
                (Some(sub), None) => (lower, Some(sub)),
                (Some(_), Some(_)) => return Err("a dotted section with a subsection".to_owned()),
                // The old `[section.subsection]` form (lowercased by Git).
                (None, Some((head, rest))) => (head.to_owned(), Some(rest.to_owned())),
                (None, None) => (lower, None),
            });
        } else if c.is_ascii_alphabetic() {
            let Some((current, subsection)) = section.clone() else {
                return Err("a key before any section".to_owned());
            };
            let start = at;
            while at < len && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'-') {
                at += 1;
            }
            let name = String::from_utf8_lossy(&bytes[start..at]).to_ascii_lowercase();
            while at < len && matches!(bytes[at], b' ' | b'\t' | b'\r') {
                at += 1;
            }
            let mut value = None;
            if at < len && bytes[at] == b'=' {
                at += 1;
                let mut text = Vec::new();
                let mut quoted = false;
                loop {
                    if at >= len {
                        if quoted {
                            return Err("an unterminated quoted value".to_owned());
                        }
                        break;
                    }
                    let b = bytes[at];
                    if b == b'\n' || (b == b'\r' && bytes.get(at + 1) == Some(&b'\n')) {
                        if quoted {
                            return Err("a quoted value across a line".to_owned());
                        }
                        break;
                    }
                    if !quoted && (b == b'#' || b == b';') {
                        while at < len && bytes[at] != b'\n' {
                            at += 1;
                        }
                        break;
                    }
                    match b {
                        b'"' => {
                            quoted = !quoted;
                            at += 1;
                        }
                        b'\\' => {
                            let Some(&next) = bytes.get(at + 1) else {
                                return Err("a value ends in '\\'".to_owned());
                            };
                            match next {
                                b'\n' => at += 2,
                                b'\r' if bytes.get(at + 2) == Some(&b'\n') => at += 3,
                                b'n' => {
                                    text.push(b'\n');
                                    at += 2;
                                }
                                b't' => {
                                    text.push(b'\t');
                                    at += 2;
                                }
                                b'b' => {
                                    text.pop();
                                    at += 2;
                                }
                                b'"' | b'\\' => {
                                    text.push(next);
                                    at += 2;
                                }
                                _ => return Err("an unknown escape in a value".to_owned()),
                            }
                        }
                        _ => {
                            text.push(b);
                            at += 1;
                        }
                    }
                }
                value = Some(String::from_utf8_lossy(&text).trim().to_owned());
            } else if at < len && !matches!(bytes[at], b'\n' | b'#' | b';') {
                return Err("a key followed by something other than '='".to_owned());
            }
            entries.push(Entry {
                section: current,
                subsection,
                name,
                value,
            });
        } else {
            return Err(format!("an unexpected character 0x{c:02x}"));
        }
    }
    Ok(entries)
}

pub(crate) fn read_bounded(path: &Path, what: &str) -> Result<Option<Vec<u8>>, GitProviderError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(unreadable(format!("{what}: {error}"))),
    };
    if metadata.file_type().is_symlink() {
        return Err(refused(format!(
            "the repository's {what} is a link or junction"
        )));
    }
    if !metadata.is_file() {
        return Err(unreadable(format!("{what} is not a file")));
    }
    if metadata.len() > MAX_CONFIG_BYTES {
        return Err(unreadable(format!("{what} is larger than 1 MiB")));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|error| unreadable(format!("{what}: {error}")))
}

/// A folder a `.git` file or `commondir` names, refused if it is a share
/// or device path, resolved against `base` when relative.
pub(crate) fn pointed_folder(
    text: &str,
    base: &Path,
    what: &str,
) -> Result<PathBuf, GitProviderError> {
    let text = text.trim();
    if text.is_empty() || names_a_share_or_device(text) || text.contains('\0') {
        return Err(GitProviderError::new(
            FailureCode::PathEscape,
            format!("the repository's {what} names a network share, a device or nothing"),
        ));
    }
    let path = Path::new(text);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    match std::fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(refused(format!(
            "the repository's {what} is a link or junction"
        ))),
        _ => Ok(path),
    }
}

fn check_file(path: &Path, what: &str) -> Result<(), GitProviderError> {
    let Some(bytes) = read_bounded(path, what)? else {
        return Ok(());
    };
    let entries = parse(&bytes).map_err(|error| unreadable(format!("{what}: {error}")))?;
    for entry in &entries {
        if let Some(reason) = refusal(entry) {
            return Err(refused(reason));
        }
    }
    Ok(())
}

/// What Git writes (or replaces) in its folder, by name: none may be a link
/// or a junction (review of #847).
const WRITTEN_THROUGH: &[&str] = &[
    "HEAD",
    "ORIG_HEAD",
    "FETCH_HEAD",
    "COMMIT_EDITMSG",
    "index",
    "packed-refs",
    "refs",
    "logs",
    "objects",
    "worktrees",
];

/// The most entries of a Git folder's `refs`, `logs` and `objects` the gate
/// looks at before it refuses.
const MAX_GIT_FOLDER_ENTRIES: usize = 200_000;

fn refuse_link(path: &Path) -> Result<(), GitProviderError> {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(refused(
            "a part of the repository's Git folder is a link or junction; Orcel does not run Git in it",
        ));
    }
    Ok(())
}

/// Review of #847: nothing under a Git folder's `refs` and `logs`, and no
/// direct entry of its `objects`, is a link or junction, so a ref, a reflog
/// or an object is written in the Git folder and nowhere else.
pub(crate) fn check_git_folder(dir: &Path) -> Result<(), GitProviderError> {
    check_git_folder_within(dir, MAX_GIT_FOLDER_ENTRIES)
}

fn check_git_folder_within(dir: &Path, most: usize) -> Result<(), GitProviderError> {
    let mut left = most;
    let mut pending: Vec<(PathBuf, bool)> = ["refs", "logs", "objects"]
        .iter()
        .map(|name| (dir.join(name), *name != "objects"))
        .collect();
    while let Some((folder, deep)) = pending.pop() {
        refuse_link(&folder)?;
        let entries = match std::fs::read_dir(&folder) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(unreadable(format!("the Git folder: {error}"))),
        };
        for entry in entries {
            let entry = entry.map_err(|error| unreadable(format!("the Git folder: {error}")))?;
            left = left
                .checked_sub(1)
                .ok_or_else(|| unreadable("the Git folder has too many entries"))?;
            let kind = entry
                .file_type()
                .map_err(|error| unreadable(format!("the Git folder: {error}")))?;
            if kind.is_symlink() {
                refuse_link(&entry.path())?;
            }
            if deep && kind.is_dir() {
                pending.push((entry.path(), true));
            }
        }
    }
    Ok(())
}

/// The gate, before any Git command runs with `cwd` as its working folder
/// inside `workspace_root` (both resolved): `cwd` is not inside a `.git`
/// folder; the nearest `.git` from `cwd` up to the workspace root is a plain
/// folder or a `.git` file whose `gitdir:` (and that folder's `commondir`)
/// names no share, device or link; and none of the configuration files
/// they lead to sets a refused key or names a share.
pub(crate) fn check_repository(workspace_root: &Path, cwd: &Path) -> Result<(), GitProviderError> {
    let cwd = std::fs::canonicalize(cwd).map_err(|error| {
        GitProviderError::new(
            FailureCode::InvalidRequest,
            format!("resolve the Git working folder: {error}"),
        )
    })?;
    let cwd = cwd.as_path();
    let relative = cwd.strip_prefix(workspace_root).map_err(|_| {
        GitProviderError::new(
            FailureCode::PathEscape,
            "the Git working folder lies outside the trusted workspace",
        )
    })?;
    if relative.components().any(|component| match component {
        Component::Normal(name) => name.eq_ignore_ascii_case(".git"),
        _ => false,
    }) {
        return Err(GitProviderError::new(
            FailureCode::InvalidRequest,
            "Git does not run inside a .git folder",
        ));
    }
    let mut folder = Some(cwd);
    while let Some(current) = folder {
        let dot_git = current.join(".git");
        match std::fs::symlink_metadata(&dot_git) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(refused("the repository's .git is a link or junction"));
            }
            Ok(metadata) => {
                let git_dir = if metadata.is_dir() {
                    dot_git
                } else {
                    let bytes = read_bounded(&dot_git, ".git file")?.unwrap_or_default();
                    let text = String::from_utf8(bytes)
                        .map_err(|_| unreadable(".git file is not UTF-8"))?;
                    let pointed = text
                        .lines()
                        .next()
                        .and_then(|line| line.strip_prefix("gitdir:"))
                        .ok_or_else(|| unreadable(".git file names no gitdir"))?;
                    pointed_folder(pointed, current, ".git file's gitdir")?
                };
                let mut folders = vec![git_dir.clone()];
                if let Some(bytes) = read_bounded(&git_dir.join("commondir"), "commondir")? {
                    let text = String::from_utf8(bytes)
                        .map_err(|_| unreadable("commondir is not UTF-8"))?;
                    folders.push(pointed_folder(&text, &git_dir, "commondir")?);
                }
                for dir in &folders {
                    for name in WRITTEN_THROUGH {
                        refuse_link(&dir.join(name))?;
                    }
                    check_file(&dir.join("config"), "config")?;
                    check_file(&dir.join("config.worktree"), "config.worktree")?;
                }
                // Re-review of #824: submodules fail closed. A submodule's
                // own configuration (`.git/modules/<name>/config`) and
                // filters are outside this gate, and raw Git runs them
                // from `add` and `commit`; a repository that declares or
                // holds one is refused.
                if std::fs::symlink_metadata(current.join(".gitmodules")).is_ok() {
                    return Err(refused(
                        "the repository has submodules (.gitmodules); Orcel does not run Git in it",
                    ));
                }
                for dir in &folders {
                    if std::fs::symlink_metadata(dir.join("modules")).is_ok() {
                        return Err(refused(
                            "the repository holds submodule repositories (.git/modules); Orcel does not run Git in it",
                        ));
                    }
                }
                return Ok(());
            }
            Err(_) => {}
        }
        if current == workspace_root {
            break;
        }
        folder = current.parent();
    }
    Ok(())
}

/// The same rules over Git's own listing (`config --list --show-scope
/// --no-includes -z`), skipping Orcel's own `-c` overrides (scope
/// `command`).
pub(crate) fn check_listed(listed: &str) -> Result<(), GitProviderError> {
    let mut fields = listed.split('\0');
    while let (Some(scope), Some(item)) = (fields.next(), fields.next()) {
        if scope == "command" {
            continue;
        }
        let (key, value) = match item.split_once('\n') {
            Some((key, value)) => (key, Some(value.to_owned())),
            None => (item, None),
        };
        let lower = key.to_ascii_lowercase();
        let Some((section, rest)) = lower.split_once('.') else {
            continue;
        };
        let (subsection, name) = match rest.rsplit_once('.') {
            // Keep the subsection as written.
            Some((_, name)) => (
                Some(key[section.len() + 1..key.len() - name.len() - 1].to_owned()),
                name.to_owned(),
            ),
            None => (None, rest.to_owned()),
        };
        let entry = Entry {
            section: section.to_owned(),
            subsection,
            name,
            value,
        };
        if let Some(reason) = refusal(&entry) {
            return Err(refused(reason));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(text: &str) -> Vec<String> {
        parse(text.as_bytes())
            .expect("parses")
            .into_iter()
            .map(|entry| match entry.subsection {
                Some(sub) => format!("{}.{sub}.{}", entry.section, entry.name),
                None => format!("{}.{}", entry.section, entry.name),
            })
            .collect()
    }

    fn refuses(text: &str) -> bool {
        parse(text.as_bytes())
            .map(|entries| entries.iter().any(|entry| refusal(entry).is_some()))
            .unwrap_or(true)
    }

    #[test]
    fn the_parser_reads_git_config_forms() {
        assert_eq!(
            keys("\u{feff}[core]\r\n\tbare = false\r\n[Hook \"Post Index\"]\n  COMMAND = x\n"),
            ["core.bare", "hook.Post Index.command"]
        );
        // A continuation line that looks like a header is part of the value.
        assert_eq!(
            keys("[user]\n\tname = a \\\n[hook \"x\"]\n\temail = b # c\n"),
            ["user.name", "user.email"]
        );
        // A quoted '#' is not a comment; the old dotted form.
        assert_eq!(
            keys("[user]\n\tname = \"a # b\"\n[Hook.X]\n\tcommand\n"),
            ["user.name", "hook.x.command"]
        );
        for bad in [
            "name = x\n",
            "[core\n",
            "[core]\n\t=x\n",
            "[core]\n\ta = \"x\n",
            "[a \"b]\n",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn command_valued_and_share_valued_keys_are_refused() {
        for text in [
            "[hook \"evil\"]\n\tcommand = touch x\n\tevent = post-index-change\n",
            "[HOOK \"evil\"]\n\tevent = reference-transaction\n",
            "[hook.evil]\n\tcommand = x\n",
            "[alias]\n\tst = !evil\n",
            "[include]\n\tpath = x\n",
            "[includeIf \"gitdir:/\"]\n\tpath = x\n",
            "[core]\n\tsshCommand = evil\n",
            "[core]\n\tfsmonitor = evil\n",
            "[core]\n\thooksPath = h\n",
            "[core]\n\tpager = evil\n",
            "[core]\n\teditor = evil\n",
            "[core]\n\taskPass = evil\n",
            "[core]\n\tgitProxy = evil\n",
            "[credential]\n\thelper = evil\n",
            "[diff]\n\texternal = evil\n",
            "[diff \"x\"]\n\tcommand = evil\n",
            "[diff \"x\"]\n\ttextconv = evil\n",
            "[merge \"x\"]\n\tdriver = evil\n",
            "[remote \"o\"]\n\tuploadpack = evil\n",
            "[remote \"o\"]\n\treceivepack = evil\n",
            "[url \"x\"]\n\tinsteadOf = y\n",
            "[http]\n\tproxy = x\n",
            "[gpg]\n\tprogram = evil\n",
            "[sequence]\n\teditor = evil\n",
            "[core]\n\texcludesFile = \\\\\\\\host\\\\share\\\\x\n",
            "[core]\n\tattributesFile = //host/share/x\n",
            "[mailmap]\n\tfile = :(optional)//host/x\n",
            "[core]\n\tbare = false\n\tbroken = \"x\n",
        ] {
            assert!(refuses(text), "{text:?}");
        }
        for text in [
            "[core]\n\tbare = false\n\tautocrlf = true\n",
            "[user]\n\tname = A\n\temail = a@example.invalid\n",
            "[remote \"origin\"]\n\turl = https://example.com/r.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            "[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n\trequired = true\n",
            "[branch \"main\"]\n\tremote = origin\n",
        ] {
            assert!(!refuses(text), "{text:?}");
        }
    }

    #[test]
    fn the_git_folder_check_is_bounded() {
        let dir = std::env::temp_dir().join(format!("orcel-git-folder-{}", std::process::id()));
        let heads = dir.join("refs").join("heads");
        std::fs::create_dir_all(&heads).expect("heads");
        for name in ["a", "b", "c"] {
            std::fs::write(heads.join(name), "x").expect("ref");
        }
        // refs/heads and its three entries.
        assert!(check_git_folder_within(&dir, 4).is_ok());
        assert!(check_git_folder_within(&dir, 3).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extensions_are_refused_whatever_their_case_or_place() {
        for text in [
            "[extensions]\n\trefStorage = files:///c/other/.git\n",
            "[Extensions]\n\tREFSTORAGE = reftable\n",
            "[extensions]\n\trefstorage = files\n\trefstorage = reftable\n",
            "[extensions.x]\n\tnoop = 1\n",
            "[extensions]\n\tunknown = 1\n",
            "[extensions]\n\tpartialClone = \n",
        ] {
            assert!(refuses(text), "{text:?}");
        }
        assert!(!refuses(
            "[extensions]\n\trefstorage = files\n\tworktreeConfig = TRUE\n\tpartialClone = my.origin-1\n"
        ));
        assert!(check_listed("local\0extensions.refstorage\nreftable\0").is_err());
        assert!(check_listed("worktree\0extensions.refstorage\nfiles:///x\0").is_err());
        assert!(check_listed("local\0extensions.refstorage\nfiles\0").is_ok());
    }

    #[test]
    fn git_listings_are_checked_with_the_same_rules() {
        assert!(check_listed("command\0core.pager\ncat\0local\0user.name\nA\0").is_ok());
        assert!(check_listed("local\0hook.evil.command\nx\0").is_err());
        assert!(check_listed("worktree\0Hook.Evil.Event\npost-index-change\0").is_err());
        assert!(check_listed("local\0core.excludesfile\n\\\\host\\share\\x\0").is_err());
    }
}
