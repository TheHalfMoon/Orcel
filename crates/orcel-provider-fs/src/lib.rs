use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

pub mod mutation;

const DEFAULT_MAX_READ_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_SEARCH_FILES: usize = 2_000;
const DEFAULT_MAX_SEARCH_RESULTS: usize = 200;
const MAX_SEARCH_FILE_BYTES: usize = 512 * 1024;
const MAX_WRITE_BYTES: usize = 2 * 1024 * 1024;
/// SG-000065 output bound for one directory listing. Entries are sorted by
/// name before truncation so the bounded result is deterministic.
pub const MAX_LIST_ENTRIES: usize = 5_000;

#[derive(Debug)]
pub struct ProviderError {
    pub code: FailureCode,
    pub message: String,
}

impl ProviderError {
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn io(context: &str, error: io::Error) -> Self {
        Self::new(
            FailureCode::ProviderUnavailable,
            format!("{context}: {error}"),
        )
    }
}

#[derive(Debug, Clone)]
pub struct WritePreview {
    pub relative: String,
    pub exists: bool,
    pub current_sha256: Option<String>,
    pub new_sha256: String,
    pub bytes: usize,
}

impl WritePreview {
    pub fn to_json(&self) -> Value {
        json!({
            "path": self.relative,
            "exists": self.exists,
            "current_sha256": self.current_sha256,
            "new_sha256": self.new_sha256,
            "bytes": self.bytes
        })
    }

    pub fn approval_digest(&self, workspace_id: &str, policy_revision: &str) -> String {
        let current = self.current_sha256.as_deref().unwrap_or("<missing>");
        sha256_hex(
            format!(
                "fs.write\n{}\n{}\n{}\n{}\n{}\n{}",
                workspace_id, policy_revision, self.relative, current, self.new_sha256, self.bytes
            )
            .as_bytes(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct FsProvider {
    root: PathBuf,
    max_read_bytes: usize,
}

impl FsProvider {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, ProviderError> {
        let root = resolve_final_path(root.as_ref())
            .map_err(|error| ProviderError::io("resolve workspace root", error))?;
        if !root.is_dir() {
            return Err(ProviderError::new(
                FailureCode::WorkspaceDenied,
                "workspace root is not a directory",
            ));
        }
        Ok(Self {
            root,
            max_read_bytes: DEFAULT_MAX_READ_BYTES,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Filesystem mutations must never create or change Git control data.
    /// Resolve each existing prefix, not only the submitted spelling: a link,
    /// junction, or Windows short-name alias can reach .git without naming it.
    /// This is a deny-only guard; typed git operations use their own provider.
    pub(crate) fn reject_git_mutation(&self, relative: &str) -> Result<(), ProviderError> {
        if self.root.components().any(|part| {
            matches!(part, Component::Normal(name)
                if name.to_string_lossy().eq_ignore_ascii_case(".git"))
        }) || is_git_dir(&self.root)
        {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "filesystem tools cannot mutate a Git metadata workspace",
            ));
        }
        let mut candidate = self.root.clone();
        let mut has_name = false;
        let mut missing_prefix = false;
        let parts = Path::new(relative).components().count();
        for (index, component) in Path::new(relative).components().enumerate() {
            let last = index + 1 == parts;
            let name = match component {
                Component::CurDir => continue,
                Component::Normal(name) => name,
                _ => {
                    return Err(ProviderError::new(
                        FailureCode::PathEscape,
                        "filesystem mutation requires a workspace-relative path",
                    ))
                }
            };
            has_name = true;
            let spelling = name.to_string_lossy();
            if spelling.eq_ignore_ascii_case(".git") {
                return Err(ProviderError::new(
                    FailureCode::CapabilityDenied,
                    "filesystem tools cannot mutate Git control paths",
                ));
            }
            #[cfg(windows)]
            if spelling.contains(':') || spelling.ends_with('.') || spelling.ends_with(' ') {
                return Err(ProviderError::new(
                    FailureCode::CapabilityDenied,
                    "Windows alternate streams and path aliases are not mutable",
                ));
            }

            candidate.push(name);
            if missing_prefix {
                // Still inspect every later spelling: newdir/.git/config is
                // prohibited even if newdir does not exist yet.
                continue;
            }
            // A link at the final name isn't followed here: create refuses any entry there,
            // and every other mutation checks the real path it opened before acting.
            if last
                && fs::symlink_metadata(&candidate)
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                continue;
            }
            match resolve_final_path(&candidate) {
                Ok(resolved) => self.ensure_not_git(&resolved)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing_prefix = true;
                }
                Err(error) => return Err(ProviderError::io("resolve mutation path", error)),
            }
        }
        if !has_name {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "workspace root cannot be a filesystem mutation target",
            ));
        }
        Ok(())
    }

    /// Refuses a resolved path that is Git control data: one with a part named `.git` inside
    /// the workspace, or one inside a directory Git itself takes for a Git directory (it holds
    /// `HEAD`, `objects` and `refs`), as a `--separate-git-dir` or bare repository is under any
    /// name. Mutations call it on each resolved prefix before acting, and again on the path an
    /// opened handle or new directory really has, so a link swapped in between is caught.
    pub(crate) fn ensure_not_git(&self, resolved: &Path) -> Result<(), ProviderError> {
        self.ensure_within(resolved)?;
        let inside = resolved.strip_prefix(&self.root).map_err(|_| {
            ProviderError::new(
                FailureCode::PathEscape,
                "resolved mutation path escaped the trusted workspace",
            )
        })?;
        let named = inside.components().any(|part| {
            matches!(part, Component::Normal(segment)
                if segment.to_string_lossy().eq_ignore_ascii_case(".git"))
        });
        if named
            || resolved
                .ancestors()
                .take(inside.components().count() + 1)
                .any(is_git_dir)
        {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "filesystem tools cannot mutate Git control paths",
            ));
        }
        Ok(())
    }

    pub fn stat(&self, relative: &str) -> Result<Value, ProviderError> {
        let resolved = self.resolve_existing(relative)?;
        let metadata =
            fs::metadata(&resolved).map_err(|error| ProviderError::io("stat target", error))?;
        Ok(json!({
            "path": relative,
            "kind": if metadata.is_dir() { "directory" } else if metadata.is_file() { "file" } else { "other" },
            "size": metadata.len(),
            "readonly": metadata.permissions().readonly()
        }))
    }

    pub fn list(&self, relative: &str) -> Result<Value, ProviderError> {
        let resolved = self.resolve_existing(relative)?;
        if !resolved.is_dir() {
            return Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "list target is not a directory",
            ));
        }

        let mut entries = Vec::new();
        let iterator =
            fs::read_dir(&resolved).map_err(|error| ProviderError::io("list directory", error))?;
        for entry in iterator {
            let entry = entry.map_err(|error| ProviderError::io("read directory entry", error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| ProviderError::io("read entry type", error))?;
            entries.push(json!({
                "name": entry.file_name().to_string_lossy(),
                "is_file": file_type.is_file(),
                "is_dir": file_type.is_dir(),
                "is_symlink": file_type.is_symlink()
            }));
        }
        entries.sort_by(|a, b| {
            a.get("name")
                .and_then(Value::as_str)
                .cmp(&b.get("name").and_then(Value::as_str))
        });
        let truncated = entries.len() > MAX_LIST_ENTRIES;
        entries.truncate(MAX_LIST_ENTRIES);

        Ok(json!({"path": relative, "entries": entries, "truncated": truncated}))
    }

    pub fn read_text(&self, relative: &str) -> Result<Value, ProviderError> {
        let bytes = self.read_bytes(relative, self.max_read_bytes)?;
        let size = bytes.len();
        let text = String::from_utf8(bytes).map_err(|_| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "fs.read supports UTF-8 text files only",
            )
        })?;

        Ok(json!({"path": relative, "text": text, "bytes": size}))
    }

    /// A regular file's bytes, through the verified open that keeps a read inside
    /// the workspace, at most `limit` of them.
    pub fn read_bytes(&self, relative: &str, limit: usize) -> Result<Vec<u8>, ProviderError> {
        let candidate = self.root.join(relative);
        let (file, resolved) = open_verified_file(&candidate)
            .map_err(|error| ProviderError::io("open file", error))?;
        self.ensure_within(&resolved)?;

        let metadata = file
            .metadata()
            .map_err(|error| ProviderError::io("read file metadata", error))?;
        if !metadata.is_file() {
            return Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "read target is not a regular file",
            ));
        }
        if metadata.len() > limit as u64 {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                format!("file exceeds {limit} byte read limit"),
            ));
        }

        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take((limit + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| ProviderError::io("read file", error))?;
        if bytes.len() > limit {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "file exceeded read limit while reading",
            ));
        }
        Ok(bytes)
    }

    pub fn preview_write(
        &self,
        relative: &str,
        content: &str,
    ) -> Result<WritePreview, ProviderError> {
        self.reject_git_mutation(relative)?;
        if content.len() > MAX_WRITE_BYTES {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "write content exceeds 2 MiB limit",
            ));
        }
        let candidate = self.root.join(relative);
        match OpenOptions::new().read(true).write(true).open(&candidate) {
            Ok(file) => {
                let resolved = final_path_from_open_file(&file, &candidate)
                    .map_err(|error| ProviderError::io("resolve write target", error))?;
                self.ensure_not_git(&resolved)?;
                refuse_linked(&file)?;
                let metadata = file
                    .metadata()
                    .map_err(|error| ProviderError::io("read write target metadata", error))?;
                if !metadata.is_file() {
                    return Err(ProviderError::new(
                        FailureCode::InvalidRequest,
                        "write target is not a regular file",
                    ));
                }
                let current = hash_file(file)?;
                Ok(WritePreview {
                    relative: relative.to_owned(),
                    exists: true,
                    current_sha256: Some(current),
                    new_sha256: sha256_hex(content.as_bytes()),
                    bytes: content.len(),
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let parent = candidate.parent().ok_or_else(|| {
                    ProviderError::new(FailureCode::InvalidRequest, "write target has no parent")
                })?;
                let resolved_parent = resolve_final_path(parent)
                    .map_err(|error| ProviderError::io("resolve write parent", error))?;
                self.ensure_within(&resolved_parent)?;
                Ok(WritePreview {
                    relative: relative.to_owned(),
                    exists: false,
                    current_sha256: None,
                    new_sha256: sha256_hex(content.as_bytes()),
                    bytes: content.len(),
                })
            }
            Err(error) => Err(ProviderError::io("open write target", error)),
        }
    }

    pub fn write_text(
        &self,
        relative: &str,
        content: &str,
        expected_current_sha256: Option<&str>,
        create_if_missing: bool,
    ) -> Result<Value, ProviderError> {
        self.reject_git_mutation(relative)?;
        if content.len() > MAX_WRITE_BYTES {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "write content exceeds 2 MiB limit",
            ));
        }

        let candidate = self.root.join(relative);
        match OpenOptions::new().read(true).write(true).open(&candidate) {
            Ok(mut file) => {
                let resolved = final_path_from_open_file(&file, &candidate)
                    .map_err(|error| ProviderError::io("resolve write target", error))?;
                self.ensure_not_git(&resolved)?;
                refuse_linked(&file)?;
                if !file
                    .metadata()
                    .map_err(|error| ProviderError::io("read write metadata", error))?
                    .is_file()
                {
                    return Err(ProviderError::new(
                        FailureCode::InvalidRequest,
                        "write target is not a regular file",
                    ));
                }
                let actual = hash_file(&file)?;
                let expected = expected_current_sha256.ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::TargetStale,
                        "existing file requires expected_current_sha256 from preview",
                    )
                })?;
                if actual != expected {
                    return Err(ProviderError::new(
                        FailureCode::TargetStale,
                        "target changed since preview",
                    ));
                }
                file.seek(SeekFrom::Start(0))
                    .map_err(|error| ProviderError::io("seek write target", error))?;
                file.set_len(0)
                    .map_err(|error| ProviderError::io("truncate write target", error))?;
                file.write_all(content.as_bytes())
                    .map_err(|error| ProviderError::io("write target", error))?;
                file.sync_data()
                    .map_err(|error| ProviderError::io("sync write target", error))?;
                Ok(json!({
                    "path": relative,
                    "created": false,
                    "bytes": content.len(),
                    "sha256": sha256_hex(content.as_bytes())
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !create_if_missing {
                    return Err(ProviderError::new(
                        FailureCode::TargetStale,
                        "target is missing and create_if_missing is false",
                    ));
                }
                if expected_current_sha256.is_some() {
                    return Err(ProviderError::new(
                        FailureCode::TargetStale,
                        "target disappeared since preview",
                    ));
                }
                self.create_text_verified(relative, content)
            }
            Err(error) => Err(ProviderError::io("open write target", error)),
        }
    }

    /// Create-only write (SG-000126): creates `relative` with `content` and
    /// never opens an existing file. An existing entry at the name, a link
    /// included, is refused as `TargetStale` without being opened.
    pub fn create_text(&self, relative: &str, content: &str) -> Result<Value, ProviderError> {
        if content.len() > MAX_WRITE_BYTES {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "write content exceeds 2 MiB limit",
            ));
        }
        self.create_text_verified(relative, content)
    }

    fn create_text_verified(&self, relative: &str, content: &str) -> Result<Value, ProviderError> {
        self.reject_git_mutation(relative)?;
        let candidate = self.root.join(relative);
        let parent = candidate.parent().ok_or_else(|| {
            ProviderError::new(FailureCode::InvalidRequest, "create target has no parent")
        })?;
        let before = resolve_final_path(parent)
            .map_err(|error| ProviderError::io("resolve create parent", error))?;
        self.ensure_within(&before)?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&candidate)
            .map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    ProviderError::new(FailureCode::TargetStale, "target already exists")
                } else {
                    ProviderError::io("create target", error)
                }
            })?;

        let resolved = final_path_from_open_file(&file, &candidate)
            .map_err(|error| ProviderError::io("resolve created target", error))?;
        if let Err(error) = self.ensure_not_git(&resolved) {
            let _ = file.set_len(0);
            drop(file);
            let _ = fs::remove_file(&resolved);
            return Err(error);
        }

        let after = resolve_final_path(parent)
            .map_err(|error| ProviderError::io("re-resolve create parent", error))?;
        if before != after {
            drop(file);
            let _ = fs::remove_file(&resolved);
            return Err(ProviderError::new(
                FailureCode::PathRaceDetected,
                "parent directory identity changed during create",
            ));
        }

        file.write_all(content.as_bytes())
            .map_err(|error| ProviderError::io("write created target", error))?;
        file.sync_data()
            .map_err(|error| ProviderError::io("sync created target", error))?;
        Ok(json!({
            "path": relative,
            "created": true,
            "bytes": content.len(),
            "sha256": sha256_hex(content.as_bytes())
        }))
    }

    pub fn search_text(
        &self,
        relative: &str,
        query: &str,
        requested_max_results: Option<usize>,
    ) -> Result<Value, ProviderError> {
        if query.is_empty() {
            return Err(ProviderError::new(
                FailureCode::InvalidRequest,
                "search query cannot be empty",
            ));
        }
        let max_results = requested_max_results
            .unwrap_or(DEFAULT_MAX_SEARCH_RESULTS)
            .clamp(1, DEFAULT_MAX_SEARCH_RESULTS);

        let start = self.resolve_existing(relative)?;
        let mut queue = VecDeque::new();
        queue.push_back(start);
        let mut scanned_files = 0usize;
        let mut matches = Vec::new();

        while let Some(path) = queue.pop_front() {
            if matches.len() >= max_results || scanned_files >= DEFAULT_MAX_SEARCH_FILES {
                break;
            }
            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.file_type().is_symlink() {
                continue;
            }

            if metadata.is_dir() {
                let entries = match fs::read_dir(&path) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let child = entry.path();
                    let file_type = match entry.file_type() {
                        Ok(file_type) => file_type,
                        Err(_) => continue,
                    };
                    if file_type.is_symlink() {
                        continue;
                    }
                    if file_type.is_dir() {
                        match resolve_final_path(&child) {
                            Ok(resolved_child) if is_within(&self.root, &resolved_child) => {
                                queue.push_back(resolved_child);
                            }
                            _ => {}
                        }
                    } else if file_type.is_file() {
                        queue.push_back(child);
                    }
                }
                continue;
            }

            if !metadata.is_file() {
                continue;
            }

            scanned_files += 1;
            if metadata.len() > MAX_SEARCH_FILE_BYTES as u64 {
                continue;
            }

            let (file, resolved) = match open_verified_file(&path) {
                Ok(opened) => opened,
                Err(_) => continue,
            };
            if !is_within(&self.root, &resolved) {
                continue;
            }

            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            if file
                .take((MAX_SEARCH_FILE_BYTES + 1) as u64)
                .read_to_end(&mut bytes)
                .is_err()
            {
                continue;
            }
            if bytes.len() > MAX_SEARCH_FILE_BYTES {
                continue;
            }
            let text = match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => continue,
            };

            for (index, line) in text.lines().enumerate() {
                if line.contains(query) {
                    let rel = resolved
                        .strip_prefix(&self.root)
                        .unwrap_or(&resolved)
                        .to_string_lossy()
                        .to_string();
                    matches.push(json!({
                        "path": rel,
                        "line": index + 1,
                        "text": truncate_line(line, 400)
                    }));
                    if matches.len() >= max_results {
                        break;
                    }
                }
            }
        }

        let truncated = matches.len() >= max_results || scanned_files >= DEFAULT_MAX_SEARCH_FILES;
        Ok(json!({
            "path": relative,
            "query": query,
            "matches": matches,
            "scanned_files": scanned_files,
            "truncated": truncated
        }))
    }

    fn resolve_existing(&self, relative: &str) -> Result<PathBuf, ProviderError> {
        let candidate = self.root.join(relative);
        let resolved = resolve_final_path(&candidate)
            .map_err(|error| ProviderError::io("resolve target", error))?;
        self.ensure_within(&resolved)?;
        Ok(resolved)
    }

    fn ensure_within(&self, resolved: &Path) -> Result<(), ProviderError> {
        if !is_within(&self.root, resolved) {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "resolved path is outside the trusted workspace",
            ));
        }
        Ok(())
    }
}

fn hash_file(mut file: impl Read + Seek) -> Result<String, ProviderError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| ProviderError::io("seek hash target", error))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| ProviderError::io("hash target", error))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_lower(&hasher.finalize()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_lower(&hasher.finalize())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn truncate_line(line: &str, max_chars: usize) -> String {
    let mut chars = line.chars();
    let mut output: String = chars.by_ref().take(max_chars).collect();
    if chars.next().is_some() {
        output.push('…');
    }
    output
}

fn open_verified_file(path: &Path) -> io::Result<(File, PathBuf)> {
    let file = File::open(path)?;
    let resolved = final_path_from_open_file(&file, path)?;
    Ok((file, resolved))
}

fn final_path_from_open_file(_file: &File, _path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        win::final_path_from_handle(_file.as_raw_handle())
    }
    #[cfg(not(windows))]
    {
        fs::canonicalize(_path)
    }
}

/// Whether Git would take `dir` for a Git directory, by the same test Git uses.
fn is_git_dir(dir: &Path) -> bool {
    dir.join("HEAD").is_file() && dir.join("objects").is_dir() && dir.join("refs").is_dir()
}

/// Refuses a file with more than one name: a write would also change the other names, which
/// could be Git control data or anything outside the workspace.
fn refuse_linked(file: &File) -> Result<(), ProviderError> {
    let links = link_count(file).map_err(|error| ProviderError::io("read link count", error))?;
    if links > 1 {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "a file with more than one hard link is not written",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn link_count(file: &File) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
fn link_count(file: &File) -> io::Result<u64> {
    use std::os::windows::io::AsRawHandle as _;
    win::link_count(file.as_raw_handle())
}

#[cfg(not(any(unix, windows)))]
fn link_count(_file: &File) -> io::Result<u64> {
    Ok(1)
}

fn resolve_final_path(path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        win::final_path(path)
    }
    #[cfg(not(windows))]
    {
        fs::canonicalize(path)
    }
}

#[cfg(windows)]
fn is_within(root: &Path, candidate: &Path) -> bool {
    fn key(path: &Path) -> String {
        path.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase()
    }
    let root = key(root);
    let candidate = key(candidate);
    candidate == root || candidate.starts_with(&(root + "\\"))
}

#[cfg(not(windows))]
fn is_within(root: &Path, candidate: &Path) -> bool {
    candidate == root || candidate.starts_with(root)
}

#[cfg(windows)]
mod win {
    use super::*;
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::RawHandle;

    type Handle = *mut c_void;

    #[repr(C)]
    #[derive(Default)]
    pub(super) struct ByHandleFileInformation {
        attributes: u32,
        creation: [u32; 2],
        access: [u32; 2],
        write: [u32; 2],
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        links: u32,
        index_high: u32,
        index_low: u32,
    }

    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_RENAME_INFO_CLASS: u32 = 3;

    /// `FILE_RENAME_INFO`; the name follows `length` in the same allocation.
    #[repr(C)]
    struct FileRenameInfo {
        flags: u32,
        root: Handle,
        length: u32,
        name: [u16; 1],
    }

    /// One entry opened for renaming. The rename, the check of where it really went and any
    /// move back all act on this handle, so they can only ever move this entry, whatever a
    /// path has been swapped to in between.
    pub(crate) struct RenameHandle(OwnedHandle);

    /// Opens the entry at `path` itself (a link is opened, not followed) for renaming.
    pub(crate) fn open_for_rename(path: &Path) -> io::Result<RenameHandle> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a NUL-terminated path that outlives the call; no security
        // attributes or template are passed.
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(RenameHandle(OwnedHandle(raw)))
    }

    impl RenameHandle {
        /// Whether the opened entry is itself a link, junction or other reparse point.
        pub(crate) fn is_reparse_point(&self) -> io::Result<bool> {
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            let mut info = ByHandleFileInformation::default();
            // SAFETY: the handle is open for this call, and `info` is a properly sized,
            // writable BY_HANDLE_FILE_INFORMATION.
            if unsafe { GetFileInformationByHandle(self.0 .0, &mut info) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0)
        }

        /// Where the entry is now.
        pub(crate) fn final_path(&self) -> io::Result<PathBuf> {
            final_path_from_handle(self.0 .0 as RawHandle)
        }

        /// Renames the entry to the absolute path `to`, never replacing an existing entry.
        pub(crate) fn rename_no_replace(&self, to: &Path) -> io::Result<()> {
            let name: Vec<u16> = to.as_os_str().encode_wide().collect();
            let offset = std::mem::offset_of!(FileRenameInfo, name);
            let total = offset + (name.len() + 1) * 2;
            // u64 storage keeps the struct's 8-byte alignment.
            let mut storage = vec![0u64; total.div_ceil(8)];
            let base = storage.as_mut_ptr().cast::<u8>();
            // SAFETY: `storage` is zeroed, aligned for FileRenameInfo and at least `total`
            // bytes: the header up to `name`, then the name and a NUL. Only those bytes are
            // written, and the buffer outlives the call that reads it.
            unsafe {
                let info = base.cast::<FileRenameInfo>();
                std::ptr::addr_of_mut!((*info).flags).write(0); // never replace
                std::ptr::addr_of_mut!((*info).root).write(std::ptr::null_mut());
                std::ptr::addr_of_mut!((*info).length).write((name.len() * 2) as u32);
                std::ptr::copy_nonoverlapping(
                    name.as_ptr().cast::<u8>(),
                    base.add(offset),
                    name.len() * 2,
                );
                if SetFileInformationByHandle(
                    self.0 .0,
                    FILE_RENAME_INFO_CLASS,
                    base.cast::<c_void>(),
                    total as u32,
                ) == 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        }
    }

    /// The number of names the open file has.
    pub(super) fn link_count(handle: RawHandle) -> io::Result<u64> {
        let mut info = ByHandleFileInformation::default();
        // SAFETY: `handle` is an open file handle owned by the caller for this call, and
        // `info` is a properly sized, writable BY_HANDLE_FILE_INFORMATION.
        if unsafe { GetFileInformationByHandle(handle as Handle, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(u64::from(info.links))
    }
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_SHARE_READ: u32 = 0x00000001;
    const FILE_SHARE_WRITE: u32 = 0x00000002;
    const FILE_SHARE_DELETE: u32 = 0x00000004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
    const VOLUME_NAME_DOS: u32 = 0x0;
    const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share_mode: u32,
            security: *mut c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn GetFinalPathNameByHandleW(file: Handle, path: *mut u16, size: u32, flags: u32) -> u32;
        fn GetFileInformationByHandle(file: Handle, info: *mut ByHandleFileInformation) -> i32;
        fn SetFileInformationByHandle(
            file: Handle,
            class: u32,
            info: *const c_void,
            size: u32,
        ) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
    }

    struct OwnedHandle(Handle);
    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub fn final_path(path: &Path) -> io::Result<PathBuf> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        let handle = OwnedHandle(raw);
        final_path_from_handle(handle.0)
    }

    pub fn final_path_from_handle(handle: RawHandle) -> io::Result<PathBuf> {
        let handle = handle as Handle;
        let required =
            unsafe { GetFinalPathNameByHandleW(handle, std::ptr::null_mut(), 0, VOLUME_NAME_DOS) };
        if required == 0 {
            return Err(io::Error::last_os_error());
        }

        // The path can grow between the size query and the read (a folder renamed meanwhile);
        // then the call returns the size it needs and fills nothing, so ask again.
        let mut size = required as usize + 1;
        let mut buffer;
        let mut attempts = 0;
        loop {
            buffer = vec![0u16; size];
            let written = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    VOLUME_NAME_DOS,
                )
            };
            if written == 0 {
                return Err(io::Error::last_os_error());
            }
            if (written as usize) < buffer.len() {
                buffer.truncate(written as usize);
                break;
            }
            attempts += 1;
            if attempts > 8 {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "the path kept changing while it was read",
                ));
            }
            size = written as usize + 1;
        }
        let value = String::from_utf16(&buffer)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-16 path"))?;
        let normalized = value
            .strip_prefix(r"\\?\UNC\")
            .map(|rest| format!(r"\\{rest}"))
            .or_else(|| value.strip_prefix(r"\\?\").map(ToOwned::to_owned))
            .unwrap_or(value);
        Ok(PathBuf::from(normalized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let root = std::env::temp_dir().join(format!("orcel-fs-{name}-{suffix}"));
        fs::create_dir_all(&root).expect("create temp root");
        root
    }

    #[test]
    fn sg126_create_text_never_opens_an_existing_entry() {
        let root = temp_root("create-only");
        let outside = temp_root("create-only-outside");
        fs::create_dir_all(root.join("reports")).unwrap();
        let provider = FsProvider::new(&root).unwrap();
        let created = provider.create_text("reports/new.md", "fresh").unwrap();
        assert_eq!(created["created"], true);
        assert_eq!(fs::read(root.join("reports/new.md")).unwrap(), b"fresh");
        // An existing file is refused without being opened or changed.
        let refused = provider.create_text("reports/new.md", "other").unwrap_err();
        assert_eq!(refused.code, FailureCode::TargetStale);
        assert_eq!(fs::read(root.join("reports/new.md")).unwrap(), b"fresh");
        // A link at the name is refused too, even a dangling one, and its
        // target is never created or written.
        #[cfg(unix)]
        {
            fs::write(outside.join("theirs"), "theirs").unwrap();
            std::os::unix::fs::symlink(outside.join("theirs"), root.join("reports/l.md")).unwrap();
            std::os::unix::fs::symlink(outside.join("absent"), root.join("reports/d.md")).unwrap();
            for name in ["reports/l.md", "reports/d.md"] {
                let refused = provider.create_text(name, "x").unwrap_err();
                assert_eq!(refused.code, FailureCode::TargetStale, "{name}");
            }
            assert_eq!(fs::read(outside.join("theirs")).unwrap(), b"theirs");
            assert!(!outside.join("absent").exists());
        }
        let big = "x".repeat(MAX_WRITE_BYTES + 1);
        assert_eq!(
            provider
                .create_text("reports/big.md", &big)
                .unwrap_err()
                .code,
            FailureCode::OutputLimit
        );
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn approval_digest_binds_workspace_and_policy_revision() {
        let preview = WritePreview {
            relative: "a.txt".into(),
            exists: true,
            current_sha256: Some("current".into()),
            new_sha256: "next".into(),
            bytes: 4,
        };
        let base = preview.approval_digest("workspace-a", "policy-1");
        assert_ne!(base, preview.approval_digest("workspace-b", "policy-1"));
        assert_ne!(base, preview.approval_digest("workspace-a", "policy-2"));
    }

    #[test]
    fn directory_listing_is_bounded_sorted_and_reports_truncation() {
        let root = temp_root("list-bound");
        for index in 0..=MAX_LIST_ENTRIES {
            fs::write(root.join(format!("f{index:05}.txt")), "").unwrap();
        }
        let provider = FsProvider::new(&root).unwrap();
        let listing = provider.list(".").unwrap();
        let entries = listing["entries"].as_array().unwrap();
        assert_eq!(entries.len(), MAX_LIST_ENTRIES);
        assert_eq!(listing["truncated"], true);
        assert_eq!(entries[0]["name"], "f00000.txt");
        assert_eq!(entries[MAX_LIST_ENTRIES - 1]["name"], "f04999.txt");
        fs::remove_file(root.join("f05000.txt")).unwrap();
        let listing = provider.list(".").unwrap();
        assert_eq!(listing["truncated"], false);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn writes_existing_file_only_when_expected_hash_matches() {
        let root = temp_root("write-existing");
        fs::write(root.join("a.txt"), "old").unwrap();
        let provider = FsProvider::new(&root).unwrap();
        let preview = provider.preview_write("a.txt", "new").unwrap();
        let result = provider
            .write_text("a.txt", "new", preview.current_sha256.as_deref(), false)
            .unwrap();
        assert_eq!(result["created"], false);
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "new");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn refuses_stale_existing_file() {
        let root = temp_root("write-stale");
        fs::write(root.join("a.txt"), "old").unwrap();
        let provider = FsProvider::new(&root).unwrap();
        let preview = provider.preview_write("a.txt", "new").unwrap();
        fs::write(root.join("a.txt"), "changed").unwrap();
        let error = provider
            .write_text("a.txt", "new", preview.current_sha256.as_deref(), false)
            .unwrap_err();
        assert_eq!(error.code, FailureCode::TargetStale);
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "changed");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn creates_missing_file_only_when_explicitly_allowed() {
        let root = temp_root("create");
        let provider = FsProvider::new(&root).unwrap();
        let preview = provider.preview_write("new.txt", "hello").unwrap();
        assert!(!preview.exists);
        provider.write_text("new.txt", "hello", None, true).unwrap();
        assert_eq!(fs::read_to_string(root.join("new.txt")).unwrap(), "hello");
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn write_symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;
        let root = temp_root("symlink");
        let outside = temp_root("outside");
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        symlink(outside.join("secret.txt"), root.join("link.txt")).unwrap();
        let provider = FsProvider::new(&root).unwrap();
        let error = provider.preview_write("link.txt", "oops").unwrap_err();
        assert_eq!(error.code, FailureCode::PathEscape);
        assert_eq!(
            fs::read_to_string(outside.join("secret.txt")).unwrap(),
            "secret"
        );
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[cfg(unix)]
    fn link_directory(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).expect("create directory symlink");
    }

    #[cfg(windows)]
    fn link_directory(target: &Path, link: &Path) {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .stdout(std::process::Stdio::null())
            .status()
            .expect("run mklink");
        assert!(status.success(), "create directory junction");
    }

    #[test]
    fn sg000041_reparse_point_into_protected_state_is_denied_for_read_and_write() {
        let root = temp_root("sg41-workspace");
        let protected = temp_root("sg41-protected");
        fs::write(protected.join("trust.jsonl"), "protected").unwrap();
        link_directory(&protected, &root.join("state"));
        let provider = FsProvider::new(&root).unwrap();

        let read = provider.read_text("state/trust.jsonl").unwrap_err();
        assert_eq!(read.code, FailureCode::PathEscape);
        let write = provider
            .preview_write("state/trust.jsonl", "forged")
            .unwrap_err();
        assert_eq!(write.code, FailureCode::PathEscape);
        let create = provider
            .write_text("state/new.jsonl", "forged", None, true)
            .unwrap_err();
        assert_eq!(create.code, FailureCode::PathEscape);
        assert_eq!(
            fs::read_to_string(protected.join("trust.jsonl")).unwrap(),
            "protected"
        );
        assert!(!protected.join("new.jsonl").exists());

        let _ = fs::remove_dir(root.join("state"));
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(protected);
    }
}
