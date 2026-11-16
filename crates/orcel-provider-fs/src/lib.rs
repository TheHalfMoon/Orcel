use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

pub mod mutation;
#[cfg(test)]
mod stream_tests;

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
        refuse_named_fork(relative)?;
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
        refuse_windows_stream(relative)?;
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
            // Streams and device names were already refused by `refuse_windows_stream`
            // above; the recogniser stays here as defence in depth beside the alias rules.
            #[cfg(windows)]
            if is_windows_stream_or_device(&spelling)
                || spelling.ends_with('.')
                || spelling.ends_with(' ')
            {
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
        let inside = inside_root(&self.root, resolved).ok_or_else(|| {
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
        refuse_named_fork(relative)?;
        refuse_windows_stream(relative)?;
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
            remove_created(file, &resolved);
            return Err(error);
        }

        let after = resolve_final_path(parent)
            .map_err(|error| ProviderError::io("re-resolve create parent", error))?;
        if before != after {
            remove_created(file, &resolved);
            return Err(ProviderError::new(
                FailureCode::PathRaceDetected,
                "parent directory identity changed during create",
            ));
        }

        file.write_all(content.as_bytes())
            .map_err(|error| ProviderError::io("write created target", error))?;
        // The directory holding the new file could have been moved into Git data after the
        // check above. The file is read back from its own descriptor, so a move is seen.
        // On a refusal the content is truncated through the descriptor first; the emptied file
        // is then removed where it now is, only if that name still holds it.
        let refusal = match final_path_from_open_file(&file, &candidate) {
            Ok(path) => self
                .ensure_not_git(&path)
                .err()
                .map(|error| (error, Some(path))),
            Err(error) => Some((ProviderError::io("resolve written target", error), None)),
        };
        if let Some((error, path)) = refusal {
            let _ = file.set_len(0);
            match path {
                Some(path) => remove_created(file, &path),
                None => drop(file),
            }
            return Err(error);
        }
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
                            Ok(resolved_child) if self.ensure_within(&resolved_child).is_ok() => {
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
            if self.ensure_within(&resolved).is_err() {
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
        refuse_named_fork(relative)?;
        refuse_windows_stream(relative)?;
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
        // A link or junction inside the workspace can lead to a stream that the submitted
        // spelling never names, so the real path is checked as well as the request.
        if cfg!(windows) && resolved_names_stream(resolved) {
            return Err(windows_stream_refusal());
        }
        // Every resolved or descriptor path passes here, so a link to a named fork is
        // refused even though its own name is plain.
        refuse_named_fork(resolved)
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

/// Windows reaches data that a listing never shows through a colon in a path segment: an
/// NTFS alternate data stream or attribute (`a.txt:s`, `a.txt::$DATA`, `a.txt:s:$DATA`,
/// `dir:$I30:$INDEX_ALLOCATION`). A reserved device name (`NUL`, `con.txt`, `COM1`,
/// `CONIN$`) opens a device instead of a workspace file. Case does not matter to either. A
/// drive letter is not a segment (`C:\ws` parses as a prefix), so it is never matched here.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_windows_stream_or_device(segment: &str) -> bool {
    if segment.contains(':') {
        return true;
    }
    let stem = segment
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    match stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
    {
        Some(number) => {
            let mut chars = number.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        }
        None => false,
    }
}

/// Whether a submitted path names a stream or device in any segment.
#[cfg_attr(not(windows), allow(dead_code))]
fn names_windows_stream(path: &Path) -> bool {
    path.components().any(|part| {
        matches!(part, Component::Normal(name)
            if is_windows_stream_or_device(&name.to_string_lossy()))
    })
}

/// Whether a submitted path is drive-relative (`a:s` or `C:x`, which Windows parses as a
/// path on drive `A:` or `C:`, never a workspace entry). An absolute path such as
/// `C:\ws\a.txt` has a root after its drive prefix and is left to the containment check.
#[cfg_attr(not(windows), allow(dead_code))]
fn is_drive_relative(path: &Path) -> bool {
    matches!(path.components().next(), Some(Component::Prefix(_))) && !path.has_root()
}

/// Whether a resolved (final) path reaches a stream: a colon in any segment after the
/// drive or volume prefix. Device names are not matched, since a real path only ever names
/// a file the volume holds.
#[cfg_attr(not(windows), allow(dead_code))]
fn resolved_names_stream(resolved: &Path) -> bool {
    resolved
        .components()
        .any(|part| matches!(part, Component::Normal(name) if name.to_string_lossy().contains(':')))
}

fn windows_stream_refusal() -> ProviderError {
    ProviderError::new(
        FailureCode::CapabilityDenied,
        "Windows alternate data streams and device names are not reachable through filesystem tools",
    )
}

/// Refuses, on Windows, a path that names an alternate data stream or a device instead of a
/// workspace entry (CapabilityDenied), or that is drive-relative (PathEscape, the code a
/// mutation always gave it). Every read-side entry point calls it before it opens or
/// resolves anything, as `reject_git_mutation` does for every mutation, and both refuse a
/// resolved path that reaches a stream in `ensure_within`. Elsewhere `:` is an ordinary file
/// name byte, so the guard does nothing.
pub(crate) fn refuse_windows_stream(relative: &str) -> Result<(), ProviderError> {
    if !cfg!(windows) {
        return Ok(());
    }
    let path = Path::new(relative);
    if is_drive_relative(path) {
        return Err(ProviderError::new(
            FailureCode::PathEscape,
            "a drive-relative path never names a workspace entry",
        ));
    }
    if names_windows_stream(path) {
        return Err(windows_stream_refusal());
    }
    Ok(())
}

fn open_verified_file(path: &Path) -> io::Result<(File, PathBuf)> {
    let file = File::open(path)?;
    let resolved = final_path_from_open_file(&file, path)?;
    Ok((file, resolved))
}

/// The real path of an open file, read from its handle (Windows) or descriptor (Linux,
/// macOS) rather than by resolving a path again, so a link swapped in or out after the
/// open can't change the answer. Elsewhere it falls back to resolving `path`.
pub fn open_file_final_path(file: &File, path: &Path) -> io::Result<PathBuf> {
    final_path_from_open_file(file, path)
}

fn final_path_from_open_file(_file: &File, _path: &Path) -> io::Result<PathBuf> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        win::final_path_from_handle(_file.as_raw_handle())
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix_fd::final_path(_file)
    }
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    {
        fs::canonicalize(_path)
    }
}

/// The real path of an open file, read from its descriptor rather than by resolving a path
/// again, so a link swapped in after the open can't change the answer.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix_fd {
    use std::fs::File;
    use std::io;
    use std::path::PathBuf;

    /// Linux: `/proc/self/fd/<fd>` names the open file's current path. An unlinked file reads
    /// as `<path> (deleted)` and a non-file descriptor as `type:[inode]`; both fail closed, as
    /// does a missing `/proc`.
    #[cfg(target_os = "linux")]
    pub(super) fn final_path(file: &File) -> io::Result<PathBuf> {
        use std::os::fd::AsRawFd as _;
        let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
        checked(path, b" (deleted)")
    }

    /// macOS: `fcntl(F_GETPATH)` writes the open file's current path into a `MAXPATHLEN` buffer.
    #[cfg(target_os = "macos")]
    pub(super) fn final_path(file: &File) -> io::Result<PathBuf> {
        use std::os::fd::AsRawFd as _;
        let mut buffer = vec![0u8; libc::PATH_MAX as usize];
        // SAFETY: the descriptor is open for the lifetime of `file`, and F_GETPATH writes at
        // most MAXPATHLEN (PATH_MAX) bytes, NUL included, into the buffer of that size.
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error());
        }
        let length = buffer.iter().position(|byte| *byte == 0).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "F_GETPATH returned no NUL")
        })?;
        buffer.truncate(length);
        use std::os::unix::ffi::OsStringExt as _;
        let path = checked(PathBuf::from(std::ffi::OsString::from_vec(buffer)), b"")?;
        same_object(file, &path)?;
        Ok(path)
    }

    /// macOS: the reported path must name the open object itself (same device and inode).
    /// A named fork opened through a link (`link -> file/..namedfork/rsrc`) is a different
    /// object from the file its path may name, and a path renamed away in between no longer
    /// names it; both fail closed.
    #[cfg(target_os = "macos")]
    fn same_object(file: &File, path: &std::path::Path) -> io::Result<()> {
        use std::os::unix::fs::MetadataExt as _;
        let open = file.metadata()?;
        let named = std::fs::metadata(path)?;
        if open.dev() != named.dev() || open.ino() != named.ino() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the open file is not the object its path names ({})",
                    path.display()
                ),
            ));
        }
        Ok(())
    }

    /// Only an absolute path counts, and on Linux not one that names an unlinked file.
    fn checked(path: PathBuf, unlinked_suffix: &[u8]) -> io::Result<PathBuf> {
        use std::os::unix::ffi::OsStrExt as _;
        let bytes = path.as_os_str().as_bytes();
        if !path.is_absolute() || (!unlinked_suffix.is_empty() && bytes.ends_with(unlinked_suffix))
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("the open file has no usable path ({})", path.display()),
            ));
        }
        Ok(path)
    }
}

/// Removes a file this call created and is refusing. Off Windows the name is removed only while
/// it still names the open file (same device and inode), so a file put there by someone else
/// after an unlink is left alone; a swap in the instant between that check and the removal
/// remains. On Windows the name is removed after the handle closes, as before; a file swapped in
/// at that name in between could be removed instead.
fn remove_created(file: File, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let same = match (file.metadata(), fs::symlink_metadata(path)) {
            (Ok(open), Ok(named)) => open.dev() == named.dev() && open.ino() == named.ino(),
            _ => false,
        };
        if same {
            let _ = fs::remove_file(path);
        }
        drop(file);
    }
    #[cfg(not(unix))]
    {
        drop(file);
        let _ = fs::remove_file(path);
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
    inside_root(root, candidate).is_some()
}

/// The part of the resolved `candidate` below the resolved `root`, or `None` when the
/// candidate is not the root or inside it. Windows keeps the plain component prefix it
/// always used (after its own case-insensitive `is_within`).
#[cfg(windows)]
pub(crate) fn inside_root(root: &Path, candidate: &Path) -> Option<PathBuf> {
    candidate.strip_prefix(root).ok().map(Path::to_path_buf)
}

/// The part of the resolved `candidate` below the resolved `root`, or `None` when the
/// candidate is not the root or inside it. A byte-for-byte component prefix always counts
/// (equal bytes name the same directory on any volume). On macOS a case-insensitive volume
/// can also report the root in another case, so a prefix that differs only in case counts
/// too, but only when it is the very same directory as the root (same device and inode).
/// Case folding alone would be wrong on a case-sensitive APFS volume, where `WS` and `ws`
/// are two different directories.
#[cfg(not(windows))]
pub(crate) fn inside_root(root: &Path, candidate: &Path) -> Option<PathBuf> {
    if let Ok(rest) = candidate.strip_prefix(root) {
        return Some(rest.to_path_buf());
    }
    #[cfg(target_os = "macos")]
    {
        case_alias_inside_root(root, candidate)
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The identity check behind macOS case aliases of the root, kept on every Unix so a
/// case-sensitive volume (Linux CI) proves it never accepts a different directory.
#[cfg(unix)]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn case_alias_inside_root(root: &Path, candidate: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::MetadataExt as _;
    let root_parts: Vec<Component<'_>> = root.components().collect();
    let candidate_parts: Vec<Component<'_>> = candidate.components().collect();
    if !root.is_absolute() || candidate_parts.len() < root_parts.len() {
        return None;
    }
    let (head, tail) = candidate_parts.split_at(root_parts.len());
    let same_spelling_ignoring_case = head.iter().zip(&root_parts).all(|(alias, real)| {
        match (alias.as_os_str().to_str(), real.as_os_str().to_str()) {
            (Some(alias), Some(real)) => alias.to_lowercase() == real.to_lowercase(),
            _ => alias == real,
        }
    });
    if !same_spelling_ignoring_case {
        return None;
    }
    let prefix: PathBuf = head.iter().collect();
    // Not followed: a link in place of the root's last part is never the root itself.
    let alias = fs::symlink_metadata(&prefix).ok()?;
    let real = fs::symlink_metadata(root).ok()?;
    if !alias.is_dir() || alias.dev() != real.dev() || alias.ino() != real.ino() {
        return None;
    }
    Some(tail.iter().collect())
}

/// macOS reaches a file's resource fork, and any other named fork, through a
/// `..namedfork` segment (`file/..namedfork/rsrc`): a second data stream behind a name a
/// listing never shows, the analogue of a Windows alternate stream. Refused in any ASCII
/// case, since a case-insensitive volume may match it either way.
fn has_named_fork_segment(path: impl AsRef<Path>) -> bool {
    path.as_ref().components().any(|part| {
        matches!(part, Component::Normal(name)
            if name.as_encoded_bytes().eq_ignore_ascii_case(b"..namedfork"))
    })
}

/// Refuses a `..namedfork` segment on macOS, in a submitted relative path or in a resolved
/// one (a link already in the workspace can point at `file/..namedfork/rsrc`, so the
/// submitted spelling alone is not enough). Elsewhere `..namedfork` is an ordinary file
/// name, so the guard does nothing there (Windows and Linux behaviour is unchanged).
pub(crate) fn refuse_named_fork(path: impl AsRef<Path>) -> Result<(), ProviderError> {
    if cfg!(target_os = "macos") && has_named_fork_segment(path) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "macOS named forks (..namedfork) are not reachable through filesystem tools",
        ));
    }
    Ok(())
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

    /// Opens the directory at `path` itself (a junction is opened, not followed) to pin it:
    /// directory-list access with no `FILE_SHARE_DELETE` makes NTFS refuse to rename or delete
    /// it, or any directory above it, while the handle is open. Entries can still be created
    /// inside it.
    pub(crate) fn pin_directory(path: &Path) -> io::Result<RenameHandle> {
        const FILE_LIST_DIRECTORY: u32 = 0x0001;
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
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
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

    const FILE_DISPOSITION_INFO_CLASS: u32 = 4;
    const FILE_DISPOSITION_INFO_EX_CLASS: u32 = 21;

    impl RenameHandle {
        /// The volume and file id of the opened entry, which name it whatever its path.
        pub(crate) fn file_id(&self) -> io::Result<(u64, u128)> {
            file_id(self.0 .0 as RawHandle)
        }

        /// Whether the opened entry is a directory.
        pub(crate) fn is_directory(&self) -> io::Result<bool> {
            const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
            let mut info = ByHandleFileInformation::default();
            // SAFETY: the handle is open for this call, and `info` is a properly sized,
            // writable BY_HANDLE_FILE_INFORMATION.
            if unsafe { GetFileInformationByHandle(self.0 .0, &mut info) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(info.attributes & FILE_ATTRIBUTE_DIRECTORY != 0)
        }

        /// Marks the entry to be deleted when this handle closes, or clears that mark. A
        /// directory that isn't empty is refused here. POSIX semantics are asked for first,
        /// as `DeleteFileW` uses since Windows 10 1903: the name goes when this handle closes
        /// even while another process (an indexer, say) holds the file open. Where the file
        /// system doesn't support that, the classic mark is used.
        pub(crate) fn set_delete_on_close(&self, delete: bool) -> io::Result<()> {
            const FILE_DISPOSITION_DELETE: u32 = 0x1;
            const FILE_DISPOSITION_POSIX_SEMANTICS: u32 = 0x2;
            let flags: u32 = if delete {
                FILE_DISPOSITION_DELETE | FILE_DISPOSITION_POSIX_SEMANTICS
            } else {
                0
            };
            // SAFETY: the handle is open with DELETE access, and `flags` is a four-byte
            // FILE_DISPOSITION_INFO_EX that outlives the call.
            let ex = unsafe {
                SetFileInformationByHandle(
                    self.0 .0,
                    FILE_DISPOSITION_INFO_EX_CLASS,
                    (&flags as *const u32).cast::<c_void>(),
                    4,
                )
            };
            if ex != 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            const ERROR_INVALID_PARAMETER: i32 = 87;
            const ERROR_NOT_SUPPORTED: i32 = 50;
            const ERROR_INVALID_FUNCTION: i32 = 1;
            if !matches!(
                error.raw_os_error(),
                Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION)
            ) {
                return Err(error);
            }
            // FILE_DISPOSITION_INFO is a single BOOLEAN.
            let info: u8 = u8::from(delete);
            // SAFETY: as above; `info` is a one-byte FILE_DISPOSITION_INFO.
            if unsafe {
                SetFileInformationByHandle(
                    self.0 .0,
                    FILE_DISPOSITION_INFO_CLASS,
                    (&info as *const u8).cast::<c_void>(),
                    1,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    /// `FILE_ID_INFO`: a 64-bit volume serial number and a 128-bit file id.
    #[repr(C)]
    #[derive(Default)]
    struct FileIdInfo {
        volume_serial: u64,
        file_id: [u8; 16],
    }

    const FILE_ID_INFO_CLASS: u32 = 18;

    /// The volume serial number and 128-bit file id of an open handle (`FILE_ID_INFO`), which
    /// ReFS needs: its ids don't fit the 64-bit index. A file system that doesn't support that
    /// class (the same codes `set_delete_on_close` treats as unsupported) gets the 32-bit serial
    /// and 64-bit index instead; one volume always answers the same way, so ids from it stay
    /// comparable.
    pub(crate) fn file_id(handle: RawHandle) -> io::Result<(u64, u128)> {
        let mut ex = FileIdInfo::default();
        // SAFETY: `handle` is an open handle owned by the caller for this call, and `ex` is a
        // properly sized, writable FILE_ID_INFO.
        let read = unsafe {
            GetFileInformationByHandleEx(
                handle as Handle,
                FILE_ID_INFO_CLASS,
                (&mut ex as *mut FileIdInfo).cast::<c_void>(),
                std::mem::size_of::<FileIdInfo>() as u32,
            )
        };
        if read != 0 {
            return Ok((ex.volume_serial, u128::from_le_bytes(ex.file_id)));
        }
        let error = io::Error::last_os_error();
        const ERROR_INVALID_PARAMETER: i32 = 87;
        const ERROR_NOT_SUPPORTED: i32 = 50;
        const ERROR_INVALID_FUNCTION: i32 = 1;
        if !matches!(
            error.raw_os_error(),
            Some(ERROR_INVALID_PARAMETER | ERROR_NOT_SUPPORTED | ERROR_INVALID_FUNCTION)
        ) {
            return Err(error);
        }
        let mut info = ByHandleFileInformation::default();
        // SAFETY: `handle` is an open handle owned by the caller for this call, and `info` is
        // a properly sized, writable BY_HANDLE_FILE_INFORMATION.
        if unsafe { GetFileInformationByHandle(handle as Handle, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((
            u64::from(info.volume_serial),
            u128::from((u64::from(info.index_high) << 32) | u64::from(info.index_low)),
        ))
    }

    /// Opens the entry at `path` itself (a link is opened, not followed) only to read its
    /// attributes and id. Its own type, so nothing can rename or delete through it.
    pub(crate) fn open_for_identity(path: &Path) -> io::Result<IdentityHandle> {
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
                FILE_READ_ATTRIBUTES,
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
        Ok(IdentityHandle(OwnedHandle(raw)))
    }

    /// One entry opened with attribute access only: it can be identified, never renamed or
    /// deleted.
    pub(crate) struct IdentityHandle(OwnedHandle);

    impl IdentityHandle {
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

        /// The volume and file id of the opened entry.
        pub(crate) fn file_id(&self) -> io::Result<(u64, u128)> {
            file_id(self.0 .0 as RawHandle)
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
        fn GetFileInformationByHandleEx(
            file: Handle,
            class: u32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
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

    /// The real path comes from the open descriptor: a directory renamed after the open, or a
    /// link the file was opened through, can't make it report a stale or link path.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn the_path_of_an_open_file_comes_from_its_descriptor() {
        let root = fs::canonicalize(temp_root("fd-path")).unwrap();
        fs::create_dir(root.join("before")).unwrap();
        fs::write(root.join("before/a.txt"), "a").unwrap();
        let file = File::open(root.join("before/a.txt")).unwrap();
        assert_eq!(
            final_path_from_open_file(&file, &root.join("before/a.txt")).unwrap(),
            root.join("before/a.txt")
        );
        // Moved after the open: the old path is gone, the descriptor reports the new one.
        fs::rename(root.join("before"), root.join("after")).unwrap();
        assert_eq!(
            final_path_from_open_file(&file, &root.join("before/a.txt")).unwrap(),
            root.join("after/a.txt")
        );
        // Opened through a directory link: the real path, not the link's.
        std::os::unix::fs::symlink(root.join("after"), root.join("link")).unwrap();
        let through = File::open(root.join("link/a.txt")).unwrap();
        assert_eq!(
            final_path_from_open_file(&through, &root.join("link/a.txt")).unwrap(),
            root.join("after/a.txt")
        );
        // Linux: an unlinked file has no usable path, so it fails closed.
        #[cfg(target_os = "linux")]
        {
            fs::remove_file(root.join("after/a.txt")).unwrap();
            assert!(final_path_from_open_file(&file, &root.join("after/a.txt")).is_err());
        }
        let _ = fs::remove_dir_all(root);
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

    /// Pins the containment decision each OS family had before MAC-M1-06 for paths that
    /// involve no filesystem lookup: Windows folds case and both separators, and its
    /// remainder is the plain component prefix; elsewhere a byte-for-byte prefix counts.
    #[test]
    fn containment_decisions_are_unchanged_for_plain_prefixes() {
        #[cfg(windows)]
        {
            let root = Path::new(r"C:\ws");
            assert!(is_within(root, Path::new(r"C:\ws")));
            assert!(is_within(root, Path::new(r"C:\WS\a.txt")));
            assert!(is_within(root, Path::new("C:/ws/a.txt")));
            assert!(!is_within(root, Path::new(r"C:\wsx\a.txt")));
            assert!(!is_within(root, Path::new(r"D:\ws\a.txt")));
            assert_eq!(
                inside_root(root, Path::new(r"C:\ws\a\b.txt")),
                Some(PathBuf::from(r"a\b.txt"))
            );
            assert_eq!(inside_root(root, Path::new(r"C:\ws")), Some(PathBuf::new()));
            assert_eq!(inside_root(root, Path::new(r"C:\WS\a.txt")), None);
        }
        #[cfg(not(windows))]
        {
            let root = Path::new("/nonexistent-orcel-root/ws");
            assert!(is_within(root, root));
            assert!(is_within(root, &root.join("a/b.txt")));
            assert!(!is_within(root, Path::new("/nonexistent-orcel-root/wsx/a")));
            assert!(!is_within(
                root,
                Path::new("/nonexistent-orcel-root/ws\\x/a")
            ));
            assert!(!is_within(root, Path::new("/nonexistent-orcel-root")));
            // No such directory exists, so a case alias has no identity to match.
            assert!(!is_within(root, Path::new("/nonexistent-orcel-root/WS/a")));
            assert_eq!(
                inside_root(root, &root.join("a/b.txt")),
                Some(PathBuf::from("a/b.txt"))
            );
        }
    }

    /// The `..namedfork` recogniser, on every host. Only a whole segment counts.
    #[test]
    fn named_fork_segments_are_recognised_in_any_case() {
        for path in [
            "a.txt/..namedfork/rsrc",
            "dir/a.txt/..namedfork/data",
            "a.txt/..NAMEDFORK/rsrc",
            "a.txt/..NamedFork/rsrc",
            "./a.txt/..namedfork/rsrc",
            "..namedfork",
        ] {
            assert!(has_named_fork_segment(path), "{path}");
        }
        for path in [
            "a.txt",
            "a..namedfork",
            "..namedforks/rsrc",
            ".namedfork/rsrc",
            "namedfork/rsrc",
            "a.txt/rsrc",
        ] {
            assert!(!has_named_fork_segment(path), "{path}");
        }
        // Off macOS the name is ordinary and the guard does nothing.
        assert_eq!(
            refuse_named_fork("a.txt/..namedfork/rsrc").is_err(),
            cfg!(target_os = "macos")
        );
        assert!(refuse_named_fork("a.txt").is_ok());
    }

    /// Whether the volume holding `dir` matches names case-insensitively. On macOS the
    /// answer must be yes (the default APFS volume, and the CI runner's), so a test that
    /// depends on it fails instead of skipping; a developer whose temporary directory sits
    /// on a case-sensitive volume sets ORCEL_ALLOW_CASE_SENSITIVE_TMP=1.
    #[cfg(unix)]
    fn case_insensitive_volume(dir: &Path) -> bool {
        fs::write(dir.join("case-probe"), "probe").unwrap();
        let insensitive = dir.join("CASE-PROBE").exists();
        fs::remove_file(dir.join("case-probe")).unwrap();
        if cfg!(target_os = "macos") && !insensitive {
            assert!(
                std::env::var_os("ORCEL_ALLOW_CASE_SENSITIVE_TMP").is_some(),
                "the macOS temporary directory is on a case-sensitive volume; the APFS \
                 case-alias tests need the default case-insensitive volume"
            );
        }
        insensitive
    }

    /// A prefix spelled like the root but in another case is the root only when it is the
    /// same directory. On a case-sensitive volume (Linux) `WS` is a different directory and
    /// must never count as inside `ws`; on a case-insensitive one (macOS) it is the root.
    #[cfg(unix)]
    #[test]
    fn a_case_alias_of_the_root_counts_only_as_the_same_directory() {
        let base = fs::canonicalize(temp_root("case-alias")).unwrap();
        let root = base.join("ws");
        fs::create_dir(&root).unwrap();
        let alias = base.join("WS");
        let insensitive = case_insensitive_volume(&base);
        if !insensitive {
            // A link spelled like the root in another case resolves to the root, but the
            // link itself is not the root directory.
            std::os::unix::fs::symlink(&root, &alias).unwrap();
            assert_eq!(case_alias_inside_root(&root, &alias.join("a.txt")), None);
            fs::remove_file(&alias).unwrap();
            fs::create_dir(&alias).unwrap();
        }
        let found = case_alias_inside_root(&root, &alias.join("a.txt"));
        if insensitive {
            assert_eq!(found, Some(PathBuf::from("a.txt")));
            assert_eq!(case_alias_inside_root(&root, &alias), Some(PathBuf::new()));
        } else {
            assert_eq!(found, None, "a different directory is never the root");
        }
        // Never a sibling, a parent, or a differently spelled link to the root.
        fs::create_dir(base.join("ws2")).unwrap();
        assert_eq!(case_alias_inside_root(&root, &base.join("WS2/a.txt")), None);
        assert_eq!(case_alias_inside_root(&root, &base), None);
        std::os::unix::fs::symlink(&root, base.join("wx")).unwrap();
        assert_eq!(case_alias_inside_root(&root, &base.join("wx/a.txt")), None);
        let _ = fs::remove_dir_all(base);
    }

    /// macOS: a workspace opened under another case of its name still reads, and the Git
    /// guard still sees `.git` through a case alias of the root.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_case_alias_of_the_workspace_keeps_reads_and_the_git_guard() {
        let base = fs::canonicalize(temp_root("case-workspace")).unwrap();
        assert!(
            case_insensitive_volume(&base),
            "case-insensitive APFS expected"
        );
        let root = base.join("ws");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::write(root.join(".git/config"), "safe").unwrap();
        fs::write(root.join("a.txt"), "hello").unwrap();
        let provider = FsProvider::new(base.join("WS")).unwrap();
        // The alias really takes the identity path: whatever case the resolved root has,
        // one of the two spellings is not a byte prefix of the other's children.
        let upper = base.join("WS/.git/config");
        let lower = root.join(".git/config");
        let alias = if upper.starts_with(provider.root()) {
            lower
        } else {
            upper
        };
        assert!(!alias.starts_with(provider.root()));
        assert_eq!(
            inside_root(provider.root(), &alias),
            Some(PathBuf::from(".git/config"))
        );
        assert_eq!(
            provider.ensure_not_git(&alias).unwrap_err().code,
            FailureCode::CapabilityDenied
        );
        assert_eq!(provider.read_text("a.txt").unwrap()["text"], "hello");
        assert_eq!(provider.read_text("A.TXT").unwrap()["text"], "hello");
        for name in [".GIT/config", ".Git/config", ".git/CONFIG"] {
            assert_eq!(
                provider
                    .write_text(name, "bad", None, true)
                    .unwrap_err()
                    .code,
                FailureCode::CapabilityDenied,
                "{name}"
            );
        }
        let error = provider
            .ensure_not_git(&base.join("WS/.git/config"))
            .unwrap_err();
        assert_eq!(error.code, FailureCode::CapabilityDenied);
        assert_eq!(
            fs::read_to_string(root.join(".git/config")).unwrap(),
            "safe"
        );
        let _ = fs::remove_dir_all(base);
    }

    /// macOS: every filesystem tool refuses a `..namedfork` path, so no tool reads or
    /// writes a resource fork, and the fork stays empty.
    #[cfg(target_os = "macos")]
    #[test]
    fn named_fork_paths_are_refused_on_macos() {
        let root = temp_root("namedfork");
        fs::write(root.join("a.txt"), "plain").unwrap();
        let provider = FsProvider::new(&root).unwrap();
        for name in [
            "a.txt/..namedfork/rsrc",
            "a.txt/..NAMEDFORK/rsrc",
            "./a.txt/..namedfork/rsrc",
        ] {
            let denied = |result: Result<Value, ProviderError>, what: &str| {
                assert_eq!(
                    result.unwrap_err().code,
                    FailureCode::CapabilityDenied,
                    "{what} {name}"
                );
            };
            denied(provider.read_text(name), "read");
            denied(provider.stat(name), "stat");
            denied(provider.list(name), "list");
            denied(provider.search_text(name, "x", None), "search");
            denied(provider.read_range(name, 1, 1), "range");
            denied(provider.write_text(name, "fork", None, true), "write");
            denied(provider.create_text(name, "fork"), "create");
            denied(provider.mkdir(name, true), "mkdir");
            assert_eq!(
                provider.preview_write(name, "fork").unwrap_err().code,
                FailureCode::CapabilityDenied
            );
            assert_eq!(
                provider.entry_identity(name).unwrap_err().code,
                FailureCode::CapabilityDenied
            );
        }
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "plain");
        assert!(fs::read(root.join("a.txt/..namedfork/rsrc"))
            .unwrap_or_default()
            .is_empty());
        let _ = fs::remove_dir_all(root);
    }

    /// macOS: a link already in the workspace that points at a named fork has a plain name,
    /// so the submitted spelling passes; the resolved or descriptor path (and the identity
    /// of the opened object) still keeps every tool off the fork.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_link_to_a_named_fork_is_refused_on_macos() {
        let root = temp_root("namedfork-link");
        fs::write(root.join("b.txt"), "plain").unwrap();
        fs::write(root.join("b.txt/..namedfork/rsrc"), "fork").unwrap();
        assert_eq!(
            fs::read_to_string(root.join("b.txt/..namedfork/rsrc")).unwrap(),
            "fork",
            "the test needs a resource fork with content"
        );
        std::os::unix::fs::symlink("b.txt/..namedfork/rsrc", root.join("link")).unwrap();
        let provider = FsProvider::new(&root).unwrap();
        assert!(provider.read_text("link").is_err(), "read through the link");
        assert!(provider.stat("link").is_err(), "stat through the link");
        assert!(provider.read_range("link", 1, 1).is_err(), "range read");
        assert!(provider.preview_write("link", "x").is_err(), "preview");
        assert!(
            provider.write_text("link", "forged", None, false).is_err(),
            "write through the link"
        );
        let search = provider.search_text("", "fork", None).unwrap();
        assert_eq!(search["matches"].as_array().unwrap().len(), 0);
        assert_eq!(
            fs::read_to_string(root.join("b.txt/..namedfork/rsrc")).unwrap(),
            "fork"
        );
        assert_eq!(fs::read_to_string(root.join("b.txt")).unwrap(), "plain");
        let _ = fs::remove_dir_all(root);
    }
}
