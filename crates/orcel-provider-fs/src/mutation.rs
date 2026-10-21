//! SG-000061 bounded filesystem mutation and lookup.
//!
//! Every operation resolves final Windows path identity, stays inside the
//! trusted workspace root, refuses links, junctions, and other reparse
//! points, binds mutations to the identity observed for approval, and
//! verifies its postcondition. There is no recursive or wildcard mutation,
//! no overwrite on move, and no attribute, permission, or link change.

use super::{
    final_path_from_open_file, hash_file, resolve_final_path, sha256_hex, FsProvider,
    ProviderError, MAX_WRITE_BYTES,
};
use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};

pub const MAX_RANGE_LINES: usize = 2_000;
pub const MAX_RANGE_BYTES: usize = 1024 * 1024;
pub const MAX_RANGE_LINE_CHARS: usize = 4_096;
pub const MAX_FIND_RESULTS: usize = 500;
pub const MAX_FIND_DEPTH: usize = 16;
pub const MAX_FIND_VISITED: usize = 20_000;
pub const MAX_EDIT_NEEDLE_BYTES: usize = 64 * 1024;
pub const MAX_EDIT_REPLACEMENTS: usize = 100;

/// Identity of an existing entry, bound into approval digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryIdentity {
    pub kind: &'static str,
    pub size: u64,
    pub sha256: Option<String>,
    pub resolved: PathBuf,
}

impl EntryIdentity {
    pub fn digest_fields(&self) -> String {
        format!(
            "{}|{}|{}",
            self.kind,
            self.size,
            self.sha256.as_deref().unwrap_or("-")
        )
    }
}

/// A prepared exact edit; applying it re-verifies the current digest.
#[derive(Debug, Clone)]
pub struct EditPreview {
    pub relative: String,
    pub current_sha256: String,
    pub new_sha256: String,
    pub replacements: usize,
    new_content: String,
}

fn invalid(message: impl Into<String>) -> ProviderError {
    ProviderError::new(FailureCode::InvalidRequest, message)
}

fn is_link_or_reparse(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

fn glob_match(pattern: &[char], name: &[char]) -> bool {
    match (pattern.first(), name.first()) {
        (None, None) => true,
        (Some('*'), _) => {
            glob_match(&pattern[1..], name) || (!name.is_empty() && glob_match(pattern, &name[1..]))
        }
        (Some('?'), Some(_)) => glob_match(&pattern[1..], &name[1..]),
        (Some(p), Some(n)) => {
            p.to_lowercase().eq(n.to_lowercase()) && glob_match(&pattern[1..], &name[1..])
        }
        _ => false,
    }
}

impl FsProvider {
    fn within(&self, resolved: &Path) -> Result<(), ProviderError> {
        if resolved == self.root {
            return Err(ProviderError::new(
                FailureCode::PathEscape,
                "the workspace root itself cannot be the target",
            ));
        }
        self.ensure_within(resolved)
    }

    /// Bounded line-range read of one UTF-8 text file.
    pub fn read_range(
        &self,
        relative: &str,
        start_line: usize,
        max_lines: usize,
    ) -> Result<Value, ProviderError> {
        if start_line == 0 || max_lines == 0 || max_lines > MAX_RANGE_LINES {
            return Err(invalid(format!(
                "start_line must be at least 1 and max_lines from 1 to {MAX_RANGE_LINES}"
            )));
        }
        let candidate = self.root.join(relative);
        let file = File::open(&candidate)
            .map_err(|error| ProviderError::io("open range target", error))?;
        let resolved = final_path_from_open_file(&file, &candidate)
            .map_err(|error| ProviderError::io("resolve range target", error))?;
        self.ensure_within(&resolved)?;
        if !file
            .metadata()
            .map_err(|error| ProviderError::io("inspect range target", error))?
            .is_file()
        {
            return Err(invalid("range target is not a regular file"));
        }
        let mut reader = BufReader::new(file);
        let mut lines = Vec::new();
        let mut bytes = 0usize;
        let mut line_number = 0usize;
        let mut buffer = Vec::new();
        let mut truncated = false;
        let mut end_of_file = false;
        loop {
            buffer.clear();
            let read = reader
                .by_ref()
                .take((MAX_RANGE_BYTES + 1) as u64)
                .read_until(b'\n', &mut buffer)
                .map_err(|error| ProviderError::io("read range target", error))?;
            if read == 0 {
                end_of_file = true;
                break;
            }
            line_number += 1;
            if line_number < start_line {
                continue;
            }
            if lines.len() == max_lines {
                break;
            }
            let text = std::str::from_utf8(&buffer)
                .map_err(|_| invalid("range target is not UTF-8 text"))?
                .trim_end_matches(['\n', '\r']);
            let mut line: String = text.chars().take(MAX_RANGE_LINE_CHARS).collect();
            if text.chars().count() > MAX_RANGE_LINE_CHARS {
                line.push('…');
            }
            bytes += line.len();
            if bytes > MAX_RANGE_BYTES {
                truncated = true;
                break;
            }
            lines.push(line);
        }
        Ok(json!({
            "path": relative,
            "start_line": start_line,
            "lines": lines,
            "end_of_file": end_of_file,
            "truncated": truncated
        }))
    }

    /// Bounded file-name glob search without following links.
    pub fn find_names(
        &self,
        relative: &str,
        pattern: &str,
        max_results: usize,
        max_depth: usize,
    ) -> Result<Value, ProviderError> {
        if pattern.is_empty()
            || pattern.chars().count() > 128
            || pattern.contains(['/', '\\', ':', '\0'])
        {
            return Err(invalid(
                "pattern must be a file-name glob of 1 to 128 characters without separators",
            ));
        }
        if max_results == 0 || max_results > MAX_FIND_RESULTS || max_depth > MAX_FIND_DEPTH {
            return Err(invalid(format!(
                "max_results must be 1 to {MAX_FIND_RESULTS} and max_depth at most {MAX_FIND_DEPTH}"
            )));
        }
        let start = self.resolve_existing(relative)?;
        if !start.is_dir() {
            return Err(invalid("find root is not a directory"));
        }
        let pattern: Vec<char> = pattern.chars().collect();
        let mut queue = VecDeque::from([(start.clone(), 0usize)]);
        let mut matches = Vec::new();
        let mut visited = 0usize;
        let mut truncated = false;
        'walk: while let Some((dir, depth)) = queue.pop_front() {
            let entries = match fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                visited += 1;
                if visited > MAX_FIND_VISITED {
                    truncated = true;
                    break 'walk;
                }
                let path = entry.path();
                let Ok(metadata) = fs::symlink_metadata(&path) else {
                    continue;
                };
                if is_link_or_reparse(&metadata) {
                    continue;
                }
                let name: Vec<char> = entry.file_name().to_string_lossy().chars().collect();
                if glob_match(&pattern, &name) {
                    if matches.len() == max_results {
                        truncated = true;
                        break 'walk;
                    }
                    let relative_path = path
                        .strip_prefix(&self.root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    matches.push(json!({
                        "path": relative_path,
                        "kind": if metadata.is_dir() { "directory" } else { "file" }
                    }));
                }
                if metadata.is_dir() && depth < max_depth {
                    queue.push_back((path, depth + 1));
                }
            }
        }
        Ok(json!({ "matches": matches, "truncated": truncated, "visited": visited }))
    }

    /// Identity of an existing file or directory that is not a link.
    pub fn entry_identity(&self, relative: &str) -> Result<EntryIdentity, ProviderError> {
        let candidate = self.root.join(relative);
        let metadata = fs::symlink_metadata(&candidate)
            .map_err(|error| ProviderError::io("inspect target", error))?;
        if is_link_or_reparse(&metadata) {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "links, junctions, and reparse points are never moved or removed",
            ));
        }
        let resolved = resolve_final_path(&candidate)
            .map_err(|error| ProviderError::io("resolve target", error))?;
        self.within(&resolved)?;
        if metadata.is_file() {
            let file =
                File::open(&resolved).map_err(|error| ProviderError::io("open target", error))?;
            Ok(EntryIdentity {
                kind: "file",
                size: metadata.len(),
                sha256: Some(hash_file(file)?),
                resolved,
            })
        } else if metadata.is_dir() {
            let entries = fs::read_dir(&resolved)
                .map_err(|error| ProviderError::io("list target", error))?
                .count() as u64;
            Ok(EntryIdentity {
                kind: "directory",
                size: entries,
                sha256: None,
                resolved,
            })
        } else {
            Err(invalid("target is neither a regular file nor a directory"))
        }
    }

    fn require_identity(
        &self,
        relative: &str,
        expected: &EntryIdentity,
    ) -> Result<EntryIdentity, ProviderError> {
        let current = self.entry_identity(relative)?;
        if current != *expected {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "target changed since approval",
            ));
        }
        Ok(current)
    }

    /// Create one directory, or its missing parents when `parents` is true.
    pub fn mkdir(&self, relative: &str, parents: bool) -> Result<Value, ProviderError> {
        let candidate = self.root.join(relative);
        if fs::symlink_metadata(&candidate).is_ok() {
            return Err(invalid("directory target already exists"));
        }
        let mut missing: Vec<std::ffi::OsString> = Vec::new();
        let mut existing = candidate.clone();
        while fs::symlink_metadata(&existing).is_err() {
            let name = existing
                .file_name()
                .ok_or_else(|| invalid("directory target has no name"))?
                .to_os_string();
            missing.push(name);
            existing = existing
                .parent()
                .ok_or_else(|| invalid("directory target has no parent"))?
                .to_path_buf();
        }
        missing.reverse();
        if missing.len() > 1 && !parents {
            return Err(invalid(
                "parent directory is missing; pass parents to create it",
            ));
        }
        if missing.len() > 32 {
            return Err(invalid("too many directory levels"));
        }
        let mut current = resolve_final_path(&existing)
            .map_err(|error| ProviderError::io("resolve existing ancestor", error))?;
        self.ensure_within(&current)?;
        let mut created = Vec::new();
        for name in missing {
            let next = current.join(&name);
            fs::create_dir(&next).map_err(|error| ProviderError::io("create directory", error))?;
            let resolved = resolve_final_path(&next)
                .map_err(|error| ProviderError::io("resolve created directory", error))?;
            if let Err(error) = self.within(&resolved) {
                let _ = fs::remove_dir(&next);
                return Err(error);
            }
            created.push(
                resolved
                    .strip_prefix(&self.root)
                    .unwrap_or(&resolved)
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            current = resolved;
        }
        let verified = resolve_final_path(&candidate)
            .map_err(|error| ProviderError::io("verify created directory", error))?;
        if !verified.is_dir() || verified != current {
            return Err(ProviderError::new(
                FailureCode::PostconditionFailed,
                "created directory did not verify",
            ));
        }
        Ok(json!({ "path": relative, "created": created }))
    }

    /// Move or rename one entry within the workspace, never overwriting.
    pub fn move_entry(
        &self,
        from: &str,
        to: &str,
        expected: &EntryIdentity,
    ) -> Result<Value, ProviderError> {
        let source = self.require_identity(from, expected)?;
        let destination = self.root.join(to);
        if fs::symlink_metadata(&destination).is_ok() {
            return Err(invalid("destination already exists; moves never overwrite"));
        }
        let name = destination
            .file_name()
            .ok_or_else(|| invalid("destination has no name"))?
            .to_os_string();
        if Path::new(&name)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(invalid("destination name is not a plain name"));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| invalid("destination has no parent"))?;
        let parent = resolve_final_path(parent)
            .map_err(|error| ProviderError::io("resolve destination parent", error))?;
        self.ensure_within(&parent)?;
        if source.kind == "directory"
            && (parent == source.resolved || parent.starts_with(&source.resolved))
        {
            return Err(invalid("a directory cannot be moved into itself"));
        }
        let target = parent.join(&name);
        move_no_replace(&source.resolved, &target)
            .map_err(|error| ProviderError::io("move entry", error))?;
        let moved = resolve_final_path(&target)
            .map_err(|error| ProviderError::io("verify moved entry", error))?;
        if fs::symlink_metadata(&source.resolved).is_ok() || self.within(&moved).is_err() {
            return Err(ProviderError::new(
                FailureCode::PostconditionFailed,
                "move did not verify",
            ));
        }
        if let Some(expected_sha) = &source.sha256 {
            let file =
                File::open(&moved).map_err(|error| ProviderError::io("open moved entry", error))?;
            if &hash_file(file)? != expected_sha {
                return Err(ProviderError::new(
                    FailureCode::PostconditionFailed,
                    "moved file content did not verify",
                ));
            }
        }
        Ok(json!({ "from": from, "to": to, "kind": source.kind }))
    }

    /// Remove one regular file or one empty directory bound to its identity.
    pub fn remove_entry(
        &self,
        relative: &str,
        expected: &EntryIdentity,
    ) -> Result<Value, ProviderError> {
        let current = self.require_identity(relative, expected)?;
        if current.kind == "directory" {
            if current.size != 0 {
                return Err(invalid(
                    "only empty directories can be removed; there is no recursive delete",
                ));
            }
            fs::remove_dir(&current.resolved)
                .map_err(|error| ProviderError::io("remove directory", error))?;
        } else {
            fs::remove_file(&current.resolved)
                .map_err(|error| ProviderError::io("remove file", error))?;
        }
        if fs::symlink_metadata(&current.resolved).is_ok() {
            return Err(ProviderError::new(
                FailureCode::PostconditionFailed,
                "removed entry still exists",
            ));
        }
        Ok(json!({ "path": relative, "kind": current.kind, "removed": true }))
    }

    /// Prepare an exact search-and-replace bound to the current digest.
    pub fn edit_preview(
        &self,
        relative: &str,
        old: &str,
        new: &str,
        expected_sha256: &str,
        expected_replacements: usize,
    ) -> Result<EditPreview, ProviderError> {
        if old.is_empty() || old.len() > MAX_EDIT_NEEDLE_BYTES || new.len() > MAX_EDIT_NEEDLE_BYTES
        {
            return Err(invalid(
                "old must be 1 byte to 64 KiB and new at most 64 KiB",
            ));
        }
        if expected_replacements == 0 || expected_replacements > MAX_EDIT_REPLACEMENTS {
            return Err(invalid(format!(
                "replacements must be 1 to {MAX_EDIT_REPLACEMENTS}"
            )));
        }
        let candidate = self.root.join(relative);
        let mut file =
            File::open(&candidate).map_err(|error| ProviderError::io("open edit target", error))?;
        let resolved = final_path_from_open_file(&file, &candidate)
            .map_err(|error| ProviderError::io("resolve edit target", error))?;
        self.ensure_within(&resolved)?;
        let metadata = file
            .metadata()
            .map_err(|error| ProviderError::io("inspect edit target", error))?;
        if !metadata.is_file() || metadata.len() as usize > MAX_WRITE_BYTES {
            return Err(invalid(
                "edit target must be a regular file of at most 2 MiB",
            ));
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|error| ProviderError::io("read edit target", error))?;
        let current_sha256 = sha256_hex(&bytes);
        if current_sha256 != expected_sha256 {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                "edit target changed since it was read",
            ));
        }
        let text =
            String::from_utf8(bytes).map_err(|_| invalid("edit target is not UTF-8 text"))?;
        let found = text.matches(old).count();
        if found != expected_replacements {
            return Err(ProviderError::new(
                FailureCode::TargetStale,
                format!(
                    "expected {expected_replacements} occurrence(s) of old text, found {found}"
                ),
            ));
        }
        let new_content = text.replace(old, new);
        if new_content.len() > MAX_WRITE_BYTES {
            return Err(ProviderError::new(
                FailureCode::OutputLimit,
                "edited content exceeds 2 MiB limit",
            ));
        }
        Ok(EditPreview {
            relative: relative.to_owned(),
            current_sha256,
            new_sha256: sha256_hex(new_content.as_bytes()),
            replacements: found,
            new_content,
        })
    }

    /// Apply a prepared edit; the write re-verifies the current digest.
    pub fn edit_apply(&self, preview: &EditPreview) -> Result<Value, ProviderError> {
        let written = self.write_text(
            &preview.relative,
            &preview.new_content,
            Some(&preview.current_sha256),
            false,
        )?;
        if written.get("sha256").and_then(Value::as_str) != Some(preview.new_sha256.as_str()) {
            return Err(ProviderError::new(
                FailureCode::PostconditionFailed,
                "edited content did not verify",
            ));
        }
        Ok(json!({
            "path": preview.relative,
            "replacements": preview.replacements,
            "previous_sha256": preview.current_sha256,
            "sha256": preview.new_sha256
        }))
    }
}

#[cfg(windows)]
fn move_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let wide = |path: &Path| -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    };
    let (source, target) = (wide(from), wide(to));
    // Flags 0: never replace an existing destination and never copy across volumes.
    if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 0) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(windows))]
fn move_no_replace(from: &Path, to: &Path) -> std::io::Result<()> {
    if fs::symlink_metadata(to).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination exists",
        ));
    }
    fs::rename(from, to)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn root(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let nanos = format!("{nanos}-{}", next_temp_sequence());
        let dir = std::env::temp_dir().join(format!(
            "orcel-fs-mut-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn provider(dir: &Path) -> FsProvider {
        FsProvider::new(dir).unwrap()
    }

    #[test]
    fn ranged_reads_are_bounded_and_utf8_only() {
        let dir = root("range");
        let lines: Vec<String> = (1..=50).map(|i| format!("line {i}")).collect();
        fs::write(dir.join("a.txt"), lines.join("\r\n")).unwrap();
        let p = provider(&dir);
        let out = p.read_range("a.txt", 10, 3).unwrap();
        assert_eq!(out["lines"], json!(["line 10", "line 11", "line 12"]));
        assert_eq!(out["end_of_file"], false);
        let tail = p.read_range("a.txt", 49, 10).unwrap();
        assert_eq!(tail["lines"], json!(["line 49", "line 50"]));
        assert_eq!(tail["end_of_file"], true);
        assert!(p.read_range("a.txt", 0, 1).is_err());
        assert!(p.read_range("a.txt", 1, MAX_RANGE_LINES + 1).is_err());
        fs::write(dir.join("bin.dat"), [0xff, 0xfe, 0x00]).unwrap();
        assert!(p.read_range("bin.dat", 1, 1).is_err());
        assert!(p.read_range("../outside.txt", 1, 1).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn name_search_is_bounded_and_never_follows_links() {
        let dir = root("find");
        fs::create_dir_all(dir.join("src/nested")).unwrap();
        fs::write(dir.join("src/main.rs"), "").unwrap();
        fs::write(dir.join("src/nested/lib.RS"), "").unwrap();
        fs::write(dir.join("README.md"), "").unwrap();
        let p = provider(&dir);
        let found = p.find_names(".", "*.rs", 10, 8).unwrap();
        let mut paths: Vec<String> = found["matches"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["path"].as_str().unwrap().to_owned())
            .collect();
        paths.sort();
        assert_eq!(paths, vec!["src/main.rs", "src/nested/lib.RS"]);
        assert_eq!(p.find_names(".", "*.rs", 1, 8).unwrap()["truncated"], true);
        assert_eq!(
            p.find_names(".", "*.rs", 10, 0).unwrap()["matches"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert!(p.find_names(".", "../*", 10, 8).is_err());
        assert!(p.find_names(".", "", 10, 8).is_err());
        assert!(p.find_names(".", "*", 0, 8).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn mkdir_creates_only_inside_the_workspace() {
        let dir = root("mkdir");
        let p = provider(&dir);
        assert!(
            p.mkdir("a/b", false).is_err(),
            "missing parent requires parents"
        );
        let out = p.mkdir("a/b", true).unwrap();
        assert_eq!(out["created"], json!(["a", "a/b"]));
        assert!(dir.join("a/b").is_dir());
        assert!(p.mkdir("a/b", true).is_err(), "existing target");
        assert!(p.mkdir("../escape", true).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn moves_never_overwrite_and_bind_identity() {
        let dir = root("move");
        fs::write(dir.join("a.txt"), "alpha").unwrap();
        fs::write(dir.join("b.txt"), "beta").unwrap();
        fs::create_dir_all(dir.join("d/inner")).unwrap();
        let p = provider(&dir);
        let id = p.entry_identity("a.txt").unwrap();
        assert!(p.move_entry("a.txt", "b.txt", &id).is_err(), "no overwrite");
        assert_eq!(fs::read_to_string(dir.join("b.txt")).unwrap(), "beta");
        fs::write(dir.join("a.txt"), "changed").unwrap();
        assert_eq!(
            p.move_entry("a.txt", "c.txt", &id).unwrap_err().code,
            FailureCode::TargetStale
        );
        let id = p.entry_identity("a.txt").unwrap();
        p.move_entry("a.txt", "d/c.txt", &id).unwrap();
        assert!(!dir.join("a.txt").exists());
        assert_eq!(fs::read_to_string(dir.join("d/c.txt")).unwrap(), "changed");
        let did = p.entry_identity("d").unwrap();
        assert!(
            p.move_entry("d", "d/inner/self", &did).is_err(),
            "no move into itself"
        );
        assert!(p.entry_identity(".").is_err(), "the root is never a target");
        assert!(p
            .move_entry("b.txt", "../out.txt", &p.entry_identity("b.txt").unwrap())
            .is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn removal_is_single_entry_identity_bound_and_never_recursive() {
        let dir = root("remove");
        fs::write(dir.join("a.txt"), "alpha").unwrap();
        fs::create_dir_all(dir.join("full/x")).unwrap();
        fs::create_dir_all(dir.join("empty")).unwrap();
        let p = provider(&dir);
        let id = p.entry_identity("a.txt").unwrap();
        fs::write(dir.join("a.txt"), "beta").unwrap();
        assert_eq!(
            p.remove_entry("a.txt", &id).unwrap_err().code,
            FailureCode::TargetStale
        );
        assert!(dir.join("a.txt").exists());
        let id = p.entry_identity("a.txt").unwrap();
        p.remove_entry("a.txt", &id).unwrap();
        assert!(!dir.join("a.txt").exists());
        let full = p.entry_identity("full").unwrap();
        assert!(
            p.remove_entry("full", &full).is_err(),
            "no recursive delete"
        );
        assert!(dir.join("full/x").exists());
        let empty = p.entry_identity("empty").unwrap();
        p.remove_entry("empty", &empty).unwrap();
        assert!(!dir.join("empty").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn exact_edits_bind_digest_and_occurrence_count() {
        let dir = root("edit");
        fs::write(dir.join("a.txt"), "one two two three").unwrap();
        let p = provider(&dir);
        let sha = sha256_hex(b"one two two three");
        assert_eq!(
            p.edit_preview("a.txt", "two", "2", &sha, 1)
                .unwrap_err()
                .code,
            FailureCode::TargetStale
        );
        assert_eq!(
            p.edit_preview("a.txt", "two", "2", &"0".repeat(64), 2)
                .unwrap_err()
                .code,
            FailureCode::TargetStale
        );
        assert!(p.edit_preview("a.txt", "", "x", &sha, 1).is_err());
        let preview = p.edit_preview("a.txt", "two", "2", &sha, 2).unwrap();
        fs::write(dir.join("a.txt"), "one two two three!").unwrap();
        assert_eq!(
            p.edit_apply(&preview).unwrap_err().code,
            FailureCode::TargetStale
        );
        fs::write(dir.join("a.txt"), "one two two three").unwrap();
        let applied = p.edit_apply(&preview).unwrap();
        assert_eq!(applied["replacements"], 2);
        assert_eq!(
            fs::read_to_string(dir.join("a.txt")).unwrap(),
            "one 2 2 three"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_never_followed_moved_or_removed() {
        let dir = root("junction");
        let outside = root("junction-outside");
        fs::write(outside.join("secret.txt"), "secret").unwrap();
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dir.join("link"))
            .arg(&outside)
            .status()
            .unwrap();
        assert!(status.success());
        let p = provider(&dir);
        assert!(p.entry_identity("link").is_err());
        assert!(p.find_names(".", "secret*", 10, 8).unwrap()["matches"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(p.read_range("link/secret.txt", 1, 1).is_err());
        assert!(p.mkdir("link/new", true).is_err());
        assert!(outside.join("secret.txt").exists());
        let _ = fs::remove_dir_all(dir);
        let _ = fs::remove_dir_all(outside);
    }
}
