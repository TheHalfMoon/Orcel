//! WI-04: change tracking between extractions. The last extraction of each
//! page is kept in a workspace-scoped store, and the next extraction of the
//! same page is compared with it line by line.
//!
//! Ported from firecrawl/firecrawl at commit
//! f84845c864b6e2af22791c18fcf89ac2a21f1434, `apps/api/src/lib/change-tracking-diff.ts`
//! (blob f447df3c106342aa6e82e155fb0e39553b330dd6), `createMarkdownChangeDiff`.
//! AGPL-3.0 upstream; ported under the founder authorization recorded in
//! `docs/orcel/grants/2026-10-13-founder-source-authorization.md`; notice:
//! `docs/orcel/notices/firecrawl-AGPL-3.0.txt`.
//!
//! What is kept: a unified diff of `previous.md` against `current.md` with
//! three lines of context, a structured form of it (hunks of added, deleted
//! and unchanged lines with their line numbers), "\ No newline at end of
//! file" where a last line has none, and no result when no line was added
//! or deleted. Orcel's changes: the diff is computed by the `similar` crate
//! (Myers, with a deadline, so a heavily changed page may get a coarser
//! diff) instead of the `diff` and `parse-diff` packages; lines end only at
//! `\n` (a `\r` stays part of its line); the text has no `====` separator
//! line or tab-suffixed file headers, and a one-line range is written
//! without `,1`; a diff larger than `MAX_DIFF_BYTES` is cut at a line,
//! its hunk header counts the lines actually emitted, and it is marked
//! truncated. Pages are keyed by their canonical URL (WI-01) without a
//! fragment, with the scheme and host lower-cased, a default port dropped
//! and an empty path written as `/`. The store is one bounded file in the
//! workspace the caller names (at most `MAX_TRACKED_PAGES` pages and
//! `MAX_TRACKED_BYTES` of Markdown, the least recently tracked evicted
//! first), read with a size bound, refused rather than replaced when it
//! does not parse or breaks a bound, and written whole through a fresh,
//! synced temporary file renamed over it; a change takes effect only once
//! it is written. One store object per workspace is expected (orceld owns
//! it); concurrent writers never tear the file, and the last one wins. The
//! user can forget one page or clear the store, which also removes stray
//! temporary files. Stored and returned text is still untrusted page text,
//! with no authority.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use similar::{capture_diff_slices_deadline, group_diff_ops, Algorithm, ChangeTag, DiffTag};

use crate::crawl_scope::canonical;
use crate::error::HostError;
use crate::extraction::MAX_EXTRACT_CHARS;

/// Pages one workspace's store keeps.
pub const MAX_TRACKED_PAGES: usize = 256;
/// Markdown bytes one workspace's store keeps, in all.
pub const MAX_TRACKED_BYTES: usize = 64 * 1024 * 1024;
/// Bytes of one diff's text (the extraction bound, as bytes).
pub const MAX_DIFF_BYTES: usize = MAX_EXTRACT_CHARS;
/// Largest store file read: the Markdown bound with room for JSON escaping
/// (at most six bytes per byte) and the envelope.
const MAX_STORE_FILE_BYTES: u64 = (MAX_TRACKED_BYTES as u64) * 6 + 1024 * 1024;
/// Time one comparison may take before it settles for a coarser diff.
const DIFF_DEADLINE: Duration = Duration::from_secs(2);
/// Lines of context around each change (the donor's `context: 3`).
const CONTEXT_LINES: usize = 3;
/// Room kept for one hunk header in the diff's byte bound.
const HEADER_BYTES: usize = 64;
/// The store file's format.
const SCHEMA: u32 = 1;
const PREAMBLE: &str = "--- previous.md\n+++ current.md\n";
const NO_NEWLINE: &str = "\\ No newline at end of file\n";

/// One line of a hunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineChange {
    pub kind: LineKind,
    /// Line number in the previous extraction (unchanged and deleted lines).
    pub old_line: Option<usize>,
    /// Line number in the current extraction (unchanged and added lines).
    pub new_line: Option<usize>,
    /// The line without its `\n`.
    pub content: String,
    /// The line is the last one and has no `\n`.
    pub no_newline: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LineKind {
    Normal,
    Add,
    Del,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hunk {
    /// The unified diff's `@@ -a,b +c,d @@` line.
    pub header: String,
    pub changes: Vec<LineChange>,
}

/// What changed since the page was last tracked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChangeDiff {
    /// Unified diff of `previous.md` against `current.md`.
    pub text: String,
    pub hunks: Vec<Hunk>,
    /// The diff was cut at `MAX_DIFF_BYTES`; lines did change even when no
    /// hunk fits.
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum Change {
    /// The page was not tracked before (or was evicted or forgotten).
    New,
    /// No line was added or deleted.
    Same,
    Changed(ChangeDiff),
}

/// Lines with their `\n`, if any.
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// The donor's `createMarkdownChangeDiff`: `None` when no line changed.
pub fn markdown_change_diff(previous: &str, current: &str) -> Option<ChangeDiff> {
    let old = lines(previous);
    let new = lines(current);
    let ops = capture_diff_slices_deadline(
        Algorithm::Myers,
        &old,
        &new,
        Some(Instant::now() + DIFF_DEADLINE),
    );
    if ops.iter().all(|op| op.tag() == DiffTag::Equal) {
        return None;
    }
    let mut hunks = Vec::new();
    let mut size = PREAMBLE.len();
    let mut truncated = false;
    'groups: for group in group_diff_ops(ops, CONTEXT_LINES) {
        let Some(first) = group.first() else {
            continue;
        };
        let (old_start, new_start) = (first.old_range().start, first.new_range().start);
        let mut changes = Vec::new();
        let mut cut = false;
        if size + HEADER_BYTES > MAX_DIFF_BYTES {
            truncated = true;
            break;
        }
        size += HEADER_BYTES;
        'ops: for op in &group {
            for change in op.iter_changes(&old, &new) {
                let line = change.value();
                let no_newline = !line.ends_with('\n');
                let content = line.strip_suffix('\n').unwrap_or(line).to_owned();
                let cost = 2 + content.len() + if no_newline { NO_NEWLINE.len() } else { 0 };
                if size + cost > MAX_DIFF_BYTES {
                    cut = true;
                    break 'ops;
                }
                size += cost;
                changes.push(LineChange {
                    kind: match change.tag() {
                        ChangeTag::Equal => LineKind::Normal,
                        ChangeTag::Insert => LineKind::Add,
                        ChangeTag::Delete => LineKind::Del,
                    },
                    old_line: change.old_index().map(|at| at + 1),
                    new_line: change.new_index().map(|at| at + 1),
                    content,
                    no_newline,
                });
            }
        }
        if changes.iter().any(|c| c.kind != LineKind::Normal) {
            let old_count = changes.iter().filter(|c| c.kind != LineKind::Add).count();
            let new_count = changes.iter().filter(|c| c.kind != LineKind::Del).count();
            hunks.push(Hunk {
                header: format!(
                    "@@ -{} +{} @@",
                    range_text(old_start, old_count),
                    range_text(new_start, new_count)
                ),
                changes,
            });
        }
        if cut {
            truncated = true;
            break 'groups;
        }
    }
    let mut text = String::from(PREAMBLE);
    for hunk in &hunks {
        text.push_str(&hunk.header);
        text.push('\n');
        for change in &hunk.changes {
            text.push(match change.kind {
                LineKind::Normal => ' ',
                LineKind::Add => '+',
                LineKind::Del => '-',
            });
            text.push_str(&change.content);
            text.push('\n');
            if change.no_newline {
                text.push_str(NO_NEWLINE);
            }
        }
    }
    Some(ChangeDiff {
        text,
        hunks,
        truncated,
    })
}

/// A unified diff range: `start,len`, with 1-based starts (0 for an empty
/// range at the top).
fn range_text(start: usize, len: usize) -> String {
    let first = if len == 0 { start } else { start + 1 };
    if len == 1 {
        first.to_string()
    } else {
        format!("{first},{len}")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    page: String,
    /// When the page was last tracked, in the store's own order.
    seq: u64,
    markdown: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Stored {
    schema: u32,
    next: u64,
    pages: Vec<Entry>,
}

impl Stored {
    fn empty() -> Self {
        Self {
            schema: SCHEMA,
            next: 0,
            pages: Vec::new(),
        }
    }

    /// Drops the least recently tracked pages until both bounds hold, then
    /// numbers the rest `0..n` in that order (so `seq` never grows).
    fn evict(&mut self) {
        self.pages.sort_by_key(|e| e.seq);
        let mut bytes: usize = self.pages.iter().map(|e| e.markdown.len()).sum();
        let mut drop = 0;
        while self.pages.len() - drop > MAX_TRACKED_PAGES || bytes > MAX_TRACKED_BYTES {
            bytes -= self.pages[drop].markdown.len();
            drop += 1;
        }
        self.pages.drain(..drop);
        for (seq, entry) in self.pages.iter_mut().enumerate() {
            entry.seq = seq as u64;
        }
        self.next = self.pages.len() as u64;
    }

    fn valid(&self) -> bool {
        let bytes: usize = self.pages.iter().map(|e| e.markdown.len()).sum();
        let mut pages: Vec<&str> = self.pages.iter().map(|e| e.page.as_str()).collect();
        pages.sort_unstable();
        pages.dedup();
        let mut seqs: Vec<u64> = self.pages.iter().map(|e| e.seq).collect();
        seqs.sort_unstable();
        seqs.dedup();
        self.schema == SCHEMA
            && self.pages.len() <= MAX_TRACKED_PAGES
            && bytes <= MAX_TRACKED_BYTES
            && pages.len() == self.pages.len()
            && seqs.len() == self.pages.len()
            && self.next <= MAX_TRACKED_PAGES as u64 + 1
            && self
                .pages
                .iter()
                .all(|e| e.seq < self.next && e.markdown.chars().count() <= MAX_EXTRACT_CHARS)
    }
}

/// The last extraction of each page, for one workspace.
#[derive(Debug)]
pub struct ChangeStore {
    path: PathBuf,
    stored: Stored,
}

fn invalid(message: &str) -> HostError {
    HostError::Invalid(message.into())
}

/// The store's key for a URL: its canonical form, without a fragment, with
/// the scheme and host lower-cased, a default port dropped and an empty
/// path written as `/`.
fn page_key(url: &str) -> String {
    let url = url.split('#').next().unwrap_or(url);
    let Some(at) = url.find("://") else {
        return canonical(url);
    };
    let scheme = url[..at].to_ascii_lowercase();
    let rest = &url[at + 3..];
    let end = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    // User information is case-sensitive; only the host is lower-cased.
    let (userinfo, host) = match authority.rfind('@') {
        Some(at) => authority.split_at(at + 1),
        None => ("", authority),
    };
    let mut host = host.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => Some(":443"),
        "http" => Some(":80"),
        _ => None,
    };
    if let Some(port) = default_port {
        if let Some(stripped) = host.strip_suffix(port) {
            host = stripped.to_owned();
        }
    }
    let path = if tail.is_empty() || tail.starts_with('?') {
        format!("/{tail}")
    } else {
        tail.to_owned()
    };
    canonical(&format!("{scheme}://{userinfo}{host}{path}"))
}

/// Reads at most `limit` bytes of `path`; `None` when it is missing.
fn read_bounded(path: &Path, limit: u64) -> Result<Option<Vec<u8>>, HostError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(HostError::Io(error)),
    };
    if file.metadata()?.len() > limit {
        return Err(invalid("change-tracking store is too large"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("change-tracking store is too large"));
    }
    Ok(Some(bytes))
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl ChangeStore {
    /// Opens the store at `path` (a file in the workspace's own state);
    /// a missing file is an empty store. A file that is too large, does
    /// not parse, or breaks a bound is refused rather than replaced.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, HostError> {
        let path = path.into();
        let stored = match read_bounded(&path, MAX_STORE_FILE_BYTES)? {
            Some(bytes) => {
                let stored: Stored = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("change-tracking store does not parse"))?;
                if !stored.valid() {
                    return Err(invalid("change-tracking store is not valid"));
                }
                stored
            }
            None => Stored::empty(),
        };
        Ok(Self { path, stored })
    }

    /// Compares `markdown` with the page's last tracked extraction, then
    /// keeps `markdown` as the page's latest. Nothing changes unless the
    /// store is written.
    pub fn track(&mut self, url: &str, markdown: &str) -> Result<Change, HostError> {
        if markdown.chars().count() > MAX_EXTRACT_CHARS {
            return Err(invalid("extraction is larger than the extraction bound"));
        }
        let key = page_key(url);
        let mut next = self.stored.clone();
        let seq = next.next;
        let change = match next.pages.iter_mut().find(|e| e.page == key) {
            Some(entry) => {
                let change = match markdown_change_diff(&entry.markdown, markdown) {
                    Some(diff) => Change::Changed(diff),
                    None => Change::Same,
                };
                entry.markdown = markdown.to_owned();
                entry.seq = seq;
                change
            }
            None => {
                next.pages.push(Entry {
                    page: key,
                    seq,
                    markdown: markdown.to_owned(),
                });
                Change::New
            }
        };
        next.next = seq + 1;
        next.evict();
        self.save(&next)?;
        self.stored = next;
        Ok(change)
    }

    /// Forgets one page; its next extraction is new.
    pub fn forget(&mut self, url: &str) -> Result<bool, HostError> {
        let key = page_key(url);
        let mut next = self.stored.clone();
        next.pages.retain(|e| e.page != key);
        if next.pages.len() == self.stored.pages.len() {
            return Ok(false);
        }
        next.evict();
        self.save(&next)?;
        self.stored = next;
        Ok(true)
    }

    /// Forgets every page, and removes stray temporary files a failed or
    /// interrupted write left next to the store.
    pub fn clear(&mut self) -> Result<(), HostError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(HostError::Io(error)),
        }
        self.stored = Stored::empty();
        let (Some(dir), Some(name)) = (self.path.parent(), self.path.file_name()) else {
            return Ok(());
        };
        let prefix = format!("{}.", name.to_string_lossy());
        let dir = if dir.as_os_str().is_empty() {
            Path::new(".")
        } else {
            dir
        };
        let entries = match std::fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(HostError::Io(error)),
        };
        for entry in entries {
            let entry = entry?;
            let file = entry.file_name().to_string_lossy().into_owned();
            if is_temp_name(&file, &prefix) {
                match std::fs::remove_file(entry.path()) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(HostError::Io(error)),
                }
            }
        }
        Ok(())
    }

    /// Pages currently tracked.
    pub fn len(&self) -> usize {
        self.stored.pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stored.pages.is_empty()
    }

    /// Writes `stored` to a fresh temporary file next to the store, syncs
    /// it, then renames it over the store, so a crash leaves the old store
    /// or the new one.
    fn save(&self, stored: &Stored) -> Result<(), HostError> {
        let bytes = serde_json::to_vec(stored)
            .map_err(|_| invalid("change-tracking store cannot be encoded"))?;
        let temp = temp_path(&self.path);
        let written = (|| -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temp, &self.path)?;
            // The rename is done: the new store is what a reopen reads, so a
            // failure to sync the directory entry must not report the write
            // as failed (memory would then disagree with disk).
            #[cfg(unix)]
            {
                let dir = match self.path.parent() {
                    Some(dir) if !dir.as_os_str().is_empty() => dir,
                    _ => Path::new("."),
                };
                if let Ok(dir) = std::fs::File::open(dir) {
                    let _ = dir.sync_all();
                }
            }
            Ok(())
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(HostError::Io(error));
        }
        Ok(())
    }
}

/// Whether `file` is `<prefix><digits>.<digits>.tmp`, the shape of
/// `temp_path`.
fn is_temp_name(file: &str, prefix: &str) -> bool {
    let Some(middle) = file
        .strip_prefix(prefix)
        .and_then(|rest| rest.strip_suffix(".tmp"))
    else {
        return false;
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit());
    matches!(middle.split_once('.'), Some((pid, n)) if digits(pid) && digits(n))
}

/// `<store>.<pid>.<n>.tmp`, unique to this process and write.
fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(
        ".{}.{}.tmp",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory removed even when the test fails.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "orcel-wi04-{name}-{}-{}",
                std::process::id(),
                TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn store(&self) -> ChangeStore {
            ChangeStore::open(self.0.join("changes.json")).unwrap()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The donor's behaviour: a unified diff with context, structured
    /// changes with line numbers, and nothing when no line changed.
    #[test]
    fn wi04_a_changed_page_returns_its_diff() {
        let previous = "# Pricing\n\nBasic: $10\nPro: $20\nTeam: $50\n\nContact sales.\n";
        let current = "# Pricing\n\nBasic: $10\nPro: $25\nTeam: $50\n\nContact sales.\n";
        let diff = markdown_change_diff(previous, current).unwrap();
        assert!(!diff.truncated);
        assert_eq!(
            diff.text,
            "--- previous.md\n+++ current.md\n@@ -1,7 +1,7 @@\n # Pricing\n \n Basic: $10\n-Pro: $20\n+Pro: $25\n Team: $50\n \n Contact sales.\n"
        );
        let changed: Vec<_> = diff.hunks[0]
            .changes
            .iter()
            .filter(|c| c.kind != LineKind::Normal)
            .collect();
        assert_eq!(changed.len(), 2);
        assert_eq!(
            (changed[0].kind, changed[0].old_line, changed[0].new_line),
            (LineKind::Del, Some(4), None)
        );
        assert_eq!(
            (changed[1].kind, changed[1].old_line, changed[1].new_line),
            (LineKind::Add, None, Some(4))
        );
        assert_eq!(markdown_change_diff(previous, previous), None);
        assert_eq!(markdown_change_diff("", ""), None);
    }

    #[test]
    fn wi04_far_apart_changes_are_separate_hunks() {
        let previous: String = (1..=30).map(|n| format!("line {n}\n")).collect();
        let current = previous
            .replace("line 2\n", "line two\n")
            .replace("line 28\n", "");
        let diff = markdown_change_diff(&previous, &current).unwrap();
        assert_eq!(diff.hunks.len(), 2);
        assert_eq!(diff.hunks[0].header, "@@ -1,5 +1,5 @@");
        assert_eq!(diff.hunks[1].header, "@@ -25,6 +25,5 @@");
        let from_empty = markdown_change_diff("", "a\n").unwrap();
        assert_eq!(from_empty.hunks[0].header, "@@ -0,0 +1 @@");
        let at_top = markdown_change_diff("b\nc\n", "a\nb\nc\n").unwrap();
        assert_eq!(at_top.hunks[0].header, "@@ -1,2 +1,3 @@");
        let at_end = markdown_change_diff("a\nb\n", "a\n").unwrap();
        assert_eq!(at_end.hunks[0].header, "@@ -1,2 +1 @@");
        // A pure insertion in the middle: literal header.
        let middle: String = (1..=20).map(|n| format!("{n}\n")).collect();
        let inserted = middle.replace("10\n", "10\nnew\n");
        let diff = markdown_change_diff(&middle, &inserted).unwrap();
        assert_eq!(diff.hunks[0].header, "@@ -8,6 +8,7 @@");
    }

    #[test]
    fn wi04_line_ends_are_kept() {
        // A last line without a newline differs from one with it, and the
        // text says so, as jsdiff does.
        let diff = markdown_change_diff("x\na", "x\na\n").unwrap();
        assert_eq!(
            diff.text,
            "--- previous.md\n+++ current.md\n@@ -1,2 +1,2 @@\n x\n-a\n\\ No newline at end of file\n+a\n"
        );
        assert!(diff.hunks[0].changes[1].no_newline);
        assert!(!diff.hunks[0].changes[2].no_newline);
        // A `\r` stays in its line: CRLF to LF is visible, and a bare `\r`
        // does not split a line.
        let crlf = markdown_change_diff("a\r\n", "a\n").unwrap();
        assert_eq!(crlf.hunks[0].changes[0].content, "a\r");
        let bare = markdown_change_diff("a\rb\n", "a\rc\n").unwrap();
        assert_eq!(bare.hunks[0].header, "@@ -1 +1 @@");
    }

    #[test]
    fn wi04_a_change_too_large_to_show_is_still_a_change() {
        // One line just under the extraction bound, changed: no hunk fits,
        // yet the page changed.
        let previous = "a".repeat(MAX_EXTRACT_CHARS - 10);
        let current = format!("b{}", &previous[1..]);
        let diff = markdown_change_diff(&previous, &current).unwrap();
        assert!(diff.truncated);
        assert!(diff.text.len() <= MAX_DIFF_BYTES);
        let dir = Scratch::new("long");
        let mut store = dir.store();
        store.track("https://site.test/", &previous).unwrap();
        assert!(matches!(
            store.track("https://site.test/", &current).unwrap(),
            Change::Changed(ChangeDiff {
                truncated: true,
                ..
            })
        ));
    }

    #[test]
    fn wi04_a_huge_diff_is_cut_with_honest_headers() {
        let previous: String = (0..60_000).map(|n| format!("old line {n}\n")).collect();
        let current: String = (0..60_000).map(|n| format!("new line {n}\n")).collect();
        let started = Instant::now();
        let diff = markdown_change_diff(&previous, &current).unwrap();
        assert!(diff.truncated);
        assert!(diff.text.len() <= MAX_DIFF_BYTES, "{}", diff.text.len());
        for hunk in &diff.hunks {
            let old = hunk
                .changes
                .iter()
                .filter(|c| c.kind != LineKind::Add)
                .count();
            let new = hunk
                .changes
                .iter()
                .filter(|c| c.kind != LineKind::Del)
                .count();
            let first_old = hunk.changes.iter().find_map(|c| c.old_line).unwrap_or(0);
            let first_new = hunk.changes.iter().find_map(|c| c.new_line).unwrap_or(0);
            assert_eq!(
                hunk.header,
                format!(
                    "@@ -{} +{} @@",
                    if old == 1 {
                        first_old.to_string()
                    } else {
                        format!("{first_old},{old}")
                    },
                    if new == 1 {
                        first_new.to_string()
                    } else {
                        format!("{first_new},{new}")
                    }
                )
            );
        }
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn wi04_the_store_tracks_pages_by_canonical_url_across_opens() {
        let dir = Scratch::new("track");
        let mut store = dir.store();
        assert_eq!(
            store.track("https://site.test/docs/", "a\nb\n").unwrap(),
            Change::New
        );
        assert_eq!(
            store
                .track("HTTPS://Site.Test:443/docs#intro", "a\nb\n")
                .unwrap(),
            Change::Same
        );
        let mut reopened = dir.store();
        match reopened.track("https://site.test/docs", "a\nc\n").unwrap() {
            Change::Changed(diff) => assert!(diff.text.contains("-b\n+c\n")),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            reopened.track("https://site.test/other", "a\n").unwrap(),
            Change::New
        );
        assert_eq!(
            reopened.track("https://site.test", "r\n").unwrap(),
            Change::New
        );
        assert_eq!(
            reopened.track("https://site.test/", "r\n").unwrap(),
            Change::Same
        );
        assert_eq!(
            reopened
                .track("https://site.test/docs?page=2", "q\n")
                .unwrap(),
            Change::New,
            "the query is part of the page"
        );
        assert_eq!(
            page_key("https://User@Site.Test:443"),
            "https://User@site.test/",
            "user information keeps its case"
        );
        assert_eq!(
            page_key("https://site.test:8443/a"),
            "https://site.test:8443/a"
        );
        assert_eq!(reopened.len(), 4);
        assert!(reopened.forget("https://site.test/docs/").unwrap());
        assert!(!reopened.forget("https://site.test/never").unwrap());
        assert_eq!(dir.store().len(), 3, "forget is written");
        assert_eq!(
            reopened.track("https://site.test/docs", "a\n").unwrap(),
            Change::New
        );
        reopened.clear().unwrap();
        assert!(reopened.is_empty());
        assert!(!dir.0.join("changes.json").exists());
        assert!(dir.store().is_empty());
    }

    /// Over the page bound, the least recently tracked page is evicted.
    #[test]
    fn wi04_the_store_over_its_bound_evicts_the_oldest() {
        let dir = Scratch::new("evict");
        let mut store = dir.store();
        for n in 0..MAX_TRACKED_PAGES {
            store
                .track(&format!("https://site.test/p{n}"), "x\n")
                .unwrap();
        }
        // Touch p0 so p1 becomes the oldest.
        assert!(matches!(
            store.track("https://site.test/p0", "y\n").unwrap(),
            Change::Changed(_)
        ));
        store.track("https://site.test/new", "z\n").unwrap();
        assert_eq!(store.len(), MAX_TRACKED_PAGES);
        let mut reopened = dir.store();
        assert_eq!(
            reopened.track("https://site.test/p1", "x\n").unwrap(),
            Change::New,
            "p1 was evicted"
        );
        assert_eq!(
            reopened.track("https://site.test/p0", "y\n").unwrap(),
            Change::Same,
            "p0 was kept"
        );
        assert!(
            reopened.stored.next <= MAX_TRACKED_PAGES as u64,
            "seq is renumbered"
        );
    }

    /// The byte bound, on the eviction rule itself (writing a 64 MiB store
    /// dozens of times would only test the disk).
    #[test]
    fn wi04_the_byte_bound_evicts_too() {
        let big = "x".repeat(MAX_EXTRACT_CHARS);
        let fit = MAX_TRACKED_BYTES / MAX_EXTRACT_CHARS;
        let mut stored = Stored {
            schema: SCHEMA,
            next: fit as u64 + 1,
            // Out of order on purpose: eviction goes by `seq`.
            pages: (0..=fit)
                .rev()
                .map(|n| Entry {
                    page: format!("https://site.test/b{n}"),
                    seq: n as u64,
                    markdown: big.clone(),
                })
                .collect(),
        };
        stored.evict();
        assert_eq!(stored.pages.len(), fit);
        let pages: Vec<&str> = stored.pages.iter().map(|e| e.page.as_str()).collect();
        assert!(!pages.contains(&"https://site.test/b0"), "the oldest went");
        assert_eq!(pages[0], "https://site.test/b1");
        assert_eq!(pages[fit - 1], format!("https://site.test/b{fit}"));
        assert!(stored.valid());
    }

    #[test]
    fn wi04_a_failed_write_changes_nothing() {
        let dir = Scratch::new("fail");
        let path = dir.0.join("changes.json");
        let mut store = ChangeStore::open(&path).unwrap();
        store.track("https://site.test/a", "one\n").unwrap();
        // Make the store's name a directory: the rename over it fails.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(matches!(
            store.track("https://site.test/a", "two\n"),
            Err(HostError::Io(_))
        ));
        assert!(matches!(
            store.forget("https://site.test/a"),
            Err(HostError::Io(_))
        ));
        assert_eq!(store.len(), 1, "memory unchanged");
        std::fs::remove_dir(&path).unwrap();
        // The unsaved "two" never became the baseline.
        assert!(matches!(
            store.track("https://site.test/a", "two\n").unwrap(),
            Change::Changed(_)
        ));
        let leftovers: Vec<_> = std::fs::read_dir(&dir.0)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(leftovers, ["changes.json"], "no temporary file is left");
    }

    #[test]
    fn wi04_clear_removes_stray_temporary_files() {
        let dir = Scratch::new("clear");
        let mut store = dir.store();
        store
            .track("https://site.test/a", "secret page text\n")
            .unwrap();
        let stray = dir.0.join("changes.json.999.0.tmp");
        std::fs::write(&stray, "secret page text").unwrap();
        let unrelated = dir.0.join("other.tmp");
        std::fs::write(&unrelated, "x").unwrap();
        let lookalike = dir.0.join("changes.json.backup.tmp");
        std::fs::write(&lookalike, "x").unwrap();
        store.clear().unwrap();
        assert!(!stray.exists());
        assert!(unrelated.exists(), "only the store's own temporary files");
        assert!(lookalike.exists(), "only the exact temporary-file shape");
    }

    #[test]
    fn wi04_bad_input_and_bad_stores_are_refused() {
        let dir = Scratch::new("bad");
        let mut store = dir.store();
        assert!(store
            .track("https://site.test/", &"x".repeat(MAX_EXTRACT_CHARS + 1))
            .is_err());
        assert!(store.is_empty());
        let path = dir.0.join("changes.json");
        let refused = |content: &[u8]| {
            std::fs::write(&path, content).unwrap();
            matches!(ChangeStore::open(&path), Err(HostError::Invalid(_)))
        };
        assert!(
            refused(b"not json"),
            "a corrupt store is refused, not replaced"
        );
        assert!(refused(
            br#"{"schema":1,"next":0,"pages":[{"page":"p","seq":0,"markdown":""}]}"#
        ));
        assert!(refused(br#"{"schema":2,"next":0,"pages":[]}"#));
        assert!(refused(
            br#"{"schema":1,"next":2,"pages":[{"page":"p","seq":0,"markdown":""},{"page":"p","seq":1,"markdown":""}]}"#
        ), "duplicate pages");
        assert!(
            refused(br#"{"schema":1,"next":18446744073709551615,"pages":[]}"#),
            "a runaway seq"
        );
        assert!(!refused(
            br#"{"schema":1,"next":1,"pages":[{"page":"p","seq":0,"markdown":""}]}"#
        ));
        // The read is bounded before parsing.
        std::fs::write(&path, vec![b' '; 64]).unwrap();
        assert!(matches!(
            read_bounded(&path, 63),
            Err(HostError::Invalid(_))
        ));
        assert_eq!(read_bounded(&path, 64).unwrap().unwrap().len(), 64);
        assert!(read_bounded(&dir.0.join("missing"), 64).unwrap().is_none());
    }
}
