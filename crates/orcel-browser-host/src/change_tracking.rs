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
//! and unchanged lines with their line numbers), and "no change" when no
//! line was added or deleted. Orcel's changes: the diff is computed by the
//! `similar` crate (Myers, with a deadline) instead of the `diff` and
//! `parse-diff` packages; pages are keyed by their canonical URL (WI-01)
//! without a fragment; the store is one bounded file in the workspace the
//! caller names (at most `MAX_TRACKED_PAGES` pages and `MAX_TRACKED_BYTES`
//! of Markdown, the least recently tracked evicted first), written whole
//! and atomically, and the user can clear it or forget one page; a diff
//! larger than the extraction bound is cut and marked truncated. Stored and
//! returned text is still untrusted page text, with no authority.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use similar::{ChangeTag, TextDiff};

use crate::crawl_scope::canonical;
use crate::error::HostError;
use crate::extraction::MAX_EXTRACT_CHARS;

/// Pages one workspace's store keeps.
pub const MAX_TRACKED_PAGES: usize = 256;
/// Markdown bytes one workspace's store keeps, in all.
pub const MAX_TRACKED_BYTES: usize = 64 * 1024 * 1024;
/// Time one comparison may take before it settles for a coarser diff.
const DIFF_DEADLINE: Duration = Duration::from_secs(2);
/// Lines of context around each change (the donor's `context: 3`).
const CONTEXT_LINES: usize = 3;
/// The store file's format.
const SCHEMA: u32 = 1;

/// One line of a hunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LineChange {
    pub kind: LineKind,
    /// Line number in the previous extraction (unchanged and deleted lines).
    pub old_line: Option<usize>,
    /// Line number in the current extraction (unchanged and added lines).
    pub new_line: Option<usize>,
    pub content: String,
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
    /// The diff was cut at the extraction bound.
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

/// The donor's `createMarkdownChangeDiff`: `None` when no line changed.
pub fn markdown_change_diff(previous: &str, current: &str) -> Option<ChangeDiff> {
    let diff = TextDiff::configure()
        .algorithm(similar::Algorithm::Myers)
        .deadline(Instant::now() + DIFF_DEADLINE)
        .diff_lines(previous, current);
    let mut hunks = Vec::new();
    let mut size = 0usize;
    let mut truncated = false;
    'groups: for group in diff.grouped_ops(CONTEXT_LINES) {
        let (Some(first), Some(last)) = (group.first(), group.last()) else {
            continue;
        };
        let old = first.old_range().start..last.old_range().end;
        let new = first.new_range().start..last.new_range().end;
        let header = format!(
            "@@ -{} +{} @@",
            range_text(old.start, old.len()),
            range_text(new.start, new.len())
        );
        let mut hunk = Hunk {
            header,
            changes: Vec::new(),
        };
        size += hunk.header.len() + 1;
        for op in &group {
            for change in diff.iter_changes(op) {
                let content = change.value().trim_end_matches(['\n', '\r']).to_owned();
                size += content.len() + 2;
                if size > MAX_EXTRACT_CHARS {
                    truncated = true;
                    if !hunk.changes.is_empty() {
                        hunks.push(hunk);
                    }
                    break 'groups;
                }
                let kind = match change.tag() {
                    ChangeTag::Equal => LineKind::Normal,
                    ChangeTag::Insert => LineKind::Add,
                    ChangeTag::Delete => LineKind::Del,
                };
                hunk.changes.push(LineChange {
                    kind,
                    old_line: change.old_index().map(|at| at + 1),
                    new_line: change.new_index().map(|at| at + 1),
                    content,
                });
            }
        }
        hunks.push(hunk);
    }
    let changed = hunks
        .iter()
        .flat_map(|hunk| &hunk.changes)
        .any(|change| change.kind != LineKind::Normal);
    if !changed {
        return None;
    }
    let mut text = String::from("--- previous.md\n+++ current.md\n");
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

/// The last extraction of each page, for one workspace.
#[derive(Debug)]
pub struct ChangeStore {
    path: PathBuf,
    stored: Stored,
}

fn invalid(message: &str) -> HostError {
    HostError::Invalid(message.into())
}

/// The store's key for a URL: its canonical form, without a fragment.
fn page_key(url: &str) -> String {
    canonical(url.split('#').next().unwrap_or(url))
}

impl ChangeStore {
    /// Opens the store at `path` (a file in the workspace's own state);
    /// a missing file is an empty store. A file that does not parse, or
    /// breaks the bounds, is refused rather than silently replaced.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, HostError> {
        let path = path.into();
        let stored = match std::fs::read(&path) {
            Ok(bytes) => {
                let stored: Stored = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("change-tracking store does not parse"))?;
                let bytes: usize = stored.pages.iter().map(|e| e.markdown.len()).sum();
                if stored.schema != SCHEMA
                    || stored.pages.len() > MAX_TRACKED_PAGES
                    || bytes > MAX_TRACKED_BYTES
                    || stored.pages.iter().any(|e| e.seq >= stored.next)
                {
                    return Err(invalid("change-tracking store is not valid"));
                }
                stored
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Stored {
                schema: SCHEMA,
                next: 0,
                pages: Vec::new(),
            },
            Err(_) => return Err(invalid("change-tracking store cannot be read")),
        };
        Ok(Self { path, stored })
    }

    /// Compares `markdown` with the page's last tracked extraction, then
    /// keeps `markdown` as the page's latest.
    pub fn track(&mut self, url: &str, markdown: &str) -> Result<Change, HostError> {
        if markdown.chars().count() > MAX_EXTRACT_CHARS {
            return Err(invalid("extraction is larger than the extraction bound"));
        }
        let key = page_key(url);
        let seq = self.stored.next;
        let change = match self.stored.pages.iter_mut().find(|e| e.page == key) {
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
                self.stored.pages.push(Entry {
                    page: key,
                    seq,
                    markdown: markdown.to_owned(),
                });
                Change::New
            }
        };
        self.stored.next += 1;
        self.evict();
        self.save()?;
        Ok(change)
    }

    /// Forgets one page; its next extraction is new.
    pub fn forget(&mut self, url: &str) -> Result<bool, HostError> {
        let key = page_key(url);
        let before = self.stored.pages.len();
        self.stored.pages.retain(|e| e.page != key);
        let removed = self.stored.pages.len() != before;
        if removed {
            self.save()?;
        }
        Ok(removed)
    }

    /// Forgets every page.
    pub fn clear(&mut self) -> Result<(), HostError> {
        self.stored.pages.clear();
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(invalid("change-tracking store cannot be cleared")),
        }
    }

    /// Pages currently tracked.
    pub fn len(&self) -> usize {
        self.stored.pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.stored.pages.is_empty()
    }

    /// Drops the least recently tracked pages until both bounds hold.
    fn evict(&mut self) {
        self.stored.pages.sort_by_key(|e| e.seq);
        let mut bytes: usize = self.stored.pages.iter().map(|e| e.markdown.len()).sum();
        let mut drop = 0;
        while self.stored.pages.len() - drop > MAX_TRACKED_PAGES || bytes > MAX_TRACKED_BYTES {
            bytes -= self.stored.pages[drop].markdown.len();
            drop += 1;
        }
        self.stored.pages.drain(..drop);
    }

    /// Writes the whole store to a sibling file, then renames it over the
    /// store, so a crash leaves the old store or the new one.
    fn save(&self) -> Result<(), HostError> {
        let bytes = serde_json::to_vec(&self.stored)
            .map_err(|_| invalid("change-tracking store cannot be encoded"))?;
        let temp = temp_path(&self.path);
        let written =
            std::fs::write(&temp, bytes).and_then(|()| std::fs::rename(&temp, &self.path));
        if written.is_err() {
            let _ = std::fs::remove_file(&temp);
            return Err(invalid("change-tracking store cannot be written"));
        }
        Ok(())
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store_in(dir: &Path) -> ChangeStore {
        ChangeStore::open(dir.join("changes.json")).unwrap()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "orcel-wi04-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
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
    }

    #[test]
    fn wi04_the_store_tracks_pages_by_canonical_url_across_opens() {
        let dir = scratch("track");
        let mut store = store_in(&dir);
        assert_eq!(
            store.track("https://site.test/docs/", "a\nb\n").unwrap(),
            Change::New
        );
        assert_eq!(
            store
                .track("https://site.test/docs#intro", "a\nb\n")
                .unwrap(),
            Change::Same
        );
        let mut reopened = store_in(&dir);
        match reopened.track("https://site.test/docs", "a\nc\n").unwrap() {
            Change::Changed(diff) => assert!(diff.text.contains("-b\n+c\n")),
            other => panic!("{other:?}"),
        }
        assert_eq!(
            reopened.track("https://site.test/other", "a\n").unwrap(),
            Change::New
        );
        assert_eq!(reopened.len(), 2);
        assert!(reopened.forget("https://site.test/docs/").unwrap());
        assert_eq!(
            reopened.track("https://site.test/docs", "a\n").unwrap(),
            Change::New
        );
        reopened.clear().unwrap();
        assert!(reopened.is_empty());
        assert!(!dir.join("changes.json").exists());
        assert!(store_in(&dir).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Over the page bound, the least recently tracked page is evicted.
    #[test]
    fn wi04_the_store_over_its_bound_evicts_the_oldest() {
        let dir = scratch("evict");
        let mut store = store_in(&dir);
        for n in 0..MAX_TRACKED_PAGES {
            store
                .track(&format!("https://site.test/p{n}"), "x\n")
                .unwrap();
        }
        // Touch p0 so p1 becomes the oldest.
        assert_eq!(
            store.track("https://site.test/p0", "y\n").unwrap(),
            Change::Changed(markdown_change_diff("x\n", "y\n").unwrap())
        );
        store.track("https://site.test/new", "z\n").unwrap();
        assert_eq!(store.len(), MAX_TRACKED_PAGES);
        let mut reopened = store_in(&dir);
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
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The byte bound, on the eviction rule itself (writing a 64 MiB store
    /// dozens of times would only test the disk).
    #[test]
    fn wi04_the_byte_bound_evicts_too() {
        let big = "x".repeat(MAX_EXTRACT_CHARS);
        let fit = MAX_TRACKED_BYTES / MAX_EXTRACT_CHARS;
        let mut store = ChangeStore {
            path: PathBuf::from("unused"),
            stored: Stored {
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
            },
        };
        store.evict();
        assert_eq!(store.len(), fit);
        let pages: Vec<&str> = store.stored.pages.iter().map(|e| e.page.as_str()).collect();
        assert!(!pages.contains(&"https://site.test/b0"), "the oldest went");
        assert!(pages.contains(&"https://site.test/b1"));
        assert!(pages.contains(&format!("https://site.test/b{fit}").as_str()));
    }

    #[test]
    fn wi04_bad_input_and_bad_stores_are_refused() {
        let dir = scratch("bad");
        let mut store = store_in(&dir);
        assert!(store
            .track("https://site.test/", &"x".repeat(MAX_EXTRACT_CHARS + 1))
            .is_err());
        assert!(store.is_empty());
        let path = dir.join("changes.json");
        std::fs::write(&path, b"not json").unwrap();
        assert!(
            ChangeStore::open(&path).is_err(),
            "a corrupt store is refused, not replaced"
        );
        std::fs::write(
            &path,
            br#"{"schema":1,"next":0,"pages":[{"page":"p","seq":0,"markdown":""}]}"#,
        )
        .unwrap();
        assert!(ChangeStore::open(&path).is_err(), "seq must be below next");
        std::fs::write(&path, br#"{"schema":2,"next":0,"pages":[]}"#).unwrap();
        assert!(ChangeStore::open(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wi04_a_huge_diff_is_cut_and_marked() {
        let previous: String = (0..60_000).map(|n| format!("old line {n}\n")).collect();
        let current: String = (0..60_000).map(|n| format!("new line {n}\n")).collect();
        let started = Instant::now();
        let diff = markdown_change_diff(&previous, &current).unwrap();
        assert!(diff.truncated);
        assert!(diff.text.len() <= MAX_EXTRACT_CHARS + 64 * 1024);
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
