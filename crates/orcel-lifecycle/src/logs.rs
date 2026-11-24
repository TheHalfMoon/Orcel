//! Bounded, redacted lifecycle logs.
//!
//! Tunnel-client output is written line by line through [`redact_line`],
//! which replaces key-like tokens and credential assignments. The redactor
//! never reads the runtime key file, so the key itself cannot be copied into a
//! log by the redaction logic.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MAX_LINE_CHARS: usize = 4096;
const TRUNCATED: &str = " [TRUNCATED]";
pub const REDACTED: &str = "[REDACTED]";

/// Credential assignment names, longest first so compound names win.
const ASSIGNMENT_MARKERS: &[&str] = &[
    "refresh_token",
    "access_token",
    "authorization",
    "credential",
    "password",
    "api_key",
    "api-key",
    "session",
    "apikey",
    "passwd",
    "secret",
    "cookie",
    "token",
    "pwd",
    "key",
];

/// Prefixes of well-known key formats and the minimum number of key
/// characters that must follow them.
const KEY_PREFIXES: &[(&str, usize)] =
    &[("github_pat_", 16), ("sess-", 8), ("ghp_", 16), ("sk-", 8)];

/// Redacts one log line and bounds its length. Tokens are split on spaces
/// and tabs; within a token every credential assignment (`name=value`,
/// `name:value`, quoted JSON forms) and every key-like value is replaced.
/// When a credential value starts in a following token (`password: secret`,
/// `--api-key value`, pretty-printed JSON) or is a quoted value that does not
/// close within its token, the rest of the line is redacted, because the
/// value's extent cannot be known and over-redaction is the safe direction.
/// An authorization scheme (`Bearer`, `Basic`) redacts exactly one token.
pub fn redact_line(line: &str) -> String {
    let mut out = Vec::new();
    let mut scheme_pending = false;
    let mut redact_rest = false;
    let mut awaiting_separator = false;
    for token in line.split([' ', '\t']) {
        if token.is_empty() {
            out.push(String::new());
            continue;
        }
        if redact_rest {
            out.push(REDACTED.to_string());
            continue;
        }
        if awaiting_separator && matches!(token, "=" | ":" | "=>") {
            out.push(token.to_string());
            awaiting_separator = false;
            redact_rest = true;
            continue;
        }
        awaiting_separator = false;
        let lower = token.to_ascii_lowercase();
        if lower == "bearer" || lower == "basic" {
            out.push(token.to_string());
            scheme_pending = true;
            continue;
        }
        if scheme_pending {
            out.push(REDACTED.to_string());
            scheme_pending = false;
            continue;
        }
        let (redacted, continues) = redact_token(token);
        out.push(redacted);
        redact_rest = continues;
        let bare = lower.trim_matches(|c: char| c == '"' || c == '\'');
        // An option such as `--api-key` or `--control-plane.api-key` whose
        // value follows in the next token(s).
        let option_name = bare
            .strip_prefix('-')
            .filter(|_| !bare.contains('='))
            .and_then(|name| name.rsplit(['.', '-', '_']).next());
        if option_name.is_some_and(|last| marker_len(last.as_bytes()) == Some(last.len())) {
            redact_rest = true;
        }
        awaiting_separator = !redact_rest && marker_len(bare.as_bytes()) == Some(bare.len());
    }
    let joined = out.join(" ");
    if joined.chars().count() > MAX_LINE_CHARS {
        joined
            .chars()
            .take(MAX_LINE_CHARS - TRUNCATED.len())
            .collect::<String>()
            + TRUNCATED
    } else {
        joined
    }
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn is_quote(byte: u8) -> bool {
    byte == b'"' || byte == b'\''
}

fn key_like_len(rest: &[u8]) -> Option<usize> {
    KEY_PREFIXES.iter().find_map(|(prefix, minimum)| {
        let prefix = prefix.as_bytes();
        if !rest.starts_with(prefix) {
            return None;
        }
        let body = rest[prefix.len()..]
            .iter()
            .take_while(|byte| is_word(**byte) || **byte == b'.')
            .count();
        (body >= *minimum).then_some(prefix.len() + body)
    })
}

fn marker_len(rest: &[u8]) -> Option<usize> {
    ASSIGNMENT_MARKERS.iter().find_map(|marker| {
        let marker = marker.as_bytes();
        let bounded =
            rest.starts_with(marker) && rest.get(marker.len()).is_none_or(|next| !is_word(*next));
        bounded.then_some(marker.len())
    })
}

/// Redacts every credential assignment and key-like value in one
/// whitespace-free token. Returns the redacted token and whether its last
/// assignment has no value in this token (so the next token is the value).
fn redact_token(token: &str) -> (String, bool) {
    let lower = token.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(token.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        // `_` and `-` separate name parts (OPENAI_API_KEY, --api-key), so only
        // an alphanumeric predecessor means the match is inside a word.
        let at_boundary = index == 0 || !bytes[index - 1].is_ascii_alphanumeric();
        if at_boundary {
            if let Some(length) = key_like_len(&bytes[index..]) {
                out.push_str(&token[copied..index]);
                out.push_str(REDACTED);
                index += length;
                copied = index;
                continue;
            }
            if let Some(length) = marker_len(&bytes[index..]) {
                let mut separator = index + length;
                while separator < bytes.len() && is_quote(bytes[separator]) {
                    separator += 1;
                }
                if separator < bytes.len() && (bytes[separator] == b'=' || bytes[separator] == b':')
                {
                    let mut start = separator + 1;
                    while start < bytes.len() && is_quote(bytes[start]) {
                        start += 1;
                    }
                    if start >= bytes.len() {
                        out.push_str(&token[copied..]);
                        return (out, true);
                    }
                    let quoted = start > separator + 1;
                    let mut end = start;
                    while end < bytes.len()
                        && !matches!(
                            bytes[end],
                            b'&' | b',' | b';' | b'"' | b'\'' | b'}' | b')' | b']'
                        )
                    {
                        end += 1;
                    }
                    out.push_str(&token[copied..start]);
                    out.push_str(REDACTED);
                    if quoted && end >= bytes.len() {
                        // The quoted value continues past this token.
                        return (out, true);
                    }
                    index = end;
                    copied = end;
                    continue;
                }
            }
        }
        index += 1;
    }
    out.push_str(&token[copied..]);
    (out, false)
}

/// An append-only log file with one rotated generation.
pub struct BoundedLog {
    path: PathBuf,
    file: File,
    written: u64,
}

impl BoundedLog {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = open_append(path)?;
        let written = file.metadata()?.len();
        Ok(Self {
            path: path.to_path_buf(),
            file,
            written,
        })
    }

    pub fn write_line(&mut self, line: &str) -> std::io::Result<()> {
        let redacted = redact_line(line);
        let bytes = redacted.len() as u64 + 1;
        if self.written + bytes > MAX_LOG_BYTES {
            self.rotate()?;
        }
        writeln!(self.file, "{redacted}")?;
        self.written += bytes;
        Ok(())
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        let rotated = self.path.with_extension("log.1");
        let _ = fs::remove_file(&rotated);
        fs::rename(&self.path, &rotated)?;
        self.file = open_append(&self.path)?;
        self.written = 0;
        Ok(())
    }
}

/// Opens a log for appending. On Unix it is created 0600 whatever the umask,
/// a link under its name is not followed, and one already there must be this
/// user's plain file and is made 0600
/// ([`orcel_platform::files::open_private_append`]).
fn open_append(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        orcel_platform::files::open_private_append(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    }
}

/// Appends one redacted, timestamped line to `logs\lifecycle.log`. The
/// transcript records lifecycle commands, versions, and outcomes only; a
/// failure to write it never changes the outcome of the command.
pub fn transcript(layout: &crate::layout::Layout, line: &str) {
    // Never write through a link or reparse point: the logs directory and the
    // file must be plain entries beneath the install root.
    let path = layout.logs_dir().join("lifecycle.log");
    if layout.ensure_private_root().is_err() {
        return;
    }
    for entry in [layout.logs_dir(), path.clone()] {
        if let Ok(metadata) = fs::symlink_metadata(&entry) {
            if metadata.file_type().is_symlink() || crate::manifest::is_reparse_point(&metadata) {
                return;
            }
        }
    }
    // Opening a FIFO nobody reads would wait for ever.
    if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.is_file()) {
        return;
    }
    if let Ok(mut log) = BoundedLog::open(&path) {
        let _ = log.write_line(&format!("{} {line}", crate::lifecycle::now_ms()));
    }
}

/// Returns up to `max_lines` final lines of a log file.
pub fn tail(path: &Path, max_lines: usize) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    let lines = text.lines().collect::<Vec<_>>();
    lines[lines.len().saturating_sub(max_lines)..]
        .iter()
        .map(|line| line.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::temp_dir;

    fn assert_hidden(line: &str, secrets: &[&str]) -> String {
        let out = redact_line(line);
        for secret in secrets {
            assert!(
                !out.contains(secret),
                "{secret} survived in {out:?} (from {line:?})"
            );
        }
        out
    }

    #[test]
    fn key_like_tokens_and_assignments_are_redacted() {
        let out = assert_hidden(
            "connect api_key=sk-proj-abcdef123456 token: abc Authorization: Bearer xyz.123 key sk-1234567890ab ok",
            &["sk-proj-abcdef123456", "abc", "xyz.123", "sk-1234567890ab"],
        );
        assert!(out.contains("api_key=[REDACTED]"), "{out}");
        assert!(out.starts_with("connect"));
        // A spaced credential (`token: abc`) redacts the rest of the line.
        assert!(out.ends_with(REDACTED), "{out}");
        assert_hidden(r#"{"password":"hunter22","user":"u"}"#, &["hunter22"]);
    }

    #[test]
    fn spaced_tabbed_pretty_and_later_assignments_are_redacted() {
        assert_hidden("password: hunter22", &["hunter22"]);
        assert_hidden("password = hunter22", &["hunter22"]);
        assert_hidden(r#"  "password": "hunter22","#, &["hunter22"]);
        assert_hidden("value	sk-abcdefghijklmnop", &["sk-abcdefghijklmnop"]);
        assert_hidden("value	sk-abcdefghijklmnop", &["sk-abcdefghijklmnop"]);
        assert_hidden("GET /cb?x=1&token=abc123&y=2", &["abc123"]);
        assert_hidden(r#"{"user":"u","password":"hunter22"}"#, &["hunter22"]);
        assert_hidden("key=sk-proj-abcdef123456", &["sk-proj-abcdef123456"]);
        assert_hidden("session=s3cr3t-value;path=/", &["s3cr3t-value"]);
        assert_hidden("Authorization: Basic dXNlcjpwYXNz", &["dXNlcjpwYXNz"]);
        assert_hidden("cookie: id=abc", &["id=abc"]);
        assert_hidden(
            "OPENAI_API_KEY=sk-proj-abcdef123456",
            &["sk-proj-abcdef123456"],
        );
        assert_hidden("env OPENAI_API_KEY=plainsecret", &["plainsecret"]);
        assert_hidden("--api-key=plainsecret", &["plainsecret"]);
        assert_hidden("--api-key plainsecret", &["plainsecret"]);
        assert_hidden(
            r#"--api-key "C:\path with space" --verbose"#,
            &["path", "with", "space"],
        );
        assert_hidden(r"--api-key file:C:\keys k", &["keys", " k"]);
        assert_hidden("password: two words here", &["two", "words", "here"]);
        assert_hidden(r#"password="two words" next"#, &["two", "words"]);
        let scheme = redact_line("Authorization: Bearer abc.def next-field");
        assert!(!scheme.contains("abc.def"), "{scheme}");
        assert_hidden(
            r"--control-plane.api-key file:C:\keys\k",
            &[r"file:C:\keys\k"],
        );
        assert_eq!(
            redact_line(r"--health.url-file C:\run\h.url"),
            r"--health.url-file C:\run\h.url"
        );
        assert_hidden("CONTROL_PLANE_TOKEN: plainsecret", &["plainsecret"]);
    }

    #[test]
    fn ordinary_words_containing_markers_are_not_redacted() {
        for line in [
            "monkey=banana",
            "tokens=5 keys=3",
            "turkey: roasted",
            "tunnel connected to control plane in 120ms",
        ] {
            assert_eq!(redact_line(line), line);
        }
    }

    #[cfg(unix)]
    #[test]
    fn transcript_never_writes_through_a_link() {
        let base = temp_dir("transcript-link");
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let layout = crate::layout::Layout::new(base.join("Orcel"));
        fs::create_dir_all(&layout.root).unwrap();
        std::os::unix::fs::symlink(&outside, layout.logs_dir()).unwrap();
        transcript(&layout, "install 0.1.0 installed");
        assert!(!outside.join("lifecycle.log").exists());
    }

    /// The lifecycle log is owner-only whatever the umask or its mode was,
    /// and a link or FIFO under its name is left alone.
    #[cfg(unix)]
    #[test]
    fn the_lifecycle_log_is_owner_only_and_never_a_link_or_fifo() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        let set = |path: &Path, mode| {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        };
        let base = temp_dir("transcript-mode");
        set(&base, 0o755);
        let layout = crate::layout::Layout::new(base.join("Orcel"));
        fs::create_dir_all(layout.logs_dir()).unwrap();
        set(&layout.root, 0o700);
        let log = layout.logs_dir().join("lifecycle.log");
        transcript(&layout, "one");
        assert_eq!(mode(&log), 0o600, "created");
        set(&log, 0o664);
        transcript(&layout, "two");
        assert_eq!(mode(&log), 0o600, "already there");
        assert_eq!(tail(&log, 5).len(), 2);

        fs::remove_file(&log).unwrap();
        let outside = base.join("outside");
        std::os::unix::fs::symlink(&outside, &log).unwrap();
        assert!(BoundedLog::open(&log).is_err(), "not followed");
        transcript(&layout, "three");
        assert!(!outside.exists());
        fs::remove_file(&log).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(&log)
            .status()
            .unwrap();
        assert!(made.success());
        // Returns; opening the FIFO would not.
        transcript(&layout, "four");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn log_rotates_at_the_bound() {
        let dir = temp_dir("logs");
        let path = dir.join("tunnel.log");
        let mut log = BoundedLog::open(&path).unwrap();
        let line = "y".repeat(4000);
        for _ in 0..300 {
            log.write_line(&line).unwrap();
        }
        assert!(fs::metadata(&path).unwrap().len() <= MAX_LOG_BYTES);
        assert!(dir.join("tunnel.log.1").is_file());
        assert_eq!(tail(&path, 2).len(), 2);
    }
}
