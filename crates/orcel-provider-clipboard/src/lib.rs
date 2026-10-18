//! SG-000038 bounded clipboard-read provider with SG-000039 bounded
//! clipboard-write extension.
//!
//! This crate implements the narrow P11 clipboard authority authorized
//! by the SG-000038 and SG-000039 SpecGrains: one explicit
//! `clipboard/read` shape returning Unicode text only, and one explicit
//! `clipboard/write` shape placing Unicode text only, each with a hard
//! 65536-byte bound, independent content-type verification,
//! deterministic secret-pattern denial, clipboard-sequence binding, and
//! bounded secret-free evidence.
//!
//! Every request represents a single bounded operation. Reads never
//! become persistent observation authority and writes never become
//! paste, input, keyboard, or desktop authority: clipboard write,
//! subscriptions, polling, monitoring, history collection, standing
//! sessions, input injection, and paste automation have no function here
//! beyond the single explicit placement, and must fail closed in the
//! policy and dispatch layers. Network authority does not exist in this
//! crate.
//!
//! Secret model: secret-pattern clipboard content is denied before any
//! placement or return path and never enters results, evidence, prompts,
//! logs, or MCP responses. Detection is deterministic pattern matching
//! over documented credential, token, key, seed, and Orcel-protected
//! families. It is not claimed to be perfect: novel exfiltration shapes
//! outside the documented families are a stated limitation, and the
//! fail-closed direction (deny on match, never leak on match) is the
//! guarantee.
//!
//! Windows reality: the native adapter moves Unicode text through the
//! real Win32 clipboard APIs (`OpenClipboard`, `GetClipboardData` and
//! `SetClipboardData` with `CF_UNICODETEXT`, `GlobalLock`,
//! `GlobalAlloc`) and binds the real clipboard sequence number
//! (`GetClipboardSequenceNumber`) without moving content for state
//! binding, so pre-approval and post-approval sequence drift fails
//! closed. A locked, empty, non-text, oversized, unwritable, or
//! otherwise unreadable clipboard fails closed with a typed error
//! instead of fabricated content. Deterministic read, write, bound,
//! denial, and secret policy is proven through the injected fake
//! adapter on every platform. These limits are recorded honestly and
//! must not be read as interactive clipboard evidence beyond what the
//! tests and the native gating test genuinely prove.
//!
//! macOS and Linux reality (XP-15): the native adapter in `unix.rs`
//! moves Unicode text through clipboard-rs (NSPasteboard; X11 or Wayland
//! data-control) under the same bounds, secret denial, and typed
//! fail-closed errors. Its sequence is derived from the clipboard text,
//! and a Wayland session that would need a focused surface reports the
//! clipboard unavailable instead of spawning helper processes. Other
//! platforms fail closed as unavailable.

use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix;

/// Schema label for bounded clipboard-read results and evidence.
pub const CLIPBOARD_SCHEMA: &str = "orcel-clipboard-read-v1";

/// Schema label for bounded clipboard-write evidence.
pub const WRITE_SCHEMA: &str = "orcel-clipboard-write-v1";

/// The only clipboard content format SG-000038 authorizes: plain Unicode
/// text. Bitmap, file-drop, audio, shell-object, HTML/RTF objects, and
/// every other binary or object format is denied with no hidden transfer.
pub const UNICODE_TEXT_FORMAT: &str = "unicode-text";

/// Hard maximum clipboard-read payload in bytes of UTF-8 text. Oversized
/// content fails closed with no silent truncation that changes read
/// semantics.
pub const MAX_CLIPBOARD_BYTES: usize = 65536;

/// Maximum workspace/policy string length accepted by the read path.
/// Oversized scope strings fail closed as malformed.
pub const MAX_SCOPE_CHARS: usize = 256;

/// The single SG-000038 read shape. Every other clipboard-like shape must
/// fail closed.
pub fn is_clipboard_read_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("clipboard", "read"))
}

/// The single SG-000039 write shape. Placement never authorizes paste,
/// input, keyboard, or desktop authority of any kind.
pub fn is_clipboard_write_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("clipboard", "write"))
}

/// Typed denial catalog for clipboard shapes that remain unauthorized.
/// Subscription, polling, monitoring, history, and watch shapes are
/// denied here so policy can map them to the STRONG gate and dispatch
/// can fail closed without reaching the provider. Clipboard write left
/// this catalog under SG-000039 and is authorized separately; clipboard
/// read never appeared here.
pub const DENIED_CLIPBOARD_SHAPES: &[(&str, &str)] = &[
    ("clipboard", "subscribe"),
    ("clipboard", "poll"),
    ("clipboard", "monitor"),
    ("clipboard", "history"),
    ("clipboard", "watch"),
];

pub fn is_denied_clipboard_shape(capability: &str, operation: &str) -> bool {
    DENIED_CLIPBOARD_SHAPES
        .iter()
        .any(|(denied_capability, denied_operation)| {
            *denied_capability == capability && *denied_operation == operation
        })
}

#[derive(Debug, Clone)]
pub struct ClipboardError {
    pub code: FailureCode,
    pub message: String,
}

impl ClipboardError {
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn digest_hex(material: &str, chars: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.chars().take(chars).collect()
}

/// SHA-256 hex digest of one clipboard-read payload, used in evidence so
/// payload comparisons never require moving raw text through logs or
/// metadata paths. Secret-denied content never reaches this function
/// because denial happens before digest binding.
pub fn clipboard_content_digest(text: &str) -> String {
    digest_hex(&format!("{CLIPBOARD_SCHEMA}|payload|{text}"), 64)
}

/// SHA-256 hex digest of one approved clipboard-write payload, used in
/// approval digests and evidence so raw text never enters approval
/// prompts beyond the bounded request itself and never enters evidence
/// at all. Secret-denied content never reaches this function because
/// denial happens before digest binding.
pub fn clipboard_write_content_digest(text: &str) -> String {
    digest_hex(&format!("{WRITE_SCHEMA}|payload|{text}"), 64)
}

/// Compute the exact approval digest for one bounded clipboard read. The
/// digest binds the workspace, the policy revision, the clipboard
/// sequence observed immediately before approval, the fixed Unicode-text
/// format bound, and the fixed size bound. Content itself is unknown
/// before the read, so it cannot be pre-bound; instead the sequence
/// binds the clipboard state, and dispatch revalidates the same sequence
/// immediately after approval, so any material clipboard change in
/// between fails closed.
pub fn clipboard_read_digest(workspace_id: &str, policy_revision: &str, sequence: u64) -> String {
    let material = format!(
        "{CLIPBOARD_SCHEMA}|{workspace_id}|{policy_revision}|{sequence}|{UNICODE_TEXT_FORMAT}|{MAX_CLIPBOARD_BYTES}|read"
    );
    digest_hex(&material, 64)
}

/// Substrings that mark clipboard text as secret-bearing. Matching is
/// ASCII case-insensitive over the full text. A match denies the read
/// before any return path; the matched material is never quoted in the
/// denial message, the evidence, or any log.
const SECRET_MARKERS: &[&str] = &[
    "-----begin",
    "private_key",
    "privatekey",
    "private-key",
    "password=",
    "password:",
    "passwd=",
    "passwd:",
    "pwd=",
    "pwd:",
    "api_key",
    "apikey",
    "api-key",
    "api_secret",
    "app_secret",
    "client_secret",
    "connectionstring",
    "connection string",
    "bearer ",
    "token=",
    "token:",
    "auth_token",
    "access_token",
    "refresh_token",
    "id_token",
    "session_token",
    "aws_access",
    "aws_secret",
    "akia",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_token",
    "xoxp-",
    "xoxb-",
    "xoxa-",
    "xoxo-",
    "sk-live-",
    "sk-test-",
    "secret=",
    "secret:",
    "credentials=",
    "credentials:",
    "mnemonic",
    "seed phrase",
    "seed-phrase",
    "recovery phrase",
    "recovery-phrase",
    "recovery code",
    "recovery-code",
    "orcel-approval",
    "orcel-trust",
    "orcel-emergency",
    "orcel-secret",
];

/// Returns true when clipboard text matches a documented secret family.
/// Matching is conservative: a match always denies, and bare everyday
/// words such as `password` or `token` without a credential shape do not
/// match, which is a documented detection limitation rather than a leak
/// path, because matched content is denied and unmatched content is
/// returned only through the explicit approved read.
pub fn contains_secret_material(text: &str) -> bool {
    let haystack = text.to_ascii_lowercase();
    if SECRET_MARKERS
        .iter()
        .any(|marker| haystack.contains(marker))
    {
        return true;
    }
    has_sk_style_token(&haystack)
}

/// Detects `sk-` style tokens: the literal `sk-` followed by at least
/// eight ASCII alphanumeric characters. Short or non-alphanumeric
/// suffixes do not match.
fn has_sk_style_token(haystack: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if &bytes[index..index + 3] == b"sk-" {
            let tail: &[u8] = &bytes[index + 3..];
            let run = tail
                .iter()
                .take_while(|byte| byte.is_ascii_alphanumeric())
                .count();
            if run >= 8 {
                return true;
            }
        }
        index += 1;
    }
    false
}

/// The adapter boundary. Policy logic, bounds, secret denial, sequence
/// binding, and evidence live in [`read_bounded_text`] and
/// [`write_bounded_text`], so adapters stay small and deterministic tests
/// never need a live desktop. Adapters move raw clipboard facts only and
/// never decide authorization. Placement adapters never synthesize input,
/// keystrokes, paste, or focus changes of any kind.
pub trait ClipboardAdapter {
    /// Return the current clipboard sequence number without reading
    /// content. The sequence binds clipboard state into the approval
    /// digest so post-approval drift fails closed.
    fn sequence_number(&self) -> Result<u64, ClipboardError>;
    /// Return the current clipboard content as Unicode text without
    /// validation. Bounds, format, and secret policy live in
    /// [`read_bounded_text`], not in adapters.
    fn read_unicode_text(&self) -> Result<String, ClipboardError>;
    /// Place Unicode text onto the clipboard without validation and
    /// return the resulting clipboard sequence number. Bounds and secret
    /// policy live in [`write_bounded_text`], not in adapters. Placement
    /// must not synthesize input, paste, keystrokes, or focus changes.
    fn write_unicode_text(&self, text: &str) -> Result<u64, ClipboardError>;
}

/// One bounded clipboard-read outcome: secret-free evidence plus the
/// bounded text. The text travels only in the approved response, never
/// in logs or metadata paths.
#[derive(Debug, Clone)]
pub struct ReadOutcome {
    pub evidence: Value,
    pub text: String,
}

/// Perform one bounded clipboard read with sequence binding. When
/// `expected_sequence` is present, the live sequence must match it or
/// the read fails closed as stale: clipboard content changed between
/// approval and actuation, so the approval no longer describes current
/// state. Empty, oversized, and secret-bearing content fails closed.
/// Evidence carries only format, sequence, size, digest, workspace, and
/// policy revision with no raw content retention.
pub fn read_bounded_text(
    adapter: &impl ClipboardAdapter,
    expected_sequence: Option<u64>,
    workspace_id: &str,
    policy_revision: &str,
) -> Result<ReadOutcome, ClipboardError> {
    if workspace_id.is_empty() || workspace_id.chars().count() > MAX_SCOPE_CHARS {
        return Err(ClipboardError::new(
            FailureCode::InvalidRequest,
            "clipboard read workspace is empty or too large",
        ));
    }
    if policy_revision.is_empty() || policy_revision.chars().count() > MAX_SCOPE_CHARS {
        return Err(ClipboardError::new(
            FailureCode::InvalidRequest,
            "clipboard read policy revision is empty or too large",
        ));
    }
    let sequence = adapter.sequence_number()?;
    if let Some(expected) = expected_sequence {
        if expected != sequence {
            return Err(ClipboardError::new(
                FailureCode::TargetStale,
                "clipboard content changed after approval; the approval no longer describes current clipboard state",
            ));
        }
    }
    let text = adapter.read_unicode_text()?;
    if text.is_empty() {
        return Err(ClipboardError::new(
            FailureCode::TargetStale,
            "clipboard is empty; there is no readable text",
        ));
    }
    let byte_length = text.len();
    if byte_length > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::new(
            FailureCode::OutputLimit,
            "clipboard content exceeds the bounded read size",
        ));
    }
    if contains_secret_material(&text) {
        return Err(ClipboardError::new(
            FailureCode::CapabilityDenied,
            "clipboard holds secret material which bounded reads never return",
        ));
    }
    let evidence = json!({
        "schema": CLIPBOARD_SCHEMA,
        "action": "read",
        "format": UNICODE_TEXT_FORMAT,
        "sequence": sequence,
        "byte_length": byte_length,
        "content_digest": clipboard_content_digest(&text),
        "workspace_id": workspace_id,
        "policy_revision": policy_revision,
    });
    Ok(ReadOutcome { evidence, text })
}

/// Compute the exact approval digest for one bounded clipboard write.
/// The digest binds the workspace, the policy revision, the content
/// digest of the exact caller text, the byte length, the fixed
/// Unicode-text format bound, and the fixed size bound. Unlike reads,
/// write content is known before approval, so the digest binds the
/// payload itself; dispatch still revalidates bounds and secrets after
/// approval, so smuggled state fails closed.
pub fn clipboard_write_digest(
    workspace_id: &str,
    policy_revision: &str,
    text_digest: &str,
    byte_length: usize,
) -> String {
    let material = format!(
        "{WRITE_SCHEMA}|{workspace_id}|{policy_revision}|{text_digest}|{byte_length}|{UNICODE_TEXT_FORMAT}|{MAX_CLIPBOARD_BYTES}|write"
    );
    digest_hex(&material, 64)
}

/// One bounded clipboard-write outcome: secret-free evidence plus the
/// resulting clipboard sequence number. The placed text travels only in
/// the approved request, never in logs, evidence, or metadata paths.
#[derive(Debug, Clone)]
pub struct WriteOutcome {
    pub evidence: Value,
    pub resulting_sequence: u64,
}

/// Perform one bounded clipboard placement. Empty, oversized, and
/// secret-bearing text fails closed before the adapter is touched, so
/// denied content never reaches the operating system. Evidence carries
/// only format, size, digests, the resulting sequence, workspace, and
/// policy revision with no raw content retention. Placement never
/// authorizes paste, input, keyboard, or desktop authority: the adapter
/// contract forbids synthesizing input of any kind.
pub fn write_bounded_text(
    adapter: &impl ClipboardAdapter,
    text: &str,
    workspace_id: &str,
    policy_revision: &str,
) -> Result<WriteOutcome, ClipboardError> {
    if workspace_id.is_empty() || workspace_id.chars().count() > MAX_SCOPE_CHARS {
        return Err(ClipboardError::new(
            FailureCode::InvalidRequest,
            "clipboard write workspace is empty or too large",
        ));
    }
    if policy_revision.is_empty() || policy_revision.chars().count() > MAX_SCOPE_CHARS {
        return Err(ClipboardError::new(
            FailureCode::InvalidRequest,
            "clipboard write policy revision is empty or too large",
        ));
    }
    if text.is_empty() {
        return Err(ClipboardError::new(
            FailureCode::InvalidRequest,
            "clipboard write text must not be empty",
        ));
    }
    let byte_length = text.len();
    if byte_length > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::new(
            FailureCode::OutputLimit,
            "clipboard write text exceeds the bounded placement size",
        ));
    }
    if contains_secret_material(text) {
        return Err(ClipboardError::new(
            FailureCode::CapabilityDenied,
            "clipboard write holds secret material which bounded writes never place",
        ));
    }
    let resulting_sequence = adapter.write_unicode_text(text)?;
    let evidence = json!({
        "schema": WRITE_SCHEMA,
        "action": "write",
        "format": UNICODE_TEXT_FORMAT,
        "byte_length": byte_length,
        "content_digest": clipboard_write_content_digest(text),
        "resulting_sequence": resulting_sequence,
        "workspace_id": workspace_id,
        "policy_revision": policy_revision,
    });
    Ok(WriteOutcome {
        evidence,
        resulting_sequence,
    })
}

/// The native adapter. On Windows it queries the real clipboard sequence
/// number, reads real Unicode text, and places real Unicode text through
/// the Win32 clipboard APIs. A locked, empty, non-text, oversized,
/// unwritable, or otherwise unreadable clipboard fails closed with a
/// typed error instead of fabricated content. Placement synthesizes no
/// input, keystrokes, paste, or focus changes. On macOS and Linux it
/// delegates to the clipboard-rs adapter in `unix.rs` with the same
/// contract. On every other platform each call fails closed as
/// unavailable.
pub struct NativeAdapter;

impl NativeAdapter {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NativeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl ClipboardAdapter for NativeAdapter {
    fn sequence_number(&self) -> Result<u64, ClipboardError> {
        native_sequence_number()
    }

    fn read_unicode_text(&self) -> Result<String, ClipboardError> {
        native_read_unicode_text()
    }

    fn write_unicode_text(&self, text: &str) -> Result<u64, ClipboardError> {
        native_write_unicode_text(text)
    }
}

#[cfg(windows)]
fn native_sequence_number() -> Result<u64, ClipboardError> {
    // GetClipboardSequenceNumber needs no clipboard ownership and moves
    // no content, so it is safe to call for state binding.
    let sequence = unsafe { windows::Win32::System::DataExchange::GetClipboardSequenceNumber() };
    Ok(sequence as u64)
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn native_sequence_number() -> Result<u64, ClipboardError> {
    unix::sequence_number()
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn native_sequence_number() -> Result<u64, ClipboardError> {
    Err(ClipboardError::new(
        FailureCode::ProviderUnavailable,
        "clipboard sequence state requires a supported desktop clipboard and is unavailable in this context",
    ))
}

#[cfg(windows)]
fn native_read_unicode_text() -> Result<String, ClipboardError> {
    use windows::Win32::Foundation::{HGLOBAL, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
    };
    use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};

    /// Win32 `CF_UNICODETEXT` clipboard format identifier (winuser.h).
    /// Kept as a local constant because the generated bindings expose it
    /// under an unrelated Ole module; the value is stable Win32 ABI.
    const CF_UNICODETEXT: u32 = 13;

    struct ClipboardGuard;
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    unsafe {
        OpenClipboard(HWND(std::ptr::null_mut())).map_err(|_| {
            ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard is locked by another owner and cannot be sampled now",
            )
        })?;
        let _guard = ClipboardGuard;
        IsClipboardFormatAvailable(CF_UNICODETEXT).map_err(|_| {
            ClipboardError::new(
                FailureCode::CapabilityDenied,
                "clipboard holds no Unicode text; bounded reads never transfer binary or object formats",
            )
        })?;
        let handle = GetClipboardData(CF_UNICODETEXT).map_err(|_| {
            ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard Unicode text is unreadable in this session",
            )
        })?;
        let global = HGLOBAL(handle.0);
        let byte_size = GlobalSize(global);
        if byte_size == 0 {
            return Err(ClipboardError::new(
                FailureCode::TargetStale,
                "clipboard is empty; there is no readable text",
            ));
        }
        // Bound the kernel-reported size before touching the mapping so a
        // pathological global object cannot drive an unbounded copy.
        if byte_size > MAX_CLIPBOARD_BYTES.saturating_add(2) {
            return Err(ClipboardError::new(
                FailureCode::OutputLimit,
                "clipboard content exceeds the bounded read size",
            ));
        }
        let locked = GlobalLock(global);
        if locked.is_null() {
            return Err(ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard Unicode text is unreadable in this session",
            ));
        }
        let units = byte_size / 2;
        let raw: &[u16] = std::slice::from_raw_parts(locked as *const u16, units);
        let end = raw.iter().position(|unit| *unit == 0).unwrap_or(units);
        let text = String::from_utf16(&raw[..end]).map_err(|_| {
            let _ = GlobalUnlock(global);
            ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard Unicode text is unreadable in this session",
            )
        })?;
        let _ = GlobalUnlock(global);
        Ok(text)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn native_read_unicode_text() -> Result<String, ClipboardError> {
    unix::read_unicode_text()
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn native_read_unicode_text() -> Result<String, ClipboardError> {
    Err(ClipboardError::new(
        FailureCode::ProviderUnavailable,
        "clipboard reads require a supported desktop clipboard and are unavailable in this context",
    ))
}

#[cfg(windows)]
fn native_write_unicode_text(text: &str) -> Result<u64, ClipboardError> {
    use windows::Win32::Foundation::{GlobalFree, HANDLE, HWND};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};

    /// Win32 `CF_UNICODETEXT` clipboard format identifier (winuser.h).
    /// Kept as a local constant because the generated bindings expose it
    /// under an unrelated Ole module; the value is stable Win32 ABI.
    const CF_UNICODETEXT: u32 = 13;

    struct ClipboardGuard;
    impl Drop for ClipboardGuard {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseClipboard();
            }
        }
    }

    // Encode first so oversized or unencodable caller text fails before
    // the clipboard is ever opened.
    let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_size = units.len().saturating_mul(2);
    if byte_size > MAX_CLIPBOARD_BYTES.saturating_add(2) {
        return Err(ClipboardError::new(
            FailureCode::OutputLimit,
            "clipboard write text exceeds the bounded placement size",
        ));
    }
    unsafe {
        OpenClipboard(HWND(std::ptr::null_mut())).map_err(|_| {
            ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard is locked by another owner and cannot be placed now",
            )
        })?;
        let _guard = ClipboardGuard;
        EmptyClipboard().map_err(|_| {
            ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard cannot be prepared for placement in this session",
            )
        })?;
        let global = GlobalAlloc(GMEM_MOVEABLE, byte_size).map_err(|_| {
            ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard placement memory is unavailable in this session",
            )
        })?;
        let locked = GlobalLock(global);
        if locked.is_null() {
            let _ = GlobalFree(global);
            return Err(ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard placement memory is unavailable in this session",
            ));
        }
        std::ptr::copy_nonoverlapping(units.as_ptr(), locked as *mut u16, units.len());
        let _ = GlobalUnlock(global);
        if SetClipboardData(CF_UNICODETEXT, HANDLE(global.0)).is_err() {
            let _ = GlobalFree(global);
            return Err(ClipboardError::new(
                FailureCode::ProviderUnavailable,
                "clipboard placement was rejected in this session",
            ));
        }
        // Success transfers global-memory ownership to the system; the
        // block must not be freed here.
        Ok(GetClipboardSequenceNumber() as u64)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn native_write_unicode_text(text: &str) -> Result<u64, ClipboardError> {
    unix::write_unicode_text(text)
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn native_write_unicode_text(_text: &str) -> Result<u64, ClipboardError> {
    Err(ClipboardError::new(
        FailureCode::ProviderUnavailable,
        "clipboard writes require a supported desktop clipboard and are unavailable in this context",
    ))
}

#[cfg(test)]
mod tests;
