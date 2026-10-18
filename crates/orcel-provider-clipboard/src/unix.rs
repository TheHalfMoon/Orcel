//! XP-15 native clipboard adapter for macOS and Linux.
//!
//! Wraps clipboard-rs 0.3.5 text get/set, as Cua's
//! `platform-linux/src/clipboard.rs` does: NSPasteboard on macOS, X11
//! selections on Linux, and the Wayland data-control protocols (through
//! wl-clipboard-rs, in process) when `WAYLAND_DISPLAY` is set. Only
//! Unicode text moves; image, file, HTML, and RTF formats are never read
//! or placed. Bounds and secret denial stay in [`crate::read_bounded_text`]
//! and [`crate::write_bounded_text`], unchanged; this module moves raw
//! clipboard facts only.
//!
//! Provenance: the long-lived Linux context and the has-text-then-get
//! read are adapted from cua@a802eaf2
//! `libs/cua-driver/rust/crates/platform-linux/src/clipboard.rs`
//! (MIT, Copyright (c) 2025 Cua AI, Inc.; full notice in
//! docs/orcel/notices/cua-driver-clipboard-MIT.txt). Modifications for
//! Orcel: text only, no image or file paths, a connection failure is not
//! cached, the XWayland fallback is refused, typed fail-closed errors,
//! and a content-derived sequence. clipboard-rs itself is MIT
//! (docs/orcel/notices/clipboard-rs-MIT.txt).
//!
//! Sequence binding: neither NSPasteboard's change count nor X11 and
//! Wayland selections are exposed through clipboard-rs, so the sequence is
//! a 64-bit SHA-256 prefix over the current text (or a fixed no-text
//! marker). Any change of content changes the sequence, so pre-approval
//! and post-approval drift still fails closed; re-placing identical text
//! keeps the same sequence, which describes the same clipboard state.
//!
//! Wayland: compositors without a data-control protocol only hand the
//! clipboard to a focused surface. This adapter has no surface and never
//! spawns `wl-copy` or any other process, so such a session reports the
//! clipboard as unavailable. clipboard-rs would otherwise fall back to the
//! XWayland selection, which is not the Wayland clipboard; that fallback
//! is refused here.
//!
//! Limitation: clipboard-rs reads the whole text before the size check,
//! so the 64 KiB bound is enforced after the copy rather than from a
//! kernel-reported size as on Windows. Oversized content still fails
//! closed and never leaves this module.

use crate::{ClipboardError, MAX_CLIPBOARD_BYTES};
use clipboard_rs::{Clipboard, ClipboardContext, ContentFormat};
use orcel_contracts::FailureCode;
use sha2::{Digest, Sha256};

fn unavailable(message: &str) -> ClipboardError {
    ClipboardError::new(FailureCode::ProviderUnavailable, message)
}

/// Run `f` against a live clipboard context. On Linux the context is kept
/// for the life of the process because an X11 selection is served by the
/// context that placed it: dropping it would empty the clipboard. A
/// failed connection is not cached, so a display that appears later is
/// picked up on the next call.
#[cfg(target_os = "linux")]
fn with_context<R>(
    f: impl FnOnce(&ClipboardContext) -> Result<R, ClipboardError>,
) -> Result<R, ClipboardError> {
    use std::sync::Mutex;
    static CONTEXT: Mutex<Option<ClipboardContext>> = Mutex::new(None);

    let mut slot = CONTEXT
        .lock()
        .map_err(|_| unavailable("clipboard adapter state is unusable in this process"))?;
    if slot.is_none() {
        let context = ClipboardContext::new()
            .map_err(|_| unavailable("no X11 or Wayland clipboard is reachable in this session"))?;
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && matches!(context, ClipboardContext::X11(_))
        {
            return Err(unavailable(
                "the Wayland compositor offers no data-control clipboard protocol and only serves a focused surface, so the clipboard is unavailable",
            ));
        }
        *slot = Some(context);
    }
    match slot.as_ref() {
        Some(context) => f(context),
        None => Err(unavailable(
            "no X11 or Wayland clipboard is reachable in this session",
        )),
    }
}

/// Run `f` against the general pasteboard. NSPasteboard keeps placed
/// content after the context is dropped, so no state is held.
#[cfg(target_os = "macos")]
fn with_context<R>(
    f: impl FnOnce(&ClipboardContext) -> Result<R, ClipboardError>,
) -> Result<R, ClipboardError> {
    let context = ClipboardContext::new()
        .map_err(|_| unavailable("the macOS pasteboard is unreachable in this session"))?;
    f(&context)
}

/// 64-bit sequence derived from clipboard text. `None` is a clipboard
/// with no Unicode text.
fn sequence_of(text: Option<&str>) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel-clipboard-sequence-v1|");
    match text {
        Some(text) => {
            hasher.update(b"text|");
            hasher.update(text.as_bytes());
        }
        None => hasher.update(b"no-text"),
    }
    let digest = hasher.finalize();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix)
}

fn current_text(context: &ClipboardContext) -> Result<Option<String>, ClipboardError> {
    if !context.has(ContentFormat::Text) {
        return Ok(None);
    }
    context
        .get_text()
        .map(Some)
        .map_err(|_| unavailable("clipboard Unicode text is unreadable in this session"))
}

pub(crate) fn sequence_number() -> Result<u64, ClipboardError> {
    with_context(|context| Ok(sequence_of(current_text(context)?.as_deref())))
}

pub(crate) fn read_unicode_text() -> Result<String, ClipboardError> {
    with_context(|context| {
        let text = current_text(context)?.ok_or_else(|| {
            ClipboardError::new(
                FailureCode::CapabilityDenied,
                "clipboard holds no Unicode text; bounded reads never transfer binary or object formats",
            )
        })?;
        if text.len() > MAX_CLIPBOARD_BYTES {
            return Err(ClipboardError::new(
                FailureCode::OutputLimit,
                "clipboard content exceeds the bounded read size",
            ));
        }
        Ok(text)
    })
}

pub(crate) fn write_unicode_text(text: &str) -> Result<u64, ClipboardError> {
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::new(
            FailureCode::OutputLimit,
            "clipboard write text exceeds the bounded placement size",
        ));
    }
    with_context(|context| {
        context
            .set_text(text.to_owned())
            .map_err(|_| unavailable("clipboard placement was rejected in this session"))?;
        Ok(sequence_of(Some(text)))
    })
}

#[cfg(test)]
mod tests {
    use super::sequence_of;

    #[test]
    fn sequence_tracks_content_and_distinguishes_no_text() {
        assert_eq!(sequence_of(Some("a")), sequence_of(Some("a")));
        assert_ne!(sequence_of(Some("a")), sequence_of(Some("b")));
        assert_ne!(sequence_of(Some("")), sequence_of(None));
    }
}
