//! XP-15 native clipboard adapter for macOS and Linux.
//!
//! Wraps arboard 3.6.1 text get/set: NSPasteboard on macOS, X11
//! selections on Linux, and the Wayland data-control protocols (through
//! wl-clipboard-rs, in process) when `WAYLAND_DISPLAY` is set. Only
//! Unicode text moves; image, file, HTML, and RTF formats are never read
//! or placed. Bounds and secret denial stay in [`crate::read_bounded_text`]
//! and [`crate::write_bounded_text`], unchanged; this module moves raw
//! clipboard facts only.
//!
//! Standard output: orceld speaks line-delimited JSON on stdout and holds
//! the stdout lock for its session, so nothing in this adapter may print.
//! arboard reports through the `log` facade; its X11 selection-server
//! thread never writes to stdout. (clipboard-rs, which the backlog card
//! named, prints from that thread when another client takes the
//! clipboard, which would block on orceld's lock or corrupt the JSON
//! stream, so it is not used.)
//!
//! Provenance: the long-lived Linux context and the read-then-map pattern
//! are adapted from cua@a802eaf2
//! `libs/cua-driver/rust/crates/platform-linux/src/clipboard.rs`
//! (MIT, Copyright (c) 2025 Cua AI, Inc.; full notice in
//! docs/orcel/notices/cua-driver-clipboard-MIT.txt). Modifications for
//! Orcel: arboard instead of clipboard-rs, text only, no image or file
//! paths, a connection failure is not cached, the XWayland fallback is
//! refused, typed fail-closed errors, and a content-derived sequence.
//! arboard is MIT OR Apache-2.0 (docs/orcel/notices/arboard-MIT.txt).
//!
//! Sequence binding: arboard exposes neither NSPasteboard's change count
//! nor X11 and Wayland selection state, so the sequence is a 64-bit
//! SHA-256 prefix over the current text (or a fixed no-text marker). Any
//! change of content changes the sequence, so pre-approval and
//! post-approval drift still fails closed; re-placing identical text
//! keeps the same sequence, which describes the same clipboard state.
//!
//! Wayland: compositors without a data-control protocol only hand the
//! clipboard to a focused surface. This adapter has no surface and never
//! spawns `wl-copy` or any other process, so such a session reports the
//! clipboard as unavailable. arboard would otherwise fall back to the
//! XWayland selection, which is not the Wayland clipboard; the adapter
//! probes for data-control first, with the same check arboard uses, and
//! refuses that fallback. The probe result is kept for the life of the
//! process, so a refused session opens no further connections.
//!
//! Limitation: arboard reads the whole text before the size check, so the
//! 64 KiB bound is enforced after the copy rather than from a
//! kernel-reported size as on Windows. Oversized content still fails
//! closed and never leaves this module.
//!
//! Limitation: arboard keeps one X11 connection per process. If the X
//! server closes it, arboard keeps returning that dead connection, and
//! dropping and recreating the handle does not replace it, so the
//! clipboard stays unavailable (fail closed, `ProviderUnavailable`) until
//! the process restarts. This was seen only on WSLg's XWayland with
//! `WAYLAND_DISPLAY` removed by hand, where the server closed the
//! connection after another client that had taken the selection exited.
//! Xvfb kept the connection and the ownership-loss test passes there.

use crate::{ClipboardError, MAX_CLIPBOARD_BYTES};
use arboard::Clipboard;
use orcel_contracts::FailureCode;
use sha2::{Digest, Sha256};

fn unavailable(message: &str) -> ClipboardError {
    ClipboardError::new(FailureCode::ProviderUnavailable, message)
}

/// Whether this session may use the clipboard at all. Outside Wayland it
/// always may. Under Wayland the compositor must offer a data-control
/// protocol; the answer cannot change for the life of the process, so it
/// is computed once.
#[cfg(target_os = "linux")]
fn wayland_permits_clipboard() -> Result<(), ClipboardError> {
    use std::sync::OnceLock;
    static PROBE: OnceLock<bool> = OnceLock::new();

    if std::env::var_os("WAYLAND_DISPLAY").is_none() {
        return Ok(());
    }
    let data_control =
        *PROBE.get_or_init(|| wl_clipboard_rs::utils::is_primary_selection_supported().is_ok());
    if data_control {
        Ok(())
    } else {
        Err(unavailable(
            "the Wayland compositor offers no data-control clipboard protocol and only serves a focused surface, so the clipboard is unavailable",
        ))
    }
}

/// Run `f` against a live clipboard. On Linux the clipboard is kept for
/// the life of the process because an X11 selection is served by the
/// client that placed it: dropping it would empty the clipboard. A failed
/// X11 connection is not cached, so a display that appears later is
/// picked up on the next call.
#[cfg(target_os = "linux")]
fn with_clipboard<R>(
    f: impl FnOnce(&mut Clipboard) -> Result<R, ClipboardError>,
) -> Result<R, ClipboardError> {
    use std::sync::Mutex;
    static CLIPBOARD: Mutex<Option<Clipboard>> = Mutex::new(None);

    wayland_permits_clipboard()?;
    let mut slot = CLIPBOARD
        .lock()
        .map_err(|_| unavailable("clipboard adapter state is unusable in this process"))?;
    if slot.is_none() {
        let clipboard = Clipboard::new()
            .map_err(|_| unavailable("no X11 or Wayland clipboard is reachable in this session"))?;
        *slot = Some(clipboard);
    }
    match slot.as_mut() {
        Some(clipboard) => f(clipboard),
        None => Err(unavailable(
            "no X11 or Wayland clipboard is reachable in this session",
        )),
    }
}

/// Run `f` against the general pasteboard. NSPasteboard keeps placed
/// content after the handle is dropped, so no state is held.
#[cfg(target_os = "macos")]
fn with_clipboard<R>(
    f: impl FnOnce(&mut Clipboard) -> Result<R, ClipboardError>,
) -> Result<R, ClipboardError> {
    let mut clipboard = Clipboard::new()
        .map_err(|_| unavailable("the macOS pasteboard is unreachable in this session"))?;
    f(&mut clipboard)
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

fn current_text(clipboard: &mut Clipboard) -> Result<Option<String>, ClipboardError> {
    match clipboard.get_text() {
        Ok(text) => Ok(Some(text)),
        Err(arboard::Error::ContentNotAvailable) => Ok(None),
        Err(_) => Err(unavailable(
            "clipboard Unicode text is unreadable in this session",
        )),
    }
}

pub(crate) fn sequence_number() -> Result<u64, ClipboardError> {
    with_clipboard(|clipboard| Ok(sequence_of(current_text(clipboard)?.as_deref())))
}

pub(crate) fn read_unicode_text() -> Result<String, ClipboardError> {
    with_clipboard(|clipboard| {
        let text = current_text(clipboard)?.ok_or_else(|| {
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
    with_clipboard(|clipboard| {
        clipboard
            .set_text(text)
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
