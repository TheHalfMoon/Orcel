//! XP-15 native clipboard adapter for macOS and Linux.
//!
//! Only Unicode text moves; image, file, HTML, and RTF formats are never
//! read or placed. Bounds and secret denial stay in
//! [`crate::read_bounded_text`] and [`crate::write_bounded_text`],
//! unchanged; this module moves raw clipboard facts only.
//!
//! Backends:
//! - macOS: arboard 3.6.1 over NSPasteboard, for reads and writes.
//! - Linux, Wayland (`WAYLAND_DISPLAY` set): wl-clipboard-rs in process,
//!   over the ext/wlr data-control protocols, for reads and writes.
//!   arboard is never constructed, so its XWayland fallback cannot be
//!   reached.
//! - Linux, X11: reads use a short-lived x11rb connection owned by this
//!   module; writes use arboard, whose process-lifetime handle serves the
//!   selection (an X11 selection lives with its owner).
//!
//! Bounded reads: on Linux another program owns the clipboard data and
//! decides how and when to send it, and orceld holds the adapter lock
//! while it waits. Every Linux read therefore has a hard deadline
//! ([`READ_DEADLINE`]) and never buffers more than [`MAX_CLIPBOARD_BYTES`]:
//! a Wayland owner that never closes its pipe, an X11 owner that never
//! answers, and an X11 INCR transfer that keeps sending all fail closed
//! within the deadline, as `ProviderUnavailable` (timeout) or
//! `OutputLimit` (too large), instead of blocking or growing memory.
//! arboard's own Linux reads are not used because they wait for EOF with
//! no deadline (Wayland) or let the owner choose the size (X11).
//!
//! Standard output: orceld speaks line-delimited JSON on stdout and holds
//! the stdout lock for its session, so nothing in this adapter may print.
//! arboard, x11rb, and wl-clipboard-rs report through the `log` facade.
//! (clipboard-rs, which the backlog card named, prints from its X11
//! selection-server thread when another client takes the clipboard, so it
//! is not used.)
//!
//! Provenance: the long-lived Linux handle and the read-then-map pattern
//! are adapted from cua@a802eaf2
//! `libs/cua-driver/rust/crates/platform-linux/src/clipboard.rs`
//! (MIT, Copyright (c) 2025 Cua AI, Inc.; full notice in
//! docs/orcel/notices/cua-driver-clipboard-MIT.txt). Modifications for
//! Orcel: arboard and wl-clipboard-rs instead of clipboard-rs, bounded
//! Linux readers, text only, no image or file paths, typed fail-closed
//! errors, and a content-derived sequence. arboard is MIT OR Apache-2.0
//! (docs/orcel/notices/arboard-MIT.txt).
//!
//! Sequence binding: none of these backends exposes NSPasteboard's change
//! count or X11 and Wayland selection state, so the sequence is a 64-bit
//! SHA-256 prefix over the current text (or a fixed no-text marker). Any
//! change of content changes the sequence, so pre-approval and
//! post-approval drift still fails closed; re-placing identical text
//! keeps the same sequence, which describes the same clipboard state.
//!
//! Wayland: compositors without a data-control protocol only hand the
//! clipboard to a focused surface. This adapter has no surface and never
//! spawns `wl-copy` or any other process, so such a session reports the
//! clipboard as unavailable. A successful data-control probe is kept for
//! the life of the process; a failed probe is not, so a compositor that
//! was not ready yet is picked up later. A failed probe opens and closes
//! one Wayland connection and starts no thread.
//!
//! Limitations:
//! - macOS reads go through NSPasteboard, which copies the whole string
//!   before the 64 KiB check and may wait on an application that
//!   promised data lazily; the deadline above is Linux-only. Oversized
//!   content still fails closed and never leaves this module.
//! - arboard keeps one X11 connection per process for writes. If the X
//!   server closes it, arboard keeps that dead connection and writes stay
//!   unavailable (fail closed) until the process restarts. This was seen
//!   only on WSLg's XWayland with `WAYLAND_DISPLAY` removed by hand.

use crate::{ClipboardError, MAX_CLIPBOARD_BYTES};
use orcel_contracts::FailureCode;
use sha2::{Digest, Sha256};

/// Hard deadline for one Linux clipboard read, from request to the last
/// byte.
#[cfg(target_os = "linux")]
pub(crate) const READ_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

fn unavailable(message: &str) -> ClipboardError {
    ClipboardError::new(FailureCode::ProviderUnavailable, message)
}

fn oversize() -> ClipboardError {
    ClipboardError::new(
        FailureCode::OutputLimit,
        "clipboard content exceeds the bounded read size",
    )
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{oversize, unavailable, READ_DEADLINE};
    use crate::{ClipboardError, MAX_CLIPBOARD_BYTES};
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::time::{Duration, Instant};

    fn read_timeout() -> ClipboardError {
        unavailable("the clipboard owner did not deliver its text before the read deadline")
    }

    fn decode(bytes: Vec<u8>) -> Result<String, ClipboardError> {
        String::from_utf8(bytes)
            .map_err(|_| unavailable("clipboard Unicode text is unreadable in this session"))
    }

    /// Read until EOF, at most `cap` bytes, finishing by `deadline`. The
    /// reader is polled before each read, so a writer that stalls or never
    /// closes cannot hold the caller past the deadline.
    pub(crate) fn read_pipe_bounded(
        mut reader: impl Read + AsRawFd,
        timeout: Duration,
        cap: usize,
    ) -> Result<Vec<u8>, ClipboardError> {
        let deadline = Instant::now() + timeout;
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(read_timeout());
            }
            let mut pollfd = libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            // SAFETY: one valid pollfd for a descriptor the reader owns.
            let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
            if ready < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(unavailable(
                    "clipboard Unicode text is unreadable in this session",
                ));
            }
            if ready == 0 {
                continue;
            }
            let count = match reader.read(&mut chunk) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    return Err(unavailable(
                        "clipboard Unicode text is unreadable in this session",
                    ))
                }
            };
            if count == 0 {
                return Ok(buffer);
            }
            if buffer.len() + count > cap {
                return Err(oversize());
            }
            buffer.extend_from_slice(&chunk[..count]);
        }
    }

    /// Whether this is a Wayland session. Under Wayland the compositor
    /// must offer data-control; a positive answer is kept for the process.
    fn wayland_session() -> Result<bool, ClipboardError> {
        use std::sync::OnceLock;
        use wl_clipboard_rs::utils::{is_primary_selection_supported, PrimarySelectionCheckError};
        static DATA_CONTROL: OnceLock<()> = OnceLock::new();

        if std::env::var_os("WAYLAND_DISPLAY").is_none() {
            return Ok(false);
        }
        if DATA_CONTROL.get().is_some() {
            return Ok(true);
        }
        match is_primary_selection_supported() {
            Ok(_) => {
                let _ = DATA_CONTROL.set(());
                Ok(true)
            }
            Err(PrimarySelectionCheckError::MissingProtocol) => Err(unavailable(
                "the Wayland compositor offers no data-control clipboard protocol and only serves a focused surface, so the clipboard is unavailable",
            )),
            Err(_) => Err(unavailable(
                "the Wayland compositor is not reachable for clipboard access in this session",
            )),
        }
    }

    fn wayland_read_text() -> Result<Option<String>, ClipboardError> {
        use wl_clipboard_rs::paste::{get_contents, ClipboardType, Error, MimeType, Seat};
        match get_contents(ClipboardType::Regular, Seat::Unspecified, MimeType::Text) {
            Ok((pipe, _mime)) => read_pipe_bounded(pipe, READ_DEADLINE, MAX_CLIPBOARD_BYTES)
                .and_then(decode)
                .map(Some),
            Err(Error::ClipboardEmpty | Error::NoMimeType | Error::NoSeats) => Ok(None),
            Err(_) => Err(unavailable(
                "clipboard Unicode text is unreadable in this session",
            )),
        }
    }

    fn wayland_place_text(text: &str) -> Result<(), ClipboardError> {
        use wl_clipboard_rs::copy::{ClipboardType, MimeType, Options, Source};
        let mut options = Options::new();
        // Background serving: wl-clipboard-rs serves the source from its
        // own thread until another client replaces the selection.
        options.foreground(false);
        options.clipboard(ClipboardType::Regular);
        options
            .copy(Source::Bytes(text.as_bytes().into()), MimeType::Text)
            .map_err(|_| unavailable("clipboard placement was rejected in this session"))
    }

    /// Read the CLIPBOARD selection as UTF-8 text over a connection owned
    /// by this call, finishing by `timeout`. Plain and INCR transfers are
    /// both capped at `cap` bytes; the owner's announced INCR size is
    /// ignored, so it cannot drive an allocation.
    pub(crate) fn x11_read_text(
        timeout: Duration,
        cap: usize,
    ) -> Result<Option<String>, ClipboardError> {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::{
            AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, Property, WindowClass,
        };
        use x11rb::protocol::Event;

        fn failed<E>(_: E) -> ClipboardError {
            unavailable("clipboard Unicode text is unreadable in this session")
        }

        let deadline = Instant::now() + timeout;
        let (conn, screen_index) = x11rb::connect(None)
            .map_err(|_| unavailable("no X11 or Wayland clipboard is reachable in this session"))?;
        let screen = &conn.setup().roots[screen_index];
        let window = conn.generate_id().map_err(failed)?;
        conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            window,
            screen.root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .map_err(failed)?;
        let atom = |name: &[u8]| -> Result<u32, ClipboardError> {
            Ok(conn
                .intern_atom(false, name)
                .map_err(failed)?
                .reply()
                .map_err(failed)?
                .atom)
        };
        let clipboard = atom(b"CLIPBOARD")?;
        let utf8 = atom(b"UTF8_STRING")?;
        let incr = atom(b"INCR")?;
        let property = atom(b"ORCEL_CLIPBOARD_READ")?;
        conn.convert_selection(window, clipboard, utf8, property, x11rb::CURRENT_TIME)
            .map_err(failed)?;
        conn.flush().map_err(failed)?;

        // One property read, capped one word above `cap` so that a larger
        // value is detected (bytes_after or length) without being fetched.
        let cap_words = (cap / 4 + 1) as u32;
        let mut buffer: Vec<u8> = Vec::new();
        let mut incremental = false;
        while Instant::now() < deadline {
            let event = match conn.poll_for_event().map_err(failed)? {
                Some(event) => event,
                None => {
                    std::thread::sleep(Duration::from_millis(2));
                    continue;
                }
            };
            match event {
                Event::SelectionNotify(event) if event.requestor == window && !incremental => {
                    if event.property == u32::from(AtomEnum::NONE) {
                        return Ok(None);
                    }
                    let reply = conn
                        .get_property(true, window, property, AtomEnum::ANY, 0, cap_words)
                        .map_err(failed)?
                        .reply()
                        .map_err(failed)?;
                    if reply.type_ == incr {
                        // Deleting the INCR property (above) asks the owner
                        // to start sending chunks.
                        incremental = true;
                        continue;
                    }
                    if reply.type_ != utf8 {
                        return Ok(None);
                    }
                    if reply.bytes_after > 0 || reply.value.len() > cap {
                        return Err(oversize());
                    }
                    return decode(reply.value).map(Some);
                }
                Event::PropertyNotify(event)
                    if incremental
                        && event.window == window
                        && event.atom == property
                        && event.state == Property::NEW_VALUE =>
                {
                    let reply = conn
                        .get_property(true, window, property, AtomEnum::ANY, 0, cap_words)
                        .map_err(failed)?
                        .reply()
                        .map_err(failed)?;
                    if reply.value.is_empty() {
                        return decode(buffer).map(Some);
                    }
                    if reply.bytes_after > 0 || buffer.len() + reply.value.len() > cap {
                        return Err(oversize());
                    }
                    buffer.extend_from_slice(&reply.value);
                }
                _ => {}
            }
        }
        Err(read_timeout())
    }

    /// Run `f` against arboard's process-lifetime X11 handle. A failed
    /// connection is not cached, so a display that appears later is
    /// picked up on the next call.
    fn with_x11_writer<R>(
        f: impl FnOnce(&mut arboard::Clipboard) -> Result<R, ClipboardError>,
    ) -> Result<R, ClipboardError> {
        use std::sync::Mutex;
        static WRITER: Mutex<Option<arboard::Clipboard>> = Mutex::new(None);

        let mut slot = WRITER
            .lock()
            .map_err(|_| unavailable("clipboard adapter state is unusable in this process"))?;
        if slot.is_none() {
            let clipboard = arboard::Clipboard::new().map_err(|_| {
                unavailable("no X11 or Wayland clipboard is reachable in this session")
            })?;
            *slot = Some(clipboard);
        }
        match slot.as_mut() {
            Some(clipboard) => f(clipboard),
            None => Err(unavailable(
                "no X11 or Wayland clipboard is reachable in this session",
            )),
        }
    }

    pub(super) fn current_text() -> Result<Option<String>, ClipboardError> {
        if wayland_session()? {
            wayland_read_text()
        } else {
            x11_read_text(READ_DEADLINE, MAX_CLIPBOARD_BYTES)
        }
    }

    pub(super) fn place_text(text: &str) -> Result<(), ClipboardError> {
        if wayland_session()? {
            wayland_place_text(text)
        } else {
            with_x11_writer(|clipboard| {
                clipboard
                    .set_text(text)
                    .map_err(|_| unavailable("clipboard placement was rejected in this session"))
            })
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{oversize, unavailable};
    use crate::{ClipboardError, MAX_CLIPBOARD_BYTES};

    /// NSPasteboard keeps placed content after the handle is dropped, so
    /// each call opens the general pasteboard and holds no state.
    fn pasteboard() -> Result<arboard::Clipboard, ClipboardError> {
        arboard::Clipboard::new()
            .map_err(|_| unavailable("the macOS pasteboard is unreachable in this session"))
    }

    pub(super) fn current_text() -> Result<Option<String>, ClipboardError> {
        match pasteboard()?.get_text() {
            Ok(text) if text.len() > MAX_CLIPBOARD_BYTES => Err(oversize()),
            Ok(text) => Ok(Some(text)),
            Err(arboard::Error::ContentNotAvailable) => Ok(None),
            Err(_) => Err(unavailable(
                "clipboard Unicode text is unreadable in this session",
            )),
        }
    }

    pub(super) fn place_text(text: &str) -> Result<(), ClipboardError> {
        pasteboard()?
            .set_text(text)
            .map_err(|_| unavailable("clipboard placement was rejected in this session"))
    }
}

#[cfg(target_os = "linux")]
use linux as platform;
#[cfg(target_os = "macos")]
use macos as platform;

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

pub(crate) fn sequence_number() -> Result<u64, ClipboardError> {
    Ok(sequence_of(platform::current_text()?.as_deref()))
}

pub(crate) fn read_unicode_text() -> Result<String, ClipboardError> {
    platform::current_text()?.ok_or_else(|| {
        ClipboardError::new(
            FailureCode::CapabilityDenied,
            "clipboard holds no Unicode text; bounded reads never transfer binary or object formats",
        )
    })
}

pub(crate) fn write_unicode_text(text: &str) -> Result<u64, ClipboardError> {
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err(ClipboardError::new(
            FailureCode::OutputLimit,
            "clipboard write text exceeds the bounded placement size",
        ));
    }
    platform::place_text(text)?;
    Ok(sequence_of(Some(text)))
}

#[cfg(test)]
mod tests;
