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
//! no deadline (Wayland) or let the owner choose the size (X11). On X11
//! the deadline covers every wait on the server, from the connection setup
//! through each reply, flush and event (#356 item 1, `DeadlineStream`),
//! so a client that holds the server grabbed cannot stall orceld either,
//! and an INCR owner that trickles small chunks ends at the deadline too.
//! Only a SelectionNotify for this request's window, selection, target
//! and property counts as the answer; others are ignored (#356 item 5).
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
//! one Wayland connection and starts no thread. Each placement is served
//! from a thread of its own until another client takes the selection;
//! the number of live serving threads is bounded (`MAX_WAYLAND_SERVERS`,
//! #356 item 4). The path from `get_contents` to `read_pipe_bounded` is
//! tested live against a headless sway in CI (#356 item 2).
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
//! - The X11 socket `connect(2)` is not bounded by the read deadline. For a
//!   local display it returns at once; only a TCP `DISPLAY` (for example
//!   SSH X11 forwarding) can wait for the kernel's connect timeout.
//! - A same-user Wayland paster that shrinks its pipe and never reads can
//!   hold one serving thread for the life of the process; at
//!   `MAX_WAYLAND_SERVERS` such threads, placements fail closed.

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

    /// Most Wayland placements whose serving threads may be alive at once
    /// (#356 item 4).
    pub(crate) const MAX_WAYLAND_SERVERS: usize = 4;

    /// Wayland placements whose serving threads are still running.
    pub(crate) static WAYLAND_SERVERS: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// Decrements [`WAYLAND_SERVERS`] when a serving thread ends, however
    /// it ends.
    struct Serving;

    impl Drop for Serving {
        fn drop(&mut self) {
            WAYLAND_SERVERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Places `text` as the Wayland selection. A Wayland selection lives
    /// with its source, so each placement is served from a thread of its
    /// own until another client takes the selection, which normally is
    /// the next placement (#356 item 4). A paste is written with a blocking
    /// write; at most 64 KiB fits in a default pipe, but a same-user paster
    /// that shrinks its pipe and never reads can hold that write, and with
    /// it the thread, for the life of the process. No thread can be stopped
    /// from outside, so instead of reaping, the number of live serving
    /// threads is bounded: at [`MAX_WAYLAND_SERVERS`] further placements
    /// fail closed as unavailable, and each held thread keeps at most its
    /// 64 KiB copy and an idle stack.
    pub(super) fn wayland_place_text(text: &str) -> Result<(), ClipboardError> {
        use std::sync::atomic::Ordering;
        use wl_clipboard_rs::copy::{ClipboardType, MimeType, Options, Source};

        let reserved = WAYLAND_SERVERS.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |live| {
            (live < MAX_WAYLAND_SERVERS).then_some(live + 1)
        });
        if reserved.is_err() {
            return Err(unavailable(
                "earlier clipboard placements are still being served to a paster that does not read them, so this placement is refused",
            ));
        }
        let guard = Serving;
        let bytes: Box<[u8]> = text.as_bytes().into();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        // wl-clipboard-rs needs the copy prepared on the thread that serves
        // it (its prepared copy is not Send), as its own background mode
        // does; this thread also owns the counter guard.
        let spawned = std::thread::Builder::new()
            .name("orcel-wayland-clipboard".into())
            .spawn(move || {
                let _guard = guard;
                let mut options = Options::new();
                options.foreground(true);
                options.clipboard(ClipboardType::Regular);
                match options.prepare_copy(Source::Bytes(bytes), MimeType::Text) {
                    Ok(prepared) => {
                        let _ = ready_tx.send(true);
                        // Returns once the selection is taken or a write
                        // fails; nobody is waiting for its result.
                        let _ = prepared.serve();
                    }
                    Err(_) => {
                        let _ = ready_tx.send(false);
                    }
                }
            });
        if spawned.is_err() {
            return Err(unavailable(
                "clipboard placement was rejected in this session",
            ));
        }
        match ready_rx.recv() {
            Ok(true) => Ok(()),
            _ => Err(unavailable(
                "clipboard placement was rejected in this session",
            )),
        }
    }

    /// An x11rb stream whose every wait ends at `deadline` (#356 item 1).
    /// x11rb blocks only in [`Stream::poll`](x11rb::rust_connection::Stream::poll)
    /// (its reads and writes never block), so bounding `poll` bounds the
    /// connection setup, every reply, every flush and every event wait: an
    /// X server another client holds grabbed (`GrabServer`), or one that
    /// stops answering, can stall a read only until the deadline. A wait
    /// that reaches the deadline fails with `TimedOut` and sets `expired`.
    pub(crate) struct DeadlineStream {
        inner: x11rb::rust_connection::DefaultStream,
        deadline: Instant,
        expired: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl x11rb::rust_connection::Stream for DeadlineStream {
        fn poll(&self, mode: x11rb::rust_connection::PollMode) -> std::io::Result<()> {
            let mut events = 0;
            if mode.readable() {
                events |= libc::POLLIN;
            }
            if mode.writable() {
                events |= libc::POLLOUT;
            }
            loop {
                let remaining = self.deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    self.expired
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the X11 clipboard read deadline passed",
                    ));
                }
                let mut pollfd = libc::pollfd {
                    fd: self.inner.as_raw_fd(),
                    events,
                    revents: 0,
                };
                let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
                // SAFETY: one valid pollfd for the descriptor `inner` owns,
                // which stays open while `self` is borrowed.
                let ready = unsafe { libc::poll(&mut pollfd, 1, millis) };
                if ready > 0 {
                    // Errors (POLLERR, POLLHUP) surface in the next read or
                    // write, as with x11rb's own stream.
                    return Ok(());
                }
                if ready < 0 {
                    let error = std::io::Error::last_os_error();
                    if error.kind() != std::io::ErrorKind::Interrupted {
                        return Err(error);
                    }
                }
            }
        }

        fn read(
            &self,
            buf: &mut [u8],
            fd_storage: &mut Vec<x11rb::utils::RawFdContainer>,
        ) -> std::io::Result<usize> {
            self.inner.read(buf, fd_storage)
        }

        fn write(
            &self,
            buf: &[u8],
            fds: &mut Vec<x11rb::utils::RawFdContainer>,
        ) -> std::io::Result<usize> {
            self.inner.write(buf, fds)
        }

        fn write_vectored(
            &self,
            bufs: &[std::io::IoSlice<'_>],
            fds: &mut Vec<x11rb::utils::RawFdContainer>,
        ) -> std::io::Result<usize> {
            self.inner.write_vectored(bufs, fds)
        }
    }

    /// Opens the `DISPLAY` connection with every wait bounded by
    /// `deadline`, authenticating as `x11rb::connect` does (Xauthority).
    /// The socket `connect(2)` itself is not bounded; for a local display it
    /// returns at once, and only a TCP `DISPLAY` (for example SSH X11
    /// forwarding) can wait for the kernel's connect timeout there.
    pub(crate) fn connect_with_deadline(
        deadline: Instant,
        expired: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<
        (
            x11rb::rust_connection::RustConnection<DeadlineStream>,
            usize,
        ),
        ClipboardError,
    > {
        use x11rb::reexports::x11rb_protocol::{parse_display::parse_display, xauth::get_auth};
        use x11rb::rust_connection::{DefaultStream, RustConnection};

        let unreachable =
            || unavailable("no X11 or Wayland clipboard is reachable in this session");
        let parsed = parse_display(None).map_err(|_| unreachable())?;
        let screen = usize::from(parsed.screen);
        for address in parsed.connect_instruction() {
            if Instant::now() >= deadline {
                return Err(read_timeout());
            }
            let Ok((inner, (family, peer))) = DefaultStream::connect(&address) else {
                continue;
            };
            let (auth_name, auth_data) = get_auth(family, &peer, parsed.display)
                .ok()
                .flatten()
                .unwrap_or_default();
            let stream = DeadlineStream {
                inner,
                deadline,
                expired: std::sync::Arc::clone(expired),
            };
            return RustConnection::connect_to_stream_with_auth_info(
                stream, screen, auth_name, auth_data,
            )
            .map(|conn| (conn, screen))
            .map_err(|_| {
                if expired.load(std::sync::atomic::Ordering::SeqCst) {
                    read_timeout()
                } else {
                    unreachable()
                }
            });
        }
        Err(unreachable())
    }

    /// Read the CLIPBOARD selection as UTF-8 text over a connection owned
    /// by this call, finishing by `timeout`. Plain and INCR transfers are
    /// both capped at `cap` bytes; the owner's announced INCR size is
    /// ignored, so it cannot drive an allocation. Every wait on the X
    /// server, from the connection setup on, ends at the deadline
    /// ([`DeadlineStream`]).
    pub(crate) fn x11_read_text(
        timeout: Duration,
        cap: usize,
    ) -> Result<Option<String>, ClipboardError> {
        use x11rb::connection::Connection;
        use x11rb::protocol::xproto::{
            AtomEnum, ConnectionExt as _, CreateWindowAux, EventMask, Property, WindowClass,
        };
        use x11rb::protocol::Event;

        let deadline = Instant::now() + timeout;
        let expired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failed = || {
            if expired.load(std::sync::atomic::Ordering::SeqCst) {
                read_timeout()
            } else {
                unavailable("clipboard Unicode text is unreadable in this session")
            }
        };
        let (conn, screen_index) = connect_with_deadline(deadline, &expired)?;
        let screen = &conn.setup().roots[screen_index];
        let window = conn.generate_id().map_err(|_| failed())?;
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
        .map_err(|_| failed())?;
        let atom = |name: &[u8]| -> Result<u32, ClipboardError> {
            Ok(conn
                .intern_atom(false, name)
                .map_err(|_| failed())?
                .reply()
                .map_err(|_| failed())?
                .atom)
        };
        let clipboard = atom(b"CLIPBOARD")?;
        let utf8 = atom(b"UTF8_STRING")?;
        let incr = atom(b"INCR")?;
        let property = atom(b"ORCEL_CLIPBOARD_READ")?;
        conn.convert_selection(window, clipboard, utf8, property, x11rb::CURRENT_TIME)
            .map_err(|_| failed())?;
        conn.flush().map_err(|_| failed())?;

        // One property read, capped one word above `cap` so that a larger
        // value is detected (bytes_after or length) without being fetched.
        let cap_words = (cap / 4 + 1) as u32;
        let mut buffer: Vec<u8> = Vec::new();
        let mut incremental = false;
        loop {
            // Bounded by the deadline through `DeadlineStream::poll`.
            let event = conn.wait_for_event().map_err(|_| failed())?;
            match event {
                // #356 item 5: only the answer to this request counts. Any
                // client can send a SelectionNotify; one for another
                // selection, target or property is ignored.
                Event::SelectionNotify(event)
                    if event.requestor == window
                        && event.selection == clipboard
                        && event.target == utf8
                        && (event.property == property
                            || event.property == u32::from(AtomEnum::NONE))
                        && !incremental =>
                {
                    if event.property == u32::from(AtomEnum::NONE) {
                        return Ok(None);
                    }
                    let reply = conn
                        .get_property(true, window, property, AtomEnum::ANY, 0, cap_words)
                        .map_err(|_| failed())?
                        .reply()
                        .map_err(|_| failed())?;
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
                        .map_err(|_| failed())?
                        .reply()
                        .map_err(|_| failed())?;
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
