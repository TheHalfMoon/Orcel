//! XP-15 adapter tests: sequence derivation everywhere; on Linux, the
//! bounded readers against owners that stall, never finish, or send too
//! much.

use super::sequence_of;

#[test]
fn sequence_tracks_content_and_distinguishes_no_text() {
    assert_eq!(sequence_of(Some("a")), sequence_of(Some("a")));
    assert_ne!(sequence_of(Some("a")), sequence_of(Some("b")));
    assert_ne!(sequence_of(Some("")), sequence_of(None));
}

/// The Wayland reader seam: wl-clipboard-rs hands over a pipe whose
/// writer is the clipboard owner. A Unix socket pair stands in for it.
#[cfg(target_os = "linux")]
mod pipe_reader {
    use super::super::linux::read_pipe_bounded;
    use crate::{FailureCode, MAX_CLIPBOARD_BYTES};
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    const SHORT: Duration = Duration::from_millis(300);

    #[test]
    fn xp15_owner_that_never_closes_the_pipe_times_out() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let error = read_pipe_bounded(reader, SHORT, MAX_CLIPBOARD_BYTES)
            .expect_err("an owner that never closes must not block the read");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(error.message.contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(writer);
    }

    #[test]
    fn xp15_owner_that_drips_forever_hits_the_overall_deadline() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let dripper = std::thread::spawn(move || {
            // One byte every 20 ms, never closing: each byte would reset a
            // per-chunk timeout, but the deadline is overall.
            while writer.write_all(b"a").is_ok() {
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let started = Instant::now();
        let error = read_pipe_bounded(reader, SHORT, MAX_CLIPBOARD_BYTES)
            .expect_err("a dripping owner must not extend the read");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(started.elapsed() < Duration::from_secs(2));
        // The reader is dropped, so the dripper's next write fails.
        dripper.join().unwrap();
    }

    #[test]
    fn xp15_owner_that_sends_too_much_is_refused_without_buffering_it() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        let flood = std::thread::spawn(move || {
            let block = vec![b'a'; 4096];
            while writer.write_all(&block).is_ok() {}
        });
        let error = read_pipe_bounded(reader, Duration::from_secs(5), MAX_CLIPBOARD_BYTES)
            .expect_err("oversize content must be refused");
        assert_eq!(error.code, FailureCode::OutputLimit);
        flood.join().unwrap();
    }

    #[test]
    fn xp15_owner_that_sends_text_and_closes_is_read() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all("caf\u{e9}".as_bytes()).unwrap();
        drop(writer);
        let bytes = read_pipe_bounded(reader, SHORT, MAX_CLIPBOARD_BYTES).unwrap();
        assert_eq!(bytes, "caf\u{e9}".as_bytes());
        let (reader, mut writer) = UnixStream::pair().unwrap();
        writer.write_all(&vec![b'a'; MAX_CLIPBOARD_BYTES]).unwrap();
        drop(writer);
        let bytes = read_pipe_bounded(reader, Duration::from_secs(5), MAX_CLIPBOARD_BYTES).unwrap();
        assert_eq!(bytes.len(), MAX_CLIPBOARD_BYTES);
    }
}

/// The X11 reader against fake CLIPBOARD owners on a live X server
/// (Xvfb in CI). Without a display the tests report why and pass, unless
/// `ORCEL_REQUIRE_LIVE_CLIPBOARD=1` is set.
#[cfg(target_os = "linux")]
mod x11_owner {
    use super::super::linux::x11_read_text;
    use crate::{FailureCode, MAX_CLIPBOARD_BYTES};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        ChangeWindowAttributesAux, ConnectionExt as _, CreateWindowAux, EventMask, PropMode,
        Property, SelectionNotifyEvent, WindowClass, SELECTION_NOTIFY_EVENT,
    };
    use x11rb::protocol::Event;
    use x11rb::wrapper::ConnectionExt as _;

    #[derive(Clone)]
    enum Behavior {
        /// Owns the selection and never answers.
        Silent,
        /// Answers with one UTF8_STRING property.
        Direct(Vec<u8>),
        /// Answers with INCR, then sends these chunks and the empty end
        /// marker; `None` sends 4 KiB chunks forever.
        Incremental(Option<Vec<Vec<u8>>>),
    }

    struct FakeOwner {
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl Drop for FakeOwner {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn display_or_skip(test: &str) -> bool {
        if x11rb::connect(None).is_ok() {
            return true;
        }
        assert!(
            std::env::var("ORCEL_REQUIRE_LIVE_CLIPBOARD").as_deref() != Ok("1"),
            "{test}: a live X display was required but none is reachable"
        );
        eprintln!("{test} skipped: no X11 display is reachable");
        false
    }

    fn spawn_owner(behavior: Behavior) -> FakeOwner {
        let stop = Arc::new(AtomicBool::new(false));
        let (ready_tx, ready_rx) = mpsc::channel();
        let thread_stop = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let (conn, screen_index) = x11rb::connect(None).unwrap();
            let screen = &conn.setup().roots[screen_index];
            let window = conn.generate_id().unwrap();
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
                &CreateWindowAux::new(),
            )
            .unwrap();
            let atom = |name: &[u8]| conn.intern_atom(false, name).unwrap().reply().unwrap().atom;
            let clipboard = atom(b"CLIPBOARD");
            let utf8 = atom(b"UTF8_STRING");
            let incr = atom(b"INCR");
            conn.set_selection_owner(window, clipboard, x11rb::CURRENT_TIME)
                .unwrap();
            let owner = conn
                .get_selection_owner(clipboard)
                .unwrap()
                .reply()
                .unwrap()
                .owner;
            assert_eq!(owner, window, "the fake owner must own CLIPBOARD");
            ready_tx.send(()).unwrap();

            // (requestor, property, next chunk index) of a running INCR.
            let mut sending: Option<(u32, u32, usize)> = None;
            while !thread_stop.load(Ordering::SeqCst) {
                let event = match conn.poll_for_event().unwrap() {
                    Some(event) => event,
                    None => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                };
                match (event, &behavior) {
                    (Event::SelectionRequest(_), Behavior::Silent) => {}
                    (Event::SelectionRequest(request), Behavior::Direct(_))
                    | (Event::SelectionRequest(request), Behavior::Incremental(_)) => {
                        if let Behavior::Direct(data) = &behavior {
                            conn.change_property8(
                                PropMode::REPLACE,
                                request.requestor,
                                request.property,
                                utf8,
                                data,
                            )
                            .unwrap();
                        } else {
                            conn.change_window_attributes(
                                request.requestor,
                                &ChangeWindowAttributesAux::new()
                                    .event_mask(EventMask::PROPERTY_CHANGE),
                            )
                            .unwrap();
                            conn.change_property32(
                                PropMode::REPLACE,
                                request.requestor,
                                request.property,
                                incr,
                                // An absurd announced size the reader must
                                // not allocate for.
                                &[u32::MAX],
                            )
                            .unwrap();
                            sending = Some((request.requestor, request.property, 0));
                        }
                        let notify = SelectionNotifyEvent {
                            response_type: SELECTION_NOTIFY_EVENT,
                            sequence: 0,
                            time: request.time,
                            requestor: request.requestor,
                            selection: request.selection,
                            target: request.target,
                            property: request.property,
                        };
                        conn.send_event(false, request.requestor, EventMask::NO_EVENT, notify)
                            .unwrap();
                        conn.flush().unwrap();
                    }
                    (Event::PropertyNotify(event), Behavior::Incremental(chunks)) => {
                        let Some((requestor, property, index)) = sending else {
                            continue;
                        };
                        if event.window != requestor
                            || event.atom != property
                            || event.state != Property::DELETE
                        {
                            continue;
                        }
                        let chunk = match chunks {
                            None => vec![b'a'; 4096],
                            Some(chunks) => chunks.get(index).cloned().unwrap_or_default(),
                        };
                        let finished = chunk.is_empty();
                        // Writes after the reader has gone fail; ignore them.
                        let _ = conn.change_property8(
                            PropMode::REPLACE,
                            requestor,
                            property,
                            utf8,
                            &chunk,
                        );
                        let _ = conn.flush();
                        sending = if finished {
                            None
                        } else {
                            Some((requestor, property, index + 1))
                        };
                    }
                    _ => {}
                }
            }
        });
        ready_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the fake owner takes the selection");
        FakeOwner {
            stop,
            handle: Some(handle),
        }
    }

    #[test]
    fn xp15_x11_owner_that_never_answers_times_out() {
        let _guard = crate::tests::native_clipboard_test_lock();
        if !display_or_skip("xp15_x11_owner_that_never_answers_times_out") {
            return;
        }
        let _owner = spawn_owner(Behavior::Silent);
        let started = Instant::now();
        let error = x11_read_text(Duration::from_millis(500), MAX_CLIPBOARD_BYTES)
            .expect_err("a silent owner must not block the read");
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(error.message.contains("deadline"));
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn xp15_x11_oversize_property_is_refused() {
        let _guard = crate::tests::native_clipboard_test_lock();
        if !display_or_skip("xp15_x11_oversize_property_is_refused") {
            return;
        }
        let _owner = spawn_owner(Behavior::Direct(vec![b'a'; MAX_CLIPBOARD_BYTES + 100]));
        let error = x11_read_text(Duration::from_secs(5), MAX_CLIPBOARD_BYTES)
            .expect_err("an oversize property must be refused");
        assert_eq!(error.code, FailureCode::OutputLimit);
    }

    #[test]
    fn xp15_x11_endless_incr_transfer_is_capped() {
        let _guard = crate::tests::native_clipboard_test_lock();
        if !display_or_skip("xp15_x11_endless_incr_transfer_is_capped") {
            return;
        }
        let _owner = spawn_owner(Behavior::Incremental(None));
        let started = Instant::now();
        let error = x11_read_text(Duration::from_secs(10), MAX_CLIPBOARD_BYTES)
            .expect_err("an endless INCR transfer must be refused");
        assert_eq!(error.code, FailureCode::OutputLimit);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn xp15_x11_incr_and_direct_text_are_read() {
        let _guard = crate::tests::native_clipboard_test_lock();
        if !display_or_skip("xp15_x11_incr_and_direct_text_are_read") {
            return;
        }
        {
            let _owner = spawn_owner(Behavior::Direct("caf\u{e9}".as_bytes().to_vec()));
            let text = x11_read_text(Duration::from_secs(5), MAX_CLIPBOARD_BYTES).unwrap();
            assert_eq!(text.as_deref(), Some("caf\u{e9}"));
        }
        let chunks = vec![vec![b'x'; 3000], vec![b'y'; 3000], b"end".to_vec()];
        let _owner = spawn_owner(Behavior::Incremental(Some(chunks)));
        let text = x11_read_text(Duration::from_secs(5), MAX_CLIPBOARD_BYTES)
            .unwrap()
            .expect("INCR text");
        assert_eq!(text.len(), 6003);
        assert!(text.starts_with('x') && text.ends_with("yend"));
    }
}
