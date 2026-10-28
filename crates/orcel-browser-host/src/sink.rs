//! XP-14 step 2 (IMPLEMENTATION_BACKLOG.md): the host-owned network sink
//! that replaces the no-route proxy on macOS and Linux.
//!
//! On Windows the engine's proxy is `http://0.0.0.0:9`, and connecting to
//! 0.0.0.0 fails. On macOS and Linux 0.0.0.0 reaches loopback, so a local
//! process listening on port 9 would receive whatever the engine sends to
//! its proxy. The sink closes that hole: the host binds `127.0.0.1:0`
//! itself, passes that exact port as the proxy, and closes every
//! connection it accepts without reading a byte or answering, so a request
//! that is not on the admitted pin list goes nowhere and no other local
//! process can be the proxy.
//!
//! Contract for launch (SG-000115): the sink must outlive the engine and
//! its whole process group. Once stopped, its port is free, and another
//! local process could bind it and become a running engine's proxy.
//!
//! This module adds no authority: launch on macOS and Linux stays refused
//! until SG-000115 is activated, and Windows keeps its no-route proxy.

#![cfg_attr(not(test), allow(dead_code))]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// How often the accept loop checks for stop when no connection waits.
const POLL: Duration = Duration::from_millis(20);

/// A listener on an ephemeral loopback port that accepts and immediately
/// closes every connection. Stopped when dropped.
#[derive(Debug)]
pub(crate) struct NetworkSink {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
}

impl NetworkSink {
    /// Bind `127.0.0.1:0` and start closing connections.
    pub(crate) fn start() -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))?;
        let address = listener.local_addr()?;
        if !address.ip().is_loopback() || address.port() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "the sink is not on an ephemeral loopback port",
            ));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicU64::new(0));
        // Non-blocking accept polled against `stop`: stopping never depends
        // on a wake-up connection that might fail (no descriptors, a full
        // backlog, a loopback filter).
        listener.set_nonblocking(true)?;
        let thread = {
            let (stop, accepted) = (Arc::clone(&stop), Arc::clone(&accepted));
            std::thread::Builder::new()
                .name("orcel-network-sink".into())
                .spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((stream, _)) => {
                                accepted.fetch_add(1, Ordering::SeqCst);
                                // Never read, never answer: close at once.
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                drop(stream);
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                std::thread::sleep(POLL);
                            }
                            // A failed accept (no descriptors, a reset
                            // before accept) must not spin the thread.
                            Err(_) => std::thread::sleep(POLL * 5),
                        }
                    }
                })?
        };
        Ok(Self {
            address,
            stop,
            accepted,
            thread: Some(thread),
        })
    }

    /// The proxy value the engine is given: this exact loopback port.
    pub(crate) fn proxy_url(&self) -> String {
        format!("http://{}", self.address)
    }

    pub(crate) fn port(&self) -> u16 {
        self.address.port()
    }

    /// How many connections reached the sink (each one an attempted
    /// egress that went nowhere); the network-leak probes report it.
    pub(crate) fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }
}

impl Drop for NetworkSink {
    fn drop(&mut self) {
        // The thread checks `stop` at least every `5 * POLL`, then drops the
        // listener and ends: the join is bounded.
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;

    #[test]
    fn the_sink_is_an_ephemeral_loopback_port() {
        let sink = NetworkSink::start().expect("sink");
        assert_ne!(sink.port(), 0);
        assert_ne!(sink.port(), 9, "never the well-known no-route port");
        assert_eq!(
            sink.proxy_url(),
            format!("http://127.0.0.1:{}", sink.port())
        );
    }

    #[test]
    fn a_proxied_request_gets_no_byte_back_and_is_counted() {
        let sink = NetworkSink::start().expect("sink");
        let mut client =
            TcpStream::connect(("127.0.0.1", sink.port())).expect("connect to the sink");
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // What an engine would send its proxy; the sink never reads it.
        let _ =
            client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        let mut answer = Vec::new();
        // The sink closed the connection: end of stream (or a reset), and
        // never a byte.
        let _ = client.read_to_end(&mut answer);
        assert!(
            answer.is_empty(),
            "the sink answered {} bytes",
            answer.len()
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while sink.accepted() < 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(sink.accepted(), 1);
    }

    #[test]
    fn many_connections_are_all_closed() {
        let sink = NetworkSink::start().expect("sink");
        for _ in 0..25 {
            let mut client = TcpStream::connect(("127.0.0.1", sink.port())).expect("connect");
            client
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut answer = Vec::new();
            let _ = client.read_to_end(&mut answer);
            assert!(answer.is_empty());
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while sink.accepted() < 25 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(sink.accepted(), 25);
    }

    #[test]
    fn stopping_is_prompt_and_counts_nothing_more() {
        let sink = NetworkSink::start().expect("sink");
        let accepted = Arc::clone(&sink.accepted);
        let started = std::time::Instant::now();
        drop(sink);
        // No wake-up connection is needed: the poll sees `stop`.
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stop took {:?}",
            started.elapsed()
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            0,
            "stopping made no connection"
        );
    }

    #[test]
    fn two_sinks_never_share_a_port() {
        let first = NetworkSink::start().expect("sink");
        let second = NetworkSink::start().expect("sink");
        assert_ne!(first.port(), second.port());
    }
}
