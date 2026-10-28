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
//! This module adds no authority: launch on macOS and Linux stays refused
//! until SG-000115 is activated, and Windows keeps its no-route proxy.

#![cfg_attr(not(test), allow(dead_code))]

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

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
        let thread = {
            let (stop, accepted) = (Arc::clone(&stop), Arc::clone(&accepted));
            std::thread::Builder::new()
                .name("orcel-network-sink".into())
                .spawn(move || {
                    for stream in listener.incoming() {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        match stream {
                            Ok(stream) => {
                                accepted.fetch_add(1, Ordering::SeqCst);
                                // Never read, never answer: close at once.
                                let _ = stream.shutdown(std::net::Shutdown::Both);
                                drop(stream);
                            }
                            // A failed accept (no descriptors, a reset
                            // before accept) must not spin the thread.
                            Err(_) => std::thread::sleep(Duration::from_millis(50)),
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
        self.stop.store(true, Ordering::SeqCst);
        // Wake the blocked accept; the thread sees `stop` and ends.
        let _ = TcpStream::connect_timeout(&self.address, Duration::from_secs(2));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

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
    fn a_stopped_sink_releases_its_port() {
        let sink = NetworkSink::start().expect("sink");
        let port = sink.port();
        drop(sink);
        // Nothing listens there any more: a connection is refused rather
        // than reaching a stale sink (or anything else holding the port
        // open on the host's behalf).
        let refused = TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            Duration::from_secs(2),
        );
        assert!(refused.is_err(), "port {port} still accepts after stop");
    }

    #[test]
    fn two_sinks_never_share_a_port() {
        let first = NetworkSink::start().expect("sink");
        let second = NetworkSink::start().expect("sink");
        assert_ne!(first.port(), second.port());
    }
}
