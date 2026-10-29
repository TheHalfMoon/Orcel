//! SG-000115 slice A4, inert pre-activation engineering (category A4 in
//! `docs/orcel/implementation-readiness/prep/SG-000115.md`): the network
//! confinement primitives for macOS and Linux, and negative leak tests
//! against fixture endpoints.
//!
//! The module is compiled only into test builds (`#[cfg(test)]` in
//! `lib.rs`), so no release build contains it. No production path calls
//! it: `build_worker_argv` (`confinement.rs`) is unchanged and keeps
//! Windows's no-route proxy, and macOS/Linux launch stays refused. The
//! tests use loopback fixtures only and never start a browser.
//!
//! On macOS and Linux `http://0.0.0.0:9` reaches loopback, so the
//! no-route proxy would hand an engine's traffic to whatever local process
//! listens on port 9. The Unix argv therefore takes the host-owned
//! `NetworkSink`'s exact loopback URL as the proxy instead. Every other
//! element stays the production argv, element for element, including the
//! `<-loopback>` bypass entry that removes the engine's implicit direct
//! route to loopback.
//!
//! Category B, not here: running the probes against a real engine, which
//! covers IP-literal navigation, WebRTC UDP and the port-9 listener with an
//! engine attached.

use std::path::Path;

use crate::confinement::{build_worker_argv, AdmittedDestination};
use crate::error::HostError;
use crate::sink::NetworkSink;

/// The production proxy element this slice replaces on Unix.
const NO_ROUTE_PROXY_ARG: &str = "--proxy-server=http://0.0.0.0:9";

/// The Unix worker argv: the production argv with exactly its no-route
/// proxy element replaced by the sink's loopback URL.
pub(crate) fn build_unix_worker_argv(
    profile_dir: &Path,
    destinations: &[AdmittedDestination],
    sink: &NetworkSink,
) -> Result<Vec<String>, HostError> {
    let proxy = sink.proxy_url();
    if !proxy.starts_with("http://127.0.0.1:") || sink.port() == 0 {
        return Err(HostError::Invalid(
            "the sink is not on an ephemeral loopback port".into(),
        ));
    }
    let mut argv = build_worker_argv(profile_dir, destinations)?;
    let positions: Vec<usize> = argv
        .iter()
        .enumerate()
        .filter(|(_, arg)| arg.as_str() == NO_ROUTE_PROXY_ARG)
        .map(|(index, _)| index)
        .collect();
    let [position] = positions.as_slice() else {
        return Err(HostError::Invalid(
            "the production argv does not carry exactly one no-route proxy".into(),
        ));
    };
    argv[*position] = format!("--proxy-server={proxy}");
    Ok(argv)
}

/// Accept a Unix worker argv only if it equals, element for element, the
/// argv built for this profile, destination set and sink.
pub(crate) fn assert_unix_worker_argv_exact(
    argv: &[String],
    profile_dir: &Path,
    destinations: &[AdmittedDestination],
    sink: &NetworkSink,
) -> Result<(), HostError> {
    let expected = build_unix_worker_argv(profile_dir, destinations, sink)?;
    if argv != expected.as_slice() {
        return Err(HostError::Invalid(
            "worker argv differs from the host-built Unix argv".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigation::DnsResolver;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    struct FakeDns(IpAddr);

    impl DnsResolver for FakeDns {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<IpAddr>, HostError> {
            Ok(vec![self.0])
        }
    }

    fn destinations() -> Vec<AdmittedDestination> {
        let pin = IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14));
        vec![AdmittedDestination::admit("https://example.com/", &FakeDns(pin)).unwrap()]
    }

    fn profile() -> PathBuf {
        PathBuf::from("/var/orcel/profile")
    }

    #[test]
    fn the_unix_argv_differs_from_production_only_in_the_proxy() {
        let sink = NetworkSink::start().unwrap();
        let production = build_worker_argv(&profile(), &destinations()).unwrap();
        let unix = build_unix_worker_argv(&profile(), &destinations(), &sink).unwrap();
        assert_eq!(production.len(), unix.len());
        let differing: Vec<(&String, &String)> = production
            .iter()
            .zip(&unix)
            .filter(|(left, right)| left != right)
            .collect();
        assert_eq!(differing.len(), 1, "{differing:?}");
        assert_eq!(differing[0].0, NO_ROUTE_PROXY_ARG);
        assert_eq!(
            differing[0].1,
            &format!("--proxy-server=http://127.0.0.1:{}", sink.port())
        );
        assert!(unix.contains(&"--proxy-bypass-list=example.com;<-loopback>".to_string()));
        assert!(!unix.iter().any(|arg| arg.contains("0.0.0.0")));
        // The production builder is unchanged: it still carries the no-route proxy.
        assert!(production.contains(&NO_ROUTE_PROXY_ARG.to_string()));
    }

    #[test]
    fn any_other_unix_argv_is_refused() {
        let sink = NetworkSink::start().unwrap();
        let other = NetworkSink::start().unwrap();
        let exact = build_unix_worker_argv(&profile(), &destinations(), &sink).unwrap();
        assert!(assert_unix_worker_argv_exact(&exact, &profile(), &destinations(), &sink).is_ok());
        // Built for another sink (another port): refused.
        let foreign = build_unix_worker_argv(&profile(), &destinations(), &other).unwrap();
        assert!(
            assert_unix_worker_argv_exact(&foreign, &profile(), &destinations(), &sink).is_err()
        );
        // The Windows argv (no-route proxy) is not a Unix argv.
        let production = build_worker_argv(&profile(), &destinations()).unwrap();
        assert!(
            assert_unix_worker_argv_exact(&production, &profile(), &destinations(), &sink).is_err()
        );
        // Added, removed, reordered or re-valued elements: refused.
        let mut added = exact.clone();
        added.insert(1, "--proxy-bypass-list=*".into());
        let mut removed = exact.clone();
        removed.retain(|arg| !arg.starts_with("--proxy-bypass-list"));
        let mut reordered = exact.clone();
        reordered.swap(0, 1);
        let mut revalued = exact.clone();
        for arg in &mut revalued {
            if arg.starts_with("--proxy-server=") {
                *arg = "--proxy-server=http://0.0.0.0:9".into();
            }
        }
        for argv in [added, removed, reordered, revalued] {
            assert!(
                assert_unix_worker_argv_exact(&argv, &profile(), &destinations(), &sink).is_err(),
                "{argv:?}"
            );
        }
    }

    /// A fixture client sends a proxy request through the sink: nothing
    /// comes back, the connection is closed, and the sink counts it.
    #[test]
    fn a_request_through_the_sink_goes_nowhere_and_is_counted() {
        let sink = NetworkSink::start().unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", sink.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // The write may race the sink's close; either way nothing is answered.
        let _ =
            client.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        let mut answer = Vec::new();
        let read = client.read_to_end(&mut answer);
        assert!(
            answer.is_empty(),
            "the sink answered: {answer:?} ({read:?})"
        );
        let started = Instant::now();
        while sink.accepted() == 0 && started.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(sink.accepted(), 1);
    }

    /// A rogue local listener receives nothing that went to the sink, and
    /// cannot take the sink's port while the sink lives (the sink must
    /// outlive the engine).
    #[test]
    fn a_rogue_listener_receives_nothing_and_cannot_take_the_sink_port() {
        let sink = NetworkSink::start().unwrap();
        let rogue = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        rogue.set_nonblocking(true).unwrap();
        for _ in 0..3 {
            let _ = TcpStream::connect(("127.0.0.1", sink.port()));
        }
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            rogue.accept().is_err(),
            "the rogue listener received a connection"
        );
        assert!(
            TcpListener::bind(("127.0.0.1", sink.port())).is_err(),
            "another process could bind the live sink's port"
        );
    }

    /// Pre-activation boundary: only lib.rs (the test-only declaration)
    /// names this module; the production argv builder is unchanged.
    #[test]
    fn the_unix_confinement_primitives_are_unreachable_from_production() {
        let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        for dir in ["src", "tests"] {
            let mut stack = vec![crate_dir.join(dir)];
            while let Some(next) = stack.pop() {
                for entry in std::fs::read_dir(&next).unwrap() {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        stack.push(path);
                    } else if path.extension().is_some_and(|ext| ext == "rs") {
                        files.push(path);
                    }
                }
            }
        }
        assert!(files.len() > 10, "the scan found the crate's sources");
        let mut named = Vec::new();
        for path in &files {
            if *path == crate_dir.join("src").join("unix_confinement.rs")
                || *path == crate_dir.join("src").join("lib.rs")
            {
                continue;
            }
            let text = std::fs::read_to_string(path).unwrap_or_default();
            for needle in [
                "unix_confinement",
                "build_unix_worker_argv",
                "assert_unix_worker_argv_exact",
            ] {
                if text.contains(needle) {
                    named.push(format!("{}: {needle}", path.display()));
                }
            }
        }
        assert!(named.is_empty(), "{named:?}");
        let lib = std::fs::read_to_string(crate_dir.join("src/lib.rs"))
            .unwrap()
            .replace("\r\n", "\n");
        let lines: Vec<&str> = lib.lines().collect();
        let code: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| {
                line.contains("unix_confinement") && !line.trim_start().starts_with("//")
            })
            .map(|(index, _)| index)
            .collect();
        assert_eq!(code.len(), 1, "lib.rs declares the module once");
        assert_eq!(lines[code[0]], "mod unix_confinement;");
        assert_eq!(lines[code[0] - 1], "#[cfg(test)]");
        let confinement = std::fs::read_to_string(crate_dir.join("src/confinement.rs")).unwrap();
        assert!(confinement.contains("const NO_ROUTE_PROXY: &str = \"http://0.0.0.0:9\";"));
        assert!(confinement.contains("argv.push(format!(\"{PROXY_FLAG}={NO_ROUTE_PROXY}\"));"));
    }
}
