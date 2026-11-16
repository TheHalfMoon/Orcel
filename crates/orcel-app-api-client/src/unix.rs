//! macOS and Linux: the socket in the per-user runtime directory, derived
//! as orceld derives it (protocol section 1; `socket_dir` in
//! `crates/orceld/src/app_api.rs`), and the server's identity confirmed
//! before the first write, the way orceld confirms its clients (MAC-M1-05):
//!
//! 1. Before connecting, the socket's directory and the socket are read
//!    without following links and must be what orceld creates: a directory
//!    of this user without group or other access that passes XP-01's
//!    private directory rules, holding a socket of this user without group
//!    or other access ([`identity::decide_endpoint`]).
//! 2. After connecting, the peer is read with
//!    `orcel_platform::peer::unix_peer_credentials` (XP-03), the code orceld
//!    reads its clients with: the kernel's uid for the peer, bound to its
//!    process instance. It must be this effective uid, from a source orceld
//!    accepts, and still alive ([`identity::decide`]).
//!
//! Only Windows is qualified in SG-000119; this code keeps the later stages
//! small and runs on the existing root legs.
//!
//! Known limit: when the OS has no private runtime directory, orceld falls
//! back to the `run` folder of its state root. This client does not resolve
//! the state root (state stores are named only through `orcel_platform`'s
//! registry, #655), so it reports that the app API has no location.

use crate::error::{ClientError, Unavailable};
use crate::identity::{self, EndpointFacts, EntryFacts, EntryKind, IdentityRefusal, ServerFacts};
use crate::transport::{Cancel, Conn};
use orcel_platform::peer::PeerIdentity;
use orcel_platform::PlatformError;
use std::ffi::OsString;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

/// An absolute value without `.` or `..` components, as orceld requires of
/// every base directory it reads.
fn usable_absolute(value: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    (path.is_absolute()
        && !path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir)))
    .then_some(path)
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// A runtime directory as the XDG spec requires one: a real directory owned
/// by this user with no group or other access.
fn private_runtime(dir: &Path) -> bool {
    let ours = effective_uid();
    std::fs::symlink_metadata(dir).is_ok_and(|meta| {
        meta.file_type().is_dir() && meta.uid() == ours && meta.permissions().mode() & 0o077 == 0
    })
}

#[cfg(target_os = "macos")]
fn runtime_dir() -> Option<PathBuf> {
    orcel_platform::paths::macos_per_user_runtime_dir()
        .and_then(|dir| usable_absolute(dir.into_os_string()))
}

#[cfg(not(target_os = "macos"))]
fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").and_then(usable_absolute)
}

/// `<runtime dir>/orcel/app-api<suffix>.sock`, when there is a private
/// runtime directory (see the module's known limit).
pub(crate) fn socket_path(suffix: &str) -> Result<PathBuf, ClientError> {
    runtime_dir()
        .filter(|dir| private_runtime(dir))
        .map(|runtime| runtime.join("orcel").join(format!("app-api{suffix}.sock")))
        .ok_or(ClientError::Unavailable(Unavailable::NoLocation))
}

fn entry(meta: &std::fs::Metadata) -> EntryFacts {
    let file_type = meta.file_type();
    let kind = if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else if file_type.is_socket() {
        EntryKind::Socket
    } else {
        EntryKind::Other
    };
    EntryFacts {
        kind,
        owner: meta.uid(),
        mode: meta.mode() & 0o7777,
    }
}

/// One entry, read without following links. A missing entry means orceld
/// is not running; one that cannot be read cannot be confirmed.
fn read_entry(path: &Path) -> Result<EntryFacts, ClientError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => Ok(entry(&meta)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Err(ClientError::Unavailable(Unavailable::NotRunning))
        }
        Err(_) => Err(ClientError::NotYours(IdentityRefusal::Unidentified)),
    }
}

/// Step 1: the socket's directory, then the socket, decided before any
/// connect. The directory is decided first, so a socket missing from a
/// directory that is not private is refused, not reported as not running.
fn check_endpoint(path: &Path, ours: u32) -> Result<(), ClientError> {
    let dir_path = path
        .parent()
        .filter(|dir| !dir.as_os_str().is_empty())
        .ok_or(ClientError::NotYours(IdentityRefusal::DirectoryNotPrivate))?;
    let dir = read_entry(dir_path)?;
    // XP-01's rules, read-only: the ancestors and (macOS) extended ACLs.
    let dir_rules = dir.kind == EntryKind::Directory
        && orcel_platform::paths::check_existing_private_dir(dir_path).is_ok();
    identity::decide_directory(dir, dir_rules, ours).map_err(ClientError::NotYours)?;
    let socket = read_entry(path)?;
    identity::decide_endpoint(&EndpointFacts {
        dir,
        dir_rules,
        socket,
        ours,
    })
    .map_err(ClientError::NotYours)
}

/// What `orcel_platform::peer` read, as the facts [`identity::decide`]
/// takes. `ProcessGone` (pid 0 included) only ever refuses this connection.
fn server_facts(read: Result<PeerIdentity, PlatformError>, ours: u32) -> ServerFacts {
    match read {
        Ok(identity) => ServerFacts::Peer {
            uid: identity.uid,
            ours,
            source: identity.source,
        },
        Err(PlatformError::ProcessGone(_)) => ServerFacts::PeerGone,
        Err(_) => ServerFacts::Unreadable,
    }
}

/// Step 2: the connected peer, read from the kernel.
fn confirm_server(stream: &UnixStream, ours: u32) -> Result<(), ClientError> {
    let read = orcel_platform::peer::unix_peer_credentials(stream);
    identity::decide(&server_facts(read, ours)).map_err(ClientError::NotYours)
}

/// Checks the endpoint, connects to `path` and confirms the server before
/// returning; nothing is written here.
pub(crate) fn connect(path: &Path, cancel: &Cancel) -> Result<UnixStream, ClientError> {
    let ours = effective_uid();
    check_endpoint(path, ours)?;
    let stream = UnixStream::connect(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            ClientError::Unavailable(Unavailable::NotRunning)
        }
        _ => ClientError::io(&error),
    })?;
    cancel
        .watch(&stream)
        .map_err(|error| ClientError::io(&error))?;
    confirm_server(&stream, ours)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| ClientError::io(&error))?;
    Ok(stream)
}

impl Conn for UnixStream {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::os::unix::net::UnixListener;
    use std::process::{Command, Stdio};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    /// The environment variable that tells the helper test which socket to
    /// serve. Read by test code only.
    const HELPER_SOCKET: &str = "ORCEL_A1_TEST_UNIX_SERVER_SOCKET";
    const HELPER_TEST: &str = "unix::tests::helper_serves_a_socket_until_stdin_closes";
    const HELPER_READY: &str = "a1-unix-helper-ready";

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    /// A 0700 directory below `/tmp` with a 0700 `orcel` directory in it,
    /// as orceld lays out its runtime directory; removed on drop.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            // Unique per test, even for tests started in the same instant.
            static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let base = PathBuf::from("/tmp").join(format!(
                "a1u-{}-{:x}-{}",
                std::process::id(),
                nanos % 0xff_ffff_ffff,
                COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(base.join("orcel")).expect("create test dir");
            chmod(&base, 0o700);
            chmod(&base.join("orcel"), 0o700);
            Self(base)
        }

        fn orcel(&self) -> PathBuf {
            self.0.join("orcel")
        }

        /// A listening socket at `orcel/<name>` with `mode`.
        fn serve(&self, name: &str, mode: u32) -> (PathBuf, UnixListener) {
            let path = self.orcel().join(name);
            let listener = UnixListener::bind(&path).expect("bind");
            chmod(&path, mode);
            listener.set_nonblocking(true).expect("nonblocking");
            (path, listener)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn connect_to(path: &Path) -> Result<UnixStream, ClientError> {
        connect(path, &Cancel::new().expect("cancel"))
    }

    /// Nothing reached the listener: the client refused before connecting.
    fn nobody_connected(listener: &UnixListener) {
        let accepted = listener.accept();
        assert!(
            matches!(&accepted, Err(error) if error.kind() == io::ErrorKind::WouldBlock),
            "the refused client connected: {accepted:?}"
        );
    }

    #[test]
    fn a_socket_served_as_orceld_serves_it_is_accepted() {
        let dir = Dir::new();
        let (path, listener) = dir.serve("s.sock", 0o600);
        let stream = connect_to(&path).expect("the endpoint orceld creates");
        let (mut served, _) = listener.accept().expect("the client connected");
        drop(stream);
        let mut buf = [0u8; 16];
        // The client wrote nothing.
        assert_eq!(served.read(&mut buf).expect("read"), 0);
    }

    #[test]
    fn a_socket_open_to_other_accounts_is_refused_before_connecting() {
        let dir = Dir::new();
        for (name, mode) in [("g.sock", 0o660), ("o.sock", 0o606), ("w.sock", 0o777)] {
            let (path, listener) = dir.serve(name, mode);
            assert_eq!(
                connect_to(&path).map(drop),
                Err(ClientError::NotYours(IdentityRefusal::SocketNotPrivate)),
                "{mode:o}"
            );
            nobody_connected(&listener);
        }
    }

    #[test]
    fn a_directory_open_to_other_accounts_is_refused_before_connecting() {
        let dir = Dir::new();
        let (path, listener) = dir.serve("s.sock", 0o600);
        for mode in [0o750, 0o705, 0o755] {
            chmod(&dir.orcel(), mode);
            assert_eq!(
                connect_to(&path).map(drop),
                Err(ClientError::NotYours(IdentityRefusal::DirectoryNotPrivate)),
                "{mode:o}"
            );
            // A missing socket there is refused too, not "not running".
            assert_eq!(
                connect_to(&dir.orcel().join("missing.sock")).map(drop),
                Err(ClientError::NotYours(IdentityRefusal::DirectoryNotPrivate))
            );
        }
        nobody_connected(&listener);
        chmod(&dir.orcel(), 0o700);
        assert!(connect_to(&path).is_ok());
    }

    #[test]
    fn a_link_or_a_file_at_the_socket_path_is_refused() {
        let dir = Dir::new();
        let (target, listener) = dir.serve("real.sock", 0o600);
        let link = dir.orcel().join("link.sock");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(
            connect_to(&link).map(drop),
            Err(ClientError::NotYours(IdentityRefusal::NotASocket))
        );
        nobody_connected(&listener);
        let file = dir.orcel().join("file.sock");
        std::fs::write(&file, b"").expect("file");
        chmod(&file, 0o600);
        assert_eq!(
            connect_to(&file).map(drop),
            Err(ClientError::NotYours(IdentityRefusal::NotASocket))
        );
        // A link in place of the directory is refused as the directory.
        let linked_dir = dir.0.join("linked");
        std::os::unix::fs::symlink(dir.orcel(), &linked_dir).expect("symlink");
        assert_eq!(
            connect_to(&linked_dir.join("real.sock")).map(drop),
            Err(ClientError::NotYours(IdentityRefusal::DirectoryNotPrivate))
        );
        nobody_connected(&listener);
    }

    #[test]
    fn a_missing_socket_or_directory_is_not_running() {
        let dir = Dir::new();
        for path in [
            dir.orcel().join("missing.sock"),
            dir.0.join("no-dir").join("missing.sock"),
        ] {
            assert_eq!(
                connect_to(&path).map(drop),
                Err(ClientError::Unavailable(Unavailable::NotRunning))
            );
        }
        // A stale socket nobody listens on is not running either.
        let (path, listener) = dir.serve("stale.sock", 0o600);
        drop(listener);
        assert_eq!(
            connect_to(&path).map(drop),
            Err(ClientError::Unavailable(Unavailable::NotRunning))
        );
    }

    #[test]
    fn what_orcel_platform_reads_maps_to_the_decision() {
        let ours = effective_uid();
        let identity = |uid, source| {
            Ok(PeerIdentity {
                process: orcel_platform::process::current_instance().expect("this process"),
                uid,
                gid: 0,
                audit_session: None,
                source,
            })
        };
        let decided = |read| identity::decide(&server_facts(read, ours));
        assert_eq!(decided(identity(ours, "linux-so-peerpidfd")), Ok(()));
        assert_eq!(decided(identity(ours, "macos-local-peertoken")), Ok(()));
        assert_eq!(
            decided(identity(ours.wrapping_add(1), "linux-so-peerpidfd")),
            Err(IdentityRefusal::OtherAccount)
        );
        assert_eq!(
            decided(identity(ours, "linux-so-peercred")),
            Err(IdentityRefusal::WeakIdentity)
        );
        // A reused or exited pid, pid 0 included.
        for pid in [0, 4242] {
            assert_eq!(
                decided(Err(PlatformError::ProcessGone(pid))),
                Err(IdentityRefusal::ServerGone)
            );
        }
        for error in [
            PlatformError::UnsupportedPlatform,
            PlatformError::IdentityUnavailable("unreadable".into()),
            PlatformError::PeerRefused {
                peer_uid: 0,
                expected_uid: ours,
            },
        ] {
            assert_eq!(decided(Err(error)), Err(IdentityRefusal::Unidentified));
        }
    }

    /// This process's own uid on a live socket, read by the same call
    /// orceld uses, is accepted (both ends are this test process).
    #[test]
    fn the_kernel_read_of_a_live_same_user_server_is_accepted() {
        let dir = Dir::new();
        let (path, _listener) = dir.serve("s.sock", 0o600);
        let stream = UnixStream::connect(&path).expect("connect");
        assert_eq!(confirm_server(&stream, effective_uid()), Ok(()));
        // The same read is refused for any other expected uid.
        assert_eq!(
            confirm_server(&stream, effective_uid().wrapping_add(1)),
            Err(ClientError::NotYours(IdentityRefusal::OtherAccount))
        );
    }

    /// Run by [`a_server_that_exits_after_the_connect_is_refused`] in a child
    /// process: serves the socket `HELPER_SOCKET` names, says `HELPER_READY`, and
    /// exits when its stdin closes. Without the variable it does nothing.
    #[test]
    fn helper_serves_a_socket_until_stdin_closes() {
        let Some(path) = std::env::var_os(HELPER_SOCKET) else {
            return;
        };
        let path = PathBuf::from(path);
        let _listener = UnixListener::bind(&path).expect("helper bind");
        chmod(&path, 0o600);
        println!("{HELPER_READY}");
        let mut sink = Vec::new();
        let _ = io::stdin().read_to_end(&mut sink);
    }

    /// A server process that is gone by the time its identity is read is
    /// refused: the read is bound to the live process (Linux: its pidfd;
    /// macOS: the audit token's pidversion), so a pid that exited, and any
    /// process that later reuses it, is never taken for the server.
    #[test]
    fn a_server_that_exits_after_the_connect_is_refused() {
        let dir = Dir::new();
        let path = dir.orcel().join("helper.sock");
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", HELPER_TEST, "--nocapture", "--test-threads=1"])
            .env(HELPER_SOCKET, &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn helper");
        let stdout = child.stdout.take().expect("helper stdout");
        let (ready_tx, ready) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                // libtest may print it on its own `test ... ` line.
                if line.contains(HELPER_READY) {
                    let _ = ready_tx.send(());
                }
            }
        });
        ready
            .recv_timeout(Duration::from_secs(30))
            .expect("the helper serves the socket");
        // While the helper lives, the whole connect accepts it.
        let started = Instant::now();
        let live = connect_to(&path).expect("a live same-user server");
        assert!(started.elapsed() < Duration::from_secs(10));
        drop(live);
        // Connected while it lives; read after it has exited and been reaped.
        let stream = UnixStream::connect(&path).expect("connect to the helper");
        child.kill().expect("kill helper");
        child.wait().expect("reap helper");
        let refused = confirm_server(&stream, effective_uid());
        if cfg!(target_os = "linux") {
            assert_eq!(
                refused,
                Err(ClientError::NotYours(IdentityRefusal::ServerGone))
            );
        } else {
            // macOS: a closed peer reads as gone (pid 0) or as unreadable;
            // either way it is refused.
            assert!(
                matches!(
                    refused,
                    Err(ClientError::NotYours(
                        IdentityRefusal::ServerGone | IdentityRefusal::Unidentified
                    ))
                ),
                "{refused:?}"
            );
        }
    }
}
