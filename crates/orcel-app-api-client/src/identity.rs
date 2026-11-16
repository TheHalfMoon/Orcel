//! Whether the endpoint's server is this user's orceld, decided before the
//! first write.
//!
//! The pipe name is predictable and the pipe namespace is shared, so
//! `ORCEL_APP_API_1.md` section 7 asks a client to confirm the server runs as
//! its own user. orceld's own `describe_holder` and `token_user` compare the
//! account only; the Control Room also requires Medium integrity or above,
//! ported from the WPF preview's `ServerIsThisUser` and
//! `ProcessRunsAsThisUser` (`apps/orcel-desktop-preview/src/Program.cs`,
//! called at line 447, defined at lines 482-510): the mandatory label's last
//! sub-authority is the level, and `0x2000` is Medium.
//!
//! On Windows the pipe object is checked too, against a server that took
//! the pid check's process and then handed the pipe on: its owner must be
//! this user (or, only when this client's token is elevated, exactly the
//! Administrators group `S-1-5-32-544`, which owns what an elevated token
//! creates) and its mandatory label must
//! be Medium or above (orceld labels its pipe `ME`); an unlabeled pipe is
//! refused.
//!
//! On macOS and Linux (MAC-M1-05) the client checks the server the way
//! orceld checks its clients (`admit_unix` in `crates/orceld/src/app_api.rs`):
//! the socket peer is read with `orcel_platform::peer::unix_peer_credentials`
//! (XP-03), so its uid comes from the kernel and is bound to the peer's
//! process instance (pid plus start generation); the uid must be this
//! process's effective uid, a peer that has exited or whose pid now names
//! another process is refused, and only the sources orceld accepts are
//! accepted (Linux's pre-6.5 `linux-so-peercred` is not, #367 item 2). Before
//! connecting, the socket and its directory are held to what orceld creates:
//! a socket this user owns without group or other access (orceld sets 0600),
//! not a link, in a directory this user owns without group or other access
//! that passes XP-01's private directory rules (orceld's `bind` holds it to
//! `ensure_private_dir`, 0700).
//!
//! The platform code only gathers [`ServerFacts`], [`ObjectFacts`] and
//! [`EndpointFacts`]; [`decide`], [`decide_object`] and [`decide_endpoint`]
//! are the whole decision, so they are unit-tested on every OS.

use std::fmt;

/// `SECURITY_MANDATORY_MEDIUM_RID`.
pub const MEDIUM_INTEGRITY: u32 = 0x2000;

/// What the platform read about the endpoint's server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFacts {
    /// The pipe was refused with `ERROR_ACCESS_DENIED`: its security
    /// refuses this account, so another account created it first.
    PipeRefusesThisAccount,
    /// `GetNamedPipeServerProcessId` failed or gave 0.
    NoServerPid,
    /// `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` failed with this
    /// Win32 error.
    ProcessNotOpened(u32),
    /// The server's token (or this process's) could not be read.
    TokenUnreadable(u32),
    /// The token was read: whether its user is this process's user, and
    /// the mandatory label's last sub-authority (`None` when the label had
    /// no sub-authority).
    Token {
        same_user: bool,
        integrity: Option<u32>,
    },
    /// Unix: the socket peer as `orcel_platform::peer` read it from the
    /// kernel: its uid, this process's effective uid, and how the identity
    /// was read (`PeerIdentity::source`).
    Peer {
        uid: u32,
        ours: u32,
        source: &'static str,
    },
    /// Unix: the peer process has exited, or its pid names another process
    /// now (`PlatformError::ProcessGone`). It means only "refuse this
    /// connection".
    PeerGone,
    /// The peer's identity could not be read on this OS.
    Unreadable,
}

/// The `orcel_platform::peer` sources orceld admits (#367 item 2): Linux
/// 6.5+'s pidfd-bound read and macOS's audit token. Anything else, the
/// pre-6.5 `linux-so-peercred` with its pid-reuse race included, is refused.
pub const ACCEPTED_PEER_SOURCES: [&str; 2] = ["linux-so-peerpidfd", "macos-local-peertoken"];

/// Unix: what one entry on the socket path is, read without following
/// links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    Directory,
    Socket,
    Symlink,
    Other,
}

/// Unix: one entry's type, owner and permission bits (`st_mode & 0o7777`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryFacts {
    pub kind: EntryKind,
    pub owner: u32,
    pub mode: u32,
}

/// Unix: the socket and its directory, read before connecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointFacts {
    /// The socket's directory.
    pub dir: EntryFacts,
    /// Whether the directory also passes XP-01's private directory rules
    /// (`orcel_platform::paths::check_existing_private_dir`: no ancestor
    /// another user can modify; on macOS no extended ACL entry).
    pub dir_rules: bool,
    /// The socket path itself.
    pub socket: EntryFacts,
    /// This process's effective uid.
    pub ours: u32,
}

/// What the platform read about the pipe object itself (Windows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectFacts {
    /// `GetSecurityInfo` failed with this Win32 error, or this process's
    /// own token could not be read.
    Unreadable(u32),
    /// The owner and the mandatory label were read: who owns the pipe,
    /// whether this client's token is elevated, and the label's last
    /// sub-authority (`None` when the pipe carries no label).
    Read {
        owner: PipeOwner,
        client_elevated: bool,
        label: Option<u32>,
    },
}

/// Who owns the pipe object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeOwner {
    /// This client's user.
    ThisUser,
    /// Exactly `S-1-5-32-544`, BUILTIN\Administrators.
    Administrators,
    /// Anyone else, or no owner.
    Other,
}

/// Why a connection was refused before anything was written. The window
/// says "orceld could not be confirmed as yours".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRefusal {
    /// Another account holds the endpoint name.
    OtherAccount,
    /// The server pid could not be read.
    NoServerPid,
    /// The server process could not be opened for a query.
    ProcessNotOpened,
    /// A token could not be read.
    TokenUnreadable,
    /// The server runs below Medium integrity.
    BelowMedium,
    /// The peer could not be identified.
    Unidentified,
    /// The pipe object is owned by someone else.
    PipeNotOwned,
    /// The pipe object's mandatory label is below Medium.
    PipeLabelBelowMedium,
    /// The pipe object carries no mandatory label.
    PipeUnlabeled,
    /// The pipe object's security could not be read.
    PipeUnreadable,
    /// Unix: the server process has exited, or its pid names another
    /// process now.
    ServerGone,
    /// Unix: the peer was identified only by a source orceld does not
    /// accept either (Linux before 6.5).
    WeakIdentity,
    /// Unix: the socket's directory is not this user's private directory.
    DirectoryNotPrivate,
    /// Unix: the socket path is a link or not a socket.
    NotASocket,
    /// Unix: the socket is owned by another account.
    SocketNotOwned,
    /// Unix: the socket grants group or other access.
    SocketNotPrivate,
}

impl IdentityRefusal {
    /// The sentence the window shows.
    pub const MESSAGE: &'static str = "orceld could not be confirmed as yours";
}

impl fmt::Display for IdentityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let why = match self {
            Self::OtherAccount => "the endpoint is held by another account",
            Self::NoServerPid => "the server process could not be read",
            Self::ProcessNotOpened => "the server process could not be opened",
            Self::TokenUnreadable => "the server's token could not be read",
            Self::BelowMedium => "the server runs below Medium integrity",
            Self::Unidentified => "the server could not be identified",
            Self::PipeNotOwned => "the endpoint is owned by another account",
            Self::PipeLabelBelowMedium => "the endpoint is labeled below Medium integrity",
            Self::PipeUnlabeled => "the endpoint carries no integrity label",
            Self::PipeUnreadable => "the endpoint's security could not be read",
            Self::ServerGone => "the server process is gone",
            Self::WeakIdentity => "the server's process could not be bound to its identity",
            Self::DirectoryNotPrivate => "the endpoint's directory is not private to this user",
            Self::NotASocket => "the endpoint is not a socket",
            Self::SocketNotOwned => "the endpoint is owned by another account",
            Self::SocketNotPrivate => "the endpoint is open to other accounts",
        };
        write!(f, "{}: {why}", Self::MESSAGE)
    }
}

/// The decision. Only a server that runs as this user, at Medium integrity
/// or above (Windows), or as this uid, read from a source bound to its live
/// process (Unix), is accepted; every failure to read refuses.
pub fn decide(facts: &ServerFacts) -> Result<(), IdentityRefusal> {
    match *facts {
        ServerFacts::PipeRefusesThisAccount => Err(IdentityRefusal::OtherAccount),
        ServerFacts::NoServerPid => Err(IdentityRefusal::NoServerPid),
        ServerFacts::ProcessNotOpened(_) => Err(IdentityRefusal::ProcessNotOpened),
        ServerFacts::TokenUnreadable(_) => Err(IdentityRefusal::TokenUnreadable),
        ServerFacts::Token {
            same_user: false, ..
        } => Err(IdentityRefusal::OtherAccount),
        ServerFacts::Token {
            same_user: true,
            integrity,
        } => match integrity {
            Some(level) if level >= MEDIUM_INTEGRITY => Ok(()),
            Some(_) => Err(IdentityRefusal::BelowMedium),
            None => Err(IdentityRefusal::TokenUnreadable),
        },
        ServerFacts::Peer { uid, ours, .. } if uid != ours => Err(IdentityRefusal::OtherAccount),
        ServerFacts::Peer { source, .. } if ACCEPTED_PEER_SOURCES.contains(&source) => Ok(()),
        ServerFacts::Peer { .. } => Err(IdentityRefusal::WeakIdentity),
        ServerFacts::PeerGone => Err(IdentityRefusal::ServerGone),
        ServerFacts::Unreadable => Err(IdentityRefusal::Unidentified),
    }
}

/// The Unix endpoint decision, before connecting: a real directory this
/// user owns, without group or other access, that passes XP-01's rules,
/// holding a socket (not a link) this user owns without group or other
/// access.
pub fn decide_endpoint(facts: &EndpointFacts) -> Result<(), IdentityRefusal> {
    let EndpointFacts {
        dir,
        dir_rules,
        socket,
        ours,
    } = *facts;
    decide_directory(dir, dir_rules, ours)?;
    if socket.kind != EntryKind::Socket {
        return Err(IdentityRefusal::NotASocket);
    }
    if socket.owner != ours {
        return Err(IdentityRefusal::SocketNotOwned);
    }
    if socket.mode & 0o077 != 0 {
        return Err(IdentityRefusal::SocketNotPrivate);
    }
    Ok(())
}

/// The directory half of [`decide_endpoint`], decided first, so a socket
/// that is missing from a directory that is not private is refused rather
/// than reported as orceld not running.
pub fn decide_directory(
    dir: EntryFacts,
    dir_rules: bool,
    ours: u32,
) -> Result<(), IdentityRefusal> {
    if dir.kind == EntryKind::Directory && dir.owner == ours && dir.mode & 0o077 == 0 && dir_rules {
        Ok(())
    } else {
        Err(IdentityRefusal::DirectoryNotPrivate)
    }
}

/// The pipe object decision: owned by this user (or by Administrators when
/// this client is elevated), labeled Medium or above. Every failure to read
/// refuses.
pub fn decide_object(facts: &ObjectFacts) -> Result<(), IdentityRefusal> {
    match *facts {
        ObjectFacts::Unreadable(_) => Err(IdentityRefusal::PipeUnreadable),
        ObjectFacts::Read {
            owner,
            client_elevated,
            label,
        } => match (owner, client_elevated) {
            (PipeOwner::ThisUser, _) | (PipeOwner::Administrators, true) => match label {
                Some(level) if level >= MEDIUM_INTEGRITY => Ok(()),
                Some(_) => Err(IdentityRefusal::PipeLabelBelowMedium),
                None => Err(IdentityRefusal::PipeUnlabeled),
            },
            _ => Err(IdentityRefusal::PipeNotOwned),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_pipe_this_user_owns_labeled_medium_or_above_is_accepted() {
        let read = |ours: bool, label| ObjectFacts::Read {
            owner: if ours {
                PipeOwner::ThisUser
            } else {
                PipeOwner::Other
            },
            client_elevated: false,
            label,
        };
        for level in [0x2000, 0x3000, 0x4000] {
            assert_eq!(decide_object(&read(true, Some(level))), Ok(()));
        }
        for level in [0x0000, 0x1000, 0x1fff] {
            assert_eq!(
                decide_object(&read(true, Some(level))),
                Err(IdentityRefusal::PipeLabelBelowMedium)
            );
        }
        assert_eq!(
            decide_object(&read(true, None)),
            Err(IdentityRefusal::PipeUnlabeled)
        );
        assert_eq!(
            decide_object(&read(false, Some(0x2000))),
            Err(IdentityRefusal::PipeNotOwned)
        );
        assert_eq!(
            decide_object(&ObjectFacts::Unreadable(5)),
            Err(IdentityRefusal::PipeUnreadable)
        );
    }

    #[test]
    fn an_administrators_owned_pipe_is_accepted_only_by_an_elevated_client() {
        let admins = |client_elevated, owner| ObjectFacts::Read {
            owner,
            client_elevated,
            label: Some(0x2000),
        };
        assert_eq!(
            decide_object(&admins(false, PipeOwner::Administrators)),
            Err(IdentityRefusal::PipeNotOwned)
        );
        assert_eq!(
            decide_object(&admins(true, PipeOwner::Administrators)),
            Ok(())
        );
        // Elevation never admits any other owner.
        assert_eq!(
            decide_object(&admins(true, PipeOwner::Other)),
            Err(IdentityRefusal::PipeNotOwned)
        );
        assert_eq!(decide_object(&admins(false, PipeOwner::ThisUser)), Ok(()));
        // An elevated client still needs the label.
        assert_eq!(
            decide_object(&ObjectFacts::Read {
                owner: PipeOwner::Administrators,
                client_elevated: true,
                label: Some(0x1000),
            }),
            Err(IdentityRefusal::PipeLabelBelowMedium)
        );
    }

    #[test]
    fn only_this_user_at_medium_or_above_is_accepted() {
        let token = |same_user, integrity| ServerFacts::Token {
            same_user,
            integrity,
        };
        // Medium, Medium Plus, High, System.
        for level in [0x2000, 0x2100, 0x3000, 0x4000] {
            assert_eq!(decide(&token(true, Some(level))), Ok(()));
        }
        // Untrusted, Low, just below Medium.
        for level in [0x0000, 0x1000, 0x1fff] {
            assert_eq!(
                decide(&token(true, Some(level))),
                Err(IdentityRefusal::BelowMedium)
            );
        }
        assert_eq!(
            decide(&token(false, Some(0x3000))),
            Err(IdentityRefusal::OtherAccount)
        );
        assert_eq!(
            decide(&token(true, None)),
            Err(IdentityRefusal::TokenUnreadable)
        );
    }

    #[test]
    fn every_failure_to_read_refuses() {
        assert_eq!(
            decide(&ServerFacts::PipeRefusesThisAccount),
            Err(IdentityRefusal::OtherAccount)
        );
        assert_eq!(
            decide(&ServerFacts::NoServerPid),
            Err(IdentityRefusal::NoServerPid)
        );
        assert_eq!(
            decide(&ServerFacts::ProcessNotOpened(5)),
            Err(IdentityRefusal::ProcessNotOpened)
        );
        assert_eq!(
            decide(&ServerFacts::TokenUnreadable(5)),
            Err(IdentityRefusal::TokenUnreadable)
        );
        assert_eq!(
            decide(&ServerFacts::Unreadable),
            Err(IdentityRefusal::Unidentified)
        );
    }

    fn peer(uid: u32, source: &'static str) -> ServerFacts {
        ServerFacts::Peer {
            uid,
            ours: 1000,
            source,
        }
    }

    #[test]
    fn unix_peer_must_be_this_uid() {
        for source in ACCEPTED_PEER_SOURCES {
            assert_eq!(decide(&peer(1000, source)), Ok(()));
            // root and any other account are refused alike.
            for other in [0, 999, 1001, u32::MAX] {
                assert_eq!(
                    decide(&peer(other, source)),
                    Err(IdentityRefusal::OtherAccount)
                );
            }
        }
    }

    #[test]
    fn unix_peer_must_come_from_a_source_orceld_accepts() {
        // The pre-6.5 Linux read can race with pid reuse; orceld refuses it
        // for its clients, and the client refuses it for its server.
        for source in [
            "linux-so-peercred",
            "",
            "test",
            "LINUX-SO-PEERPIDFD",
            "macos-getpeereid",
        ] {
            assert_eq!(
                decide(&peer(1000, source)),
                Err(IdentityRefusal::WeakIdentity)
            );
        }
        // Another account is reported as such whatever the source.
        assert_eq!(
            decide(&peer(0, "linux-so-peercred")),
            Err(IdentityRefusal::OtherAccount)
        );
    }

    #[test]
    fn a_unix_server_that_is_gone_or_unreadable_is_refused() {
        assert_eq!(
            decide(&ServerFacts::PeerGone),
            Err(IdentityRefusal::ServerGone)
        );
        assert_eq!(
            decide(&ServerFacts::Unreadable),
            Err(IdentityRefusal::Unidentified)
        );
    }

    const OURS: u32 = 501;

    fn entry(kind: EntryKind, owner: u32, mode: u32) -> EntryFacts {
        EntryFacts { kind, owner, mode }
    }

    /// What orceld creates: a 0700 directory and a 0600 socket of this user.
    fn orcelds() -> EndpointFacts {
        EndpointFacts {
            dir: entry(EntryKind::Directory, OURS, 0o700),
            dir_rules: true,
            socket: entry(EntryKind::Socket, OURS, 0o600),
            ours: OURS,
        }
    }

    fn changed(change: &dyn Fn(&mut EndpointFacts)) -> Result<(), IdentityRefusal> {
        let mut facts = orcelds();
        change(&mut facts);
        decide_endpoint(&facts)
    }

    #[test]
    fn the_endpoint_orceld_creates_is_accepted() {
        assert_eq!(decide_endpoint(&orcelds()), Ok(()));
        // Fewer owner bits still grant nobody else anything.
        for (dir, socket) in [(0o500, 0o600), (0o700, 0o700), (0o700, 0o400)] {
            assert_eq!(
                changed(&|facts| {
                    facts.dir.mode = dir;
                    facts.socket.mode = socket;
                }),
                Ok(()),
                "{dir:o} {socket:o}"
            );
        }
    }

    #[test]
    fn a_directory_that_is_not_this_users_private_one_is_refused() {
        let refused = |change: &dyn Fn(&mut EndpointFacts)| {
            assert_eq!(changed(change), Err(IdentityRefusal::DirectoryNotPrivate));
        };
        for mode in [0o710, 0o750, 0o755, 0o701, 0o777, 0o1777, 0o720, 0o702] {
            refused(&|facts| facts.dir.mode = mode);
        }
        for owner in [0, OURS + 1] {
            refused(&|facts| facts.dir.owner = owner);
        }
        for kind in [EntryKind::Symlink, EntryKind::Socket, EntryKind::Other] {
            refused(&|facts| facts.dir.kind = kind);
        }
        refused(&|facts| facts.dir_rules = false);
        // The directory is decided first.
        refused(&|facts| {
            facts.dir.mode = 0o755;
            facts.socket.owner = 0;
        });
    }

    #[test]
    fn a_socket_that_is_not_this_users_private_one_is_refused() {
        for kind in [EntryKind::Symlink, EntryKind::Directory, EntryKind::Other] {
            assert_eq!(
                changed(&|facts| facts.socket.kind = kind),
                Err(IdentityRefusal::NotASocket)
            );
        }
        for owner in [0, OURS + 1, u32::MAX] {
            assert_eq!(
                changed(&|facts| facts.socket.owner = owner),
                Err(IdentityRefusal::SocketNotOwned)
            );
        }
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o777, 0o610, 0o601] {
            assert_eq!(
                changed(&|facts| facts.socket.mode = mode),
                Err(IdentityRefusal::SocketNotPrivate),
                "{mode:o}"
            );
        }
        // Another account's socket is refused as such, whatever its mode.
        assert_eq!(
            changed(&|facts| {
                facts.socket.owner = 0;
                facts.socket.mode = 0o666;
            }),
            Err(IdentityRefusal::SocketNotOwned)
        );
    }

    #[test]
    fn the_refusal_says_orceld_could_not_be_confirmed_as_yours() {
        assert!(IdentityRefusal::BelowMedium
            .to_string()
            .starts_with("orceld could not be confirmed as yours"));
    }
}
