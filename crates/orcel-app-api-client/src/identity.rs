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
//! The platform code only gathers [`ServerFacts`]; [`decide`] is the whole
//! decision, so it is unit-tested on every OS.

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
    /// Unix: the socket peer's uid, against this process's effective uid.
    PeerUid { peer: u32, ours: u32 },
    /// The peer's identity could not be read on this OS.
    Unreadable,
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
        };
        write!(f, "{}: {why}", Self::MESSAGE)
    }
}

/// The decision. Only a server that runs as this user, at Medium integrity
/// or above (Windows), or as this uid (Unix), is accepted; every failure to
/// read refuses.
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
        ServerFacts::PeerUid { peer, ours } if peer == ours => Ok(()),
        ServerFacts::PeerUid { .. } => Err(IdentityRefusal::OtherAccount),
        ServerFacts::Unreadable => Err(IdentityRefusal::Unidentified),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn unix_peer_must_be_this_uid() {
        assert_eq!(
            decide(&ServerFacts::PeerUid {
                peer: 1000,
                ours: 1000
            }),
            Ok(())
        );
        assert_eq!(
            decide(&ServerFacts::PeerUid {
                peer: 0,
                ours: 1000
            }),
            Err(IdentityRefusal::OtherAccount)
        );
    }

    #[test]
    fn the_refusal_says_orceld_could_not_be_confirmed_as_yours() {
        assert!(IdentityRefusal::BelowMedium
            .to_string()
            .starts_with("orceld could not be confirmed as yours"));
    }
}
