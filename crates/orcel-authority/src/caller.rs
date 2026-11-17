//! What the service observed about a pipe client, and the role it earns.
//!
//! Every fact here comes from the operating system, not from the client:
//! the token user SID, logon session (authentication LUID) and terminal
//! services session from the client's token (read while impersonating it
//! at the level the client allowed), the process id from
//! `GetNamedPipeClientProcessId`, the image path through a process handle
//! opened while impersonating, and whether the token carries
//! `NT AUTHORITY\INTERACTIVE`.
//!
//! Roles:
//!
//! - [`CallerRole::Orceld`]: the image is one of the configured trusted
//!   orceld images (exact path, compared case-insensitively). Only orceld
//!   may `Authorize`. A same-user process can still start that image or
//!   inject into it (C-27 e), so this is defense in depth and audit, not
//!   a boundary; the record says what was observed.
//! - [`CallerRole::Interactive`]: any other process of an interactive
//!   logon in the active console session. It may record a grant or
//!   enrollment intent (the owner's CLI); issuance still needs the
//!   service-observed unlock, the service-rendered confirmation and the
//!   Windows Hello signature, none of which a process can supply.
//! - [`CallerRole::Other`]: everything else (a non-interactive logon, a
//!   session other than the active console, an unreadable token). It may
//!   ask `Status` only.
//!
//! Deferred to a later slice (recorded in SG132_SLICE1.md): requiring an
//! Authenticode signature on the orceld image. Development builds are
//! unsigned, so the signature state is recorded in the audit but not
//! enforced.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallerFacts {
    pub pid: u32,
    /// The process's creation time (FILETIME) read with its image, so a
    /// reused PID is a different caller; 0 when it could not be read.
    pub process_generation: u64,
    /// Win32 image path, or empty when it could not be read.
    pub image: String,
    pub user_sid: String,
    pub logon_session_id: u64,
    pub ts_session_id: u32,
    /// The token carries `S-1-5-4` (INTERACTIVE).
    pub interactive: bool,
    /// The terminal-services session is the active console session.
    pub console_session: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerRole {
    Orceld,
    Interactive,
    Other,
}

impl CallerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Orceld => "orceld",
            Self::Interactive => "interactive",
            Self::Other => "other",
        }
    }
}

/// Which images count as orceld.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientPolicy {
    /// Exact paths of trusted orceld images.
    pub trusted_orceld_images: Vec<PathBuf>,
}

fn same_path(left: &str, right: &Path) -> bool {
    let normalize = |text: &str| {
        let text = text.strip_prefix(r"\\?\").unwrap_or(text);
        text.replace('/', "\\").to_lowercase()
    };
    !left.is_empty() && normalize(left) == normalize(&right.to_string_lossy())
}

impl ClientPolicy {
    pub fn classify(&self, facts: &CallerFacts) -> CallerRole {
        if facts.user_sid.is_empty() || facts.logon_session_id == 0 {
            return CallerRole::Other;
        }
        if self
            .trusted_orceld_images
            .iter()
            .any(|image| same_path(&facts.image, image))
        {
            return CallerRole::Orceld;
        }
        if facts.interactive && facts.console_session {
            CallerRole::Interactive
        } else {
            CallerRole::Other
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(image: &str, interactive: bool, console: bool) -> CallerFacts {
        CallerFacts {
            pid: 42,
            process_generation: 7,
            image: image.to_owned(),
            user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            logon_session_id: 7,
            ts_session_id: 1,
            interactive,
            console_session: console,
        }
    }

    #[test]
    fn roles_follow_observed_facts() {
        let policy = ClientPolicy {
            trusted_orceld_images: vec![PathBuf::from(r"C:\Orcel\bin\orceld.exe")],
        };
        assert_eq!(
            policy.classify(&facts(r"c:\orcel\BIN\orceld.exe", true, true)),
            CallerRole::Orceld
        );
        assert_eq!(
            policy.classify(&facts(r"\\?\C:\Orcel\bin\orceld.exe", true, true)),
            CallerRole::Orceld
        );
        assert_eq!(
            policy.classify(&facts(r"C:\Temp\orceld.exe", true, true)),
            CallerRole::Interactive
        );
        assert_eq!(
            policy.classify(&facts(r"C:\Temp\x.exe", true, false)),
            CallerRole::Other
        );
        assert_eq!(
            policy.classify(&facts(r"C:\Temp\x.exe", false, true)),
            CallerRole::Other
        );
        assert_eq!(
            policy.classify(&facts("", true, true)),
            CallerRole::Interactive
        );
        let mut unknown = facts(r"C:\Orcel\bin\orceld.exe", true, true);
        unknown.user_sid.clear();
        assert_eq!(policy.classify(&unknown), CallerRole::Other);
    }
}
