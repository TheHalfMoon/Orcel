//! Principal, device and per-OS identity binding (spec sections 4.1, 4.2).
//!
//! Wire types only. Nothing here reads an OS identity; the per-OS readers
//! live in `orcel-platform` and return the binding from the running
//! process's own kernel credentials.

use serde::{Deserialize, Serialize};

use crate::Contract;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// The only kind that can issue a lease (C-03).
    LocalUser,
    McpClient,
    RestClient,
    RemotePrincipal,
    /// Recorded for attribution and job ownership, never as authority.
    AgentRuntime,
    /// Recorded for attribution, never as authority.
    Sidecar,
}

impl PrincipalKind {
    /// Whether a principal of this kind may appear as the issuing principal
    /// of a lease (C-03). Only `LocalUser` may.
    pub const fn may_issue_lease(self) -> bool {
        matches!(self, Self::LocalUser)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    /// `"orcel.principal/1"`.
    pub contract: String,
    pub kind: PrincipalKind,
    /// Opaque. `LocalUser`: SHA-256 of the OS identity binding;
    /// `RestClient`: the token id.
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_profile_id: Option<String>,
    /// Bounded; escaped by `prompt_display` before any prompt shows it.
    pub display: String,
}

impl Contract for Principal {
    const CONTRACT: &'static str = "orcel.principal/1";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsFamily {
    Windows,
    Macos,
    Linux,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    #[serde(rename = "x86_64")]
    X86_64,
    #[serde(rename = "aarch64")]
    Aarch64,
}

/// Outbound description of this device (capability reports, sessions). It
/// may gain optional fields within its major, so unknown fields are not
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// `"orcel.device/1"`.
    pub contract: String,
    /// `derive_device_id(authority key)` in `full_control_store.rs`.
    pub device_id: String,
    pub os: OsFamily,
    /// For example `"10.0.26100"`, `"15.6"`, `"Ubuntu 24.04 6.8.0"`.
    pub os_build: String,
    pub arch: Arch,
    /// SG-000055 device epoch; remote leases bind it.
    pub device_epoch: u64,
}

impl Contract for Device {
    const CONTRACT: &'static str = "orcel.device/1";
}

/// The OS identity a lease binds (spec section 4.2).
///
/// Wave 1 implements `Windows` only, and `orcel-full-control-lease/1`
/// leases keep their existing `windows_user_sid` and `logon_session_id`
/// fields byte for byte. This enum is the shape `orcel-full-control-lease/2`
/// will carry in Wave 2; until a reader exists for an OS, Full User is
/// refused there with `LEASE_UNSUPPORTED_PLATFORM`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "os", rename_all = "snake_case", deny_unknown_fields)]
pub enum OsIdentityBinding {
    /// `TokenUser` plus `TokenStatistics.AuthenticationId`.
    Windows {
        user_sid: String,
        logon_session_luid: u64,
    },
    /// `getuid` plus `getaudit_addr` `ai_asid` (Wave 2).
    Macos {
        uid: u32,
        audit_session_id: u32,
        console_user: bool,
    },
    /// `sd_pid_get_session` / logind (Wave 2).
    Linux {
        uid: u32,
        login_session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        seat: Option<String>,
    },
}

impl OsIdentityBinding {
    pub const fn os(&self) -> OsFamily {
        match self {
            Self::Windows { .. } => OsFamily::Windows,
            Self::Macos { .. } => OsFamily::Macos,
            Self::Linux { .. } => OsFamily::Linux,
        }
    }
}
