//! Capability discovery (spec section 4.6).
//!
//! Every call that hits a non-`available` entry fails with the matching
//! `FailureCode`, never a degraded success. `unsupported` is explicit: it is
//! never a silent fallback.

use serde::{Deserialize, Serialize};

use crate::identity::Device;
use crate::{Contract, FailureCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum BuildKind {
    Release,
    LiveBrowserDev,
    LiveBrowserTest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct CapabilityReport {
    /// `"orcel.capability-report/1"`.
    pub contract: String,
    pub device: Device,
    pub build: BuildKind,
    pub entries: Vec<CapabilityEntry>,
}

impl Contract for CapabilityReport {
    const CONTRACT: &'static str = "orcel.capability-report/1";
}

/// How a component that backs a capability is isolated from `orceld`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(rename_all = "snake_case")]
pub enum ComponentIsolation {
    /// Orcel's own code, linked into an Orcel process.
    InProcess,
    /// A separate supervised child over the sidecar protocol (section 4.9)
    /// or the contained JSON-over-stdio protocol (section 4.17), never
    /// linked into an Orcel process. Chosen for architecture reasons:
    /// donor runtimes and copy-first components run contained, with no
    /// ambient network, their own resource limits and a crash boundary
    /// away from `orceld` (C-09 to C-13), and a separately built component
    /// keeps its own workspace and release packaging (C-17).
    Sidecar,
}

/// The component that backs a capability entry, reported so the user can
/// see which code and licence a capability runs on. Informational: it never
/// decides policy, admission or status (C-10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct ComponentRef {
    /// For example `"orcel-fetch"`.
    pub name: String,
    /// SPDX licence expression of the component itself.
    pub license: String,
    pub isolation: ComponentIsolation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
pub struct CapabilityEntry {
    /// `capability/operation`, for example `"web/scrape"`.
    pub capability: String,
    /// `"fetch"`, `"chromium"` or `"obscura"` where engines differ.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(flatten)]
    pub status: CapabilityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component: Option<ComponentRef>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(test, derive(schemars::JsonSchema))]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    /// Could work here but is not ready (no engine found, disabled).
    Unavailable {
        reason: String,
    },
    /// Not implemented on this OS or build; never a silent fallback.
    Unsupported {
        reason: String,
    },
    /// Refused by policy, for example `"FD-UP-2 stealth"`, `"cloud-only"`.
    Blocked {
        policy: String,
    },
    /// An opt-in feature this client has not been granted, for example
    /// `"web.privacy.sensitive:geolocation_override"`.
    PermissionRequired {
        permission: String,
    },
}

impl CapabilityStatus {
    /// The failure code a call hitting this entry fails with, or `None` for
    /// `available`.
    pub const fn failure_code(&self) -> Option<FailureCode> {
        match self {
            Self::Available => None,
            Self::Unavailable { .. } => Some(FailureCode::ProviderUnavailable),
            Self::Unsupported { .. } => Some(FailureCode::Unsupported),
            Self::Blocked { .. } => Some(FailureCode::PolicyBlocked),
            Self::PermissionRequired { .. } => Some(FailureCode::PermissionRequired),
        }
    }
}
