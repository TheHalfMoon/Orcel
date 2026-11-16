//! Tool registry entry (spec section 4.5).
//!
//! The TypeScript catalog in `apps/orcel-mcp/src/tool_contract.ts` stays
//! authoritative for MCP; this is its Rust mirror. Nothing here registers a
//! tool.

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::identity::OsFamily;
use crate::lease::{ApprovalClass, ExecutorClass};
use crate::Contract;

/// Effect classes, spelled as in the TypeScript catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Read,
    Preview,
    Write,
    Destructive,
    Execute,
    Network,
    DesktopObserve,
    DesktopCapture,
    DesktopControl,
    Clipboard,
}

/// Remote exposure, spelled as in the TypeScript catalog: the string
/// `"local_only"` or an array of OAuth scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteExposure {
    LocalOnly,
    Scopes(Vec<String>),
}

const LOCAL_ONLY: &str = "local_only";

impl Serialize for RemoteExposure {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::LocalOnly => serializer.serialize_str(LOCAL_ONLY),
            Self::Scopes(scopes) => scopes.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for RemoteExposure {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExposureVisitor;

        impl<'de> Visitor<'de> for ExposureVisitor {
            type Value = RemoteExposure;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("\"local_only\" or an array of scope strings")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value == LOCAL_ONLY {
                    Ok(RemoteExposure::LocalOnly)
                } else {
                    Err(E::invalid_value(de::Unexpected::Str(value), &self))
                }
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut scopes = Vec::new();
                while let Some(scope) = seq.next_element::<String>()? {
                    scopes.push(scope);
                }
                Ok(RemoteExposure::Scopes(scopes))
            }
        }

        deserializer.deserialize_any(ExposureVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolEntry {
    /// `"orcel.tool/1"`.
    pub contract: String,
    /// MCP tool name, for example `"web_scrape"`.
    pub name: String,
    /// For example `"web"`.
    pub capability: String,
    /// For example `"scrape"`.
    pub operation: String,
    pub effect: EffectClass,
    /// Required in every mode (C-04).
    pub approval: ApprovalClass,
    /// Full Control executor class that additionally gates the call. It
    /// never replaces the approval.
    #[serde(default)]
    pub lease_gate: Option<ExecutorClass>,
    pub remote: RemoteExposure,
    /// Discovery only.
    pub profiles: Vec<String>,
    /// Where an implementation exists.
    pub platforms: Vec<OsFamily>,
    /// Path of the input JSON Schema.
    pub input_schema: String,
    pub output_bound: String,
    /// Grain id that introduced the entry.
    pub since: String,
}

impl Contract for ToolEntry {
    const CONTRACT: &'static str = "orcel.tool/1";
}
