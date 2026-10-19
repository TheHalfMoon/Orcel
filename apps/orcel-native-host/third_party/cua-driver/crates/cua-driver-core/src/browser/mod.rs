//! Platform-agnostic browser-tool v1 core.
//!
//! Typed browser inspection, preparation, navigation, input, dialog, upload,
//! and download tools over an exact-or-refused binding model:
//!
//! - The native entrypoint is `pid + window_id`. Browser target ids,
//!   tab ids, and page refs (`p<snapshot>:<index>`) are opaque,
//!   session-scoped capabilities minted by core.
//! - Mutation is permitted only for **exact** bindings (unique
//!   bounds-correlated, optionally title-tie-broken). Heuristic
//!   bindings are read-only; everything else is a structured refusal
//!   with a stable code (see [`refusal::BrowserRefusalCode`]).
//! - Core owns schemas, semantics, CDP target handling, the target/ref
//!   store, lifecycle cleanup and correlation. Platform adapters
//!   implement [`platform::BrowserPlatform`] for process identity,
//!   endpoint ownership, native window metadata, classification and
//!   explicit setup — without depending on core internals.
//!
//! Wiring (per platform crate):
//! ```ignore
//! let engine = BrowserEngine::new(Arc::new(MyPlatformAdapter::new()));
//! register_browser_tools(&engine, &mut registry);
//! ```
//!
//! The legacy `crate::page` contract remains separate because its first-page
//! and URL-hint semantics predate exact browser capabilities. Its CDP paths
//! nevertheless reuse the pooled, loopback-validated WebSocket transport in
//! [`cdp_ws`] so the repository has one event-capable demultiplexer.
//!
//! v2 DOM-ref slice: snapshots compose shadow DOM (piercing, minus
//! user-agent roots), same-process iframes (via `contentDocument`),
//! and — only when the capability is proven live — OOPIF child targets
//! auto-attached beneath the bound tab's own session. Every ref
//! carries its frame's document identity (frame id + loader id), which
//! is re-proven before any mutation; frames whose identity or
//! capability cannot be proven are omitted or refused, never guessed.

#[cfg(not(feature = "orcel-minimal"))]
mod adapter_support;
#[cfg(not(feature = "orcel-minimal"))]
pub mod binding;
#[cfg(not(feature = "orcel-minimal"))]
pub mod cdp_ws;
pub mod download;
#[cfg(not(feature = "orcel-minimal"))]
pub mod engine;
#[cfg(not(feature = "orcel-minimal"))]
mod grant;
#[cfg(not(feature = "orcel-minimal"))]
mod keyed_gates;
#[cfg(test)]
#[cfg(not(feature = "orcel-minimal"))]
pub(crate) mod mock_cdp;
#[cfg(not(feature = "orcel-minimal"))]
mod mutation;
#[cfg(not(feature = "orcel-minimal"))]
pub mod platform;
#[cfg(not(feature = "orcel-minimal"))]
pub mod pointer;
#[cfg(not(feature = "orcel-minimal"))]
mod prepare;
#[cfg(not(feature = "orcel-minimal"))]
mod reconnect;
#[cfg(not(feature = "orcel-minimal"))]
pub mod refusal;
#[cfg(not(feature = "orcel-minimal"))]
mod semantic;
#[cfg(not(feature = "orcel-minimal"))]
mod setup_descriptor;
#[cfg(not(feature = "orcel-minimal"))]
pub mod store;
#[cfg(not(feature = "orcel-minimal"))]
pub mod tools;
pub mod types;
#[cfg(test)]
#[cfg(not(feature = "orcel-minimal"))]
mod v2_tests;

#[cfg(not(feature = "orcel-minimal"))]
pub use adapter_support::{
    is_firefox, loopback_websocket_port, parse_devtools_active_port, BrowserCursorTracker,
};
#[cfg(not(feature = "orcel-minimal"))]
pub use engine::BrowserEngine;
#[cfg(not(feature = "orcel-minimal"))]
pub use platform::{
    BrowserConsentOutcome, BrowserConsentRequest, BrowserPlatform, BrowserVisualAction,
    BrowserVisualActionKind, ExistingProfileSetupOutcome, ExistingProfileSetupRequest,
    IsolatedBrowserProcess, PrepareAction, PrepareAttachment, PrepareAttachmentKind,
    PrepareOutcome, PrepareProfile, PrepareProfileMode, PrepareRequest, PrepareSideEffects,
    PrepareStrategy,
};
#[cfg(not(feature = "orcel-minimal"))]
pub use refusal::{BrowserRefusal, BrowserRefusalCode};
#[cfg(not(feature = "orcel-minimal"))]
pub use setup_descriptor::{
    existing_profile_setup_descriptor, BrowserSetupDescriptor, EXISTING_PROFILE_SETUP_READY_TIMEOUT,
};
#[cfg(not(feature = "orcel-minimal"))]
pub use tools::register_browser_tools;
pub use types::{
    BindingQuality, BrowserClassification, BrowserEngineFamily, BrowserProduct,
    EndpointOwnershipMethod, EndpointOwnershipProof, NativeOwnershipMethod, NativeOwnershipProof,
    NativeWindowInfo, OwnedEndpoint, ProcessFingerprint, Rect,
};

#[cfg(not(feature = "orcel-minimal"))]
pub(crate) fn session_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "description": format!(
            "{} Browser targets, tabs, and refs belong to the resolved lifecycle session.",
            cua_driver_contract::MULTI_CALL_SESSION_DESCRIPTION
        )
    })
}

#[cfg(not(feature = "orcel-minimal"))]
pub(crate) fn required_session_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "string",
        "description": "For multi-call work, prefer a short public session label and repeat it on every call that accepts it. This tool requires the label that owns its browser target, tab, and refs."
    })
}

#[cfg(test)]
#[cfg(not(feature = "orcel-minimal"))]
mod tests {
    use super::*;

    #[test]
    fn browser_session_schema_keeps_naming_and_capability_guidance_together() {
        let schema = session_schema();
        let description = schema["description"]
            .as_str()
            .expect("browser session description");
        assert!(description.contains("prefer a short public session label"));
        assert!(description.contains("repeat it on every call that accepts it"));
        assert!(description.contains("Browser targets, tabs, and refs"));
    }

    #[test]
    fn required_browser_session_schema_does_not_suggest_omission() {
        let schema = required_session_schema();
        let description = schema["description"]
            .as_str()
            .expect("required browser session description");
        assert!(description.contains("prefer a short public session label"));
        assert!(description.contains("repeat it on every call that accepts it"));
        assert!(description.contains("requires the label"));
        assert!(!description.contains("Omit it"));
    }
}
