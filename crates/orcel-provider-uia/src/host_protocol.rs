// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// XP-04 private computer host protocol generations. The adapter offers
// `orcel-computer-host/2` first and falls back to `/1` only when the host
// refuses `/2` with `invalid_request`, and only on Windows: the macOS and
// Linux host (`orcel-native-host`, XP-06) has no `/1` history, and `/1` has no
// window kind to name its windows with. The capability table a `/2` host
// returns is advisory: it can only make the adapter skip a call that cannot
// work. It never grants anything; the kernel registry still enforces every
// binding and approval. Specification:
// docs/orcel/implementation-readiness/protocol/ORCEL_COMPUTER_HOST_2.md

use crate::UiaError;
use orcel_contracts::FailureCode;
use serde::Deserialize;
use std::collections::BTreeMap;

pub(crate) const PROTOCOL_V1: &str = "orcel-computer-host/1";
pub(crate) const PROTOCOL_V2: &str = "orcel-computer-host/2";
/// The Windows host (`apps/orcel-computer-host`).
pub(crate) const WINDOWS_HOST_IDENTITY: &str = "orcel-windows-computer-host";
/// The macOS and Linux host (`apps/orcel-native-host`, XP-06).
pub(crate) const NATIVE_HOST_IDENTITY: &str = "orcel-native-host";

/// Upper bound on capability entries accepted from one `/2` hello.
const MAX_CAPABILITY_ENTRIES: usize = 64;
/// Upper bound on one capability reason accepted from a host.
const MAX_REASON_BYTES: usize = 128;

/// The exact `/1` operation surface. A `/1` host has no capability table,
/// so these operations keep their historical availability.
pub(crate) const V1_OPERATIONS: [&str; 16] = [
    "hello",
    "ping",
    "list_windows",
    "observe_window",
    "capture_window",
    "cursor_position",
    "semantic_action",
    "window_action",
    "input_move",
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
    "input_hotkey",
    "shutdown",
];

/// The operations the kernel accepts from the macOS and Linux host (XP-06).
/// Every other operation is unavailable there until XP-11 and XP-12 qualify
/// semantic actions, capture and input, even if a host advertises it.
pub(crate) const NATIVE_OBSERVATION_OPERATIONS: [&str; 6] = [
    "hello",
    "ping",
    "shutdown",
    "list_windows",
    "observe_window",
    "cursor_position",
];

const PLATFORMS: [&str; 3] = ["windows", "macos", "linux"];
const BACKENDS: [&str; 4] = ["uia", "ax", "atspi-x11", "atspi-wayland"];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum ProtocolGeneration {
    #[default]
    V1,
    V2,
}

impl ProtocolGeneration {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::V1 => PROTOCOL_V1,
            Self::V2 => PROTOCOL_V2,
        }
    }
}

/// Closed `support` values. Any other value is read as `Unavailable`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CapabilitySupport {
    Delivered,
    ForegroundOnly,
    Refused,
    Unavailable,
}

impl CapabilitySupport {
    fn parse(value: &str) -> Self {
        match value {
            "delivered" => Self::Delivered,
            "foreground_only" => Self::ForegroundOnly,
            "refused" => Self::Refused,
            _ => Self::Unavailable,
        }
    }

    fn is_usable(self) -> bool {
        matches!(self, Self::Delivered | Self::ForegroundOnly)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireError {
    code: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WireCapability {
    support: String,
    #[serde(default)]
    reason: Option<String>,
}

/// One hello response frame. Fields a generation does not define are
/// ignored, so `/1` and `/2` replies decode the same way.
#[derive(Debug, Deserialize)]
pub(crate) struct HelloFrame {
    pub(crate) id: u64,
    pub(crate) ok: bool,
    pub(crate) protocol: String,
    pub(crate) host: String,
    #[serde(default)]
    platform: Option<String>,
    #[serde(default)]
    backend: Option<String>,
    #[serde(default)]
    capabilities: Option<BTreeMap<String, WireCapability>>,
    #[serde(default)]
    error: Option<WireError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostCapability {
    support: CapabilitySupport,
    reason: Option<String>,
}

/// The negotiated generation and, for `/2`, the capability table, the host
/// identity every response must echo and the window kind bound requests use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NegotiatedHost {
    generation: ProtocolGeneration,
    capabilities: BTreeMap<String, HostCapability>,
    identity: &'static str,
    window_kind: &'static str,
}

impl NegotiatedHost {
    /// A `/1` session with the Windows host.
    pub(crate) fn v1() -> Self {
        Self {
            generation: ProtocolGeneration::V1,
            capabilities: BTreeMap::new(),
            identity: WINDOWS_HOST_IDENTITY,
            window_kind: "hwnd",
        }
    }

    pub(crate) fn generation(&self) -> ProtocolGeneration {
        self.generation
    }

    /// The host identity every response must echo.
    pub(crate) fn identity(&self) -> &'static str {
        self.identity
    }

    /// The `/2` window reference kind the negotiated backend serves.
    pub(crate) fn window_kind(&self) -> &'static str {
        self.window_kind
    }

    /// Unknown or omitted capabilities are unavailable.
    pub(crate) fn support(&self, op: &str) -> CapabilitySupport {
        match self.generation {
            ProtocolGeneration::V1 if V1_OPERATIONS.contains(&op) => CapabilitySupport::Delivered,
            ProtocolGeneration::V1 => CapabilitySupport::Unavailable,
            ProtocolGeneration::V2 => self
                .capabilities
                .get(op)
                .map(|capability| capability.support)
                .unwrap_or(CapabilitySupport::Unavailable),
        }
    }

    /// Fails closed before any frame is sent for an operation the host does
    /// not deliver. This only removes calls; it never adds one.
    pub(crate) fn require(&self, op: &str) -> Result<(), UiaError> {
        if self.support(op).is_usable() {
            return Ok(());
        }
        let reason = self
            .capabilities
            .get(op)
            .and_then(|capability| capability.reason.as_deref())
            .unwrap_or("not reported");
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            format!("computer host does not deliver {op} on this machine ({reason})"),
        ))
    }
}

/// The platform tag this build expects from a `/2` host.
pub(crate) fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// The host identity a host serving `platform` must report.
pub(crate) fn expected_host_identity(platform: &str) -> &'static str {
    if platform == "windows" {
        WINDOWS_HOST_IDENTITY
    } else {
        NATIVE_HOST_IDENTITY
    }
}

/// The window kind of a backend, when the backend serves `platform`. Each
/// platform has its own closed backend set, so a host cannot claim, for
/// example, UIA on Linux.
fn window_kind(platform: &str, backend: &str) -> Option<&'static str> {
    match (platform, backend) {
        ("windows", "uia") => Some("hwnd"),
        ("macos", "ax") => Some("cgwindow"),
        ("linux", "atspi-x11") => Some("x11"),
        ("linux", "atspi-wayland") => Some("wl_toplevel"),
        _ => None,
    }
}

fn handshake_error(message: &str) -> UiaError {
    UiaError::new(FailureCode::ProviderUnavailable, message.to_owned())
}

/// Negotiates the protocol generation. `hello` performs one hello exchange
/// in the given generation. A transport failure (for example a host crash)
/// is returned at once: there is no retry.
pub(crate) fn negotiate(
    expected_platform: &str,
    mut hello: impl FnMut(&'static str) -> Result<HelloFrame, UiaError>,
) -> Result<NegotiatedHost, UiaError> {
    let identity = expected_host_identity(expected_platform);
    let reply = hello(PROTOCOL_V2)?;
    if reply.host != identity {
        return Err(handshake_error("computer host handshake identity mismatch"));
    }
    if reply.ok {
        if reply.protocol != PROTOCOL_V2 {
            return Err(handshake_error("computer host handshake identity mismatch"));
        }
        return accept_v2(expected_platform, reply);
    }
    let refused_as_invalid = reply.protocol == PROTOCOL_V1
        && reply
            .error
            .as_ref()
            .is_some_and(|error| error.code == "invalid_request");
    if !refused_as_invalid {
        return Err(handshake_error(
            "computer host refused the protocol handshake",
        ));
    }
    if expected_platform != "windows" {
        return Err(handshake_error(
            "computer host on this platform must speak orcel-computer-host/2",
        ));
    }
    let legacy = hello(PROTOCOL_V1)?;
    if !legacy.ok || legacy.protocol != PROTOCOL_V1 || legacy.host != identity {
        return Err(handshake_error("computer host handshake identity mismatch"));
    }
    Ok(NegotiatedHost::v1())
}

fn accept_v2(expected_platform: &str, reply: HelloFrame) -> Result<NegotiatedHost, UiaError> {
    let platform = reply.platform.as_deref().unwrap_or_default();
    if !PLATFORMS.contains(&platform) || platform != expected_platform {
        return Err(handshake_error(
            "computer host reported a platform this build does not serve",
        ));
    }
    let backend = reply.backend.as_deref().unwrap_or_default();
    if !BACKENDS.contains(&backend) {
        return Err(handshake_error("computer host reported an unknown backend"));
    }
    let Some(window_kind) = window_kind(platform, backend) else {
        return Err(handshake_error(
            "computer host reported a backend its platform does not serve",
        ));
    };
    let table = reply.capabilities.unwrap_or_default();
    if table.len() > MAX_CAPABILITY_ENTRIES {
        return Err(handshake_error(
            "computer host capability table exceeds the bounded size",
        ));
    }
    // Spec section 5: keys that name no operation are ignored, so an
    // advertised unknown operation stays unavailable.
    let capabilities = table
        .into_iter()
        .filter(|(op, _)| V1_OPERATIONS.contains(&op.as_str()))
        .map(|(op, wire)| {
            let reason = wire
                .reason
                .filter(|reason| reason.len() <= MAX_REASON_BYTES && reason.is_ascii());
            let mut capability = HostCapability {
                support: CapabilitySupport::parse(&wire.support),
                reason,
            };
            // XP-06 kernel cap: off Windows the host is observation only
            // until XP-11, whatever its hello claims.
            if expected_platform != "windows"
                && !NATIVE_OBSERVATION_OPERATIONS.contains(&op.as_str())
            {
                capability = HostCapability {
                    support: CapabilitySupport::Unavailable,
                    reason: Some("observation_only".to_owned()),
                };
            }
            (op, capability)
        })
        .collect();
    Ok(NegotiatedHost {
        generation: ProtocolGeneration::V2,
        capabilities,
        identity: expected_host_identity(expected_platform),
        window_kind,
    })
}

/// Maps a host refusal code onto an existing public failure code. No host
/// code creates a new public code. A `/1` session keeps the exact `/1`
/// mapping; the closed `/2` set applies only once `/2` is negotiated. Codes
/// outside the set, and the mutation outcome states `cancelled` and
/// `outcome_unknown` when they reach this path, map to `ProviderUnavailable`.
pub(crate) fn map_refusal_code(generation: ProtocolGeneration, code: &str) -> FailureCode {
    if generation == ProtocolGeneration::V1 {
        return match code {
            "invalid_request" => FailureCode::InvalidRequest,
            "capability_denied" => FailureCode::CapabilityDenied,
            "target_stale" => FailureCode::TargetStale,
            "output_limit" => FailureCode::OutputLimit,
            _ => FailureCode::ProviderUnavailable,
        };
    }
    match code {
        "invalid_request" => FailureCode::InvalidRequest,
        "capability_denied"
        | "background_unavailable"
        | "background_occluded"
        | "background_uipi_blocked"
        | "protected_surface" => FailureCode::CapabilityDenied,
        "target_stale" => FailureCode::TargetStale,
        "output_limit" => FailureCode::OutputLimit,
        "timeout" => FailureCode::ProcessTimeout,
        _ => FailureCode::ProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn frame(raw: &str) -> HelloFrame {
        serde_json::from_str(raw).unwrap()
    }

    const V2_WINDOWS_HELLO: &str = r#"{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-windows-computer-host","platform":"windows","backend":"uia","capabilities":{"hello":{"support":"delivered"},"list_windows":{"support":"delivered"},"capture_window":{"support":"delivered","delivery":"background"},"input_click":{"support":"foreground_only","delivery":"foreground"},"input_hotkey":{"support":"refused","reason":"background_unavailable"},"input_key":{"support":"sideways"}}}"#;
    const V1_REFUSES_V2: &str = r#"{"id":1,"ok":false,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","error":{"code":"invalid_request","message":"protocol generation mismatch"}}"#;
    const V1_HELLO: &str = r#"{"id":2,"ok":true,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host"}"#;

    #[test]
    fn negotiation_picks_v2_and_stores_the_capability_table() {
        let offered = RefCell::new(Vec::new());
        let host = negotiate("windows", |protocol| {
            offered.borrow_mut().push(protocol);
            Ok(frame(V2_WINDOWS_HELLO))
        })
        .unwrap();
        assert_eq!(offered.into_inner(), vec![PROTOCOL_V2]);
        assert_eq!(host.generation(), ProtocolGeneration::V2);
        assert_eq!(host.generation().as_str(), PROTOCOL_V2);
        assert_eq!(host.support("list_windows"), CapabilitySupport::Delivered);
        assert_eq!(
            host.support("input_click"),
            CapabilitySupport::ForegroundOnly
        );
        assert!(host.require("capture_window").is_ok());
        assert!(host.require("input_click").is_ok());
        let refused = host.require("input_hotkey").unwrap_err();
        assert_eq!(refused.code, FailureCode::ProviderUnavailable);
        assert!(refused.message.contains("background_unavailable"));
    }

    #[test]
    fn omitted_or_unknown_capability_is_unavailable() {
        let host = negotiate("windows", |_| Ok(frame(V2_WINDOWS_HELLO))).unwrap();
        assert_eq!(
            host.support("observe_window"),
            CapabilitySupport::Unavailable
        );
        assert_eq!(host.support("input_key"), CapabilitySupport::Unavailable);
        assert_eq!(
            host.support("launch_process"),
            CapabilitySupport::Unavailable
        );
        let error = host.require("observe_window").unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(error.message.contains("not reported"));
    }

    #[test]
    fn v1_host_that_refuses_v2_as_invalid_request_still_works() {
        let offered = RefCell::new(Vec::new());
        let host = negotiate("windows", |protocol| {
            offered.borrow_mut().push(protocol);
            Ok(frame(if protocol == PROTOCOL_V2 {
                V1_REFUSES_V2
            } else {
                V1_HELLO
            }))
        })
        .unwrap();
        assert_eq!(offered.into_inner(), vec![PROTOCOL_V2, PROTOCOL_V1]);
        assert_eq!(host.generation(), ProtocolGeneration::V1);
        for op in V1_OPERATIONS {
            assert!(host.require(op).is_ok(), "{op}");
        }
        assert!(host.require("launch_process").is_err());
    }

    #[test]
    fn other_refusals_never_fall_back_to_v1() {
        let calls = RefCell::new(0);
        let refusal = r#"{"id":1,"ok":false,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","error":{"code":"capability_denied","message":"no"}}"#;
        let error = negotiate("windows", |_| {
            *calls.borrow_mut() += 1;
            Ok(frame(refusal))
        })
        .unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert_eq!(*calls.borrow(), 1);
    }

    #[test]
    fn host_crash_during_hello_is_unavailable_without_retry() {
        let calls = RefCell::new(0);
        let error = negotiate("windows", |_| {
            *calls.borrow_mut() += 1;
            Err(UiaError::new(
                FailureCode::ProviderUnavailable,
                "computer host exited before returning a response",
            ))
        })
        .unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert_eq!(*calls.borrow(), 1);

        let calls = RefCell::new(0);
        let error = negotiate("windows", |protocol| {
            *calls.borrow_mut() += 1;
            if protocol == PROTOCOL_V2 {
                Ok(frame(V1_REFUSES_V2))
            } else {
                Err(UiaError::new(
                    FailureCode::ProviderUnavailable,
                    "computer host exited before returning a response",
                ))
            }
        })
        .unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert_eq!(*calls.borrow(), 2);
    }

    #[test]
    fn v2_hello_must_match_identity_platform_and_backend() {
        let wrong_platform = V2_WINDOWS_HELLO.replace("\"windows\"", "\"macos\"");
        assert!(negotiate("windows", |_| Ok(frame(&wrong_platform))).is_err());
        // The Windows identity with a macOS tag is not the macOS host, and
        // UIA is not a macOS backend.
        assert!(negotiate("macos", |_| Ok(frame(&wrong_platform))).is_err());
        let uia_on_macos =
            wrong_platform.replace("orcel-windows-computer-host", NATIVE_HOST_IDENTITY);
        assert!(negotiate("macos", |_| Ok(frame(&uia_on_macos))).is_err());
        let ax_on_macos = uia_on_macos.replace("\"uia\"", "\"ax\"");
        assert!(negotiate("macos", |_| Ok(frame(&ax_on_macos))).is_ok());
        let unknown_platform = V2_WINDOWS_HELLO.replace("\"windows\"", "\"plan9\"");
        assert!(negotiate("plan9", |_| Ok(frame(&unknown_platform))).is_err());
        let unknown_backend = V2_WINDOWS_HELLO.replace("\"uia\"", "\"vnc\"");
        assert!(negotiate("windows", |_| Ok(frame(&unknown_backend))).is_err());
        let wrong_host = V2_WINDOWS_HELLO.replace("orcel-windows-computer-host", "other-host");
        assert!(negotiate("windows", |_| Ok(frame(&wrong_host))).is_err());
        let v1_claiming_ok =
            V2_WINDOWS_HELLO.replace("orcel-computer-host/2", "orcel-computer-host/1");
        assert!(negotiate("windows", |_| Ok(frame(&v1_claiming_ok))).is_err());
        let missing_platform = r#"{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-windows-computer-host","backend":"uia"}"#;
        assert!(negotiate("windows", |_| Ok(frame(missing_platform))).is_err());
    }

    #[test]
    fn capability_table_and_reasons_are_bounded() {
        let entries = (0..=MAX_CAPABILITY_ENTRIES)
            .map(|index| format!("\"op{index}\":{{\"support\":\"delivered\"}}"))
            .collect::<Vec<_>>()
            .join(",");
        let oversized = format!(
            r#"{{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-windows-computer-host","platform":"windows","backend":"uia","capabilities":{{{entries}}}}}"#
        );
        assert!(negotiate("windows", |_| Ok(frame(&oversized))).is_err());

        let long_reason = "x".repeat(MAX_REASON_BYTES + 1);
        let raw = format!(
            r#"{{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-windows-computer-host","platform":"windows","backend":"uia","capabilities":{{"input_key":{{"support":"refused","reason":"{long_reason}"}}}}}}"#
        );
        let host = negotiate("windows", |_| Ok(frame(&raw))).unwrap();
        let error = host.require("input_key").unwrap_err();
        assert!(!error.message.contains(&long_reason));
    }

    #[test]
    fn refusal_codes_map_onto_existing_failure_codes() {
        let cases = [
            ("invalid_request", FailureCode::InvalidRequest),
            ("capability_denied", FailureCode::CapabilityDenied),
            ("target_stale", FailureCode::TargetStale),
            ("permission_missing", FailureCode::ProviderUnavailable),
            ("background_unavailable", FailureCode::CapabilityDenied),
            ("background_occluded", FailureCode::CapabilityDenied),
            ("background_uipi_blocked", FailureCode::CapabilityDenied),
            ("protected_surface", FailureCode::CapabilityDenied),
            ("output_limit", FailureCode::OutputLimit),
            ("timeout", FailureCode::ProcessTimeout),
            ("provider_unavailable", FailureCode::ProviderUnavailable),
            ("postcondition_failed", FailureCode::ProviderUnavailable),
            ("cancelled", FailureCode::ProviderUnavailable),
            ("outcome_unknown", FailureCode::ProviderUnavailable),
            ("never_defined", FailureCode::ProviderUnavailable),
        ];
        for (code, expected) in cases {
            assert_eq!(
                map_refusal_code(ProtocolGeneration::V2, code),
                expected,
                "{code}"
            );
        }
    }

    #[test]
    fn v1_sessions_keep_the_v1_refusal_mapping() {
        let cases = [
            ("invalid_request", FailureCode::InvalidRequest),
            ("capability_denied", FailureCode::CapabilityDenied),
            ("target_stale", FailureCode::TargetStale),
            ("output_limit", FailureCode::OutputLimit),
            ("provider_unavailable", FailureCode::ProviderUnavailable),
            ("timeout", FailureCode::ProviderUnavailable),
            ("background_unavailable", FailureCode::ProviderUnavailable),
            ("background_occluded", FailureCode::ProviderUnavailable),
            ("background_uipi_blocked", FailureCode::ProviderUnavailable),
            ("protected_surface", FailureCode::ProviderUnavailable),
            ("permission_missing", FailureCode::ProviderUnavailable),
            ("postcondition_failed", FailureCode::ProviderUnavailable),
            ("never_defined", FailureCode::ProviderUnavailable),
        ];
        for (code, expected) in cases {
            assert_eq!(
                map_refusal_code(ProtocolGeneration::V1, code),
                expected,
                "{code}"
            );
        }
        assert_eq!(ProtocolGeneration::default(), ProtocolGeneration::V1);
    }

    #[test]
    fn advertised_unknown_operation_stays_unavailable() {
        let raw = r#"{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-windows-computer-host","platform":"windows","backend":"uia","capabilities":{"launch_process":{"support":"delivered"},"shell":{"support":"delivered"},"ping":{"support":"delivered"}}}"#;
        let host = negotiate("windows", |_| Ok(frame(raw))).unwrap();
        assert_eq!(
            host.support("launch_process"),
            CapabilitySupport::Unavailable
        );
        assert_eq!(host.support("shell"), CapabilitySupport::Unavailable);
        assert!(host.require("launch_process").is_err());
        assert!(host.require("ping").is_ok());
        assert!(!host.capabilities.contains_key("launch_process"));
    }

    const V2_LINUX_HELLO: &str = r#"{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-native-host","platform":"linux","backend":"atspi-x11","capabilities":{"hello":{"support":"delivered"},"list_windows":{"support":"delivered"},"observe_window":{"support":"unavailable","reason":"permission_missing"},"input_click":{"support":"refused","reason":"capability_denied"}}}"#;

    #[test]
    fn native_host_negotiates_identity_and_window_kind_per_backend() {
        let host = negotiate("linux", |_| Ok(frame(V2_LINUX_HELLO))).unwrap();
        assert_eq!(host.generation(), ProtocolGeneration::V2);
        assert_eq!(host.identity(), NATIVE_HOST_IDENTITY);
        assert_eq!(host.window_kind(), "x11");
        let error = host.require("observe_window").unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert!(error.message.contains("permission_missing"));
        assert!(host.require("input_click").is_err());
        let wayland = V2_LINUX_HELLO.replace("atspi-x11", "atspi-wayland");
        let host = negotiate("linux", |_| Ok(frame(&wayland))).unwrap();
        assert_eq!(host.window_kind(), "wl_toplevel");
        let macos = V2_LINUX_HELLO
            .replace("\"linux\"", "\"macos\"")
            .replace("atspi-x11", "ax");
        let host = negotiate("macos", |_| Ok(frame(&macos))).unwrap();
        assert_eq!(host.window_kind(), "cgwindow");
        let windows = negotiate("windows", |_| Ok(frame(V2_WINDOWS_HELLO))).unwrap();
        assert_eq!(windows.identity(), WINDOWS_HOST_IDENTITY);
        assert_eq!(windows.window_kind(), "hwnd");
        // The Windows host is not accepted on Linux, nor the native host on
        // Windows, nor an AT-SPI backend on macOS.
        assert!(negotiate("linux", |_| Ok(frame(V2_WINDOWS_HELLO))).is_err());
        assert!(negotiate("windows", |_| Ok(frame(V2_LINUX_HELLO))).is_err());
        let atspi_on_macos = V2_LINUX_HELLO.replace("\"linux\"", "\"macos\"");
        assert!(negotiate("macos", |_| Ok(frame(&atspi_on_macos))).is_err());
    }

    #[test]
    fn native_hello_claiming_input_or_capture_is_capped_to_observation() {
        let claims_everything = V2_LINUX_HELLO
            .replace(
                r#""input_click":{"support":"refused","reason":"capability_denied"}"#,
                r#""input_click":{"support":"delivered"},"input_hotkey":{"support":"foreground_only"},"semantic_action":{"support":"delivered"},"capture_window":{"support":"delivered"},"window_action":{"support":"delivered"},"cursor_position":{"support":"delivered"}"#,
            );
        for platform in ["linux", "macos"] {
            let raw = if platform == "macos" {
                claims_everything
                    .replace("\"linux\"", "\"macos\"")
                    .replace("atspi-x11", "ax")
            } else {
                claims_everything.clone()
            };
            let host = negotiate(platform, |_| Ok(frame(&raw))).unwrap();
            for op in [
                "input_click",
                "input_hotkey",
                "semantic_action",
                "capture_window",
                "window_action",
            ] {
                let error = host.require(op).unwrap_err();
                assert_eq!(error.code, FailureCode::ProviderUnavailable, "{op}");
                assert!(
                    error.message.contains("observation_only"),
                    "{op}: {error:?}"
                );
            }
            assert!(host.require("list_windows").is_ok());
            assert!(host.require("cursor_position").is_ok());
        }
        // Windows keeps whatever its host reports.
        let windows = negotiate("windows", |_| Ok(frame(V2_WINDOWS_HELLO))).unwrap();
        assert!(windows.require("input_click").is_ok());
    }

    #[test]
    fn native_platforms_never_fall_back_to_v1() {
        let offered = RefCell::new(Vec::new());
        let refuses_v2 = V1_REFUSES_V2.replace("orcel-windows-computer-host", NATIVE_HOST_IDENTITY);
        let error = negotiate("linux", |protocol| {
            offered.borrow_mut().push(protocol);
            Ok(frame(&refuses_v2))
        })
        .unwrap_err();
        assert_eq!(error.code, FailureCode::ProviderUnavailable);
        assert_eq!(offered.into_inner(), vec![PROTOCOL_V2]);
    }

    #[test]
    fn current_platform_is_a_closed_platform_tag() {
        assert!(PLATFORMS.contains(&current_platform()));
    }
}
