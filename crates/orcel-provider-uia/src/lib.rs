//! SG-000027 read-only Windows UI Automation observation provider.
//!
//! This crate implements the narrow P09 observation authority authorized by
//! the SG-000027 SpecGrain: server-derived process identity, typed window
//! identity, typed element identity, bounded read-only tree observation,
//! stale-identity fail-closed behavior, protected Orcel approval-surface
//! exclusion, and password and secret redaction.
//!
//! No actuation authority exists in this crate. Invoke, click, value setting,
//! text entry, select, toggle, scroll, focus, keyboard input, mouse input,
//! `SendInput`, coordinate requests, screenshots, clipboard access, network
//! egress, and elevation have no function here and must fail closed in the
//! policy and dispatch layers. A missing UIA element is reported as stale or
//! denied and must never become coordinate authority; coordinate fallback is
//! P10 work.
//!
//! Identity model:
//! - process identities are server-allocated as `uia-proc-` plus 16 lowercase
//!   hex characters derived from the PID and the executable digest, and they
//!   carry the process generation so PID reuse and restarts fail closed;
//! - window identities are server-allocated as `uia-win-` plus 16 lowercase
//!   hex characters derived from the owning process identity and the window
//!   handle, and they carry the window generation so destroyed or reused
//!   window handles fail closed;
//! - element identities are server-allocated as `uia-el-` plus 16 lowercase
//!   hex characters derived from the owning window identity and the UIA
//!   runtime identity, and they carry the tree generation so disappeared,
//!   replaced, or role-changed elements fail closed.
//!
//! Windows reality: since SG-000063 the native adapter observes the live
//! interactive desktop read-only through Win32 and UI Automation (see
//! `native_desktop`): visible top-level windows of other processes in the
//! caller's session with real process identity (image path and creation
//! time), and bounded control-view trees with password values never read.
//! Outside the interactive window station it fails closed as unavailable.
//! Actuation, capture, and input remain unavailable in the native adapter;
//! their registry behavior is proven only through the injected fake adapter
//! and must not be read as interactive desktop evidence.

use orcel_contracts::FailureCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[cfg(windows)]
mod native_desktop;

mod computer_host;
mod host_protocol;
mod native_host_path;
pub use computer_host::{
    ComputerHostAdapter, DesktopActionResult, DesktopCursorPosition, DesktopInputAction,
    DesktopWindowAction,
};
pub use native_host_path::{
    owner_and_mode_trusted, NATIVE_HOST_FILE_NAME, SYSTEM_NATIVE_HOST_PATH,
};
#[cfg(unix)]
pub use native_host_path::{trusted_native_host_path, TrustedHostBinary};

pub const UIA_SCHEMA: &str = "orcel-uia-observation-v1";
pub const INVOKE_SCHEMA: &str = "orcel-uia-invoke-v1";
pub const VALUE_SCHEMA: &str = "orcel-uia-value-v1";
pub const SELECT_SCHEMA: &str = "orcel-uia-select-v1";
pub const TOGGLE_SCHEMA: &str = "orcel-uia-toggle-v1";
pub const SCROLL_SCHEMA: &str = "orcel-uia-scroll-v1";
pub const CAPTURE_SCHEMA: &str = "orcel-screenshot-capture-v1";
pub const VISUAL_SCHEMA: &str = "orcel-visual-proposal-v1";
pub const COORD_SCHEMA: &str = "orcel-coordinate-derivation-v1";
pub const EXECUTE_SCHEMA: &str = "orcel-bounded-execution-v1";
pub const PROCESS_ID_PREFIX: &str = "uia-proc-";
pub const WINDOW_ID_PREFIX: &str = "uia-win-";
pub const ELEMENT_ID_PREFIX: &str = "uia-el-";
pub const FRAME_ID_PREFIX: &str = "uia-frame-";
pub const PROPOSAL_ID_PREFIX: &str = "uia-prop-";
pub const COORD_ID_PREFIX: &str = "uia-coord-";
pub const LEASE_ID_PREFIX: &str = "uia-lease-";
pub const POLICY_REVISION: &str = "sg-000027-v1";
pub const INVOKE_POLICY_REVISION: &str = "sg-000028-v1";

pub const MAX_WINDOWS: usize = 64;
pub const MAX_TREE_DEPTH: usize = 8;
pub const MAX_TREE_NODES: usize = 256;
pub const MAX_STRING_CHARS: usize = 256;
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

const ID_HEX_CHARS: usize = 16;

/// Window classes and titles that identify protected Orcel approval and
/// security surfaces. Observation must never target these surfaces, because
/// the agent must not be able to inspect trusted approval material in a way
/// that undermines STRONG presence, approval decisions, trust changes,
/// emergency revoke, or protected credential handling.
const PROTECTED_WINDOW_MARKERS: &[&str] = &[
    "orcelapprove",
    "orcel approval",
    "orcel trust",
    "orcel emergency revoke",
];

/// XP-06: the OS authentication and lock surfaces of each platform the
/// native host serves, matched like [`PROTECTED_WINDOW_MARKERS`] against the
/// window title and class (the owning application on macOS and Linux). The
/// host also refuses their executables outright. Windows adds nothing, so its
/// behaviour is unchanged.
#[cfg(target_os = "macos")]
const OS_PROTECTED_WINDOW_MARKERS: &[&str] =
    &["loginwindow", "securityagent", "screensaver", "coreautha"];
#[cfg(all(unix, not(target_os = "macos")))]
const OS_PROTECTED_WINDOW_MARKERS: &[&str] = &[
    "polkit",
    "screensaver",
    "i3lock",
    "swaylock",
    "light-locker",
    "kscreenlocker",
    "xsecurelock",
];
#[cfg(not(unix))]
const OS_PROTECTED_WINDOW_MARKERS: &[&str] = &[];

/// Substrings that mark a control as password or secret bearing. Matching is
/// ASCII case-insensitive and applies to the control type, the automation id,
/// and the accessible name.
const PASSWORD_MARKERS: &[&str] = &["password", "passwd", "secret", "token"];

/// The only UIA capability and operation shapes SG-000027 authorizes. Every
/// other UIA-like shape must fail closed.
pub fn is_allowed_uia_shape(capability: &str, operation: &str) -> bool {
    matches!(
        (capability, operation),
        ("uia.process", "observe")
            | ("uia.window", "list")
            | ("uia.window", "observe")
            | ("uia.tree", "observe")
            | ("uia.element", "observe")
    )
}

/// Current live qualification of one retained desktop shape. SG-000095
/// supersedes the SG-000063 read-only qualification only for the exact
/// semantic-action and target-window capture shapes listed below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopShapeQualification {
    /// Live through the selected adapter and exposed by a governed MCP tool.
    LiveExposed,
    /// Live as registry state used by exposed tools, without its own MCP tool.
    LiveInternal,
    /// Retained internally but intentionally not exposed by the current MCP surface.
    NotLive,
}

/// Test-pinned current decision for every retained UIA desktop shape.
/// SG-000095 exposes semantic UIA actions and exact-window capture only through
/// the ComputerHostAdapter under Full User authority; the legacy visual /
/// coordinate / click-lease chain remains unexposed.
pub const DESKTOP_SHAPE_QUALIFICATIONS: &[(&str, &str, DesktopShapeQualification)] = &[
    ("uia.window", "list", DesktopShapeQualification::LiveExposed),
    (
        "uia.tree",
        "observe",
        DesktopShapeQualification::LiveExposed,
    ),
    (
        "uia.process",
        "observe",
        DesktopShapeQualification::LiveInternal,
    ),
    (
        "uia.window",
        "observe",
        DesktopShapeQualification::LiveInternal,
    ),
    (
        "uia.element",
        "observe",
        DesktopShapeQualification::LiveInternal,
    ),
    (
        "uia.element",
        "invoke",
        DesktopShapeQualification::LiveExposed,
    ),
    (
        "uia.element",
        "set_value",
        DesktopShapeQualification::LiveExposed,
    ),
    (
        "uia.element",
        "select",
        DesktopShapeQualification::LiveExposed,
    ),
    (
        "uia.element",
        "toggle",
        DesktopShapeQualification::LiveExposed,
    ),
    (
        "uia.element",
        "scroll",
        DesktopShapeQualification::LiveExposed,
    ),
    (
        "uia.screenshot",
        "capture",
        DesktopShapeQualification::LiveExposed,
    ),
    ("uia.visual", "propose", DesktopShapeQualification::NotLive),
    (
        "uia.coordinates",
        "propose",
        DesktopShapeQualification::NotLive,
    ),
    ("uia.input", "execute", DesktopShapeQualification::NotLive),
];

/// Whether one retained UIA shape is currently projected by MCP. This is only
/// discovery metadata; orceld still enforces Full User lease, approval,
/// freshness, protected-surface, interruption, and remote-context denial.
pub fn is_mcp_exposed_desktop_shape(capability: &str, operation: &str) -> bool {
    DESKTOP_SHAPE_QUALIFICATIONS
        .iter()
        .any(|(shape_capability, shape_operation, qualification)| {
            *shape_capability == capability
                && *shape_operation == operation
                && *qualification == DesktopShapeQualification::LiveExposed
        })
}

/// Typed denial catalog for UIA shapes that remain unauthorized. Actuation,
/// synthetic input, coordinates, screenshots, clipboard, network, and
/// elevation shapes are denied here so policy can map them to the STRONG
/// gate and dispatch can fail closed without reaching the registry.
///
/// NOTE (SG-000028 successor): `uia.element/invoke` is lawfully authorized
/// by the SG-000028 successor grain and is therefore no longer in this
/// denied set for current-tree authority. The frozen SG-000027 qualified
/// head recorded this shape as denied; current-tree authority records the
/// successor delta.
///
/// NOTE (SG-000029 successor): `uia.element/set_value` is lawfully
/// authorized by the SG-000029 successor grain and is therefore no longer
/// in this denied set for current-tree authority. Select, toggle, scroll,
/// focus, keyboard, mouse, coordinates, screenshots, clipboard, network,
/// and elevation remain denied in every successor grain prior to their own
/// successor authorization.
///
/// NOTE (SG-000030 successor): `uia.element/select` is lawfully authorized
/// by the SG-000030 successor grain and is therefore no longer in this
/// denied set for current-tree authority. The frozen SG-000027 qualified
/// head recorded this shape as denied; current-tree authority records the
/// successor delta. Toggle, scroll, focus, keyboard, mouse, coordinates,
/// screenshots, clipboard, network, and elevation remain denied in every
/// successor grain.
///
/// NOTE (SG-000031 successor): `uia.element/toggle` is lawfully authorized
/// by the SG-000031 successor grain and is therefore no longer in this
/// denied set for current-tree authority. The frozen SG-000027 qualified
/// head recorded this shape as denied; current-tree authority records the
/// successor delta. Scroll, focus, keyboard, mouse, coordinates,
/// screenshots, clipboard, network, and elevation remain denied in every
/// successor grain prior to their own successor authorization.
///
/// NOTE (SG-000032 successor): `uia.element/scroll` is lawfully authorized
/// by the SG-000032 successor grain and is therefore no longer in this
/// denied set for current-tree authority. The frozen SG-000027 qualified
/// head recorded this shape as denied; current-tree authority records the
/// successor delta. Focus, keyboard, mouse, coordinates, screenshots,
/// clipboard, network, and elevation remain denied in every successor
/// grain.
///
/// NOTE (SG-000033 successor): `uia.screenshot/capture` is lawfully
/// authorized by the SG-000033 successor grain as a single read-only
/// window-scoped capture shape and is therefore no longer in this denied
/// set for current-tree authority. The frozen SG-000027 qualified head
/// recorded this shape as denied; current-tree authority records the
/// successor delta. Visual target proposals, coordinate proposals, input
/// execution, monitor scope, desktop scope, focus, keyboard, mouse,
/// clipboard, network, and elevation remain denied in every successor
/// grain prior to their own successor authorization.
///
/// NOTE (SG-000035 successor): `uia.coordinates/propose` is lawfully
/// authorized by the SG-000035 successor grain as a single proposal-only
/// coordinate derivation shape and is therefore reachable as current-tree
/// authority outside this denied set. The frozen SG-000027 qualified head
/// recorded `uia.coordinates/request` as denied; that raw request shape
/// remains in this denied set and remains denied in every successor
/// grain. Input execution, input leases, monitor scope, desktop scope,
/// focus, keyboard, mouse, clipboard, network, and elevation remain
/// denied in every successor grain prior to their own successor
/// authorization.
///
/// NOTE (SG-000036 successor): `uia.input/execute` is lawfully
/// authorized by the SG-000036 successor grain as a single bounded
/// click-only execution shape under an explicit single-use input lease
/// and is therefore reachable as current-tree authority outside this
/// denied set. The frozen SG-000027 qualified head recorded
/// `uia.input/keyboard`, `uia.input/mouse`, and `uia.input/sendinput`
/// as denied; those raw synthetic-input shapes remain in this denied
/// set and remain denied in every successor grain. Standing input
/// sessions, keyboard, drag, monitor scope, desktop scope, clipboard,
/// network, and elevation remain denied in every successor grain prior
/// to their own successor authorization.
///
/// NOTE (SG-000037 successor): human-interruption epoch invalidation is
/// lawfully authorized by the SG-000037 successor grain as revocation-only
/// handling bound into input leases and execution approval digests. The
/// frozen SG-000036 qualified head recorded leases without epoch binding;
/// current-tree authority records the successor delta. No new actuating
/// input shape is added: keyboard, drag, monitor scope, desktop scope,
/// clipboard, network, and elevation remain denied in every successor
/// grain prior to their own successor authorization. Human physical
/// interaction always wins over Orcel automation.
pub const DENIED_UIA_SHAPES: &[(&str, &str)] = &[
    ("uia.element", "click"),
    ("uia.element", "focus"),
    ("uia.window", "focus"),
    ("uia.window", "close"),
    ("uia.input", "keyboard"),
    ("uia.input", "mouse"),
    ("uia.input", "sendinput"),
    ("uia.coordinates", "request"),
    ("uia.clipboard", "read"),
    ("uia.clipboard", "write"),
    ("uia.network", "fetch"),
    ("uia.process", "spawn"),
    ("uia.process", "inject"),
    ("uia.process", "terminate"),
    ("uia.elevation", "request"),
];

/// The single SG-000028 actuation shape. Observation shapes remain authorized
/// through `is_allowed_uia_shape`; invoke is authorized separately so the
/// SG-000027 frozen policy meaning is preserved while current-tree authority
/// records the successor delta.
pub fn is_invoke_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.element", "invoke"))
}

/// Control types eligible for InvokePattern actuation. All other control
/// types must fail closed as denied, including value-capable, selection
/// capable, toggle capable, scroll capable, password, and secret controls.
pub const INVOKE_ELIGIBLE_CONTROL_TYPES: &[&str] =
    &["Button", "Hyperlink", "MenuItem", "SplitButton"];

/// The required UIA pattern name for invoke targets.
pub const INVOKE_PATTERN_NAME: &str = "Invoke";

pub fn is_invoke_eligible_control_type(control_type: &str) -> bool {
    INVOKE_ELIGIBLE_CONTROL_TYPES.contains(&control_type)
}

/// The single SG-000029 value actuation shape. Invoke remains authorized
/// through `is_invoke_shape`; value is authorized separately so frozen
/// policy meanings are preserved while current-tree authority records the
/// successor delta.
pub fn is_value_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.element", "set_value"))
}

/// Control types eligible for ValuePattern actuation. All other control
/// types must fail closed as denied, including invoke-capable, selection
/// capable, toggle capable, scroll capable, password, and secret controls.
pub const VALUE_ELIGIBLE_CONTROL_TYPES: &[&str] = &["Edit", "Document", "ComboBox"];

/// The required UIA pattern name for value targets.
pub const VALUE_PATTERN_NAME: &str = "Value";

/// Maximum value length in characters for structured set_value. Oversized
/// values fail closed without silent truncation.
pub const MAX_VALUE_CHARS: usize = 1024;

pub fn is_value_eligible_control_type(control_type: &str) -> bool {
    VALUE_ELIGIBLE_CONTROL_TYPES.contains(&control_type)
}

/// The single SG-000030 select actuation shape. Invoke and value remain
/// authorized through their own predicates; select is authorized separately
/// so frozen policy meanings are preserved while current-tree authority
/// records the successor delta.
pub fn is_select_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.element", "select"))
}

/// Control types eligible for SelectionItem actuation. All other control
/// types must fail closed as denied, including invoke-capable, value
/// capable, toggle capable, scroll capable, password, and secret controls.
pub const SELECT_ELIGIBLE_CONTROL_TYPES: &[&str] = &["ListItem", "TreeItem", "TabItem"];

/// The required UIA pattern name for select targets.
pub const SELECT_PATTERN_NAME: &str = "SelectionItem";

pub fn is_select_eligible_control_type(control_type: &str) -> bool {
    SELECT_ELIGIBLE_CONTROL_TYPES.contains(&control_type)
}

/// The single SG-000031 toggle actuation shape. Select remains authorized
/// through its own predicate; toggle is authorized separately so frozen
/// policy meanings are preserved while current-tree authority records the
/// successor delta.
pub fn is_toggle_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.element", "toggle"))
}

/// Control types eligible for TogglePattern actuation. All other control
/// types must fail closed as denied, including invoke-capable, value
/// capable, selection capable, scroll capable, password, and secret controls.
pub const TOGGLE_ELIGIBLE_CONTROL_TYPES: &[&str] = &["CheckBox", "RadioButton"];

/// The required UIA pattern name for toggle targets.
pub const TOGGLE_PATTERN_NAME: &str = "Toggle";

pub fn is_toggle_eligible_control_type(control_type: &str) -> bool {
    TOGGLE_ELIGIBLE_CONTROL_TYPES.contains(&control_type)
}

/// The single SG-000032 scroll actuation shape. Toggle remains authorized
/// through its own predicate; scroll is authorized separately so frozen
/// policy meanings are preserved while current-tree authority records the
/// successor delta.
pub fn is_scroll_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.element", "scroll"))
}

/// Control types eligible for ScrollPattern actuation. All other control
/// types must fail closed as denied, including invoke-capable, value
/// capable, selection capable, toggle capable, password, and secret controls.
pub const SCROLL_ELIGIBLE_CONTROL_TYPES: &[&str] = &["ScrollBar", "Pane", "List", "Tree"];

/// The required UIA pattern name for scroll targets.
pub const SCROLL_PATTERN_NAME: &str = "Scroll";

/// Scroll directions authorized for structured scrolling. Any other
/// direction string fails closed.
pub const SCROLL_DIRECTIONS: &[&str] = &["up", "down", "left", "right"];

/// Maximum scroll amount per structured scroll action. Larger amounts,
/// repeat counts, and indefinite scrolling fail closed.
pub const MAX_SCROLL_AMOUNT: u64 = 100;

pub fn is_scroll_eligible_control_type(control_type: &str) -> bool {
    SCROLL_ELIGIBLE_CONTROL_TYPES.contains(&control_type)
}

pub fn is_scroll_direction(direction: &str) -> bool {
    SCROLL_DIRECTIONS.contains(&direction)
}

/// The single SG-000033 read-only vision shape. Scroll remains authorized
/// through its own predicate; window-scoped screenshot capture is
/// authorized separately so frozen policy meanings are preserved while
/// current-tree authority records the successor delta. A capture never
/// grants visual target proposals, coordinate proposals, input execution,
/// monitor scope, or desktop scope.
pub fn is_capture_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.screenshot", "capture"))
}

/// The single SG-000034 non-actuating vision shape. Capture remains
/// authorized through its own predicate; visual target proposals are
/// authorized separately so frozen policy meanings are preserved while
/// current-tree authority records the successor delta. A proposal never
/// grants coordinate derivation, input execution, monitor scope, or
/// desktop scope.
pub fn is_visual_propose_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.visual", "propose"))
}

/// A bounded pixel region inside one exact frame. Regions are evidence
/// geometry for successor coordinate grains, never screen input
/// coordinates: no execution path consumes a region without a successor
/// grain authorizing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VisualRegion {
    pub x: u64,
    pub y: u64,
    pub width: u64,
    pub height: u64,
}

/// Frame-relative coordinates derived deterministically from one exact
/// bounded proposal region. Derived coordinates are evidence geometry
/// for the successor input grain, never input authority: no execution
/// path consumes derived coordinates without a successor grain
/// authorizing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedCoordinate {
    pub x: u64,
    pub y: u64,
}

/// The single SG-000035 proposal-only derivation shape. Visual proposals
/// remain authorized through their own predicate; coordinate derivation
/// is authorized separately so frozen policy meanings are preserved
/// while current-tree authority records the successor delta. Derivation
/// never calls any input API and never grants input execution, input
/// leases, monitor scope, or desktop scope.
pub fn is_coordinate_propose_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.coordinates", "propose"))
}

/// The single SG-000036 bounded execution shape. Coordinate derivation
/// remains authorized through its own predicate; bounded execution is
/// authorized separately so frozen policy meanings are preserved while
/// current-tree authority records the successor delta. Execution is
/// click-only, confined to the exact owning window, and gated by an
/// explicit single-use input lease plus fresh approval.
pub fn is_input_execute_shape(capability: &str, operation: &str) -> bool {
    matches!((capability, operation), ("uia.input", "execute"))
}

/// The only input operation SG-000036 authorizes: a single click
/// confined to the exact owning window of one exact bound coordinate
/// identity. Keyboard, drag, multi-click, wheel, touch, focus, and raw
/// synthetic input fail closed.
pub const EXECUTE_OPERATION_CLICK: &str = "click";

pub fn is_execute_operation(operation: &str) -> bool {
    operation == EXECUTE_OPERATION_CLICK
}

/// Lifetime of one explicit input lease in milliseconds. Leases expire
/// quickly so an unconsumed lease cannot become a standing input
/// session; expired leases fail closed.
pub const LEASE_TTL_MS: u64 = 60_000;

/// Maximum live input leases held by the registry. Grants beyond the
/// bound fail closed after sweeping expired leases, so the registry
/// cannot accumulate unbounded pending state.
pub const MAX_LEASES: usize = 64;

/// Schema label for bounded human-interruption evidence. Interruption
/// evidence carries only the epoch, the bounded physical-source reason,
/// the report timestamp, the workspace, and the policy revision. It never
/// carries keystroke content, pointer paths, window content, credentials,
/// or secret material.
pub const INTERRUPT_SCHEMA: &str = "orcel-human-interruption-v1";

/// Maximum human-interruption reason length in characters. Reasons are a
/// fixed allowlist, so oversized values fail closed without truncation
/// that changes revocation semantics.
pub const MAX_INTERRUPT_REASON_CHARS: usize = 64;

/// Bounded physical sources that may report human interruption. Only these
/// reasons increment the interruption epoch. Orcel synthetic execution is
/// never a reason: the registry never calls the report path for its own
/// adapter actuation, so automation cannot revoke its own lease.
pub const HUMAN_INTERRUPT_REASONS: &[&str] = &[
    "human-keyboard",
    "human-mouse-move",
    "human-mouse-button",
    "human-touch-pen",
    "human-foreground-change",
    "human-presence",
    "emergency-stop",
    "approval-pending-suspension",
];

/// Returns true when the interruption reason is one of the bounded
/// physical sources. Empty, oversized, and unknown reasons fail closed.
pub fn is_human_interrupt_reason(reason: &str) -> bool {
    !reason.is_empty()
        && reason.chars().count() <= MAX_INTERRUPT_REASON_CHARS
        && HUMAN_INTERRUPT_REASONS.contains(&reason)
}

/// Origin of one observed input event for interruption classification.
/// The registry distinguishes Orcel-generated synthetic input (which must
/// never revoke its own lease), OS or other synthetic input, real human
/// physical input, and unknown input (which fails closed toward
/// interruption so ambiguous sensing never lets automation fight the user).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOrigin {
    OrcelSynthetic,
    OsSynthetic,
    HumanPhysical,
    Unknown,
}

/// Classify one observed input event. `is_orcel_own` marks actuation that
/// Orcel itself just performed through the bounded execution adapter.
/// `is_injected` carries the Windows injected-input flag
/// (`LLKHF_INJECTED` / `LLMHF_INJECTED`): set for synthetic input from any
/// source. `sensor_trusted` is false when the sensor could not determine
/// injection provenance, in which case classification is `Unknown` and the
/// caller must fail closed toward interruption.
pub fn classify_input_event(
    is_injected: bool,
    is_orcel_own: bool,
    sensor_trusted: bool,
) -> InputOrigin {
    if !sensor_trusted {
        return InputOrigin::Unknown;
    }
    if is_orcel_own {
        return InputOrigin::OrcelSynthetic;
    }
    if is_injected {
        return InputOrigin::OsSynthetic;
    }
    InputOrigin::HumanPhysical
}

/// Returns true when the classified origin must revoke live input leases.
/// Orcel synthetic execution never interrupts itself. Every other origin,
/// including ambiguous `Unknown`, revokes: the system never fights the
/// user for control and never suppresses a genuine human override behind
/// a forged synthetic-origin claim.
pub fn should_interrupt_on_origin(origin: InputOrigin) -> bool {
    !matches!(origin, InputOrigin::OrcelSynthetic)
}

/// Derive deterministic frame-relative coordinates (region center,
/// integer division) from one exact bounded region. Regions are
/// pre-validated inside the exact frame geometry, so the derived center
/// always lies inside the frame.
pub fn derive_region_center(region: VisualRegion) -> DerivedCoordinate {
    DerivedCoordinate {
        x: region.x + region.width / 2,
        y: region.y + region.height / 2,
    }
}

/// The only capture scope SG-000033 authorizes: the exact target window.
/// Monitor scope, desktop scope, caller-selected regions, and arbitrary
/// rectangles fail closed.
pub const CAPTURE_SCOPE_TARGET_WINDOW: &str = "target-window";

pub fn is_capture_scope(scope: &str) -> bool {
    scope == CAPTURE_SCOPE_TARGET_WINDOW
}

/// Maximum capture payload in bytes. Oversized captures fail closed with
/// no silent downscaling that changes evidence semantics.
pub const MAX_CAPTURE_BYTES: usize = 8 * 1024 * 1024;
/// Base64 expands by 4/3. Keep the public capture response below the private
/// host's 16 MiB frame while leaving the 64 KiB observation bound unchanged.
pub const MAX_CAPTURE_RESPONSE_BYTES: usize = 12 * 1024 * 1024;

/// Maximum capture dimensions in pixels. Geometry outside these bounds
/// fails closed.
pub const MAX_CAPTURE_WIDTH: u32 = 7680;
pub const MAX_CAPTURE_HEIGHT: u32 = 4320;

/// Fixed pixel format reported by the bounded capture provider. Adapters
/// report raw 8-bit RGBA bytes in row-major order.
pub const CAPTURE_PIXEL_FORMAT: &str = "rgba8";

pub fn is_well_formed_frame_id(value: &str) -> bool {
    is_well_formed_typed_id(value, FRAME_ID_PREFIX)
}

pub fn is_well_formed_proposal_id(value: &str) -> bool {
    is_well_formed_typed_id(value, PROPOSAL_ID_PREFIX)
}

pub fn is_well_formed_coord_id(value: &str) -> bool {
    is_well_formed_typed_id(value, COORD_ID_PREFIX)
}

pub fn is_well_formed_lease_id(value: &str) -> bool {
    is_well_formed_typed_id(value, LEASE_ID_PREFIX)
}

/// SHA-256 hex digest of one requested value, used in approval digests and
/// evidence so raw value bytes never enter approval prompts beyond the
/// bounded request itself and never enter evidence at all.
pub fn value_content_digest(value: &str) -> String {
    digest_hex(&format!("orcel-uia-value-v1|{value}"), 64)
}

pub fn is_denied_uia_shape(capability: &str, operation: &str) -> bool {
    DENIED_UIA_SHAPES
        .iter()
        .any(|(denied_capability, denied_operation)| {
            *denied_capability == capability && *denied_operation == operation
        })
}

#[derive(Debug, Clone)]
pub struct UiaError {
    pub code: FailureCode,
    pub message: String,
}

impl UiaError {
    pub fn new(code: FailureCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub fn is_well_formed_process_id(value: &str) -> bool {
    is_well_formed_typed_id(value, PROCESS_ID_PREFIX)
}

pub fn is_well_formed_window_id(value: &str) -> bool {
    is_well_formed_typed_id(value, WINDOW_ID_PREFIX)
}

pub fn is_well_formed_element_id(value: &str) -> bool {
    is_well_formed_typed_id(value, ELEMENT_ID_PREFIX)
}

fn is_well_formed_typed_id(value: &str, prefix: &str) -> bool {
    value.len() == prefix.len() + ID_HEX_CHARS
        && value.starts_with(prefix)
        && value[prefix.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn digest_hex(material: &str, chars: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(material.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.chars().take(chars).collect()
}

fn allocate_process_id(pid: u32, exe_id: &str) -> String {
    format!(
        "{PROCESS_ID_PREFIX}{}",
        digest_hex(&format!("{UIA_SCHEMA}|proc|{pid}|{exe_id}"), ID_HEX_CHARS)
    )
}

fn allocate_window_id(process_id: &str, hwnd: u64) -> String {
    format!(
        "{WINDOW_ID_PREFIX}{}",
        digest_hex(
            &format!("{UIA_SCHEMA}|win|{process_id}|{hwnd}"),
            ID_HEX_CHARS
        )
    )
}

fn allocate_element_id(window_id: &str, runtime_id: &str) -> String {
    format!(
        "{ELEMENT_ID_PREFIX}{}",
        digest_hex(
            &format!("{UIA_SCHEMA}|el|{window_id}|{runtime_id}"),
            ID_HEX_CHARS
        )
    )
}

fn allocate_frame_id(window_id: &str, capture_generation: u64) -> String {
    format!(
        "{FRAME_ID_PREFIX}{}",
        digest_hex(
            &format!("{CAPTURE_SCHEMA}|frame|{window_id}|{capture_generation}"),
            ID_HEX_CHARS
        )
    )
}

fn allocate_proposal_id(frame_id: &str, proposal_generation: u64) -> String {
    format!(
        "{PROPOSAL_ID_PREFIX}{}",
        digest_hex(
            &format!("{VISUAL_SCHEMA}|proposal|{frame_id}|{proposal_generation}"),
            ID_HEX_CHARS
        )
    )
}

fn allocate_coord_id(proposal_id: &str, derivation_generation: u64) -> String {
    format!(
        "{COORD_ID_PREFIX}{}",
        digest_hex(
            &format!("{COORD_SCHEMA}|coordinate|{proposal_id}|{derivation_generation}"),
            ID_HEX_CHARS
        )
    )
}

fn allocate_lease_id(coord_id: &str, lease_sequence: u64) -> String {
    format!(
        "{LEASE_ID_PREFIX}{}",
        digest_hex(
            &format!("{EXECUTE_SCHEMA}|lease|{coord_id}|{lease_sequence}"),
            ID_HEX_CHARS
        )
    )
}

/// SHA-256 hex digest of one capture payload, used in approval-adjacent
/// evidence and frame records so payload comparisons never require moving
/// raw pixels through logs or metadata paths.
pub fn capture_payload_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"orcel-screenshot-capture-v1|payload|");
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if bytes.is_empty() {
        return String::new();
    }
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 0x03) << 4) | (b >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[(((b & 0x0f) << 2) | (c >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(c & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// A process as reported by an adapter. Adapters never allocate authority;
/// they only report OS-visible facts that the registry binds into typed
/// identities.
#[derive(Debug, Clone)]
pub struct NativeProcess {
    pub pid: u32,
    pub exe_name: String,
    pub exe_id: String,
    pub session_id: u32,
    pub session_verified: bool,
    pub start_generation: u64,
    pub generation_source: &'static str,
}

/// A top-level window as reported by an adapter.
#[derive(Debug, Clone)]
pub struct NativeWindow {
    pub hwnd: u64,
    pub title: String,
    pub class: String,
    pub visible: bool,
    /// Adapter-provided replacement marker. The fake adapter changes this
    /// value to simulate a destroyed and recreated window behind a reused
    /// handle. The native adapter derives it from stable window metadata.
    pub window_nonce: u64,
}

/// One UIA element as reported by an adapter, with already-nested children.
#[derive(Debug, Clone)]
pub struct NativeElement {
    pub runtime_id: String,
    pub control_type: String,
    pub automation_id: String,
    pub name: String,
    pub enabled: bool,
    pub selected: bool,
    pub toggled: bool,
    pub scroll_horizontal_percent: u8,
    pub scroll_vertical_percent: u8,
    pub patterns: Vec<String>,
    pub value: Option<String>,
    pub value_is_password: bool,
    pub children: Vec<NativeElement>,
}

/// One window-scoped capture as reported by an adapter. Adapters report
/// raw pixels for the exact target window only; scope enforcement,
/// identity binding, bounds, and protected-surface exclusion live in the
/// registry, so adapters stay small and deterministic tests never need a
/// live desktop. Pixel bytes are 8-bit RGBA in row-major order.
#[derive(Debug, Clone)]
pub struct CapturedImage {
    pub width: u32,
    pub height: u32,
    pub bytes: Vec<u8>,
}

/// The adapter boundary. Policy logic, identity allocation, stale checks,
/// redaction, bounds, and protected-surface exclusion live in the registry,
/// so adapters stay small and deterministic tests never need a live desktop.
pub trait UiaAdapter {
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError>;
    fn list_windows(&self, pid: u32) -> Result<Vec<NativeWindow>, UiaError>;
    fn read_tree(&self, hwnd: u64) -> Result<Vec<NativeElement>, UiaError>;
    /// Perform one structured InvokePattern actuation against the live
    /// element identified by window handle and UIA runtime identity. The
    /// registry revalidates every binding before calling this method, so
    /// adapters must not retarget, fall back to coordinates, or synthesize
    /// generic input. The default implementation fails closed as
    /// unavailable, which the native adapter uses until an interactive
    /// session broker exists.
    fn invoke_element(&self, _hwnd: u64, _runtime_id: &str) -> Result<(), UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "structured UIA invoke requires an interactive session broker and is unavailable in this context",
        ))
    }
    /// Perform one structured ValuePattern write against the live element
    /// identified by window handle and UIA runtime identity. The registry
    /// revalidates every binding before calling this method, so adapters
    /// must not retarget, fall back to keyboard, clipboard, or coordinates,
    /// or synthesize generic input. The default implementation fails closed
    /// as unavailable, which the native adapter uses until an interactive
    /// session broker exists.
    fn set_value_element(
        &self,
        _hwnd: u64,
        _runtime_id: &str,
        _value: &str,
    ) -> Result<(), UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "structured UIA set_value requires an interactive session broker and is unavailable in this context",
        ))
    }
    /// Perform one structured SelectionItem actuation against the live
    /// element identified by window handle and UIA runtime identity. The
    /// registry revalidates every binding before calling this method, so
    /// adapters must not retarget, fall back to mouse, keyboard, or
    /// coordinates, or synthesize generic input. The default implementation
    /// fails closed as unavailable, which the native adapter uses until an
    /// interactive session broker exists.
    fn select_element(
        &self,
        _hwnd: u64,
        _runtime_id: &str,
        _selected: bool,
    ) -> Result<(), UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "structured UIA select requires an interactive session broker and is unavailable in this context",
        ))
    }
    /// Perform one structured TogglePattern actuation against the live
    /// element identified by window handle and UIA runtime identity. The
    /// registry revalidates every binding before calling this method, so
    /// adapters must not retarget, fall back to Invoke, click, Space, Enter,
    /// keyboard, mouse, or coordinates, or synthesize generic input. The
    /// default implementation fails closed as unavailable, which the native
    /// adapter uses until an interactive session broker exists.
    fn toggle_element(
        &self,
        _hwnd: u64,
        _runtime_id: &str,
        _toggled: bool,
    ) -> Result<(), UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "structured UIA toggle requires an interactive session broker and is unavailable in this context",
        ))
    }
    /// Perform one structured ScrollPattern actuation against the live
    /// element identified by window handle and UIA runtime identity. The
    /// registry revalidates every binding before calling this method, so
    /// adapters must not retarget, fall back to wheel, touch, keyboard
    /// paging, mouse, or coordinates, repeat the scroll, or synthesize
    /// generic input. The default implementation fails closed as
    /// unavailable, which the native adapter uses until an interactive
    /// session broker exists.
    fn scroll_element(
        &self,
        _hwnd: u64,
        _runtime_id: &str,
        _direction: &str,
        _amount: u64,
    ) -> Result<(), UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "structured UIA scroll requires an interactive session broker and is unavailable in this context",
        ))
    }
    /// Capture the exact target window identified by window handle. The
    /// registry revalidates every binding before calling this method, so
    /// adapters must capture the bound window only and must never widen to
    /// monitor scope, desktop scope, caller-selected regions, or adjacent
    /// windows. The default implementation fails closed as unavailable,
    /// which the native adapter uses until an interactive session broker
    /// exists.
    fn capture_window(&self, _hwnd: u64) -> Result<CapturedImage, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "window-scoped screenshot capture requires an interactive session broker and is unavailable in this context",
        ))
    }
    /// Perform one bounded click confined to the exact owning window at
    /// the given frame-relative coordinates. The registry revalidates
    /// every binding and consumes an explicit single-use input lease
    /// before calling this method, so adapters must actuate the bound
    /// window only and must never widen to other windows, monitors, or
    /// the desktop, and must never synthesize keyboard, drag, or raw
    /// input. The default implementation fails closed as unavailable,
    /// which the native adapter uses until an interactive session broker
    /// exists.
    fn execute_click(&self, _hwnd: u64, _x: u64, _y: u64) -> Result<(), UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "bounded input execution requires an interactive session broker and is unavailable in this context",
        ))
    }
}

/// The native adapter. On Windows it observes the live interactive desktop
/// read-only (`native_desktop`): processes that own visible top-level
/// windows in the caller's session, with real image identity, session, and
/// creation time; their windows; and bounded control-view trees. Outside the
/// interactive window station it fails closed as unavailable. Actuation,
/// capture, and input are not implemented and fail closed as unavailable.
pub struct NativeAdapter;

impl NativeAdapter {
    pub fn new() -> Self {
        Self
    }

    /// Off Windows there is no desktop to observe; only the current process
    /// is reported, with explicit unverified markers.
    #[cfg(not(windows))]
    fn current_process() -> NativeProcess {
        let pid = std::process::id();
        let (exe_name, exe_id) = match std::env::current_exe() {
            Ok(path) => {
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown")
                    .to_owned();
                let normalized = path.to_string_lossy().to_lowercase();
                let digest = digest_hex(&format!("{UIA_SCHEMA}|exe|{normalized}"), ID_HEX_CHARS);
                (name, digest)
            }
            Err(_) => ("unknown".to_owned(), "0".repeat(ID_HEX_CHARS)),
        };
        NativeProcess {
            pid,
            exe_name,
            exe_id,
            session_id: 0,
            session_verified: false,
            start_generation: 0,
            generation_source: "std-fallback",
        }
    }
}

impl Default for NativeAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl UiaAdapter for NativeAdapter {
    /// On Windows: the processes that own visible top-level windows in the
    /// caller's interactive session, each with a verified image path and
    /// creation time. Elsewhere: only the current process.
    #[cfg(windows)]
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        let mut seen: Vec<u32> = Vec::new();
        let mut processes = Vec::new();
        for window in native_desktop::visible_windows()? {
            if seen.contains(&window.pid) {
                continue;
            }
            seen.push(window.pid);
            if let Some(process) = native_desktop::process_facts(window.pid) {
                processes.push(process);
            }
        }
        Ok(processes)
    }

    #[cfg(not(windows))]
    fn list_processes(&self) -> Result<Vec<NativeProcess>, UiaError> {
        Ok(vec![Self::current_process()])
    }

    #[cfg(windows)]
    fn list_windows(&self, pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        let Some(process) = native_desktop::process_facts(pid) else {
            return Ok(Vec::new());
        };
        Ok(native_desktop::visible_windows()?
            .iter()
            .filter(|window| window.pid == pid)
            .map(|window| native_desktop::native_window(window, &process))
            .collect())
    }

    #[cfg(not(windows))]
    fn list_windows(&self, _pid: u32) -> Result<Vec<NativeWindow>, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "live desktop window enumeration is available only on Windows",
        ))
    }

    #[cfg(windows)]
    fn read_tree(&self, hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        native_desktop::read_tree(hwnd)
    }

    #[cfg(not(windows))]
    fn read_tree(&self, _hwnd: u64) -> Result<Vec<NativeElement>, UiaError> {
        Err(UiaError::new(
            FailureCode::ProviderUnavailable,
            "live desktop tree enumeration is available only on Windows",
        ))
    }
}

#[derive(Debug, Clone)]
struct ProcessRecord {
    process_id: String,
    pid: u32,
    exe_name: String,
    exe_id: String,
    session_id: u32,
    session_verified: bool,
    process_generation: u64,
    generation_source: &'static str,
    workspace_id: String,
    policy_revision: String,
    superseded: bool,
}

#[derive(Debug, Clone)]
struct WindowRecord {
    window_id: String,
    process_id: String,
    hwnd: u64,
    title: String,
    class: String,
    visible: bool,
    window_nonce: u64,
    window_generation: u64,
    tree_generation: u64,
    workspace_id: String,
    policy_revision: String,
}

#[derive(Debug, Clone)]
struct ElementRecord {
    element_id: String,
    window_id: String,
    runtime_id: String,
    control_type: String,
    automation_id: String,
    name: String,
    enabled: bool,
    selected: bool,
    toggled: bool,
    scroll_horizontal_percent: u8,
    scroll_vertical_percent: u8,
    patterns: Vec<String>,
    value: Option<String>,
    value_is_password: bool,
    redacted: bool,
    tree_generation: u64,
}

/// One server-allocated capture frame. Frames are evidence for successor
/// visual grains and are never themselves input-execution authority. A
/// frame binds its owning window, capture generation, geometry, payload
/// digest, workspace, and policy revision; replayed, foreign, and
/// policy-drifted frames fail closed as stale and stale frames are never
/// actionable.
#[derive(Debug, Clone)]
struct FrameRecord {
    frame_id: String,
    window_id: String,
    process_id: String,
    process_generation: u64,
    window_generation: u64,
    capture_generation: u64,
    width: u32,
    height: u32,
    payload_digest: String,
    workspace_id: String,
    policy_revision: String,
}

/// One server-allocated visual target proposal. Proposals are evidence
/// for successor coordinate grains and are never themselves
/// coordinate-derivation or input-execution authority. A proposal binds
/// its owning frame, proposal generation, bounded region, workspace, and
/// policy revision; replayed, foreign, and policy-drifted proposals fail
/// closed as stale and stale proposals are never actionable.
#[derive(Debug, Clone)]
struct ProposalRecord {
    proposal_id: String,
    frame_id: String,
    window_id: String,
    process_id: String,
    process_generation: u64,
    window_generation: u64,
    capture_generation: u64,
    proposal_generation: u64,
    region_x: u64,
    region_y: u64,
    region_width: u64,
    region_height: u64,
    workspace_id: String,
    policy_revision: String,
}

/// One server-allocated derived coordinate identity. Derived coordinates
/// are evidence for the successor input grain and are never themselves
/// input-execution authority. An identity binds its owning proposal,
/// derivation generation, coordinates, workspace, and policy revision;
/// replayed, foreign, and policy-drifted identities fail closed as stale
/// and stale coordinates are never actionable.
#[derive(Debug, Clone)]
struct CoordinateRecord {
    coord_id: String,
    proposal_id: String,
    frame_id: String,
    window_id: String,
    process_id: String,
    process_generation: u64,
    window_generation: u64,
    capture_generation: u64,
    proposal_generation: u64,
    derivation_generation: u64,
    x: u64,
    y: u64,
    workspace_id: String,
    policy_revision: String,
}

/// One explicit single-use input lease. Leases are minted from a fully
/// validated coordinate binding, bound into the approval digest, and
/// consumed exactly once at execution. A lease binds its owning
/// coordinate identity, click-only operation, the interruption epoch at
/// grant time, expiry, workspace, and policy revision; replayed, expired,
/// revoked, epoch-drifted, and foreign leases fail closed. Unapproved,
/// unconsumed leases are inert: they expire quickly and are swept, and
/// execution is reachable only through the approval-gated dispatch path.
/// Any material human interaction after the grant increments the registry
/// epoch, so this lease fails closed on the next execution and a retry
/// needs a fresh lease bound to the new epoch.
#[derive(Debug, Clone)]
struct LeaseRecord {
    lease_id: String,
    coord_id: String,
    proposal_id: String,
    frame_id: String,
    window_id: String,
    process_id: String,
    process_generation: u64,
    window_generation: u64,
    capture_generation: u64,
    proposal_generation: u64,
    derivation_generation: u64,
    interruption_epoch: u64,
    x: u64,
    y: u64,
    hwnd: u64,
    operation: String,
    expires_at_ms: u64,
    consumed: bool,
    workspace_id: String,
    policy_revision: String,
}

/// Server-side typed identity registry. Identities are allocated here and
/// can never be named by callers; every observation revalidates the exact
/// binding set and fails closed on drift.
///
/// The registry also holds the monotonic human-interruption epoch. The
/// epoch starts at zero, increments exactly once per valid
/// human-interruption report, and never decrements or resets. Every input
/// lease records the epoch at grant time and every execution revalidates
/// it, so material human interaction after a grant revokes the lease.
/// Human physical interaction always wins over Orcel automation.
#[derive(Debug, Default)]
pub struct UiaRegistry {
    processes: HashMap<String, ProcessRecord>,
    windows: HashMap<String, WindowRecord>,
    elements: HashMap<String, ElementRecord>,
    frames: HashMap<String, FrameRecord>,
    proposals: HashMap<String, ProposalRecord>,
    coordinates: HashMap<String, CoordinateRecord>,
    leases: HashMap<String, LeaseRecord>,
    interruption_epoch: u64,
    window_counter: u64,
    tree_counter: u64,
    capture_counter: u64,
    proposal_counter: u64,
    derivation_counter: u64,
    lease_counter: u64,
}

impl UiaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_count(&self) -> usize {
        self.processes.len()
    }

    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    pub fn proposal_count(&self) -> usize {
        self.proposals.len()
    }

    pub fn coordinate_count(&self) -> usize {
        self.coordinates.len()
    }

    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }

    /// Test hook: read whether one lease is consumed.
    pub fn lease_consumed(&self, lease_id: &str) -> Option<bool> {
        self.leases.get(lease_id).map(|record| record.consumed)
    }

    /// Read the current monotonic human-interruption epoch. The epoch
    /// starts at zero and increments exactly once per valid
    /// human-interruption report. Leases record this value at grant time.
    pub fn interruption_epoch(&self) -> u64 {
        self.interruption_epoch
    }

    /// Test hook: read the interruption epoch bound into one lease.
    pub fn lease_interruption_epoch(&self, lease_id: &str) -> Option<u64> {
        self.leases
            .get(lease_id)
            .map(|record| record.interruption_epoch)
    }

    /// Report material human interaction and revoke live lease material.
    /// Only the bounded physical-source reasons increment the epoch;
    /// empty, oversized, and unknown reasons fail closed without mutating
    /// the epoch. The epoch never decrements or resets, so leases granted
    /// before this call fail closed on their next execution and a retry
    /// needs a fresh lease bound to the new epoch. The returned evidence
    /// carries only the epoch, reason, timestamp, workspace, and policy
    /// revision with no input content and no secret material.
    ///
    /// Windows reality: the interactive session broker is the only lawful
    /// caller. It derives reports from narrow user-presence signals (last
    /// input timing with injected-input filtering so Orcel synthetic input
    /// never counts as human, foreground and window interaction, and the
    /// emergency-stop path) and never from keystroke or pointer-path
    /// content. Headless contexts report no physical input instead of
    /// fabricating it; deterministic epoch policy is proven through the
    /// injected fake adapter on every platform.
    pub fn report_human_interruption(
        &mut self,
        reason: &str,
        workspace_id: &str,
        policy_revision: &str,
        now_ms: u64,
    ) -> Result<Value, UiaError> {
        if !is_human_interrupt_reason(reason) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "human-interruption reason is empty, oversized, or unknown and never revokes input authority",
            ));
        }
        if workspace_id.is_empty() || workspace_id.chars().count() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "human-interruption workspace is empty or too large",
            ));
        }
        if policy_revision.is_empty() || policy_revision.chars().count() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "human-interruption policy revision is empty or too large",
            ));
        }
        self.interruption_epoch = self.interruption_epoch.saturating_add(1);
        let result = json!({
            "schema": INTERRUPT_SCHEMA,
            "action": "human-interruption",
            "interruption_epoch": self.interruption_epoch,
            "reason": reason,
            "reported_at_ms": now_ms,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    /// Register or refresh one native process. A changed start generation
    /// for a known PID marks the previous record superseded so the old
    /// identity fails closed instead of silently retargeting. Returns the
    /// server-allocated process identity and its generation.
    pub fn register_process(
        &mut self,
        native: &NativeProcess,
        workspace_id: &str,
        policy_revision: &str,
    ) -> (String, u64) {
        let process_id = allocate_process_id(native.pid, &native.exe_id);
        match self.processes.get(&process_id) {
            Some(existing)
                if existing.process_generation == native.start_generation
                    && existing.exe_id == native.exe_id =>
            {
                (process_id, existing.process_generation)
            }
            Some(_) => {
                if let Some(record) = self.processes.get_mut(&process_id) {
                    record.superseded = true;
                }
                let record = ProcessRecord {
                    process_id: process_id.clone(),
                    pid: native.pid,
                    exe_name: truncate_owned(&native.exe_name, MAX_STRING_CHARS).0,
                    exe_id: native.exe_id.clone(),
                    session_id: native.session_id,
                    session_verified: native.session_verified,
                    process_generation: native.start_generation,
                    generation_source: native.generation_source,
                    workspace_id: workspace_id.to_owned(),
                    policy_revision: policy_revision.to_owned(),
                    superseded: false,
                };
                self.processes.insert(process_id.clone(), record);
                (process_id, native.start_generation)
            }
            None => {
                let record = ProcessRecord {
                    process_id: process_id.clone(),
                    pid: native.pid,
                    exe_name: truncate_owned(&native.exe_name, MAX_STRING_CHARS).0,
                    exe_id: native.exe_id.clone(),
                    session_id: native.session_id,
                    session_verified: native.session_verified,
                    process_generation: native.start_generation,
                    generation_source: native.generation_source,
                    workspace_id: workspace_id.to_owned(),
                    policy_revision: policy_revision.to_owned(),
                    superseded: false,
                };
                self.processes.insert(process_id.clone(), record);
                (process_id, native.start_generation)
            }
        }
    }

    fn require_live_process(
        &self,
        process_id: &str,
        expected_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ProcessRecord, UiaError> {
        let record = self.processes.get(process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia process identity is unknown; it may have exited or never existed",
            )
        })?;
        if record.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia process identity was superseded by a restart and fails closed",
            ));
        }
        if record.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia process identity belongs to another workspace",
            ));
        }
        if record.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia process identity was issued under another policy revision",
            ));
        }
        if record.process_generation != expected_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia process generation drifted; the process may have restarted or its PID may have been reused",
            ));
        }
        Ok(record.clone())
    }

    fn require_live_window(
        &self,
        window_id: &str,
        expected_window_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<WindowRecord, UiaError> {
        let record = self.windows.get(window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia window identity is unknown; it may have been destroyed or never existed",
            )
        })?;
        if record.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window identity belongs to another workspace",
            ));
        }
        if record.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window identity was issued under another policy revision",
            ));
        }
        if record.window_generation != expected_window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window generation drifted; the window may have been destroyed and its handle reused",
            ));
        }
        match self.processes.get(&record.process_id) {
            Some(process) if !process.superseded => Ok(record.clone()),
            _ => Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window identity lost its live owning process",
            )),
        }
    }

    /// Observe one registered process. This is a local registry read with no
    /// adapter access and no OS mutation.
    pub fn observe_process(
        &self,
        process_id: &str,
        expected_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_process_id(process_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia process identity is malformed",
            ));
        }
        let record = self.require_live_process(
            process_id,
            expected_generation,
            workspace_id,
            policy_revision,
        )?;
        Ok(json!({
            "schema": UIA_SCHEMA,
            "process_id": record.process_id,
            "pid": record.pid,
            "exe_name": record.exe_name,
            "exe_id": record.exe_id,
            "session_id": record.session_id,
            "session_verified": record.session_verified,
            "process_generation": record.process_generation,
            "generation_source": record.generation_source,
            "workspace_id": record.workspace_id,
            "policy_revision": record.policy_revision,
        }))
    }

    /// Discover windows through the adapter and bind them into typed
    /// identities. Protected Orcel surfaces are omitted and counted, never
    /// returned. Unknown adapter failures fail closed as unavailable.
    pub fn list_windows(
        &mut self,
        adapter: &impl UiaAdapter,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let natives = adapter.list_processes().map_err(|error| {
            UiaError::new(
                FailureCode::ProviderUnavailable,
                format!("uia process enumeration is unavailable: {}", error.message),
            )
        })?;
        let mut entries: Vec<Value> = Vec::new();
        let mut protected_omitted = 0u64;
        for native_process in natives.iter().take(MAX_WINDOWS) {
            let (owner_id, owner_generation) =
                self.register_process(native_process, workspace_id, policy_revision);
            let native_windows = adapter.list_windows(native_process.pid).map_err(|error| {
                UiaError::new(
                    FailureCode::ProviderUnavailable,
                    format!("uia window enumeration is unavailable: {}", error.message),
                )
            })?;
            for native_window in native_windows.iter().take(MAX_WINDOWS) {
                let record =
                    self.register_window(&owner_id, native_window, workspace_id, policy_revision);
                if is_protected_window(&native_window.title, &native_window.class) {
                    protected_omitted += 1;
                    continue;
                }
                entries.push(json!({
                    "process_id": record.process_id,
                    "process_generation": owner_generation,
                    "exe_name": truncate_owned(&native_process.exe_name, MAX_STRING_CHARS).0,
                    "window_id": record.window_id,
                    "window_generation": record.window_generation,
                    "title": record.title,
                    "class": record.class,
                }));
                if entries.len() >= MAX_WINDOWS {
                    break;
                }
            }
            if entries.len() >= MAX_WINDOWS {
                break;
            }
        }
        let result = json!({
            "schema": UIA_SCHEMA,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
            "windows": entries,
            "window_count": entries.len(),
            "protected_omitted": protected_omitted,
        });
        enforce_response_bytes(&result)
    }

    fn register_window(
        &mut self,
        process_id: &str,
        native: &NativeWindow,
        workspace_id: &str,
        policy_revision: &str,
    ) -> WindowRecord {
        let window_id = allocate_window_id(process_id, native.hwnd);
        self.window_counter += 1;
        match self.windows.get(&window_id) {
            Some(existing)
                if existing.process_id == process_id
                    && existing.window_nonce == native.window_nonce
                    && existing.title == truncate_owned(&native.title, MAX_STRING_CHARS).0
                    && existing.class == truncate_owned(&native.class, MAX_STRING_CHARS).0 =>
            {
                existing.clone()
            }
            Some(_) => {
                self.tree_counter += 1;
                let record = WindowRecord {
                    window_id: window_id.clone(),
                    process_id: process_id.to_owned(),
                    hwnd: native.hwnd,
                    title: truncate_owned(&native.title, MAX_STRING_CHARS).0,
                    class: truncate_owned(&native.class, MAX_STRING_CHARS).0,
                    visible: native.visible,
                    window_nonce: native.window_nonce,
                    window_generation: self.window_counter,
                    tree_generation: self.tree_counter,
                    workspace_id: workspace_id.to_owned(),
                    policy_revision: policy_revision.to_owned(),
                };
                self.remove_window_elements(&window_id);
                self.windows.insert(window_id, record.clone());
                record
            }
            None => {
                self.tree_counter += 1;
                let record = WindowRecord {
                    window_id: window_id.clone(),
                    process_id: process_id.to_owned(),
                    hwnd: native.hwnd,
                    title: truncate_owned(&native.title, MAX_STRING_CHARS).0,
                    class: truncate_owned(&native.class, MAX_STRING_CHARS).0,
                    visible: native.visible,
                    window_nonce: native.window_nonce,
                    window_generation: self.window_counter,
                    tree_generation: self.tree_counter,
                    workspace_id: workspace_id.to_owned(),
                    policy_revision: policy_revision.to_owned(),
                };
                self.windows.insert(window_id, record.clone());
                record
            }
        }
    }

    fn remove_window_elements(&mut self, window_id: &str) {
        let stale: Vec<String> = self
            .elements
            .iter()
            .filter(|(_, element)| element.window_id == window_id)
            .map(|(id, _)| id.clone())
            .collect();
        for id in stale {
            self.elements.remove(&id);
        }
    }

    /// Observe one typed window without reading its tree.
    pub fn observe_window(
        &self,
        window_id: &str,
        expected_window_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_window_id(window_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia window identity is malformed",
            ));
        }
        let record = self.require_live_window(
            window_id,
            expected_window_generation,
            workspace_id,
            policy_revision,
        )?;
        if is_protected_window(&record.title, &record.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia observation of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&record.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia window identity lost its owning process",
            )
        })?;
        let result = json!({
            "schema": UIA_SCHEMA,
            "window_id": record.window_id,
            "process_id": record.process_id,
            "process_generation": process.process_generation,
            "window_generation": record.window_generation,
            "tree_generation": record.tree_generation,
            "title": record.title,
            "class": record.class,
            "visible": record.visible,
            "workspace_id": record.workspace_id,
            "policy_revision": record.policy_revision,
        });
        enforce_response_bytes(&result)
    }

    /// Observe the bounded tree of one typed window. The adapter supplies
    /// the live tree, which is re-registered every call so disappeared,
    /// replaced, and role-changed elements fail closed on the next
    /// observation instead of serving stale snapshots.
    #[allow(clippy::too_many_arguments)]
    pub fn observe_tree(
        &mut self,
        adapter: &impl UiaAdapter,
        window_id: &str,
        expected_window_generation: u64,
        max_depth: Option<u64>,
        max_nodes: Option<u64>,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_window_id(window_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia window identity is malformed",
            ));
        }
        let record = self.require_live_window(
            window_id,
            expected_window_generation,
            workspace_id,
            policy_revision,
        )?;
        if is_protected_window(&record.title, &record.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia observation of a protected Orcel surface is denied",
            ));
        }
        let depth_cap = max_depth
            .unwrap_or(MAX_TREE_DEPTH as u64)
            .min(MAX_TREE_DEPTH as u64);
        let node_cap = max_nodes
            .unwrap_or(MAX_TREE_NODES as u64)
            .min(MAX_TREE_NODES as u64);
        if node_cap == 0 {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia tree observation requires at least one node",
            ));
        }
        // The handle may have been destroyed and reused since listing:
        // re-verify that the same live window of the same process instance
        // still owns it before reading anything.
        let owner_pid = self
            .processes
            .get(&record.process_id)
            .map(|process| process.pid)
            .ok_or_else(|| {
                UiaError::new(
                    FailureCode::TargetStale,
                    "uia window identity lost its owning process",
                )
            })?;
        let live_windows = adapter.list_windows(owner_pid).map_err(|error| {
            UiaError::new(
                FailureCode::ProviderUnavailable,
                format!("uia window enumeration is unavailable: {}", error.message),
            )
        })?;
        let still_bound = live_windows.iter().any(|live| {
            live.hwnd == record.hwnd
                && live.window_nonce == record.window_nonce
                && truncate_owned(&live.class, MAX_STRING_CHARS).0 == record.class
        });
        if !still_bound {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window identity no longer matches a live window; list windows again",
            ));
        }
        let natives = adapter.read_tree(record.hwnd).map_err(|error| {
            UiaError::new(
                FailureCode::ProviderUnavailable,
                format!("uia tree enumeration is unavailable: {}", error.message),
            )
        })?;
        self.tree_counter += 1;
        let tree_generation = self.tree_counter;
        if let Some(stored) = self.windows.get_mut(window_id) {
            stored.tree_generation = tree_generation;
        }
        self.remove_window_elements(window_id);
        let mut rendered: Vec<Value> = Vec::new();
        let mut truncated = false;
        let mut used_bytes = 0usize;
        let mut stack: Vec<(&NativeElement, u64)> = natives
            .iter()
            .rev()
            .map(|element| (element, 0u64))
            .collect();
        while let Some((native, depth)) = stack.pop() {
            if rendered.len() as u64 >= node_cap {
                truncated = true;
                break;
            }
            if depth > depth_cap {
                truncated = true;
                continue;
            }
            let stored = self.store_element(window_id, native, tree_generation);
            let mut node = render_element(&stored);
            node["depth"] = json!(depth);
            used_bytes += serde_json::to_vec(&node)
                .map(|bytes| bytes.len())
                .unwrap_or(0);
            if used_bytes > MAX_RESPONSE_BYTES {
                truncated = true;
                self.elements.remove(&stored.element_id);
                break;
            }
            rendered.push(node);
            for child in native.children.iter().rev() {
                stack.push((child, depth + 1));
            }
        }
        let result = json!({
            "schema": UIA_SCHEMA,
            "window_id": record.window_id,
            "window_generation": record.window_generation,
            "tree_generation": tree_generation,
            "nodes": rendered,
            "node_count": rendered.len(),
            "truncated": truncated,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    fn store_element(
        &mut self,
        window_id: &str,
        native: &NativeElement,
        tree_generation: u64,
    ) -> ElementRecord {
        let element_id = allocate_element_id(window_id, &native.runtime_id);
        let redacted = is_password_field(&native.control_type, &native.automation_id, &native.name)
            || native.value_is_password;
        let (automation_id, automation_truncated) =
            truncate_owned(&native.automation_id, MAX_STRING_CHARS);
        let (name, name_truncated) = truncate_owned(&native.name, MAX_STRING_CHARS);
        let value = if redacted {
            None
        } else {
            native
                .value
                .as_ref()
                .map(|raw| truncate_owned(raw, MAX_STRING_CHARS).0)
        };
        let _ = automation_truncated;
        let _ = name_truncated;
        let record = ElementRecord {
            element_id: element_id.clone(),
            window_id: window_id.to_owned(),
            runtime_id: truncate_owned(&native.runtime_id, MAX_STRING_CHARS).0,
            control_type: truncate_owned(&native.control_type, MAX_STRING_CHARS).0,
            automation_id,
            name,
            enabled: native.enabled,
            selected: native.selected,
            toggled: native.toggled,
            scroll_horizontal_percent: native.scroll_horizontal_percent.min(100),
            scroll_vertical_percent: native.scroll_vertical_percent.min(100),
            patterns: native.patterns.iter().take(16).cloned().collect(),
            value,
            value_is_password: native.value_is_password,
            redacted,
            tree_generation,
        };
        self.elements.insert(element_id, record.clone());
        record
    }

    /// Observe one typed element. The element must belong to the current
    /// tree generation of its window; older identities fail closed.
    pub fn observe_element(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_element_id(element_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia element identity is malformed",
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is unknown; it may have disappeared or never existed",
            )
        })?;
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity was issued under another policy revision",
            ));
        }
        if record.tree_generation != expected_tree_generation
            || record.tree_generation != window.tree_generation
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is stale; the UI tree regenerated and the target must be re-observed",
            ));
        }
        let result = render_element(record);
        enforce_response_bytes(&result)
    }

    /// Test hook: read the current window and tree generations of a window.
    pub fn window_generations(&self, window_id: &str) -> Option<(u64, u64)> {
        self.windows
            .get(window_id)
            .map(|record| (record.window_generation, record.tree_generation))
    }

    /// Test hook: simulate a window replacement behind a reused handle.
    pub fn bump_window_generation(&mut self, window_id: &str) -> bool {
        self.window_counter += 1;
        self.tree_counter += 1;
        let window_counter = self.window_counter;
        let tree_counter = self.tree_counter;
        match self.windows.get_mut(window_id) {
            Some(record) => {
                record.window_generation = window_counter;
                record.tree_generation = tree_counter;
                true
            }
            None => false,
        }
    }

    /// Test hook: simulate a tree regeneration without replacing the window.
    pub fn invalidate_tree(&mut self, window_id: &str) -> bool {
        self.tree_counter += 1;
        let tree_counter = self.tree_counter;
        match self.windows.get_mut(window_id) {
            Some(record) => {
                record.tree_generation = tree_counter;
                true
            }
            None => false,
        }
    }

    /// Test hook: simulate an element disappearing from the live tree.
    pub fn remove_element(&mut self, element_id: &str) -> bool {
        self.elements.remove(element_id).is_some()
    }

    /// Test hook: mark a process record superseded to simulate a restart
    /// behind a reused PID.
    pub fn mark_process_superseded(&mut self, process_id: &str) -> bool {
        match self.processes.get_mut(process_id) {
            Some(record) => {
                record.superseded = true;
                true
            }
            None => false,
        }
    }

    /// Resolve the current invoke binding for approval digest computation.
    /// This performs the same fail-closed revalidation as `invoke_element`
    /// but performs no adapter mutation, so dispatch can bind approval
    /// before actuation and then revalidate again immediately before the
    /// adapter call.
    pub fn invoke_binding(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<InvokeBinding, UiaError> {
        let resolved = self.require_invoke_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            workspace_id,
            policy_revision,
        )?;
        Ok(resolved)
    }

    /// Perform one structured InvokePattern actuation against the injected
    /// adapter after immediate pre-actuation revalidation. Any drift fails
    /// closed without silent retargeting and without fallback to mouse,
    /// keyboard, SendInput, coordinates, screenshots, or elevation. On
    /// success the owning window tree generation is advanced and its
    /// elements are removed so stale identities cannot be replayed.
    pub fn invoke_element(
        &mut self,
        adapter: &impl UiaAdapter,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_invoke_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            workspace_id,
            policy_revision,
        )?;
        adapter
            .invoke_element(binding.hwnd, &binding.runtime_id)
            .map_err(|error| {
                UiaError::new(
                    error.code,
                    format!("uia invoke actuation failed: {}", error.message),
                )
            })?;
        let prior_tree_generation = binding.tree_generation;
        self.tree_counter += 1;
        let new_tree_generation = self.tree_counter;
        if let Some(stored) = self.windows.get_mut(&binding.window_id) {
            stored.tree_generation = new_tree_generation;
        }
        self.remove_window_elements(&binding.window_id);
        let result = json!({
            "schema": INVOKE_SCHEMA,
            "action": "invoke",
            "element_id": binding.element_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "prior_tree_generation": prior_tree_generation,
            "new_tree_generation": new_tree_generation,
            "control_type": binding.control_type,
            "pattern": INVOKE_PATTERN_NAME,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    /// Resolve the current value binding for approval digest computation.
    /// This performs the same fail-closed revalidation as `set_value_element`
    /// but performs no adapter mutation, so dispatch can bind approval
    /// before actuation and then revalidate again immediately before the
    /// adapter call.
    pub fn value_binding(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        value: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ValueBinding, UiaError> {
        let resolved = self.require_value_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            value,
            workspace_id,
            policy_revision,
        )?;
        Ok(resolved)
    }

    /// Perform one structured ValuePattern write against the injected
    /// adapter after immediate pre-actuation revalidation. Any drift fails
    /// closed without silent retargeting and without fallback to keyboard,
    /// clipboard, mouse, SendInput, coordinates, screenshots, or elevation.
    /// On success the owning window tree generation is advanced and its
    /// elements are removed so stale identities cannot be replayed. Evidence
    /// carries only the value digest, never raw value bytes.
    #[allow(clippy::too_many_arguments)]
    pub fn set_value_element(
        &mut self,
        adapter: &impl UiaAdapter,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        value: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_value_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            value,
            workspace_id,
            policy_revision,
        )?;
        adapter
            .set_value_element(binding.hwnd, &binding.runtime_id, value)
            .map_err(|error| {
                UiaError::new(
                    error.code,
                    format!("uia set_value actuation failed: {}", error.message),
                )
            })?;
        let prior_tree_generation = binding.tree_generation;
        self.tree_counter += 1;
        let new_tree_generation = self.tree_counter;
        if let Some(stored) = self.windows.get_mut(&binding.window_id) {
            stored.tree_generation = new_tree_generation;
        }
        self.remove_window_elements(&binding.window_id);
        let result = json!({
            "schema": VALUE_SCHEMA,
            "action": "set_value",
            "element_id": binding.element_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "prior_tree_generation": prior_tree_generation,
            "new_tree_generation": new_tree_generation,
            "control_type": binding.control_type,
            "pattern": VALUE_PATTERN_NAME,
            "value_digest": binding.value_digest,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    /// Resolve the current select binding for approval digest computation.
    /// This performs the same fail-closed revalidation as `select_element`
    /// but performs no adapter mutation, so dispatch can bind approval
    /// before actuation and then revalidate again immediately before the
    /// adapter call.
    #[allow(clippy::too_many_arguments)]
    pub fn select_binding(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_selected: bool,
        selected: bool,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<SelectBinding, UiaError> {
        let resolved = self.require_select_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            expected_selected,
            selected,
            workspace_id,
            policy_revision,
        )?;
        Ok(resolved)
    }

    /// Perform one structured SelectionItem actuation against the injected
    /// adapter after immediate pre-actuation revalidation. Any drift fails
    /// closed without silent retargeting and without fallback to mouse,
    /// keyboard, SendInput, coordinates, screenshots, or elevation. On
    /// success the owning window tree generation is advanced and its
    /// elements are removed so stale identities cannot be replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn select_element(
        &mut self,
        adapter: &impl UiaAdapter,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_selected: bool,
        selected: bool,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_select_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            expected_selected,
            selected,
            workspace_id,
            policy_revision,
        )?;
        adapter
            .select_element(binding.hwnd, &binding.runtime_id, selected)
            .map_err(|error| {
                UiaError::new(
                    error.code,
                    format!("uia select actuation failed: {}", error.message),
                )
            })?;
        let prior_tree_generation = binding.tree_generation;
        self.tree_counter += 1;
        let new_tree_generation = self.tree_counter;
        if let Some(stored) = self.windows.get_mut(&binding.window_id) {
            stored.tree_generation = new_tree_generation;
        }
        self.remove_window_elements(&binding.window_id);
        let result = json!({
            "schema": SELECT_SCHEMA,
            "action": "select",
            "element_id": binding.element_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "prior_tree_generation": prior_tree_generation,
            "new_tree_generation": new_tree_generation,
            "control_type": binding.control_type,
            "pattern": SELECT_PATTERN_NAME,
            "expected_selected": binding.expected_selected,
            "selected": binding.selected,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    #[allow(clippy::too_many_arguments)]
    fn require_select_target(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_selected: bool,
        _selected: bool,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<SelectBinding, UiaError> {
        if !is_well_formed_element_id(element_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia element identity is malformed",
            ));
        }
        if expected_control_type.is_empty() || expected_control_type.len() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia select expected_control_type is empty or too large",
            ));
        }
        if !is_select_eligible_control_type(expected_control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia select actuates only ListItem, TreeItem, and TabItem elements",
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is unknown; it may have disappeared or never existed",
            )
        })?;
        if record.control_type != expected_control_type {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element control type changed since observation; stale targets fail closed",
            ));
        }
        if !is_select_eligible_control_type(&record.control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia select target control type is not eligible for SelectionItem actuation",
            ));
        }
        if !record
            .patterns
            .iter()
            .any(|pattern| pattern == SELECT_PATTERN_NAME)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia select target does not support the SelectionItem pattern; no mouse or keyboard fallback is permitted",
            ));
        }
        if !record.enabled {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia select targets only enabled elements; disabled elements are denied",
            ));
        }
        if record.value_is_password
            || record.redacted
            || is_password_field(&record.control_type, &record.automation_id, &record.name)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia select of a password or secret bearing element is denied",
            ));
        }
        if record.selected != expected_selected {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia select expected selection state drifted; the target must be re-observed",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity was issued under another policy revision",
            ));
        }
        if record.tree_generation != expected_tree_generation
            || record.tree_generation != window.tree_generation
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is stale; the UI tree regenerated and the target must be re-observed",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia select of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&window.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia select target lost its owning process",
            )
        })?;
        if process.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia select target process was superseded by a restart and fails closed",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia select target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia select target process was issued under another policy revision",
            ));
        }
        Ok(SelectBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            element_id: record.element_id.clone(),
            tree_generation: record.tree_generation,
            control_type: record.control_type.clone(),
            expected_selected,
            selected: _selected,
            hwnd: window.hwnd,
            runtime_id: record.runtime_id.clone(),
        })
    }

    /// Resolve the current toggle binding for approval digest computation.
    /// This performs the same fail-closed revalidation as `toggle_element`
    /// but performs no adapter mutation, so dispatch can bind approval
    /// before actuation and then revalidate again immediately before the
    /// adapter call.
    #[allow(clippy::too_many_arguments)]
    pub fn toggle_binding(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_toggled: bool,
        toggled: bool,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ToggleBinding, UiaError> {
        let resolved = self.require_toggle_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            expected_toggled,
            toggled,
            workspace_id,
            policy_revision,
        )?;
        Ok(resolved)
    }

    /// Perform one structured TogglePattern actuation against the injected
    /// adapter after immediate pre-actuation revalidation. Any drift fails
    /// closed without silent retargeting and without fallback to Invoke,
    /// click, Space, Enter, keyboard, mouse, SendInput, coordinates,
    /// screenshots, or elevation. On success the owning window tree
    /// generation is advanced and its elements are removed so stale
    /// identities cannot be replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn toggle_element(
        &mut self,
        adapter: &impl UiaAdapter,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_toggled: bool,
        toggled: bool,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_toggle_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            expected_toggled,
            toggled,
            workspace_id,
            policy_revision,
        )?;
        adapter
            .toggle_element(binding.hwnd, &binding.runtime_id, toggled)
            .map_err(|error| {
                UiaError::new(
                    error.code,
                    format!("uia toggle actuation failed: {}", error.message),
                )
            })?;
        let prior_tree_generation = binding.tree_generation;
        self.tree_counter += 1;
        let new_tree_generation = self.tree_counter;
        if let Some(stored) = self.windows.get_mut(&binding.window_id) {
            stored.tree_generation = new_tree_generation;
        }
        self.remove_window_elements(&binding.window_id);
        let result = json!({
            "schema": TOGGLE_SCHEMA,
            "action": "toggle",
            "element_id": binding.element_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "prior_tree_generation": prior_tree_generation,
            "new_tree_generation": new_tree_generation,
            "control_type": binding.control_type,
            "pattern": TOGGLE_PATTERN_NAME,
            "expected_toggled": binding.expected_toggled,
            "toggled": binding.toggled,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    #[allow(clippy::too_many_arguments)]
    fn require_toggle_target(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_toggled: bool,
        _toggled: bool,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ToggleBinding, UiaError> {
        if !is_well_formed_element_id(element_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia element identity is malformed",
            ));
        }
        if expected_control_type.is_empty() || expected_control_type.len() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia toggle expected_control_type is empty or too large",
            ));
        }
        if !is_toggle_eligible_control_type(expected_control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia toggle actuates only CheckBox and RadioButton elements",
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is unknown; it may have disappeared or never existed",
            )
        })?;
        if record.control_type != expected_control_type {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element control type changed since observation; stale targets fail closed",
            ));
        }
        if !is_toggle_eligible_control_type(&record.control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia toggle target control type is not eligible for TogglePattern actuation",
            ));
        }
        if !record
            .patterns
            .iter()
            .any(|pattern| pattern == TOGGLE_PATTERN_NAME)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia toggle target does not support the Toggle pattern; no Invoke, click, Space, Enter, keyboard, or mouse fallback is permitted",
            ));
        }
        if !record.enabled {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia toggle targets only enabled elements; disabled elements are denied",
            ));
        }
        if record.value_is_password
            || record.redacted
            || is_password_field(&record.control_type, &record.automation_id, &record.name)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia toggle of a password or secret bearing element is denied",
            ));
        }
        if record.toggled != expected_toggled {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia toggle expected toggle state drifted; the target must be re-observed",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity was issued under another policy revision",
            ));
        }
        if record.tree_generation != expected_tree_generation
            || record.tree_generation != window.tree_generation
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is stale; the UI tree regenerated and the target must be re-observed",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia toggle of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&window.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia toggle target lost its owning process",
            )
        })?;
        if process.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia toggle target process was superseded by a restart and fails closed",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia toggle target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia toggle target process was issued under another policy revision",
            ));
        }
        Ok(ToggleBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            element_id: record.element_id.clone(),
            tree_generation: record.tree_generation,
            control_type: record.control_type.clone(),
            expected_toggled,
            toggled: _toggled,
            hwnd: window.hwnd,
            runtime_id: record.runtime_id.clone(),
        })
    }

    /// Resolve the current scroll binding for approval digest computation.
    /// This performs the same fail-closed revalidation as `scroll_element`
    /// but performs no adapter mutation, so dispatch can bind approval
    /// before actuation and then revalidate again immediately before the
    /// adapter call.
    #[allow(clippy::too_many_arguments)]
    pub fn scroll_binding(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_horizontal_percent: u64,
        expected_vertical_percent: u64,
        direction: &str,
        amount: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ScrollBinding, UiaError> {
        let resolved = self.require_scroll_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            expected_horizontal_percent,
            expected_vertical_percent,
            direction,
            amount,
            workspace_id,
            policy_revision,
        )?;
        Ok(resolved)
    }

    /// Perform one structured ScrollPattern actuation against the injected
    /// adapter after immediate pre-actuation revalidation. Any drift fails
    /// closed without silent retargeting and without fallback to wheel,
    /// touch, keyboard paging, mouse, SendInput, coordinates, screenshots,
    /// or elevation. Repeat counts and indefinite scrolling are denied: at
    /// most one bounded scroll executes per approval. On success the owning
    /// window tree generation is advanced and its elements are removed so
    /// stale identities cannot be replayed.
    #[allow(clippy::too_many_arguments)]
    pub fn scroll_element(
        &mut self,
        adapter: &impl UiaAdapter,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_horizontal_percent: u64,
        expected_vertical_percent: u64,
        direction: &str,
        amount: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_scroll_target(
            element_id,
            expected_tree_generation,
            expected_control_type,
            expected_horizontal_percent,
            expected_vertical_percent,
            direction,
            amount,
            workspace_id,
            policy_revision,
        )?;
        adapter
            .scroll_element(binding.hwnd, &binding.runtime_id, direction, amount)
            .map_err(|error| {
                UiaError::new(
                    error.code,
                    format!("uia scroll actuation failed: {}", error.message),
                )
            })?;
        let prior_tree_generation = binding.tree_generation;
        self.tree_counter += 1;
        let new_tree_generation = self.tree_counter;
        if let Some(stored) = self.windows.get_mut(&binding.window_id) {
            stored.tree_generation = new_tree_generation;
        }
        self.remove_window_elements(&binding.window_id);
        let result = json!({
            "schema": SCROLL_SCHEMA,
            "action": "scroll",
            "element_id": binding.element_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "prior_tree_generation": prior_tree_generation,
            "new_tree_generation": new_tree_generation,
            "control_type": binding.control_type,
            "pattern": SCROLL_PATTERN_NAME,
            "expected_horizontal_percent": binding.expected_horizontal_percent,
            "expected_vertical_percent": binding.expected_vertical_percent,
            "direction": binding.direction,
            "amount": binding.amount,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    #[allow(clippy::too_many_arguments)]
    fn require_scroll_target(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        expected_horizontal_percent: u64,
        expected_vertical_percent: u64,
        direction: &str,
        amount: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ScrollBinding, UiaError> {
        if !is_well_formed_element_id(element_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia element identity is malformed",
            ));
        }
        if expected_control_type.is_empty() || expected_control_type.len() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia scroll expected_control_type is empty or too large",
            ));
        }
        if !is_scroll_eligible_control_type(expected_control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia scroll actuates only ScrollBar, Pane, List, and Tree elements",
            ));
        }
        if !is_scroll_direction(direction) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia scroll direction must be one of up, down, left, or right",
            ));
        }
        if !(1..=MAX_SCROLL_AMOUNT).contains(&amount) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia scroll amount must be between 1 and 100 inclusive",
            ));
        }
        if expected_horizontal_percent > 100 || expected_vertical_percent > 100 {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia scroll expected scroll position must be between 0 and 100 inclusive",
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is unknown; it may have disappeared or never existed",
            )
        })?;
        if record.control_type != expected_control_type {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element control type changed since observation; stale targets fail closed",
            ));
        }
        if !is_scroll_eligible_control_type(&record.control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia scroll target control type is not eligible for ScrollPattern actuation",
            ));
        }
        if !record
            .patterns
            .iter()
            .any(|pattern| pattern == SCROLL_PATTERN_NAME)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia scroll target does not support the Scroll pattern; no wheel, touch, keyboard-paging, or mouse fallback is permitted",
            ));
        }
        if !record.enabled {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia scroll targets only enabled elements; disabled elements are denied",
            ));
        }
        if record.value_is_password
            || record.redacted
            || is_password_field(&record.control_type, &record.automation_id, &record.name)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia scroll of a password or secret bearing element is denied",
            ));
        }
        if u64::from(record.scroll_horizontal_percent) != expected_horizontal_percent
            || u64::from(record.scroll_vertical_percent) != expected_vertical_percent
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia scroll expected scroll position drifted; the target must be re-observed",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity was issued under another policy revision",
            ));
        }
        if record.tree_generation != expected_tree_generation
            || record.tree_generation != window.tree_generation
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is stale; the UI tree regenerated and the target must be re-observed",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia scroll of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&window.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia scroll target lost its owning process",
            )
        })?;
        if process.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia scroll target process was superseded by a restart and fails closed",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia scroll target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia scroll target process was issued under another policy revision",
            ));
        }
        Ok(ScrollBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            element_id: record.element_id.clone(),
            tree_generation: record.tree_generation,
            control_type: record.control_type.clone(),
            expected_horizontal_percent: expected_horizontal_percent as u8,
            expected_vertical_percent: expected_vertical_percent as u8,
            direction: direction.to_owned(),
            amount,
            hwnd: window.hwnd,
            runtime_id: record.runtime_id.clone(),
        })
    }

    /// Resolve the current capture binding for approval digest computation.
    /// This performs the same fail-closed revalidation as `capture_window`
    /// but performs no adapter capture, so dispatch can bind approval
    /// before capture and then revalidate again immediately before the
    /// adapter call.
    pub fn capture_binding(
        &self,
        window_id: &str,
        expected_window_generation: u64,
        scope: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<CaptureBinding, UiaError> {
        self.require_capture_target(
            window_id,
            expected_window_generation,
            scope,
            workspace_id,
            policy_revision,
        )
    }

    /// Perform one window-scoped screenshot capture against the adapter
    /// after immediate pre-capture revalidation. Any drift fails closed
    /// without silent retargeting and without fallback to monitor scope,
    /// desktop scope, caller-selected regions, visual target proposals,
    /// coordinate proposals, input execution, clipboard, network, or
    /// elevation. On success a server-allocated typed frame identity is
    /// minted with a fresh capture generation and the exact geometry; the
    /// frame is evidence for successor visual grains and never grants
    /// coordinate or input authority. Oversized or geometry-mismatched
    /// payloads fail closed with no silent downscaling.
    pub fn capture_window(
        &mut self,
        adapter: &impl UiaAdapter,
        window_id: &str,
        expected_window_generation: u64,
        scope: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_capture_target(
            window_id,
            expected_window_generation,
            scope,
            workspace_id,
            policy_revision,
        )?;
        let image = adapter.capture_window(binding.hwnd).map_err(|error| {
            UiaError::new(
                error.code,
                format!("window-scoped screenshot capture failed: {}", error.message),
            )
        })?;
        if image.width == 0
            || image.height == 0
            || image.width > MAX_CAPTURE_WIDTH
            || image.height > MAX_CAPTURE_HEIGHT
        {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "screenshot capture geometry is empty or exceeds the bounded dimensions",
            ));
        }
        let expected_len = (image.width as usize)
            .checked_mul(image.height as usize)
            .and_then(|pixels| pixels.checked_mul(4));
        match expected_len {
            Some(len) if len == image.bytes.len() && len <= MAX_CAPTURE_BYTES => {}
            _ => {
                return Err(UiaError::new(
                    FailureCode::OutputLimit,
                    "screenshot capture payload exceeds the bounded size or mismatches its geometry",
                ));
            }
        }
        self.capture_counter += 1;
        let capture_generation = self.capture_counter;
        let frame_id = allocate_frame_id(&binding.window_id, capture_generation);
        let payload_digest = capture_payload_digest(&image.bytes);
        self.frames.insert(
            frame_id.clone(),
            FrameRecord {
                frame_id: frame_id.clone(),
                window_id: binding.window_id.clone(),
                process_id: binding.process_id.clone(),
                process_generation: binding.process_generation,
                window_generation: binding.window_generation,
                capture_generation,
                width: image.width,
                height: image.height,
                payload_digest: payload_digest.clone(),
                workspace_id: workspace_id.to_owned(),
                policy_revision: policy_revision.to_owned(),
            },
        );
        let result = json!({
            "schema": CAPTURE_SCHEMA,
            "action": "capture",
            "frame_id": frame_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "capture_generation": capture_generation,
            "scope": CAPTURE_SCOPE_TARGET_WINDOW,
            "pixel_format": CAPTURE_PIXEL_FORMAT,
            "encoding": "base64",
            "width": image.width,
            "height": image.height,
            "payload_digest": payload_digest,
            "pixels_b64": base64_encode(&image.bytes),
            "truncated": false,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes_with_limit(
            &result,
            MAX_CAPTURE_RESPONSE_BYTES,
            "screenshot capture exceeded the bounded response size",
        )
    }

    /// Describe one server-allocated capture frame without returning raw
    /// pixels. Successor visual grains validate frames through this
    /// read-only check; replayed, foreign, generation-drifted, and
    /// policy-drifted frames fail closed as stale. A missing or denied
    /// frame is never actionable and never becomes coordinate authority.
    pub fn describe_frame(
        &self,
        frame_id: &str,
        expected_capture_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_frame_id(frame_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "screenshot frame identity is malformed",
            ));
        }
        let record = self.frames.get(frame_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame identity is unknown or stale and is never actionable",
            )
        })?;
        if record.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame identity belongs to another workspace",
            ));
        }
        if record.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame identity was issued under another policy revision",
            ));
        }
        if record.capture_generation != expected_capture_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame generation drifted; the frame is stale and never actionable",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame lost its owning window",
            )
        })?;
        if window.window_generation != record.window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame owning window drifted; the frame is stale and never actionable",
            ));
        }
        let process = self.processes.get(&record.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame lost its owning process",
            )
        })?;
        if process.superseded || process.process_generation != record.process_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame owning process drifted; the frame is stale and never actionable",
            ));
        }
        Ok(json!({
            "schema": CAPTURE_SCHEMA,
            "frame_id": record.frame_id,
            "window_id": record.window_id,
            "process_id": record.process_id,
            "process_generation": record.process_generation,
            "window_generation": record.window_generation,
            "capture_generation": record.capture_generation,
            "scope": CAPTURE_SCOPE_TARGET_WINDOW,
            "pixel_format": CAPTURE_PIXEL_FORMAT,
            "width": record.width,
            "height": record.height,
            "payload_digest": record.payload_digest,
            "workspace_id": record.workspace_id,
            "policy_revision": record.policy_revision,
        }))
    }

    fn require_capture_target(
        &self,
        window_id: &str,
        expected_window_generation: u64,
        scope: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<CaptureBinding, UiaError> {
        if !is_well_formed_window_id(window_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia window identity is malformed",
            ));
        }
        if !is_capture_scope(scope) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "screenshot capture scope is fixed to the target window; monitor scope, desktop scope, and caller-selected regions are denied",
            ));
        }
        let window = self.windows.get(window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia window identity is unknown; it may have been destroyed or never existed",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window identity was issued under another policy revision",
            ));
        }
        if window.window_generation != expected_window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia window generation drifted; the window may have been destroyed and its handle reused",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "screenshot capture of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&window.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "screenshot capture target lost its owning process",
            )
        })?;
        if process.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot capture target process was superseded by a restart and fails closed",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot capture target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot capture target process was issued under another policy revision",
            ));
        }
        Ok(CaptureBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            scope: CAPTURE_SCOPE_TARGET_WINDOW.to_owned(),
            hwnd: window.hwnd,
        })
    }

    /// Resolve the current proposal binding for approval digest
    /// computation. This performs the same fail-closed revalidation as
    /// `propose_visual_target` but mints no proposal identity, so dispatch
    /// can bind approval before proposing and then revalidate again
    /// immediately before minting.
    pub fn proposal_binding(
        &self,
        frame_id: &str,
        expected_capture_generation: u64,
        region: VisualRegion,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ProposalBinding, UiaError> {
        self.require_proposal_target(
            frame_id,
            expected_capture_generation,
            region,
            workspace_id,
            policy_revision,
        )
    }

    /// Mint one non-actuating visual target proposal against a live frame
    /// after immediate pre-proposal revalidation. Any drift fails closed
    /// without silent retargeting and without fallback to coordinate
    /// derivation, input execution, clipboard, network, or elevation. The
    /// region must lie inside the exact frame geometry; oversized,
    /// frame-external, and empty regions fail closed with no silent
    /// expansion. On success a server-allocated typed proposal identity is
    /// minted with a fresh proposal generation; the proposal is evidence
    /// for successor coordinate grains and never grants coordinate or
    /// input authority.
    pub fn propose_visual_target(
        &mut self,
        frame_id: &str,
        expected_capture_generation: u64,
        region: VisualRegion,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_proposal_target(
            frame_id,
            expected_capture_generation,
            region,
            workspace_id,
            policy_revision,
        )?;
        self.proposal_counter += 1;
        let proposal_generation = self.proposal_counter;
        let proposal_id = allocate_proposal_id(&binding.frame_id, proposal_generation);
        self.proposals.insert(
            proposal_id.clone(),
            ProposalRecord {
                proposal_id: proposal_id.clone(),
                frame_id: binding.frame_id.clone(),
                window_id: binding.window_id.clone(),
                process_id: binding.process_id.clone(),
                process_generation: binding.process_generation,
                window_generation: binding.window_generation,
                capture_generation: binding.capture_generation,
                proposal_generation,
                region_x: region.x,
                region_y: region.y,
                region_width: region.width,
                region_height: region.height,
                workspace_id: workspace_id.to_owned(),
                policy_revision: policy_revision.to_owned(),
            },
        );
        let result = json!({
            "schema": VISUAL_SCHEMA,
            "action": "propose",
            "proposal_id": proposal_id,
            "frame_id": binding.frame_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "capture_generation": binding.capture_generation,
            "proposal_generation": proposal_generation,
            "region": {
                "x": region.x,
                "y": region.y,
                "width": region.width,
                "height": region.height,
            },
            "frame_width": binding.frame_width,
            "frame_height": binding.frame_height,
            "truncated": false,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    /// Describe one server-allocated proposal without granting any
    /// execution authority. Successor coordinate grains validate proposals
    /// through this read-only check; replayed, foreign,
    /// generation-drifted, and policy-drifted proposals fail closed as
    /// stale. A missing or denied proposal is never actionable and never
    /// becomes coordinate authority.
    pub fn describe_proposal(
        &self,
        proposal_id: &str,
        expected_proposal_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_proposal_id(proposal_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "visual proposal identity is malformed",
            ));
        }
        let record = self.proposals.get(proposal_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal identity is unknown or stale and is never actionable",
            )
        })?;
        if record.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal identity belongs to another workspace",
            ));
        }
        if record.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal identity was issued under another policy revision",
            ));
        }
        if record.proposal_generation != expected_proposal_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal generation drifted; the proposal is stale and never actionable",
            ));
        }
        let frame = self.frames.get(&record.frame_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal lost its owning frame",
            )
        })?;
        if frame.capture_generation != record.capture_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal owning frame drifted; the proposal is stale and never actionable",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal lost its owning window",
            )
        })?;
        if window.window_generation != record.window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal owning window drifted; the proposal is stale and never actionable",
            ));
        }
        let process = self.processes.get(&record.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal lost its owning process",
            )
        })?;
        if process.superseded || process.process_generation != record.process_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal owning process drifted; the proposal is stale and never actionable",
            ));
        }
        Ok(json!({
            "schema": VISUAL_SCHEMA,
            "proposal_id": record.proposal_id,
            "frame_id": record.frame_id,
            "window_id": record.window_id,
            "process_id": record.process_id,
            "process_generation": record.process_generation,
            "window_generation": record.window_generation,
            "capture_generation": record.capture_generation,
            "proposal_generation": record.proposal_generation,
            "region": {
                "x": record.region_x,
                "y": record.region_y,
                "width": record.region_width,
                "height": record.region_height,
            },
            "workspace_id": record.workspace_id,
            "policy_revision": record.policy_revision,
        }))
    }

    fn require_proposal_target(
        &self,
        frame_id: &str,
        expected_capture_generation: u64,
        region: VisualRegion,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ProposalBinding, UiaError> {
        if !is_well_formed_frame_id(frame_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "screenshot frame identity is malformed",
            ));
        }
        if region.width == 0 || region.height == 0 {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "visual proposal region is empty",
            ));
        }
        let frame = self.frames.get(frame_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame identity is unknown or stale and is never actionable",
            )
        })?;
        if frame.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame identity belongs to another workspace",
            ));
        }
        if frame.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame identity was issued under another policy revision",
            ));
        }
        if frame.capture_generation != expected_capture_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "screenshot frame generation drifted; the frame is stale and never actionable",
            ));
        }
        let right = region.x.checked_add(region.width).ok_or_else(|| {
            UiaError::new(
                FailureCode::InvalidRequest,
                "visual proposal region overflows its bounds",
            )
        })?;
        let bottom = region.y.checked_add(region.height).ok_or_else(|| {
            UiaError::new(
                FailureCode::InvalidRequest,
                "visual proposal region overflows its bounds",
            )
        })?;
        if right > u64::from(frame.width) || bottom > u64::from(frame.height) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "visual proposal region exceeds the exact frame geometry",
            ));
        }
        let window = self.windows.get(&frame.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal target lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal target window belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal target window was issued under another policy revision",
            ));
        }
        if window.window_generation != frame.window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal owning window drifted; the frame is stale and never actionable",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "visual target proposal on a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&frame.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal target lost its owning process",
            )
        })?;
        if process.superseded || process.process_generation != frame.process_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal owning process drifted; the frame is stale and never actionable",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal target process was issued under another policy revision",
            ));
        }
        Ok(ProposalBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            frame_id: frame.frame_id.clone(),
            capture_generation: frame.capture_generation,
            region,
            frame_width: frame.width,
            frame_height: frame.height,
        })
    }

    /// Resolve the current derivation binding for approval digest
    /// computation. This performs the same fail-closed revalidation as
    /// `derive_coordinates` but mints no coordinate identity, so dispatch
    /// can bind approval before derivation and then revalidate again
    /// immediately before minting.
    pub fn derivation_binding(
        &self,
        proposal_id: &str,
        expected_proposal_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<DerivationBinding, UiaError> {
        self.require_derivation_target(
            proposal_id,
            expected_proposal_generation,
            workspace_id,
            policy_revision,
        )
    }

    /// Derive deterministic frame-relative coordinates from one live
    /// proposal after immediate pre-derivation revalidation. Any drift
    /// fails closed without silent retargeting and without fallback to
    /// raw coordinate requests, input execution, clipboard, network, or
    /// elevation. Callers supply no coordinates: the coordinates are
    /// computed from the exact bounded proposal region. Derivation never
    /// calls any input API. On success a server-allocated typed
    /// coordinate identity is minted with a fresh derivation generation;
    /// the identity is evidence for the successor input grain and never
    /// grants input authority.
    pub fn derive_coordinates(
        &mut self,
        proposal_id: &str,
        expected_proposal_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        let binding = self.require_derivation_target(
            proposal_id,
            expected_proposal_generation,
            workspace_id,
            policy_revision,
        )?;
        self.derivation_counter += 1;
        let derivation_generation = self.derivation_counter;
        let coord_id = allocate_coord_id(&binding.proposal_id, derivation_generation);
        self.coordinates.insert(
            coord_id.clone(),
            CoordinateRecord {
                coord_id: coord_id.clone(),
                proposal_id: binding.proposal_id.clone(),
                frame_id: binding.frame_id.clone(),
                window_id: binding.window_id.clone(),
                process_id: binding.process_id.clone(),
                process_generation: binding.process_generation,
                window_generation: binding.window_generation,
                capture_generation: binding.capture_generation,
                proposal_generation: binding.proposal_generation,
                derivation_generation,
                x: binding.x,
                y: binding.y,
                workspace_id: workspace_id.to_owned(),
                policy_revision: policy_revision.to_owned(),
            },
        );
        let result = json!({
            "schema": COORD_SCHEMA,
            "action": "propose",
            "coord_id": coord_id,
            "proposal_id": binding.proposal_id,
            "frame_id": binding.frame_id,
            "window_id": binding.window_id,
            "process_id": binding.process_id,
            "process_generation": binding.process_generation,
            "window_generation": binding.window_generation,
            "capture_generation": binding.capture_generation,
            "proposal_generation": binding.proposal_generation,
            "derivation_generation": derivation_generation,
            "x": binding.x,
            "y": binding.y,
            "frame_width": binding.frame_width,
            "frame_height": binding.frame_height,
            "truncated": false,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    /// Describe one server-allocated coordinate identity without granting
    /// any execution authority. The successor input grain validates
    /// coordinate identities through this read-only check; replayed,
    /// foreign, generation-drifted, and policy-drifted identities fail
    /// closed as stale. A missing or denied coordinate identity is never
    /// actionable and never becomes input authority.
    pub fn describe_coordinates(
        &self,
        coord_id: &str,
        expected_derivation_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_coord_id(coord_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "derived coordinate identity is malformed",
            ));
        }
        let record = self.coordinates.get(coord_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "derived coordinate identity is unknown or stale and is never actionable",
            )
        })?;
        if record.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinate identity belongs to another workspace",
            ));
        }
        if record.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinate identity was issued under another policy revision",
            ));
        }
        if record.derivation_generation != expected_derivation_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinate generation drifted; the coordinates are stale and never actionable",
            ));
        }
        let proposal = self.proposals.get(&record.proposal_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates lost their owning proposal",
            )
        })?;
        if proposal.proposal_generation != record.proposal_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates owning proposal drifted; the coordinates are stale and never actionable",
            ));
        }
        let frame = self.frames.get(&record.frame_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates lost their owning frame",
            )
        })?;
        if frame.capture_generation != record.capture_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates owning frame drifted; the coordinates are stale and never actionable",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates lost their owning window",
            )
        })?;
        if window.window_generation != record.window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates owning window drifted; the coordinates are stale and never actionable",
            ));
        }
        let process = self.processes.get(&record.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates lost their owning process",
            )
        })?;
        if process.superseded || process.process_generation != record.process_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinates owning process drifted; the coordinates are stale and never actionable",
            ));
        }
        Ok(json!({
            "schema": COORD_SCHEMA,
            "coord_id": record.coord_id,
            "proposal_id": record.proposal_id,
            "frame_id": record.frame_id,
            "window_id": record.window_id,
            "process_id": record.process_id,
            "process_generation": record.process_generation,
            "window_generation": record.window_generation,
            "capture_generation": record.capture_generation,
            "proposal_generation": record.proposal_generation,
            "derivation_generation": record.derivation_generation,
            "x": record.x,
            "y": record.y,
            "workspace_id": record.workspace_id,
            "policy_revision": record.policy_revision,
        }))
    }

    fn require_derivation_target(
        &self,
        proposal_id: &str,
        expected_proposal_generation: u64,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<DerivationBinding, UiaError> {
        if !is_well_formed_proposal_id(proposal_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "visual proposal identity is malformed",
            ));
        }
        let proposal = self.proposals.get(proposal_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "visual proposal identity is unknown or stale and is never actionable",
            )
        })?;
        if proposal.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal identity belongs to another workspace",
            ));
        }
        if proposal.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal identity was issued under another policy revision",
            ));
        }
        if proposal.proposal_generation != expected_proposal_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "visual proposal generation drifted; the proposal is stale and never actionable",
            ));
        }
        let frame = self.frames.get(&proposal.frame_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation lost its owning frame",
            )
        })?;
        if frame.capture_generation != proposal.capture_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation owning frame drifted; the proposal is stale and never actionable",
            ));
        }
        let window = self.windows.get(&proposal.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation target window belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation target window was issued under another policy revision",
            ));
        }
        if window.window_generation != proposal.window_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation owning window drifted; the proposal is stale and never actionable",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "coordinate derivation for a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&proposal.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation lost its owning process",
            )
        })?;
        if process.superseded || process.process_generation != proposal.process_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation owning process drifted; the proposal is stale and never actionable",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "coordinate derivation target process was issued under another policy revision",
            ));
        }
        let region = VisualRegion {
            x: proposal.region_x,
            y: proposal.region_y,
            width: proposal.region_width,
            height: proposal.region_height,
        };
        let derived = derive_region_center(region);
        Ok(DerivationBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            frame_id: frame.frame_id.clone(),
            capture_generation: frame.capture_generation,
            proposal_id: proposal.proposal_id.clone(),
            proposal_generation: proposal.proposal_generation,
            x: derived.x,
            y: derived.y,
            frame_width: frame.width,
            frame_height: frame.height,
        })
    }

    /// Mint one explicit single-use input lease from a fully validated
    /// coordinate binding. The lease is inert until the approval-gated
    /// dispatch path consumes it exactly once: execution is unreachable
    /// without fresh approval bound to this exact lease. Expired leases
    /// are swept on every grant; grants beyond the live-lease bound fail
    /// closed so no standing input session can accumulate. The lease
    /// records the current interruption epoch, so material human
    /// interaction after this grant revokes the lease on its next
    /// execution.
    pub fn grant_input_lease(
        &mut self,
        coord_id: &str,
        expected_derivation_generation: u64,
        operation: &str,
        workspace_id: &str,
        policy_revision: &str,
        now_ms: u64,
    ) -> Result<ExecuteBinding, UiaError> {
        if !is_execute_operation(operation) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "bounded input execution actuates only the click operation",
            ));
        }
        let coordinate = self.coordinates.get(coord_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "derived coordinate identity is unknown or stale and is never actionable",
            )
        })?;
        if coordinate.derivation_generation != expected_derivation_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "derived coordinate generation drifted; the coordinates are stale and never actionable",
            ));
        }
        let snapshot = coordinate.clone();
        let derivation = self.require_derivation_target(
            &snapshot.proposal_id,
            snapshot.proposal_generation,
            workspace_id,
            policy_revision,
        )?;
        if derivation.frame_id != snapshot.frame_id
            || derivation.x != snapshot.x
            || derivation.y != snapshot.y
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease coordinate binding drifted; the lease is revoked",
            ));
        }
        self.sweep_expired_leases(now_ms);
        let live = self.leases.values().filter(|lease| !lease.consumed).count();
        if live >= MAX_LEASES {
            return Err(UiaError::new(
                FailureCode::OutputLimit,
                "input lease bound reached; no standing input session is permitted",
            ));
        }
        let window = self.windows.get(&derivation.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "bounded execution lost its owning window",
            )
        })?;
        self.lease_counter += 1;
        let lease_id = allocate_lease_id(&snapshot.coord_id, self.lease_counter);
        let expires_at_ms = now_ms.saturating_add(LEASE_TTL_MS);
        self.leases.insert(
            lease_id.clone(),
            LeaseRecord {
                lease_id: lease_id.clone(),
                coord_id: snapshot.coord_id.clone(),
                proposal_id: snapshot.proposal_id.clone(),
                frame_id: snapshot.frame_id.clone(),
                window_id: snapshot.window_id.clone(),
                process_id: snapshot.process_id.clone(),
                process_generation: snapshot.process_generation,
                window_generation: snapshot.window_generation,
                capture_generation: snapshot.capture_generation,
                proposal_generation: snapshot.proposal_generation,
                derivation_generation: snapshot.derivation_generation,
                interruption_epoch: self.interruption_epoch,
                x: snapshot.x,
                y: snapshot.y,
                hwnd: window.hwnd,
                operation: EXECUTE_OPERATION_CLICK.to_owned(),
                expires_at_ms,
                consumed: false,
                workspace_id: workspace_id.to_owned(),
                policy_revision: policy_revision.to_owned(),
            },
        );
        Ok(ExecuteBinding {
            process_id: snapshot.process_id,
            process_generation: snapshot.process_generation,
            window_id: snapshot.window_id,
            window_generation: snapshot.window_generation,
            frame_id: snapshot.frame_id,
            capture_generation: snapshot.capture_generation,
            proposal_id: snapshot.proposal_id,
            proposal_generation: snapshot.proposal_generation,
            coord_id: snapshot.coord_id,
            derivation_generation: snapshot.derivation_generation,
            interruption_epoch: self.interruption_epoch,
            x: snapshot.x,
            y: snapshot.y,
            hwnd: window.hwnd,
            operation: EXECUTE_OPERATION_CLICK.to_owned(),
            lease_id,
            lease_expires_at_ms: expires_at_ms,
        })
    }

    /// Execute one bounded click under an explicit single-use input lease
    /// after immediate pre-execution revalidation of the entire identity
    /// chain. Any drift fails closed without silent retargeting and
    /// without fallback to keyboard, drag, clipboard, network, or
    /// elevation. Replayed, expired, revoked, epoch-drifted, and foreign
    /// leases fail closed. A human-interruption report after the grant
    /// increments the registry epoch, so the lease fails closed here and
    /// a retry needs a fresh lease and fresh approval; interrupted actions
    /// are never replayed and queued continuations never run. Adapter
    /// failure does not consume the lease, but the approval is already
    /// one-shot consumed by dispatch, so a retry requires fresh approval.
    /// On success the lease is consumed exactly once and the evidence
    /// carries only identities, generations, coordinates, operation,
    /// lease, and approval record material.
    pub fn execute_input(
        &mut self,
        adapter: &impl UiaAdapter,
        lease_id: &str,
        workspace_id: &str,
        policy_revision: &str,
        now_ms: u64,
    ) -> Result<Value, UiaError> {
        if !is_well_formed_lease_id(lease_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "input lease identity is malformed",
            ));
        }
        self.sweep_expired_leases(now_ms);
        let lease = self.leases.get(lease_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "input lease is unknown, consumed, or expired and is never reusable",
            )
        })?;
        if lease.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease belongs to another workspace",
            ));
        }
        if lease.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease was issued under another policy revision",
            ));
        }
        if now_ms > lease.expires_at_ms {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease expired before execution",
            ));
        }
        if lease.operation != EXECUTE_OPERATION_CLICK {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "bounded input execution actuates only the click operation",
            ));
        }
        if lease.interruption_epoch != self.interruption_epoch {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "human interruption revoked this input lease; automation must stop and a retry needs a fresh lease and fresh approval",
            ));
        }
        let snapshot = lease.clone();
        let coordinate = self.coordinates.get(&snapshot.coord_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "input lease lost its owning coordinate identity",
            )
        })?;
        if coordinate.derivation_generation != snapshot.derivation_generation
            || coordinate.proposal_id != snapshot.proposal_id
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease coordinate identity drifted; the lease is revoked",
            ));
        }
        let proposal = self.proposals.get(&snapshot.proposal_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "input lease lost its owning proposal",
            )
        })?;
        if proposal.proposal_generation != snapshot.proposal_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease owning proposal drifted; the lease is revoked",
            ));
        }
        let frame = self.frames.get(&snapshot.frame_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "input lease lost its owning frame",
            )
        })?;
        if frame.capture_generation != snapshot.capture_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease owning frame drifted; the lease is revoked",
            ));
        }
        let window = self.windows.get(&snapshot.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "input lease lost its owning window",
            )
        })?;
        if window.window_generation != snapshot.window_generation || window.hwnd != snapshot.hwnd {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease owning window drifted; the lease is revoked",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "bounded input execution on a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&snapshot.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "input lease lost its owning process",
            )
        })?;
        if process.superseded || process.process_generation != snapshot.process_generation {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease owning process drifted; the lease is revoked",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "input lease target process was issued under another policy revision",
            ));
        }
        adapter
            .execute_click(snapshot.hwnd, snapshot.x, snapshot.y)
            .map_err(|error| {
                UiaError::new(
                    error.code,
                    format!("bounded input execution failed: {}", error.message),
                )
            })?;
        if let Some(stored) = self.leases.get_mut(lease_id) {
            stored.consumed = true;
        }
        let result = json!({
            "schema": EXECUTE_SCHEMA,
            "action": "execute",
            "lease_id": snapshot.lease_id,
            "coord_id": snapshot.coord_id,
            "proposal_id": snapshot.proposal_id,
            "frame_id": snapshot.frame_id,
            "window_id": snapshot.window_id,
            "process_id": snapshot.process_id,
            "process_generation": snapshot.process_generation,
            "window_generation": snapshot.window_generation,
            "capture_generation": snapshot.capture_generation,
            "proposal_generation": snapshot.proposal_generation,
            "derivation_generation": snapshot.derivation_generation,
            "interruption_epoch": snapshot.interruption_epoch,
            "x": snapshot.x,
            "y": snapshot.y,
            "operation": EXECUTE_OPERATION_CLICK,
            "workspace_id": workspace_id,
            "policy_revision": policy_revision,
        });
        enforce_response_bytes(&result)
    }

    fn sweep_expired_leases(&mut self, now_ms: u64) {
        self.leases
            .retain(|_, lease| !lease.consumed && lease.expires_at_ms >= now_ms);
    }

    fn require_value_target(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        value: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<ValueBinding, UiaError> {
        if !is_well_formed_element_id(element_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia element identity is malformed",
            ));
        }
        if expected_control_type.is_empty() || expected_control_type.len() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia set_value expected_control_type is empty or too large",
            ));
        }
        if !is_value_eligible_control_type(expected_control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia set_value actuates only Edit, Document, and ComboBox elements",
            ));
        }
        if value.chars().count() > MAX_VALUE_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia set_value value exceeds the bounded length",
            ));
        }
        if value.contains('\0') {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia set_value value contains a NUL byte",
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is unknown; it may have disappeared or never existed",
            )
        })?;
        if record.control_type != expected_control_type {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element control type changed since observation; stale targets fail closed",
            ));
        }
        if !is_value_eligible_control_type(&record.control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia set_value target control type is not eligible for ValuePattern actuation",
            ));
        }
        if !record
            .patterns
            .iter()
            .any(|pattern| pattern == VALUE_PATTERN_NAME)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia set_value target does not support the Value pattern; no keyboard or clipboard fallback is permitted",
            ));
        }
        if !record.enabled {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia set_value targets only enabled elements; disabled elements are denied",
            ));
        }
        if record.value_is_password
            || record.redacted
            || is_password_field(&record.control_type, &record.automation_id, &record.name)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia set_value of a password or secret bearing element is denied",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity was issued under another policy revision",
            ));
        }
        if record.tree_generation != expected_tree_generation
            || record.tree_generation != window.tree_generation
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is stale; the UI tree regenerated and the target must be re-observed",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia set_value of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&window.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia set_value target lost its owning process",
            )
        })?;
        if process.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia set_value target process was superseded by a restart and fails closed",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia set_value target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia set_value target process was issued under another policy revision",
            ));
        }
        Ok(ValueBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            element_id: record.element_id.clone(),
            tree_generation: record.tree_generation,
            control_type: record.control_type.clone(),
            value_digest: value_content_digest(value),
            hwnd: window.hwnd,
            runtime_id: record.runtime_id.clone(),
        })
    }

    fn require_invoke_target(
        &self,
        element_id: &str,
        expected_tree_generation: u64,
        expected_control_type: &str,
        workspace_id: &str,
        policy_revision: &str,
    ) -> Result<InvokeBinding, UiaError> {
        if !is_well_formed_element_id(element_id) {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia element identity is malformed",
            ));
        }
        if expected_control_type.is_empty() || expected_control_type.len() > MAX_STRING_CHARS {
            return Err(UiaError::new(
                FailureCode::InvalidRequest,
                "uia invoke expected_control_type is empty or too large",
            ));
        }
        if !is_invoke_eligible_control_type(expected_control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia invoke actuates only Button, Hyperlink, MenuItem, and SplitButton elements",
            ));
        }
        let record = self.elements.get(element_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is unknown; it may have disappeared or never existed",
            )
        })?;
        if record.control_type != expected_control_type {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element control type changed since observation; stale targets fail closed",
            ));
        }
        if !is_invoke_eligible_control_type(&record.control_type) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia invoke target control type is not eligible for InvokePattern actuation",
            ));
        }
        if !record
            .patterns
            .iter()
            .any(|pattern| pattern == INVOKE_PATTERN_NAME)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia invoke target does not support the Invoke pattern; no mouse or keyboard fallback is permitted",
            ));
        }
        if !record.enabled {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia invoke targets only enabled elements; disabled elements are denied",
            ));
        }
        if record.value_is_password
            || record.redacted
            || is_password_field(&record.control_type, &record.automation_id, &record.name)
        {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia invoke of a password or secret bearing element is denied",
            ));
        }
        let window = self.windows.get(&record.window_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia element identity lost its owning window",
            )
        })?;
        if window.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity belongs to another workspace",
            ));
        }
        if window.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity was issued under another policy revision",
            ));
        }
        if record.tree_generation != expected_tree_generation
            || record.tree_generation != window.tree_generation
        {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia element identity is stale; the UI tree regenerated and the target must be re-observed",
            ));
        }
        if is_protected_window(&window.title, &window.class) {
            return Err(UiaError::new(
                FailureCode::CapabilityDenied,
                "uia invoke of a protected Orcel surface is denied",
            ));
        }
        let process = self.processes.get(&window.process_id).ok_or_else(|| {
            UiaError::new(
                FailureCode::TargetStale,
                "uia invoke target lost its owning process",
            )
        })?;
        if process.superseded {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia invoke target process was superseded by a restart and fails closed",
            ));
        }
        if process.workspace_id != workspace_id {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia invoke target process belongs to another workspace",
            ));
        }
        if process.policy_revision != policy_revision {
            return Err(UiaError::new(
                FailureCode::TargetStale,
                "uia invoke target process was issued under another policy revision",
            ));
        }
        Ok(InvokeBinding {
            process_id: process.process_id.clone(),
            process_generation: process.process_generation,
            window_id: window.window_id.clone(),
            window_generation: window.window_generation,
            element_id: record.element_id.clone(),
            tree_generation: record.tree_generation,
            control_type: record.control_type.clone(),
            hwnd: window.hwnd,
            runtime_id: record.runtime_id.clone(),
        })
    }
}

/// Server-resolved invoke binding used for approval digest computation and
/// evidence. Callers never supply these values directly; they are resolved
/// from the typed element identity immediately before actuation.
#[derive(Debug, Clone)]
pub struct InvokeBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub element_id: String,
    pub tree_generation: u64,
    pub control_type: String,
    pub hwnd: u64,
    pub runtime_id: String,
}

/// Compute the exact approval digest for one structured invoke. Any material
/// drift after approval invalidates the approval because dispatch revalidates
/// the same binding set immediately before the adapter call.
pub fn invoke_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &InvokeBinding,
) -> String {
    let material = format!(
        "orcel-uia-invoke-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|invoke",
        binding.process_id,
        binding.process_generation,
        binding.window_id,
        binding.window_generation,
        binding.element_id,
        binding.tree_generation,
        binding.control_type,
    );
    digest_hex(&material, 64)
}

/// Server-resolved value binding used for approval digest computation and
/// evidence. Callers never supply these values directly; they are resolved
/// from the typed element identity immediately before actuation.
#[derive(Debug, Clone)]
pub struct ValueBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub element_id: String,
    pub tree_generation: u64,
    pub control_type: String,
    pub value_digest: String,
    pub hwnd: u64,
    pub runtime_id: String,
}

/// Compute the exact approval digest for one structured set_value. The
/// digest binds the value digest rather than raw value bytes where
/// practical, and dispatch revalidates the same binding set immediately
/// before the adapter call so any material drift invalidates the approval.
pub fn value_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &ValueBinding,
) -> String {
    let material = format!(
        "orcel-uia-value-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|set_value",
        binding.process_id,
        binding.process_generation,
        binding.window_id,
        binding.window_generation,
        binding.element_id,
        binding.tree_generation,
        binding.control_type,
        binding.value_digest,
    );
    digest_hex(&material, 64)
}

/// Server-resolved select binding used for approval digest computation and
/// evidence. Callers never supply these values directly; they are resolved
/// from the typed element identity immediately before actuation.
#[derive(Debug, Clone)]
pub struct SelectBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub element_id: String,
    pub tree_generation: u64,
    pub control_type: String,
    pub expected_selected: bool,
    pub selected: bool,
    pub hwnd: u64,
    pub runtime_id: String,
}

/// Compute the exact approval digest for one structured select. The digest
/// binds expected and requested selection state, and dispatch revalidates
/// the same binding set immediately before the adapter call so any material
/// drift invalidates the approval.
pub fn select_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &SelectBinding,
) -> String {
    let material = format!(
        "orcel-uia-select-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|{}|select",
        binding.process_id,
        binding.process_generation,
        binding.window_id,
        binding.window_generation,
        binding.element_id,
        binding.tree_generation,
        binding.control_type,
        if binding.expected_selected { "1" } else { "0" },
        if binding.selected { "1" } else { "0" },
    );
    digest_hex(&material, 64)
}

/// Server-resolved toggle binding used for approval digest computation and
/// evidence. Callers never supply these values directly; they are resolved
/// from the typed element identity immediately before actuation.
#[derive(Debug, Clone)]
pub struct ToggleBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub element_id: String,
    pub tree_generation: u64,
    pub control_type: String,
    pub expected_toggled: bool,
    pub toggled: bool,
    pub hwnd: u64,
    pub runtime_id: String,
}

/// Compute the exact approval digest for one structured toggle. The digest
/// binds expected and requested toggle state, and dispatch revalidates
/// the same binding set immediately before the adapter call so any material
/// drift invalidates the approval.
pub fn toggle_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &ToggleBinding,
) -> String {
    let material = format!(
        "orcel-uia-toggle-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|{}|toggle",
        binding.process_id,
        binding.process_generation,
        binding.window_id,
        binding.window_generation,
        binding.element_id,
        binding.tree_generation,
        binding.control_type,
        if binding.expected_toggled { "1" } else { "0" },
        if binding.toggled { "1" } else { "0" },
    );
    digest_hex(&material, 64)
}

/// Server-resolved scroll binding used for approval digest computation and
/// evidence. Callers never supply these values directly; they are resolved
/// from the typed element identity immediately before actuation, except for
/// the bounded direction, bounded amount, and expected scroll position,
/// which are validated against strict bounds and then bound into the
/// approval digest.
#[derive(Debug, Clone)]
pub struct ScrollBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub element_id: String,
    pub tree_generation: u64,
    pub control_type: String,
    pub expected_horizontal_percent: u8,
    pub expected_vertical_percent: u8,
    pub direction: String,
    pub amount: u64,
    pub hwnd: u64,
    pub runtime_id: String,
}

/// Compute the exact approval digest for one structured scroll. The digest
/// binds expected scroll position, requested direction, and requested
/// amount, and dispatch revalidates the same binding set immediately before
/// the adapter call so any material drift invalidates the approval.
pub fn scroll_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &ScrollBinding,
) -> String {
    let material = format!(
        "orcel-uia-scroll-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|scroll",
        binding.process_id,
        binding.process_generation,
        binding.window_id,
        binding.window_generation,
        binding.element_id,
        binding.tree_generation,
        binding.control_type,
        binding.expected_horizontal_percent,
        binding.expected_vertical_percent,
        binding.direction,
        binding.amount,
    );
    digest_hex(&material, 64)
}

/// Server-resolved capture binding used for approval digest computation
/// and evidence. Callers never supply these values directly; they are
/// resolved from the typed window identity immediately before capture,
/// except for the fixed target-window scope, which is validated and then
/// bound into the approval digest.
#[derive(Debug, Clone)]
pub struct CaptureBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub scope: String,
    pub hwnd: u64,
}

/// Compute the exact approval digest for one window-scoped screenshot
/// capture. The digest binds the fixed capture scope, and dispatch
/// revalidates the same binding set immediately before the adapter call
/// so any material drift invalidates the approval.
pub fn capture_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &CaptureBinding,
) -> String {
    let material = format!(
        "orcel-screenshot-capture-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|capture",
        binding.process_id,
        binding.process_generation,
        binding.window_id,
        binding.window_generation,
        binding.scope,
    );
    digest_hex(&material, 64)
}

/// Server-resolved proposal binding used for approval digest computation
/// and evidence. Callers never supply these values directly; they are
/// resolved from the typed frame identity immediately before proposal,
/// except for the bounded region, which is validated against the exact
/// frame geometry and then bound into the approval digest.
#[derive(Debug, Clone)]
pub struct ProposalBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub frame_id: String,
    pub capture_generation: u64,
    pub region: VisualRegion,
    pub frame_width: u32,
    pub frame_height: u32,
}

/// Compute the exact approval digest for one visual target proposal. The
/// digest binds the bounded region, and dispatch revalidates the same
/// binding set immediately before minting so any material drift
/// invalidates the approval.
pub fn visual_proposal_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &ProposalBinding,
) -> String {
    let material = format!(
        "orcel-visual-proposal-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|propose",
        binding.frame_id,
        binding.capture_generation,
        binding.window_id,
        binding.window_generation,
        binding.process_id,
        binding.process_generation,
        binding.region.x,
        binding.region.y,
        binding.region.width,
        binding.region.height,
    );
    digest_hex(&material, 64)
}

/// Server-resolved derivation binding used for approval digest
/// computation and evidence. Callers never supply these values directly;
/// they are resolved from the typed proposal identity immediately before
/// derivation, including the deterministically derived coordinates, which
/// are bound into the approval digest.
#[derive(Debug, Clone)]
pub struct DerivationBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub frame_id: String,
    pub capture_generation: u64,
    pub proposal_id: String,
    pub proposal_generation: u64,
    pub x: u64,
    pub y: u64,
    pub frame_width: u32,
    pub frame_height: u32,
}

/// Compute the exact approval digest for one coordinate derivation. The
/// digest binds the derived coordinates, and dispatch revalidates the
/// same binding set immediately before minting so any material drift
/// invalidates the approval.
pub fn coordinate_derivation_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &DerivationBinding,
) -> String {
    let material = format!(
        "orcel-coordinate-derivation-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|derive",
        binding.proposal_id,
        binding.proposal_generation,
        binding.frame_id,
        binding.capture_generation,
        binding.window_id,
        binding.window_generation,
        binding.x,
        binding.y,
    );
    digest_hex(&material, 64)
}

/// Server-resolved execution binding used for approval digest
/// computation and evidence. Callers never supply these values directly;
/// they are resolved from the typed coordinate identity immediately
/// before execution, including the explicit single-use lease minted from
/// the validated binding and the interruption epoch at grant time.
#[derive(Debug, Clone)]
pub struct ExecuteBinding {
    pub process_id: String,
    pub process_generation: u64,
    pub window_id: String,
    pub window_generation: u64,
    pub frame_id: String,
    pub capture_generation: u64,
    pub proposal_id: String,
    pub proposal_generation: u64,
    pub coord_id: String,
    pub derivation_generation: u64,
    pub interruption_epoch: u64,
    pub x: u64,
    pub y: u64,
    pub hwnd: u64,
    pub operation: String,
    pub lease_id: String,
    pub lease_expires_at_ms: u64,
}

/// Compute the exact approval digest for one bounded execution. The
/// digest binds the derived coordinates, the click-only operation, the
/// interruption epoch at grant time, and the explicit lease, and dispatch
/// revalidates the same binding set and consumes the lease immediately,
/// so any material drift, human interruption, or replay invalidates the
/// approval.
pub fn execute_approval_digest(
    workspace_id: &str,
    policy_revision: &str,
    binding: &ExecuteBinding,
) -> String {
    let material = format!(
        "orcel-bounded-execution-v1|{workspace_id}|{policy_revision}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|execute",
        binding.coord_id,
        binding.derivation_generation,
        binding.proposal_id,
        binding.proposal_generation,
        binding.frame_id,
        binding.capture_generation,
        binding.window_id,
        binding.window_generation,
        binding.interruption_epoch,
        binding.x,
        binding.y,
        binding.operation,
        binding.lease_id,
    );
    digest_hex(&material, 64)
}

fn render_element(record: &ElementRecord) -> Value {
    json!({
        "schema": UIA_SCHEMA,
        "element_id": record.element_id,
        "window_id": record.window_id,
        "runtime_id": record.runtime_id,
        "control_type": record.control_type,
        "automation_id": record.automation_id,
        "name": record.name,
        "enabled": record.enabled,
        "selected": record.selected,
        "toggled": record.toggled,
        "scroll_horizontal_percent": record.scroll_horizontal_percent,
        "scroll_vertical_percent": record.scroll_vertical_percent,
        "patterns": record.patterns,
        "value": record.value,
        "value_is_password": record.value_is_password,
        "redacted": record.redacted,
        "tree_generation": record.tree_generation,
    })
}

fn enforce_response_bytes_with_limit(
    result: &Value,
    max_bytes: usize,
    message: &str,
) -> Result<Value, UiaError> {
    let bytes = serde_json::to_vec(result)
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    if bytes > max_bytes {
        return Err(UiaError::new(FailureCode::OutputLimit, message));
    }
    Ok(result.clone())
}

fn enforce_response_bytes(result: &Value) -> Result<Value, UiaError> {
    enforce_response_bytes_with_limit(
        result,
        MAX_RESPONSE_BYTES,
        "uia observation exceeded the bounded response size",
    )
}

fn truncate_owned(raw: &str, limit: usize) -> (String, bool) {
    let clipped: String = raw.chars().take(limit).collect();
    let truncated = raw.chars().count() > limit;
    (clipped, truncated)
}

pub fn is_protected_window(title: &str, class: &str) -> bool {
    let haystack = format!("{title} {class}").to_ascii_lowercase();
    PROTECTED_WINDOW_MARKERS
        .iter()
        .chain(OS_PROTECTED_WINDOW_MARKERS)
        .any(|marker| haystack.contains(marker))
}

pub fn is_password_field(control_type: &str, automation_id: &str, name: &str) -> bool {
    let haystack = format!("{control_type} {automation_id} {name}").to_ascii_lowercase();
    PASSWORD_MARKERS
        .iter()
        .any(|marker| haystack.contains(marker))
}

#[cfg(test)]
mod sg000027_tests;
#[cfg(test)]
mod sg000028_tests;
#[cfg(test)]
mod sg000029_tests;
#[cfg(test)]
mod sg000030_tests;
#[cfg(test)]
mod sg000031_tests;
#[cfg(test)]
mod sg000032_tests;
#[cfg(test)]
mod sg000033_tests;
#[cfg(test)]
mod sg000034_tests;
#[cfg(test)]
mod sg000035_tests;
#[cfg(test)]
mod sg000036_tests;
#[cfg(test)]
mod sg000037_tests;
#[cfg(test)]
mod sg000063_tests;
