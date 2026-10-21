// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Bounded raw input (XP-12): what pointer, scroll and key input may do to the
//! one window the kernel approved. Everything in this file is pure except the
//! [`tick`] readers, so the rules are tested on every OS.
//!
//! The kernel has already refused what it can before an approval is armed
//! (`orcel_provider_uia::check_native_input_limits`), bound the approval to the
//! exact window (pid, start generation and nonce) and to the digest of the
//! exact input, and spent it once. The host trusts none of that:
//!
//! - [`validate_shape`] refuses, before native work, any frame that carries a
//!   field its operation does not use, or lacks one it needs.
//! - [`plan`] turns the frame into delivery units, each an event or a short
//!   run of events that is checked again immediately before it is delivered.
//!   Coordinates are window-relative points. A point outside the bound
//!   window's live frame is refused, never clamped to its edge: clamping would
//!   deliver an event the approval did not name.
//! - [`classify_key`] admits one key from a closed set and nothing that
//!   composes with a modifier, so no input reaches a system shortcut (lock,
//!   log out, force quit, Spotlight, task switching, a function key).
//! - Typed text is at most [`MAX_TYPED_CHARS`] characters, no control
//!   character, delivered [`TYPE_CHUNK_CHARS`] at a time with the checks
//!   repeated before each chunk.
//! - [`tick_is_fresh`] is the human-input binding: input is refused when the
//!   user touched the keyboard or pointer after the kernel read the tick.
//! - [`occluded_at`] is the z-order check for macOS (X11 uses the XP-07
//!   exposure check). A window the stacking order cannot prove clear is not
//!   a target.

use crate::protocol::{code, HostPlatform, Request};
pub use crate::semantic::Refusal;
use cua_driver_contract::{WindowElement, WindowInfo};

/// The raw input operations this host delivers.
pub const INPUT_OPERATIONS: [&str; 5] = [
    "input_click",
    "input_drag",
    "input_scroll",
    "input_type_text",
    "input_key",
];

/// The raw input operations that address a point.
pub const POINTER_OPERATIONS: [&str; 3] = ["input_click", "input_drag", "input_scroll"];

/// The raw input operations that address the focused control of the window.
/// On X11 their background route needs a virtual master keyboard fed by a
/// uinput device, which a headless Xvfb cannot have, so a session can serve
/// the pointer operations and not these.
pub const KEYBOARD_OPERATIONS: [&str; 2] = ["input_type_text", "input_key"];

/// Whether `op` is one of [`INPUT_OPERATIONS`].
pub fn is_input_operation(op: &str) -> bool {
    INPUT_OPERATIONS.contains(&op)
}

/// Whether `op` is one of [`KEYBOARD_OPERATIONS`].
pub fn is_keyboard_operation(op: &str) -> bool {
    KEYBOARD_OPERATIONS.contains(&op)
}

/// The most characters one `input_type_text` types.
pub const MAX_TYPED_CHARS: usize = 256;
/// Characters per delivery unit of typed text. The checks run before each.
pub const TYPE_CHUNK_CHARS: usize = 8;
/// The most wheel lines one `input_scroll` turns.
pub const MAX_SCROLL_LINES: i64 = 20;
/// The most clicks one `input_click` makes.
pub const MAX_CLICK_COUNT: i64 = 3;
/// Window-relative coordinates beyond this are malformed, not merely outside.
const MAX_COORDINATE: i64 = 1_000_000;
/// How far the human-input tick may differ from the one it is held to: clock
/// jitter only. The readers have at most 10 ms resolution, so a keystroke or a
/// pointer move after the read is above this.
pub const TICK_TOLERANCE_MS: u32 = 30;
/// The person must have been quiet this long before the first unit: the
/// baseline the kernel read is taken right after the Approve click, and a
/// person still typing or moving at that moment is not a person who agreed to
/// this input. The worker waits out the remainder and requires the tick not to
/// move meanwhile.
pub const QUIET_MS: u32 = 250;
/// The most a window may move or resize between the plan and a unit, in
/// points, before the plan is stale.
pub const FRAME_DRIFT_POINTS: f64 = 1.0;

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

/// The request fields an input operation may carry, and the ones it needs.
fn field_rules(op: &str) -> Option<(&'static [&'static str], &'static [&'static str])> {
    Some(match op {
        "input_click" => (
            &[
                "x",
                "y",
                "button",
                "click_count",
                "expected_last_input_tick",
            ],
            &["x", "y", "expected_last_input_tick"],
        ),
        "input_drag" => (
            &["x", "y", "to_x", "to_y", "expected_last_input_tick"],
            &["x", "y", "to_x", "to_y", "expected_last_input_tick"],
        ),
        "input_scroll" => (
            &["x", "y", "scroll_x", "scroll_y", "expected_last_input_tick"],
            &["x", "y", "expected_last_input_tick"],
        ),
        "input_type_text" => (
            &["text", "expected_last_input_tick"],
            &["text", "expected_last_input_tick"],
        ),
        "input_key" => (
            &["key", "expected_last_input_tick"],
            &["key", "expected_last_input_tick"],
        ),
        _ => return None,
    })
}

/// Every request field an input operation could be given, by wire name.
fn present_fields(request: &Request) -> Vec<&'static str> {
    let mut present = Vec::new();
    let mut add = |name: &'static str, is_some: bool| {
        if is_some {
            present.push(name);
        }
    };
    add("element_runtime_id", request.element_runtime_id.is_some());
    add("semantic_action", request.semantic_action.is_some());
    add("window_action", request.window_action.is_some());
    add("value", request.value.is_some());
    add("x", request.x.is_some());
    add("y", request.y.is_some());
    add("to_x", request.to_x.is_some());
    add("to_y", request.to_y.is_some());
    add("button", request.button.is_some());
    add("click_count", request.click_count.is_some());
    add("scroll_x", request.scroll_x.is_some());
    add("scroll_y", request.scroll_y.is_some());
    add("text", request.text.is_some());
    add("key", request.key.is_some());
    add(
        "expected_last_input_tick",
        request.expected_last_input_tick.is_some(),
    );
    add("max_nodes", request.max_nodes.is_some());
    add("max_depth", request.max_depth.is_some());
    present
}

/// The frame-independent part of an input request: exactly the fields its
/// operation uses, in range, and every rule that needs no window (the button
/// and count, one scroll axis and its size, the typed text, the key set).
/// Run by the protocol decoder before any native work; the worker applies the
/// same rules again through [`plan`], against the live frame.
pub fn validate_shape(request: &Request) -> Result<(), Refusal> {
    plan(request, &Frame::UNBOUNDED).map(|_| ())
}

fn check_fields(request: &Request) -> Result<(), Refusal> {
    let Some((allowed, required)) = field_rules(&request.op) else {
        return Err(refuse(
            code::CAPABILITY_DENIED,
            "operation is not a raw input operation this host delivers",
        ));
    };
    let present = present_fields(request);
    if let Some(extra) = present.iter().find(|name| !allowed.contains(name)) {
        return Err(refuse(
            code::INVALID_REQUEST,
            format!("{} does not take the field {extra}", request.op),
        ));
    }
    if let Some(missing) = required.iter().find(|name| !present.contains(name)) {
        return Err(refuse(
            code::INVALID_REQUEST,
            format!("{} needs the field {missing}", request.op),
        ));
    }
    for value in [request.x, request.y, request.to_x, request.to_y]
        .into_iter()
        .flatten()
    {
        if !(0..=MAX_COORDINATE).contains(&value) {
            return Err(refuse(
                code::INVALID_REQUEST,
                "input coordinates are window-relative and not negative",
            ));
        }
    }
    Ok(())
}

/// The window's live frame in points: coordinates are `[0, width) x [0, height)`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Frame {
    pub width: f64,
    pub height: f64,
    /// The window's screen origin, for the occlusion check.
    pub origin_x: f64,
    pub origin_y: f64,
}

impl Frame {
    /// A frame no point is outside of, for the checks that need no window.
    const UNBOUNDED: Frame = Frame {
        width: 1.0e12,
        height: 1.0e12,
        origin_x: 0.0,
        origin_y: 0.0,
    };

    pub fn of(window: &WindowInfo) -> Self {
        Self {
            width: window.bounds.width,
            height: window.bounds.height,
            origin_x: window.bounds.x,
            origin_y: window.bounds.y,
        }
    }

    /// Whether the window is still where and as large as the plan assumed.
    pub fn matches(&self, other: &Frame) -> bool {
        (self.width - other.width).abs() <= FRAME_DRIFT_POINTS
            && (self.height - other.height).abs() <= FRAME_DRIFT_POINTS
            && (self.origin_x - other.origin_x).abs() <= FRAME_DRIFT_POINTS
            && (self.origin_y - other.origin_y).abs() <= FRAME_DRIFT_POINTS
    }

    fn contains(&self, x: i64, y: i64) -> bool {
        self.width.is_finite()
            && self.height.is_finite()
            && self.width > 0.0
            && self.height > 0.0
            && (x as f64) < self.width
            && (y as f64) < self.height
            && x >= 0
            && y >= 0
    }

    /// The screen point a window-relative point names.
    pub fn screen_point(&self, x: i64, y: i64) -> (f64, f64) {
        (self.origin_x + x as f64, self.origin_y + y as f64)
    }
}

/// Which mouse button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Button {
    Left,
    Right,
}

/// One delivery unit: delivered as one Cua call, checked again right before.
#[derive(Debug, Clone, PartialEq)]
pub enum Unit {
    Click {
        x: i64,
        y: i64,
        button: Button,
        count: u32,
    },
    Drag {
        x: i64,
        y: i64,
        to_x: i64,
        to_y: i64,
    },
    Scroll {
        x: i64,
        y: i64,
        direction: &'static str,
        lines: u32,
    },
    Text(String),
    Key(&'static str),
}

impl Unit {
    /// The window-relative points the unit touches, for the occlusion check.
    pub fn points(&self) -> Vec<(i64, i64)> {
        match self {
            Self::Click { x, y, .. } | Self::Scroll { x, y, .. } => vec![(*x, *y)],
            Self::Drag { x, y, to_x, to_y } => vec![(*x, *y), (*to_x, *to_y)],
            Self::Text(_) | Self::Key(_) => Vec::new(),
        }
    }
}

/// The full plan of one request: the units, in delivery order.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub units: Vec<Unit>,
}

/// The delivery units of `request` against the live `frame`.
pub fn plan(request: &Request, frame: &Frame) -> Result<Plan, Refusal> {
    check_fields(request)?;
    let outside = || {
        refuse(
            code::INVALID_REQUEST,
            "the point lies outside the bound window's frame; input is never clamped onto its edge",
        )
    };
    let point = |x: Option<i64>, y: Option<i64>| -> Result<(i64, i64), Refusal> {
        let (x, y) = (x.unwrap_or(-1), y.unwrap_or(-1));
        if frame.contains(x, y) {
            Ok((x, y))
        } else {
            Err(outside())
        }
    };
    let units = match request.op.as_str() {
        "input_click" => {
            let (x, y) = point(request.x, request.y)?;
            let button = match request.button.as_deref().unwrap_or("left") {
                "left" => Button::Left,
                "right" => Button::Right,
                _ => {
                    return Err(refuse(
                        code::INVALID_REQUEST,
                        "input_click uses the left or right button",
                    ))
                }
            };
            let count = request.click_count.unwrap_or(1);
            if !(1..=MAX_CLICK_COUNT).contains(&count) {
                return Err(refuse(
                    code::INVALID_REQUEST,
                    "input_click clicks one to three times",
                ));
            }
            vec![Unit::Click {
                x,
                y,
                button,
                count: count as u32,
            }]
        }
        "input_drag" => {
            let (x, y) = point(request.x, request.y)?;
            let (to_x, to_y) = point(request.to_x, request.to_y)?;
            vec![Unit::Drag { x, y, to_x, to_y }]
        }
        "input_scroll" => {
            let (x, y) = point(request.x, request.y)?;
            let (scroll_x, scroll_y) =
                (request.scroll_x.unwrap_or(0), request.scroll_y.unwrap_or(0));
            if (scroll_x == 0) == (scroll_y == 0) {
                return Err(refuse(
                    code::INVALID_REQUEST,
                    "input_scroll turns exactly one axis",
                ));
            }
            let amount = if scroll_x == 0 { scroll_y } else { scroll_x };
            if amount.unsigned_abs() > MAX_SCROLL_LINES as u64 {
                return Err(refuse(
                    code::INVALID_REQUEST,
                    "input_scroll turns at most 20 lines",
                ));
            }
            let direction = match (scroll_x, scroll_y) {
                (0, y) if y < 0 => "up",
                (0, _) => "down",
                (x, _) if x < 0 => "left",
                _ => "right",
            };
            vec![Unit::Scroll {
                x,
                y,
                direction,
                lines: amount.unsigned_abs() as u32,
            }]
        }
        "input_type_text" => {
            let text = request.text.as_deref().unwrap_or_default();
            let chars: Vec<char> = text.chars().collect();
            if chars.is_empty() || chars.len() > MAX_TYPED_CHARS {
                return Err(refuse(
                    code::INVALID_REQUEST,
                    "typed text is one to 256 characters",
                ));
            }
            if chars.iter().any(|c| c.is_control()) {
                return Err(refuse(
                    code::INVALID_REQUEST,
                    "typed text carries no control character; use input_key for Enter or Tab",
                ));
            }
            chars
                .chunks(TYPE_CHUNK_CHARS)
                .map(|chunk| Unit::Text(chunk.iter().collect()))
                .collect()
        }
        "input_key" => vec![Unit::Key(classify_key(
            request.key.as_deref().unwrap_or_default(),
        )?)],
        _ => {
            return Err(refuse(
                code::CAPABILITY_DENIED,
                "operation is not a raw input operation this host delivers",
            ))
        }
    };
    Ok(Plan { units })
}

/// Names that make a key a modifier or part of a chord.
const MODIFIER_NAMES: [&str; 17] = [
    "cmd",
    "command",
    "super",
    "meta",
    "win",
    "windows",
    "ctrl",
    "control",
    "alt",
    "option",
    "opt",
    "shift",
    "fn",
    "altgr",
    "hyper",
    "cmdorctrl",
    "capslock",
];

/// The keys that act as themselves in any focused control and compose with
/// nothing: navigation, editing and activation keys. The wire name is on the
/// left, the Cua key name on the right.
const PLAIN_KEYS: [(&str, &str); 15] = [
    ("enter", "return"),
    ("return", "return"),
    ("tab", "tab"),
    ("escape", "escape"),
    ("esc", "escape"),
    ("space", "space"),
    ("backspace", "backspace"),
    ("delete", "delete"),
    ("up", "up"),
    ("down", "down"),
    ("left", "left"),
    ("right", "right"),
    ("home", "home"),
    ("end", "end"),
    ("pageup", "pageup"),
];

const LETTERS_AND_DIGITS: &str = "abcdefghijklmnopqrstuvwxyz0123456789";

/// The one key `key` names, as Cua spells it. A chord, a modifier or a
/// function key can reach a system shortcut and is `capability_denied`; a name
/// outside the closed set is `invalid_request`. Nothing is guessed.
pub fn classify_key(key: &str) -> Result<&'static str, Refusal> {
    let chord = || {
        refuse(
            code::CAPABILITY_DENIED,
            "a key chord, modifier or function key can reach a system shortcut and is not delivered",
        )
    };
    if key.is_empty() || key.len() > crate::protocol::MAX_KEY_BYTES || !key.is_ascii() {
        return Err(refuse(
            code::INVALID_REQUEST,
            "the key is not in the typed key set",
        ));
    }
    let lower = key.to_ascii_lowercase();
    if lower.contains(['+', '-', ' ', '\t', ',', '=', '_', '.']) {
        return Err(chord());
    }
    if MODIFIER_NAMES.contains(&lower.as_str()) {
        return Err(chord());
    }
    let function_key = lower
        .strip_prefix('f')
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit()));
    if function_key {
        return Err(chord());
    }
    if lower == "pagedown" {
        return Ok("pagedown");
    }
    if let Some((_, cua)) = PLAIN_KEYS.iter().find(|(wire, _)| *wire == lower) {
        return Ok(cua);
    }
    let mut chars = lower.chars();
    if let (Some(only), None) = (chars.next(), chars.next()) {
        if let Some(index) = LETTERS_AND_DIGITS.find(only) {
            return Ok(&LETTERS_AND_DIGITS[index..index + 1]);
        }
    }
    Err(refuse(
        code::INVALID_REQUEST,
        "the key is not in the typed key set",
    ))
}

/// The human-input binding. `expected` is the tick the kernel read just
/// before it armed the action, `now` the tick read immediately before a
/// delivery unit. Input newer than `expected` by more than the tolerance means
/// the person touched the machine since, and the unit is not delivered. Ticks
/// are milliseconds that wrap, so the comparison is on the signed difference.
pub fn tick_is_fresh(expected: u32, now: u32) -> bool {
    let delta = now.wrapping_sub(expected) as i32;
    delta.unsigned_abs() <= TICK_TOLERANCE_MS
}

/// How the host's own delivered events show on the human-input clock, per
/// platform. The rule decides which tick changes between delivery units are
/// the host's own and which are the person's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnEvents {
    /// The host's events move the clock. X11: XTest events on Cua's virtual
    /// master device reset the X server's idle counter, so a tick that lies
    /// inside the call that delivered the unit is the host's own.
    MoveTheClock,
    /// The host's events never move the clock. macOS: events posted to one
    /// process (`CGEventPostToPid`, and the SkyLight `SLEventPostToPid` route)
    /// bypass the HID event stream that the combined session state reads, so
    /// the tick must stay exactly what it was. Any change is the person.
    LeaveTheClock,
}

impl OwnEvents {
    /// The rule for the platform the worker runs on.
    pub fn on(platform: HostPlatform) -> Self {
        if platform == crate::protocol::MACOS {
            Self::LeaveTheClock
        } else {
            Self::MoveTheClock
        }
    }
}

/// Clock-reading slack on either side of a delivery call when the host's own
/// events move the X11 clock: `/proc/uptime` and the tick derived from it each
/// have 10 ms resolution. The settle wait after the call is outside the window.
pub const OWN_EVENT_MARGIN_MS: u32 = 20;

/// The macOS tick is one millisecond count derived from two clock reads, so
/// two reads of the same last event may round one millisecond apart. Exactly
/// equal means equal up to that rounding.
pub const MACOS_TICK_ROUNDING_MS: u32 = 1;

/// Whether the tick read after a delivery unit is explained by the host's own
/// events or by nothing happening. Under [`OwnEvents::LeaveTheClock`] (macOS)
/// only an unchanged tick is. Under [`OwnEvents::MoveTheClock`] (X11) the tick
/// may also lie inside the delivery call itself: `start` is read just before
/// the call and `end` just after it returns, before any settle wait, all in
/// the tick clock. Anything else is the person touching the keyboard or
/// pointer, and the rest of the sequence is not sent.
pub fn explained_by_own_events(
    rule: OwnEvents,
    baseline: u32,
    after: u32,
    start: u32,
    end: u32,
) -> bool {
    match rule {
        OwnEvents::LeaveTheClock => {
            (after.wrapping_sub(baseline) as i32).unsigned_abs() <= MACOS_TICK_ROUNDING_MS
        }
        OwnEvents::MoveTheClock => {
            if tick_is_fresh(baseline, after) {
                return true;
            }
            let from = start.wrapping_sub(OWN_EVENT_MARGIN_MS);
            let span = end.wrapping_sub(from).wrapping_add(OWN_EVENT_MARGIN_MS);
            after.wrapping_sub(from) <= span
        }
    }
}

/// Whether the tick read right before a delivery call is still the baseline:
/// nothing has touched the machine since the last check. Under
/// [`OwnEvents::LeaveTheClock`] (macOS) that is equality up to the reader's
/// rounding; under [`OwnEvents::MoveTheClock`] (X11) the clock-jitter
/// tolerance of [`tick_is_fresh`]. No own event lies between the gate and the
/// call, so nothing else explains a change.
pub fn still_at_baseline(rule: OwnEvents, baseline: u32, now: u32) -> bool {
    match rule {
        OwnEvents::LeaveTheClock => {
            (now.wrapping_sub(baseline) as i32).unsigned_abs() <= MACOS_TICK_ROUNDING_MS
        }
        OwnEvents::MoveTheClock => tick_is_fresh(baseline, now),
    }
}

/// How long the person must still stay quiet before the first unit, given the
/// current tick clock and the last input: zero when they already were.
pub fn quiet_remaining_ms(clock: u32, last_input: u32) -> u32 {
    let idle = clock.wrapping_sub(last_input) as i32;
    if idle < 0 {
        return QUIET_MS;
    }
    QUIET_MS.saturating_sub(idle as u32)
}

/// Physical capture pixels per point: 1 or 2, the only coherent macOS window
/// capture ratios, within a rounding tolerance. Anything else is a frame the
/// capture and the window list disagree on, and input is not delivered.
pub fn backing_scale(width_pt: f64, height_pt: f64, px_w: u32, px_h: u32) -> Option<f64> {
    if !(width_pt.is_finite() && height_pt.is_finite()) || width_pt <= 0.0 || height_pt <= 0.0 {
        return None;
    }
    let (scale_x, scale_y) = (f64::from(px_w) / width_pt, f64::from(px_h) / height_pt);
    let nearest = if (scale_x - 1.0).abs() <= (scale_x - 2.0).abs() {
        1.0
    } else {
        2.0
    };
    let coherent = (scale_x - scale_y).abs() <= 0.03
        && (scale_x - nearest).abs() <= 0.03
        && (scale_y - nearest).abs() <= 0.03;
    coherent.then_some(nearest)
}

/// What stands between a screen point and the target window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occlusion {
    /// No window in front of the target covers the point.
    Clear,
    /// A window in front covers the point.
    Covered,
    /// The stacking order cannot be read for the target or a window at the
    /// point, so nothing proves the point is clear.
    Unknown,
}

/// Whether any other window is in front of `target` at the screen point
/// `(sx, sy)`. Every window counts, whatever its owner: a menu or popup of
/// the target's own application covering the point is not the window the
/// approval named.
pub fn occluded_at(target: &WindowInfo, windows: &[WindowInfo], sx: f64, sy: f64) -> Occlusion {
    let mut unknown = false;
    for other in windows {
        if other.window_id == target.window_id
            || !other.is_on_screen
            || other.minimized == Some(true)
            || other.on_current_space == Some(false)
        {
            continue;
        }
        let bounds = &other.bounds;
        let inside = bounds.width > 0.0
            && bounds.height > 0.0
            && sx >= bounds.x
            && sy >= bounds.y
            && sx < bounds.x + bounds.width
            && sy < bounds.y + bounds.height;
        if !inside {
            continue;
        }
        match (target.z_index, other.z_index) {
            (Some(mine), Some(theirs)) if theirs > mine => return Occlusion::Covered,
            (Some(_), Some(_)) => {}
            _ => unknown = true,
        }
    }
    if unknown {
        Occlusion::Unknown
    } else {
        Occlusion::Clear
    }
}

/// Whether the window's observed tree shows a secure text field. Input to a
/// window that shows one is refused: a click can focus it and typed text then
/// lands in it, and the host cannot tell which element holds the focus.
pub fn shows_secure_field(elements: &[WindowElement]) -> bool {
    elements
        .iter()
        .any(|element| crate::map::is_secure_role(&element.role))
}

/// The human-input tick readers: milliseconds on the machine's monotonic
/// clock at which the person last touched the keyboard or pointer.
pub mod tick {
    /// The tick, or why it cannot be read.
    pub fn current() -> Result<u32, String> {
        imp::current()
    }

    /// The clock the tick is measured on, in milliseconds: the machine's
    /// monotonic clock.
    pub fn clock_ms() -> Result<u32, String> {
        imp::clock_ms()
    }

    #[cfg(target_os = "linux")]
    mod imp {
        use x11rb::connection::Connection as _;
        use x11rb::protocol::screensaver::ConnectionExt as _;
        use x11rb::rust_connection::RustConnection;

        /// Milliseconds since boot, from `/proc/uptime` (10 ms resolution).
        fn uptime_ms() -> Result<u64, String> {
            let text = std::fs::read_to_string("/proc/uptime")
                .map_err(|error| format!("/proc/uptime is unreadable: {error}"))?;
            let seconds: f64 = text
                .split_whitespace()
                .next()
                .and_then(|field| field.parse().ok())
                .ok_or_else(|| "/proc/uptime is malformed".to_owned())?;
            Ok((seconds * 1000.0) as u64)
        }

        pub fn clock_ms() -> Result<u32, String> {
            uptime_ms().map(|ms| ms as u32)
        }

        pub fn current() -> Result<u32, String> {
            let (connection, screen) = RustConnection::connect(None)
                .map_err(|error| format!("the X display is unreachable: {error}"))?;
            let root = connection
                .setup()
                .roots
                .get(screen)
                .ok_or_else(|| "the X screen is missing".to_owned())?
                .root;
            let idle = connection
                .screensaver_query_info(root)
                .map_err(|error| format!("MIT-SCREEN-SAVER is unavailable: {error}"))?
                .reply()
                .map_err(|error| format!("MIT-SCREEN-SAVER is unavailable: {error}"))?
                .ms_since_user_input;
            Ok(uptime_ms()?.wrapping_sub(u64::from(idle)) as u32)
        }
    }

    #[cfg(target_os = "macos")]
    mod imp {
        #[link(name = "CoreGraphics", kind = "framework")]
        extern "C" {
            fn CGEventSourceSecondsSinceLastEventType(state_id: i32, event_type: u32) -> f64;
        }

        /// `kCGEventSourceStateCombinedSessionState`: hardware and synthetic
        /// events of the whole login session.
        const COMBINED_SESSION_STATE: i32 = 0;
        /// `kCGAnyInputEventType`.
        const ANY_INPUT_EVENT_TYPE: u32 = u32::MAX;

        /// The monotonic clock in milliseconds, with its fraction kept.
        fn monotonic_ms() -> Result<f64, String> {
            let mut now = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: `now` is a live, writable `timespec`; clock_gettime
            // writes only through the pointer it is given.
            let status = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
            if status != 0 {
                return Err("the monotonic clock is unreadable".to_owned());
            }
            Ok(now.tv_sec as f64 * 1000.0 + now.tv_nsec as f64 / 1_000_000.0)
        }

        pub fn clock_ms() -> Result<u32, String> {
            monotonic_ms().map(|ms| ms as u64 as u32)
        }

        /// The last event's instant, rounded once from the unrounded
        /// difference, so two reads of the same event agree to within one
        /// millisecond (`MACOS_TICK_ROUNDING_MS`).
        pub fn current() -> Result<u32, String> {
            // SAFETY: a plain CoreGraphics query taking two integers and
            // returning a number of seconds; it reads no memory of ours.
            let idle = unsafe {
                CGEventSourceSecondsSinceLastEventType(COMBINED_SESSION_STATE, ANY_INPUT_EVENT_TYPE)
            };
            if !idle.is_finite() || idle < 0.0 {
                return Err("the last input time is unreadable".to_owned());
            }
            let last = (monotonic_ms()? - idle * 1000.0).round();
            if !last.is_finite() || last < 0.0 {
                return Err("the last input time is unreadable".to_owned());
            }
            Ok(last as u64 as u32)
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    mod imp {
        pub fn current() -> Result<u32, String> {
            Err("no human-input clock exists on this platform".to_owned())
        }

        pub fn clock_ms() -> Result<u32, String> {
            Err("no human-input clock exists on this platform".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cua_driver_contract::WindowBounds;

    fn request(op: &str, fields: &str) -> Request {
        let line = format!(
            r#"{{"id":1,"protocol":"orcel-computer-host/2","op":"{op}",{fields}"window":{{"kind":"x11","id":9,"expected_pid":1,"expected_start_generation":2,"expected_window_nonce":3}}}}"#
        );
        serde_json::from_str(&line).expect("a request")
    }

    fn click(x: i64, y: i64) -> Request {
        request(
            "input_click",
            &format!(r#""x":{x},"y":{y},"expected_last_input_tick":5,"#),
        )
    }

    fn frame() -> Frame {
        Frame {
            width: 320.0,
            height: 200.0,
            origin_x: 100.0,
            origin_y: 50.0,
        }
    }

    fn denied<T: std::fmt::Debug>(result: Result<T, Refusal>) -> &'static str {
        result.unwrap_err().code
    }

    #[test]
    fn a_click_inside_the_frame_is_one_unit() {
        let planned = plan(&click(10, 20), &frame()).unwrap();
        assert_eq!(
            planned.units,
            vec![Unit::Click {
                x: 10,
                y: 20,
                button: Button::Left,
                count: 1
            }]
        );
        // The last pixel is inside; the frame's edge is not.
        assert!(plan(&click(319, 199), &frame()).is_ok());
        assert_eq!(
            denied(plan(&click(320, 10), &frame())),
            code::INVALID_REQUEST
        );
        assert_eq!(
            denied(plan(&click(10, 200), &frame())),
            code::INVALID_REQUEST
        );
    }

    #[test]
    fn a_point_outside_the_frame_is_refused_never_clamped() {
        let far = request(
            "input_click",
            r#""x":900,"y":10,"expected_last_input_tick":5,"#,
        );
        assert_eq!(denied(plan(&far, &frame())), code::INVALID_REQUEST);
        let drag_end_outside = request(
            "input_drag",
            r#""x":1,"y":1,"to_x":321,"to_y":5,"expected_last_input_tick":5,"#,
        );
        assert_eq!(
            denied(plan(&drag_end_outside, &frame())),
            code::INVALID_REQUEST
        );
        let scroll_outside = request(
            "input_scroll",
            r#""x":5,"y":205,"scroll_y":3,"expected_last_input_tick":5,"#,
        );
        assert_eq!(
            denied(plan(&scroll_outside, &frame())),
            code::INVALID_REQUEST
        );
        // A negative or absurd coordinate never reaches the frame test.
        for fields in [
            r#""x":-1,"y":1,"expected_last_input_tick":5,"#,
            r#""x":1,"y":-1,"expected_last_input_tick":5,"#,
            r#""x":1000001,"y":1,"expected_last_input_tick":5,"#,
        ] {
            assert_eq!(
                denied(validate_shape(&request("input_click", fields))),
                code::INVALID_REQUEST,
                "{fields}"
            );
        }
        // A degenerate live frame admits no point.
        let empty = Frame {
            width: 0.0,
            ..frame()
        };
        assert_eq!(denied(plan(&click(0, 0), &empty)), code::INVALID_REQUEST);
        let nan = Frame {
            width: f64::NAN,
            ..frame()
        };
        assert_eq!(denied(plan(&click(0, 0), &nan)), code::INVALID_REQUEST);
    }

    #[test]
    fn each_operation_takes_its_own_fields_and_no_other() {
        let tick = r#""expected_last_input_tick":5"#;
        let good = [
            (
                "input_click",
                format!(r#""x":1,"y":2,"button":"right","click_count":2,{tick},"#),
            ),
            (
                "input_drag",
                format!(r#""x":1,"y":2,"to_x":3,"to_y":4,{tick},"#),
            ),
            (
                "input_scroll",
                format!(r#""x":1,"y":2,"scroll_y":-3,"scroll_x":0,{tick},"#),
            ),
            ("input_type_text", format!(r#""text":"hi",{tick},"#)),
            ("input_key", format!(r#""key":"tab",{tick},"#)),
        ];
        for (op, fields) in &good {
            assert_eq!(validate_shape(&request(op, fields)), Ok(()), "{op}");
        }
        // A foreign field is refused: no text on a click, no point on a key,
        // no element or semantic verb anywhere.
        let foreign = [
            ("input_click", r#""text":"x","#),
            ("input_click", r#""key":"a","#),
            ("input_click", r#""to_x":1,"#),
            ("input_click", r#""scroll_y":1,"#),
            ("input_drag", r#""button":"left","#),
            ("input_scroll", r#""text":"x","#),
            ("input_type_text", r#""x":1,"#),
            ("input_type_text", r#""key":"a","#),
            ("input_key", r#""x":1,"#),
            ("input_key", r#""text":"a","#),
            ("input_key", r#""button":"left","#),
            ("input_key", r#""element_runtime_id":"e1-00","#),
            ("input_key", r#""semantic_action":"invoke","#),
            ("input_key", r#""window_action":"close","#),
            ("input_key", r#""value":"x","#),
            ("input_key", r#""max_nodes":9,"#),
        ];
        for (op, extra) in foreign {
            let fields = format!(
                "{extra}{}",
                match op {
                    "input_click" => r#""x":1,"y":2,"expected_last_input_tick":5,"#,
                    "input_drag" =>
                        r#""x":1,"y":2,"to_x":3,"to_y":4,"expected_last_input_tick":5,"#,
                    "input_scroll" => r#""x":1,"y":2,"scroll_y":1,"expected_last_input_tick":5,"#,
                    "input_type_text" => r#""text":"a","expected_last_input_tick":5,"#,
                    _ => r#""key":"a","expected_last_input_tick":5,"#,
                }
            );
            assert_eq!(
                denied(validate_shape(&request(op, &fields))),
                code::INVALID_REQUEST,
                "{op} {extra}"
            );
        }
        // A missing field, above all the human-input tick, is refused.
        for (op, fields) in [
            ("input_click", r#""x":1,"y":2,"#),
            ("input_click", r#""x":1,"expected_last_input_tick":5,"#),
            (
                "input_drag",
                r#""x":1,"y":2,"to_x":3,"expected_last_input_tick":5,"#,
            ),
            ("input_scroll", r#""x":1,"expected_last_input_tick":5,"#),
            ("input_type_text", r#""expected_last_input_tick":5,"#),
            ("input_key", r#""key":"a","#),
        ] {
            assert_eq!(
                denied(validate_shape(&request(op, fields))),
                code::INVALID_REQUEST,
                "{op} {fields}"
            );
        }
        for op in [
            "input_move",
            "input_hotkey",
            "window_action",
            "semantic_action",
        ] {
            assert_eq!(
                denied(validate_shape(&request(op, r#""x":1,"#))),
                code::CAPABILITY_DENIED,
                "{op}"
            );
        }
    }

    #[test]
    fn click_buttons_and_counts_are_closed() {
        let with = |extra: &str| {
            request(
                "input_click",
                &format!(r#""x":1,"y":2,{extra},"expected_last_input_tick":5,"#),
            )
        };
        assert!(plan(&with(r#""button":"right""#), &frame()).is_ok());
        assert!(plan(&with(r#""click_count":3"#), &frame()).is_ok());
        for bad in [
            r#""button":"middle""#,
            r#""button":"Left""#,
            r#""button":"""#,
            r#""click_count":0"#,
            r#""click_count":4"#,
            r#""click_count":-1"#,
        ] {
            assert_eq!(
                denied(plan(&with(bad), &frame())),
                code::INVALID_REQUEST,
                "{bad}"
            );
        }
    }

    #[test]
    fn a_scroll_turns_one_axis_by_a_bounded_amount() {
        let scroll = |x: i64, y: i64| {
            plan(
                &request(
                    "input_scroll",
                    &format!(
                        r#""x":5,"y":5,"scroll_x":{x},"scroll_y":{y},"expected_last_input_tick":5,"#
                    ),
                ),
                &frame(),
            )
        };
        let unit = |plan: Plan| plan.units.into_iter().next().unwrap();
        assert_eq!(
            unit(scroll(0, -3).unwrap()),
            Unit::Scroll {
                x: 5,
                y: 5,
                direction: "up",
                lines: 3
            }
        );
        assert_eq!(
            unit(scroll(0, 20).unwrap()),
            Unit::Scroll {
                x: 5,
                y: 5,
                direction: "down",
                lines: 20
            }
        );
        assert_eq!(
            unit(scroll(-1, 0).unwrap()),
            Unit::Scroll {
                x: 5,
                y: 5,
                direction: "left",
                lines: 1
            }
        );
        assert_eq!(
            unit(scroll(7, 0).unwrap()),
            Unit::Scroll {
                x: 5,
                y: 5,
                direction: "right",
                lines: 7
            }
        );
        for (x, y) in [(0, 0), (1, 1), (0, 21), (-21, 0), (i64::MIN, 0)] {
            assert_eq!(denied(scroll(x, y)), code::INVALID_REQUEST, "{x} {y}");
        }
    }

    #[test]
    fn typed_text_is_bounded_and_delivered_in_checked_chunks() {
        let typed = |text: &str| {
            plan(
                &request(
                    "input_type_text",
                    &format!(
                        r#""text":{},"expected_last_input_tick":5,"#,
                        serde_json::to_string(text).unwrap()
                    ),
                ),
                &frame(),
            )
        };
        let planned = typed("hello, world! 12345").unwrap();
        assert_eq!(
            planned.units,
            vec![
                Unit::Text("hello, w".into()),
                Unit::Text("orld! 12".into()),
                Unit::Text("345".into()),
            ]
        );
        // The longest text is accepted, one character more is not.
        let longest = "é".repeat(MAX_TYPED_CHARS);
        let planned = typed(&longest).unwrap();
        assert_eq!(planned.units.len(), MAX_TYPED_CHARS / TYPE_CHUNK_CHARS);
        assert_eq!(
            denied(typed(&"a".repeat(MAX_TYPED_CHARS + 1))),
            code::INVALID_REQUEST
        );
        assert_eq!(denied(typed("")), code::INVALID_REQUEST);
        // No control character: Enter, Tab, Escape and NUL go through input_key.
        for control in ["a\nb", "a\tb", "a\rb", "\u{1b}", "a\0b", "\u{7f}", "\u{85}"] {
            assert_eq!(denied(typed(control)), code::INVALID_REQUEST, "{control:?}");
        }
        // A multi-byte character is never split across chunks.
        for unit in typed(&"日本語テキスト".repeat(5)).unwrap().units {
            assert!(matches!(unit, Unit::Text(_)));
            if let Unit::Text(chunk) = unit {
                assert!(chunk.chars().count() <= TYPE_CHUNK_CHARS);
            }
        }
    }

    #[test]
    fn the_key_set_is_closed_and_no_system_shortcut_gets_through() {
        for (wire, cua) in [
            ("Enter", "return"),
            ("return", "return"),
            ("TAB", "tab"),
            ("Escape", "escape"),
            ("space", "space"),
            ("BackSpace", "backspace"),
            ("Delete", "delete"),
            ("Up", "up"),
            ("pagedown", "pagedown"),
            ("PageUp", "pageup"),
            ("a", "a"),
            ("Z", "z"),
            ("7", "7"),
        ] {
            assert_eq!(classify_key(wire), Ok(cua), "{wire}");
        }
        // Chords, modifiers and function keys reach lock, log out, force quit,
        // Spotlight, task switching and screenshots: all capability_denied.
        for shortcut in [
            "cmd+q",
            "ctrl+alt+delete",
            "ctrl+cmd+q",
            "cmd+space",
            "cmd+tab",
            "alt+f4",
            "super+l",
            "ctrl+alt+l",
            "Meta",
            "super",
            "cmd",
            "Command",
            "ctrl",
            "Control",
            "alt",
            "Option",
            "shift",
            "fn",
            "win",
            "windows",
            "f1",
            "F4",
            "f12",
            "cmd+shift+3",
            "ctrl-alt-del",
            "cmd shift 4",
            "cmd,q",
            "capslock",
            "a+b",
        ] {
            assert_eq!(
                denied(classify_key(shortcut)),
                code::CAPABILITY_DENIED,
                "{shortcut}"
            );
        }
        // Anything else is simply not in the set.
        for unknown in [
            "",
            "ab",
            "enterx",
            "printscreen",
            "menu",
            "insert",
            "numlock",
            "é",
            "volumeup",
            "power",
            "eject",
            "\u{1b}",
            "a\0",
            "sleep",
        ] {
            assert_eq!(
                denied(classify_key(unknown)),
                code::INVALID_REQUEST,
                "{unknown:?}"
            );
        }
        assert_eq!(
            denied(classify_key(
                &"a".repeat(crate::protocol::MAX_KEY_BYTES + 1)
            )),
            code::INVALID_REQUEST
        );
    }

    #[test]
    fn the_human_input_binding_tolerates_jitter_and_refuses_newer_input() {
        assert!(tick_is_fresh(1_000, 1_000));
        assert!(tick_is_fresh(1_000, 1_000 + TICK_TOLERANCE_MS));
        assert!(tick_is_fresh(1_000, 1_000 - 20));
        // A keystroke or pointer move after the read.
        assert!(!tick_is_fresh(1_000, 1_000 + TICK_TOLERANCE_MS + 1));
        assert!(!tick_is_fresh(1_000, 90_000));
        // A tick the kernel could not read (0) never matches a live one.
        assert!(!tick_is_fresh(0, 5_000_000));
        // The tick wraps every 49.7 days.
        assert!(tick_is_fresh(u32::MAX - 10, 10));
        assert!(!tick_is_fresh(u32::MAX - 100, 2_000));
        // Keystrokes arrive tens of milliseconds apart: the blind spot is
        // clock jitter, not half a second.
        assert!(!tick_is_fresh(1_000, 1_000 + 100));
        assert!(TICK_TOLERANCE_MS <= 30);
    }

    #[test]
    fn the_hosts_own_events_move_the_baseline_and_a_persons_do_not() {
        let x11 = OwnEvents::MoveTheClock;
        // A unit delivered between 5_000 and 5_020 moves the idle clock to
        // 5_010: that is explained. No movement at all is explained too.
        assert!(explained_by_own_events(x11, 1_000, 5_010, 5_000, 5_020));
        assert!(explained_by_own_events(x11, 1_000, 1_005, 5_000, 5_020));
        // A person typing keeps the tick newer than the unit: not explained,
        // however many times it is read.
        assert!(!explained_by_own_events(x11, 1_000, 5_150, 5_000, 5_020));
        assert!(!explained_by_own_events(x11, 1_000, 5_100, 5_000, 5_020));
        // A touch before the unit began and after the baseline.
        assert!(!explained_by_own_events(x11, 1_000, 3_000, 5_000, 5_020));
        // The clock wraps.
        assert!(explained_by_own_events(
            x11,
            u32::MAX - 500,
            5,
            u32::MAX - 20,
            30
        ));
        assert!(!explained_by_own_events(
            x11,
            u32::MAX - 500,
            500,
            u32::MAX - 20,
            30
        ));
        // A person who keeps typing through a whole sequence is caught at the
        // first unit that follows a keystroke outside the unit's own window.
        let strokes = [5_150u32, 5_400, 5_650];
        let mut baseline = 1_000u32;
        let mut cancelled = false;
        for (index, stroke) in strokes.iter().enumerate() {
            let start = 5_000 + index as u32 * 250;
            if !explained_by_own_events(x11, baseline, *stroke, start, start + 20) {
                cancelled = true;
                break;
            }
            baseline = *stroke;
        }
        assert!(cancelled);
    }

    /// #404: the window that explains a tick is the delivery call and the
    /// clock-reading margin only. The settle wait after the call is not in
    /// it, so a person who touches the pointer while the host waits for its
    /// unit to be processed is caught.
    #[test]
    fn right_before_the_call_the_tick_must_still_be_the_baseline() {
        let (x11, mac) = (OwnEvents::MoveTheClock, OwnEvents::LeaveTheClock);
        assert!(still_at_baseline(x11, 10_105, 10_105));
        assert!(still_at_baseline(x11, 10_105, 10_105 + TICK_TOLERANCE_MS));
        assert!(!still_at_baseline(x11, 10_105, 10_200));
        assert!(still_at_baseline(mac, 1_000, 1_001));
        assert!(!still_at_baseline(mac, 1_000, 1_002));
        assert!(!still_at_baseline(mac, 1_000, 1_020));
    }

    #[test]
    fn the_explained_window_is_the_call_and_the_reading_margin_only() {
        let x11 = OwnEvents::MoveTheClock;
        let (start, end) = (5_000u32, 5_020u32);
        assert!(explained_by_own_events(
            x11,
            1_000,
            end + OWN_EVENT_MARGIN_MS,
            start,
            end
        ));
        assert!(!explained_by_own_events(
            x11,
            1_000,
            end + OWN_EVENT_MARGIN_MS + 1,
            start,
            end
        ));
        assert!(explained_by_own_events(
            x11,
            1_000,
            start - OWN_EVENT_MARGIN_MS,
            start,
            end
        ));
        assert!(!explained_by_own_events(
            x11,
            1_000,
            start - OWN_EVENT_MARGIN_MS - 1,
            start,
            end
        ));
        // A touch 25 ms into the 40 ms settle wait: the old window (call,
        // settle and 30 ms either side) explained it; this one does not.
        assert!(!explained_by_own_events(x11, 1_000, end + 25, start, end));
    }

    /// #404: on macOS the host's events never move the session clock, so the
    /// tick must stay what it was, up to the reader's millisecond rounding.
    /// A change inside the delivery call is the person, not the host.
    #[test]
    fn on_macos_the_tick_must_stay_exactly_equal() {
        let mac = OwnEvents::LeaveTheClock;
        assert_eq!(OwnEvents::on(crate::protocol::MACOS), mac);
        assert_eq!(
            OwnEvents::on(crate::protocol::LINUX_X11),
            OwnEvents::MoveTheClock
        );
        assert!(explained_by_own_events(mac, 1_000, 1_000, 5_000, 5_020));
        assert!(explained_by_own_events(mac, 1_000, 1_001, 5_000, 5_020));
        assert!(explained_by_own_events(mac, 1_000, 999, 5_000, 5_020));
        assert!(!explained_by_own_events(mac, 1_000, 1_002, 5_000, 5_020));
        assert!(!explained_by_own_events(mac, 1_000, 998, 5_000, 5_020));
        // Inside the call, where X11 would accept it, and within the 30 ms
        // jitter tolerance of the baseline: both refused on macOS.
        assert!(!explained_by_own_events(mac, 1_000, 5_010, 5_000, 5_020));
        assert!(!explained_by_own_events(mac, 1_000, 1_020, 5_000, 5_020));
        // The clock wraps.
        assert!(explained_by_own_events(mac, u32::MAX, 0, 5_000, 5_020));
        assert!(!explained_by_own_events(mac, u32::MAX, 1, 5_000, 5_020));
    }

    #[test]
    fn the_person_must_have_been_quiet_before_the_first_unit() {
        assert_eq!(quiet_remaining_ms(10_000, 9_000), 0);
        assert_eq!(quiet_remaining_ms(10_000, 10_000 - QUIET_MS), 0);
        assert_eq!(quiet_remaining_ms(10_000, 9_900), QUIET_MS - 100);
        assert_eq!(quiet_remaining_ms(10_000, 10_000), QUIET_MS);
        // An input stamped in the future of the clock is not quiet either.
        assert_eq!(quiet_remaining_ms(10_000, 10_500), QUIET_MS);
    }

    fn window(id: u64, x: f64, y: f64, w: f64, h: f64, z: Option<i64>) -> WindowInfo {
        WindowInfo {
            window_id: id,
            pid: Some(10),
            app_name: "App".into(),
            title: "T".into(),
            bounds: WindowBounds {
                x,
                y,
                width: w,
                height: h,
            },
            is_on_screen: true,
            z_index: z,
            layer: Some(0),
            minimized: None,
            current_space_id: None,
            on_current_space: None,
            space_ids: None,
        }
    }

    #[test]
    fn a_window_in_front_at_the_point_covers_the_target() {
        let target = window(1, 100.0, 50.0, 320.0, 200.0, Some(5));
        let behind = window(2, 0.0, 0.0, 2000.0, 2000.0, Some(2));
        let beside = window(3, 500.0, 50.0, 100.0, 100.0, Some(9));
        let in_front = window(4, 150.0, 80.0, 40.0, 40.0, Some(9));
        let all = |extra: &[WindowInfo]| {
            let mut all = vec![target.clone(), behind.clone(), beside.clone()];
            all.extend_from_slice(extra);
            all
        };
        assert_eq!(
            occluded_at(&target, &all(&[]), 110.0, 60.0),
            Occlusion::Clear
        );
        assert_eq!(
            occluded_at(&target, &all(std::slice::from_ref(&in_front)), 160.0, 90.0),
            Occlusion::Covered
        );
        // The same window does not cover a point outside it.
        assert_eq!(
            occluded_at(&target, &all(std::slice::from_ref(&in_front)), 300.0, 200.0),
            Occlusion::Clear
        );
        // Edges: the far edge is outside the covering window.
        assert_eq!(
            occluded_at(&target, &all(std::slice::from_ref(&in_front)), 190.0, 90.0),
            Occlusion::Clear
        );
        // A hidden, minimized or other-Space window covers nothing.
        for hide in [
            |w: &mut WindowInfo| w.is_on_screen = false,
            |w: &mut WindowInfo| w.minimized = Some(true),
            |w: &mut WindowInfo| w.on_current_space = Some(false),
        ] {
            let mut hidden = in_front.clone();
            hide(&mut hidden);
            assert_eq!(
                occluded_at(&target, &all(&[hidden]), 160.0, 90.0),
                Occlusion::Clear
            );
        }
        // A window of the target's own application counts too.
        let mut own = in_front.clone();
        own.pid = target.pid;
        assert_eq!(
            occluded_at(&target, &all(&[own]), 160.0, 90.0),
            Occlusion::Covered
        );
    }

    #[test]
    fn an_unreadable_stacking_order_proves_nothing() {
        let target = window(1, 100.0, 50.0, 320.0, 200.0, None);
        let other = window(2, 150.0, 80.0, 40.0, 40.0, Some(9));
        assert_eq!(
            occluded_at(&target, &[target.clone(), other.clone()], 160.0, 90.0),
            Occlusion::Unknown
        );
        // Unreadable only matters where a window actually is.
        assert_eq!(
            occluded_at(&target, &[target.clone(), other], 300.0, 200.0),
            Occlusion::Clear
        );
        let target = window(1, 100.0, 50.0, 320.0, 200.0, Some(5));
        let unordered = window(2, 150.0, 80.0, 40.0, 40.0, None);
        assert_eq!(
            occluded_at(&target, &[target.clone(), unordered], 160.0, 90.0),
            Occlusion::Unknown
        );
        // A tie is not "in front".
        let tie = window(2, 150.0, 80.0, 40.0, 40.0, Some(5));
        assert_eq!(
            occluded_at(&target, &[target.clone(), tie], 160.0, 90.0),
            Occlusion::Clear
        );
    }

    #[test]
    fn the_frame_maps_window_points_to_the_screen_and_notices_drift() {
        let live = frame();
        assert_eq!(live.screen_point(10, 20), (110.0, 70.0));
        assert!(live.matches(&Frame {
            origin_x: 100.5,
            ..live
        }));
        assert!(!live.matches(&Frame {
            origin_x: 102.0,
            ..live
        }));
        assert!(!live.matches(&Frame {
            width: 330.0,
            ..live
        }));
        assert!(!live.matches(&Frame {
            height: 100.0,
            ..live
        }));
    }

    #[test]
    fn only_a_coherent_one_or_two_times_capture_gives_a_scale() {
        assert_eq!(backing_scale(320.0, 200.0, 320, 200), Some(1.0));
        assert_eq!(backing_scale(320.0, 200.0, 640, 400), Some(2.0));
        assert_eq!(backing_scale(320.0, 200.0, 641, 400), Some(2.0));
        assert_eq!(backing_scale(320.0, 200.0, 700, 400), None);
        assert_eq!(backing_scale(320.0, 200.0, 640, 200), None);
        assert_eq!(backing_scale(320.0, 200.0, 960, 600), None);
        assert_eq!(backing_scale(0.0, 200.0, 0, 400), None);
        assert_eq!(backing_scale(f64::NAN, 200.0, 640, 400), None);
    }

    #[test]
    fn a_secure_field_anywhere_in_the_tree_blocks_input() {
        let element = |role: &str| WindowElement {
            element_index: 0,
            role: role.into(),
            depth: 0,
            element_token: None,
            label: None,
            value: None,
            value_description: None,
            enabled: Some(true),
            selected: None,
            in_web_content: None,
            actions: None,
            parent_index: None,
            frame: None,
            min: None,
            max: None,
        };
        assert!(shows_secure_field(&[
            element("AXWindow"),
            element("AXSecureTextField")
        ]));
        assert!(shows_secure_field(&[element("password text")]));
        assert!(!shows_secure_field(&[
            element("AXWindow"),
            element("AXTextField")
        ]));
        assert!(!shows_secure_field(&[]));
    }

    #[test]
    fn the_input_set_is_exactly_five_operations() {
        assert_eq!(INPUT_OPERATIONS.len(), 5);
        for op in INPUT_OPERATIONS {
            assert!(is_input_operation(op));
            assert!(field_rules(op).is_some());
            assert_eq!(is_keyboard_operation(op), KEYBOARD_OPERATIONS.contains(&op));
            assert!(POINTER_OPERATIONS.contains(&op) != is_keyboard_operation(op));
        }
        for op in [
            "input_move",
            "input_hotkey",
            "window_action",
            "semantic_action",
            "",
        ] {
            assert!(!is_input_operation(op), "{op}");
            assert!(field_rules(op).is_none(), "{op}");
        }
    }
}
