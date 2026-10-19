//! SG-000063 live read-only desktop observation on Windows.
//!
//! This module reads the caller's interactive desktop through Win32 and UI
//! Automation and never changes it: no focus, activation, input, pattern
//! invocation, or window message is sent. It reports OS facts only; the
//! registry still allocates identities and applies bounds, protected-surface
//! exclusion, and redaction.
//!
//! - Only the interactive window station `WinSta0` is observed; any other
//!   station (a service session, a non-interactive runner) fails closed as
//!   unavailable instead of reporting an empty desktop as real.
//! - Only visible, uncloaked, titled top-level windows owned by processes in
//!   the caller's session are reported. Windows of this process, which hosts
//!   the Orcel approval prompts, of the Orcel product executables, and of
//!   the Windows credential, consent, and logon prompt hosts are never
//!   reported. Processes whose image path and creation time cannot be read
//!   are omitted rather than given a fabricated identity.
//! - Tree reads use the UIA control view with bounded depth and node count
//!   and bounded COM timeouts. Password elements are detected through
//!   `IsPassword` and their values are never read.

use crate::{
    digest_hex, NativeElement, NativeProcess, NativeWindow, UiaError, ID_HEX_CHARS, MAX_TREE_DEPTH,
    MAX_TREE_NODES, UIA_SCHEMA,
};
use orcel_contracts::FailureCode;
use std::ffi::c_void;
use windows::core::Interface;
use windows::Win32::Foundation::{BOOL, HANDLE, HWND, LPARAM};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
    SAFEARRAY,
};
use windows::Win32::System::Ole::{
    SafeArrayDestroy, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
};
use windows::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetUserObjectInformationW, UOI_NAME,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation8, IUIAutomation, IUIAutomation2, IUIAutomationElement,
    IUIAutomationScrollPattern, IUIAutomationSelectionItemPattern, IUIAutomationTogglePattern,
    IUIAutomationTreeWalker, IUIAutomationValuePattern, ToggleState_On, UIA_InvokePatternId,
    UIA_ScrollPatternId, UIA_SelectionItemPatternId, UIA_TogglePatternId, UIA_ValuePatternId,
    UIA_PATTERN_ID,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId, IsWindow, IsWindowVisible,
};

/// UIA cross-process connection and transaction timeouts, so one hung
/// application cannot stall orceld.
const UIA_CONNECTION_TIMEOUT_MS: u32 = 2_000;
const UIA_TRANSACTION_TIMEOUT_MS: u32 = 5_000;
const TITLE_BUFFER_CHARS: usize = 512;

/// Executables whose windows are never observed: the Orcel product
/// executables, and the Windows hosts of credential, consent, and logon
/// prompts. `CredentialUIBroker.exe` hosts the Windows Hello dialog that
/// shows Orcel's STRONG approval request, so it is a protected surface.
const EXCLUDED_EXECUTABLES: &[&str] = &[
    "orcel.exe",
    "orceld.exe",
    "orcel-mcp-host.exe",
    "credentialuibroker.exe",
    "consent.exe",
    "logonui.exe",
];

pub(crate) fn is_excluded_executable(exe_name: &str) -> bool {
    EXCLUDED_EXECUTABLES
        .iter()
        .any(|excluded| exe_name.eq_ignore_ascii_case(excluded))
}

fn unavailable(message: impl Into<String>) -> UiaError {
    UiaError::new(FailureCode::ProviderUnavailable, message)
}

fn utf16_text(buffer: &[u16]) -> String {
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..end])
}

/// Only the interactive window station hosts the user's desktop.
pub(crate) fn is_interactive_station(name: &str) -> bool {
    name.eq_ignore_ascii_case("WinSta0")
}

/// Fail closed unless this process is attached to the interactive window
/// station. A service or non-interactive session has no user desktop.
pub(crate) fn require_interactive_station() -> Result<(), UiaError> {
    let station = unsafe { GetProcessWindowStation() }.map_err(|_| {
        unavailable("this process has no window station; desktop observation is unavailable")
    })?;
    let mut name = [0u16; 64];
    let mut needed = 0u32;
    unsafe {
        GetUserObjectInformationW(
            HANDLE(station.0),
            UOI_NAME,
            Some(name.as_mut_ptr().cast()),
            (name.len() * 2) as u32,
            Some(&mut needed),
        )
    }
    .map_err(|_| {
        unavailable("the window station name is unreadable; desktop observation is unavailable")
    })?;
    if !is_interactive_station(&utf16_text(&name)) {
        return Err(unavailable(
            "this process is not attached to the interactive window station; desktop observation is unavailable",
        ));
    }
    Ok(())
}

/// XP-03: the terminal session read lives in orcel-platform.
fn session_of(pid: u32) -> Option<u32> {
    orcel_platform::session::session_of_pid(pid).ok()
}

fn own_session() -> Result<u32, UiaError> {
    session_of(std::process::id()).ok_or_else(|| {
        unavailable("the caller's session is unreadable; desktop observation is unavailable")
    })
}

fn hwnd_from(raw: u64) -> HWND {
    HWND(raw as usize as *mut c_void)
}

fn window_text(hwnd: HWND) -> String {
    let mut buffer = [0u16; TITLE_BUFFER_CHARS];
    let len = unsafe { GetWindowTextW(hwnd, &mut buffer) };
    utf16_text(&buffer[..len.max(0) as usize])
}

fn class_name(hwnd: HWND) -> String {
    let mut buffer = [0u16; 256];
    let len = unsafe { GetClassNameW(hwnd, &mut buffer) };
    utf16_text(&buffer[..len.max(0) as usize])
}

fn is_cloaked(hwnd: HWND) -> bool {
    let mut cloaked = 0u32;
    unsafe {
        DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            (&mut cloaked as *mut u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    }
    .map(|_| cloaked != 0)
    .unwrap_or(false)
}

fn owner_pid(hwnd: HWND) -> u32 {
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    pid
}

unsafe extern "system" fn collect_handle(hwnd: HWND, lparam: LPARAM) -> BOOL {
    let handles = &mut *(lparam.0 as *mut Vec<u64>);
    handles.push(hwnd.0 as usize as u64);
    BOOL(1)
}

/// One visible top-level window in the caller's session.
#[derive(Debug, Clone)]
pub(crate) struct DesktopWindow {
    pub hwnd: u64,
    pub pid: u32,
    pub title: String,
    pub class: String,
}

/// Enumerate visible, uncloaked, titled top-level windows owned by other
/// processes in the caller's session. Windows of this process are never
/// reported because this process shows the Orcel approval prompts.
pub(crate) fn visible_windows() -> Result<Vec<DesktopWindow>, UiaError> {
    require_interactive_station()?;
    let session = own_session()?;
    let own_pid = std::process::id();
    let mut handles: Vec<u64> = Vec::new();
    unsafe {
        EnumWindows(
            Some(collect_handle),
            LPARAM(&mut handles as *mut Vec<u64> as isize),
        )
    }
    .map_err(|_| unavailable("top-level window enumeration failed"))?;
    let mut windows = Vec::new();
    for raw in handles {
        let hwnd = hwnd_from(raw);
        if !unsafe { IsWindowVisible(hwnd) }.as_bool() || is_cloaked(hwnd) {
            continue;
        }
        let title = window_text(hwnd);
        if title.trim().is_empty() {
            continue;
        }
        let pid = owner_pid(hwnd);
        if pid == 0 || pid == own_pid || session_of(pid) != Some(session) {
            continue;
        }
        windows.push(DesktopWindow {
            hwnd: raw,
            pid,
            title,
            class: class_name(hwnd),
        });
    }
    Ok(windows)
}

/// Read the identity facts of one process: its Win32 image path and its
/// creation time as the start generation. Returns `None` when either fact
/// is unreadable, so the caller omits the process instead of fabricating it.
pub(crate) fn process_facts(pid: u32) -> Option<NativeProcess> {
    let session_id = session_of(pid)?;
    // XP-03: one process handle in orcel-platform reads both facts.
    let (image, generation) = orcel_platform::process::image_path_and_generation(pid).ok()?;
    let exe_name = image.rsplit(['\\', '/']).next().unwrap_or("").to_owned();
    if exe_name.is_empty() || is_excluded_executable(&exe_name) {
        return None;
    }
    Some(NativeProcess {
        pid,
        exe_name,
        exe_id: digest_hex(
            &format!("{UIA_SCHEMA}|exe|{}", image.to_lowercase()),
            ID_HEX_CHARS,
        ),
        session_id,
        session_verified: true,
        start_generation: generation.generation,
        generation_source: generation.source,
    })
}

/// Bind one desktop window to the adapter window shape. The nonce changes
/// when the owning process instance or the window class changes behind the
/// same handle; the registry also compares the title and class.
pub(crate) fn native_window(window: &DesktopWindow, process: &NativeProcess) -> NativeWindow {
    let nonce = digest_hex(
        &format!(
            "{UIA_SCHEMA}|nonce|{}|{}|{}",
            process.pid, process.start_generation, window.class
        ),
        ID_HEX_CHARS,
    );
    NativeWindow {
        hwnd: window.hwnd,
        title: window.title.clone(),
        class: window.class.clone(),
        visible: true,
        window_nonce: u64::from_str_radix(&nonce, 16).unwrap_or(0),
    }
}

struct ComScope(bool);

impl ComScope {
    fn enter() -> Self {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        Self(result.is_ok())
    }
}

impl Drop for ComScope {
    fn drop(&mut self) {
        if self.0 {
            unsafe { CoUninitialize() };
        }
    }
}

/// Read the bounded UIA control-view tree of one top-level window. The
/// window must still exist, be visible, and belong to another process in the
/// caller's session. The adapter reads at most one level and one node past
/// the registry bounds so the registry can report truncation honestly.
pub(crate) fn read_tree(raw: u64) -> Result<Vec<NativeElement>, UiaError> {
    require_interactive_station()?;
    let session = own_session()?;
    let hwnd = hwnd_from(raw);
    if !unsafe { IsWindow(hwnd) }.as_bool() || !unsafe { IsWindowVisible(hwnd) }.as_bool() {
        return Err(UiaError::new(
            FailureCode::TargetStale,
            "the window no longer exists or is no longer visible",
        ));
    }
    let pid = owner_pid(hwnd);
    if pid == 0 || pid == std::process::id() || session_of(pid) != Some(session) {
        return Err(UiaError::new(
            FailureCode::CapabilityDenied,
            "the window is outside the caller's observable session",
        ));
    }
    // A recycled handle may now belong to an excluded or unidentifiable
    // process; re-check the owner before reading anything.
    if process_facts(pid).is_none() {
        return Err(UiaError::new(
            FailureCode::CapabilityDenied,
            "the window owner is excluded or its identity is unreadable",
        ));
    }
    let _com = ComScope::enter();
    read_tree_with_com(hwnd)
}

fn read_tree_with_com(hwnd: HWND) -> Result<Vec<NativeElement>, UiaError> {
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|_| unavailable("UI Automation is unavailable in this session"))?;
    if let Ok(bounded) = automation.cast::<IUIAutomation2>() {
        unsafe {
            let _ = bounded.SetConnectionTimeout(UIA_CONNECTION_TIMEOUT_MS);
            let _ = bounded.SetTransactionTimeout(UIA_TRANSACTION_TIMEOUT_MS);
        }
    }
    let root = unsafe { automation.ElementFromHandle(hwnd) }
        .map_err(|_| unavailable("UI Automation could not bind the window"))?;
    let walker = unsafe { automation.ControlViewWalker() }
        .map_err(|_| unavailable("the UI Automation control view is unavailable"))?;
    let mut budget = MAX_TREE_NODES + 1;
    let mut fallback = 0u64;
    Ok(vec![read_element(
        &walker,
        &root,
        0,
        &mut budget,
        &mut fallback,
    )])
}

fn read_element(
    walker: &IUIAutomationTreeWalker,
    element: &IUIAutomationElement,
    depth: usize,
    budget: &mut usize,
    fallback: &mut u64,
) -> NativeElement {
    *budget = budget.saturating_sub(1);
    let mut native = describe(element, fallback);
    if depth <= MAX_TREE_DEPTH {
        let mut child = unsafe { walker.GetFirstChildElement(element) }.ok();
        while let Some(current) = child {
            if *budget == 0 {
                break;
            }
            native
                .children
                .push(read_element(walker, &current, depth + 1, budget, fallback));
            child = unsafe { walker.GetNextSiblingElement(&current) }.ok();
        }
    }
    native
}

fn has_pattern(element: &IUIAutomationElement, pattern: UIA_PATTERN_ID) -> bool {
    unsafe { element.GetCurrentPattern(pattern) }.is_ok()
}

fn describe(element: &IUIAutomationElement, fallback: &mut u64) -> NativeElement {
    let control_type = unsafe { element.CurrentControlType() }
        .map(|id| control_type_name(id.0).to_owned())
        .unwrap_or_else(|_| "Unknown".to_owned());
    let automation_id = unsafe { element.CurrentAutomationId() }
        .map(|text| text.to_string())
        .unwrap_or_default();
    let name = unsafe { element.CurrentName() }
        .map(|text| text.to_string())
        .unwrap_or_default();
    let enabled = unsafe { element.CurrentIsEnabled() }
        .map(|flag| flag.as_bool())
        .unwrap_or(false);
    // Treat an unreadable password flag as a password so values stay unread.
    let value_is_password = unsafe { element.CurrentIsPassword() }
        .map(|flag| flag.as_bool())
        .unwrap_or(true);
    let runtime_id = runtime_id(element).unwrap_or_else(|| {
        *fallback += 1;
        format!("unidentified.{fallback}")
    });
    let mut patterns = Vec::new();
    if has_pattern(element, UIA_InvokePatternId) {
        patterns.push("Invoke".to_owned());
    }
    let mut value = None;
    if let Ok(pattern) =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationValuePattern>(UIA_ValuePatternId) }
    {
        patterns.push("Value".to_owned());
        if !value_is_password {
            value = unsafe { pattern.CurrentValue() }
                .ok()
                .map(|text| text.to_string());
        }
    }
    let mut selected = false;
    if let Ok(pattern) = unsafe {
        element.GetCurrentPatternAs::<IUIAutomationSelectionItemPattern>(UIA_SelectionItemPatternId)
    } {
        patterns.push("SelectionItem".to_owned());
        selected = unsafe { pattern.CurrentIsSelected() }
            .map(|flag| flag.as_bool())
            .unwrap_or(false);
    }
    let mut toggled = false;
    if let Ok(pattern) =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationTogglePattern>(UIA_TogglePatternId) }
    {
        patterns.push("Toggle".to_owned());
        toggled = unsafe { pattern.CurrentToggleState() }
            .map(|state| state == ToggleState_On)
            .unwrap_or(false);
    }
    let mut scroll_horizontal_percent = 0u8;
    let mut scroll_vertical_percent = 0u8;
    if let Ok(pattern) =
        unsafe { element.GetCurrentPatternAs::<IUIAutomationScrollPattern>(UIA_ScrollPatternId) }
    {
        patterns.push("Scroll".to_owned());
        scroll_horizontal_percent =
            percent(unsafe { pattern.CurrentHorizontalScrollPercent() }.unwrap_or(-1.0));
        scroll_vertical_percent =
            percent(unsafe { pattern.CurrentVerticalScrollPercent() }.unwrap_or(-1.0));
    }
    NativeElement {
        runtime_id,
        control_type,
        automation_id,
        name,
        enabled,
        selected,
        toggled,
        scroll_horizontal_percent,
        scroll_vertical_percent,
        patterns,
        value,
        value_is_password,
        children: Vec::new(),
    }
}

/// UIA reports -1 when an axis cannot scroll; that and any out-of-range
/// value clamp into 0..=100.
fn percent(value: f64) -> u8 {
    if value.is_finite() && value > 0.0 {
        value.round().min(100.0) as u8
    } else {
        0
    }
}

fn runtime_id(element: &IUIAutomationElement) -> Option<String> {
    let array: *mut SAFEARRAY = unsafe { element.GetRuntimeId() }.ok()?;
    if array.is_null() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    unsafe {
        if let (Ok(lower), Ok(upper)) = (SafeArrayGetLBound(array, 1), SafeArrayGetUBound(array, 1))
        {
            for index in lower..=upper.min(lower + 31) {
                let mut part = 0i32;
                if SafeArrayGetElement(array, &index, (&mut part as *mut i32).cast()).is_ok() {
                    parts.push(part.to_string());
                }
            }
        }
        let _ = SafeArrayDestroy(array);
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("."))
    }
}

fn control_type_name(id: i32) -> &'static str {
    match id {
        50000 => "Button",
        50001 => "Calendar",
        50002 => "CheckBox",
        50003 => "ComboBox",
        50004 => "Edit",
        50005 => "Hyperlink",
        50006 => "Image",
        50007 => "ListItem",
        50008 => "List",
        50009 => "Menu",
        50010 => "MenuBar",
        50011 => "MenuItem",
        50012 => "ProgressBar",
        50013 => "RadioButton",
        50014 => "ScrollBar",
        50015 => "Slider",
        50016 => "Spinner",
        50017 => "StatusBar",
        50018 => "Tab",
        50019 => "TabItem",
        50020 => "Text",
        50021 => "ToolBar",
        50022 => "ToolTip",
        50023 => "Tree",
        50024 => "TreeItem",
        50025 => "Custom",
        50026 => "Group",
        50027 => "Thumb",
        50028 => "DataGrid",
        50029 => "DataItem",
        50030 => "Document",
        50031 => "SplitButton",
        50032 => "Window",
        50033 => "Pane",
        50034 => "Header",
        50035 => "HeaderItem",
        50036 => "Table",
        50037 => "TitleBar",
        50038 => "Separator",
        50039 => "SemanticZoom",
        50040 => "AppBar",
        _ => "Unknown",
    }
}
