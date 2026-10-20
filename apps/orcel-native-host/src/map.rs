// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Cua observations mapped into Orcel's `windowFact` and `elementFact`.
//!
//! Everything here is pure, so it is tested on every OS. The worker supplies
//! the live process facts.
//!
//! Window identity: Cua's window id is carried as an opaque `u64` of the
//! kind this host serves. Orcel adds the owning process's start generation
//! (`orcel-platform`, XP-03) and a nonce over the kind, id, pid, generation,
//! Linux boot id and owning application, so a recycled window id or pid
//! never matches an old binding.
//!
//! Elements: Cua returns a flat list in depth-first order, each actionable
//! row carrying the `element_index` of its nearest actionable ancestor. The
//! tree is rebuilt from those links, bounded by node count and depth.
//!
//! Role table (`control_type`): AX roles and AT-SPI role names map onto the
//! UIA control type names the registry already knows; see [`control_type`].
//! An unknown role is `Custom`, never guessed.
//!
//! Redaction, as the Windows host does it with UIA `IsPassword`: a secure
//! text role (`AXSecureTextField`, which patch P-06 reports, or an AT-SPI
//! `password text`) is `value_is_password` and its value is never sent. The
//! host also drops the value of any element whose role or name carries a
//! password marker, the rule the registry applies again.

use crate::protocol::{ElementFact, ProcessFact, WindowFact, MAX_TEXT_BYTES, MAX_WINDOWS};
use cua_driver_contract::{WindowElement, WindowInfo};
use sha2::{Digest, Sha256};

/// Longest title, application name or element name sent, in characters.
pub const MAX_NAME_CHARS: usize = 1024;
/// Longest element runtime id sent, in bytes (the `/1` request bound).
pub const MAX_RUNTIME_ID_BYTES: usize = 512;
/// Most patterns sent per element, as the adapter keeps.
pub const MAX_PATTERNS: usize = 16;

/// Executables whose windows the host never lists or observes, compared
/// case-insensitively with the image file name. The Windows host keeps the
/// same kind of list (`protectedExecutables` in `native_win32_windows.go`):
/// Orcel itself and the OS authentication and lock surfaces.
#[cfg(target_os = "macos")]
pub const PROTECTED_EXECUTABLES: &[&str] = &[
    "orcel",
    "orceld",
    "orcel-native-host",
    "loginwindow",
    "securityagent",
    "screensaverengine",
    "coreautha",
];
#[cfg(not(target_os = "macos"))]
pub const PROTECTED_EXECUTABLES: &[&str] = &[
    "orcel",
    "orceld",
    "orcel-native-host",
    "polkit-gnome-authentication-agent-1",
    "polkit-kde-authentication-agent-1",
    "polkit-mate-authentication-agent-1",
    "lxpolkit",
    "xfce-polkit",
    "gnome-screensaver",
    "xscreensaver",
    "i3lock",
    "swaylock",
    "light-locker",
    "kscreenlocker_greet",
    "xsecurelock",
];

/// Substrings that mark a password-bearing control, as the registry's
/// `PASSWORD_MARKERS` in `crates/orcel-provider-uia/src/lib.rs`.
const PASSWORD_MARKERS: &[&str] = &["password", "passwd", "secret", "token"];

pub fn is_protected_executable(exe_name: &str) -> bool {
    PROTECTED_EXECUTABLES
        .iter()
        .any(|name| exe_name.eq_ignore_ascii_case(name))
}

/// Truncates to at most `limit` characters.
pub fn bound_chars(raw: &str, limit: usize) -> String {
    raw.chars().take(limit).collect()
}

/// Truncates to at most `limit` bytes on a character boundary.
pub fn bound_bytes(raw: &str, limit: usize) -> String {
    if raw.len() <= limit {
        return raw.to_owned();
    }
    let mut end = limit;
    while !raw.is_char_boundary(end) {
        end -= 1;
    }
    raw[..end].to_owned()
}

/// The stable id of an executable path, as the Windows host derives it.
pub fn exe_id(path: &str) -> String {
    let digest = Sha256::digest(format!("orcel-computer-host/exe/v1|{path}").as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// What the host binds a window to besides its id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub fact: ProcessFact,
    /// Linux boot id; folded into the nonce because the start generation
    /// restarts at every boot.
    pub boot_id: Option<u128>,
}

/// The replacement marker of one window. Any change of kind, id, owning
/// process instance or owning application gives another value.
pub fn window_nonce(kind: &str, id: u64, process: &ProcessIdentity, application: &str) -> u64 {
    let material = format!(
        "orcel-native-host/window/v1|{kind}|{id}|{}|{}|{}|{application}",
        process.fact.pid,
        process.fact.start_generation,
        process.boot_id.unwrap_or(0)
    );
    let digest = Sha256::digest(material.as_bytes());
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(bytes)
}

/// Why a Cua window was left out of a listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Omission {
    /// The window has no attested owner pid (for example GNOME or KDE
    /// Wayland without Cua's compositor helper). Identity is never inferred
    /// from a title.
    NoAttestedOwner,
    /// The host's own window, or an id of 0.
    NotATarget,
    /// Off screen or untitled, as the Windows host skips them.
    NotVisible,
    /// The owner exited, runs as another user, or its facts are unreadable.
    OwnerUnreadable,
    /// The owner is a protected executable.
    Protected,
    /// More than 64 windows.
    OverLimit,
}

/// Maps Cua windows into window facts. `identity` reads the live facts of
/// a pid and returns `None` when the process is gone, unreadable or owned by
/// another user.
pub fn map_windows(
    windows: &[WindowInfo],
    kind: &str,
    own_pid: u32,
    mut identity: impl FnMut(u32) -> Option<ProcessIdentity>,
) -> (Vec<WindowFact>, Vec<Omission>) {
    let mut facts = Vec::new();
    let mut omitted = Vec::new();
    for window in windows {
        let Some(pid) = window.pid else {
            omitted.push(Omission::NoAttestedOwner);
            continue;
        };
        if pid == 0 || pid == own_pid || window.window_id == 0 {
            omitted.push(Omission::NotATarget);
            continue;
        }
        let title = window.title.trim();
        if !window.is_on_screen || title.is_empty() {
            omitted.push(Omission::NotVisible);
            continue;
        }
        let Some(process) = identity(pid) else {
            omitted.push(Omission::OwnerUnreadable);
            continue;
        };
        if is_protected_executable(&process.fact.exe_name) {
            omitted.push(Omission::Protected);
            continue;
        }
        if facts.len() >= MAX_WINDOWS {
            omitted.push(Omission::OverLimit);
            continue;
        }
        let class = bound_chars(&window.app_name, MAX_NAME_CHARS);
        let window_nonce = window_nonce(kind, window.window_id, &process, &class);
        facts.push(WindowFact {
            process: process.fact,
            hwnd: window.window_id,
            title: bound_chars(title, MAX_NAME_CHARS),
            class,
            visible: true,
            window_nonce,
        });
    }
    (facts, omitted)
}

/// Normalized control type for an AX role or an AT-SPI role name.
pub fn control_type(role: &str) -> &'static str {
    match role {
        "AXButton" | "AXMenuButton" | "AXColorWell" | "AXDisclosureTriangle" => "Button",
        "AXCheckBox" => "CheckBox",
        "AXRadioButton" => "RadioButton",
        "AXTextField" | "AXSecureTextField" | "AXTextArea" | "AXDateField" | "AXTimeField" => {
            "Edit"
        }
        "AXComboBox" | "AXPopUpButton" => "ComboBox",
        "AXMenu" => "Menu",
        "AXMenuBar" => "MenuBar",
        "AXMenuItem" | "AXMenuBarItem" => "MenuItem",
        "AXList" => "List",
        "AXRow" | "AXCell" => "DataItem",
        "AXOutline" | "AXBrowser" => "Tree",
        "AXTable" | "AXGrid" => "Table",
        "AXTabGroup" => "Tab",
        "AXSlider" => "Slider",
        "AXIncrementor" | "AXStepper" => "Spinner",
        "AXScrollBar" => "ScrollBar",
        "AXStaticText" | "AXHeading" => "Text",
        "AXImage" => "Image",
        "AXLink" => "Hyperlink",
        "AXWindow" | "AXSheet" | "AXDrawer" | "AXDialog" => "Window",
        "AXToolbar" => "ToolBar",
        "AXProgressIndicator" | "AXLevelIndicator" | "AXBusyIndicator" => "ProgressBar",
        "AXGroup" | "AXRadioGroup" | "AXLayoutArea" => "Group",
        "AXScrollArea" | "AXSplitGroup" => "Pane",
        "AXSplitter" => "Thumb",
        "AXWebArea" => "Document",
        _ => atspi_control_type(&role.trim().to_ascii_lowercase()),
    }
}

fn atspi_control_type(role: &str) -> &'static str {
    match role {
        "push button" | "toggle button" | "button" => "Button",
        "check box" => "CheckBox",
        "radio button" => "RadioButton",
        "text" | "entry" | "password text" | "editbar" | "date editor" => "Edit",
        "combo box" => "ComboBox",
        "menu" | "popup menu" => "Menu",
        "menu bar" => "MenuBar",
        "menu item" | "check menu item" | "radio menu item" | "tearoff menu item" => "MenuItem",
        "list" | "list box" => "List",
        "list item" => "ListItem",
        "tree" | "tree table" => "Tree",
        "tree item" => "TreeItem",
        "table" => "Table",
        "table cell" | "cell" => "DataItem",
        "page tab list" => "Tab",
        "page tab" => "TabItem",
        "slider" => "Slider",
        "spin button" => "Spinner",
        "scroll bar" => "ScrollBar",
        "label" | "static" | "caption" | "heading" | "paragraph" => "Text",
        "image" | "icon" => "Image",
        "link" => "Hyperlink",
        "frame" | "window" | "dialog" | "alert" | "file chooser" => "Window",
        "tool bar" => "ToolBar",
        "progress bar" | "level bar" => "ProgressBar",
        "panel" | "filler" | "section" | "grouping" | "form" => "Group",
        "scroll pane" | "split pane" | "viewport" => "Pane",
        "document web" | "document frame" | "document text" | "terminal" => "Document",
        "status bar" => "StatusBar",
        "separator" => "Separator",
        "tool tip" => "ToolTip",
        _ => "Custom",
    }
}

/// Whether a role is a secure text field whose value must never be sent.
pub fn is_secure_role(role: &str) -> bool {
    role == "AXSecureTextField" || role.to_ascii_lowercase().contains("password")
}

fn has_password_marker(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    PASSWORD_MARKERS.iter().any(|marker| lower.contains(marker))
}

fn is_toggle_role(role: &str) -> bool {
    matches!(
        role,
        "AXCheckBox" | "check box" | "toggle button" | "check menu item"
    )
}

/// UIA-style pattern names from the actions an element advertises and the
/// patterns its role implies. Informational for observation.
pub fn patterns(role: &str, actions: &[String]) -> Vec<String> {
    let mut out: Vec<&'static str> = Vec::new();
    let mut add = |pattern: &'static str| {
        if !out.contains(&pattern) {
            out.push(pattern);
        }
    };
    for action in actions {
        match action.trim().to_ascii_lowercase().as_str() {
            "axpress" | "axconfirm" | "click" | "press" | "activate" | "jump" => add("Invoke"),
            "axincrement" | "axdecrement" => add("RangeValue"),
            "axshowmenu" | "expand or contract" | "expand" | "collapse" => add("ExpandCollapse"),
            "axpick" | "select" => add("SelectionItem"),
            "toggle" => add("Toggle"),
            _ => {}
        }
    }
    match control_type(role) {
        "Edit" => add("Value"),
        "CheckBox" => add("Toggle"),
        "RadioButton" | "TabItem" | "ListItem" | "TreeItem" => add("SelectionItem"),
        "Slider" | "Spinner" => add("RangeValue"),
        "ComboBox" => add("ExpandCollapse"),
        _ => {}
    }
    if is_toggle_role(role) {
        add("Toggle");
    }
    out.into_iter()
        .take(MAX_PATTERNS)
        .map(str::to_owned)
        .collect()
}

/// One Cua element as an element fact without children.
pub fn element_fact(element: &WindowElement) -> ElementFact {
    let role = element.role.as_str();
    let name = bound_chars(element.label.as_deref().unwrap_or_default(), MAX_NAME_CHARS);
    let secure = is_secure_role(role);
    let value = if secure || has_password_marker(role) || has_password_marker(&name) {
        None
    } else {
        element
            .value
            .as_deref()
            .map(|value| bound_bytes(value, MAX_TEXT_BYTES))
    };
    let runtime_id = element
        .element_token
        .clone()
        .unwrap_or_else(|| element.element_index.to_string());
    let selected = element.selected.unwrap_or(false);
    ElementFact {
        runtime_id: bound_bytes(&runtime_id, MAX_RUNTIME_ID_BYTES),
        control_type: control_type(role).to_owned(),
        automation_id: String::new(),
        name,
        enabled: element.enabled.unwrap_or(true),
        selected,
        toggled: is_toggle_role(role) && selected,
        scroll_horizontal_percent: 0,
        scroll_vertical_percent: 0,
        patterns: patterns(role, element.actions.as_deref().unwrap_or_default()),
        value,
        value_is_password: secure,
        children: Vec::new(),
    }
}

/// Rebuilds the element tree from Cua's depth-first list, keeping at most
/// `node_limit` nodes and `depth_limit` levels. A node whose parent was
/// dropped is dropped with it, so no subtree is re-rooted.
pub fn element_tree(
    elements: &[WindowElement],
    node_limit: usize,
    depth_limit: usize,
) -> Vec<ElementFact> {
    let mut slots: Vec<Option<ElementFact>> = Vec::new();
    let mut parents: Vec<Option<usize>> = Vec::new();
    let mut depths: Vec<usize> = Vec::new();
    let mut slot_of = std::collections::HashMap::<u64, Option<usize>>::new();
    for element in elements {
        if slots.len() >= node_limit {
            break;
        }
        let parent = match element.parent_index {
            None => None,
            Some(index) => match slot_of.get(&index) {
                // The parent was seen and dropped: drop this subtree too.
                Some(None) => {
                    slot_of.insert(element.element_index, None);
                    continue;
                }
                Some(Some(slot)) => Some(*slot),
                // The parent is not in the list (it was not actionable).
                None => None,
            },
        };
        let depth = parent.map_or(0, |slot| depths[slot] + 1);
        if depth >= depth_limit {
            slot_of.insert(element.element_index, None);
            continue;
        }
        slot_of.insert(element.element_index, Some(slots.len()));
        slots.push(Some(element_fact(element)));
        parents.push(parent);
        depths.push(depth);
    }
    let mut roots = Vec::new();
    for index in (0..slots.len()).rev() {
        let Some(node) = slots[index].take() else {
            continue;
        };
        match parents[index] {
            Some(parent) => {
                if let Some(parent) = slots[parent].as_mut() {
                    parent.children.push(node);
                }
            }
            None => roots.push(node),
        }
    }
    roots.reverse();
    for root in &mut roots {
        restore_order(root);
    }
    roots
}

/// Children were attached last-first; put them back in document order.
fn restore_order(node: &mut ElementFact) {
    node.children.reverse();
    for child in &mut node.children {
        restore_order(child);
    }
}

/// Total nodes in a tree.
#[cfg(test)]
pub fn count_nodes(nodes: &[ElementFact]) -> usize {
    nodes
        .iter()
        .map(|node| 1 + count_nodes(&node.children))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cua_driver_contract::WindowBounds;

    fn window(id: u64, pid: Option<u32>, title: &str, app: &str) -> WindowInfo {
        WindowInfo {
            window_id: id,
            pid,
            app_name: app.into(),
            title: title.into(),
            bounds: WindowBounds {
                x: 0.0,
                y: 0.0,
                width: 400.0,
                height: 300.0,
            },
            is_on_screen: true,
            z_index: Some(1),
            layer: Some(0),
            minimized: None,
            current_space_id: None,
            on_current_space: None,
            space_ids: None,
        }
    }

    fn identity(pid: u32, generation: u64, exe: &str) -> ProcessIdentity {
        ProcessIdentity {
            fact: ProcessFact {
                pid,
                exe_name: exe.into(),
                exe_id: exe_id(&format!("/usr/bin/{exe}")),
                session_id: 0,
                session_verified: false,
                start_generation: generation,
                generation_source: "linux-proc-starttime".into(),
            },
            boot_id: Some(7),
        }
    }

    fn element(index: u64, role: &str, parent: Option<u64>) -> WindowElement {
        WindowElement {
            element_index: index,
            role: role.into(),
            depth: 0,
            element_token: Some(format!("42:{index}")),
            label: Some(format!("node {index}")),
            value: Some(format!("value {index}")),
            value_description: None,
            enabled: Some(true),
            selected: None,
            in_web_content: None,
            actions: Some(vec!["AXPress".into()]),
            parent_index: parent,
            frame: None,
            min: None,
            max: None,
        }
    }

    #[test]
    fn identity_binding_rejects_a_recycled_window() {
        let original = identity(4410, 133_702, "gedit");
        let nonce = window_nonce("x11", 1312, &original, "gedit");
        // Same window id and pid, but a new process instance owns it.
        let recycled_pid = identity(4410, 133_999, "gedit");
        assert_ne!(nonce, window_nonce("x11", 1312, &recycled_pid, "gedit"));
        // Same process, another application behind the reused id.
        assert_ne!(nonce, window_nonce("x11", 1312, &original, "xterm"));
        // Same facts after a reboot.
        let mut rebooted = original.clone();
        rebooted.boot_id = Some(8);
        assert_ne!(nonce, window_nonce("x11", 1312, &rebooted, "gedit"));
        // A different kind or id.
        assert_ne!(nonce, window_nonce("wl_toplevel", 1312, &original, "gedit"));
        assert_ne!(nonce, window_nonce("x11", 1313, &original, "gedit"));
        assert_eq!(nonce, window_nonce("x11", 1312, &original, "gedit"));
    }

    /// A lock or authentication surface of the OS the test runs on, from
    /// that OS's own protected list.
    #[cfg(target_os = "macos")]
    const OS_LOCK_SCREEN: &str = "ScreenSaverEngine";
    #[cfg(not(target_os = "macos"))]
    const OS_LOCK_SCREEN: &str = "i3lock";

    #[test]
    fn os_lock_and_authentication_surfaces_are_protected_executables() {
        assert!(is_protected_executable(OS_LOCK_SCREEN));
        #[cfg(target_os = "macos")]
        for name in ["loginwindow", "SecurityAgent", "coreautha"] {
            assert!(is_protected_executable(name), "{name}");
        }
        #[cfg(not(target_os = "macos"))]
        for name in [
            "polkit-gnome-authentication-agent-1",
            "swaylock",
            "xscreensaver",
        ] {
            assert!(is_protected_executable(name), "{name}");
        }
        assert!(!is_protected_executable("gedit"));
    }

    #[test]
    fn windows_without_attested_owner_self_or_protected_owner_are_omitted() {
        let windows = vec![
            window(1, None, "No owner", "app"),
            window(2, Some(99), "Host itself", "host"),
            window(3, Some(10), "Locked", "lock"),
            window(4, Some(11), "", "untitled"),
            window(5, Some(12), "Gone", "gone"),
            window(6, Some(13), "Editor", "gedit"),
        ];
        let (facts, omitted) = map_windows(&windows, "x11", 99, |pid| match pid {
            10 => Some(identity(10, 1, OS_LOCK_SCREEN)),
            11 => Some(identity(11, 1, "untitled")),
            13 => Some(identity(13, 5, "gedit")),
            _ => None,
        });
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].hwnd, 6);
        assert_eq!(facts[0].title, "Editor");
        assert_eq!(facts[0].class, "gedit");
        assert_eq!(facts[0].process.start_generation, 5);
        assert_eq!(
            omitted,
            vec![
                Omission::NoAttestedOwner,
                Omission::NotATarget,
                Omission::Protected,
                Omission::NotVisible,
                Omission::OwnerUnreadable,
            ]
        );
    }

    #[test]
    fn listing_is_bounded_to_64_windows_and_bounded_strings() {
        let long = "t".repeat(5000);
        let windows: Vec<_> = (1..=80)
            .map(|id| window(id, Some(13), &long, "gedit"))
            .collect();
        let (facts, omitted) = map_windows(&windows, "x11", 1, |_| Some(identity(13, 5, "gedit")));
        assert_eq!(facts.len(), MAX_WINDOWS);
        assert_eq!(omitted.len(), 16);
        assert!(facts
            .iter()
            .all(|fact| fact.title.chars().count() == MAX_NAME_CHARS));
    }

    #[test]
    fn secure_text_values_never_leave_the_host() {
        for role in ["AXSecureTextField", "password text"] {
            let mut field = element(1, role, None);
            field.value = Some("hunter2-secret-value".into());
            field.label = Some("Sign in".into());
            let fact = element_fact(&field);
            assert!(fact.value_is_password, "{role}");
            assert_eq!(fact.value, None, "{role}");
            assert_eq!(fact.control_type, "Edit");
            let wire = serde_json::to_string(&fact).unwrap();
            assert!(!wire.contains("hunter2"), "{wire}");
        }
        // A plain field named like a secret keeps value_is_password false,
        // as on Windows, but its value is not sent either.
        let mut named = element(2, "AXTextField", None);
        named.label = Some("API token".into());
        let fact = element_fact(&named);
        assert!(!fact.value_is_password);
        assert_eq!(fact.value, None);
        // An ordinary field keeps its value.
        let plain = element_fact(&element(3, "entry", None));
        assert_eq!(plain.value.as_deref(), Some("value 3"));
    }

    #[test]
    fn tree_is_rebuilt_in_order_and_bounded() {
        let elements = vec![
            element(0, "AXWindow", None),
            element(1, "AXButton", Some(0)),
            element(2, "AXGroup", Some(0)),
            element(3, "AXCheckBox", Some(2)),
            element(4, "AXStaticText", Some(9)),
        ];
        let tree = element_tree(&elements, 256, 8);
        assert_eq!(tree.len(), 2);
        assert_eq!(tree[0].runtime_id, "42:0");
        let children: Vec<_> = tree[0]
            .children
            .iter()
            .map(|c| c.runtime_id.as_str())
            .collect();
        assert_eq!(children, vec!["42:1", "42:2"]);
        assert_eq!(tree[0].children[1].children[0].control_type, "CheckBox");
        assert_eq!(tree[1].runtime_id, "42:4");

        // Depth 2 drops the checkbox, and nothing re-roots under it.
        let shallow = element_tree(&elements, 256, 2);
        assert_eq!(count_nodes(&shallow), 4);
        assert!(shallow[0].children[1].children.is_empty());

        // A chain deeper than the bound keeps exactly `depth_limit` levels.
        let chain: Vec<_> = (0..20)
            .map(|i| element(i, "AXGroup", i.checked_sub(1)))
            .collect();
        assert_eq!(count_nodes(&element_tree(&chain, 256, 8)), 8);

        // The node bound holds for a wide list.
        let wide: Vec<_> = (0..1000)
            .map(|i| element(i, "AXButton", if i == 0 { None } else { Some(0) }))
            .collect();
        assert_eq!(count_nodes(&element_tree(&wide, 256, 8)), 256);
    }

    #[test]
    fn role_table_and_patterns_are_closed() {
        assert_eq!(control_type("AXButton"), "Button");
        assert_eq!(control_type("push button"), "Button");
        assert_eq!(control_type("Push Button"), "Button");
        assert_eq!(control_type("check box"), "CheckBox");
        assert_eq!(control_type("AXSomethingNew"), "Custom");
        assert_eq!(control_type("hologram"), "Custom");
        assert_eq!(patterns("AXButton", &["AXPress".into()]), vec!["Invoke"]);
        assert_eq!(
            patterns("check box", &["toggle".into()]),
            vec!["Toggle".to_owned()]
        );
        assert_eq!(patterns("AXTextField", &[]), vec!["Value"]);
        let mut checked = element(1, "AXCheckBox", None);
        checked.selected = Some(true);
        assert!(element_fact(&checked).toggled);
    }

    #[test]
    fn exe_id_matches_the_windows_derivation() {
        // sha256("orcel-computer-host/exe/v1|/usr/bin/gedit"), first 16 bytes.
        let id = exe_id("/usr/bin/gedit");
        assert_eq!(id.len(), 32);
        assert_ne!(id, exe_id("/usr/bin/gedit2"));
        assert!(is_protected_executable("ORCELD"));
    }

    #[test]
    fn bound_bytes_cuts_on_a_char_boundary() {
        assert_eq!(bound_bytes("aé", 2), "a");
        assert_eq!(bound_bytes("abc", 8), "abc");
    }
}
