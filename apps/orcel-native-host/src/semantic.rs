// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//! Semantic actions (XP-11): which element an action may land on, and what it
//! may do there. Everything in this file is pure, so it is tested on every OS.
//!
//! The kernel registry has already bound the action to an observed element
//! and obtained approval for that exact target. The host does not rely on
//! that. The worker lists the window again, recomputes the stable runtime ids
//! ([`crate::map::runtime_ids`]), finds the one element whose id equals the
//! request's ([`locate`]) and applies [`plan`] to the live facts of that
//! element before one action is delivered. An id that is absent, ambiguous or
//! outside the bounded tree is `target_stale`.
//!
//! The verbs are the closed set of `orcel-computer-host/2`: `invoke`,
//! `set_value`, `select`, `toggle` and `scroll`. Each of the first four is one
//! accessibility action on the exact element (AX on macOS, AT-SPI on Linux).
//! None can be delivered as a pointer or key event: the vendored tool that
//! performs them has no such route (`PATCHES.md`, P-09). `scroll` is refused
//! because Cua delivers it as a wheel event at a screen position, which is
//! pixel-addressed input (XP-12).

use crate::map::{self, control_type};
use crate::protocol::{code, ElementFact, MAX_RUNTIME_ID_BYTES, MAX_TEXT_BYTES};
use cua_driver_contract::WindowElement;
use std::collections::HashMap;

/// A verb the host delivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Invoke,
    SetValue,
    Select,
    Toggle,
}

impl Verb {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invoke => "invoke",
            Self::SetValue => "set_value",
            Self::Select => "select",
            Self::Toggle => "toggle",
        }
    }
}

/// Why an action is not delivered: a closed protocol code and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub message: String,
}

fn refuse(code: &'static str, message: impl Into<String>) -> Refusal {
    Refusal {
        code,
        message: message.into(),
    }
}

/// Parses a verb name. `scroll` is a protocol verb that this host refuses;
/// an unknown name is `invalid_request`.
pub fn parse_verb(name: &str) -> Result<Verb, Refusal> {
    match name {
        "invoke" => Ok(Verb::Invoke),
        "set_value" => Ok(Verb::SetValue),
        "select" => Ok(Verb::Select),
        "toggle" => Ok(Verb::Toggle),
        "scroll" => Err(refuse(
            code::CAPABILITY_DENIED,
            "scroll is delivered as a wheel event at a screen position, which is pixel-addressed input; it waits for XP-12",
        )),
        _ => Err(refuse(
            code::INVALID_REQUEST,
            "semantic_action is not one of invoke, set_value, select, toggle or scroll",
        )),
    }
}

/// The action names that activate a control on either platform: AX action
/// names (`AXPress`) and AT-SPI action names, which GTK4 namespaces
/// (`win.activate`). `scroll`, `showmenu` and `delete`-like names never count.
pub fn has_activation(actions: &[String]) -> bool {
    actions.iter().any(|action| {
        let name: String = action
            .rsplit('.')
            .next()
            .unwrap_or(action)
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect::<String>()
            .to_ascii_lowercase();
        matches!(
            name.as_str(),
            "axpress"
                | "axpick"
                | "press"
                | "click"
                | "activate"
                | "toggle"
                | "select"
                | "check"
                | "uncheck"
                | "invoke"
                | "dodefault"
        )
    })
}

/// The element of the bounded tree whose runtime id is `wanted`. `None` when
/// the id is unknown, too long, or names more than one element.
pub fn locate<'a>(
    observable: &[&'a WindowElement],
    ids: &HashMap<u64, String>,
    wanted: &str,
) -> Option<&'a WindowElement> {
    if wanted.is_empty() || wanted.len() > MAX_RUNTIME_ID_BYTES {
        return None;
    }
    let mut found = None;
    for element in observable {
        if ids.get(&element.element_index).map(String::as_str) == Some(wanted) {
            if found.is_some() {
                return None;
            }
            found = Some(*element);
        }
    }
    found
}

fn password_marked(element: &WindowElement, fact: &ElementFact) -> bool {
    let marked = |text: &str| {
        let lower = text.to_ascii_lowercase();
        ["password", "passwd", "secret", "token"]
            .iter()
            .any(|marker| lower.contains(marker))
    };
    fact.value_is_password
        || map::is_secure_role(&element.role)
        || marked(&element.role)
        || marked(&fact.name)
}

/// Whether `verb` may be delivered to `element`, judged on its live facts.
/// `value` is the text a `set_value` writes.
pub fn plan(
    verb: Verb,
    element: &WindowElement,
    fact: &ElementFact,
    value: Option<&str>,
) -> Result<(), Refusal> {
    if password_marked(element, fact) {
        return Err(refuse(
            code::PROTECTED_SURFACE,
            "a password or secret bearing element takes no semantic action",
        ));
    }
    if !fact.enabled {
        return Err(refuse(code::CAPABILITY_DENIED, "the element is disabled"));
    }
    let control = control_type(&element.role);
    let has = |pattern: &str| fact.patterns.iter().any(|candidate| candidate == pattern);
    let activates = has_activation(element.actions.as_deref().unwrap_or_default());
    match verb {
        Verb::Invoke => {
            if !matches!(control, "Button" | "Hyperlink" | "MenuItem") {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "invoke acts only on a Button, Hyperlink or MenuItem",
                ));
            }
            if !has("Invoke") || !activates {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "the element does not advertise an activation action; there is no pointer fallback",
                ));
            }
            if has("Toggle") {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "the element is a toggle; use the toggle action",
                ));
            }
        }
        Verb::Toggle => {
            if !matches!(control, "CheckBox" | "Button" | "MenuItem") || !has("Toggle") {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "toggle acts only on a check box or toggle button",
                ));
            }
            if !activates {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "the element does not advertise an activation action; there is no pointer fallback",
                ));
            }
        }
        Verb::Select => {
            if !matches!(control, "RadioButton" | "TabItem" | "ListItem" | "TreeItem")
                || !has("SelectionItem")
            {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "select acts only on a radio button, tab, list item or tree item",
                ));
            }
            if !activates {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "the element does not advertise a selection action; there is no pointer fallback",
                ));
            }
        }
        Verb::SetValue => {
            if !matches!(control, "Edit" | "Slider" | "Spinner") {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "set_value acts only on a text field, slider or spin button",
                ));
            }
            if element.in_web_content == Some(true) {
                return Err(refuse(
                    code::CAPABILITY_DENIED,
                    "an accessibility value write into web content cannot be verified; it is not served",
                ));
            }
            match value {
                None => return Err(refuse(code::INVALID_REQUEST, "set_value needs a value")),
                Some(text) if text.len() > MAX_TEXT_BYTES => {
                    return Err(refuse(
                        code::INVALID_REQUEST,
                        "the value exceeds the bounded limit",
                    ))
                }
                Some(_) => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::map::{element_fact, runtime_ids};

    fn element(index: u64, role: &str, label: &str, actions: &[&str]) -> WindowElement {
        WindowElement {
            element_index: index,
            role: role.into(),
            depth: 0,
            element_token: Some(format!("s00000001:{index}")),
            label: Some(label.into()),
            value: None,
            value_description: None,
            enabled: Some(true),
            selected: None,
            in_web_content: None,
            actions: Some(actions.iter().map(|a| (*a).to_owned()).collect()),
            parent_index: None,
            frame: None,
            min: None,
            max: None,
        }
    }

    fn judge(verb: Verb, element: &WindowElement, value: Option<&str>) -> Result<(), Refusal> {
        let fact = element_fact(element, "e");
        plan(verb, element, &fact, value)
    }

    fn denied(result: Result<(), Refusal>) -> &'static str {
        result.unwrap_err().code
    }

    #[test]
    fn each_verb_accepts_its_own_control_kind() {
        let button = element(1, "AXButton", "Increment", &["AXPress"]);
        assert_eq!(judge(Verb::Invoke, &button, None), Ok(()));
        let gtk_button = element(1, "push button", "Increment", &["click"]);
        assert_eq!(judge(Verb::Invoke, &gtk_button, None), Ok(()));
        let checkbox = element(2, "AXCheckBox", "I agree", &["AXPress"]);
        assert_eq!(judge(Verb::Toggle, &checkbox, None), Ok(()));
        let gtk_checkbox = element(2, "check box", "I agree", &["click"]);
        assert_eq!(judge(Verb::Toggle, &gtk_checkbox, None), Ok(()));
        let radio = element(3, "AXRadioButton", "Small", &["AXPress"]);
        assert_eq!(judge(Verb::Select, &radio, None), Ok(()));
        let gtk_radio = element(3, "radio button", "Small", &["click"]);
        assert_eq!(judge(Verb::Select, &gtk_radio, None), Ok(()));
        let field = element(4, "AXTextField", "Note", &[]);
        assert_eq!(judge(Verb::SetValue, &field, Some("hello")), Ok(()));
        let entry = element(4, "entry", "Note", &["activate"]);
        assert_eq!(judge(Verb::SetValue, &entry, Some("")), Ok(()));
    }

    #[test]
    fn a_verb_never_lands_on_another_kind_of_control() {
        let button = element(1, "AXButton", "Increment", &["AXPress"]);
        let checkbox = element(2, "AXCheckBox", "I agree", &["AXPress"]);
        let radio = element(3, "AXRadioButton", "Small", &["AXPress"]);
        let field = element(4, "AXTextField", "Note", &[]);
        for (verb, target) in [
            (Verb::Toggle, &button),
            (Verb::Select, &button),
            (Verb::SetValue, &button),
            (Verb::Invoke, &checkbox),
            (Verb::Invoke, &radio),
            (Verb::Invoke, &field),
            (Verb::Select, &field),
            (Verb::Toggle, &field),
        ] {
            assert_eq!(
                denied(judge(verb, target, Some("x"))),
                code::CAPABILITY_DENIED,
                "{verb:?} on {}",
                target.role
            );
        }
    }

    #[test]
    fn an_element_without_an_activation_action_has_no_fallback() {
        // The pointer route would be the only way to press this.
        let mute = element(1, "AXButton", "Mute", &["AXShowMenu"]);
        assert_eq!(
            denied(judge(Verb::Invoke, &mute, None)),
            code::CAPABILITY_DENIED
        );
        let bare = element(1, "AXButton", "Bare", &[]);
        assert_eq!(
            denied(judge(Verb::Invoke, &bare, None)),
            code::CAPABILITY_DENIED
        );
        let row = element(2, "list item", "Row", &[]);
        assert_eq!(
            denied(judge(Verb::Select, &row, None)),
            code::CAPABILITY_DENIED
        );
    }

    #[test]
    fn secure_password_and_secret_elements_are_protected() {
        for (role, label) in [
            ("AXSecureTextField", "Sign in"),
            ("password text", "Sign in"),
            ("AXTextField", "API token"),
            ("entry", "Password"),
            ("AXButton", "Show secret"),
        ] {
            let target = element(1, role, label, &["AXPress"]);
            for verb in [Verb::Invoke, Verb::SetValue, Verb::Select, Verb::Toggle] {
                assert_eq!(
                    denied(judge(verb, &target, Some("hunter2"))),
                    code::PROTECTED_SURFACE,
                    "{role} {label}"
                );
            }
        }
    }

    #[test]
    fn disabled_elements_and_web_values_are_refused() {
        let mut disabled = element(1, "AXButton", "Go", &["AXPress"]);
        disabled.enabled = Some(false);
        assert_eq!(
            denied(judge(Verb::Invoke, &disabled, None)),
            code::CAPABILITY_DENIED
        );
        let mut web = element(2, "AXTextField", "Search", &[]);
        web.in_web_content = Some(true);
        assert_eq!(
            denied(judge(Verb::SetValue, &web, Some("q"))),
            code::CAPABILITY_DENIED
        );
        // A web button can still be invoked.
        let mut link = element(3, "AXLink", "Docs", &["AXPress"]);
        link.in_web_content = Some(true);
        assert_eq!(judge(Verb::Invoke, &link, None), Ok(()));
    }

    #[test]
    fn set_value_needs_a_bounded_value() {
        let field = element(1, "AXTextField", "Note", &[]);
        assert_eq!(
            denied(judge(Verb::SetValue, &field, None)),
            code::INVALID_REQUEST
        );
        let long = "a".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(
            denied(judge(Verb::SetValue, &field, Some(&long))),
            code::INVALID_REQUEST
        );
    }

    #[test]
    fn scroll_and_unknown_verbs_are_refused_without_a_native_call() {
        assert_eq!(
            parse_verb("scroll").unwrap_err().code,
            code::CAPABILITY_DENIED
        );
        for name in ["", "click", "type", "INVOKE", "invoke ", "drag"] {
            assert_eq!(
                parse_verb(name).unwrap_err().code,
                code::INVALID_REQUEST,
                "{name:?}"
            );
        }
        assert_eq!(parse_verb("invoke"), Ok(Verb::Invoke));
        assert_eq!(parse_verb("set_value"), Ok(Verb::SetValue));
    }

    #[test]
    fn the_runtime_id_must_name_exactly_one_observable_element() {
        let list = vec![
            element(0, "AXWindow", "W", &[]),
            element(1, "AXButton", "A", &["AXPress"]),
            element(2, "AXButton", "B", &["AXPress"]),
        ];
        let ids = runtime_ids(&list);
        let observable: Vec<&WindowElement> = list.iter().collect();
        assert_eq!(
            locate(&observable, &ids, &ids[&2]).map(|e| e.element_index),
            Some(2)
        );
        assert!(locate(&observable, &ids, "e2-0000000000000000").is_none());
        assert!(locate(&observable, &ids, "").is_none());
        assert!(locate(&observable, &ids, &"x".repeat(MAX_RUNTIME_ID_BYTES + 1)).is_none());
        // An element outside the bounded tree is not addressable.
        let bounded: Vec<&WindowElement> = list.iter().take(2).collect();
        assert!(locate(&bounded, &ids, &ids[&2]).is_none());
        // Two elements claiming one id: refused, never the first one.
        let mut clash = ids.clone();
        clash.insert(1, ids[&2].clone());
        assert!(locate(&observable, &clash, &ids[&2]).is_none());
        // A token Cua minted is not an identity.
        assert!(locate(&observable, &ids, "s00000001:2").is_none());
    }

    /// The self-approval click: no verb may reach the windows Orcel's own
    /// approval brokers draw (the XP-10 helper's "Orcel approval SOFT" and
    /// "Orcel approval STRONG", the XP-09 alert drawn by
    /// UserNotificationCenter) or an OS authentication surface. The worker
    /// applies exactly these two predicates before it reads a tree.
    #[test]
    fn orcel_approval_windows_and_their_owners_are_never_targets() {
        use crate::capture::is_protected_window;
        use crate::map::is_protected_executable;
        for (title, class) in [
            (
                "Orcel approval SOFT",
                "orcel-approval-helper-linux orcel-approval-helper-linux",
            ),
            ("Orcel approval STRONG", "orcel-approval-helper-linux"),
            ("Orcel Trust", "Orcel orcel"),
            ("Orcel Emergency Revoke", "orceld"),
            ("", "OrcelApprove"),
        ] {
            assert!(is_protected_window(title, class), "{title:?} {class:?}");
        }
        for exe in ["orcel-approval-helper-linux", "orceld", "orcel", "Orcel"] {
            assert!(is_protected_executable(exe), "{exe}");
        }
        #[cfg(target_os = "macos")]
        for class in ["UserNotificationCenter", "SecurityAgent", "loginwindow"] {
            assert!(is_protected_window("", class), "{class}");
            assert!(is_protected_executable(class), "{class}");
        }
        #[cfg(not(target_os = "macos"))]
        for class in [
            "polkit-gnome-authentication-agent-1",
            "swaylock",
            "pinentry-gtk",
        ] {
            assert!(is_protected_window("", class), "{class}");
        }
        assert!(!is_protected_window("Editor", "gedit"));
    }

    #[test]
    fn activation_names_cover_both_platforms_and_nothing_else() {
        let names = |list: &[&str]| list.iter().map(|n| (*n).to_owned()).collect::<Vec<_>>();
        for good in [
            "AXPress",
            "AXPick",
            "click",
            "Activate",
            "toggle",
            "win.activate",
            "check",
        ] {
            assert!(has_activation(&names(&[good])), "{good}");
        }
        for bad in [
            "AXShowMenu",
            "AXScrollToVisible",
            "scroll",
            "clipboard.copy",
            "delete",
            "",
        ] {
            assert!(!has_activation(&names(&[bad])), "{bad}");
        }
    }
}
