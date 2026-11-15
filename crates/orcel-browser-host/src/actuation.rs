//! SG-000077 verified structured browser actuation.
//!
//! Every mutation verifies exact page, origin, document generation, node
//! identity, role, state, supported action, workspace, and policy revision
//! immediately before dispatch, consumes a fresh one-shot approval, and
//! verifies the postcondition afterwards. Mutation is never automatically
//! retried after dispatch and never silently falls back to coordinates.
//! Password-field filling is denied.

use crate::error::HostError;

/// Supported structured actions in this grain. Anything else is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedAction {
    Click,
    Fill,
    /// Click a link to download its document into an approved folder; the
    /// target state binds the link, the folder and the file name.
    Download,
    /// Fill and submit a discovered WebMCP declarative tool form; the target
    /// state binds the tool record, its action and the exact arguments.
    Execute,
    /// BR-02: choose options of a native select by their labels; the
    /// target state binds the exact labels.
    Select,
    /// BR-02: set a checkbox or radio; the target state binds the state.
    Check,
    /// BR-02: press one key from `PRESS_KEYS` on the element; the target
    /// state binds the key.
    Press,
    /// BR-02: move the pointer over the element.
    Hover,
    /// SG-000122: press Enter, and only Enter, in a single-line text field
    /// (it may submit what the page holds); the target state is `enter`.
    Enter,
    /// BR-03: set a file input to one host-staged file; the target state
    /// binds the page's origin, the file's digest and its name.
    Upload,
}

impl SupportedAction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Click => "click",
            Self::Fill => "fill",
            Self::Download => "download",
            Self::Execute => "execute",
            Self::Select => "select",
            Self::Check => "check",
            Self::Press => "press",
            Self::Hover => "hover",
            Self::Enter => "enter",
            Self::Upload => "upload",
        }
    }

    pub fn parse(text: &str) -> Result<Self, HostError> {
        match text {
            "click" => Ok(Self::Click),
            "fill" => Ok(Self::Fill),
            "download" => Ok(Self::Download),
            "execute" => Ok(Self::Execute),
            "select" => Ok(Self::Select),
            "check" => Ok(Self::Check),
            "press" => Ok(Self::Press),
            "hover" => Ok(Self::Hover),
            "enter" => Ok(Self::Enter),
            "upload" => Ok(Self::Upload),
            _ => Err(HostError::Invalid("unsupported actuation action".into())),
        }
    }
}

/// Roles permitted per action. Password and secret roles are never
/// permitted for any action in this grain.
pub fn role_supports_action(role: &str, action: SupportedAction) -> Result<(), HostError> {
    let lower = role.to_ascii_lowercase();
    // Substring matching on purpose: it fails closed (for example "pin"
    // also denies "spinbutton", which no action allows anyway).
    for denied in ["password", "secret", "credential", "token", "pin"] {
        if lower.contains(denied) {
            return Err(HostError::Invalid("password-field filling denied".into()));
        }
    }
    let allowed: &[&str] = match action {
        SupportedAction::Click => &["button", "link", "hyperlink", "menuitem", "tab", "checkbox"],
        SupportedAction::Fill => &["textbox", "edit", "document", "combobox", "searchbox"],
        SupportedAction::Download => &["link", "hyperlink"],
        SupportedAction::Execute => &["webmcp-tool"],
        SupportedAction::Select => &["combobox", "listbox"],
        SupportedAction::Check => &["checkbox", "radio"],
        // Focusable controls only: a key pressed on an element that cannot
        // take focus would go to whatever had it.
        SupportedAction::Press => &[
            "textbox",
            "searchbox",
            "combobox",
            "listbox",
            "option",
            "button",
            "link",
            "checkbox",
            "radio",
            "menuitem",
            "tab",
            "slider",
        ],
        SupportedAction::Hover => &["button", "link", "menuitem", "tab", "img", "image"],
        // SG-000122: text fields only (the worker also requires an input
        // whose type state is text, search, email, url or tel).
        SupportedAction::Enter => &["textbox", "searchbox", "combobox"],
        // A file input is a button in the accessibility tree; the worker
        // also requires the element itself to be <input type=file>.
        SupportedAction::Upload => &["button"],
    };
    // BR-02's actions match roles exactly (`tab` is not `table`); the
    // earlier actions keep their substring rule.
    let exact = matches!(
        action,
        SupportedAction::Select
            | SupportedAction::Check
            | SupportedAction::Press
            | SupportedAction::Hover
            | SupportedAction::Enter
            | SupportedAction::Upload
    );
    if allowed.iter().any(|entry| {
        if exact {
            lower == *entry
        } else {
            lower.contains(entry)
        }
    }) {
        return Ok(());
    }
    Err(HostError::Invalid(
        "role does not support the action".into(),
    ))
}

/// BR-02: the longest value filled and the most options selected at once
/// (mirrors the worker). SG-000122: a select chooses exactly one option of
/// a native select.
pub const MAX_FORM_VALUE_BYTES: usize = 1024;
pub const MAX_FORM_OPTIONS: usize = 1;
/// BR-02: the keys an approved press may send (mirrors the worker):
/// navigation and editing keys only, no characters (Space aside) and no
/// modifiers.
pub const PRESS_KEYS: [&str; 12] = [
    "Enter",
    "Tab",
    "Escape",
    "ArrowUp",
    "ArrowDown",
    "ArrowLeft",
    "ArrowRight",
    "Home",
    "End",
    "PageUp",
    "PageDown",
    "Space",
];

/// Roles a Space may be pressed on: controls Space activates or toggles,
/// never a text field (where it would type, which only an approved fill
/// may do).
const SPACE_ROLES: [&str; 6] = ["button", "checkbox", "radio", "option", "menuitem", "tab"];

/// BR-02: one form action and its exact input. Its `state` is what the
/// one-shot approval binds (through the target digest), so the approver
/// sees, and approves, exactly the value entered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormInput {
    /// Type `value` into a text field, replacing its content (empty clears).
    Fill { value: String },
    /// Choose these options of a native select, by their visible labels.
    Select { labels: Vec<String> },
    /// Set a checkbox or radio.
    Check { checked: bool },
    /// Press one key from `PRESS_KEYS` on the element.
    Press { key: String },
    /// Move the pointer over the element.
    Hover,
    /// SG-000122: press Enter in a single-line text field.
    Enter,
}

impl FormInput {
    pub fn action(&self) -> SupportedAction {
        match self {
            Self::Fill { .. } => SupportedAction::Fill,
            Self::Select { .. } => SupportedAction::Select,
            Self::Check { .. } => SupportedAction::Check,
            Self::Press { .. } => SupportedAction::Press,
            Self::Hover => SupportedAction::Hover,
            Self::Enter => SupportedAction::Enter,
        }
    }

    /// Refuses input the worker would refuse: oversized, control
    /// characters (one line only), no, too many or repeated options.
    pub fn check(&self) -> Result<(), HostError> {
        let bounded =
            |text: &str| text.len() <= MAX_FORM_VALUE_BYTES && !text.chars().any(char::is_control);
        let fits = match self {
            Self::Fill { value } => bounded(value),
            Self::Select { labels } => {
                let mut unique = labels.clone();
                unique.sort();
                unique.dedup();
                !labels.is_empty()
                    && labels.len() <= MAX_FORM_OPTIONS
                    && unique.len() == labels.len()
                    && labels
                        .iter()
                        .all(|label| !label.is_empty() && bounded(label))
            }
            Self::Check { .. } | Self::Hover | Self::Enter => true,
            Self::Press { key } => PRESS_KEYS.contains(&key.as_str()),
        };
        if fits {
            Ok(())
        } else {
            Err(HostError::Invalid(
                "the form input must be bounded, on one line, and select at least one option"
                    .into(),
            ))
        }
    }

    /// The approval state for this input: the action and its exact input.
    pub fn state(&self) -> String {
        match self {
            Self::Fill { value } => format!("fill\n{value}"),
            Self::Select { labels } => format!("select\n{}", labels.join("\n")),
            Self::Check { checked } => format!("check\n{checked}"),
            Self::Press { key } => format!("press\n{key}"),
            Self::Hover => "hover".to_owned(),
            Self::Enter => "enter".to_owned(),
        }
    }
}

/// BR-02: whether a field's accessible name suggests a secret (a password,
/// PIN, one-time code, card or security code). Such a field is never
/// filled, whatever its attributes say.
pub fn name_looks_secret(name: &str) -> bool {
    let words: Vec<String> = name
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(str::to_lowercase)
        .collect();
    let has = |word: &str| words.iter().any(|w| w == word);
    // Prefixes catch run-together forms ("Pincode", "Passcode", "CVV2").
    let starts = |prefix: &str| words.iter().any(|w| w.starts_with(prefix));
    let pair = |a: &str, b: &str| words.windows(2).any(|w| w[0] == a && w[1] == b);
    [
        "password",
        "passcode",
        "passphrase",
        "pin",
        "otp",
        "cvc",
        "cvv",
        "csc",
        "secret",
        "token",
        "passwort",
        "contrase\u{f1}a",
    ]
    .iter()
    .any(|word| has(word))
        || ["pin", "cvv", "cvc", "passw", "passc"]
            .iter()
            .any(|prefix| starts(prefix))
        || pair("card", "number")
        || pair("card", "no")
        || pair("security", "code")
        || pair("one", "time")
        || pair("verification", "code")
}

impl FormInput {
    /// Refuses an input the target's role cannot take (a Space on a text
    /// field), beyond `role_supports_action`.
    pub fn check_for_role(&self, role: &str) -> Result<(), HostError> {
        if let Self::Press { key } = self {
            if key == "Space" && !SPACE_ROLES.contains(&role.to_ascii_lowercase().as_str()) {
                return Err(HostError::Invalid(
                    "Space is pressed only on buttons, checkboxes, radios, options, menu items and tabs"
                        .into(),
                ));
            }
        }
        Ok(())
    }
}

/// SG-000122: how the worker classified an observed form control of the
/// main frame (the host keeps it with the node; it never crosses): a
/// single-line text field (an input whose type state is text, search,
/// email, url or tel, a missing or unknown type being text), a native
/// select, or a checkbox or radio input. Anything else carries no kind.
/// Only the Windows worker session uses these (tests run them everywhere).
#[cfg(any(windows, test))]
pub const CONTROL_LINE: &str = "line";
#[cfg(any(windows, test))]
pub const CONTROL_SELECT: &str = "select";
#[cfg(any(windows, test))]
pub const CONTROL_TOGGLE: &str = "toggle";

/// SG-000122: the host's own checks of a live form action against the
/// observed target, before any worker frame: fill and Enter only on a
/// single-line text field whose name does not look secret, with a fill value
/// the approval prompt shows exactly and in full; select exactly one option
/// of a native select; check only a checkbox or radio input. Press with any
/// other key, and hover, are not live actions. The worker checks the element
/// again when it acts.
#[cfg(any(windows, test))]
pub fn live_form_check(
    role: &str,
    control: Option<&str>,
    name: &str,
    input: &FormInput,
) -> Result<(), HostError> {
    input.check()?;
    let (roles, kind): (&[&str], &str) = match input {
        FormInput::Fill { .. } | FormInput::Enter => {
            (&["textbox", "searchbox", "combobox"], CONTROL_LINE)
        }
        FormInput::Select { .. } => (&["combobox", "listbox"], CONTROL_SELECT),
        FormInput::Check { .. } => (&["checkbox", "radio"], CONTROL_TOGGLE),
        FormInput::Press { .. } | FormInput::Hover => {
            return Err(HostError::Invalid("not a live form action".into()))
        }
    };
    role_supports_action(role, input.action())?;
    if !roles.contains(&role) || control != Some(kind) {
        return Err(HostError::Invalid(
            "the target is not the kind of control the action needs".into(),
        ));
    }
    if matches!(input, FormInput::Fill { .. } | FormInput::Enter) && name_looks_secret(name) {
        return Err(HostError::Invalid("password-field filling denied".into()));
    }
    if let FormInput::Fill { value } = input {
        live_fill_value(value)?;
    }
    Ok(())
}

/// SG-000122 (decision on SG-000108 decision 4): a fill value must be shown
/// exactly and in full by the approval prompt: no character the prompt would
/// escape, and a displayed length (a backslash counting double) of at most
/// the prompt's summary bound. It is refused, never truncated. The rule is
/// the prompt's own (`orcel_contracts::prompt_display`).
#[cfg(any(windows, test))]
pub fn live_fill_value(value: &str) -> Result<(), HostError> {
    use orcel_contracts::prompt_display::{
        plainly_spaced, shown_exactly, NotShownExactly, MAX_SUMMARY_CHARS,
    };
    match shown_exactly(value, MAX_SUMMARY_CHARS) {
        // SG-000122 slice A2: every plain space visible on the prompt line.
        Ok(_) if !plainly_spaced(value) => Err(HostError::Invalid(
            "the value has a leading, trailing or doubled space the approval prompt could not show"
                .into(),
        )),
        Ok(_) => Ok(()),
        Err(NotShownExactly::Escaped) => Err(HostError::Invalid(
            "the value holds a character the approval prompt would escape".into(),
        )),
        Err(NotShownExactly::TooLong) => Err(HostError::Invalid(
            "the value is longer than the approval prompt shows in full".into(),
        )),
    }
}

/// SG-000122 slice A2: where an observed node stands in page order. The
/// worker numbers main-frame nodes `e1`, `e2`, ... as it walks the
/// accessibility tree; anything else (a frame's node) comes after, by its
/// reference.
#[cfg(any(windows, test))]
fn page_order(reference: &str) -> (u8, u64, &str) {
    match reference
        .strip_prefix('e')
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse::<u64>().ok())
    {
        Some(number) => (0, number, ""),
        None => (1, 0, reference),
    }
}

/// One observed node, as [`shared_name_ordinal`] reads it: its node id,
/// worker reference, role and accessible name.
#[cfg(any(windows, test))]
pub struct OrdinalNode<'a> {
    pub node_id: &'a str,
    pub reference: &'a str,
    pub role: &'a str,
    pub name: &'a str,
}

/// SG-000122 slice A2: what a live form approval binds about its target,
/// from the host's record of the latest observation: the approval state, the
/// observed accessible name, and the ordinal (`shared_name_ordinal`). Only
/// the Windows worker session builds one.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveFormBinding {
    pub state: String,
    pub name: String,
    pub ordinal: Option<(usize, usize)>,
}

/// SG-000122 slice A2: when two or more observed nodes of the target's role
/// would have the same name line drawn in the approval prompt
/// (`prompt_display::shown_field_name`: its label and shown characters), the
/// target's position among them in page order and how many there are
/// ("2 of 3"); `None` when its drawn name line is its own (or the target is
/// not among `nodes`). The ordinal is computed from the host's record of its
/// latest observation, both when the approval is bound and when the action is
/// dispatched, and the host binding covers it: if the caller observed the
/// page again in between and the ordinal changed, the action is refused. It
/// is not re-measured in the live page at dispatch; there the worker acts on
/// the exact observed reference, and falls back to role and name only when
/// exactly one element has them, so a shared name is never retargeted.
#[cfg(any(windows, test))]
pub fn shared_name_ordinal(nodes: &[OrdinalNode<'_>], node_id: &str) -> Option<(usize, usize)> {
    use orcel_contracts::prompt_display::shown_field_name;
    let target = nodes.iter().find(|node| node.node_id == node_id)?;
    let shown = shown_field_name(target.name);
    let mut same: Vec<&OrdinalNode<'_>> = nodes
        .iter()
        .filter(|node| node.role == target.role && shown_field_name(node.name) == shown)
        .collect();
    if same.len() < 2 {
        return None;
    }
    same.sort_by(|a, b| {
        page_order(a.reference)
            .cmp(&page_order(b.reference))
            .then_with(|| a.node_id.cmp(b.node_id))
    });
    let position = same.iter().position(|node| node.node_id == node_id)? + 1;
    Some((position, same.len()))
}

/// Exact pre-dispatch target binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActuationTarget {
    pub page_id: String,
    pub origin: String,
    pub document_generation: u64,
    pub node_id: String,
    pub role: String,
    pub state: String,
    pub action: SupportedAction,
    pub workspace: String,
    pub policy_revision: u64,
}

/// Fresh one-shot approval. Consumption is exactly once; the token is
/// useless afterwards and cannot be renewed silently.
#[derive(Debug, Clone)]
pub struct ApprovalToken {
    pub approval_id: String,
    pub target_digest: String,
    pub workspace: String,
    pub policy_revision: u64,
    pub consumed: bool,
}

impl ApprovalToken {
    pub fn consume(&mut self) -> Result<(), HostError> {
        if self.consumed {
            return Err(HostError::Invalid("approval replay denied".into()));
        }
        if self.approval_id.is_empty() || self.target_digest.is_empty() {
            return Err(HostError::Invalid("approval material malformed".into()));
        }
        self.consumed = true;
        Ok(())
    }
}

/// Short binding digest over the complete target set.
pub fn target_digest(target: &ActuationTarget) -> String {
    let text = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        target.page_id,
        target.origin,
        target.document_generation,
        target.node_id,
        target.role,
        target.state,
        target.action.name(),
        target.workspace,
        target.policy_revision
    );
    crate::observation::short_digest(&text)
}

/// Verify the target immediately before dispatch against live state.
/// Any mismatch fails closed as stale or drifted.
pub fn verify_target(
    target: &ActuationTarget,
    actual_document_generation: u64,
    actual_state: &str,
    actual_policy_revision: u64,
    actual_workspace: &str,
) -> Result<(), HostError> {
    if target.page_id.is_empty() || target.node_id.is_empty() || target.origin.is_empty() {
        return Err(HostError::Invalid("actuation identity malformed".into()));
    }
    crate::navigation::parse_navigation_url(&target.origin)?;
    crate::observation::validate_identity_field(&target.workspace)?;
    if target.document_generation != actual_document_generation {
        return Err(HostError::Invalid("stale document generation".into()));
    }
    if target.state != actual_state {
        return Err(HostError::Invalid("element state drift denied".into()));
    }
    if target.policy_revision != actual_policy_revision {
        return Err(HostError::Invalid("policy revision drift denied".into()));
    }
    if target.workspace != actual_workspace {
        return Err(HostError::Invalid("workspace drift denied".into()));
    }
    role_supports_action(&target.role, target.action)?;
    Ok(())
}

/// Dispatch outcome. Success only carries a dispatch receipt; completion
/// requires separate postcondition verification with fresh observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    Dispatched { receipt: String },
}

/// Dispatch one verified actuation with one fresh approval. The approval
/// is consumed before mutation and cannot be reused.
pub fn dispatch(
    target: &ActuationTarget,
    approval: &mut ApprovalToken,
    actual_document_generation: u64,
    actual_state: &str,
    actual_policy_revision: u64,
    actual_workspace: &str,
) -> Result<DispatchOutcome, HostError> {
    verify_target(
        target,
        actual_document_generation,
        actual_state,
        actual_policy_revision,
        actual_workspace,
    )?;
    if approval.consumed {
        return Err(HostError::Invalid("approval replay denied".into()));
    }
    if approval.workspace != target.workspace || approval.policy_revision != target.policy_revision
    {
        return Err(HostError::Invalid("approval drift denied".into()));
    }
    if approval.target_digest != target_digest(target) {
        return Err(HostError::Invalid("approval digest mismatch".into()));
    }
    approval.consume()?;
    Ok(DispatchOutcome::Dispatched {
        receipt: format!("dispatch-{}", target_digest(target)),
    })
}

/// Verify the postcondition with a fresh observation generation. The
/// document generation must advance by exactly one; anything else fails
/// closed as unverified rather than retried.
pub fn verify_postcondition(
    before_generation: u64,
    observed_generation: u64,
) -> Result<(), HostError> {
    if observed_generation != before_generation.wrapping_add(1) {
        return Err(HostError::Invalid("postcondition unverified".into()));
    }
    Ok(())
}

/// Automatic mutation retry after dispatch is never authorized.
pub fn retry_after_dispatch(_receipt: &str) -> Result<(), HostError> {
    Err(HostError::Invalid("mutation auto-retry denied".into()))
}

/// Silent coordinate fallback is never authorized.
pub fn coordinate_fallback() -> Result<(), HostError> {
    Err(HostError::Invalid(
        "silent coordinate fallback denied".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BR-02: form inputs are bounded and their approval state names the
    /// exact input; each action has its own roles; secrets stay denied.
    #[test]
    fn br02_form_inputs_bind_their_exact_value() {
        let fill = FormInput::Fill {
            value: "Ada Lovelace".into(),
        };
        assert_eq!(fill.state(), "fill\nAda Lovelace");
        assert_eq!(fill.action(), SupportedAction::Fill);
        assert_eq!(
            FormInput::Select {
                labels: vec!["Porto".into()]
            }
            .state(),
            "select\nPorto"
        );
        assert!(
            FormInput::Select {
                labels: vec!["Lisbon".into(), "Porto".into()]
            }
            .check()
            .is_err(),
            "one option only"
        );
        assert_eq!(FormInput::Check { checked: false }.state(), "check\nfalse");
        assert!(
            FormInput::Fill {
                value: String::new()
            }
            .check()
            .is_ok(),
            "clearing a field"
        );
        for bad in [
            FormInput::Fill {
                value: "a\nb".into(),
            },
            FormInput::Fill {
                value: "x".repeat(MAX_FORM_VALUE_BYTES + 1),
            },
            FormInput::Select { labels: vec![] },
            FormInput::Select {
                labels: vec![String::new()],
            },
            FormInput::Select {
                labels: vec!["a".into(); MAX_FORM_OPTIONS + 1],
            },
        ] {
            assert!(bad.check().is_err(), "{bad:?}");
        }
        // Different values are different approvals.
        let target = |state: String| ActuationTarget {
            page_id: "p1".into(),
            origin: "https://fixture.test".into(),
            document_generation: 1,
            node_id: "n1".into(),
            role: "textbox".into(),
            state,
            action: SupportedAction::Fill,
            workspace: "w".into(),
            policy_revision: 1,
        };
        assert_ne!(
            target_digest(&target(fill.state())),
            target_digest(&target(
                FormInput::Fill {
                    value: "Ada Byron".into()
                }
                .state()
            ))
        );
        assert!(role_supports_action("combobox", SupportedAction::Select).is_ok());
        assert!(role_supports_action("textbox", SupportedAction::Select).is_err());
        assert!(role_supports_action("checkbox", SupportedAction::Check).is_ok());
        assert!(role_supports_action("button", SupportedAction::Check).is_err());
        assert!(role_supports_action("password", SupportedAction::Fill).is_err());
        assert_eq!(
            SupportedAction::parse("select").unwrap(),
            SupportedAction::Select
        );
        assert_eq!(SupportedAction::parse("check").unwrap().name(), "check");
        assert_eq!(
            SupportedAction::parse("upload").unwrap(),
            SupportedAction::Upload
        );
        assert!(role_supports_action("button", SupportedAction::Upload).is_ok());
        assert!(role_supports_action("textbox", SupportedAction::Upload).is_err());
        let press = FormInput::Press {
            key: "Enter".into(),
        };
        assert_eq!(
            (press.state(), press.action()),
            (
                "press
Enter"
                    .to_owned(),
                SupportedAction::Press
            )
        );
        assert!(press.check().is_ok());
        assert!(press.check_for_role("textbox").is_ok());
        let space = FormInput::Press {
            key: "Space".into(),
        };
        assert!(space.check_for_role("checkbox").is_ok());
        assert!(space.check_for_role("textbox").is_err(), "Space would type");
        assert!(
            role_supports_action("table", SupportedAction::Hover).is_err(),
            "exact roles"
        );
        assert!(role_supports_action("dialog", SupportedAction::Press).is_err());
        for key in ["a", "Control+A", "enter", "", "Backspace", "Delete"] {
            assert!(
                FormInput::Press { key: key.into() }.check().is_err(),
                "{key}"
            );
        }
        assert_eq!(FormInput::Hover.state(), "hover");
        assert!(role_supports_action("link", SupportedAction::Hover).is_ok());
        assert!(role_supports_action("textbox", SupportedAction::Hover).is_err());
        assert!(role_supports_action("searchbox", SupportedAction::Press).is_ok());
        assert!(role_supports_action("heading", SupportedAction::Press).is_err());
        assert!(
            FormInput::Select {
                labels: vec!["a".into(), "a".into()]
            }
            .check()
            .is_err(),
            "repeated options"
        );
        for secret in [
            "Password",
            "PIN",
            "Card number",
            "Security code",
            "One-time code",
            "CVV",
            "Pincode",
            "Passcode:",
            "Card no.",
            "CVV2",
        ] {
            assert!(name_looks_secret(secret), "{secret}");
        }
        for plain in [
            "Full name",
            "City",
            "Shipping address",
            "Spinning class",
            "Email",
        ] {
            assert!(!name_looks_secret(plain), "{plain}");
        }
    }

    /// SG-000122: the host's live checks, before any worker frame.
    #[test]
    fn sg122_live_form_actions_need_the_right_control_and_a_showable_value() {
        let fill = |value: &str| FormInput::Fill {
            value: value.into(),
        };
        let ok = |role: &str, control: &str, input: &FormInput| {
            live_form_check(role, Some(control), "Full name", input)
        };
        assert!(ok("textbox", CONTROL_LINE, &fill("Ada")).is_ok());
        assert!(ok("searchbox", CONTROL_LINE, &FormInput::Enter).is_ok());
        assert!(ok("combobox", CONTROL_LINE, &fill("Ada")).is_ok());
        // A textarea, contenteditable or an input of another type carries
        // no `line` kind (or none at all): fill and Enter are refused.
        for control in [
            None,
            Some(CONTROL_SELECT),
            Some(CONTROL_TOGGLE),
            Some("multiline"),
        ] {
            for input in [fill("Ada"), FormInput::Enter] {
                assert!(
                    live_form_check("textbox", control, "Notes", &input).is_err(),
                    "{control:?} {input:?}"
                );
            }
        }
        // Enter on a non-text element, and other keys or hover anywhere.
        for role in ["button", "link", "checkbox", "spinbutton", "slider"] {
            assert!(ok(role, CONTROL_LINE, &FormInput::Enter).is_err(), "{role}");
        }
        for key in ["Tab", "Escape", "Space", "ArrowDown", "Enter"] {
            assert!(
                ok(
                    "textbox",
                    CONTROL_LINE,
                    &FormInput::Press { key: key.into() }
                )
                .is_err(),
                "{key}"
            );
        }
        assert!(ok("link", CONTROL_LINE, &FormInput::Hover).is_err());
        // Secret-looking names are never filled or typed into.
        for input in [fill("x"), FormInput::Enter] {
            assert!(live_form_check("textbox", Some(CONTROL_LINE), "Password", &input).is_err());
        }
        // Select: one option of a native select; check: a checkbox or radio.
        let one = FormInput::Select {
            labels: vec!["Porto".into()],
        };
        assert!(ok("combobox", CONTROL_SELECT, &one).is_ok());
        assert!(ok("listbox", CONTROL_SELECT, &one).is_ok());
        assert!(
            ok("combobox", CONTROL_LINE, &one).is_err(),
            "not a native select"
        );
        let two = FormInput::Select {
            labels: vec!["Lisbon".into(), "Porto".into()],
        };
        assert!(ok("listbox", CONTROL_SELECT, &two).is_err());
        let check = FormInput::Check { checked: true };
        assert!(ok("checkbox", CONTROL_TOGGLE, &check).is_ok());
        assert!(ok("radio", CONTROL_TOGGLE, &check).is_ok());
        assert!(ok("checkbox", CONTROL_LINE, &check).is_err());
        assert!(ok("switch", CONTROL_TOGGLE, &check).is_err());
        // The value: shown exactly and in full, or refused.
        let at = "a".repeat(1024);
        assert!(ok("textbox", CONTROL_LINE, &fill(&at)).is_ok());
        assert!(ok("textbox", CONTROL_LINE, &fill("C:\\temp\\x")).is_ok());
        let past = "\\".repeat(512) + "a";
        assert!(
            ok("textbox", CONTROL_LINE, &fill(&past)).is_err(),
            "a backslash counts double"
        );
        for escaped in [
            "a\u{202e}b",
            "a\u{200b}b",
            "a\u{a0}b",
            "a\u{85}b",
            "e\u{301}\u{302}\u{303}",
        ] {
            assert!(
                ok("textbox", CONTROL_LINE, &fill(escaped)).is_err(),
                "{escaped:?}"
            );
        }
        assert_eq!(FormInput::Enter.state(), "enter");
        assert_eq!(FormInput::Enter.action().name(), "enter");
        assert_eq!(
            SupportedAction::parse("enter").unwrap(),
            SupportedAction::Enter
        );
    }

    /// SG-000122 slice A2: the ordinal is shown only when another node of
    /// the same role shows the same name, counts in page order, and moves
    /// when such a field is added before the target.
    #[test]
    fn sg122_a_shared_shown_name_gets_an_ordinal_in_page_order() {
        let long = "Shipping address line ".repeat(10);
        fn node<'a>(
            node_id: &'a str,
            reference: &'a str,
            role: &'a str,
            name: &'a str,
        ) -> OrdinalNode<'a> {
            OrdinalNode {
                node_id,
                reference,
                role,
                name,
            }
        }
        let a = format!("{long}A");
        let b = format!("{long}B");
        let nodes = vec![
            node("d1-e9", "e9", "textbox", "Email"),
            node("d1-e12", "e12", "textbox", b.as_str()),
            node("d1-e3", "e3", "textbox", a.as_str()),
            node("d1-e4", "e4", "checkbox", a.as_str()),
            node("d1-e5", "e5", "textbox", "Phone"),
            node("d1-e20", "e20", "textbox", "Email"),
        ];
        assert_eq!(shared_name_ordinal(&nodes, "d1-e5"), None);
        assert_eq!(shared_name_ordinal(&nodes, "d1-e4"), None, "another role");
        assert_eq!(shared_name_ordinal(&nodes, "d1-e9"), Some((1, 2)));
        assert_eq!(shared_name_ordinal(&nodes, "d1-e20"), Some((2, 2)));
        // e3 comes before e12 in page order, though listed after it.
        assert_eq!(shared_name_ordinal(&nodes, "d1-e3"), Some((1, 2)));
        assert_eq!(shared_name_ordinal(&nodes, "d1-e12"), Some((2, 2)));
        assert_eq!(shared_name_ordinal(&nodes, "d1-e99"), None);
        // A third "Email" added before the target changes its ordinal.
        let mut more = nodes;
        more.push(node("d1-e1", "e1", "textbox", "Email"));
        assert_eq!(shared_name_ordinal(&more, "d1-e20"), Some((3, 3)));
    }

    fn target() -> ActuationTarget {
        ActuationTarget {
            page_id: "page-1".into(),
            origin: "https://example.com:443".into(),
            document_generation: 3,
            node_id: "node-1".into(),
            role: "button".into(),
            state: "enabled".into(),
            action: SupportedAction::Click,
            workspace: "workspace-1".into(),
            policy_revision: 9,
        }
    }

    fn approval_for(target: &ActuationTarget) -> ApprovalToken {
        ApprovalToken {
            approval_id: "approval-1".into(),
            target_digest: target_digest(target),
            workspace: target.workspace.clone(),
            policy_revision: target.policy_revision,
            consumed: false,
        }
    }

    #[test]
    fn verified_click_dispatches_with_postcondition() {
        let target = target();
        let mut approval = approval_for(&target);
        let outcome = dispatch(&target, &mut approval, 3, "enabled", 9, "workspace-1").unwrap();
        assert!(matches!(outcome, DispatchOutcome::Dispatched { .. }));
        assert!(approval.consumed);
        assert!(verify_postcondition(3, 4).is_ok());
    }

    #[test]
    fn stale_state_and_policy_drift_fail_closed() {
        let target = target();
        let mut approval = approval_for(&target);
        assert!(dispatch(&target, &mut approval, 4, "enabled", 9, "workspace-1").is_err());
        let mut approval = approval_for(&target);
        assert!(dispatch(&target, &mut approval, 3, "disabled", 9, "workspace-1").is_err());
        let mut approval = approval_for(&target);
        assert!(dispatch(&target, &mut approval, 3, "enabled", 10, "workspace-1").is_err());
        let mut approval = approval_for(&target);
        assert!(dispatch(&target, &mut approval, 3, "enabled", 9, "workspace-2").is_err());
    }

    #[test]
    fn approval_replay_and_digest_mismatch_fail_closed() {
        let target = target();
        let mut approval = approval_for(&target);
        dispatch(&target, &mut approval, 3, "enabled", 9, "workspace-1").unwrap();
        assert!(dispatch(&target, &mut approval, 3, "enabled", 9, "workspace-1").is_err());
        let mut forged = approval_for(&target);
        forged.target_digest = "forged".into();
        assert!(dispatch(&target, &mut forged, 3, "enabled", 9, "workspace-1").is_err());
    }

    #[test]
    fn unsupported_roles_and_password_fill_are_denied() {
        assert!(SupportedAction::parse("drag").is_err());
        let mut password_target = target();
        password_target.role = "password".into();
        password_target.action = SupportedAction::Fill;
        let mut approval = approval_for(&password_target);
        assert!(dispatch(
            &password_target,
            &mut approval,
            3,
            "enabled",
            9,
            "workspace-1"
        )
        .is_err());
        let mut pane_target = target();
        pane_target.role = "pane".into();
        pane_target.action = SupportedAction::Click;
        let mut approval = approval_for(&pane_target);
        assert!(dispatch(&pane_target, &mut approval, 3, "enabled", 9, "workspace-1").is_err());
    }

    #[test]
    fn postcondition_retry_and_fallback_never_authorize() {
        assert!(verify_postcondition(3, 3).is_err());
        assert!(verify_postcondition(3, 5).is_err());
        assert!(retry_after_dispatch("dispatch-abc").is_err());
        assert!(coordinate_fallback().is_err());
    }
}
