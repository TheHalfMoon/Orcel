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
    };
    if allowed.iter().any(|entry| lower.contains(entry)) {
        return Ok(());
    }
    Err(HostError::Invalid(
        "role does not support the action".into(),
    ))
}

/// BR-02: the longest value filled and the most options selected at once
/// (mirrors the worker).
pub const MAX_FORM_VALUE_BYTES: usize = 1024;
pub const MAX_FORM_OPTIONS: usize = 16;

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
}

impl FormInput {
    pub fn action(&self) -> SupportedAction {
        match self {
            Self::Fill { .. } => SupportedAction::Fill,
            Self::Select { .. } => SupportedAction::Select,
            Self::Check { .. } => SupportedAction::Check,
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
            Self::Check { .. } => true,
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
                labels: vec!["Lisbon".into(), "Porto".into()]
            }
            .state(),
            "select\nLisbon\nPorto"
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
