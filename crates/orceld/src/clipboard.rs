//! SG-000038 bounded clipboard-read dispatch with SG-000039 bounded
//! clipboard-write extension.
//!
//! This module dispatches the single SG-000038 `clipboard/read` shape
//! and the single SG-000039 `clipboard/write` shape against the
//! dedicated clipboard provider backed by the native adapter. One
//! explicit read returns at most 65536 bytes of Unicode text and one
//! explicit write places at most 65536 bytes of Unicode text, each with
//! secret-pattern denial, clipboard-sequence binding, and bounded
//! secret-free evidence.
//!
//! Every read and every write requires fresh per-operation SOFT approval
//! with exact digest binding. Reads bind the clipboard sequence observed
//! immediately before approval and revalidate it immediately after, so
//! clipboard content that changes in between fails closed as stale.
//! Writes bind the content digest of the exact caller text, and the
//! provider revalidates bounds and secrets after approval. Each approval
//! authorizes at most one operation: clipboard subscriptions, polling,
//! monitoring, history, watchers, and standing sessions have no dispatch
//! path and return `Ok(None)` so the caller fails closed through the
//! STRONG gate or the legacy denial. Placement never authorizes paste,
//! input, keyboard, or desktop authority of any kind. No MCP clipboard
//! tool exists; the agent cannot reach reads or writes through its own
//! tool surface.

use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{Workspace, POLICY_REVISION};
use orcel_provider_clipboard::{
    clipboard_read_digest, clipboard_write_content_digest, clipboard_write_digest,
    read_bounded_text, write_bounded_text, ClipboardAdapter, NativeAdapter, MAX_CLIPBOARD_BYTES,
    UNICODE_TEXT_FORMAT,
};
use orcel_provider_fs::ProviderError;
use serde_json::Value;

/// Dispatch the SG-000038/SG-000039 clipboard shapes. Returns `Ok(None)`
/// for non-clipboard shapes and for denied clipboard shapes so the
/// caller falls through to the STRONG gate and the legacy dispatchers.
pub fn dispatch_clipboard(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    if orcel_provider_clipboard::is_clipboard_write_shape(&request.capability, &request.operation) {
        return write_with_approval(workspace, approval, request, &NativeAdapter::new()).map(Some);
    }
    if !orcel_provider_clipboard::is_clipboard_read_shape(&request.capability, &request.operation) {
        return Ok(None);
    }
    read_with_approval(workspace, approval, request, &NativeAdapter::new()).map(Some)
}

fn read_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    adapter: &impl ClipboardAdapter,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "clipboard read shapes do not accept a target field",
        ));
    }
    reject_clipboard_arguments(request)?;
    // Bind clipboard state before approval without reading content: the
    // sequence number moves no clipboard bytes.
    let sequence = adapter
        .sequence_number()
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let digest = clipboard_read_digest(&workspace.id, POLICY_REVISION, sequence);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "read clipboard",
        "clipboard".to_owned(),
        format!(
            "format={UNICODE_TEXT_FORMAT} max_bytes={MAX_CLIPBOARD_BYTES} sequence={sequence} action=read"
        ),
        digest.clone(),
    );
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    approval
        .consume(
            &token,
            &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
            orcel_approval::now_ms(),
        )
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let outcome = read_bounded_text(adapter, Some(sequence), &workspace.id, POLICY_REVISION)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let mut stamped = outcome.evidence;
    stamped["approval_record"] = Value::String(token.record_id);
    stamped["text"] = Value::String(outcome.text);
    Ok(stamped)
}

fn reject_clipboard_arguments(request: &RequestEnvelope) -> Result<(), ProviderError> {
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "clipboard arguments must be an object",
        )
    })?;
    if let Some(key) = arguments.keys().next() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("clipboard/read does not accept argument field: {key}"),
        ));
    }
    Ok(())
}

fn write_with_approval(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    adapter: &impl ClipboardAdapter,
) -> Result<Value, ProviderError> {
    write_with_approval_to(
        crate::mutation_journal::global(),
        workspace,
        approval,
        request,
        adapter,
    )
}

/// A clipboard placement, journaled to `sink` (SG-000120 RJ-02): never the
/// text, only the approval digest that already binds its content digest.
fn write_with_approval_to(
    sink: crate::mutation_journal::Sink,
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    adapter: &impl ClipboardAdapter,
) -> Result<Value, ProviderError> {
    if request.target.is_some() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "clipboard write shapes do not accept a target field",
        ));
    }
    let arguments = request.arguments.as_object().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "clipboard arguments must be an object",
        )
    })?;
    if arguments.len() != 1 || !arguments.contains_key("text") {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "clipboard/write accepts exactly the text argument",
        ));
    }
    let text = arguments
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                "clipboard/write requires arguments.text as a string",
            )
        })?;
    // SG-000064: refuse text that the provider would refuse anyway before
    // asking the human, so no approval prompt is shown for a placement
    // that can never happen. The provider revalidates after approval.
    if text.is_empty() {
        return Err(ProviderError::new(
            FailureCode::InvalidRequest,
            "clipboard write text must not be empty",
        ));
    }
    if text.len() > MAX_CLIPBOARD_BYTES {
        return Err(ProviderError::new(
            FailureCode::OutputLimit,
            "clipboard write text exceeds the bounded placement size",
        ));
    }
    if orcel_provider_clipboard::contains_secret_material(text) {
        return Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "clipboard write holds secret material which bounded writes never place",
        ));
    }
    // The approval summary carries the digest and bounds only, never the
    // caller text, so secret-bearing text cannot leak through prompts.
    let text_digest = clipboard_write_content_digest(text);
    let byte_length = text.len();
    let digest = clipboard_write_digest(&workspace.id, POLICY_REVISION, &text_digest, byte_length);
    let prompt = ApprovalPrompt::new(
        workspace.id.clone(),
        POLICY_REVISION,
        "write clipboard",
        "clipboard".to_owned(),
        format!(
            "format={UNICODE_TEXT_FORMAT} byte_length={byte_length} max_bytes={MAX_CLIPBOARD_BYTES} content_digest={text_digest} action=write"
        ),
        digest.clone(),
    );
    // SG-000120 RJ-02: journaled before the prompt; an effect orceld cannot
    // read back, so a crash after dispatch is recorded unknown.
    let journaled = crate::mutation_journal::opaque(workspace, request, &digest, "clipboard");
    crate::mutation_journal::journaled_with(
        sink,
        journaled,
        || {
            let token = approval
                .request_token(&prompt)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            approval
                .consume(
                    &token,
                    &ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION),
                    orcel_approval::now_ms(),
                )
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(token)
        },
        |token| {
            // Placement happens only after approval, and the provider revalidates
            // bounds and secrets. Placement synthesizes no input of any kind:
            // write != paste by construction of the adapter contract.
            let outcome = write_bounded_text(adapter, text, &workspace.id, POLICY_REVISION)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            let mut stamped = outcome.evidence;
            stamped["approval_record"] = Value::String(token.record_id);
            Ok(stamped)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_approval::test_support::FixedApprovalBroker;
    use orcel_approval::ApprovalDecision;
    use orcel_provider_clipboard::{ClipboardAdapter, ClipboardError};
    use std::cell::{Cell, RefCell};
    use std::path::PathBuf;

    struct FakeClipboard {
        sequence: Cell<u64>,
        content: RefCell<Option<String>>,
        non_text: bool,
        bump_after_first_sequence: Cell<bool>,
        sequence_calls: Cell<usize>,
        reads: Cell<usize>,
        writes: Cell<usize>,
    }

    impl FakeClipboard {
        fn with_text(sequence: u64, text: &str) -> Self {
            Self {
                sequence: Cell::new(sequence),
                content: RefCell::new(Some(text.to_owned())),
                non_text: false,
                bump_after_first_sequence: Cell::new(false),
                sequence_calls: Cell::new(0),
                reads: Cell::new(0),
                writes: Cell::new(0),
            }
        }

        fn empty() -> Self {
            Self {
                sequence: Cell::new(9),
                content: RefCell::new(None),
                non_text: false,
                bump_after_first_sequence: Cell::new(false),
                sequence_calls: Cell::new(0),
                reads: Cell::new(0),
                writes: Cell::new(0),
            }
        }
    }

    impl ClipboardAdapter for FakeClipboard {
        fn sequence_number(&self) -> Result<u64, ClipboardError> {
            let calls = self.sequence_calls.get();
            self.sequence_calls.set(calls + 1);
            if self.bump_after_first_sequence.get() && calls >= 1 {
                self.sequence.set(self.sequence.get().saturating_add(1));
            }
            Ok(self.sequence.get())
        }

        fn read_unicode_text(&self) -> Result<String, ClipboardError> {
            self.reads.set(self.reads.get() + 1);
            if self.non_text {
                return Err(ClipboardError::new(
                    FailureCode::CapabilityDenied,
                    "clipboard holds no Unicode text",
                ));
            }
            self.content
                .borrow()
                .clone()
                .ok_or_else(|| ClipboardError::new(FailureCode::TargetStale, "clipboard is empty"))
        }

        fn write_unicode_text(&self, _text: &str) -> Result<u64, ClipboardError> {
            self.writes.set(self.writes.get().saturating_add(1));
            self.content.replace(Some(_text.to_owned()));
            self.sequence.set(self.sequence.get().saturating_add(1));
            Ok(self.sequence.get())
        }
    }

    fn write_request(text: &str) -> RequestEnvelope {
        RequestEnvelope {
            version: orcel_contracts::INTERNAL_PROTOCOL_VERSION,
            request_id: "clipboard-write-1".to_owned(),
            client_session_id: "session-1".to_owned(),
            workspace_id: "clipboard-dispatch-workspace".to_owned(),
            capability: "clipboard".to_owned(),
            operation: "write".to_owned(),
            target: None,
            arguments: serde_json::json!({"text": text}),
        }
    }

    fn approved_write(
        adapter: &FakeClipboard,
        request: &RequestEnvelope,
    ) -> Result<Value, ProviderError> {
        write_with_approval(
            &workspace(),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            request,
            adapter,
        )
    }

    #[test]
    fn rj02_an_approved_write_is_journaled_without_its_text() {
        let dir = std::env::temp_dir().join(format!(
            "orceld-rj02-clipboard-{}-{}",
            std::process::id(),
            orcel_approval::now_ms()
        ));
        let path = dir.join("mutations.jsonl");
        let journal: &'static _ = Box::leak(Box::new(
            crate::mutation_journal::test_support::journal(path.clone(), "this"),
        ));
        let adapter = FakeClipboard::empty();
        write_with_approval_to(
            crate::mutation_journal::Sink::Journal(journal),
            &workspace(),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            &write_request("journal-me-not"),
            &adapter,
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("journal-me-not"), "no clipboard text");
        for event in ["\"pending\"", "\"dispatched\"", "\"settled\"", "\"opaque\""] {
            assert!(text.contains(event), "{event}");
        }
        assert!(text.contains("\"outcome\":\"done\""));
        let _ = std::fs::remove_dir_all(dir);
    }

    fn workspace() -> Workspace {
        Workspace {
            id: "clipboard-dispatch-workspace".to_owned(),
            root: PathBuf::from("C:\\clipboard-test"),
        }
    }

    fn read_request() -> RequestEnvelope {
        RequestEnvelope {
            version: orcel_contracts::INTERNAL_PROTOCOL_VERSION,
            request_id: "clipboard-read-1".to_owned(),
            client_session_id: "session-1".to_owned(),
            workspace_id: "clipboard-dispatch-workspace".to_owned(),
            capability: "clipboard".to_owned(),
            operation: "read".to_owned(),
            target: None,
            arguments: serde_json::json!({}),
        }
    }

    fn approved_read(
        adapter: &FakeClipboard,
        request: &RequestEnvelope,
    ) -> Result<Value, ProviderError> {
        read_with_approval(
            &workspace(),
            &FixedApprovalBroker(ApprovalDecision::Approved),
            request,
            adapter,
        )
    }

    #[test]
    fn non_clipboard_shapes_fall_through_without_actuation() {
        let workspace = workspace();
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);
        for (capability, operation) in [
            ("clipboard", "subscribe"),
            ("clipboard", "poll"),
            ("clipboard", "monitor"),
            ("clipboard", "history"),
            ("clipboard", "watch"),
            ("uia.input", "execute"),
            ("fs", "read"),
        ] {
            let mut request = read_request();
            request.capability = capability.to_owned();
            request.operation = operation.to_owned();
            let result = dispatch_clipboard(&workspace, &approval, &request).unwrap();
            assert!(
                result.is_none(),
                "shape must fall through: {capability}/{operation}"
            );
        }
    }

    #[test]
    fn target_and_argument_fields_are_rejected() {
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);
        let adapter = FakeClipboard::with_text(4, "plain dispatch text");
        let mut with_target = read_request();
        with_target.target = Some("clipboard".to_owned());
        let error = read_with_approval(&workspace(), &approval, &with_target, &adapter)
            .expect_err("target must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        let mut with_args = read_request();
        with_args.arguments = serde_json::json!({"format": "text"});
        let error = read_with_approval(&workspace(), &approval, &with_args, &adapter)
            .expect_err("arguments must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        assert_eq!(adapter.reads.get(), 0);
    }

    #[test]
    fn approved_read_returns_text_with_evidence_and_approval_record() {
        let adapter = FakeClipboard::with_text(11, "quarterly report draft");
        let result = approved_read(&adapter, &read_request()).unwrap();
        assert_eq!(result["action"], "read");
        assert_eq!(result["format"], "unicode-text");
        assert_eq!(result["sequence"], 11);
        assert_eq!(result["text"], "quarterly report draft");
        assert!(result["approval_record"].is_string());
        assert!(result["content_digest"].is_string());
        assert_eq!(adapter.reads.get(), 1);
    }

    #[test]
    fn denied_approval_reads_no_clipboard_content() {
        let adapter = FakeClipboard::with_text(11, "quarterly report draft");
        let error = read_with_approval(
            &workspace(),
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &read_request(),
            &adapter,
        )
        .expect_err("denied approval must fail");
        assert!(matches!(
            error.code,
            FailureCode::ApprovalDenied | FailureCode::ApprovalUnavailable
        ));
        assert_eq!(adapter.reads.get(), 0);
    }

    #[test]
    fn clipboard_drift_between_approval_and_read_fails_closed() {
        let adapter = FakeClipboard::with_text(11, "quarterly report draft");
        adapter.bump_after_first_sequence.set(true);
        let error =
            approved_read(&adapter, &read_request()).expect_err("drifted clipboard must fail");
        assert!(matches!(error.code, FailureCode::TargetStale));
    }

    #[test]
    fn secret_and_empty_clipboard_fail_closed_in_dispatch() {
        let secret = FakeClipboard::with_text(5, "api_key=DO-NOT-SHARE");
        let error = approved_read(&secret, &read_request()).expect_err("secret content must fail");
        assert!(matches!(error.code, FailureCode::CapabilityDenied));
        let empty = FakeClipboard::empty();
        let error = approved_read(&empty, &read_request()).expect_err("empty clipboard must fail");
        assert!(matches!(error.code, FailureCode::TargetStale));
    }

    #[test]
    fn approved_write_places_text_with_evidence_and_approval_record() {
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let result = approved_write(&adapter, &write_request("quarterly report draft")).unwrap();
        assert_eq!(result["action"], "write");
        assert_eq!(result["format"], "unicode-text");
        assert_eq!(result["byte_length"], 22);
        assert_eq!(result["resulting_sequence"], 12);
        assert!(result["approval_record"].is_string());
        assert!(result["content_digest"].is_string());
        for key in [
            "text", "content", "password", "secret", "token", "paste", "input",
        ] {
            assert!(
                result.get(key).is_none(),
                "write evidence must not carry {key}"
            );
        }
        assert_eq!(adapter.writes.get(), 1);
    }

    #[test]
    fn denied_approval_places_nothing() {
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let error = write_with_approval(
            &workspace(),
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &write_request("quarterly report draft"),
            &adapter,
        )
        .expect_err("denied approval must fail");
        assert!(matches!(
            error.code,
            FailureCode::ApprovalDenied | FailureCode::ApprovalUnavailable
        ));
        assert_eq!(adapter.writes.get(), 0);
    }

    #[test]
    fn write_argument_shape_is_exact() {
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let approval = FixedApprovalBroker(ApprovalDecision::Approved);
        let mut missing = write_request("x");
        missing.arguments = serde_json::json!({});
        let error = write_with_approval(&workspace(), &approval, &missing, &adapter)
            .expect_err("missing text must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        let mut extra = write_request("x");
        extra.arguments = serde_json::json!({"text": "x", "format": "text"});
        let error = write_with_approval(&workspace(), &approval, &extra, &adapter)
            .expect_err("extra fields must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        let mut non_string = write_request("x");
        non_string.arguments = serde_json::json!({"text": 42});
        let error = write_with_approval(&workspace(), &approval, &non_string, &adapter)
            .expect_err("non-string text must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        let mut with_target = write_request("x");
        with_target.target = Some("clipboard".to_owned());
        let error = write_with_approval(&workspace(), &approval, &with_target, &adapter)
            .expect_err("target must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        assert_eq!(adapter.writes.get(), 0);
    }

    #[test]
    fn write_denies_empty_oversized_and_secret_text() {
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let error =
            approved_write(&adapter, &write_request("")).expect_err("empty write must fail");
        assert!(matches!(error.code, FailureCode::InvalidRequest));
        let big = "a".repeat(orcel_provider_clipboard::MAX_CLIPBOARD_BYTES + 1);
        let error =
            approved_write(&adapter, &write_request(&big)).expect_err("oversized write must fail");
        assert!(matches!(error.code, FailureCode::OutputLimit));
        let error = approved_write(&adapter, &write_request("token=tok_live_999"))
            .expect_err("secret write must fail");
        assert!(matches!(error.code, FailureCode::CapabilityDenied));
        assert_eq!(adapter.writes.get(), 0);
    }

    #[test]
    fn refused_write_text_never_reaches_the_approval_prompt() {
        // A denying broker would turn any prompted request into an approval
        // failure; these refusals keep their own codes, so no prompt ran.
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let denied = FixedApprovalBroker(ApprovalDecision::Denied);
        let big = "a".repeat(orcel_provider_clipboard::MAX_CLIPBOARD_BYTES + 1);
        for (text, code) in [
            ("", FailureCode::InvalidRequest),
            (big.as_str(), FailureCode::OutputLimit),
            ("token=tok_live_999", FailureCode::CapabilityDenied),
        ] {
            let error = write_with_approval(&workspace(), &denied, &write_request(text), &adapter)
                .expect_err("refused text must fail before approval");
            assert_eq!(error.code, code);
        }
        assert_eq!(adapter.writes.get(), 0);
    }

    #[test]
    fn write_never_authorizes_paste_or_input_authority() {
        // Placement touches only the clipboard adapter: no UIA lease, no
        // input execution, no keyboard, no SendInput, and no focus change
        // exists anywhere on the write path. The evidence carries no
        // input-capable material.
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let result = approved_write(&adapter, &write_request("standup notes")).unwrap();
        assert_eq!(result["action"], "write");
        for key in [
            "paste",
            "input",
            "keyboard",
            "sendinput",
            "click",
            "focus",
            "lease",
            "coord_id",
            "hwnd",
        ] {
            assert!(
                result.get(key).is_none(),
                "write result must not carry {key}"
            );
        }
        assert_eq!(adapter.writes.get(), 1);
        assert_eq!(adapter.reads.get(), 0);
    }

    #[test]
    fn write_then_read_round_trip_needs_fresh_approvals() {
        let adapter = FakeClipboard::with_text(11, "old clipboard text");
        let placed = approved_write(&adapter, &write_request("standup notes")).unwrap();
        assert_eq!(placed["resulting_sequence"], 12);
        let sampled = approved_read(&adapter, &read_request()).unwrap();
        assert_eq!(sampled["sequence"], 12);
        assert_eq!(sampled["text"], "standup notes");
    }
}
