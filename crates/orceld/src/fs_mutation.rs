//! SG-000061 bounded filesystem dispatch.
//!
//! Reads (`fs.read_range`, `fs.find`) need no approval. Mutations bind the
//! identity observed before approval into the approval digest and the
//! provider re-verifies it after approval: `fs.mkdir`, `fs.move`, and
//! `fs.edit` require SOFT approval; `fs.remove` requires the STRONG
//! destructive class. Every mutation verifies its postcondition.

use crate::mutation_journal::{self, Mutation, Postcondition, Sink};
use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation, Preview, PreviewMode};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::{Workspace, POLICY_REVISION};
use orcel_provider_fs::mutation::EntryIdentity;
use orcel_provider_fs::{FsProvider, ProviderError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn digest(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field.as_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn target(request: &RequestEnvelope) -> Result<&str, ProviderError> {
    request.target.as_deref().ok_or_else(|| {
        ProviderError::new(
            FailureCode::InvalidRequest,
            "workspace-relative target is required",
        )
    })
}

fn usize_arg(
    request: &RequestEnvelope,
    name: &str,
    default: usize,
) -> Result<usize, ProviderError> {
    match request.arguments.get(name) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value.as_u64().map(|v| v as usize).ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("{name} must be an unsigned integer"),
            )
        }),
    }
}

fn string_arg<'a>(request: &'a RequestEnvelope, name: &str) -> Result<&'a str, ProviderError> {
    request
        .arguments
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ProviderError::new(
                FailureCode::InvalidRequest,
                format!("{name} must be a string"),
            )
        })
}

/// The person's choice for approval previews, from orceld's launch settings (the
/// `ORCEL_APPROVAL_PREVIEWS` variable its launcher sets, never a request): `sizes` shows sizes
/// only; anything else, or nothing, shows a bounded preview that is hidden when the content
/// looks like a credential.
pub(crate) fn preview_mode() -> PreviewMode {
    match std::env::var("ORCEL_APPROVAL_PREVIEWS").as_deref() {
        Ok("sizes") => PreviewMode::SizesOnly,
        _ => PreviewMode::Content,
    }
}

/// Whether text matches a known credential pattern: the clipboard's secret filter, or one of
/// the preview patterns below. Such content is never previewed. This decides only whether a
/// preview is hidden, so it leans towards hiding; it is a pattern list, not a guarantee.
pub(crate) fn looks_secret(text: &str) -> bool {
    orcel_provider_clipboard::contains_secret_material(text) || preview_secret_pattern(text)
}

/// Credential shapes the clipboard filter doesn't cover: provider key prefixes, JWTs, long
/// mixed-case tokens, `NAME_KEY=value` style assignments, and a password in a URL.
fn preview_secret_pattern(text: &str) -> bool {
    const PREFIXES: [&str; 26] = [
        "sk-ant-",
        "sk-proj-",
        "sk-svcacct-",
        "sk_live_",
        "sk_test_",
        "rk_live_",
        "rk_test_",
        "pk_live_",
        "whsec_",
        "github_pat_",
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "xoxs-",
        "AKIA",
        "ASIA",
        "AIza",
        "ya29.",
        "npm_",
        "hf_",
    ];
    let token_char = |c: char| c.is_ascii_alphanumeric() || "-_./+=".contains(c);
    for word in text.split(|c: char| !token_char(c)) {
        if PREFIXES
            .iter()
            .any(|prefix| word.starts_with(prefix) && word.len() >= prefix.len() + 12)
        {
            return true;
        }
        // A JWT: three dot-separated base64url parts, the first a JSON header.
        if word.starts_with("eyJ") && word.matches('.').count() == 2 && word.len() > 30 {
            return true;
        }
        // A long token mixing upper case, lower case and digits (an AWS secret key, a key
        // body without its BEGIN line). Lower-case hex digests don't match.
        if word.len() >= 32
            && word.chars().any(|c| c.is_ascii_uppercase())
            && word.chars().any(|c| c.is_ascii_lowercase())
            && word.chars().any(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(['=', ':']) {
            let name = name
                .trim()
                .trim_start_matches("export ")
                .to_ascii_uppercase();
            let named = [
                "KEY",
                "TOKEN",
                "SECRET",
                "PASSWORD",
                "PASSWD",
                "CREDENTIAL",
                "AUTH",
            ]
            .iter()
            .any(|part| name.contains(part));
            if named && !name.contains(' ') && value.trim().trim_matches(['"', '\'']).len() >= 8 {
                return true;
            }
        }
    }
    // user:password@host in a URL.
    text.match_indices("://").any(|(at, _)| {
        let rest = &text[at + 3..];
        let authority = &rest[..rest.find(['/', ' ', '\n', '"', '\'']).unwrap_or(rest.len())];
        authority
            .rsplit_once('@')
            .is_some_and(|(user_info, _)| user_info.contains(':'))
    })
}

/// What the prompt says the target is: whether it is a file (so its type is shown), for a
/// move where it goes, and a preview of the content.
#[derive(Clone)]
struct Shown<'a> {
    file: bool,
    destination: Option<&'a str>,
    preview: Option<Preview>,
}

impl Shown<'_> {
    const DIRECTORY: Self = Self {
        file: false,
        destination: None,
        preview: None,
    };

    fn entry(identity: &EntryIdentity) -> Self {
        Self {
            file: identity.kind == "file",
            destination: None,
            preview: None,
        }
    }

    fn mark(self, prompt: ApprovalPrompt) -> ApprovalPrompt {
        let prompt = if self.file { prompt.for_file() } else { prompt };
        let prompt = match self.preview {
            Some(preview) => prompt.with_preview(preview),
            None => prompt,
        };
        match self.destination {
            Some(destination) => prompt.with_destination(destination),
            None => prompt,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn approve(
    approval: &impl ApprovalBroker,
    workspace: &Workspace,
    strong: bool,
    action: &str,
    target: &str,
    shown: Shown<'_>,
    summary: String,
    digest: String,
) -> Result<(), ProviderError> {
    let prompt = if strong {
        ApprovalPrompt::new_strong(
            workspace.id.clone(),
            POLICY_REVISION,
            action,
            target.to_owned(),
            summary,
            digest.clone(),
        )
    } else {
        ApprovalPrompt::new(
            workspace.id.clone(),
            POLICY_REVISION,
            action,
            target.to_owned(),
            summary,
            digest.clone(),
        )
    };
    let prompt = shown.mark(prompt);
    let token = approval
        .request_token(&prompt)
        .map_err(|error| ProviderError::new(error.code, error.message))?;
    let expectation = if strong {
        ConsumeExpectation::strong(digest, workspace.id.clone(), POLICY_REVISION)
    } else {
        ConsumeExpectation::new(digest, workspace.id.clone(), POLICY_REVISION)
    };
    approval
        .consume(&token, &expectation, orcel_approval::now_ms())
        .map_err(|error| ProviderError::new(error.code, error.message))
}

/// One approved, journaled mutation (SG-000120 RJ-02): `pending` before the
/// approval, `dispatched` before `act`, then its outcome. Refused, with
/// nothing asked, when the journal cannot record it.
#[allow(clippy::too_many_arguments)]
fn approved<T>(
    sink: Sink,
    approval: &impl ApprovalBroker,
    workspace: &Workspace,
    request: &RequestEnvelope,
    strong: bool,
    action: &str,
    target: &str,
    shown: Shown<'_>,
    summary: String,
    digest: String,
    postcondition: Postcondition,
    act: impl FnOnce() -> Result<T, ProviderError>,
) -> Result<T, ProviderError> {
    let mutation = Mutation {
        capability: request.capability.clone(),
        operation: request.operation.clone(),
        approval_digest: digest.clone(),
        workspace_id: workspace.id.clone(),
        policy_revision: POLICY_REVISION.to_owned(),
        root: workspace.root.clone(),
        target: target.to_owned(),
        postcondition,
    };
    mutation_journal::journaled(
        sink,
        mutation,
        || {
            approve(
                approval, workspace, strong, action, target, shown, summary, digest,
            )
        },
        act,
    )
}

fn identity_summary(identity: &EntryIdentity) -> String {
    format!(
        "kind={} size={} sha256={}",
        identity.kind,
        identity.size,
        identity.sha256.as_deref().unwrap_or("-")
    )
}

pub fn dispatch_fs_mutation(
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    dispatch_fs_mutation_to(mutation_journal::global(), workspace, approval, request)
}

/// [`dispatch_fs_mutation`] journaling to `sink`.
pub(crate) fn dispatch_fs_mutation_to(
    sink: Sink,
    workspace: &Workspace,
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
) -> Result<Option<Value>, ProviderError> {
    if !orcel_policy::is_fs_mutation_shape(&request.capability, &request.operation) {
        return Ok(None);
    }
    let provider = FsProvider::new(&workspace.root)?;
    let relative = target(request)?;
    let value = match request.capability.as_str() {
        "fs.read_range" => provider.read_range(
            relative,
            usize_arg(request, "start_line", 1)?,
            usize_arg(request, "max_lines", 200)?,
        )?,
        "fs.find" => provider.find_names(
            relative,
            string_arg(request, "pattern")?,
            usize_arg(request, "max_results", 100)?,
            usize_arg(request, "max_depth", 8)?,
        )?,
        "fs.mkdir" => {
            let parents = request
                .arguments
                .get("parents")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            approved(
                sink,
                approval,
                workspace,
                request,
                false,
                "create directory",
                relative,
                Shown::DIRECTORY,
                format!("path={relative} parents={parents}"),
                digest(&[
                    "ORCEL_FS_MKDIR_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    if parents { "1" } else { "0" },
                ]),
                Postcondition::Directory {
                    created: mutation_journal::first_missing(&workspace.root, relative),
                },
                || provider.mkdir(relative, parents),
            )?
        }
        "fs.move" => {
            let to = string_arg(request, "to")?;
            let identity = provider.entry_identity(relative)?;
            approved(
                sink,
                approval,
                workspace,
                request,
                false,
                "move or rename",
                relative,
                Shown {
                    destination: Some(to),
                    ..Shown::entry(&identity)
                },
                format!("from={relative} to={to} {}", identity_summary(&identity)),
                digest(&[
                    "ORCEL_FS_MOVE_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    to,
                    &identity.digest_fields(),
                ]),
                Postcondition::Moved {
                    to: to.to_owned(),
                    sha256: identity.sha256.clone(),
                },
                || provider.move_entry(relative, to, &identity),
            )?
        }
        "fs.remove" => {
            let identity = provider.entry_identity(relative)?;
            approved(
                sink,
                approval,
                workspace,
                request,
                true,
                "remove one file or empty directory",
                relative,
                Shown::entry(&identity),
                format!("path={relative} {}", identity_summary(&identity)),
                digest(&[
                    "ORCEL_FS_REMOVE_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    &identity.digest_fields(),
                ]),
                Postcondition::Absent {
                    before_kind: identity.kind.to_owned(),
                    before_sha256: identity.sha256.clone(),
                },
                || provider.remove_entry(relative, &identity),
            )?
        }
        "fs.edit" => {
            let (old, new) = (string_arg(request, "old")?, string_arg(request, "new")?);
            let preview = provider.edit_preview(
                relative,
                old,
                new,
                string_arg(request, "expected_sha256")?,
                usize_arg(request, "replacements", 1)?,
            )?;
            approved(
                sink,
                approval,
                workspace,
                request,
                false,
                "edit file",
                relative,
                Shown {
                    file: true,
                    destination: None,
                    preview: Some(Preview::of_edit(
                        old,
                        new,
                        preview_mode(),
                        looks_secret(old) || looks_secret(new),
                    )),
                },
                format!(
                    "path={relative} replacements={} sha256={} -> {}",
                    preview.replacements, preview.current_sha256, preview.new_sha256
                ),
                digest(&[
                    "ORCEL_FS_EDIT_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    &preview.current_sha256,
                    &preview.new_sha256,
                    &preview.replacements.to_string(),
                ]),
                Postcondition::File {
                    sha256: preview.new_sha256.clone(),
                    before: Some(preview.current_sha256.clone()),
                },
                || provider.edit_apply(&preview),
            )?
        }
        _ => {
            return Err(ProviderError::new(
                FailureCode::CapabilityDenied,
                "unknown filesystem operation",
            ))
        }
    };
    Ok(Some(json!(value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_approval::test_support::{
        broker_with_presence, FixedApprovalBroker, TestPresenceVerifier,
    };
    use orcel_approval::ApprovalDecision;
    use std::fs;
    use std::path::PathBuf;

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn fixture(label: &str) -> (Workspace, PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let nanos = format!("{nanos}-{}", next_temp_sequence());
        let root =
            std::env::temp_dir().join(format!("orceld-fs-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        (
            Workspace {
                id: "default".into(),
                root: fs::canonicalize(&root).unwrap(),
            },
            root,
        )
    }

    fn request(
        capability: &str,
        operation: &str,
        target: &str,
        arguments: Value,
    ) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "fs".into(),
            client_session_id: "s".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: Some(target.into()),
            arguments,
        }
    }

    #[test]
    fn mutations_require_approval_and_denials_change_nothing() {
        let (workspace, root) = fixture("deny");
        fs::write(root.join("a.txt"), "alpha").unwrap();
        let denied = FixedApprovalBroker(ApprovalDecision::Denied);
        for (capability, operation, target, arguments) in [
            ("fs.mkdir", "mkdir", "newdir", json!({})),
            ("fs.move", "move", "a.txt", json!({ "to": "b.txt" })),
            (
                "fs.edit",
                "edit",
                "a.txt",
                json!({ "old": "alpha", "new": "beta", "expected_sha256": format!("{:x}", Sha256::digest(b"alpha")) }),
            ),
        ] {
            assert!(dispatch_fs_mutation(
                &workspace,
                &denied,
                &request(capability, operation, target, arguments)
            )
            .is_err());
        }
        assert!(!root.join("newdir").exists());
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "alpha");
        let _ = fs::remove_dir_all(root);
    }

    /// What each prompt says its target is: a file's moves and edits are files, with a move's
    /// destination; a directory and a new directory are not. The broker records and denies, so
    /// nothing changes.
    #[test]
    fn prompts_say_what_the_target_is_and_where_a_move_goes() {
        use orcel_approval::{ApprovalError, ApprovedToken, TargetKind};
        struct Recording(std::cell::RefCell<Vec<(TargetKind, Option<String>)>>);
        impl ApprovalBroker for Recording {
            fn request_token(
                &self,
                prompt: &ApprovalPrompt,
            ) -> Result<ApprovedToken, ApprovalError> {
                self.0
                    .borrow_mut()
                    .push((prompt.target_kind, prompt.destination.clone()));
                Err(ApprovalError {
                    code: FailureCode::ApprovalDenied,
                    message: "recorded only".into(),
                })
            }
            fn consume(
                &self,
                _: &ApprovedToken,
                _: &ConsumeExpectation,
                _: u64,
            ) -> Result<(), ApprovalError> {
                Err(ApprovalError {
                    code: FailureCode::ApprovalDenied,
                    message: "recorded only".into(),
                })
            }
        }
        let (workspace, root) = fixture("shown");
        fs::write(root.join("a.txt"), "alpha").unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        let recording = Recording(std::cell::RefCell::new(Vec::new()));
        for (capability, operation, target, arguments) in [
            ("fs.move", "move", "a.txt", json!({ "to": "b.sh" })),
            ("fs.move", "move", "dir", json!({ "to": "dir2" })),
            ("fs.mkdir", "mkdir", "newdir", json!({})),
            (
                "fs.edit",
                "edit",
                "a.txt",
                json!({ "old": "alpha", "new": "beta", "expected_sha256": format!("{:x}", Sha256::digest(b"alpha")) }),
            ),
        ] {
            let _ = dispatch_fs_mutation(
                &workspace,
                &recording,
                &request(capability, operation, target, arguments),
            );
        }
        assert_eq!(
            *recording.0.borrow(),
            vec![
                (TargetKind::File, Some("b.sh".to_owned())),
                (TargetKind::Other, Some("dir2".to_owned())),
                (TargetKind::Other, None),
                (TargetKind::File, None),
            ]
        );
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "alpha");
        let _ = fs::remove_dir_all(root);
    }

    /// An edit's prompt previews the text it removes and adds; a replacement that looks like a
    /// credential is not shown. The broker records and denies, so nothing changes.
    #[test]
    fn an_edit_prompt_previews_its_change_and_hides_a_credential() {
        use orcel_approval::{ApprovalError, ApprovedToken};
        struct Recording(std::cell::RefCell<Vec<Option<Preview>>>);
        impl ApprovalBroker for Recording {
            fn request_token(
                &self,
                prompt: &ApprovalPrompt,
            ) -> Result<ApprovedToken, ApprovalError> {
                self.0.borrow_mut().push(prompt.preview.clone());
                Err(ApprovalError {
                    code: FailureCode::ApprovalDenied,
                    message: "recorded only".into(),
                })
            }
            fn consume(
                &self,
                _: &ApprovedToken,
                _: &ConsumeExpectation,
                _: u64,
            ) -> Result<(), ApprovalError> {
                Err(ApprovalError {
                    code: FailureCode::ApprovalDenied,
                    message: "recorded only".into(),
                })
            }
        }
        let (workspace, root) = fixture("preview");
        fs::write(root.join("a.txt"), "alpha").unwrap();
        let sha = format!("{:x}", Sha256::digest(b"alpha"));
        let recording = Recording(std::cell::RefCell::new(Vec::new()));
        for new in ["beta", "password=hunter2"] {
            let _ = dispatch_fs_mutation(
                &workspace,
                &recording,
                &request(
                    "fs.edit",
                    "edit",
                    "a.txt",
                    json!({ "old": "alpha", "new": new, "expected_sha256": sha }),
                ),
            );
        }
        let seen = recording.0.borrow();
        assert_eq!(
            seen[0],
            Some(Preview::Content {
                lines: vec![('-', "alpha".to_owned()), ('+', "beta".to_owned())],
                more_lines: 0,
            })
        );
        assert!(
            matches!(seen[1], Some(Preview::Hidden { .. })),
            "{:?}",
            seen[1]
        );
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "alpha");
        let _ = fs::remove_dir_all(root);
    }

    /// The preview check hides common credential shapes and leaves ordinary text alone.
    #[test]
    fn the_preview_check_hides_common_credentials() {
        for secret in [
            "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUv",
            "OPENAI=sk-proj-abcdefghijklmnop123",
            "stripe sk_live_51HabcdefghijklmnopQR",
            "github_pat_11ABCDEFG0123456789_abcdef",
            "token ghp_abcdefghijklmnopqrstuvwxyz0123",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijk",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "AIzaSyA1234567890abcdefghijklmnopq",
            "DJANGO_SECRET_KEY=abcdefgh1234",
            "export AWS_SESSION_TOKEN=\"abcdefghijk\"",
            "api_token: abcdefghij",
            "DATABASE_URL=postgres://user:hunter22@db.example/app",
            "see https://admin:pw12345@example.com/path",
        ] {
            assert!(looks_secret(secret), "{secret}");
        }
        for ordinary in [
            "hello world\nsecond line",
            "the key: is to keep it short",
            "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "https://example.com/a/b?x=1",
            "fn main() { println!(\"hi\"); }",
            "key = 1",
        ] {
            assert!(!looks_secret(ordinary), "{ordinary}");
        }
    }

    #[test]
    fn removal_requires_strong_presence() {
        let (workspace, root) = fixture("remove");
        fs::write(root.join("a.txt"), "alpha").unwrap();
        let remove = request("fs.remove", "remove", "a.txt", json!({}));
        assert!(dispatch_fs_mutation(
            &workspace,
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &remove
        )
        .is_err());
        for verifier in [
            TestPresenceVerifier::denied(),
            TestPresenceVerifier::unavailable(),
        ] {
            let broker = broker_with_presence(root.join("approval.jsonl"), verifier);
            assert!(dispatch_fs_mutation(&workspace, &broker, &remove).is_err());
            assert!(root.join("a.txt").exists());
        }
        let broker = broker_with_presence(
            root.join("approval.jsonl"),
            TestPresenceVerifier::verified(),
        );
        let removed = dispatch_fs_mutation(&workspace, &broker, &remove)
            .unwrap()
            .unwrap();
        assert_eq!(removed["removed"], true);
        assert!(!root.join("a.txt").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn approved_soft_mutations_and_reads_work_end_to_end() {
        let (workspace, root) = fixture("ok");
        fs::write(root.join("a.txt"), "one\ntwo\nthree\n").unwrap();
        let approved = FixedApprovalBroker(ApprovalDecision::Approved);
        let made = dispatch_fs_mutation(
            &workspace,
            &approved,
            &request("fs.mkdir", "mkdir", "src/sub", json!({ "parents": true })),
        )
        .unwrap()
        .unwrap();
        assert_eq!(made["created"], json!(["src", "src/sub"]));
        dispatch_fs_mutation(
            &workspace,
            &approved,
            &request("fs.move", "move", "a.txt", json!({ "to": "src/a.txt" })),
        )
        .unwrap();
        let sha = format!("{:x}", Sha256::digest(b"one\ntwo\nthree\n"));
        let edited = dispatch_fs_mutation(
            &workspace,
            &approved,
            &request(
                "fs.edit",
                "edit",
                "src/a.txt",
                json!({ "old": "two", "new": "2", "expected_sha256": sha }),
            ),
        )
        .unwrap()
        .unwrap();
        assert_eq!(edited["replacements"], 1);
        let range = dispatch_fs_mutation(
            &workspace,
            &approved,
            &request(
                "fs.read_range",
                "read",
                "src/a.txt",
                json!({ "start_line": 2, "max_lines": 1 }),
            ),
        )
        .unwrap()
        .unwrap();
        assert_eq!(range["lines"], json!(["2"]));
        let found = dispatch_fs_mutation(
            &workspace,
            &approved,
            &request("fs.find", "find", ".", json!({ "pattern": "a.*" })),
        )
        .unwrap()
        .unwrap();
        assert_eq!(found["matches"][0]["path"], "src/a.txt");
        assert!(
            dispatch_fs_mutation(
                &workspace,
                &approved,
                &request("fs.delete", "delete", "src/a.txt", json!({}))
            )
            .unwrap()
            .is_none(),
            "the generic shape is not handled here"
        );
        let _ = fs::remove_dir_all(root);
    }
}
