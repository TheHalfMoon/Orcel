//! SG-000061 bounded filesystem dispatch.
//!
//! Reads (`fs.read_range`, `fs.find`) need no approval. Mutations bind the
//! identity observed before approval into the approval digest and the
//! provider re-verifies it after approval: `fs.mkdir`, `fs.move`, and
//! `fs.edit` require SOFT approval; `fs.remove` requires the STRONG
//! destructive class. Every mutation verifies its postcondition.

use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
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

fn approve(
    approval: &impl ApprovalBroker,
    workspace: &Workspace,
    strong: bool,
    action: &str,
    target: &str,
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
            approve(
                approval,
                workspace,
                false,
                "create directory",
                relative,
                format!("path={relative} parents={parents}"),
                digest(&[
                    "ORCEL_FS_MKDIR_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    if parents { "1" } else { "0" },
                ]),
            )?;
            provider.mkdir(relative, parents)?
        }
        "fs.move" => {
            let to = string_arg(request, "to")?;
            let identity = provider.entry_identity(relative)?;
            approve(
                approval,
                workspace,
                false,
                "move or rename",
                relative,
                format!("from={relative} to={to} {}", identity_summary(&identity)),
                digest(&[
                    "ORCEL_FS_MOVE_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    to,
                    &identity.digest_fields(),
                ]),
            )?;
            provider.move_entry(relative, to, &identity)?
        }
        "fs.remove" => {
            let identity = provider.entry_identity(relative)?;
            approve(
                approval,
                workspace,
                true,
                "remove one file or empty directory",
                relative,
                format!("path={relative} {}", identity_summary(&identity)),
                digest(&[
                    "ORCEL_FS_REMOVE_V1",
                    &workspace.id,
                    POLICY_REVISION,
                    relative,
                    &identity.digest_fields(),
                ]),
            )?;
            provider.remove_entry(relative, &identity)?
        }
        "fs.edit" => {
            let preview = provider.edit_preview(
                relative,
                string_arg(request, "old")?,
                string_arg(request, "new")?,
                string_arg(request, "expected_sha256")?,
                usize_arg(request, "replacements", 1)?,
            )?;
            approve(
                approval,
                workspace,
                false,
                "edit file",
                relative,
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
            )?;
            provider.edit_apply(&preview)?
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
