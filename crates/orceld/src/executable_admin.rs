//! SG-000060 local protected executable registry management.
//!
//! `executable.registry.add` requires STRONG platform presence bound to a
//! digest of the exact entry (path, hash, size, grammar, and the tier when
//! it is the opt-in contained tier, XP-13b). `remove` is
//! authority-reducing and needs no approval. `list` is read-only. Remote
//! contexts can never reach these capabilities (local-only `executable.`
//! prefix), and no MCP tool exists for them.

use orcel_approval::{ApprovalBroker, ApprovalPrompt, ConsumeExpectation};
use orcel_contracts::{FailureCode, RequestEnvelope};
use orcel_policy::executable_registry::{
    build_entry, load_registry, registration_digest, save_registry, upsert, ExecutionTier,
};
use orcel_policy::POLICY_REVISION;
use orcel_provider_fs::ProviderError;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub fn is_registry_management(capability: &str) -> bool {
    capability.starts_with("executable.registry.")
}

fn strings(arguments: &Value, name: &str) -> Result<Vec<String>, ProviderError> {
    match arguments.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str().map(str::to_owned).ok_or_else(|| {
                    ProviderError::new(
                        FailureCode::InvalidRequest,
                        format!("{name} must list strings"),
                    )
                })
            })
            .collect(),
        Some(_) => Err(ProviderError::new(
            FailureCode::InvalidRequest,
            format!("{name} must be a list of strings"),
        )),
    }
}

fn summary(entry: &orcel_policy::executable_registry::RegisteredExecutable) -> Value {
    json!({
        "id": entry.id,
        "path": entry.path,
        "sha256": entry.sha256,
        "size": entry.size,
        "subcommands": entry.subcommands,
        "denied_args": entry.denied_args,
        "max_args": entry.max_args,
        "tier": entry.tier.as_str(),
    })
}

/// Registered executable identifiers for read-only status.
pub fn registered_summaries(path: &Path) -> Vec<Value> {
    load_registry(path)
        .iter()
        .map(|entry| json!({ "id": entry.id, "path": entry.path, "subcommands": entry.subcommands, "max_args": entry.max_args, "tier": entry.tier.as_str() }))
        .collect()
}

pub fn dispatch_registry(
    registry_path: &Path,
    workspace_roots: &[PathBuf],
    approval: &impl ApprovalBroker,
    request: &RequestEnvelope,
    now_ms: u64,
) -> Result<Value, ProviderError> {
    match (request.capability.as_str(), request.operation.as_str()) {
        ("executable.registry.list", "get") => Ok(json!({
            "executables": load_registry(registry_path).iter().map(summary).collect::<Vec<_>>()
        })),
        ("executable.registry.remove", "remove") => {
            let id = request
                .arguments
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| ProviderError::new(FailureCode::InvalidRequest, "id is required"))?;
            let entries = load_registry(registry_path);
            let next: Vec<_> = entries
                .iter()
                .filter(|entry| entry.id != id)
                .cloned()
                .collect();
            let removed = entries.len() - next.len();
            save_registry(registry_path, &next)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(json!({ "removed": removed }))
        }
        ("executable.registry.add", "add") => {
            let arguments = &request.arguments;
            let object = arguments.as_object().ok_or_else(|| {
                ProviderError::new(FailureCode::InvalidRequest, "arguments must be an object")
            })?;
            const FIELDS: [&str; 6] = [
                "id",
                "path",
                "subcommands",
                "denied_args",
                "max_args",
                "tier",
            ];
            if object.keys().any(|key| !FIELDS.contains(&key.as_str())) {
                return Err(ProviderError::new(
                    FailureCode::InvalidRequest,
                    "registration accepts only id, path, subcommands, denied_args, max_args, and tier",
                ));
            }
            let tier = match arguments.get("tier") {
                None | Some(Value::Null) => ExecutionTier::Safe,
                Some(Value::String(tier)) => ExecutionTier::parse(Some(tier))
                    .map_err(|error| ProviderError::new(error.code, error.message))?,
                Some(_) => {
                    return Err(ProviderError::new(
                        FailureCode::InvalidRequest,
                        "tier must be a string",
                    ))
                }
            };
            let id = arguments
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let path = arguments
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ProviderError::new(FailureCode::InvalidRequest, "path is required")
                })?;
            let max_args = arguments
                .get("max_args")
                .and_then(Value::as_u64)
                .unwrap_or(16) as usize;
            let mut entry = build_entry(
                id,
                Path::new(path),
                strings(arguments, "subcommands")?,
                strings(arguments, "denied_args")?,
                max_args,
                workspace_roots,
                now_ms,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?;
            entry.tier = tier;
            let digest = registration_digest(&entry, POLICY_REVISION);
            let prompt = ApprovalPrompt::new_strong(
                request.workspace_id.clone(),
                POLICY_REVISION,
                "register a protected executable",
                entry.path.clone(),
                format!(
                    "id={} sha256={} size={} subcommands={} denied_args={} max_args={} tier={}",
                    entry.id,
                    entry.sha256,
                    entry.size,
                    entry.subcommands.join(","),
                    entry.denied_args.join(","),
                    entry.max_args,
                    entry.tier.as_str()
                ),
                digest.clone(),
            );
            let token = approval
                .request_token(&prompt)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            approval
                .consume(
                    &token,
                    &ConsumeExpectation::strong(
                        digest,
                        request.workspace_id.clone(),
                        POLICY_REVISION,
                    ),
                    orcel_approval::now_ms(),
                )
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            // Re-hash after approval: the file must still be what was approved.
            let confirmed = build_entry(
                &entry.id,
                Path::new(&entry.path),
                entry.subcommands.clone(),
                entry.denied_args.clone(),
                entry.max_args,
                workspace_roots,
                now_ms,
            )
            .map_err(|error| ProviderError::new(error.code, error.message))?;
            if confirmed.sha256 != entry.sha256 || confirmed.size != entry.size {
                return Err(ProviderError::new(
                    FailureCode::TargetStale,
                    "the executable changed during approval; registration fails closed",
                ));
            }
            let next = upsert(&load_registry(registry_path), entry.clone())
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            save_registry(registry_path, &next)
                .map_err(|error| ProviderError::new(error.code, error.message))?;
            Ok(summary(&entry))
        }
        _ => Err(ProviderError::new(
            FailureCode::CapabilityDenied,
            "unknown executable registry operation",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use orcel_approval::test_support::{
        broker_with_presence, FixedApprovalBroker, TestPresenceVerifier,
    };
    use orcel_approval::ApprovalDecision;

    /// A fake executable the registry admits on this OS: off Windows it
    /// must start with the native image magic (XP-13b).
    fn native_image(body: &[u8]) -> Vec<u8> {
        let magic: &[u8] = if cfg!(windows) {
            b""
        } else if cfg!(target_os = "macos") {
            &[0xcf, 0xfa, 0xed, 0xfe]
        } else {
            &[0x7f, b'E', b'L', b'F']
        };
        [magic, body].concat()
    }

    fn next_temp_sequence() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        // macOS clocks tick in microseconds, so a timestamp alone can repeat
        // across parallel tests in one process.
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    }

    fn temp(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let nanos = format!("{nanos}-{}", next_temp_sequence());
        let dir = std::env::temp_dir().join(format!(
            "orceld-registry-{label}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn request(capability: &str, operation: &str, arguments: Value) -> RequestEnvelope {
        RequestEnvelope {
            version: 1,
            request_id: "reg".into(),
            client_session_id: "local".into(),
            workspace_id: "default".into(),
            capability: capability.into(),
            operation: operation.into(),
            target: None,
            arguments,
        }
    }

    #[test]
    fn registration_requires_strong_presence_and_records_hash_pinned_identity() {
        let dir = temp("add");
        let exe = dir.join("tool.exe");
        std::fs::write(&exe, native_image(b"MZ tool")).unwrap();
        let registry = dir.join("executable_registry.json");
        let add = request(
            "executable.registry.add",
            "add",
            json!({ "id": "tool", "path": exe.to_string_lossy(), "subcommands": ["test"], "denied_args": ["--config"], "max_args": 4 }),
        );
        for verifier in [
            TestPresenceVerifier::denied(),
            TestPresenceVerifier::unavailable(),
        ] {
            let broker = broker_with_presence(dir.join("approval.jsonl"), verifier);
            assert!(dispatch_registry(&registry, &[], &broker, &add, 1).is_err());
            assert!(load_registry(&registry).is_empty());
        }
        assert!(dispatch_registry(
            &registry,
            &[],
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &add,
            1
        )
        .is_err());
        let broker =
            broker_with_presence(dir.join("approval.jsonl"), TestPresenceVerifier::verified());
        let added = dispatch_registry(&registry, &[], &broker, &add, 1).unwrap();
        assert_eq!(added["id"], "tool");
        assert_eq!(added["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(load_registry(&registry).len(), 1);
        let listed = dispatch_registry(
            &registry,
            &[],
            &broker,
            &request("executable.registry.list", "get", json!({})),
            1,
        )
        .unwrap();
        assert_eq!(listed["executables"][0]["subcommands"][0], "test");
        let removed = dispatch_registry(
            &registry,
            &[],
            &FixedApprovalBroker(ApprovalDecision::Denied),
            &request(
                "executable.registry.remove",
                "remove",
                json!({ "id": "tool" }),
            ),
            1,
        )
        .unwrap();
        assert_eq!(
            removed["removed"], 1,
            "removal is authority-reducing and needs no approval"
        );
        assert!(load_registry(&registry).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// XP-13b: the contained tier is chosen at registration, under the same
    /// STRONG approval, and an unknown tier is refused.
    #[test]
    fn xp13b_a_registration_can_choose_the_contained_tier() {
        let dir = temp("tier");
        let exe = dir.join("tool.exe");
        std::fs::write(&exe, native_image(b"MZ tool")).unwrap();
        let registry = dir.join("executable_registry.json");
        let broker =
            broker_with_presence(dir.join("approval.jsonl"), TestPresenceVerifier::verified());
        let add = |tier: Value| {
            request(
                "executable.registry.add",
                "add",
                json!({ "id": "tool", "path": exe.to_string_lossy(), "max_args": 2, "tier": tier }),
            )
        };
        for bad in [json!("sandboxed"), json!(true)] {
            assert!(dispatch_registry(&registry, &[], &broker, &add(bad), 1).is_err());
        }
        assert!(load_registry(&registry).is_empty());
        let added =
            dispatch_registry(&registry, &[], &broker, &add(json!("contained")), 1).unwrap();
        assert_eq!(added["tier"], "contained");
        assert_eq!(load_registry(&registry)[0].tier, ExecutionTier::Contained);
        let safe = dispatch_registry(&registry, &[], &broker, &add(Value::Null), 1).unwrap();
        assert_eq!(safe["tier"], "safe");
        assert_eq!(load_registry(&registry)[0].tier, ExecutionTier::Safe);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn registration_rejects_interpreters_workspace_binaries_and_extra_fields() {
        let dir = temp("reject");
        let broker =
            broker_with_presence(dir.join("approval.jsonl"), TestPresenceVerifier::verified());
        let registry = dir.join("executable_registry.json");
        let shell = dir.join("powershell.exe");
        std::fs::write(&shell, native_image(b"MZ")).unwrap();
        assert!(dispatch_registry(
            &registry,
            &[],
            &broker,
            &request(
                "executable.registry.add",
                "add",
                json!({ "id": "ps", "path": shell.to_string_lossy() })
            ),
            1
        )
        .is_err());
        let tool = dir.join("tool.exe");
        std::fs::write(&tool, native_image(b"MZ")).unwrap();
        assert!(dispatch_registry(
            &registry,
            std::slice::from_ref(&dir),
            &broker,
            &request(
                "executable.registry.add",
                "add",
                json!({ "id": "tool", "path": tool.to_string_lossy() })
            ),
            1
        )
        .is_err());
        assert!(dispatch_registry(
            &registry,
            &[],
            &broker,
            &request(
                "executable.registry.add",
                "add",
                json!({ "id": "tool", "path": tool.to_string_lossy(), "trusted": true })
            ),
            1
        )
        .is_err());
        assert!(load_registry(&registry).is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }
}
