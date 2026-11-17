//! JSON Schema drift test (spec section 4.0).
//!
//! It lives in the library's unit tests rather than in
//! `tests/schema_drift.rs` because the `JsonSchema` derives are compiled
//! only under `cfg(test)`: integration tests link the library built without
//! `cfg(test)`, and a non-dev dependency on schemars would put it in the
//! normal dependency graph, which section 3 forbids.
//!
//! `schemars` =1.2.3 is a dev-dependency only, so the `JsonSchema` derives
//! exist only in test builds and never ship. This test regenerates the
//! draft 2020-12 schema of every top-level contract and fails when a file
//! in `docs/orcel/contracts/schema/` differs, is missing or is stale. To
//! regenerate after an intended contract change, run
//! `ORCEL_BLESS_SCHEMAS=1 cargo test -p orcel-contracts schema_` and commit
//! the result.
//!
//! It also checks each object fixture against its schema's top level:
//! every fixture key is a declared property, every required property is
//! present, and unknown properties are refused in the schema exactly where
//! serde refuses them.

use schemars::{schema_for, JsonSchema, Schema};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::capability::CapabilityReport;
use crate::event::{AnchorRef, AuditEvent};
use crate::identity::{Device, OsIdentityBinding, Principal};
use crate::job::Job;
use crate::lease::{DispatchAuthority, GrantRef, LeaseView, StandingApproval};
use crate::session::Session;
use crate::sidecar::{HostToSidecar, SidecarToHost};
use crate::tool::ToolEntry;
use crate::web::{CrawlBudget, Ids, WebBatchScrapeRequest, WebCrawlRequest, WebScrapeRequest};
use crate::FailureCode;

/// (file stem, schema, whether serde refuses unknown fields at the top
/// level). The stems match the golden fixtures where one exists.
fn schemas() -> Vec<(&'static str, Schema, bool)> {
    fn entry<T: JsonSchema>(name: &'static str, strict: bool) -> (&'static str, Schema, bool) {
        (name, schema_for!(T), strict)
    }
    vec![
        entry::<AnchorRef>("anchor_ref", true),
        entry::<AuditEvent>("audit_event", true),
        entry::<CapabilityReport>("capability_report", false),
        entry::<CrawlBudget>("crawl_budget", true),
        entry::<Device>("device", false),
        entry::<DispatchAuthority>("dispatch_authority", true),
        entry::<FailureCode>("failure_code", false),
        entry::<GrantRef>("grant_ref", true),
        entry::<HostToSidecar>("host_to_sidecar", true),
        entry::<Ids>("ids", true),
        entry::<Job>("job", false),
        entry::<LeaseView>("lease_view", false),
        entry::<OsIdentityBinding>("os_identity_binding", true),
        entry::<Principal>("principal", true),
        entry::<Session>("session", true),
        entry::<SidecarToHost>("sidecar_to_host", true),
        entry::<StandingApproval>("standing_approval", true),
        entry::<ToolEntry>("tool_entry", true),
        entry::<WebBatchScrapeRequest>("web_batch_scrape_request", true),
        entry::<WebCrawlRequest>("web_crawl_request", true),
        entry::<WebScrapeRequest>("web_scrape_request", true),
    ]
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn schema_dir() -> PathBuf {
    manifest_dir().join("../../docs/orcel/contracts/schema")
}

fn render(schema: &Schema) -> String {
    let mut text = serde_json::to_string_pretty(schema).expect("schema serializes");
    text.push('\n');
    text
}

#[test]
fn schema_files_match_the_generated_schemas() {
    let dir = schema_dir();
    let bless = std::env::var_os("ORCEL_BLESS_SCHEMAS").is_some_and(|v| v == "1");
    if bless {
        std::fs::create_dir_all(&dir).expect("create schema dir");
    }
    let mut expected_files = BTreeSet::new();
    let mut drift = Vec::new();
    for (name, schema, _) in schemas() {
        let file = format!("{name}.schema.json");
        let path = dir.join(&file);
        let generated = render(&schema);
        expected_files.insert(file.clone());
        if bless {
            std::fs::write(&path, &generated).expect("write schema");
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(on_disk) if on_disk.replace("\r\n", "\n") == generated => {}
            Ok(_) => drift.push(format!("{file}: differs from the generated schema")),
            Err(error) => drift.push(format!("{file}: {error}")),
        }
    }
    let on_disk: BTreeSet<String> = std::fs::read_dir(&dir)
        .expect("schema dir exists")
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    for stale in on_disk.difference(&expected_files) {
        drift.push(format!("{stale}: no contract generates this file"));
    }
    assert!(
        drift.is_empty(),
        "schema drift (regenerate with ORCEL_BLESS_SCHEMAS=1):\n{}",
        drift.join("\n")
    );
}

#[test]
fn schemas_are_draft_2020_12() {
    for (name, schema, _) in schemas() {
        assert_eq!(
            schema.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema"),
            "{name}"
        );
    }
}

#[test]
fn schema_top_level_agrees_with_object_fixtures_and_serde_strictness() {
    for (name, schema, strict) in schemas() {
        let path = manifest_dir().join(format!("tests/fixtures/{name}.json"));
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue; // failure_code has no fixture
        };
        let fixture: Value = serde_json::from_str(&text).expect("fixture parses");
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            continue; // enums and frame unions are covered by round trips
        };
        let items = match fixture {
            Value::Array(items) => items,
            other => vec![other],
        };
        let required = schema
            .get("required")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for item in &items {
            let object = item
                .as_object()
                .expect("object fixture for a struct schema");
            for key in object.keys() {
                assert!(
                    properties.contains_key(key),
                    "{name}: fixture key {key} not in schema"
                );
            }
            for key in &required {
                let key = key.as_str().unwrap();
                assert!(
                    object.contains_key(key),
                    "{name}: required {key} missing from fixture"
                );
            }
        }
        let refuses = schema.get("additionalProperties") == Some(&Value::Bool(false));
        assert_eq!(
            refuses, strict,
            "{name}: additionalProperties vs serde strictness"
        );
    }
}
