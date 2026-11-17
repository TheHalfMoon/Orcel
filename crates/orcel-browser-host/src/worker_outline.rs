//! W2-03: the host side of the worker's Stagehand-derived capabilities: the
//! bounded accessibility outline (`outline` / `outlined`) and the
//! deterministic, schema-driven extraction (`extract_schema` /
//! `schema_extracted`), worker protocol generation 18.
//!
//! The worker code is copied and adapted from browserbase/stagehand at
//! commit 82827a219512f0399cb159720a63f7d271d21480 (MIT License, Copyright
//! (c) 2024 Browserbase Inc.; notice in `docs/orcel/notices/stagehand-MIT.txt`;
//! provenance in `docs/orcel/stagehand_provenance.json`). This file is new
//! Orcel code: the wire types the host accepts and the policy gate.
//!
//! The host is the authority. Neither capability is admitted by any grain
//! yet, so `admit` refuses both and the host never sends either frame: a new
//! observation surface needs an SG-000076 amendment (which names in the
//! outline a caller may see, and how they are redacted and digested), and a
//! schema extraction on a live page needs an SG-000133 amendment (the
//! browser-backed `extract` with a schema and no model). Using an outline
//! node as an action target would further need an SG-000122 amendment; until
//! then every action stays one of the existing approved actions on a
//! snapshot ref. No model is ever called from the worker: any language-model
//! step belongs to orceld with the user's own key.

use crate::error::HostError;

/// A Stagehand-derived worker capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerCapability {
    /// The bounded accessibility outline of the committed document.
    Outline,
    /// The schema-driven extraction from that outline.
    SchemaExtract,
}

impl WorkerCapability {
    /// The grain amendment that would admit this capability.
    pub fn pending_grain(self) -> &'static str {
        match self {
            WorkerCapability::Outline => "SG-000076",
            WorkerCapability::SchemaExtract => "SG-000133",
        }
    }
}

/// Whether a grain admits the capability. None does yet; changing this is a
/// grain amendment, not a configuration.
pub const fn admitted(_capability: WorkerCapability) -> bool {
    false
}

/// The policy gate every use passes before any frame is sent: denied by
/// default, with the amendment it waits for.
pub fn admit(capability: WorkerCapability) -> Result<(), HostError> {
    if admitted(capability) {
        return Ok(());
    }
    Err(HostError::Invalid(format!(
        "the browser {} is not admitted (denied by default until a {} amendment)",
        match capability {
            WorkerCapability::Outline => "outline",
            WorkerCapability::SchemaExtract => "schema extraction",
        },
        capability.pending_grain()
    )))
}

/// Mirrors the worker's bounds (apps/orcel-browser-worker/src/outline).
#[cfg_attr(not(windows), allow(dead_code))]
pub const MAX_OUTLINE_NODES: usize = 512;
/// The deepest node level the worker sends (roots are level 0).
#[cfg_attr(not(windows), allow(dead_code))]
pub const MAX_OUTLINE_DEPTH: usize = 32;
pub const MAX_OUTLINE_NAME_BYTES: usize = 512;
pub const MAX_OUTLINE_XPATH_BYTES: usize = 1024;
pub const MAX_SCHEMA_FIELDS: usize = 32;
#[cfg_attr(not(windows), allow(dead_code))]
pub const MAX_SCHEMA_LIST_ITEMS: usize = 32;
#[cfg_attr(not(windows), allow(dead_code))]
pub const MAX_SCHEMA_TEXT_BYTES: usize = 2048;

/// One outline node as the worker sends it. Every string but `id` and
/// `xpath` is page text; there is no field for a value.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutlineNode {
    pub id: String,
    pub role: String,
    pub name: String,
    pub xpath: String,
    #[serde(default)]
    pub url: Option<String>,
    pub children: Vec<OutlineNode>,
}

/// One schema field as the host would send it: a key, what to take, and
/// exactly one target (a role with an optional exact name, or an XPath).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaField {
    pub key: String,
    pub take: SchemaTake,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub xpath: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SchemaTake {
    Text,
    Texts,
    Url,
}

/// One extracted value as the worker sends it (page text).
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaValue {
    pub key: String,
    pub found: bool,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub texts: Option<Vec<String>>,
    #[serde(default)]
    pub url: Option<String>,
}

/// An outline the host accepted (host-internal page text, bound to the
/// document generation; never returned to a caller before an amendment says
/// how its names are redacted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outline {
    pub url: String,
    pub document_generation: u64,
    pub truncated: bool,
    pub nodes: Vec<OutlineNode>,
}

/// A schema extraction the host accepted (page text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaExtraction {
    pub url: String,
    pub document_generation: u64,
    pub truncated: bool,
    pub values: Vec<SchemaValue>,
}

#[cfg_attr(not(windows), allow(dead_code))]
fn protocol_violation() -> HostError {
    HostError::Unavailable(crate::error::UnavailableReason::ProtocolViolation)
}

/// Re-check the worker's outline bounds (defense against a worker bug or a
/// compromised worker): node count, name and XPath bytes, no control
/// characters, ids of the outline's own shape.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn check_outline(nodes: &[OutlineNode]) -> Result<(), HostError> {
    let mut count = 0usize;
    let mut stack: Vec<(&OutlineNode, usize)> = nodes.iter().map(|node| (node, 0)).collect();
    while let Some((node, depth)) = stack.pop() {
        count += 1;
        let id_ok = node.id.is_empty()
            || node.id.strip_prefix("0-").is_some_and(|rest| {
                !rest.is_empty() && rest.len() <= 12 && rest.bytes().all(|b| b.is_ascii_digit())
            });
        if count > MAX_OUTLINE_NODES
            || depth > MAX_OUTLINE_DEPTH
            || !id_ok
            || !role_ok(&node.role)
            || node.name.len() > MAX_OUTLINE_NAME_BYTES
            || node.xpath.len() > MAX_OUTLINE_XPATH_BYTES
            || node.name.chars().any(char::is_control)
            || node.role.chars().any(char::is_control)
            || node.xpath.chars().any(char::is_control)
        {
            return Err(protocol_violation());
        }
        if let Some(url) = &node.url {
            if !(url.starts_with("https://") || url.starts_with("http://")) || url.len() > 2048 {
                return Err(protocol_violation());
            }
        }
        stack.extend(node.children.iter().map(|child| (child, depth + 1)));
    }
    Ok(())
}

/// The worker's role pattern: a letter, then up to 47 letters, digits,
/// spaces, commas or hyphens.
fn role_ok(role: &str) -> bool {
    role.len() <= 48
        && role.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
        && role
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ,-".contains(c))
}

/// Re-check a schema reply: one value per field, in order, each bounded.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn check_values(fields: &[SchemaField], values: &[SchemaValue]) -> Result<(), HostError> {
    if fields.len() != values.len() {
        return Err(protocol_violation());
    }
    for (field, value) in fields.iter().zip(values) {
        let text_ok = value
            .text
            .as_deref()
            .is_none_or(|t| t.len() <= MAX_SCHEMA_TEXT_BYTES && !t.chars().any(char::is_control));
        let texts_ok = value.texts.as_deref().is_none_or(|items| {
            items.len() <= MAX_SCHEMA_LIST_ITEMS
                && items
                    .iter()
                    .all(|t| t.len() <= MAX_OUTLINE_NAME_BYTES && !t.chars().any(char::is_control))
        });
        let url_ok = value.url.as_deref().is_none_or(|u| {
            (u.starts_with("https://") || u.starts_with("http://")) && u.len() <= 2048
        });
        let shape_ok = match field.take {
            SchemaTake::Text => value.texts.is_none() && value.url.is_none(),
            SchemaTake::Texts => value.text.is_none() && value.url.is_none(),
            SchemaTake::Url => value.text.is_none() && value.texts.is_none(),
        };
        if value.key != field.key || !text_ok || !texts_ok || !url_ok || !shape_ok {
            return Err(protocol_violation());
        }
    }
    Ok(())
}

fn bounded_text(text: &str, max: usize) -> bool {
    !text.is_empty() && text.len() <= max && !text.chars().any(char::is_control)
}

/// Check a schema the way the worker does, before anything is sent.
pub fn validate_schema(fields: &[SchemaField]) -> Result<(), HostError> {
    let invalid = |why: &str| Err(HostError::Invalid(format!("schema extraction: {why}")));
    if fields.is_empty() || fields.len() > MAX_SCHEMA_FIELDS {
        return invalid("between 1 and 32 fields");
    }
    let mut keys = std::collections::BTreeSet::new();
    for field in fields {
        let key_ok = field.key.len() <= 40
            && field
                .key
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_lowercase())
            && field
                .key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !key_ok || !keys.insert(field.key.as_str()) {
            return invalid("keys are short lowercase identifiers, each once");
        }
        match (&field.role, &field.name, &field.xpath) {
            (None, None, Some(xpath)) => {
                let ok = xpath.starts_with('/')
                    && xpath.len() <= MAX_OUTLINE_XPATH_BYTES
                    && xpath
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "_-/[]():.*=' ".contains(c));
                if !ok {
                    return invalid("an XPath is an outline element path");
                }
            }
            (Some(role), name, None) => {
                if !role_ok(role) {
                    return invalid("a role is a short role name");
                }
                if let Some(name) = name {
                    if !bounded_text(name, MAX_OUTLINE_NAME_BYTES) {
                        return invalid("a name is bounded text");
                    }
                }
            }
            _ => return invalid("each field has one target: a role (and name) or an XPath"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_capabilities_are_denied_by_default_with_their_amendment() {
        for (capability, grain) in [
            (WorkerCapability::Outline, "SG-000076"),
            (WorkerCapability::SchemaExtract, "SG-000133"),
        ] {
            assert!(!admitted(capability));
            match admit(capability) {
                Err(HostError::Invalid(why)) => {
                    assert!(why.contains("denied by default"), "{why}");
                    assert!(why.contains(grain), "{why}");
                }
                other => panic!("not denied: {other:?}"),
            }
        }
    }

    #[test]
    fn outline_nodes_carry_no_value_and_no_unknown_field() {
        let node: OutlineNode = serde_json::from_str(
            r#"{"id":"0-5","role":"heading","name":"Fees","xpath":"/html[1]/body[1]/h1[1]","children":[{"id":"0-7","role":"link","name":"Pay","xpath":"/html[1]/body[1]/a[1]","url":"https://fixture.test/pay","children":[]}]}"#,
        )
        .unwrap();
        assert_eq!(
            node.children[0].url.as_deref(),
            Some("https://fixture.test/pay")
        );
        for bad in [
            r#"{"id":"0-1","role":"textbox","name":"","xpath":"/x","value":"hunter2","children":[]}"#,
            r#"{"id":"0-1","role":"textbox","name":"","xpath":"/x","description":"d","children":[]}"#,
            r#"{"id":"0-1","role":"heading","name":"x","children":[]}"#,
        ] {
            assert!(serde_json::from_str::<OutlineNode>(bad).is_err(), "{bad}");
        }
        assert!(serde_json::from_str::<SchemaValue>(
            r#"{"key":"k","found":true,"text":"t","html":"<b>"}"#
        )
        .is_err());
    }

    #[test]
    fn schemas_are_checked_like_the_worker_checks_them() {
        let field =
            |key: &str, role: Option<&str>, name: Option<&str>, xpath: Option<&str>| SchemaField {
                key: key.into(),
                take: SchemaTake::Text,
                role: role.map(Into::into),
                name: name.map(Into::into),
                xpath: xpath.map(Into::into),
            };
        assert!(validate_schema(&[
            field("title", Some("heading"), None, None),
            field("fee", Some("heading"), Some("Fees & passes"), None),
            field("rows", None, None, Some("/html[1]/body[1]/ul[1]")),
        ])
        .is_ok());
        for bad in [
            vec![],
            vec![field("Title", Some("heading"), None, None)],
            vec![
                field("a", Some("heading"), None, None),
                field("a", Some("heading"), None, None),
            ],
            vec![field("a", None, None, None)],
            vec![field("a", Some("heading"), None, Some("/html[1]"))],
            vec![field("a", None, None, Some("//*[@id='x']"))],
            vec![field("a", Some("heading<script>"), None, None)],
            vec![field("a", Some("heading"), Some("line\nbreak"), None)],
            vec![field("a", Some("heading"), Some(""), None)],
        ] {
            assert!(validate_schema(&bad).is_err(), "{bad:?}");
        }
        let many: Vec<_> = (0..33)
            .map(|i| field(&format!("k{i}"), Some("heading"), None, None))
            .collect();
        assert!(validate_schema(&many).is_err());
    }

    #[test]
    fn worker_replies_are_rechecked_against_the_bounds() {
        let node = |id: &str, name: &str, url: Option<&str>| OutlineNode {
            id: id.into(),
            role: "link".into(),
            name: name.into(),
            xpath: "/html[1]/body[1]/a[1]".into(),
            url: url.map(Into::into),
            children: Vec::new(),
        };
        assert!(check_outline(&[node("0-7", "Pay", Some("https://fixture.test/pay"))]).is_ok());
        assert!(check_outline(&[node("", "", None)]).is_ok());
        for bad in [
            node("e7", "Pay", None),
            node("0-", "Pay", None),
            node("0-7", "a\u{7}b", None),
            node("0-7", &"x".repeat(MAX_OUTLINE_NAME_BYTES + 1), None),
            node("0-7", "Pay", Some("javascript:alert(1)")),
        ] {
            assert!(
                check_outline(std::slice::from_ref(&bad)).is_err(),
                "{bad:?}"
            );
        }
        let wide: Vec<_> = (0..=MAX_OUTLINE_NODES)
            .map(|i| node(&format!("0-{i}"), "", None))
            .collect();
        assert!(check_outline(&wide).is_err());
        // Roles follow the worker's pattern.
        for role in [
            "heading<script>",
            "1st",
            " lead",
            "x\u{202e}y",
            &"x".repeat(49),
        ] {
            let mut bad = node("0-7", "Pay", None);
            bad.role = role.to_owned();
            assert!(check_outline(std::slice::from_ref(&bad)).is_err(), "{role}");
        }
        let mut decorated = node("0-7", "Pay", None);
        decorated.role = "scrollable, div".into();
        assert!(check_outline(std::slice::from_ref(&decorated)).is_ok());
        // Depth 32 (levels 0..=32) is the worker's bound; one more is refused.
        let chain = |levels: usize| {
            let mut top = node("0-1", "", None);
            for _ in 0..levels {
                let mut parent = node("0-1", "", None);
                parent.children.push(top);
                top = parent;
            }
            top
        };
        assert!(check_outline(&[chain(MAX_OUTLINE_DEPTH)]).is_ok());
        assert!(check_outline(&[chain(MAX_OUTLINE_DEPTH + 1)]).is_err());

        let fields = [
            SchemaField {
                key: "title".into(),
                take: SchemaTake::Text,
                role: Some("heading".into()),
                name: None,
                xpath: None,
            },
            SchemaField {
                key: "rows".into(),
                take: SchemaTake::Texts,
                role: Some("listitem".into()),
                name: None,
                xpath: None,
            },
        ];
        let value = |key: &str, text: Option<&str>, texts: Option<Vec<&str>>| SchemaValue {
            key: key.into(),
            found: text.is_some() || texts.is_some(),
            text: text.map(Into::into),
            texts: texts.map(|t| t.into_iter().map(Into::into).collect()),
            url: None,
        };
        assert!(check_values(
            &fields,
            &[
                value("title", Some("Fees"), None),
                value("rows", None, Some(vec!["a", "b"]))
            ]
        )
        .is_ok());
        assert!(check_values(&fields, &[value("title", Some("Fees"), None)]).is_err());
        assert!(check_values(
            &fields,
            &[value("rows", None, None), value("title", None, None)]
        )
        .is_err());
        assert!(check_values(
            &fields,
            &[
                value("title", None, Some(vec!["a"])),
                value("rows", None, None)
            ]
        )
        .is_err());
        let long: Vec<&str> = vec!["x"; MAX_SCHEMA_LIST_ITEMS + 1];
        assert!(check_values(
            &fields,
            &[value("title", None, None), value("rows", None, Some(long))]
        )
        .is_err());
    }
}
