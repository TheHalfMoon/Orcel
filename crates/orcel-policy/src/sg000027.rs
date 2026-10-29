#[path = "sg000026.rs"]
mod sg000026_legacy;

pub use orcel_approval::ApprovalClass;
pub use sg000026_legacy::{
    validate_relative_target, FetchDestination, PolicyDecision, PolicyError, PushDestination,
    Workspace,
};

use orcel_contracts::{FailureCode, RequestEnvelope};
use serde_json::Value;

pub const POLICY_REVISION: &str = "sg-000027-v1";

#[derive(Debug, Clone)]
pub struct PolicyEngine {
    legacy: sg000026_legacy::PolicyEngine,
}

impl PolicyEngine {
    pub fn new(workspaces: Vec<Workspace>) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000026_legacy::PolicyEngine::new(workspaces)?,
        })
    }

    pub fn with_destinations(
        workspaces: Vec<Workspace>,
        fetch_destinations: Vec<FetchDestination>,
        push_destinations: Vec<PushDestination>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            legacy: sg000026_legacy::PolicyEngine::with_destinations(
                workspaces,
                fetch_destinations,
                push_destinations,
            )?,
        })
    }

    pub fn workspace(&self, id: &str) -> Option<&Workspace> {
        self.legacy.workspace(id)
    }

    pub fn fetch_destination(
        &self,
        workspace_id: &str,
        policy_id: &str,
    ) -> Option<&FetchDestination> {
        self.legacy.fetch_destination(workspace_id, policy_id)
    }

    pub fn push_destination(
        &self,
        workspace_id: &str,
        policy_id: &str,
    ) -> Option<&PushDestination> {
        self.legacy.push_destination(workspace_id, policy_id)
    }

    /// Authorize one request. UIA observation shapes are validated here so
    /// the UIA registry can never be reached through a predecessor engine.
    /// Every other shape retains its SG-000026 validation and every
    /// remaining shape falls through unchanged.
    pub fn authorize(&self, request: &RequestEnvelope) -> Result<PolicyDecision, PolicyError> {
        if is_uia_shape(request) {
            self.validate_uia_shape(request)?;
            let workspace = self
                .legacy
                .workspace(&request.workspace_id)
                .ok_or_else(|| {
                    policy_error(
                        FailureCode::WorkspaceDenied,
                        "requested workspace is not configured",
                    )
                })?;
            return Ok(PolicyDecision {
                workspace: workspace.clone(),
                policy_revision: POLICY_REVISION,
            });
        }
        if orcel_provider_uia::is_denied_uia_shape(&request.capability, &request.operation) {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "capability/operation is denied by {POLICY_REVISION}: {}/{}; SG-000027 authorizes only uia.process/observe, uia.window/list, uia.window/observe, uia.tree/observe, and uia.element/observe as read-only observation, and invoke, click, value setting, select, toggle, scroll, focus, keyboard, mouse, SendInput, coordinates, screenshots, clipboard, network, and elevation remain absent",
                    request.capability, request.operation
                ),
            ));
        }
        let decision = self.legacy.authorize(request)?;
        Ok(PolicyDecision {
            workspace: decision.workspace,
            policy_revision: POLICY_REVISION,
        })
    }
}

pub fn approval_class_for(capability: &str, operation: &str) -> ApprovalClass {
    if orcel_provider_uia::is_allowed_uia_shape(capability, operation) {
        return ApprovalClass::Soft;
    }
    if orcel_provider_uia::is_denied_uia_shape(capability, operation) {
        return ApprovalClass::Strong;
    }
    sg000026_legacy::approval_class_for(capability, operation)
}

fn is_uia_shape(request: &RequestEnvelope) -> bool {
    is_uia_shape_str(&request.capability, &request.operation)
}

fn is_uia_shape_str(capability: &str, operation: &str) -> bool {
    orcel_provider_uia::is_allowed_uia_shape(capability, operation)
}

/// Fields that would widen UIA observation into actuation, synthetic input,
/// unrestricted introspection, or secret access. None of them is accepted by
/// any UIA shape; in particular no caller-supplied PID, HWND, runtime id,
/// selector, coordinate, approval material, or secret field is accepted, so
/// callers can only name server-allocated typed identities.
const UIA_WIDENING_FIELDS: &[&str] = &[
    "pid",
    "process_handle",
    "hwnd",
    "handle",
    "window_handle",
    "runtime_id",
    "runtime",
    "selector",
    "xpath",
    "coordinate",
    "coordinates",
    "x",
    "y",
    "point",
    "rect",
    "invoke",
    "click",
    "value",
    "set_value",
    "text",
    "keys",
    "select",
    "toggle",
    "scroll",
    "focus",
    "keyboard",
    "mouse",
    "sendinput",
    "synthetic",
    "screenshot",
    "frame",
    "clipboard",
    "password",
    "passwords",
    "secret",
    "secrets",
    "token",
    "tokens",
    "credentials",
    "cookies",
    "session",
    "approval",
    "approval_id",
    "nonce",
    "digest",
    "path",
    "file",
    "executable",
    "script",
    "command",
    "argv",
    "elevate",
    "elevation",
    "admin",
    "com_object",
    "pattern_invoke",
    "process_command",
];

impl PolicyEngine {
    /// Validate one UIA observation shape. This layer is pure policy: it
    /// performs no OS access and no mutation, and it accepts no widening
    /// field of any kind.
    fn validate_uia_shape(&self, request: &RequestEnvelope) -> Result<(), PolicyError> {
        if request.version != orcel_contracts::INTERNAL_PROTOCOL_VERSION {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "unsupported internal protocol version",
            ));
        }
        if self.legacy.workspace(&request.workspace_id).is_none() {
            return Err(policy_error(
                FailureCode::WorkspaceDenied,
                "requested workspace is not configured",
            ));
        }
        if request.target.is_some() {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                "uia observation shapes do not accept a target field",
            ));
        }
        let arguments = request.arguments.as_object().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                "uia arguments must be an object",
            )
        })?;
        let shape = format!("{}/{}", request.capability, request.operation);
        if let Some(key) = arguments
            .keys()
            .find(|key| UIA_WIDENING_FIELDS.contains(&key.as_str()))
        {
            return Err(policy_error(
                FailureCode::CapabilityDenied,
                format!(
                    "uia observation request must not carry authority-widening field: {key}; only server-allocated typed identities and expected generations are accepted"
                ),
            ));
        }
        let allowed: &[&str] = match request.operation.as_str() {
            "list" => {
                if request.capability.as_str() != "uia.window" {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        format!("{shape} is not an authorized uia verb"),
                    ));
                }
                &[]
            }
            "observe" => match request.capability.as_str() {
                "uia.process" => {
                    validate_process_observe_arguments(&shape, arguments)?;
                    &["process_id", "expected_process_generation"]
                }
                "uia.window" => {
                    validate_window_observe_arguments(&shape, arguments)?;
                    &["window_id", "expected_window_generation"]
                }
                "uia.tree" => {
                    validate_tree_observe_arguments(&shape, arguments)?;
                    &[
                        "window_id",
                        "expected_window_generation",
                        "max_depth",
                        "max_nodes",
                        // SG-000128: an optional scoped root, both or neither.
                        "root_element_id",
                        "expected_tree_generation",
                    ]
                }
                "uia.element" => {
                    validate_element_observe_arguments(&shape, arguments)?;
                    &["element_id", "expected_tree_generation"]
                }
                _ => {
                    return Err(policy_error(
                        FailureCode::CapabilityDenied,
                        format!("{shape} is not an authorized uia verb"),
                    ))
                }
            },
            _ => {
                return Err(policy_error(
                    FailureCode::CapabilityDenied,
                    format!("{shape} is not an authorized uia verb"),
                ))
            }
        };
        if let Some(key) = arguments
            .keys()
            .find(|key| !allowed.contains(&key.as_str()))
        {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} does not accept argument field: {key}"),
            ));
        }
        Ok(())
    }
}

fn validate_process_observe_arguments(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), PolicyError> {
    let process_id = required_shape_string(shape, arguments, "process_id")?;
    if !orcel_provider_uia::is_well_formed_process_id(process_id) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} process_id is malformed"),
        ));
    }
    required_shape_u64(shape, arguments, "expected_process_generation")?;
    Ok(())
}

fn validate_window_observe_arguments(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), PolicyError> {
    let window_id = required_shape_string(shape, arguments, "window_id")?;
    if !orcel_provider_uia::is_well_formed_window_id(window_id) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} window_id is malformed"),
        ));
    }
    required_shape_u64(shape, arguments, "expected_window_generation")?;
    Ok(())
}

fn validate_tree_observe_arguments(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), PolicyError> {
    let window_id = required_shape_string(shape, arguments, "window_id")?;
    if !orcel_provider_uia::is_well_formed_window_id(window_id) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} window_id is malformed"),
        ));
    }
    required_shape_u64(shape, arguments, "expected_window_generation")?;
    if let Some(value) = arguments.get("max_depth") {
        value.as_u64().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} requires arguments.max_depth as an unsigned integer"),
            )
        })?;
    }
    if let Some(value) = arguments.get("max_nodes") {
        value.as_u64().ok_or_else(|| {
            policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} requires arguments.max_nodes as an unsigned integer"),
            )
        })?;
    }
    // SG-000128: a scoped root is an element id orceld issued, with the tree
    // generation it belongs to; both or neither.
    match (
        arguments.get("root_element_id"),
        arguments.get("expected_tree_generation"),
    ) {
        (None, None) => {}
        (Some(root), Some(generation)) => {
            let root = root.as_str().ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.root_element_id as a string"),
                )
            })?;
            if !orcel_provider_uia::is_well_formed_element_id(root) {
                return Err(policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} root_element_id is malformed"),
                ));
            }
            generation.as_u64().ok_or_else(|| {
                policy_error(
                    FailureCode::InvalidRequest,
                    format!("{shape} requires arguments.expected_tree_generation as an unsigned integer"),
                )
            })?;
        }
        _ => {
            return Err(policy_error(
                FailureCode::InvalidRequest,
                format!("{shape} root_element_id and expected_tree_generation go together"),
            ));
        }
    }
    Ok(())
}

fn validate_element_observe_arguments(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
) -> Result<(), PolicyError> {
    let element_id = required_shape_string(shape, arguments, "element_id")?;
    if !orcel_provider_uia::is_well_formed_element_id(element_id) {
        return Err(policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} element_id is malformed"),
        ));
    }
    required_shape_u64(shape, arguments, "expected_tree_generation")?;
    Ok(())
}

fn required_shape_string<'a>(
    shape: &str,
    arguments: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, PolicyError> {
    arguments.get(name).and_then(Value::as_str).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} requires arguments.{name} as a string"),
        )
    })
}

fn required_shape_u64(
    shape: &str,
    arguments: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<u64, PolicyError> {
    arguments.get(name).and_then(Value::as_u64).ok_or_else(|| {
        policy_error(
            FailureCode::InvalidRequest,
            format!("{shape} requires arguments.{name} as an unsigned integer"),
        )
    })
}

fn policy_error(code: FailureCode, message: impl Into<String>) -> PolicyError {
    PolicyError {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod sg000128_tree_argument_tests {
    use super::*;
    use serde_json::json;

    fn check(arguments: Value) -> Result<(), PolicyError> {
        validate_tree_observe_arguments("uia.tree/observe", arguments.as_object().expect("object"))
    }

    fn window_id() -> String {
        format!("{}{}", orcel_provider_uia::WINDOW_ID_PREFIX, "a".repeat(16))
    }

    fn element_id() -> String {
        format!(
            "{}{}",
            orcel_provider_uia::ELEMENT_ID_PREFIX,
            "b".repeat(16)
        )
    }

    #[test]
    fn the_unscoped_shape_is_unchanged() {
        assert!(check(json!({"window_id": window_id(), "expected_window_generation": 3})).is_ok());
        assert!(check(json!({"window_id": window_id(), "expected_window_generation": 3, "max_depth": 4, "max_nodes": 9})).is_ok());
    }

    #[test]
    fn a_scoped_root_needs_both_arguments_well_formed() {
        assert!(check(
            json!({"window_id": window_id(), "expected_window_generation": 3,
            "root_element_id": element_id(), "expected_tree_generation": 5})
        )
        .is_ok());
        for broken in [
            json!({"window_id": window_id(), "expected_window_generation": 3, "root_element_id": element_id()}),
            json!({"window_id": window_id(), "expected_window_generation": 3, "expected_tree_generation": 5}),
            json!({"window_id": window_id(), "expected_window_generation": 3, "root_element_id": "not an id", "expected_tree_generation": 5}),
            json!({"window_id": window_id(), "expected_window_generation": 3, "root_element_id": 7, "expected_tree_generation": 5}),
            json!({"window_id": window_id(), "expected_window_generation": 3, "root_element_id": element_id(), "expected_tree_generation": "5"}),
        ] {
            assert_eq!(check(broken).unwrap_err().code, FailureCode::InvalidRequest);
        }
    }
}
