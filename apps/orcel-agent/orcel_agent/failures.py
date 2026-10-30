"""SG-000129 M3 slice 4a2: what a failed call means, told to the model.

orceld answers a refused or failed call with a typed code
(`crates/orcel-contracts/src/lib.rs`, FailureCode). The model sees the code and
static Orcel guidance for it, never the error message: that text comes from
the call's target and is untrusted. An unknown or malformed code is shown as
INTERNAL_ERROR.

The guidance never widens anything. A refusal stays final for that exact call
(the gate enforces it); the text only steers the model toward observing
again, choosing a different read, or finishing.

Design reference, no code copied: DeerFlow's tool-error handling turns a
failed tool into an error-status tool message with a recovery hint.
"""

from __future__ import annotations

import re

from .journal import OUTCOME_UNKNOWN

_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")

_FINAL = "Orcel refused this exact call, and it will not be retried. "

#: orceld's FailureCode values -> static guidance. Keep in step with the enum.
GUIDANCE: dict[str, str] = {
    "INVALID_REQUEST": _FINAL + "Check the tool's arguments against its schema before trying a different call.",
    "CAPABILITY_DENIED": _FINAL + "This operation is not allowed here. Choose another read-only approach or finish.",
    "WORKSPACE_DENIED": _FINAL + "The workspace is not trusted for this call. Do not try other workspaces to get around it.",
    "PATH_ESCAPE": _FINAL + "The path leaves the workspace. Use a path inside the workspace.",
    "PATH_RACE_DETECTED": _FINAL + "The path changed while it was being checked. Observe it again before relying on it.",
    "APPROVAL_REQUIRED": _FINAL + "This needs a person's approval, which this agent does not request on its own.",
    "APPROVAL_DENIED": "The person denied approval. The run stops; do not ask again.",
    "APPROVAL_UNAVAILABLE": "No approval could be obtained. The run stops; do not ask again.",
    "TARGET_STALE": _FINAL + "What you acted on has changed. Observe again before relying on it.",
    "PROVIDER_UNAVAILABLE": _FINAL + "This capability is not available on this device. Choose another approach or finish.",
    "PROCESS_TIMEOUT": _FINAL + "The operation timed out. Do not assume it did or did not take effect.",
    "PROCESS_TERMINATION_UNVERIFIED": _FINAL + "Orcel could not verify that the operation stopped. Do not assume its effects.",
    "OUTPUT_LIMIT": _FINAL + "The result was too large. Ask for a smaller range or fewer results.",
    "POSTCONDITION_FAILED": _FINAL + "Orcel could not verify the expected result. Observe again before relying on it.",
    "INTERNAL_ERROR": _FINAL + "Orcel failed internally. Choose another approach or finish.",
    "REMOTE_SESSION_INACTIVE": _FINAL + "There is no active remote session for this call.",
}

UNKNOWN_OUTCOME_TEXT = (
    f"{OUTCOME_UNKNOWN}: this call may or may not have happened. Do not assume it succeeded or failed; "
    "observe again before relying on it."
)


def failure_code(code: object) -> str:
    """A code the model may see: a known FailureCode, OUTCOME_UNKNOWN, or
    INTERNAL_ERROR for anything else."""
    if code == OUTCOME_UNKNOWN:
        return OUTCOME_UNKNOWN
    if isinstance(code, str) and _CODE.match(code) and code in GUIDANCE:
        return code
    return "INTERNAL_ERROR"


def failure_text(code: object) -> str:
    """The model-facing text for a failed or uncertain call."""
    known = failure_code(code)
    if known == OUTCOME_UNKNOWN:
        return UNKNOWN_OUTCOME_TEXT
    return f"REFUSED: {known}. {GUIDANCE[known]}"
