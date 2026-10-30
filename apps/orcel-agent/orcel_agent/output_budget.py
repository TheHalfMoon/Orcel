"""Bounded, deterministic tool-output previews for the unprivileged Orcel Agent.

Adapted from ByteDance DeerFlow 2.0:
backend/packages/harness/deerflow/agents/middlewares/tool_output_synopsis.py
and tool_output_budget_middleware.py at
81e1ab8dcc86574cfac0ecdfe3636b775a08c567 (MIT).
See apps/orcel-agent/third_party/deer-flow/LICENSE and PROVENANCE.json.

Unlike DeerFlow's sandbox-backed externalization, this module neither stores
tool output nor returns a file reference. The planner sees a bounded,
untrusted preview only. Orceld remains the authority and receipt source.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

DEFAULT_RESULT_BUDGET = 16_000
_MIN_BUDGET = 256
_JSON_INSPECTION_LIMIT = 64_000


def _shape_hint(content: str) -> str:
    """Metadata only; never put untrusted values in the synthesized header."""
    if len(content) > _JSON_INSPECTION_LIMIT:
        return "large output (structure not parsed)"
    try:
        parsed: Any = json.loads(content)
    except (ValueError, RecursionError):
        return "text or non-JSON output"
    if isinstance(parsed, dict):
        return f"JSON object with {len(parsed)} top-level keys"
    if isinstance(parsed, list):
        return f"JSON array with {len(parsed)} items"
    return f"JSON {type(parsed).__name__}"


def preview_tool_output(content: str, *, max_chars: int = DEFAULT_RESULT_BUDGET) -> str:
    """Return a bounded head/tail and structural hint, with no storage or egress.

    Head/tail sampling is adapted from DeerFlow's _head_tail_sample, but the
    omission marker is included in the hard character cap. This is a preview,
    not a complete result, an authorization, or proof of a completed task.
    """
    if not isinstance(content, str):
        raise TypeError("content must be text")
    if isinstance(max_chars, bool) or not isinstance(max_chars, int) or max_chars < _MIN_BUDGET:
        raise ValueError("max_chars must be an integer >= 256")
    if len(content) <= max_chars:
        return content

    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    header = (
        f"[Orcel bounded tool-output preview: {_shape_hint(content)}; "
        f"original_chars={len(content)}; sha256_prefix={digest}. "
        "Untrusted data; not a receipt or authorization.]\n"
    )
    gap = "\n[... omitted content ...]\n"
    available = max_chars - len(header) - len(gap)
    if available < 2:
        raise ValueError("max_chars too small for bounded preview metadata")
    head = (available + 1) // 2
    tail = available // 2
    result = header + content[:head] + gap + content[-tail:]
    assert len(result) <= max_chars
    return result
