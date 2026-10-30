"""Loop detection for the Orcel Agent (SG-000129 slice 3).

Adapted from bytedance/deer-flow,
backend/packages/harness/deerflow/agents/middlewares/loop_detection_middleware.py
at commit 81e1ab8dcc86574cfac0ecdfe3636b775a08c567 (blob
3cdf40ea178b80f0bfde7d5f2233463dc2faa0ad). Copyright (c) 2025 Bytedance Ltd.
and/or its affiliates; Copyright (c) 2025-2026 DeerFlow Authors. MIT License:
see third_party/deer-flow/LICENSE. Ledger: third_party/PROVENANCE.json.

Copied unchanged in logic: argument normalisation, the read-range window, the
per-tool call key, the order-independent call-set hash, the two detection
layers (identical call sets in a sliding window; per-tool frequency in a
window sized to the largest hard limit, with decay and re-arming), the
warn-once rule and the decision record.

Changed for Orcel:
- DeerFlow's tool names map to the Orcel edge's: `read_file` to `fs_read` and
  `fs_read_range` (whose `max_lines` becomes the window's end line);
  `write_file`/`str_replace` to `fs_write`/`fs_edit`; the narration-stripped
  `bash`/`ls`/`glob`/`grep` to `fs_list`/`fs_find`/`fs_search`.
- One detector serves one agent run, so the LangGraph runtime, thread/run
  scoping, LRU eviction, fallback run ids and the lock are dropped.
- The AgentMiddleware hooks are replaced: `ChatModelPlanner` calls `track()`
  on each proposal, appends queued warnings to the next model call (after
  the tool messages, as DeerFlow does) and turns a hard stop into a finish.
- The wrap-up text no longer asks the agent to write files (it is read-only).
- Decisions go to the agent's own event log instead of DeerFlow's audit
  context and run-event catalogue; logging is dropped.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Literal, Optional

# Defaults (DeerFlow's)
DEFAULT_WARN_THRESHOLD = 3  # warn after 3 identical calls
DEFAULT_HARD_LIMIT = 5  # force-stop after 5 identical calls
DEFAULT_WINDOW_SIZE = 20  # track the last N tool calls
DEFAULT_TOOL_FREQ_WARN = 30  # warn after 30 calls to the same tool
DEFAULT_TOOL_FREQ_HARD_LIMIT = 50  # force-stop after 50 calls to the same tool
MAX_PENDING_WARNINGS = 4
# Stands in for an omitted end line in a read's key: the read runs to the last
# line, which is not the same window as any numbered bound.
_OPEN_ENDED_READ = "end"

#: DeerFlow `read_file` -> the Orcel reads.
_READ_TOOLS = frozenset({"fs_read", "fs_read_range"})
#: DeerFlow `write_file`/`str_replace` -> the Orcel content-changing tools
#: (never on the read-only allowlist; kept so the rule stays meaningful).
_CONTENT_TOOLS = frozenset({"fs_write", "fs_edit"})
#: DeerFlow's narration-stripped sandbox tools -> their Orcel counterparts.
_UI_NARRATION_TOOLS = frozenset({"fs_list", "fs_find", "fs_search"})


def _normalize_tool_call_args(raw_args: object) -> tuple[dict, Optional[str]]:
    """Normalize tool call args to a dict plus an optional fallback key.

    Some providers serialize ``args`` as a JSON string instead of a dict.
    Those are parsed defensively so loop detection does not crash, while a
    stable fallback key is kept for non-dict payloads.
    """
    if isinstance(raw_args, dict):
        return raw_args, None

    if isinstance(raw_args, str):
        try:
            parsed = json.loads(raw_args)
        except (TypeError, ValueError, json.JSONDecodeError):
            return {}, raw_args

        if isinstance(parsed, dict):
            return parsed, None
        return {}, json.dumps(parsed, sort_keys=True, default=str)

    if raw_args is None:
        return {}, None

    return {}, json.dumps(raw_args, sort_keys=True, default=str)


def _coerce_line_number(value: object) -> Optional[int]:
    """Parse one line bound, or ``None`` when absent or unusable."""
    try:
        line = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        # OverflowError: a JSON number such as 1e999 parses to float('inf'),
        # which int() rejects; treat it like any other unusable bound.
        return None
    return max(line, 1)


def _orcel_read_bounds(name: str, args: dict) -> dict:
    """Orcel's reads in DeerFlow's terms: `fs_read` reads the whole file;
    `fs_read_range` reads `max_lines` lines from `start_line`."""
    if name == "fs_read":
        return {"start_line": None, "end_line": None}
    start = _coerce_line_number(args.get("start_line"))
    count = _coerce_line_number(args.get("max_lines"))
    end = None if count is None else (start or 1) + count - 1
    return {"start_line": start, "end_line": end}


def _normalized_read_range(args: dict) -> tuple[int, Optional[int]]:
    """Normalize a read's line range into one comparable window.

    An omitted end reads through the last line, so it normalizes to ``None``
    (open-ended) rather than collapsing onto the start. A reversed range is
    ordered. The window is otherwise kept exact: quantizing it collapsed
    distinct pages of one file onto a single key, so paging tripped the hard
    stop; an exact window still catches the same read emitted over and over,
    and a loop that jitters its bounds is what the per-tool frequency layer
    covers.
    """
    start_line = _coerce_line_number(args.get("start_line"))
    end_line = _coerce_line_number(args.get("end_line"))
    if start_line is None:
        start_line = 1
    if end_line is not None and end_line < start_line:
        start_line, end_line = end_line, start_line
    return start_line, end_line


def _stable_tool_key(name: str, args: dict, fallback_key: Optional[str]) -> str:
    """Derive a stable key from the args that change what a call does."""
    if name in _READ_TOOLS and fallback_key is None:
        path = args.get("path") or ""
        start_line, end_line = _normalized_read_range(_orcel_read_bounds(name, args))
        return f"{path}:{start_line}-{end_line if end_line is not None else _OPEN_ENDED_READ}"

    # Content-changing tools are content-sensitive: the same path may be
    # updated with different payloads, so the full args are hashed.
    if name in _CONTENT_TOOLS:
        if fallback_key is not None:
            return fallback_key
        return json.dumps(args, sort_keys=True, default=str)

    if fallback_key is not None:
        return fallback_key

    # Every other argument can change what the call does (paging, cursors,
    # patterns); only a narration field is dropped, so rewording it cannot
    # make a repeated call look new.
    if name in _UI_NARRATION_TOOLS:
        args = {key: value for key, value in args.items() if key != "description"}
    return json.dumps(args, sort_keys=True, default=str)


def _hash_tool_calls(tool_calls: list[dict]) -> str:
    """Deterministic, order-independent hash of a set of tool calls."""
    normalized: list[str] = []
    for tc in tool_calls:
        name = tc.get("name", "")
        args, fallback_key = _normalize_tool_call_args(tc.get("args", {}))
        key = _stable_tool_key(name, args, fallback_key)
        normalized.append(f"{name}:{key}")
    normalized.sort()
    blob = json.dumps(normalized, sort_keys=True, default=str)
    return hashlib.md5(blob.encode(), usedforsecurity=False).hexdigest()[:12]


_WRAP_UP_INSTRUCTIONS = (
    "Stop calling tools and produce your final answer with the results collected so far. "
    "If you cannot complete the task, summarize what you accomplished so far."
)

WARNING_MSG = "[LOOP DETECTED] You are repeating the same tool calls. Stop repeating them and wrap up now. " + _WRAP_UP_INSTRUCTIONS

TOOL_FREQ_WARNING_MSG = (
    "[LOOP DETECTED] You have called {tool_name} {count} times without producing a final answer. "
    "Stop calling {tool_name} and wrap up now. " + _WRAP_UP_INSTRUCTIONS
)

HARD_STOP_MSG = "[FORCED STOP] Repeated tool calls exceeded the safety limit. Producing final answer with results collected so far."

TOOL_FREQ_HARD_STOP_MSG = (
    "[FORCED STOP] Tool {tool_name} called {count} times — exceeded the per-tool safety limit. "
    "Producing final answer with results collected so far."
)


@dataclass(frozen=True)
class LoopDecision:
    """A loop-detection transition, recorded for audit."""

    message: str
    action: Literal["warn", "hard_stop"]
    detection_layer: Literal["identical_call_set", "tool_frequency"]
    tool_names: tuple[str, ...]
    count: int
    threshold: int

    @property
    def hard_stop(self) -> bool:
        return self.action == "hard_stop"


@dataclass
class LoopDetector:
    """Both detection layers for one agent run."""

    warn_threshold: int = DEFAULT_WARN_THRESHOLD
    hard_limit: int = DEFAULT_HARD_LIMIT
    window_size: int = DEFAULT_WINDOW_SIZE
    tool_freq_warn: int = DEFAULT_TOOL_FREQ_WARN
    tool_freq_hard_limit: int = DEFAULT_TOOL_FREQ_HARD_LIMIT
    tool_freq_overrides: dict[str, tuple[int, int]] = field(default_factory=dict)
    decisions: list[LoopDecision] = field(default_factory=list)
    _history: list[str] = field(default_factory=list)
    _warned: set[str] = field(default_factory=set)
    _tool_name_history: deque = field(default_factory=deque)
    _tool_name_counter: Counter = field(default_factory=Counter)
    _tool_freq_warned: set[str] = field(default_factory=set)
    _pending: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._default_tool_freq_thresholds = (self.tool_freq_warn, self.tool_freq_hard_limit)
        # The frequency count can never exceed the window, so the window must
        # be at least as long as the largest hard limit it is compared with.
        self._tool_freq_window = max(
            self.window_size,
            self.tool_freq_hard_limit,
            *(hard for _, hard in self.tool_freq_overrides.values()),
        )

    def track(self, tool_calls: list[dict]) -> Optional[LoopDecision]:
        """Track one model reply's tool calls; return a warning or hard stop.

        Layer 1 (hash) catches identical call sets; layer 2 (frequency)
        catches the same tool called many times with varying arguments.
        """
        if not tool_calls:
            return None
        decision = self._track(tool_calls)
        if decision is not None:
            self.decisions.append(decision)
            if not decision.hard_stop and len(self._pending) < MAX_PENDING_WARNINGS:
                self._pending.append(decision.message)
        return decision

    def drain_warnings(self) -> list[str]:
        """Warnings queued for the next model call (then cleared)."""
        pending, self._pending = self._pending, []
        return pending

    def _track(self, tool_calls: list[dict]) -> Optional[LoopDecision]:
        call_hash = _hash_tool_calls(tool_calls)
        history = self._history
        history.append(call_hash)
        if len(history) > self.window_size:
            history[:] = history[-self.window_size:]
        self._warned.intersection_update(history)

        count = history.count(call_hash)
        tool_names = [str(tc.get("name") or "?") for tc in tool_calls]

        # Layer 1: identical call sets.
        if count >= self.hard_limit:
            return LoopDecision(HARD_STOP_MSG, "hard_stop", "identical_call_set", tuple(tool_names), count,
                                self.hard_limit)

        # A warning admits the whole batch, so frequency accounting still runs
        # and a later hard limit still wins; hash warnings keep priority.
        warning: Optional[LoopDecision] = None
        if count >= self.warn_threshold and call_hash not in self._warned:
            warning = LoopDecision(WARNING_MSG, "warn", "identical_call_set", tuple(tool_names), count,
                                   self.warn_threshold)

        # Layer 2: per-tool frequency, windowed.
        for tc in tool_calls:
            name = tc.get("name", "")
            if not name:
                continue
            self._tool_name_history.append(name)
            self._tool_name_counter[name] += 1
            while len(self._tool_name_history) > self._tool_freq_window:
                old = self._tool_name_history.popleft()
                remaining = self._tool_name_counter[old] - 1
                if remaining <= 0:
                    del self._tool_name_counter[old]
                else:
                    self._tool_name_counter[old] = remaining
                old_warn = self.tool_freq_overrides.get(old, self._default_tool_freq_thresholds)[0]
                if remaining < old_warn:
                    # Any tool can evict an older name: re-arm it once its
                    # burst decays, even when the current call is another tool.
                    self._tool_freq_warned.discard(old)
            freq_count = self._tool_name_counter.get(name, 0)
            eff_warn, eff_hard = self.tool_freq_overrides.get(name, self._default_tool_freq_thresholds)

            if freq_count >= eff_hard:
                return LoopDecision(TOOL_FREQ_HARD_STOP_MSG.format(tool_name=name, count=freq_count), "hard_stop",
                                    "tool_frequency", (name,), freq_count, eff_hard)

            if freq_count >= eff_warn:
                if warning is None and name not in self._tool_freq_warned:
                    warning = LoopDecision(TOOL_FREQ_WARNING_MSG.format(tool_name=name, count=freq_count), "warn",
                                           "tool_frequency", (name,), freq_count, eff_warn)
            else:
                # Decayed below the warn threshold: a future burst warns again.
                self._tool_freq_warned.discard(name)

        if warning is not None:
            if warning.detection_layer == "identical_call_set":
                self._warned.add(call_hash)
            else:
                warned_name = warning.tool_names[0]
                # Later calls in this batch may already have decayed the burst.
                if self._tool_name_counter.get(warned_name, 0) >= warning.threshold:
                    self._tool_freq_warned.add(warned_name)
        return warning
