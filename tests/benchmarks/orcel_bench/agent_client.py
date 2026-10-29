"""BM-02 through the Orcel Agent (M1 of the DeerFlow/Orcel Agent master plan).

`AgentOrcel` has the same interface as `Orceld` (a context manager with
`call`, `calls` and `audit_records`), so the Tier A runner drives the same
deterministic task plans unchanged. Here every call goes through the Orcel
Agent's dispatch rules (allowlist, refusal-is-final, budgets, the resume
journal) and then through the real MCP edge (`apps/orcel-mcp`), which
forwards to a test orceld on the episode's workspace.

Rows are labelled `deterministic` / `orcel-agent-scripted` (M1): the plans are
the task's scripted plans, not a model. The agent's private run store is
deleted when the episode ends.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .orcel import Call, OrcelError, OrcelRefused, orceld_env

_AGENT_ROOT = Path(__file__).resolve().parents[3] / "apps" / "orcel-agent"
if str(_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENT_ROOT))

from orcel_agent.agent import Agent, AgentStop  # noqa: E402
from orcel_agent.edge import Edge, EdgeError  # noqa: E402
from orcel_agent.events import EventLog  # noqa: E402
from orcel_agent.journal import DispatchJournal  # noqa: E402
from orcel_agent.planner import ToolCall  # noqa: E402
from orcel_agent.store import open_store  # noqa: E402

#: The task's own deterministic plans, dispatched through the Orcel Agent.
PLANNER = {"kind": "deterministic", "name": "orcel-agent-scripted", "version": "m1"}

#: The kernel shapes Tier A plans use, and the edge tool that forwards each.
SHAPES: dict[tuple[str, str], str] = {
    ("fs.read", "read"): "fs_read",
    ("fs.list", "list"): "fs_list",
    ("fs.stat", "stat"): "fs_stat",
    ("fs.read_range", "read"): "fs_read_range",
    ("fs.find", "find"): "fs_find",
}


@dataclass
class AgentOrcel:
    orceld: Path
    edge_js: Path
    workspace: Path
    node: str = "node"
    calls: list[Call] = field(default_factory=list)
    audit_records: int = 0
    _state: Optional[Path] = None
    _edge: Optional[Edge] = None
    _agent: Optional[Agent] = None
    _store_root: Optional[Path] = None

    def __enter__(self) -> "AgentOrcel":
        self._state = Path(tempfile.mkdtemp(prefix="orcel-agent-state-"))
        scratch = self._state / "tmp"
        scratch.mkdir()
        env = orceld_env(self.workspace, self._state, scratch)
        env["ORCEL_DAEMON"] = str(self.orceld)
        self._edge = Edge([self.node, str(self.edge_js)], env)
        try:
            self._edge.start()
        except EdgeError as error:
            self._cleanup()
            raise OrcelError("orcel-crash", f"the edge did not start: {error}") from error
        self._store_root = self._state / "agent"
        store = open_store(self._store_root, uuid.uuid4().hex)
        journal = DispatchJournal(store.journal_path, store.check_capacity)
        self._agent = Agent(self._edge, journal, EventLog(store.run_id))
        self._agent.prepare()
        return self

    def call(self, capability: str, operation: str, target: Optional[str],
             arguments: Optional[dict[str, Any]] = None) -> Any:
        assert self._agent is not None
        tool = SHAPES.get((capability, operation))
        started = time.perf_counter()
        if tool is None:
            raise OrcelError("plan-error", f"no edge tool forwards {capability}/{operation}")
        tool_arguments: dict[str, Any] = dict(arguments or {})
        if target is not None:
            tool_arguments["path"] = target
        try:
            step = self._agent.dispatch(ToolCall(tool, tool_arguments))
        except AgentStop as stop:
            raise OrcelError("agent-stop", stop.outcome) from stop
        except EdgeError as error:
            raise OrcelError("orcel-crash", str(error)) from error
        millis = (time.perf_counter() - started) * 1000
        self.calls.append(Call(capability, operation, target, step.ok, step.error_code, millis))
        if not step.ok:
            raise OrcelRefused(step.error_code or "INTERNAL_ERROR", "")
        return step.result

    def __exit__(self, *_exc: object) -> None:
        try:
            if self._edge is not None:
                self._edge.close()
        finally:
            audit = None if self._state is None else self._state / "audit" / "audit.jsonl"
            if audit is not None and audit.is_file():
                with audit.open("rb") as handle:
                    self.audit_records = sum(1 for _ in handle)
            self._cleanup()

    def _cleanup(self) -> None:
        if self._state is not None:
            shutil.rmtree(self._state, ignore_errors=True)
            self._state = None
