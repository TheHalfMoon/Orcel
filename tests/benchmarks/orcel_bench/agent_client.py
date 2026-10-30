"""BM-02 through the Orcel Agent (M1 of the DeerFlow/Orcel Agent master plan).

`AgentOrcel` has the same interface as `Orceld` (a context manager with
`call`, `calls` and `audit_records`), so the Tier A runner drives the same
deterministic task plans unchanged. Here every call goes through the Orcel
Agent's dispatch rules (allowlist, refusal-is-final, budgets, the resume
journal) and then through the real MCP edge (`apps/orcel-mcp`), which
forwards to a test orceld on the episode's workspace.

Rows are labelled `deterministic` / `orcel-agent-scripted` (M1): the plans are
the task's scripted plans, not a model, and only the agent's dispatch rules
are exercised here (its planner loop is covered by the agent's unit tests).
The agent's private run store is deleted when the episode ends.

SG-000129 slice 2 adds `planner="chat"`: each planned call is first emitted as
a LangChain tool call by a scripted in-process chat model and must come back
unchanged through the Orcel Agent's `ChatModelPlanner` (the conversation, the
model call and the reply parsing), with the model bound to the edge's own
schema for that tool, and the planner's proposal is what the gate
dispatches. Built with `chat_agent`, so the allowlist is read-only.
Rows are labelled `deterministic` / `orcel-agent-langchain-scripted`: still
the task's scripted plans, not a model. Needs the agent's locked environment.
"""

from __future__ import annotations

import shutil
import sys
from collections import deque
import tempfile
import time
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
from orcel_agent.store import new_run_id, open_store  # noqa: E402

#: The task's own deterministic plans, dispatched through the Orcel Agent.
PLANNER = {"kind": "deterministic", "name": "orcel-agent-scripted", "version": "m1"}
CHAT_PLANNER = {"kind": "deterministic", "name": "orcel-agent-langchain-scripted", "version": "sg-000129-slice2"}

#: The goal the chat planner is shown; the plan itself is the task's.
GOAL = "Solve the BM-02 Tier A task with read-only Orcel tools."


def _chat_planner() -> Any:
    """The LangChain path, imported only in chat mode (the M1 job's Python
    has no LangChain). orcel_agent is imported first: it switches tracing off
    before LangChain loads."""
    import orcel_agent  # noqa: F401
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel

    from orcel_agent.chat_planner import ChatModelPlanner

    class ScriptedReplies(GenericFakeChatModel):
        """Replays the next scripted reply and records the tools it was bound
        (a real model would choose among them; this one does not)."""

        bound: list = []

        def bind_tools(self, tools: Any, **kwargs: Any) -> "ScriptedReplies":
            self.bound = list(tools)
            return self

    return ChatModelPlanner, ScriptedReplies

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
    _tools: list = field(default_factory=list)
    _replies: Any = None
    _model: Any = None
    _planner: Any = None
    timeout_s: float = 60.0
    planner: str = "scripted"

    @property
    def timeout(self) -> float:
        return self.timeout_s

    @timeout.setter
    def timeout(self, value: float) -> None:
        # The runner's per-call deadline (`call_timeout`) reaches the edge.
        self.timeout_s = value
        if self._edge is not None:
            self._edge.timeout_s = value

    def __enter__(self) -> "AgentOrcel":
        self._state = Path(tempfile.mkdtemp(prefix="orcel-agent-state-"))
        try:
            scratch = self._state / "tmp"
            scratch.mkdir()
            env = orceld_env(self.workspace, self._state, scratch)
            env["ORCEL_DAEMON"] = str(self.orceld)
            self._edge = Edge([self.node, str(self.edge_js)], env, timeout_s=self.timeout_s)
            try:
                self._edge.start()
            except EdgeError as error:
                raise OrcelError("orcel-crash", f"the edge did not start: {error}") from error
            store = open_store(self._state / "agent", new_run_id())
            journal = DispatchJournal(store.journal_path, store.check_capacity)
            # The episode's whole state directory (with this store) is
            # removed in __exit__, so the agent keeps its store until then.
            if self.planner == "chat":
                from orcel_agent.entry import chat_agent

                self._agent = chat_agent(self._edge, journal, EventLog(store.run_id), store=store, keep_store=True)
            else:
                self._agent = Agent(self._edge, journal, EventLog(store.run_id), store=store, keep_store=True)
            self._tools = self._agent.prepare()
            if self.planner == "chat":
                # One planner (with its default loop detector) per episode; its
                # scripted model is fed one reply per planned call.
                planner_class, replies = _chat_planner()
                self._replies = deque()
                self._model = replies(messages=self._feed())
                self._planner = planner_class(self._model, events=self._agent.events)
        except BaseException:
            self.__exit__(None, None, None)
            raise
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
        intended = ToolCall(tool, tool_arguments)
        if self.planner == "chat":
            from langchain_core.messages import AIMessage

            reply = AIMessage(content="", tool_calls=[{"name": tool, "args": tool_arguments, "id": "bm02", "type": "tool_call"}])
            self._replies.append(reply)
            model = self._model
            proposal = self._planner.propose(GOAL, list(self._agent.steps), self._tools)
            # The model was offered the edge's own schema for this tool, and
            # its reply parsed back to exactly the planned call.
            offered = {entry["function"]["name"]: entry["function"]["parameters"] for entry in model.bound}
            schema = next((spec.input_schema for spec in self._tools if spec.name == tool), None)
            if schema is None or offered.get(tool) != schema:
                raise OrcelError("plan-error", f"{tool} was not offered with the edge's schema")
            if proposal != intended:
                raise OrcelError("plan-error", f"the chat planner proposed {proposal!r}, not {intended!r}")
            intended = proposal
        try:
            step = self._agent.dispatch(intended)
        except AgentStop as stop:
            raise OrcelError("agent-stop", stop.outcome) from stop
        except EdgeError as error:
            raise OrcelError("orcel-crash", str(error)) from error
        millis = (time.perf_counter() - started) * 1000
        self.calls.append(Call(capability, operation, target, step.ok, step.error_code, millis))
        if not step.ok:
            raise OrcelRefused(step.error_code or "INTERNAL_ERROR", "")
        return step.result

    def _feed(self) -> Any:
        while self._replies:
            yield self._replies.popleft()

    def __exit__(self, *_exc: object) -> None:
        try:
            if self._edge is not None:
                self._edge.close()
                self._edge = None
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
