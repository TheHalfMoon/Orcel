"""The Orcel Agent loop (M1): observe, propose, dispatch through the edge,
record.

The agent proposes and orceld decides. The loop enforces the client-side
rules from the master plan (section C):
- **Allowlist.** Only allowlisted tools the edge actually lists are offered
  to the planner or dispatched. In M1 the list is the read-only tools, which
  is stricter than `core`.
- **Refusal is final.** An identical call is never re-proposed after orceld
  refused it.
- **Approval budget.** At most `max_approval_requests` approval requests per
  run. The run stops at the first denial and never re-asks.
- **Step budget.** At most `max_steps` dispatched calls.
- **Resume invariant.** A dispatched call without a recorded answer (a
  crash) becomes `OUTCOME_UNKNOWN`. A mutation then needs a successful
  read-only observation first, and nothing is re-dispatched from agent
  state.
- **Finish is a claim.** It is never treated as proof of success.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from .edge import ToolOutcome, ToolSpec
from .events import EventLog
from .journal import OUTCOME_UNKNOWN, DispatchJournal, digest
from .planner import Finish, Planner, Step, ToolCall

#: M1's allowlist: read-only observation tools only (stricter than `core`).
READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {"fs_read", "fs_read_range", "fs_list", "fs_stat", "fs_find", "fs_search", "workspace_get", "system_status"}
)

APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
APPROVAL_DENIED = {"APPROVAL_DENIED", "APPROVAL_UNAVAILABLE"}


class ToolSource(Protocol):
    def list_tools(self) -> list[ToolSpec]:
        ...

    def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        ...


@dataclass
class RunResult:
    outcome: str
    answer: Any = None
    steps: list[Step] = field(default_factory=list)
    approval_requests: int = 0


class AgentStop(Exception):
    def __init__(self, outcome: str) -> None:
        super().__init__(outcome)
        self.outcome = outcome


@dataclass
class Agent:
    edge: ToolSource
    journal: DispatchJournal
    events: EventLog
    allowlist: frozenset[str] = READ_ONLY_TOOLS
    max_steps: int = 32
    max_approval_requests: int = 3
    mutating: frozenset[str] = frozenset()
    steps: list[Step] = field(default_factory=list)
    approval_requests: int = 0
    _tools: dict[str, ToolSpec] = field(default_factory=dict)
    _refused: set[tuple[str, str]] = field(default_factory=set)
    _must_reobserve: bool = False
    _prepared: bool = False

    def prepare(self) -> list[ToolSpec]:
        """List the edge's tools, keep the allowlisted ones, and surface
        unanswered calls from a previous crash as `OUTCOME_UNKNOWN`. Runs
        once per agent; later calls return the same tools."""
        if self._prepared:
            return list(self._tools.values())
        self._prepared = True
        self._tools = {tool.name: tool for tool in self.edge.list_tools() if tool.name in self.allowlist}
        self.events.emit("run.started", tools=sorted(self._tools))
        for unanswered in self.journal.unanswered():
            self.steps.append(Step(ToolCall(unanswered.tool, {}), ok=False, error_code=OUTCOME_UNKNOWN))
            self.journal.resolve_unknown(unanswered.seq)
            self._must_reobserve = True
            self.events.emit("step.outcome_unknown", step_id=f"resume-{unanswered.seq}", tool=unanswered.tool)
        return list(self._tools.values())

    def dispatch(self, call: ToolCall) -> Step:
        """Forward one proposed call, under every client-side rule."""
        if not self._prepared:
            raise AgentStop("not-prepared")
        if call.tool not in self._tools:
            raise AgentStop("proposal-outside-allowlist")
        if not isinstance(call.arguments, dict):
            raise AgentStop("proposal-malformed")
        required = self._tools[call.tool].input_schema.get("required", [])
        if any(name not in call.arguments for name in required):
            raise AgentStop("proposal-malformed")
        key = (call.tool, digest(call.arguments))
        if key in self._refused:
            raise AgentStop("repeat-refused")
        if call.tool in self.mutating and self._must_reobserve:
            raise AgentStop("reobserve-before-mutation")
        if len(self.steps) >= self.max_steps:
            raise AgentStop("step-budget")
        step_id = f"step-{len(self.steps) + 1}"
        self.events.emit("step.dispatched", step_id=step_id, tool=call.tool)
        seq = self.journal.dispatched(call.tool, call.arguments)
        outcome = self.edge.call_tool(call.tool, call.arguments)
        self.journal.recorded(seq, outcome.ok, outcome.error_code)
        step = Step(call, outcome.ok, outcome.result, outcome.error_code)
        self.steps.append(step)
        self.events.emit("step.finished", step_id=step_id, tool=call.tool, ok=outcome.ok, code=outcome.error_code)
        if outcome.ok:
            if call.tool not in self.mutating:
                self._must_reobserve = False
            return step
        self._refused.add(key)
        if outcome.error_code == APPROVAL_REQUIRED:
            self.approval_requests += 1
            if self.approval_requests > self.max_approval_requests:
                raise AgentStop("approval-budget")
        if outcome.error_code in APPROVAL_DENIED:
            raise AgentStop("approval-denied")
        return step

    def run(self, goal: str, planner: Planner) -> RunResult:
        tools = self.prepare()
        try:
            while True:
                proposal = planner.propose(goal, list(self.steps), tools)
                if isinstance(proposal, Finish):
                    self.events.emit("run.finished", claimed=True)
                    return RunResult("finished", proposal.answer, list(self.steps), self.approval_requests)
                if not isinstance(proposal, ToolCall):
                    raise AgentStop("proposal-malformed")
                self.dispatch(proposal)
        except AgentStop as stop:
            self.events.emit("run.stopped", reason=stop.outcome)
            return RunResult(stop.outcome, None, list(self.steps), self.approval_requests)

