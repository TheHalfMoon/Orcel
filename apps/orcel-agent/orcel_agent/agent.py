"""The Orcel Agent loop (M1): observe, propose, dispatch through the edge,
record.

The agent proposes and orceld decides. The loop enforces the client-side
rules from the master plan (section C):
- **Allowlist.** Only allowlisted tools the edge actually lists are offered
  or dispatched. In M1 the list is the read-only tools, which is stricter
  than `core`.
- **Fail-closed classes.** Every tool outside `READ_ONLY_TOOLS` is treated
  as mutating and approval-bearing.
- **Refusal is final.** An identical call is never dispatched again after
  orceld refused it. This survives a resume.
- **Approval budget.** orceld never answers "approval required"; its broker
  prompts the person and answers with the result or a denial. So the budget
  counts approval-bearing calls *before* dispatch: at most
  `max_approval_requests` per run, with a stop at the first denial and no
  re-asking, even after a resume.
- **Step budget.** At most `max_steps` dispatched calls, counted across a
  resume.
- **Resume invariant.**
  - A dispatched call without a recorded answer becomes `OUTCOME_UNKNOWN`,
    surfaced once.
  - A mutation then needs a successful read-only observation first.
  - The unknown call itself is never dispatched again.
- **Edge failure.** A broken connection mid-call is recorded as unknown and
  stops the run.
- **Finish is a claim.** It is never treated as proof of success.
- **Store.** The run's store is deleted when the run ends, unless
  `keep_store` is set. A crash keeps it for resume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .edge import APPROVAL_CALL_TIMEOUT_S, EdgeError, ToolOutcome, ToolSpec
from .events import EventLog
from .journal import OUTCOME_UNKNOWN, DispatchJournal, digest
from .planner import Finish, Planner, Step, ToolCall
from .store import RunStore

#: M1's allowlist: read-only observation tools whose contract approval is
#: `none` (`apps/orcel-mcp/src/tool_contract.ts`); stricter than `core`.
READ_ONLY_TOOLS: frozenset[str] = frozenset(
    {"fs_read", "fs_read_range", "fs_list", "fs_stat", "fs_find", "fs_search", "workspace_get", "system_status"}
)

APPROVAL_DENIED = {"APPROVAL_DENIED", "APPROVAL_UNAVAILABLE"}


class ToolSource(Protocol):
    def list_tools(self) -> list[ToolSpec]:
        ...

    def call_tool(self, name: str, arguments: dict[str, Any], timeout_s: Optional[float] = None) -> ToolOutcome:
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
    store: Optional[RunStore] = None
    keep_store: bool = False
    allowlist: frozenset[str] = READ_ONLY_TOOLS
    max_steps: int = 32
    max_approval_requests: int = 3
    steps: list[Step] = field(default_factory=list)
    approval_requests: int = 0
    _dispatched: int = 0
    _tools: dict[str, ToolSpec] = field(default_factory=dict)
    _refused: set[tuple[str, str]] = field(default_factory=set)
    _unknown: set[tuple[str, str]] = field(default_factory=set)
    _must_reobserve: bool = False
    _denied: bool = False
    _prepared: bool = False

    def is_mutating(self, tool: str) -> bool:
        """Fail closed: anything not known read-only may change state or
        prompt for approval."""
        return tool not in READ_ONLY_TOOLS

    def prepare(self) -> list[ToolSpec]:
        """List the edge's tools, keep the allowlisted ones, rebuild the
        refusals and budgets from the journal, and surface calls a crash cut
        off as `OUTCOME_UNKNOWN`. Runs once per agent."""
        if self._prepared:
            return list(self._tools.values())
        self._prepared = True
        self._tools = {tool.name: tool for tool in self.edge.list_tools() if tool.name in self.allowlist}
        self.events.emit("run.started", tools=sorted(self._tools))
        for entry in self.journal.entries():
            key = (entry.tool, entry.arguments_sha256)
            self._dispatched += 1
            if self.is_mutating(entry.tool):
                self.approval_requests += 1
            if entry.answered and not entry.ok:
                if entry.error_code == OUTCOME_UNKNOWN:
                    self._unknown.add(key)
                else:
                    self._refused.add(key)
                if entry.error_code in APPROVAL_DENIED:
                    self._denied = True
            elif not entry.answered:
                self._unknown.add(key)
        for entry in self.journal.unanswered():
            step = Step(ToolCall(entry.tool, {}), ok=False, error_code=OUTCOME_UNKNOWN,
                        arguments_sha256=entry.arguments_sha256)
            self.steps.append(step)
            self.journal.resolve_unknown(entry.seq)
            self._must_reobserve = True
            self.events.emit("step.outcome_unknown", step_id=f"resume-{entry.seq}", tool=entry.tool)
        return list(self._tools.values())

    def dispatch(self, call: ToolCall) -> Step:
        """Forward one proposed call, under every client-side rule."""
        if not self._prepared:
            raise AgentStop("not-prepared")
        if self._denied:
            raise AgentStop("approval-denied")
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
        mutating = self.is_mutating(call.tool)
        if mutating and key in self._unknown:
            raise AgentStop("unknown-outcome-replay")
        if mutating and self._must_reobserve:
            raise AgentStop("reobserve-before-mutation")
        if self._dispatched >= self.max_steps:
            raise AgentStop("step-budget")
        if mutating:
            if self.approval_requests >= self.max_approval_requests:
                raise AgentStop("approval-budget")
            self.approval_requests += 1
        step_id = f"step-{self._dispatched + 1}"
        self.events.emit("step.dispatched", step_id=step_id, tool=call.tool)
        seq = self.journal.dispatched(call.tool, call.arguments)
        self._dispatched += 1
        try:
            outcome = self.edge.call_tool(call.tool, call.arguments,
                                          APPROVAL_CALL_TIMEOUT_S if mutating else None)
        except EdgeError as error:
            # The call may or may not have reached orceld: unknown.
            self.journal.recorded(seq, False, OUTCOME_UNKNOWN)
            self._unknown.add(key)
            self._must_reobserve = True
            self.events.emit("step.outcome_unknown", step_id=step_id, tool=call.tool)
            raise AgentStop("edge-failure") from error
        self.journal.recorded(seq, outcome.ok, outcome.error_code)
        step = Step(call, outcome.ok, outcome.result, outcome.error_code, key[1])
        self.steps.append(step)
        self.events.emit("step.finished", step_id=step_id, tool=call.tool, ok=outcome.ok, code=outcome.error_code)
        if outcome.ok:
            if not mutating:
                self._must_reobserve = False
            return step
        self._refused.add(key)
        if outcome.error_code in APPROVAL_DENIED:
            self._denied = True
            raise AgentStop("approval-denied")
        return step

    def run(self, goal: str, planner: Planner) -> RunResult:
        try:
            tools = self.prepare()
            if self._denied:
                raise AgentStop("approval-denied")
            while True:
                proposal = planner.propose(goal, list(self.steps), tools)
                if isinstance(proposal, Finish):
                    self.events.emit("run.finished", claimed=True)
                    result = RunResult("finished", proposal.answer, list(self.steps), self.approval_requests)
                    break
                if not isinstance(proposal, ToolCall):
                    raise AgentStop("proposal-malformed")
                self.dispatch(proposal)
        except AgentStop as stop:
            self.events.emit("run.stopped", reason=stop.outcome)
            result = RunResult(stop.outcome, None, list(self.steps), self.approval_requests)
        # Reached only when the run ended (a crash propagates and keeps the
        # store for resume).
        if self.store is not None and not self.keep_store:
            self.store.delete()
        return result
