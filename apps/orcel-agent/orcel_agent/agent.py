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
  - Every journal entry returns as history, so a planner continues after the
    calls already made.
  - A completed mutation is never dispatched again.
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

_JSON_TYPES: dict[str, tuple[type, ...]] = {
    "string": (str,), "integer": (int,), "number": (int, float), "boolean": (bool,),
    "array": (list,), "object": (dict,), "null": (type(None),),
}


def arguments_match(schema: dict[str, Any], arguments: dict[str, Any]) -> bool:
    """SG-000129 slice 2: a proposal's arguments against the tool's own input
    schema, before dispatch. Required names are present; a name the schema
    does not declare is refused when the schema closes its properties; and a
    declared JSON type must match (a boolean is never an integer). orceld
    validates again; this only keeps a model's malformed call off the wire."""
    if any(name not in arguments for name in schema.get("required", [])):
        return False
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return True
    for name, value in arguments.items():
        declared = properties.get(name)
        if declared is None:
            if schema.get("additionalProperties") is False:
                return False
            continue
        kinds = declared.get("type") if isinstance(declared, dict) else None
        if kinds is None:
            continue
        allowed: tuple[type, ...] = ()
        for kind in [kinds] if isinstance(kinds, str) else list(kinds):
            allowed += _JSON_TYPES.get(kind, ())
        if not allowed or not isinstance(value, allowed):
            return False
        if isinstance(value, bool) and bool not in allowed:
            return False
    return True


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
    #: Set when the planner stopped on its own (e.g. "loop_capped"): a
    #: capped run is not a clean finish.
    stop_reason: Optional[str] = None


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
    #: SG-000129, private: set only by `entry.chat_agent`. The gate then
    #: refuses any allowlist or call outside READ_ONLY_TOOLS, in prepare()
    #: and in every dispatch. (Defence in depth: ChatModelPlanner refuses
    #: non-read-only tools on its own.)
    _read_only_only: bool = False
    steps: list[Step] = field(default_factory=list)
    approval_requests: int = 0
    _dispatched: int = 0
    _tools: dict[str, ToolSpec] = field(default_factory=dict)
    _refused: set[tuple[str, str]] = field(default_factory=set)
    _unknown: set[tuple[str, str]] = field(default_factory=set)
    _completed: set[tuple[str, str]] = field(default_factory=set)
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
        if self._read_only_only and not set(self.allowlist) <= READ_ONLY_TOOLS:
            raise AgentStop("allowlist-too-wide")
        self._prepared = True
        self._tools = {tool.name: tool for tool in self.edge.list_tools() if tool.name in self.allowlist}
        self.events.emit("run.started", tools=sorted(self._tools))
        # Every journal entry comes back as history (names, digests and
        # codes; results are never kept), so a planner resumes after the
        # calls already made instead of proposing them again.
        for entry in self.journal.entries():
            key = (entry.tool, entry.arguments_sha256)
            mutating = self.is_mutating(entry.tool)
            self._dispatched += 1
            if mutating:
                self.approval_requests += 1
            unknown = not entry.answered or entry.error_code == OUTCOME_UNKNOWN
            if unknown:
                self._unknown.add(key)
                # Re-observation is owed until a later read-only call
                # succeeds, across any number of resumes.
                self._must_reobserve = True
            elif entry.ok:
                if mutating:
                    self._completed.add(key)
                else:
                    self._must_reobserve = False
            else:
                self._refused.add(key)
                if entry.error_code in APPROVAL_DENIED:
                    self._denied = True
            self.steps.append(Step(ToolCall(entry.tool, {}), ok=entry.ok and not unknown,
                                   error_code=OUTCOME_UNKNOWN if unknown else entry.error_code,
                                   arguments_sha256=entry.arguments_sha256, resumed=True))
            if not entry.answered and not entry.surfaced:
                self.journal.resolve_unknown(entry.seq)
                self.events.emit("step.outcome_unknown", step_id=f"resume-{entry.seq}", tool=entry.tool)
        return list(self._tools.values())

    def dispatch(self, call: ToolCall) -> Step:
        """Forward one proposed call, under every client-side rule."""
        if not self._prepared:
            raise AgentStop("not-prepared")
        if self._read_only_only and (self.is_mutating(call.tool) or not set(self.allowlist) <= READ_ONLY_TOOLS):
            raise AgentStop("proposal-outside-allowlist")
        if self._denied:
            raise AgentStop("approval-denied")
        if call.tool not in self._tools:
            raise AgentStop("proposal-outside-allowlist")
        if not isinstance(call.arguments, dict):
            raise AgentStop("proposal-malformed")
        if not arguments_match(self._tools[call.tool].input_schema, call.arguments):
            raise AgentStop("proposal-malformed")
        key = (call.tool, digest(call.arguments))
        if key in self._refused:
            raise AgentStop("repeat-refused")
        mutating = self.is_mutating(call.tool)
        if mutating and key in self._unknown:
            raise AgentStop("unknown-outcome-replay")
        if mutating and key in self._completed:
            raise AgentStop("completed-mutation-replay")
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
        except Exception as error:  # noqa: BLE001 - any failure here leaves the outcome unknown
            # The call may or may not have reached orceld: unknown. SG-000129
            # slice 4a2: any exception, not only EdgeError, and the unknown
            # step is kept in the run's steps so the caller sees it.
            self.journal.recorded(seq, False, OUTCOME_UNKNOWN)
            self._unknown.add(key)
            self._must_reobserve = True
            self.steps.append(Step(call, False, None, OUTCOME_UNKNOWN, key[1]))
            self.events.emit("step.outcome_unknown", step_id=step_id, tool=call.tool)
            raise AgentStop("edge-failure") from error
        self.journal.recorded(seq, outcome.ok, outcome.error_code)
        step = Step(call, outcome.ok, outcome.result, outcome.error_code, key[1])
        self.steps.append(step)
        self.events.emit("step.finished", step_id=step_id, tool=call.tool, ok=outcome.ok, code=outcome.error_code)
        if outcome.ok:
            if mutating:
                self._completed.add(key)
            else:
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
                try:
                    proposal = planner.propose(goal, list(self.steps), tools)
                except AgentStop:
                    raise
                except Exception as error:  # noqa: BLE001 - a planner failure stops the run cleanly
                    # SG-000129 slice 4a2: a model or planner exception stops
                    # the run instead of crashing it. Nothing was dispatched.
                    raise AgentStop("planner-error") from error
                if isinstance(proposal, Finish):
                    self.events.emit("run.finished", claimed=True, stop_reason=proposal.stop_reason)
                    result = RunResult("finished", proposal.answer, list(self.steps), self.approval_requests,
                                       proposal.stop_reason)
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
