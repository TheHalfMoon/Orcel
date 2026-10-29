"""The provider-neutral planner contract (master plan, row 11).

A planner sees the goal, the steps so far and the tools the agent may use,
and proposes one tool call or a finish. Its proposal is a request, never an
authorization: the agent checks it against its allowlist and the tool's
schema, and orceld decides it. M1 ships the scripted planner; the LangChain
chat-model adapter (M2) and a typed-decision adapter implement the same
protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, Protocol, Sequence, Union

from .edge import ToolSpec
from .journal import OUTCOME_UNKNOWN


@dataclass(frozen=True)
class ToolCall:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Finish:
    """The planner's claim that it is done. A claim, never a receipt: the
    task's checker decides success."""

    answer: Any = None


Proposal = Union[ToolCall, Finish]


@dataclass(frozen=True)
class Step:
    """One dispatched call and what orceld answered (or `outcome_unknown`
    after a resume)."""

    call: ToolCall
    ok: bool
    result: Any = None
    error_code: Optional[str] = None


class Planner(Protocol):
    def propose(self, goal: str, steps: Sequence[Step], tools: Sequence[ToolSpec]) -> Proposal:
        ...


class ScriptedPlanner:
    """Replays a fixed, labelled plan: deterministic, no model."""

    label = "scripted-plan"

    def __init__(self, calls: Sequence[ToolCall], answer: Any = None) -> None:
        self._calls = list(calls)
        self._answer = answer

    def propose(self, goal: str, steps: Sequence[Step], tools: Sequence[ToolSpec]) -> Proposal:
        # Only the steps this run dispatched count: an `OUTCOME_UNKNOWN`
        # step surfaced on resume is history, not a step of this script.
        done = sum(1 for step in steps if step.error_code != OUTCOME_UNKNOWN)
        if done < len(self._calls):
            return self._calls[done]
        return Finish(self._answer)
