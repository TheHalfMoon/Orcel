"""BM-02: the task format, from cua-bench.

Adapted from trycua/cua at commit a802eaf26ca97616a6bf0de6a29729a9346fbb1f,
`libs/cua-bench/cua_bench/core.py` (blob ab33166e: the ``Task`` dataclass) and
`libs/cua-bench/cua_bench/decorators.py` (blob b7095f05: ``tasks_config``,
``setup_task``, ``solve_task``, ``evaluate_task``). MIT, Copyright (c)
2024-2025 TryCua; licence in ../LICENSE-cua-bench.txt.

Modifications for Orcel: test-only tooling that never ships in the product;
the decorators mark functions in place instead of filling a global registry,
and accept only the bare or ``split=...`` forms; ``Task.computer`` is gone
(Orcel's runner supplies a disposable session, see session.py).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

#: The four functions a task module defines, in the order an episode uses them.
KINDS = ("tasks_config", "setup_task", "solve_task", "evaluate_task")
#: An Orcel task (BM-02, ORCEL_EXECUTION_PLAN.md) has no oracle `solve_task`:
#: its `orcel_plan(task, orcel)` observes and acts only through Orcel and
#: returns its answer, which `evaluate_task` scores as `session.answer`.
ORCEL_KINDS = ("tasks_config", "setup_task", "orcel_plan", "evaluate_task")


@dataclass
class Task:
    """One task variant, as returned by the ``tasks_config`` function."""

    #: The instruction an agent receives (the oracle ignores it).
    description: str
    #: A stable identifier for the variant; the index is used otherwise.
    task_id: Optional[str] = None
    #: Variant-specific values the setup, solve and evaluate functions read.
    metadata: dict[str, Any] = field(default_factory=dict)


def _marker(kind: str) -> Callable[..., Any]:
    def mark(func: Optional[Callable[..., Any]] = None, /, *, split: str = "train") -> Any:
        def apply(inner: Callable[..., Any]) -> Callable[..., Any]:
            inner._ob_kind = kind  # type: ignore[attr-defined]
            inner._ob_split = split  # type: ignore[attr-defined]
            return inner

        return apply(func) if func is not None else apply

    mark.__name__ = kind
    mark.__doc__ = f"Marks a task module's {kind} function (bare, or with split=...)."
    return mark


tasks_config = _marker("tasks_config")
setup_task = _marker("setup_task")
solve_task = _marker("solve_task")
evaluate_task = _marker("evaluate_task")
orcel_plan = _marker("orcel_plan")
