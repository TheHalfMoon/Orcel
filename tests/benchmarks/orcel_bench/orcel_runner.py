"""BM-02: run Orcel tasks through the real `orceld` (Tier A of
ORCEL_EXECUTION_PLAN.md) and write benchmark report rows.

Orcel-owned. Each episode: a fresh workspace built by the task's
`setup_task`; the real orceld started on it (orcel.py); the task's
deterministic `orcel_plan(task, orcel)` observing only through Orcel (it sees
the task's description and declared `inputs`, never the expected answer, and
a client with nothing but `call`); orceld stopped; at least one Orcel call
made and audited by orceld; the workspace checked byte for byte against its state after setup
(Tier A tasks are read-only, so any change fails the episode); the answer
scored by `evaluate_task`. Observed codes are fixed words; the trace records
Orcel calls (capability, operation, outcome, latency, error code), never file
contents or task text.
"""

from __future__ import annotations

import importlib.util
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

from .orcel import Orceld, OrcelError, OrcelRefused
from .runner import (
    _CASE_PART,
    MAX_CASE_CHARS,
    PHASE_TIMEOUT_S,
    TaskLoadError,
    TaskModule,
    _percentile,
    _phase,
    _PhaseTimeout,
    _variant_id,
    reward_of,
)
from .session import FileSession
from .task import ORCEL_KINDS, Task

PLANNER = {"kind": "deterministic", "name": "orcel-fs-planner", "version": "1"}


def load_orcel_task(directory: Path, split: str = "train") -> TaskModule:
    """Import ``directory/main.py`` and collect its four Orcel functions."""
    main = directory / "main.py"
    if not main.is_file():
        raise TaskLoadError(f"{directory}: no main.py")
    name = directory.name
    if not _CASE_PART.match(name):
        raise TaskLoadError(f"{directory}: the directory name is not a case id part")
    spec = importlib.util.spec_from_file_location(f"orcel_bench_orcel_task_{name.replace('-', '_')}", main)
    if spec is None or spec.loader is None:
        raise TaskLoadError(f"{directory}: cannot import main.py")
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    functions: dict[str, Callable[..., Any]] = {}
    for value in vars(module).values():
        kind = getattr(value, "_ob_kind", None)
        if kind in ORCEL_KINDS and getattr(value, "_ob_split", None) == split:
            if kind in functions:
                raise TaskLoadError(f"{directory}: two {kind} functions")
            functions[kind] = value
    missing = [kind for kind in ORCEL_KINDS if kind not in functions]
    if missing:
        raise TaskLoadError(f"{directory}: missing {', '.join(missing)}")
    return TaskModule(name=name, functions=functions)


def _tree(root: Path) -> dict[str, bytes]:
    """Every file and folder under `root`, with file bytes."""
    out: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        out[relative + ("/" if path.is_dir() else "")] = b"" if path.is_dir() else path.read_bytes()
    return out


@dataclass
class OrcelEpisode:
    status: str
    observed: str
    seconds: float
    calls: list[dict[str, Any]] = field(default_factory=list)
    audit_records: int = 0
    #: For an orceld failure, why (orceld's first stderr line); trace only.
    detail: str = ""


class PlanClient:
    """What a plan holds: Orcel's request interface and nothing else (no
    workspace path, no process)."""

    __slots__ = ("_call",)

    def __init__(self, orcel: Orceld) -> None:
        self._call = orcel.call

    def call(self, capability: str, operation: str, target: Optional[str], arguments: Optional[dict[str, Any]] = None) -> Any:
        return self._call(capability, operation, target, arguments)


def plan_view(task: Task) -> Task:
    """The task as a plan sees it: its description and declared
    `metadata["inputs"]`; the rest of the metadata (the ground truth the
    setup and evaluation use) is withheld."""
    return Task(description=task.description, task_id=task.task_id, metadata=dict(task.metadata.get("inputs", {})))


def _plan(func: Callable[..., Any], task: Task, orcel: Orceld, timeout: float) -> Any:
    """The planner on its own thread with a deadline (it only blocks on
    orceld, whose calls have their own deadline)."""
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = func(plan_view(task), PlanClient(orcel))
        except BaseException as error:  # noqa: BLE001 - re-raised below
            outcome["error"] = error

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise _PhaseTimeout()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


def run_orcel_episode(
    module: TaskModule,
    task: Task,
    orceld: Path,
    timeout: float = PHASE_TIMEOUT_S,
    orceld_args: tuple[str, ...] = (),
    call_timeout: Optional[float] = None,
    client_factory: Optional[Callable[[Path], Any]] = None,
) -> OrcelEpisode:
    session = FileSession()
    started = time.perf_counter()
    calls: list[dict[str, Any]] = []
    audit_records = 0

    detail = ""

    def done(status: str, observed: str) -> OrcelEpisode:
        return OrcelEpisode(status, observed, time.perf_counter() - started, calls, audit_records, detail)

    try:
        try:
            _phase(module.functions["setup_task"], task, session, timeout)
        except _PhaseTimeout:
            return done("error", "timeout")
        except Exception:  # noqa: BLE001
            return done("error", "setup-error")
        before = _tree(session.root)
        # The direct orceld client, or another with its interface (the Orcel
        # Agent through the MCP edge, agent_client.py).
        orcel = Orceld(orceld, session.root, args=orceld_args) if client_factory is None else client_factory(session.root)
        if call_timeout is not None:
            orcel.timeout = call_timeout
        try:
            with orcel:
                answer = _plan(module.functions["orcel_plan"], task, orcel, timeout)
        except OrcelError as error:
            detail = str(error)[:400]
            return done("error", error.observed)
        except OrcelRefused:
            return done("fail", "orcel-refused")
        except _PhaseTimeout:
            return done("error", "timeout")
        except Exception:  # noqa: BLE001
            return done("error", "plan-error")
        finally:
            calls.extend(
                {
                    "capability": call.capability,
                    "operation": call.operation,
                    "ok": call.ok,
                    "code": call.code,
                    "ms": round(call.millis, 3),
                }
                for call in orcel.calls
            )
            audit_records = orcel.audit_records
        if _tree(session.root) != before:
            return done("fail", "workspace-changed")
        # The answer must come through Orcel: no call, or calls orceld did
        # not audit, fail the episode whatever the answer.
        if not calls:
            return done("fail", "no-orcel-call")
        if audit_records < len(calls):
            return done("fail", "unaudited")
        session.answer = answer  # type: ignore[attr-defined]
        try:
            reward = reward_of(_phase(module.functions["evaluate_task"], task, session, timeout))
        except _PhaseTimeout:
            return done("error", "timeout")
        except Exception:  # noqa: BLE001
            return done("error", "evaluate-error")
        if reward == 1.0:
            return done("pass", "solved")
        return done("fail", "unsolved")
    finally:
        session.close()


def run_orcel(
    task_dirs: list[Path],
    orceld: Path,
    repeat: int = 1,
    split: str = "train",
    timeout: float = PHASE_TIMEOUT_S,
    trace: Optional[Path] = None,
    orceld_args: tuple[str, ...] = (),
    call_timeout: Optional[float] = None,
    client_factory: Optional[Callable[[Path], Any]] = None,
) -> list[dict[str, Any]]:
    """One report row per task variant, solved through orceld; `trace`
    receives one JSON line per episode."""
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    if not orceld.is_file():
        raise TaskLoadError(f"no orceld binary at {orceld}")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    traces: list[str] = []
    for directory in task_dirs:
        group = directory.parent.name
        if not _CASE_PART.match(group):
            raise TaskLoadError(f"{directory}: the group directory name is not a case id part")
        module = load_orcel_task(directory, split)
        tasks = module.functions["tasks_config"]()
        if not isinstance(tasks, list) or not all(isinstance(task, Task) for task in tasks):
            raise TaskLoadError(f"{directory}: tasks_config must return a list of Task")
        for index, task in enumerate(tasks):
            case = f"{group}/{module.name}/{_variant_id(task, index)}"
            if len(case) > MAX_CASE_CHARS:
                raise TaskLoadError(f"case id longer than {MAX_CASE_CHARS} characters: {case[:40]}...")
            if case in seen:
                raise TaskLoadError(f"duplicate case id {case}")
            seen.add(case)
            episodes = [
                run_orcel_episode(module, task, orceld, timeout, orceld_args, call_timeout, client_factory)
                for _ in range(repeat)
            ]
            for number, episode in enumerate(episodes):
                traces.append(
                    json.dumps(
                        {
                            "case": case,
                            "episode": number,
                            "status": episode.status,
                            "observed": episode.observed,
                            "ms": round(episode.seconds * 1000, 3),
                            "orcel_calls": episode.calls,
                            "orcel_audit_records": episode.audit_records,
                            "detail": episode.detail,
                        }
                    )
                )
            worst = next((e for e in episodes if e.status == "error"), None) or next(
                (e for e in episodes if e.status == "fail"), episodes[0]
            )
            millis = [round(e.seconds * 1000, 3) for e in episodes]
            rows.append(
                {
                    "case": case,
                    "status": worst.status,
                    "observed": worst.observed,
                    "latency_ms": {"p50": _percentile(millis, 0.5), "p95": _percentile(millis, 0.95)},
                    "steps": max(len(e.calls) for e in episodes),
                    "model_calls": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                }
            )
    if trace is not None:
        trace.write_text("\n".join(traces) + ("\n" if traces else ""), encoding="utf-8")
    return rows
