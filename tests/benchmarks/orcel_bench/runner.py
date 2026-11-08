"""BM-02: run task episodes with the oracle and write a benchmark report.

The episode flow (setup, then the solver, then evaluate; the reward of an
evaluate result) is adapted from trycua/cua at commit
a802eaf26ca97616a6bf0de6a29729a9346fbb1f,
`libs/cua-bench/cua_bench/runner/episode.py` (blob 02e1d1ab: ``reward_of``
and the phase order). MIT, Copyright (c) 2024-2025 TryCua; licence in
../LICENSE-cua-bench.txt.

Modifications for Orcel: oracle only (no agents, no models, no cloud, no
screenshots or traces); each episode gets its own disposable FileSession;
results are rows of orcel-benchmark-report/1
(docs/orcel/implementation-readiness/protocol/BENCHMARK_REPORT_1.schema.json),
whose observed codes are fixed words, never task text or error messages;
``reward_of`` is strict (a missing, non-numeric or out-of-range value is no
reward, so the variant is unsolved); each phase runs on its own thread with
a deadline, so a phase that blocks without awaiting still times out.
"""

from __future__ import annotations

import asyncio
import importlib.util
import math
import platform
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Optional

from .session import FileSession
from .task import KINDS, Task

SCHEMA = "orcel-benchmark-report/1"
PLANNER = {"kind": "deterministic", "name": "oracle", "version": "1"}
#: A task directory's name, and a variant id, as they appear in a case id.
_CASE_PART = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
#: How long one phase of one episode may take.
PHASE_TIMEOUT_S = 30.0
#: The schema's longest case id.
MAX_CASE_CHARS = 200


class TaskLoadError(Exception):
    pass


@dataclass
class TaskModule:
    name: str
    functions: dict[str, Callable[..., Any]]


def load_task(directory: Path, split: str = "train") -> TaskModule:
    """Import ``directory/main.py`` and collect its four marked functions."""
    main = directory / "main.py"
    if not main.is_file():
        raise TaskLoadError(f"{directory}: no main.py")
    name = directory.name
    if not _CASE_PART.match(name):
        raise TaskLoadError(f"{directory}: the directory name is not a case id part")
    spec = importlib.util.spec_from_file_location(f"orcel_bench_task_{name.replace('-', '_')}", main)
    if spec is None or spec.loader is None:
        raise TaskLoadError(f"{directory}: cannot import main.py")
    module: ModuleType = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    functions: dict[str, Callable[..., Any]] = {}
    for value in vars(module).values():
        kind = getattr(value, "_ob_kind", None)
        if kind in KINDS and getattr(value, "_ob_split", None) == split:
            if kind in functions:
                raise TaskLoadError(f"{directory}: two {kind} functions")
            functions[kind] = value
    missing = [kind for kind in KINDS if kind not in functions]
    if missing:
        raise TaskLoadError(f"{directory}: missing {', '.join(missing)}")
    return TaskModule(name=name, functions=functions)


def reward_of(evaluation: Any) -> Optional[float]:
    """Scalar reward from an evaluate() result (a number in [0, 1], or a
    non-empty list of them, averaged). Anything else, including one bad
    entry in a list, is no reward."""
    if isinstance(evaluation, bool):
        return 1.0 if evaluation else 0.0
    if isinstance(evaluation, (int, float)):
        value = float(evaluation)
        return value if math.isfinite(value) and 0.0 <= value <= 1.0 else None
    if isinstance(evaluation, (list, tuple)) and evaluation:
        values = [reward_of(v) for v in evaluation]
        if any(v is None for v in values):
            return None
        return sum(values) / len(values)  # type: ignore[arg-type]
    return None


@dataclass
class Episode:
    status: str  # pass, fail or error
    observed: str  # solved, unsolved, setup-error, solve-error, evaluate-error, timeout
    seconds: float


class _PhaseTimeout(Exception):
    """The runner's own deadline (never a TimeoutError a task raises)."""


def _phase(func: Callable[..., Any], task: Task, session: FileSession, timeout: float) -> Any:
    """Run one async phase on its own thread and event loop, with a
    deadline that holds even when the phase blocks without awaiting. A
    phase past its deadline is abandoned (a daemon thread), its session is
    closed so it can do nothing more there, and the episode is a timeout."""
    outcome: dict[str, Any] = {}

    def target() -> None:
        try:
            outcome["value"] = asyncio.run(func(task, session))
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


def run_episode(module: TaskModule, task: Task, timeout: float = PHASE_TIMEOUT_S) -> Episode:
    session = FileSession()
    started = time.perf_counter()
    phase = "setup"
    try:
        _phase(module.functions["setup_task"], task, session, timeout)
        phase = "solve"
        _phase(module.functions["solve_task"], task, session, timeout)
        phase = "evaluate"
        reward = reward_of(_phase(module.functions["evaluate_task"], task, session, timeout))
    except _PhaseTimeout:
        return Episode("error", "timeout", time.perf_counter() - started)
    except Exception:  # noqa: BLE001 - a failing task is a result, its message is not reported
        return Episode("error", f"{phase}-error", time.perf_counter() - started)
    finally:
        session.close()
    seconds = time.perf_counter() - started
    if reward == 1.0:
        return Episode("pass", "solved", seconds)
    return Episode("fail", "unsolved", seconds)


def _percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def _variant_id(task: Task, index: int) -> str:
    variant = task.task_id if task.task_id is not None else str(index)
    if not _CASE_PART.match(variant):
        raise TaskLoadError(f"variant id {variant!r} is not a case id part")
    return variant


def run_oracle(
    task_dirs: list[Path], repeat: int = 1, split: str = "train", timeout: float = PHASE_TIMEOUT_S
) -> list[dict[str, Any]]:
    """One report row per task variant; ``repeat`` episodes give its latency."""
    if repeat < 1:
        raise ValueError("repeat must be at least 1")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for directory in task_dirs:
        group = directory.parent.name
        if not _CASE_PART.match(group):
            raise TaskLoadError(f"{directory}: the group directory name is not a case id part")
        module = load_task(directory, split)
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
            episodes = [run_episode(module, task, timeout) for _ in range(repeat)]
            # The row is as good as its worst episode.
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
                    "steps": 1,
                    "model_calls": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                }
            )
    return rows


def machine() -> dict[str, Any]:
    """The machine fields that need no probing: no CPU model, no memory."""
    system = platform.system()
    os_name = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(system)
    if os_name is None:
        raise RuntimeError(f"unsupported OS {system!r}")
    arch = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "arm64", "aarch64": "arm64"}.get(
        platform.machine().lower()
    )
    if arch is None:
        raise RuntimeError(f"unsupported architecture {platform.machine()!r}")
    # On macOS platform.release() is the Darwin kernel's version; the
    # product version is what a reader expects.
    raw = platform.mac_ver()[0] if os_name == "macos" else platform.release()
    release = re.sub(r"[^A-Za-z0-9._+-]", "-", raw or "unknown")
    if not release[:1].isalnum():
        release = "v" + release
    return {"os": os_name, "os_version": release[:64], "arch": arch}


def report(orcel_commit: str, rows: list[dict[str, Any]], planner: Optional[dict[str, str]] = None) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{40}", orcel_commit):
        raise ValueError("orcel_commit must be a full lowercase commit id")
    return {
        "schema": SCHEMA,
        "orcel_commit": orcel_commit,
        "suite": "journeys",
        "machine": machine(),
        "planner": dict(planner or PLANNER),
        "rows": rows,
    }
