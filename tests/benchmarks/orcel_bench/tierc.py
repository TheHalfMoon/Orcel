"""BM-02 Tier C, slice C1 (ORCEL_EXECUTION_PLAN.md): the harness around the
pinned cua-driver-bench GUI tasks, before any GUI runs.

Orcel-owned. For each task of a verified taskpack and the platform
descriptor of this OS (`platform/launch.<os>.json`), an episode:

1. a fresh workspace, artifacts folder and result path in a private temp
   folder;
2. the task's own reset `setup`, then its reset `verify` (both must exit 0);
3. no plan (this is the no-op baseline: nothing drives the apps yet);
4. the task's own evaluator, exactly as the descriptor's `evaluate` command
   line says, on the untouched workspace;
5. teardown: every folder of the episode removed.

The case passes only when reset works and the evaluator rejects the
untouched workspace (`passed` false, score below 1): that proves the reset
and scoring pipeline is wired correctly and that a no-op is never scored as
a solution. It says nothing about GUI success. Commands are the task's own,
run with this interpreter (`-E -s`) and a scrubbed
environment; reports carry fixed codes and the score only, never task text
or evaluator detail.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

PLANNER = {"kind": "deterministic", "name": "tierc-noop-baseline", "version": "1"}
#: How long one task command (reset or evaluator) may take.
STEP_TIMEOUT_S = 120.0
#: Environment variables a task command keeps; everything else is dropped.
_KEPT_ENV = ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR", "LANG", "LC_ALL")


class TierCError(Exception):
    """The taskpack or a descriptor is not what the harness expects."""


def platform_name() -> str:
    system = platform.system()
    name = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(system)
    if name is None:
        raise TierCError(f"no Tier C descriptor for {system}")
    return name


def load_descriptor(task_dir: Path, os_name: str) -> dict[str, Any]:
    path = task_dir / "platform" / f"launch.{os_name}.json"
    try:
        descriptor = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TierCError(f"{task_dir.name}: unreadable descriptor {path.name}: {error}") from error
    if descriptor.get("platform") != os_name or descriptor.get("descriptor_version") != "1":
        raise TierCError(f"{task_dir.name}: {path.name} is not a version 1 {os_name} descriptor")
    semantics = descriptor.get("semantics")
    if not isinstance(semantics, dict):
        raise TierCError(f"{task_dir.name}: {path.name} has no semantics block")
    for key in ("setup", "verify"):
        if not _is_argv(semantics.get("reset", {}).get(key)):
            raise TierCError(f"{task_dir.name}: reset.{key} is not a command line")
    if not _is_argv(semantics.get("evaluate")):
        raise TierCError(f"{task_dir.name}: evaluate is not a command line")
    return descriptor


def _is_argv(value: Any) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(part, str) for part in value)


def expand(template: list[str], values: dict[str, str]) -> list[str]:
    """Fill a descriptor command line. `${python}` becomes this interpreter
    without environment or user site-packages; every other `${name}` must be known, and a placeholder
    inside a longer argument is refused (no string building)."""
    argv: list[str] = []
    for part in template:
        if part == "${python}":
            # Not -I: the task's scripts import their sibling modules from
            # the script's own folder, which -I drops. -E -s still ignore
            # PYTHON* variables and user site-packages; the folder itself is
            # verified file by file before anything runs.
            argv.extend([sys.executable, "-E", "-s"])
        elif part.startswith("${") and part.endswith("}"):
            name = part[2:-1]
            if name not in values:
                raise TierCError(f"unknown placeholder {part}")
            argv.append(values[name])
        elif "${" in part:
            raise TierCError(f"placeholder inside an argument: {part}")
        else:
            argv.append(part)
    return argv


def _env(scratch: Path) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in _KEPT_ENV}
    env.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "HOME": str(scratch),
            "USERPROFILE": str(scratch),
            "TEMP": str(scratch),
            "TMP": str(scratch),
            "TMPDIR": str(scratch),
        }
    )
    return env


@dataclass
class Episode:
    status: str
    observed: str
    seconds: float
    score: Optional[float] = None


def _run(argv: list[str], task_dir: Path, env: dict[str, str]) -> Optional[int]:
    """Exit code, or None on timeout. Output is discarded (never reported)."""
    try:
        done = subprocess.run(
            argv,
            cwd=task_dir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=STEP_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None
    return done.returncode


def run_noop_episode(task_dir: Path, os_name: str) -> Episode:
    started = time.perf_counter()

    def done(status: str, observed: str, score: Optional[float] = None) -> Episode:
        return Episode(status, observed, time.perf_counter() - started, score)

    semantics = load_descriptor(task_dir, os_name)["semantics"]
    root = Path(tempfile.mkdtemp(prefix="orcel-tierc-"))
    try:
        workspace, artifacts, scratch = root / "workspace", root / "artifacts", root / "scratch"
        for folder in (workspace, artifacts, scratch):
            folder.mkdir()
        result = root / "result.json"
        values = {
            "workspace": str(workspace),
            "artifacts": str(artifacts),
            "result": str(result),
            # Nothing ran, so nothing failed.
            "agent_exit_code": "0",
        }
        env = _env(scratch)
        for phase in ("setup", "verify"):
            code = _run(expand(semantics["reset"][phase], values), task_dir, env)
            if code is None:
                return done("error", f"reset-{phase}-timeout")
            if code != 0:
                return done("error", f"reset-{phase}-failed")
        code = _run(expand(semantics["evaluate"], values), task_dir, env)
        if code is None:
            return done("error", "evaluator-timeout")
        if code != 0:
            return done("error", "evaluator-failed")
        try:
            outcome = json.loads(result.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return done("error", "evaluator-no-result")
        passed, score = outcome.get("passed"), outcome.get("score")
        if not isinstance(passed, bool) or not isinstance(score, (int, float)):
            return done("error", "evaluator-bad-result")
        if passed or score >= 1:
            # A no-op scored as a solution: the pipeline cannot be trusted.
            return done("fail", "noop-scored-as-solved", float(score))
        return done("pass", "noop-rejected", float(score))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def run_noop(pack: Path, os_name: Optional[str] = None) -> list[dict[str, Any]]:
    """One report row per task of the verified taskpack at `pack`."""
    os_name = os_name or platform_name()
    tasks = sorted(path for path in (pack / "tasks" / "shared").iterdir() if path.is_dir())
    if not tasks:
        raise TierCError("the taskpack has no tasks")
    rows = []
    for task_dir in tasks:
        episode = run_noop_episode(task_dir, os_name)
        millis = round(episode.seconds * 1000, 3)
        rows.append(
            {
                "case": f"tierc-noop/{task_dir.name}/{os_name}",
                "status": episode.status,
                "observed": episode.observed,
                "latency_ms": {"p50": millis, "p95": millis},
                "steps": 0,
                "model_calls": 0,
                "tokens_in": 0,
                "tokens_out": 0,
            }
        )
    return rows
