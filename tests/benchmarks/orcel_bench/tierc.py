"""BM-02 Tier C, slice C1 (ORCEL_EXECUTION_PLAN.md): the harness around the
pinned cua-driver-bench GUI tasks, before any GUI runs.

Orcel-owned. For each task of a verified taskpack and the platform
descriptor of this OS (`platform/launch.<os>.json`), an episode:

1. a fresh copy of the verified task folder, a workspace, an artifacts
   folder and a result path, all in a private temp folder (the pack itself
   is never run from, so nothing a task writes can reach it);
2. the task's own reset `setup`, then its reset `verify` (both must exit 0);
3. no plan (this is the no-op baseline: nothing drives the apps yet);
4. the task's own evaluator, exactly as the descriptor's `evaluate` command
   line says, on the untouched workspace;
5. teardown: every folder of the episode removed.

The case passes only when reset works and the evaluator rejects the
untouched workspace (`passed` false, score below 1): that proves the reset
and scoring pipeline is wired correctly and that a no-op is never scored as
a solution. It says nothing about GUI success. Commands are the task's own,
run with this interpreter (`-E -s -B`: no PYTHON* variables, no user
site-packages, no bytecode written) and a scrubbed environment. The pack is
verified against its lock file by file at the start of every run. Reports
carry fixed codes and latency only, never the score, task text or
evaluator detail.

Trust basis: the task code is third-party (pinned by commit and verified
blob by blob, FD-04) and runs with the account's own file access; there is
no sandbox beyond the scrubbed environment and private folders. Real-pack
runs belong on CI or disposable VMs, as the Tier C plan says.
"""

from __future__ import annotations

import json
import math
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
            # the script's own folder, which -I drops. -E -s ignore PYTHON*
            # variables and user site-packages, and -B writes no bytecode
            # (-E would otherwise ignore PYTHONDONTWRITEBYTECODE). The folder
            # is the episode's own copy of the verified task.
            argv.extend([sys.executable, "-E", "-s", "-B"])
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


def run_noop_episode(verified_task: Path, os_name: str) -> Episode:
    started = time.perf_counter()

    def done(status: str, observed: str, score: Optional[float] = None) -> Episode:
        return Episode(status, observed, time.perf_counter() - started, score)

    semantics = load_descriptor(verified_task, os_name)["semantics"]
    root = Path(tempfile.mkdtemp(prefix="orcel-tierc-"))
    try:
        # The episode runs from its own copy: the verified pack is never
        # written to, whatever the task's code does.
        task_dir = root / "task"
        shutil.copytree(verified_task, task_dir, symlinks=False)
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
        if (
            not isinstance(passed, bool)
            or isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not math.isfinite(score)
        ):
            return done("error", "evaluator-bad-result")
        if passed or score >= 1:
            # A no-op scored as a solution: the pipeline cannot be trusted.
            return done("fail", "noop-scored-as-solved", float(score))
        return done("pass", "noop-rejected", float(score))
    finally:
        shutil.rmtree(root, ignore_errors=True)


def run_noop(pack: Path, lock: Optional[dict[str, Any]], os_name: Optional[str] = None) -> list[dict[str, Any]]:
    """One report row per task of the taskpack at `pack`, which is verified
    against `lock` file by file first. Only the harness's own tests pass
    `lock=None`, for stand-in packs that have no lock."""
    if lock is not None:
        from .taskpack import TaskpackError, verify

        try:
            verify(lock, pack)
        except TaskpackError as error:
            raise TierCError(f"the taskpack does not verify: {error}") from error
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
