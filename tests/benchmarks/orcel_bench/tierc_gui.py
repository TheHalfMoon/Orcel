"""BM-02 Tier C, slice C2a (ORCEL_EXECUTION_PLAN.md): launch a pinned GUI
task's own apps on a disposable CI runner and observe them only through the
real orceld.

Orcel-owned. For one task of the verified taskpack and this OS's
descriptor, one episode:

1. a fresh copy of the verified task (`${bundle}`), a workspace and
   scratch folders in a private temp folder; the task's reset `setup` and
   `verify`;
2. the descriptor's own prerequisite installs for its Electron apps
   (`npm ci`, pinned by the app's lockfile), in the copy;
3. each Electron app launched exactly as the descriptor says;
4. the real orceld (the binary under test, over its stdio protocol) finds
   each app's window by its descriptor title with `uia.window list`, then
   observes it with `uia.window observe` and `uia.tree observe`. These are
   orceld's read-only shapes: no approval is asked and nothing is clicked
   or typed;
5. the task's evaluator on the still untouched workspace must reject it;
6. teardown: each app's whole process tree is stopped, orceld must no longer
   list its window, and every folder is removed.

This proves the launch, observation, scoring and cleanup path on a real
desktop session. It is not a solved task and not agent performance: no plan
runs and no action is taken. It never runs on a person's desktop (CI only,
unless explicitly allowed), because it opens windows and lists the
session's windows.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Optional

from .orcel import Orceld, OrcelError, OrcelRefused
from .tierc import TierCError, _env, expand, load_descriptor, platform_name

PLANNER = {"kind": "deterministic", "name": "tierc-observe-only", "version": "1"}
#: How long an app may take to show its window.
WINDOW_TIMEOUT_S = 90.0
#: How long the prerequisite install may take.
INSTALL_TIMEOUT_S = 600.0


def _fill(part: str, values: dict[str, str]) -> str:
    """One launch argument: a whole `${name}`, or `--flag=${name}`, or a
    path starting with `${bundle}`/`${workspace}`. Anything else with a
    placeholder is refused."""
    if "${" not in part:
        return part
    for name, value in values.items():
        token = "${" + name + "}"
        if part == token:
            return value
        if part.startswith("--") and part.endswith("=" + token) and part.count("${") == 1:
            return part[: -len(token)] + value
        if part.startswith(token + "/") and part.count("${") == 1:
            return value + part[len(token):]
    raise TierCError(f"unsupported placeholder use in {part!r}")


def electron_apps(descriptor: dict[str, Any]) -> list[dict[str, Any]]:
    apps = [app for app in descriptor.get("apps", []) if app.get("kind") == "electron"]
    for app in apps:
        if not isinstance(app.get("command"), list) or not app.get("window", {}).get("title"):
            raise TierCError(f"electron app {app.get('id')!r} has no command or window title")
    return apps


def _kill_tree(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(process.pid)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.kill()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def _titles(orcel: Orceld) -> list[str]:
    listing = orcel.call("uia.window", "list", None, {})
    return [str(entry.get("title", "")) for entry in listing.get("windows", [])]


def _find_window(orcel: Orceld, title: str) -> Optional[dict[str, Any]]:
    deadline = time.monotonic() + WINDOW_TIMEOUT_S
    while time.monotonic() < deadline:
        listing = orcel.call("uia.window", "list", None, {})
        for entry in listing.get("windows", []):
            if entry.get("title") == title:
                return entry
        time.sleep(1.0)
    return None


def run_observe_episode(pack: Path, lock: Optional[dict[str, Any]], task: str, orceld: Path) -> list[dict[str, Any]]:
    """One report row per Electron app of `task`."""
    if os.environ.get("GITHUB_ACTIONS") != "true" and os.environ.get("ORCEL_TIERC_ALLOW_LOCAL") != "1":
        raise TierCError("tierc-observe opens windows and lists the session's windows: CI runners only")
    if lock is not None:
        from .taskpack import TaskpackError, verify

        try:
            verify(lock, pack)
        except TaskpackError as error:
            raise TierCError(f"the taskpack does not verify: {error}") from error
    os_name = platform_name()
    verified_task = pack / "tasks" / "shared" / task
    descriptor = load_descriptor(verified_task, os_name)
    apps = electron_apps(descriptor)
    if not apps:
        raise TierCError(f"{task}: no Electron app in the {os_name} descriptor")
    semantics = descriptor["semantics"]
    root = Path(tempfile.mkdtemp(prefix="orcel-tierc-gui-"))
    rows: list[dict[str, Any]] = []
    launched: list[subprocess.Popen[bytes]] = []
    try:
        bundle = root / "task"
        shutil.copytree(verified_task, bundle, symlinks=False)
        workspace, artifacts, scratch = root / "workspace", root / "artifacts", root / "scratch"
        for folder in (workspace, artifacts, scratch):
            folder.mkdir()
        values = {
            "bundle": str(bundle),
            "workspace": str(workspace),
            "artifacts": str(artifacts),
            "result": str(root / "result.json"),
            "agent_exit_code": "0",
        }
        env = _env(scratch)
        for phase in ("setup", "verify"):
            done = subprocess.run(expand(semantics["reset"][phase], values), cwd=bundle, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
            if done.returncode != 0:
                raise TierCError(f"{task}: reset {phase} failed")
        # The descriptor's own prerequisite installs (pinned lockfiles).
        installed: set[str] = set()
        for app in apps:
            cwd = _fill(app["cwd"], values)
            if cwd in installed:
                continue
            npm = "npm.cmd" if os.name == "nt" else "npm"
            done = subprocess.run([npm, "ci", "--no-audit", "--no-fund"], cwd=cwd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=INSTALL_TIMEOUT_S, check=False)
            if done.returncode != 0:
                raise TierCError(f"{task}: npm ci failed in {Path(cwd).name}")
            installed.add(cwd)
        app_env = dict(os.environ)
        with Orceld(orceld, workspace) as orcel:
            for app in apps:
                started = time.perf_counter()
                observed = "observed"
                status = "pass"
                launch_env = {k: v for k, v in app_env.items() if k not in set(app.get("unset_env", []))}
                process = subprocess.Popen(
                    [_fill(part, values) for part in app["command"]],
                    cwd=_fill(app["cwd"], values),
                    env=launch_env,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                launched.append(process)
                title = app["window"]["title"]
                try:
                    entry = _find_window(orcel, title)
                    if entry is None:
                        status, observed = "fail", "window-not-found"
                    else:
                        orcel.call("uia.window", "observe", None, {
                            "window_id": entry["window_id"],
                            "expected_window_generation": entry["window_generation"],
                        })
                        tree = orcel.call("uia.tree", "observe", None, {
                            "window_id": entry["window_id"],
                            "expected_window_generation": entry["window_generation"],
                        })
                        if not tree.get("nodes"):
                            status, observed = "fail", "empty-tree"
                except OrcelRefused as refusal:
                    status, observed = "fail", f"orcel-refused-{refusal.code.lower()}"
                except OrcelError as error:
                    status, observed = "error", error.observed
                millis = round((time.perf_counter() - started) * 1000, 3)
                rows.append({
                    "case": f"tierc-observe/{task}/{app['id']}/{os_name}",
                    "status": status,
                    "observed": observed,
                    "latency_ms": {"p50": millis, "p95": millis},
                    "steps": len(orcel.calls),
                    "model_calls": 0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                })
            # The untouched workspace must still be rejected.
            done = subprocess.run(expand(semantics["evaluate"], values), cwd=bundle, env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
            outcome = json.loads((root / "result.json").read_text(encoding="utf-8")) if done.returncode == 0 else {}
            rejected = outcome.get("passed") is False
            # Teardown: every process tree stopped, and no window left.
            for process in launched:
                _kill_tree(process)
            deadline = time.monotonic() + 30
            remaining = [app["window"]["title"] for app in apps]
            while remaining and time.monotonic() < deadline:
                titles = _titles(orcel)
                remaining = [title for title in remaining if title in titles]
                if remaining:
                    time.sleep(1.0)
            for row in rows:
                if row["status"] == "pass" and not rejected:
                    row["status"], row["observed"] = "fail", "evaluator-did-not-reject"
                elif row["status"] == "pass" and remaining:
                    row["status"], row["observed"] = "fail", "window-left-after-teardown"
        return rows
    finally:
        for process in launched:
            _kill_tree(process)
        shutil.rmtree(root, ignore_errors=True)
