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
            rest = part[len(token):]
            if ".." in rest.replace("\\", "/").split("/"):
                raise TierCError(f"a launch path may not climb out of its folder: {part!r}")
            return value + rest
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


def _app_env(scratch: Path, unset: list[str]) -> dict[str, str]:
    """The environment for npm and the task's apps: the scrubbed task
    environment plus what Node, npm and Electron need, every per-user folder
    inside the episode's scratch."""
    env = _env(scratch)
    for key in ("COMSPEC", "ComSpec", "PATHEXT", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE"):
        if key in os.environ:
            env[key] = os.environ[key]
    for key, folder in (("APPDATA", "appdata"), ("LOCALAPPDATA", "localappdata"), ("npm_config_cache", "npm-cache"),
                        ("ELECTRON_CACHE", "electron-cache"), ("XDG_CACHE_HOME", "cache")):
        path = scratch / folder
        path.mkdir(exist_ok=True)
        env[key] = str(path)
    for key in unset:
        env.pop(key, None)
    return env


def _left_running(root: Path) -> list[int]:
    """Process ids whose executable or command line is under `root`."""
    if os.name != "nt":
        return []
    # The folder goes in through the environment, never pasted into the
    # script, so no character in it can change the query.
    script = (
        "$root = $env:ORCEL_TIERC_ROOT; Get-CimInstance Win32_Process | Where-Object { "
        "($_.ExecutablePath -and $_.ExecutablePath.StartsWith($root, 'OrdinalIgnoreCase')) -or "
        "($_.CommandLine -and $_.CommandLine.IndexOf($root, [StringComparison]::OrdinalIgnoreCase) -ge 0) } "
        "| Where-Object { $_.ProcessId -ne $PID } | ForEach-Object { $_.ProcessId }"
    )
    done = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                          capture_output=True, text=True, timeout=60, check=False,
                          env=dict(os.environ, ORCEL_TIERC_ROOT=str(root)))
    return [int(line) for line in done.stdout.split() if line.strip().isdigit()]


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


class Episode:
    """One prepared episode: a verified task copy, a reset workspace and the
    descriptor's pinned prerequisite installs, all under a private root."""

    def __init__(self, pack: Path, lock: Optional[dict[str, Any]], task: str, purpose: str) -> None:
        if os.environ.get("GITHUB_ACTIONS") != "true" and os.environ.get("ORCEL_TIERC_ALLOW_LOCAL") != "1":
            raise TierCError(f"{purpose} opens windows and lists the session's windows: CI runners only")
        if lock is not None:
            from .taskpack import TaskpackError, verify

            try:
                verify(lock, pack)
            except TaskpackError as error:
                raise TierCError(f"the taskpack does not verify: {error}") from error
        self.task = task
        self.os_name = platform_name()
        verified_task = pack / "tasks" / "shared" / task
        descriptor = load_descriptor(verified_task, self.os_name)
        self.apps = electron_apps(descriptor)
        if not self.apps:
            raise TierCError(f"{task}: no Electron app in the {self.os_name} descriptor")
        self.semantics = descriptor["semantics"]
        self.root = Path(tempfile.mkdtemp(prefix="orcel-tierc-gui-"))
        self.launched: list[subprocess.Popen[bytes]] = []
        self.bundle = self.root / "task"
        shutil.copytree(verified_task, self.bundle, symlinks=False)
        self.workspace, self.artifacts, self.scratch = self.root / "workspace", self.root / "artifacts", self.root / "scratch"
        for folder in (self.workspace, self.artifacts, self.scratch):
            folder.mkdir()
        self.values = {
            "bundle": str(self.bundle),
            "workspace": str(self.workspace),
            "artifacts": str(self.artifacts),
            "result": str(self.root / "result.json"),
            "agent_exit_code": "0",
        }
        self.env = _env(self.scratch)
        for phase in ("setup", "verify"):
            done = subprocess.run(expand(self.semantics["reset"][phase], self.values), cwd=self.bundle, env=self.env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
            if done.returncode != 0:
                raise TierCError(f"{task}: reset {phase} failed")
        # The descriptor's own prerequisite installs (pinned lockfiles).
        installed: set[str] = set()
        for app in self.apps:
            cwd = _fill(app["cwd"], self.values)
            if cwd in installed:
                continue
            npm = "npm.cmd" if os.name == "nt" else "npm"
            done = subprocess.run([npm, "ci", "--no-audit", "--no-fund"], cwd=cwd, env=_app_env(self.scratch, []),
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=INSTALL_TIMEOUT_S, check=False)
            if done.returncode != 0:
                raise TierCError(f"{task}: npm ci failed in {Path(cwd).name}")
            installed.add(cwd)

    def launch(self, app: dict[str, Any]) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(
            [_fill(part, self.values) for part in app["command"]],
            cwd=_fill(app["cwd"], self.values),
            env=_app_env(self.scratch, list(app.get("unset_env", []))),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.launched.append(process)
        return process

    def evaluate(self) -> Optional[dict[str, Any]]:
        """The task's evaluator; its result, or None when it failed."""
        done = subprocess.run(expand(self.semantics["evaluate"], self.values), cwd=self.bundle, env=self.env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120, check=False)
        result = self.root / "result.json"
        if done.returncode != 0 or not result.is_file():
            return None
        return json.loads(result.read_text(encoding="utf-8"))

    def teardown(self, orcel: Orceld, titles: list[str]) -> tuple[list[str], list[int]]:
        """Stop every launched tree; the titles orceld still lists and the
        processes left running from the episode folder (killed)."""
        for process in self.launched:
            _kill_tree(process)
        deadline = time.monotonic() + 30
        remaining = list(titles)
        while remaining and time.monotonic() < deadline:
            listed = _titles(orcel)
            remaining = [title for title in remaining if title in listed]
            if remaining:
                time.sleep(1.0)
        leftover = _left_running(self.root)
        for pid in leftover:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False)
        return remaining, leftover

    def close(self) -> None:
        for process in self.launched:
            _kill_tree(process)
        shutil.rmtree(self.root, ignore_errors=True)
        if self.root.exists():
            print(f"tierc: the episode folder could not be removed: {self.root}", file=sys.stderr)


def _row(case: str, status: str, observed: str, started: float, steps: int) -> dict[str, Any]:
    millis = round((time.perf_counter() - started) * 1000, 3)
    return {
        "case": case,
        "status": status,
        "observed": observed,
        "latency_ms": {"p50": millis, "p95": millis},
        "steps": steps,
        "model_calls": 0,
        "tokens_in": 0,
        "tokens_out": 0,
    }


def run_observe_episode(pack: Path, lock: Optional[dict[str, Any]], task: str, orceld: Path) -> list[dict[str, Any]]:
    """C2a: one report row per Electron app of `task`, observed only."""
    episode = Episode(pack, lock, task, "tierc-observe")
    rows: list[dict[str, Any]] = []
    try:
        with Orceld(orceld, episode.workspace) as orcel:
            for app in episode.apps:
                started = time.perf_counter()
                calls_before = len(orcel.calls)
                status, observed = "pass", "observed"
                episode.launch(app)
                try:
                    entry = _find_window(orcel, app["window"]["title"])
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
                rows.append(_row(f"tierc-observe/{task}/{app['id']}/{episode.os_name}", status, observed,
                                 started, len(orcel.calls) - calls_before))
            outcome = episode.evaluate()
            remaining, leftover = episode.teardown(orcel, [app["window"]["title"] for app in episode.apps])
        for row in rows:
            if row["status"] != "pass":
                continue
            if outcome is None:
                row["status"], row["observed"] = "error", "evaluator-failed"
            elif outcome.get("passed") is not False:
                row["status"], row["observed"] = "fail", "evaluator-did-not-reject"
            elif remaining:
                row["status"], row["observed"] = "fail", "window-left-after-teardown"
            elif leftover:
                row["status"], row["observed"] = "fail", "process-left-after-teardown"
        return rows
    finally:
        episode.close()


def load_plan(path: Path) -> dict[str, Any]:
    plan = json.loads(path.read_text(encoding="utf-8"))
    if not str(plan.get("label", "")).startswith("scripted-plan"):
        raise TierCError("a Tier C plan must be labelled scripted-plan")
    for key in ("task", "app", "window_title", "targets", "must_stay_passed", "steps"):
        if key not in plan:
            raise TierCError(f"the plan has no {key}")
    return plan


def judge_act(plan: dict[str, Any], acted: dict[str, Any], outcome: Optional[dict[str, Any]],
              remaining: bool, leftover: bool, reach_only: bool) -> tuple[str, str]:
    """The row status and observed code for one act episode (pure; tested)."""
    calls = acted.get("calls", [])
    expected = "reached-and-gated" if reach_only else "completed"
    if acted.get("outcome") != expected:
        return "fail", str(acted.get("outcome"))[:64]
    if outcome is None:
        return "error", "evaluator-failed"
    checks = outcome.get("detail", {}).get("checks", {})

    def passed(name: str) -> bool:
        check = checks.get(name)
        return isinstance(check, dict) and check.get("passed") is True

    if reach_only:
        # Slice 3a: every target reached through the scoped read and the
        # first action refused for want of a person-granted Full User lease.
        # Each target check must be present and not passed (nothing written,
        # not merely absent), and the preserved checks must still pass.
        if any(not isinstance(checks.get(name), dict) for name in plan["targets"]):
            return "fail", "target-check-missing"
        if any(passed(name) for name in plan["targets"]):
            return "fail", "gated-action-wrote"
        observed = "form-reached-actions-gated"
    else:
        if any(not passed(name) for name in plan["targets"]):
            return "fail", "target-check-not-passed"
        count = sum(1 for name in checks if passed(name))
        observed = f"scripted-checks-{count}-of-{len(checks)}"
    if any(not passed(name) for name in plan["must_stay_passed"]):
        return "fail", "preserved-check-broken"
    if acted.get("audit_records", 0) < len(calls):
        return "fail", "unaudited"
    if remaining:
        return "fail", "window-left-after-teardown"
    if leftover:
        return "fail", "process-left-after-teardown"
    return "pass", observed


def run_act_episode(pack: Path, lock: Optional[dict[str, Any]], plan_path: Path, orceld: Path, act_test: Path,
                    reach_only: bool = False) -> list[dict[str, Any]]:
    """C2b: one report row for a scripted plan acting through orceld's
    approval-gated UIA shapes in its test build (scripted SOFT consent).

    The row passes when every targeted evaluator check passes, every
    must-stay-passed check still passes, each call orceld answered was
    audited, and teardown leaves no window or process behind. The observed
    code records how many of the evaluator's checks pass (counts only)."""
    plan = load_plan(plan_path)
    episode = Episode(pack, lock, plan["task"], "tierc-act")
    started = time.perf_counter()
    try:
        app = next((a for a in episode.apps if a["id"] == plan["app"]), None)
        if app is None or app["window"]["title"] != plan["window_title"]:
            raise TierCError("the plan's app or window title is not in the task's descriptor")
        with Orceld(orceld, episode.workspace) as orcel:
            episode.launch(app)
            # The title changes while the page loads; act only once it has
            # held across two listings a few seconds apart.
            found = _find_window(orcel, plan["window_title"])
            if found is not None:
                time.sleep(3.0)
                found = _find_window(orcel, plan["window_title"])
            if found is None:
                episode.teardown(orcel, [plan["window_title"]])
                return [_row(f"tierc-act/{plan['task']}/{plan['app']}/{episode.os_name}", "fail", "window-not-found", started, 0)]
            state = episode.root / "act-state"
            state.mkdir()
            result_path = episode.root / "act-result.json"
            act_env = dict(os.environ)
            act_env.update({
                "ORCEL_TIERC_ACT_PLAN": str(plan_path),
                "ORCEL_TIERC_ACT_WORKSPACE": str(episode.workspace),
                "ORCEL_TIERC_ACT_RESULT": str(result_path),
                "ORCEL_TIERC_ACT_STATE": str(state),
                "ORCEL_TIERC_ACT_MODE": "reach" if reach_only else "act",
            })
            done = subprocess.run(
                [str(act_test), "--ignored", "--exact", "bm02_tier_c_act_tests::bm02_tier_c_scripted_plan_acts_through_orceld", "--nocapture"],
                env=act_env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=600, check=False,
            )
            # The act test's own diagnostics go to the log, never the report.
            for line in done.stderr.decode("utf-8", "replace").splitlines():
                if line.startswith("TIERC-ACT-DIAG"):
                    print(line[:2000], file=sys.stderr)
            acted = json.loads(result_path.read_text(encoding="utf-8")) if done.returncode == 0 and result_path.is_file() else None
            time.sleep(2.0)
            outcome = episode.evaluate()
            remaining, leftover = episode.teardown(orcel, [plan["window_title"]])
        case = f"tierc-act/{plan['task']}/{plan['app']}/{episode.os_name}"
        if acted is None:
            return [_row(case, "error", "act-run-failed", started, 0)]
        calls = acted.get("calls", [])
        status, observed = judge_act(plan, acted, outcome, bool(remaining), bool(leftover), reach_only)
        return [_row(case, status, observed, started, len(calls))]
    finally:
        episode.close()
