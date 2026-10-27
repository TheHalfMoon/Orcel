"""BM-02: the oracle-only dry run and the runner's guards.

Run from the repository root:

    python3 -m unittest discover -s tests/benchmarks/tests -t tests/benchmarks -v
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
REPO = BENCH.parent.parent
sys.path.insert(0, str(BENCH))

from orcel_bench import FileSession, SessionError  # noqa: E402
from orcel_bench.__main__ import all_tasks, main  # noqa: E402
from orcel_bench.runner import TaskLoadError, load_task, report, reward_of, run_oracle  # noqa: E402

COMMIT = "0123456789abcdef0123456789abcdef01234567"


def write_task(root: Path, group: str, name: str, body: str) -> Path:
    directory = root / group / name
    directory.mkdir(parents=True)
    (directory / "main.py").write_text(textwrap.dedent(body), encoding="utf-8")
    return directory


BROKEN = """
    import orcel_bench as ob

    @ob.tasks_config
    def load():
        return [ob.Task(description="write ok", task_id="only")]

    @ob.setup_task
    async def setup(task, session):
        pass

    @ob.solve_task
    async def solve(task, session):
        await session.write_file("answer.txt", "wrong")

    @ob.evaluate_task
    async def evaluate(task, session):
        return [1.0 if (await session.read_file("answer.txt")) == "ok" else 0.0]
"""

RAISES = """
    import orcel_bench as ob

    @ob.tasks_config
    def load():
        return [ob.Task(description="x")]

    @ob.setup_task
    async def setup(task, session):
        pass

    @ob.solve_task
    async def solve(task, session):
        raise RuntimeError("sk-" + "secret-looking message that must not reach the report")

    @ob.evaluate_task
    async def evaluate(task, session):
        return 1.0
"""


SLEEPS = """
    import time
    import orcel_bench as ob

    @ob.tasks_config
    def load():
        return [ob.Task(description="x")]

    @ob.setup_task
    async def setup(task, session):
        pass

    @ob.solve_task
    async def solve(task, session):
        time.sleep(3)

    @ob.evaluate_task
    async def evaluate(task, session):
        return 1.0
"""

RAISES_TIMEOUT = """
    import orcel_bench as ob

    @ob.tasks_config
    def load():
        return [ob.Task(description="x")]

    @ob.setup_task
    async def setup(task, session):
        pass

    @ob.solve_task
    async def solve(task, session):
        raise TimeoutError("the task's own")

    @ob.evaluate_task
    async def evaluate(task, session):
        return 1.0
"""

# Variants with the given task ids (None: the index is used).
OK_TASK = """
    import orcel_bench as ob

    @ob.tasks_config
    def load():
        return [ob.Task(description="x", task_id=i) for i in ({ids},)]

    @ob.setup_task
    async def setup(task, session):
        pass

    @ob.solve_task
    async def solve(task, session):
        pass

    @ob.evaluate_task
    async def evaluate(task, session):
        return 1.0
"""


class OracleDryRun(unittest.TestCase):
    def test_every_orcel_task_is_solved_by_its_oracle_and_the_report_validates(self) -> None:
        tasks = all_tasks()
        self.assertGreaterEqual(len(tasks), 2)
        with tempfile.TemporaryDirectory() as scratch:
            out = Path(scratch) / "oracle.report.json"
            self.assertEqual(main(["oracle", "--commit", COMMIT, "--out", str(out), "--repeat", "3"]), 0)
            produced = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(produced["suite"], "journeys")
            self.assertEqual(produced["planner"], {"kind": "deterministic", "name": "oracle", "version": "1"})
            cases = [row["case"] for row in produced["rows"]]
            self.assertIn("orcel/hello-file/hello", cases)
            self.assertIn("orcel/report-rename/three", cases)
            self.assertTrue(all(row["status"] == "pass" and row["observed"] == "solved" for row in produced["rows"]))
            node = shutil.which("node")
            if node is None:
                # Under CI the report must be checked, never skipped.
                if os.environ.get("CI"):
                    self.fail("node is required under CI to check the report")
                self.skipTest("node is not installed; the report shape is checked by CI")
            checked = subprocess.run(
                [node, str(REPO / "scripts" / "check-benchmark-report.mjs"), str(out)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_a_wrong_solution_is_reported_unsolved(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            directory = write_task(Path(scratch), "probe", "broken", BROKEN)
            (row,) = run_oracle([directory])
            self.assertEqual((row["case"], row["status"], row["observed"]), ("probe/broken/only", "fail", "unsolved"))

    def test_a_raising_phase_is_an_error_with_a_fixed_code_and_no_message(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            directory = write_task(Path(scratch), "probe", "raises", RAISES)
            (row,) = run_oracle([directory])
            self.assertEqual((row["status"], row["observed"]), ("error", "solve-error"))
            self.assertNotIn("secret", json.dumps(report(COMMIT, [row])))

    def test_a_task_missing_a_function_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            directory = write_task(Path(scratch), "probe", "partial", "import orcel_bench as ob\n")
            with self.assertRaises(TaskLoadError):
                load_task(directory)

    def test_rewards(self) -> None:
        self.assertEqual(reward_of([1.0, 0.0]), 0.5)
        self.assertEqual(reward_of(True), 1.0)
        self.assertEqual(reward_of(1), 1.0)
        for bad in [float("nan"), "1.0", None, [], [1.0, None], [1.0, "x"], [1.5, 0.5], -0.1, 2]:
            self.assertIsNone(reward_of(bad), repr(bad))

    def test_a_blocking_phase_times_out_and_a_task_timeout_error_is_a_phase_error(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            sleeps = write_task(Path(scratch), "probe", "sleeps", SLEEPS)
            (row,) = run_oracle([sleeps], timeout=0.5)
            self.assertEqual((row["status"], row["observed"]), ("error", "timeout"))
            raises = write_task(Path(scratch), "probe", "raises-timeout", RAISES_TIMEOUT)
            (row,) = run_oracle([raises], timeout=5)
            self.assertEqual((row["status"], row["observed"]), ("error", "solve-error"))

    def test_case_ids_are_checked_unique_and_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            bad_group = write_task(Path(scratch), "My Group", "ok", OK_TASK.format(ids='"v"'))
            with self.assertRaises(TaskLoadError):
                run_oracle([bad_group])
            duplicate = write_task(Path(scratch), "probe", "dup", OK_TASK.format(ids='None, "0"'))
            with self.assertRaises(TaskLoadError):
                run_oracle([duplicate])
            long = write_task(Path(scratch), "probe", "long", OK_TASK.format(ids='"a" * 300'))
            with self.assertRaises(TaskLoadError):
                run_oracle([long])

    def test_report_needs_a_full_commit(self) -> None:
        with self.assertRaises(ValueError):
            report("abc123", [])


class SessionConfinement(unittest.TestCase):
    def test_paths_stay_inside_the_workspace(self) -> None:
        session = FileSession()
        try:
            for bad in ["", "/etc/passwd", "../x", "a/../../x", "a\\b", "./a", "a//b", "C:/x", "C:x", "a:stream", "a.", "a/b ", ".", "x\0y", "CON", "dir/nul.txt", "com1"]:
                with self.assertRaises(SessionError, msg=bad):
                    asyncio.run(session.write_file(bad, "x"))
            asyncio.run(session.write_file("dir/ok.txt", "fine"))
            self.assertEqual(asyncio.run(session.read_file("dir/ok.txt")), "fine")
        finally:
            session.close()

    @unittest.skipIf(os.name == "nt", "creating a symlink needs a privilege on Windows")
    def test_a_link_out_of_the_workspace_is_refused(self) -> None:
        session = FileSession()
        outside = Path(tempfile.mkdtemp())
        try:
            (session.root / "link").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(SessionError):
                asyncio.run(session.write_file("link/escape.txt", "x"))
            self.assertFalse((outside / "escape.txt").exists())
        finally:
            session.close()
            shutil.rmtree(outside, ignore_errors=True)

    def test_a_write_past_its_check_does_not_recreate_an_ended_workspace(self) -> None:
        session = FileSession()
        root = session.root
        target = root / "sub" / "late.txt"
        # The path check passed before the session ended.
        session.close()
        with self.assertRaises(SessionError):
            session._make_parents(target)
        self.assertFalse(root.exists())

    def test_the_workspace_is_removed_and_the_session_ends(self) -> None:
        session = FileSession()
        root = session.root
        asyncio.run(session.write_file("a.txt", "x"))
        session.close()
        self.assertFalse(root.exists())
        with self.assertRaises(SessionError):
            asyncio.run(session.read_file("a.txt"))


if __name__ == "__main__":
    unittest.main()
