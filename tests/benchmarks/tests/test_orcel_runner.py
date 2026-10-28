"""BM-02: the Orcel runner's own failure handling.

These tests check how the runner classifies an orceld that crashes, hangs,
breaks the protocol, changes the workspace or refuses unexpectedly. They use
small stand-in programs (this Python interpreter running a script) in place of
orceld, and test only the runner: Orcel results come from the real orceld
(crates/orceld/tests/bm02_orcel_benchmark.rs runs the task set through it on
every OS).
"""

from __future__ import annotations

import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))

from orcel_bench.orcel_runner import load_orcel_task, run_orcel  # noqa: E402
from orcel_bench.runner import TaskLoadError, report  # noqa: E402

COMMIT = "0123456789abcdef0123456789abcdef01234567"

TASK = """
import orcel_bench as ob

@ob.tasks_config
def load():
    return [ob.Task(description="list the root", task_id="only")]

@ob.setup_task
async def setup(task, session):
    await session.write_file("a.txt", "a\\n")

@ob.orcel_plan
def plan(task, orcel):
    return [entry["name"] for entry in orcel.call("fs.list", "list", ".")["entries"]]

@ob.evaluate_task
async def evaluate(task, session):
    return session.answer == ["a.txt"]
"""

# Stand-ins for orceld: each reads one request per line and behaves badly in
# one way (or answers like orceld would, for the control).
STANDINS = {
    "answers": """
import json, os, sys, pathlib
audit = pathlib.Path(os.environ["ORCEL_AUDIT_PATH"])
audit.parent.mkdir(parents=True, exist_ok=True)
for line in sys.stdin:
    request = json.loads(line)
    with audit.open("a") as handle:
        handle.write("{}" + chr(10))
    print(json.dumps({"version": 1, "request_id": request["request_id"], "ok": True,
                      "result": {"entries": [{"name": "a.txt", "is_file": True, "is_dir": False}]}}), flush=True)
""",
    "unaudited": """
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"version": 1, "request_id": request["request_id"], "ok": True,
                      "result": {"entries": [{"name": "a.txt", "is_file": True, "is_dir": False}]}}), flush=True)
""",
    "oversized": """
import sys
for line in sys.stdin:
    sys.stdout.write("x" * (9 << 20) + chr(10))
    sys.stdout.flush()
""",
    "exits": "import sys; sys.exit(3)\n",
    "hangs": "import sys, time\nfor line in sys.stdin:\n    time.sleep(60)\n",
    "wrong-id": """
import json, sys
for line in sys.stdin:
    print(json.dumps({"version": 1, "request_id": "other", "ok": True, "result": {}}), flush=True)
""",
    "not-json": "import sys\nfor line in sys.stdin:\n    print('garbage', flush=True)\n",
    "refuses": """
import json, sys
for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps({"version": 1, "request_id": request["request_id"], "ok": False,
                      "error": {"code": "POLICY_DENIED", "message": "no"}}), flush=True)
""",
    "writes": """
import json, os, sys, pathlib
for line in sys.stdin:
    request = json.loads(line)
    pathlib.Path(os.environ["ORCEL_WORKSPACE_ROOT"], "b.txt").write_text("changed")
    print(json.dumps({"version": 1, "request_id": request["request_id"], "ok": True,
                      "result": {"entries": [{"name": "a.txt", "is_file": True, "is_dir": False}]}}), flush=True)
""",
}


class OrcelRunnerFailures(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        root = Path(self.scratch.name)
        self.task = root / "probe" / "list-root"
        self.task.mkdir(parents=True)
        (self.task / "main.py").write_text(textwrap.dedent(TASK), encoding="utf-8")
        self.scripts = {}
        for name, body in STANDINS.items():
            script = root / f"{name}.py"
            script.write_text(textwrap.dedent(body), encoding="utf-8")
            self.scripts[name] = script

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def run_with(self, standin: str, **kwargs):
        trace = Path(self.scratch.name) / f"{standin}.jsonl"
        rows = run_orcel(
            [self.task],
            Path(sys.executable),
            orceld_args=(str(self.scripts[standin]),),
            trace=trace,
            **kwargs,
        )
        return rows, [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]

    def test_a_well_behaved_orceld_solves_the_task_and_is_traced(self) -> None:
        (row,), (episode,) = self.run_with("answers")
        self.assertEqual((row["status"], row["observed"], row["steps"]), ("pass", "solved", 1))
        self.assertEqual(episode["orcel_calls"][0]["capability"], "fs.list")
        self.assertNotIn("a.txt", json.dumps(episode), "the trace never carries file names or contents")

    def test_each_failure_is_classified(self) -> None:
        cases = {
            "exits": ("error", "orcel-crash"),
            "wrong-id": ("error", "orcel-protocol"),
            "not-json": ("error", "orcel-protocol"),
            "refuses": ("fail", "orcel-refused"),
            "writes": ("fail", "workspace-changed"),
            "unaudited": ("fail", "unaudited"),
            "oversized": ("error", "orcel-protocol"),
        }
        for standin, expected in cases.items():
            with self.subTest(standin):
                (row,), _ = self.run_with(standin)
                self.assertEqual((row["status"], row["observed"]), expected)

    def test_a_hung_orceld_times_out(self) -> None:
        (row,), _ = self.run_with("hangs", call_timeout=1.0)
        self.assertEqual((row["status"], row["observed"]), ("error", "orcel-timeout"))

    def test_rows_are_valid_report_rows(self) -> None:
        rows, _ = self.run_with("answers", repeat=3)
        produced = report(COMMIT, rows, {"kind": "deterministic", "name": "orcel-fs-planner", "version": "1"})
        self.assertEqual(produced["planner"]["name"], "orcel-fs-planner")
        self.assertEqual(rows[0]["model_calls"], 0)

    def test_an_answer_that_bypasses_orcel_fails(self) -> None:
        # A plan that answers from what it was handed, with no Orcel call.
        (self.task / "main.py").write_text(
            textwrap.dedent(TASK).replace(
                'return [entry["name"] for entry in orcel.call("fs.list", "list", ".")["entries"]]',
                'return ["a.txt"]',
            ),
            encoding="utf-8",
        )
        (row,), _ = self.run_with("answers")
        self.assertEqual((row["status"], row["observed"]), ("fail", "no-orcel-call"))

    def test_a_plan_sees_only_declared_inputs_and_call(self) -> None:
        seen = Path(self.scratch.name) / "seen.json"
        body = (
            textwrap.dedent(TASK)
            .replace(
                'ob.Task(description="list the root", task_id="only")',
                'ob.Task(description="list the root", task_id="only", metadata={"truth": ["a.txt"], "inputs": {"where": "."}})',
            )
            .replace(
                "def plan(task, orcel):\n",
                "def plan(task, orcel):\n"
                "    import json, pathlib\n"
                f"    pathlib.Path({str(seen)!r}).write_text(json.dumps("
                "{'metadata': task.metadata, 'attrs': sorted(a for a in dir(orcel) if not a.startswith('_'))}))\n",
            )
        )
        (self.task / "main.py").write_text(body, encoding="utf-8")
        (row,), _ = self.run_with("answers")
        self.assertEqual(row["status"], "pass")
        self.assertEqual(json.loads(seen.read_text(encoding="utf-8")), {"metadata": {"where": "."}, "attrs": ["call"]})

    def test_a_task_without_a_plan_is_refused(self) -> None:
        (self.task / "main.py").write_text("import orcel_bench as ob\n", encoding="utf-8")
        with self.assertRaises(TaskLoadError):
            load_orcel_task(self.task)

    def test_every_shipped_orcel_task_loads_with_unique_variants(self) -> None:
        tasks = sorted(path.parent for path in (BENCH / "orcel-tasks").glob("*/*/main.py"))
        variants = 0
        for directory in tasks:
            module = load_orcel_task(directory)
            variants += len(module.functions["tasks_config"]())
        self.assertGreaterEqual(variants, 20)


if __name__ == "__main__":
    unittest.main()
