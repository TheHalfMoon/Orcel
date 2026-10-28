"""BM-02 Tier C, slice C1: the no-op baseline harness classifies each outcome.

Stand-in tasks (small scripts in the descriptor shape) check the harness
itself; the pinned taskpack's real tasks run in test_taskpack.py.
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

import orcel_bench.tierc as tierc  # noqa: E402
from orcel_bench.tierc import TierCError, expand, platform_name  # noqa: E402

OS = platform_name()

SETUP_OK = "import sys, pathlib\nw = pathlib.Path(sys.argv[sys.argv.index('--workspace') + 1])\n(w / 'state.json').write_text('{}')\n"
VERIFY_OK = "import sys, pathlib\nw = pathlib.Path(sys.argv[sys.argv.index('--workspace') + 1])\nsys.exit(0 if (w / 'state.json').is_file() else 1)\n"


def evaluator(passed: bool, score: float, exit_code: int = 0, write: bool = True) -> str:
    result = json.dumps({"passed": passed, "score": score, "detail": {"secret": "never reported"}})
    return textwrap.dedent(
        f"""
        import sys, pathlib
        from helper import ok  # a sibling module, as the real evaluators import
        result = pathlib.Path(sys.argv[sys.argv.index('--result') + 1])
        if {write!r}:
            result.write_text({result!r})
        sys.exit({exit_code})
        """
    )


class TierCNoopBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self.scratch = tempfile.TemporaryDirectory()
        self.pack = Path(self.scratch.name) / "pack"

    def tearDown(self) -> None:
        self.scratch.cleanup()

    def task(self, name: str, setup: str = SETUP_OK, verify: str = VERIFY_OK, evaluate: str = evaluator(False, 0.2)) -> None:
        root = self.pack / "tasks" / "shared" / name
        for folder in ("reset", "evaluator", "platform"):
            (root / folder).mkdir(parents=True)
        (root / "reset" / "setup.py").write_text(setup, encoding="utf-8")
        (root / "reset" / "verify.py").write_text(verify, encoding="utf-8")
        (root / "evaluator" / "evaluate.py").write_text(evaluate, encoding="utf-8")
        (root / "evaluator" / "helper.py").write_text("ok = True\n", encoding="utf-8")
        descriptor = {
            "platform": OS,
            "descriptor_version": "1",
            "semantics": {
                "reset": {
                    "setup": ["${python}", "reset/setup.py", "--workspace", "${workspace}"],
                    "verify": ["${python}", "reset/verify.py", "--workspace", "${workspace}"],
                },
                "evaluate": [
                    "${python}", "evaluator/evaluate.py", "--workspace", "${workspace}",
                    "--artifacts", "${artifacts}", "--result", "${result}",
                    "--agent-exit-code", "${agent_exit_code}",
                ],
            },
        }
        (root / "platform" / f"launch.{OS}.json").write_text(json.dumps(descriptor), encoding="utf-8")

    def run_pack(self) -> list[dict]:
        # A stand-in pack has no lock: nothing to verify it against.
        return tierc.run_noop(self.pack, None)

    def tree(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.pack).as_posix(): (b"" if path.is_dir() else path.read_bytes())
            for path in sorted(self.pack.rglob("*"))
        }

    def outcome(self) -> tuple[str, str]:
        (row,) = self.run_pack()
        return row["status"], row["observed"]

    def test_a_rejected_noop_passes_and_reports_nothing_from_the_task(self) -> None:
        self.task("t")
        before = self.tree()
        (row,) = self.run_pack()
        # The pack is never written to (no __pycache__, nothing else).
        self.assertEqual(self.tree(), before)
        self.assertEqual((row["status"], row["observed"]), ("pass", "noop-rejected"))
        self.assertEqual(row["case"], f"tierc-noop/t/{OS}")
        self.assertNotIn("secret", json.dumps(row))

    def test_each_failure_is_classified(self) -> None:
        cases = {
            "noop scored as solved": ({"evaluate": evaluator(True, 1.0)}, ("fail", "noop-scored-as-solved")),
            "score of one": ({"evaluate": evaluator(False, 1.0)}, ("fail", "noop-scored-as-solved")),
            "setup fails": ({"setup": "import sys; sys.exit(2)"}, ("error", "reset-setup-failed")),
            "verify fails": ({"verify": "import sys; sys.exit(1)"}, ("error", "reset-verify-failed")),
            "evaluator crashes": ({"evaluate": evaluator(False, 0.0, exit_code=3)}, ("error", "evaluator-failed")),
            "no result": ({"evaluate": evaluator(False, 0.0, write=False)}, ("error", "evaluator-no-result")),
            "not a number": ({"evaluate": "import sys, pathlib\nr = pathlib.Path(sys.argv[sys.argv.index('--result') + 1])\nr.write_text('{\"passed\": false, \"score\": NaN}')\n"}, ("error", "evaluator-bad-result")),
            "score missing": ({"evaluate": "import sys, pathlib\nr = pathlib.Path(sys.argv[sys.argv.index('--result') + 1])\nr.write_text('{\"passed\": false}')\n"}, ("error", "evaluator-bad-result")),
            "PYTHON variables are ignored": ({"setup": "import os, sys\nif os.environ.get('PYTHONPATH'):\n    sys.exit(5)\n" + SETUP_OK}, ("pass", "noop-rejected")),
        }
        for label, (scripts, expected) in cases.items():
            with self.subTest(label):
                self.tearDown()
                self.setUp()
                self.task("t", **scripts)
                self.assertEqual(self.outcome(), expected)

    def test_no_episode_folder_is_left_behind(self) -> None:
        self.task("t")
        with tempfile.TemporaryDirectory() as temp:
            import tempfile as module

            saved = module.tempdir
            module.tempdir = temp
            try:
                self.run_pack()
            finally:
                module.tempdir = saved
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_command_lines_are_filled_exactly(self) -> None:
        argv = expand(["${python}", "x.py", "--w", "${workspace}"], {"workspace": "/w"})
        self.assertEqual(argv[1:], ["-E", "-s", "-B", "x.py", "--w", "/w"])
        with self.assertRaises(TierCError):
            expand(["${nope}"], {})
        with self.assertRaises(TierCError):
            expand(["--w=${workspace}"], {"workspace": "/w"})

    def test_a_descriptor_for_another_os_is_refused(self) -> None:
        self.task("t")
        path = self.pack / "tasks" / "shared" / "t" / "platform" / f"launch.{OS}.json"
        descriptor = json.loads(path.read_text(encoding="utf-8"))
        descriptor["platform"] = "other"
        path.write_text(json.dumps(descriptor), encoding="utf-8")
        with self.assertRaises(TierCError):
            self.run_pack()

    def test_a_slow_step_times_out(self) -> None:
        self.task("t", setup="import time; time.sleep(30)")
        saved = tierc.STEP_TIMEOUT_S
        tierc.STEP_TIMEOUT_S = 1.0
        try:
            self.assertEqual(self.outcome(), ("error", "reset-setup-timeout"))
        finally:
            tierc.STEP_TIMEOUT_S = saved

    def test_a_pack_that_does_not_verify_is_refused_before_anything_runs(self) -> None:
        marker = Path(self.scratch.name) / "ran"
        self.task("t", setup=f"import pathlib; pathlib.Path({str(marker)!r}).write_text('x')")
        lock = {"files": [{"path": "nothing-here", "sha256": "0" * 64, "git_blob": "0" * 40}]}
        with self.assertRaises(TierCError):
            tierc.run_noop(self.pack, lock)
        self.assertFalse(marker.exists(), "task code ran before verification")


if __name__ == "__main__":
    unittest.main()
