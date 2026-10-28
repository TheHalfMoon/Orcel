"""BM-02: the pinned cua-driver-bench taskpack is intact and its own checks pass.

The taskpack (trycua/cua, FSL-1.1-MIT, authorized by FD-04) is not copied
into Orcel: tests/benchmarks/taskpacks/cua-driver-bench.lock.json pins the
donor commit and every file's git blob id and sha256. These tests fetch it
(ORCEL_TASKPACK_SOURCE may name a local clone of trycua/cua instead of the
public URL), verify it file by file, then run each task's own digest check
and test suites, as the taskpack's README says to.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))

from orcel_bench.taskpack import TaskpackError, fetch, load_lock, verify  # noqa: E402

LOCK = load_lock("cua-driver-bench")


class PinnedTaskpack(unittest.TestCase):
    scratch: tempfile.TemporaryDirectory[str]
    pack: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls.scratch = tempfile.TemporaryDirectory(prefix="orcel-taskpack-")
        try:
            cls.pack = fetch("cua-driver-bench", Path(cls.scratch.name) / "pack", os.environ.get("ORCEL_TASKPACK_SOURCE"))
        except TaskpackError as error:
            cls.scratch.cleanup()
            if os.environ.get("CI"):
                raise
            raise unittest.SkipTest(f"taskpack unavailable here: {error}")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.scratch.cleanup()

    def tasks(self) -> list[Path]:
        return sorted(path for path in (self.pack / "tasks" / "shared").iterdir() if path.is_dir())

    def run_python(self, task: Path, *args: str) -> subprocess.CompletedProcess[str]:
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        return subprocess.run([sys.executable, "-I", *args], cwd=task, capture_output=True, text=True, check=False, env=env)

    def test_the_lock_pins_the_licensed_donor_commit(self) -> None:
        donor = LOCK["donor"]
        self.assertEqual(donor["commit"], "a802eaf26ca97616a6bf0de6a29729a9346fbb1f")
        self.assertEqual(donor["license"], "FSL-1.1-MIT")
        self.assertTrue((self.pack / "LICENSE").read_text(encoding="utf-8").startswith("# Functional Source License, Version 1.1"))

    def test_a_changed_or_extra_file_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / "copy"
            shutil.copytree(self.pack, copy)
            verify(LOCK, copy)
            brief = copy / "tasks" / "shared" / "cdb-s02" / "brief.md"
            brief.write_bytes(brief.read_bytes().replace(b"\n", b"\r\n"))
            with self.assertRaises(TaskpackError):
                verify(LOCK, copy)
            brief.unlink()
            with self.assertRaises(TaskpackError):
                verify(LOCK, copy)

    def test_nothing_beyond_the_locked_files_is_accepted(self) -> None:
        cases = {
            "a .git file": lambda root: (root / "tasks" / "shared" / "cdb-s02" / ".git").write_text("x"),
            "a .git directory": lambda root: (root / "tasks" / ".git").mkdir(),
            "an unlisted empty directory": lambda root: (root / "tasks" / "shared" / "extra").mkdir(),
        }
        for label, change in cases.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as scratch:
                copy = Path(scratch) / "copy"
                shutil.copytree(self.pack, copy)
                change(copy)
                with self.assertRaises(TaskpackError):
                    verify(LOCK, copy)

    @unittest.skipIf(os.name == "nt", "creating a symlink needs a privilege on Windows")
    def test_a_link_with_the_locked_bytes_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / "copy"
            shutil.copytree(self.pack, copy)
            brief = copy / "tasks" / "shared" / "cdb-s02" / "brief.md"
            outside = Path(scratch) / "brief.md"
            shutil.copyfile(brief, outside)
            brief.unlink()
            brief.symlink_to(outside)
            with self.assertRaises(TaskpackError):
                verify(LOCK, copy)

    @unittest.skipUnless(os.name == "nt", "a junction is a Windows reparse point")
    def test_a_junction_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / "copy"
            shutil.copytree(self.pack, copy)
            target = Path(scratch) / "elsewhere"
            shutil.move(str(copy / "tasks" / "shared" / "cdb-s04"), target)
            made = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(copy / "tasks" / "shared" / "cdb-s04"), str(target)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(made.returncode, 0, made.stderr)
            with self.assertRaises(TaskpackError):
                verify(LOCK, copy)

    @unittest.skipIf(os.name == "nt", "Windows has no executable bit")
    def test_an_executable_bit_the_lock_does_not_record_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as scratch:
            copy = Path(scratch) / "copy"
            shutil.copytree(self.pack, copy)
            (copy / "LICENSE").chmod(0o755)
            with self.assertRaises(TaskpackError):
                verify(LOCK, copy)

    def test_the_lock_records_the_donor_tree(self) -> None:
        self.assertEqual(LOCK["donor"]["tree"], "72a1d950e96081faa877003265d018224553ff44")

    def test_three_tasks(self) -> None:
        self.assertEqual([task.name for task in self.tasks()], ["cdb-s02", "cdb-s03", "cdb-s04"])

    def test_manifest_digests_are_up_to_date(self) -> None:
        for task in self.tasks():
            result = self.run_python(task, "tools/refresh_manifest_digests.py", "--check")
            self.assertEqual(result.returncode, 0, f"{task.name}: {result.stdout}{result.stderr}")

    def test_each_task_suite_passes(self) -> None:
        for task in self.tasks():
            result = self.run_python(task, "-m", "unittest", "discover", "-s", "tests", "-v")
            self.assertEqual(result.returncode, 0, f"{task.name}:\n{result.stderr[-3000:]}")
            # Record which checks could not run here (and why) in the log.
            for line in result.stderr.splitlines():
                if "skipped" in line:
                    print(f"{task.name}: {line.strip()}", file=sys.stderr)

    def test_tier_c_noop_baseline_rejects_every_untouched_task(self) -> None:
        # BM-02 Tier C, C1: each task's own reset and evaluator, run by the
        # harness with this OS's descriptor; a no-op must never score.
        from orcel_bench.tierc import run_noop

        rows = run_noop(self.pack, LOCK)
        # Running the tasks left the verified pack untouched.
        verify(LOCK, self.pack)
        self.assertEqual(len(rows), 3)
        for row in rows:
            print(f"TIERC-EVIDENCE {row['case']} {row['status']} {row['observed']} {row['latency_ms']['p50']}ms", file=sys.stderr)
            self.assertEqual((row["status"], row["observed"]), ("pass", "noop-rejected"), row["case"])

    def test_each_app_store_suite_passes(self) -> None:
        node = shutil.which("node")
        if node is None:
            if os.environ.get("CI"):
                self.fail("node is required under CI")
            self.skipTest("node is not installed")
        for task in self.tasks():
            for tests in sorted(task.glob("apps/*/tests")) + sorted(task.glob("fixture/*/tests")):
                files = sorted(str(path) for path in tests.glob("*.test.js"))
                if files:
                    result = subprocess.run([node, "--test", *files], cwd=tests.parent, capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 0, f"{tests}:\n{result.stdout[-3000:]}")


if __name__ == "__main__":
    unittest.main()
