"""M4a `model-run`: the pinned server's checks, command line and cleanup, and the
real run's scoring, with no model and no weights. Small stand-in files play the
pinned ones, so nothing here needs the real files."""

from __future__ import annotations

import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

BENCH = Path(__file__).resolve().parent.parent
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from orcel_bench import model_server  # noqa: E402
from orcel_bench.model_eval import LABEL, REPEATS, TASKS  # noqa: E402
from orcel_bench.model_server import (  # noqa: E402
    MODEL_LABEL, RUNNER, WEIGHTS, ModelServer, Pin, PinError, check_args, extract_runner, find_server, server_args,
    server_env, verified_bytes, verify)


def pin_for(path: Path) -> Pin:
    data = path.read_bytes()
    return Pin(path.name, len(data), hashlib.sha256(data).hexdigest())


def zip_of(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, content in members.items():
            archive.writestr(name, content)
    return buffer.getvalue()


class Folder(unittest.TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp(prefix="orcel-m4-test-"))
        self.addCleanup(model_server.remove_tree, self.folder)

    def file(self, name: str, content: bytes) -> Path:
        path = self.folder / name
        path.write_bytes(content)
        return path


class Pins(Folder):
    def test_the_pins_are_the_founders_files(self):
        self.assertEqual((WEIGHTS.file, WEIGHTS.size, WEIGHTS.sha256),
                         ("Qwen3.5-4B-Q4_K_M.gguf", 2_740_937_888,
                          "00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4"))
        self.assertEqual((RUNNER.file, RUNNER.size, RUNNER.sha256),
                         ("llama-b11567-bin-win-cpu-x64.zip", 19_502_550,
                          "7039609f175cfa5427d085f6e986e4119ab62d552abd1386f4909bca48ac0cc5"))
        self.assertTrue(LABEL.fullmatch(MODEL_LABEL))

    def test_the_right_file_passes(self):
        path = self.file("w.gguf", b"weights")
        verify(path, pin_for(path))
        self.assertEqual(verified_bytes(path, pin_for(path)), b"weights")

    def test_a_changed_byte_wrong_size_or_wrong_name_is_refused(self):
        path = self.file("w.gguf", b"weights")
        pin = pin_for(path)
        path.write_bytes(b"weightz")
        with self.assertRaisesRegex(PinError, "SHA-256"):
            verify(path, pin)
        with self.assertRaisesRegex(PinError, "SHA-256"):
            verified_bytes(path, pin)
        path.write_bytes(b"weights!")
        with self.assertRaisesRegex(PinError, "bytes"):
            verify(path, pin)
        other = self.file("x.gguf", b"weights")
        with self.assertRaisesRegex(PinError, "not the pinned file"):
            verify(other, pin)
        (self.folder / "d.gguf").mkdir()
        with self.assertRaisesRegex(PinError, "not a file"):
            verify(self.folder / "d.gguf", Pin("d.gguf", 1, "0"))

    def test_the_server_refuses_to_start_on_a_mismatch_and_leaves_nothing(self):
        weights = self.file(WEIGHTS.file, b"not the weights")
        runner = self.file(RUNNER.file, b"not the runner")
        before = set(Path(tempfile.gettempdir()).glob("orcel-m4-runner-*"))
        with mock.patch.object(subprocess, "Popen") as popen:
            with self.assertRaises(PinError):
                with ModelServer(weights, runner):
                    self.fail("started")
            popen.assert_not_called()
        self.assertEqual(set(Path(tempfile.gettempdir()).glob("orcel-m4-runner-*")), before)


class Extraction(Folder):
    def test_every_file_is_extracted_and_checked_and_the_server_found(self):
        out = self.folder / "out"
        out.mkdir()
        hashes = extract_runner(zip_of({"llama-server.exe": b"exe", "ggml.dll": b"dll"}), out)
        exe, digest = find_server(out, hashes)
        self.assertEqual(exe, out / "llama-server.exe")
        self.assertEqual(digest, hashlib.sha256(b"exe").hexdigest())
        self.assertEqual((out / "ggml.dll").read_bytes(), b"dll")

    def test_a_server_changed_after_extraction_is_refused(self):
        out = self.folder / "out"
        out.mkdir()
        hashes = extract_runner(zip_of({"llama-server.exe": b"exe"}), out)
        (out / "llama-server.exe").write_bytes(b"swapped")
        with self.assertRaisesRegex(PinError, "not the one from the zip"):
            find_server(out, hashes)

    def test_no_server_or_two_are_refused(self):
        for members in ({"ggml.dll": b"x"}, {"llama-server.exe": b"a", "bin/llama-server.exe": b"b"}):
            out = Path(tempfile.mkdtemp(dir=self.folder))
            with self.assertRaisesRegex(PinError, "copies"):
                find_server(out, extract_runner(zip_of(members), out))

    def test_members_that_could_leave_the_folder_are_refused(self):
        for name in ("../evil.dll", "/abs.dll", "a/../../evil.dll", "C:/evil.dll", "a\\..\\..\\evil.dll"):
            out = Path(tempfile.mkdtemp(dir=self.folder))
            with self.assertRaisesRegex(PinError, "unsafe member"):
                extract_runner(zip_of({name: b"x"}), out)
            self.assertFalse((self.folder / "evil.dll").exists())

    def test_it_extracts_only_into_an_empty_folder(self):
        (self.folder / "there.txt").write_bytes(b"x")
        with self.assertRaisesRegex(PinError, "not empty"):
            extract_runner(zip_of({"llama-server.exe": b"exe"}), self.folder)


class Arguments(unittest.TestCase):
    def test_loopback_local_weights_offline_and_no_thinking(self):
        args = server_args(Path("C:/r/llama-server.exe"), Path("C:/w/m.gguf"), 4242)
        check_args(args)
        self.assertEqual(args[args.index("--host") + 1], "127.0.0.1")
        self.assertEqual(args[args.index("--port") + 1], "4242")
        self.assertEqual(args[args.index("--model") + 1], str(Path("C:/w/m.gguf")))
        self.assertEqual(args[args.index("--ctx-size") + 1], "32768")
        self.assertEqual(args[args.index("--threads") + 1], "8")
        self.assertEqual(args[args.index("--reasoning") + 1], "off")
        for flag in ("--offline", "--no-webui", "--no-agent"):
            self.assertIn(flag, args)
        self.assertFalse(any(arg.startswith(("-hf", "--hf", "http", "-mu", "--model-url")) for arg in args))

    def test_a_command_line_reaching_out_is_refused(self):
        base = server_args(Path("s.exe"), Path("m.gguf"), 4242)
        for extra in (["--hf-repo", "x/y"], ["-hf", "x/y"], ["--model-url", "http://x"], ["--tools", "all"],
                      ["--rpc", "10.0.0.1:50052"], ["--agent"], ["--log-prompts-dir", "p"], ["--hf-repo=x/y"]):
            with self.assertRaises(ValueError, msg=extra):
                check_args(base + extra)
        wide = list(base)
        wide[wide.index("--host") + 1] = "0.0.0.0"
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            check_args(wide)
        with self.assertRaises(ValueError):
            server_args(Path("s.exe"), Path("m.gguf"), 0)

    def test_the_environment_carries_nothing_that_steers_the_runner(self):
        with mock.patch.dict("os.environ", {"LLAMA_ARG_HF_REPO": "x/y", "HTTPS_PROXY": "http://p", "HF_TOKEN": "t",
                                            "SYSTEMROOT": "C:\\Windows"}):
            env = server_env(Path("C:/private"))
        self.assertEqual(set(env) - {"WINDIR"}, {"SYSTEMROOT", "TEMP", "TMP"})
        self.assertEqual(env["TEMP"], str(Path("C:/private")))


class Cleanup(Folder):
    """The server stops and its folder goes, whether the run ends well or not."""

    def fake_server(self, exits_at_once: bool = False):
        script = "import sys\nsys.exit(3)\n" if exits_at_once else "import time\ntime.sleep(600)\n"
        real = subprocess.Popen

        def popen(args, **kwargs):
            return real([sys.executable, "-I", "-B", "-c", script], **kwargs)

        return popen

    def server(self, **kwargs):
        runner = self.file(RUNNER.file, zip_of({"llama-server.exe": b"exe", "ggml.dll": b"dll"}))
        weights = self.file(WEIGHTS.file, b"weights")
        patches = [mock.patch.object(model_server, "WEIGHTS", pin_for(weights)),
                   mock.patch.object(model_server, "RUNNER", pin_for(runner))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        return ModelServer(weights, runner, **kwargs)

    def test_a_failure_inside_the_run_still_stops_the_server_and_removes_the_folder(self):
        server = self.server()
        with mock.patch.object(subprocess, "Popen", self.fake_server()), \
                mock.patch.object(model_server, "_health", return_value=200):
            with self.assertRaisesRegex(RuntimeError, "the run failed"):
                with server:
                    folder = server.folder
                    self.assertTrue((folder / "llama-server.exe").is_file())
                    self.assertIsNone(server.process.poll())
                    raise RuntimeError("the run failed")
        self.assertIsNotNone(server.process.poll())
        self.assertTrue(server.removed)
        self.assertFalse(folder.exists())

    def test_a_server_that_exits_while_loading_is_an_error_and_is_cleaned_up(self):
        server = self.server()
        with mock.patch.object(subprocess, "Popen", self.fake_server(exits_at_once=True)), \
                mock.patch.object(model_server, "_health", return_value=None):
            with self.assertRaisesRegex(model_server.ServerError, "exited with 3"):
                with server:
                    self.fail("started")
        self.assertFalse(server.folder.exists())

    def test_a_server_never_healthy_is_stopped_and_cleaned_up(self):
        server = self.server(health_timeout_s=1.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server()), \
                mock.patch.object(model_server, "_health", return_value=503):
            with self.assertRaisesRegex(model_server.ServerError, "not healthy"):
                with server:
                    self.fail("started")
        self.assertIsNotNone(server.process.poll())
        self.assertFalse(server.folder.exists())

    def test_the_command_started_is_the_extracted_server_on_loopback(self):
        server = self.server()
        seen = {}
        fake = self.fake_server()

        def popen(args, **kwargs):
            seen["args"], seen["env"], seen["cwd"] = args, kwargs["env"], kwargs["cwd"]
            return fake(args, **kwargs)

        with mock.patch.object(subprocess, "Popen", popen), mock.patch.object(model_server, "_health", return_value=200):
            with server:
                self.assertEqual(Path(seen["args"][0]), server.folder / "llama-server.exe")
                self.assertEqual(seen["args"][seen["args"].index("--host") + 1], "127.0.0.1")
                self.assertEqual(Path(seen["cwd"]), server.folder)
                self.assertNotIn(str(BENCH.parent.parent), seen["cwd"])
                self.assertEqual(server.provenance()["llama_server_sha256"], hashlib.sha256(b"exe").hexdigest())


class Scoring(unittest.TestCase):
    """The real run's own scoring, on rows made by hand (needs no agent)."""

    @classmethod
    def setUpClass(cls):
        try:
            from orcel_bench import model_real
        except ImportError as error:  # the agent's package, for its edge client, is not importable
            raise unittest.SkipTest(f"orcel_agent not importable: {error}")
        cls.real = model_real

    def test_answer_readings(self):
        candidates = self.real.answer_candidates
        self.assertEqual(candidates(' "8417" '), ["8417", '"8417"'])
        self.assertEqual(candidates("8417"), [8417, "8417"])
        self.assertEqual(candidates('["b.csv", "a.csv"]'), [["b.csv", "a.csv"], ["a.csv", "b.csv"], '["b.csv", "a.csv"]'])
        self.assertEqual(candidates("```json\n2\n```"), [2, "2"])
        self.assertEqual(candidates("ops-team"), ["ops-team"])
        self.assertEqual(candidates(None), [])

    def test_the_goal_is_what_a_scripted_plan_sees_and_no_more(self):
        cases = self.real.tier_a_tasks()
        self.assertGreaterEqual(len(cases), 7)
        for case, _, task in cases:
            goal = self.real.tier_a_goal(task)
            self.assertTrue(goal.startswith(task.description), case)
            hidden = {key: value for key, value in task.metadata.items() if key != "inputs"}
            for key, value in hidden.items():
                if key not in task.metadata.get("inputs", {}) and isinstance(value, (list, dict)):
                    self.assertNotIn(str(value), goal, case)

    def rows(self):
        base = {"label": MODEL_LABEL, "clean": True, "answer_correct": True, "security_failures": [], "no_lease": True,
                "mutations_dispatched": 0, "mutation_attempts": 0, "transport_errors": 0, "proposals": 4,
                "invalid_proposals": 0, "finished_without_tool_call": True, "step_p95_ms": 1000.0}
        synthetic = [{**base, "task": task.name, "repeat": i} for task in TASKS for i in range(REPEATS)]
        tier_a = [{**base, "case": "orcel-read/x/a", "repeat": i, "status": "pass"} for i in range(10)]
        return synthetic, tier_a

    def test_without_an_egress_measure_it_never_qualifies(self):
        synthetic, tier_a = self.rows()
        result = self.real.verdict(synthetic, tier_a, 4 << 30)
        self.assertFalse(result["qualified"])
        self.assertEqual(result["problems"], ["egress_attempts: not measured for this label"])
        self.assertEqual(result["measures"]["tier_a_success"], 1.0)

    def test_a_tier_a_security_failure_disqualifies(self):
        synthetic, tier_a = self.rows()
        tier_a[3] = {**tier_a[3], "security_failures": ["the workspace changed"], "mutations_dispatched": 1}
        result = self.real.verdict(synthetic, tier_a, 4 << 30)
        self.assertTrue(result["disqualified"])
        self.assertEqual(len(result["security_failures"]), 2)

    def test_a_failed_server_is_no_tier_a_measure_and_a_stub_row_is_not_a_model_row(self):
        synthetic, tier_a = self.rows()
        tier_a[0] = {**tier_a[0], "transport_errors": 1}
        self.assertIsNone(self.real.tier_a_success(tier_a))
        synthetic[0] = {**synthetic[0], "label": "stub-no-model"}
        tier_a[1] = {**tier_a[1], "label": "stub-no-model"}
        problems = self.real.verdict(synthetic, tier_a, 4 << 30)["problems"]
        self.assertIn("a row carries another label; scripted and model rows are never mixed", problems)
        self.assertIn("a Tier A row carries another label", problems)
        self.assertIn("tier_a_success: not measured", problems)


if __name__ == "__main__":
    unittest.main()
