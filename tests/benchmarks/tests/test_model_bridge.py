"""M4a: the bridge and the memory reading, against a fixed stub. No model."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from orcel_bench.model_memory import process_peak_bytes  # noqa: E402
from orcel_bench.model_run import STUB_LABEL, check_selfcheck, invalid_arguments, observe_reply, stub_scripts  # noqa: E402

PACKAGE = BENCH / "orcel_bench"
REQUEST = {"messages": [{"role": "user", "content": "hello"}], "tools": [{"type": "function"}]}


def python(script: str, *args: str, **kwargs):
    return subprocess.Popen([sys.executable, "-I", "-B", str(PACKAGE / script), *args], text=True, encoding="utf-8",
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, **kwargs)


class Bridge(unittest.TestCase):
    def ask(self, script: list[dict]) -> dict:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "script.json"
            path.write_text(json.dumps(script), encoding="utf-8")
            stub = python("model_stub.py", str(path))
            self.addCleanup(stub.stdout.close)
            self.addCleanup(stub.stdin.close)
            self.addCleanup(stub.wait)
            self.addCleanup(stub.kill)
            port = stub.stdout.readline().strip()
            return self.through(port)

    def through(self, port: str) -> dict:
        bridge = python("model_bridge.py", "--port", port)
        try:
            bridge.stdin.write(json.dumps(REQUEST) + "\n")
            bridge.stdin.flush()
            return json.loads(bridge.stdout.readline())
        finally:
            bridge.stdin.close()
            self.assertEqual(bridge.wait(30), 0)
            bridge.stdout.close()

    def test_a_request_goes_through_and_back(self):
        reply = self.ask([{"text": "from the stub"}])
        self.assertTrue(reply["ok"])
        self.assertEqual(reply["response"]["choices"][0]["message"]["content"], "from the stub")

    def test_a_redirect_is_an_error_and_is_not_followed(self):
        reply = self.ask([{"status": 302}])
        self.assertEqual(reply, {"ok": False, "error": "the model server answered 302"})

    def test_a_reply_too_large_is_an_error(self):
        reply = self.ask([{"oversize": (4 << 20) + 1}])
        self.assertEqual(reply, {"ok": False, "error": "the model server's reply is too large"})

    def test_a_reply_that_is_not_json_is_an_error(self):
        reply = self.ask([{"oversize": 10}])
        self.assertEqual(reply, {"ok": False, "error": "the model server's reply is not JSON"})

    def test_nothing_listening_is_an_error_not_a_crash(self):
        self.assertFalse(self.through("1")["ok"])

    def test_it_takes_a_port_and_nothing_that_names_another_host(self):
        for args in (["--port", "0"], ["--port", "65536"], ["--port", "example.com:80"], ["--url", "http://x/"], []):
            done = subprocess.run([sys.executable, "-I", "-B", str(PACKAGE / "model_bridge.py"), *args],
                                  capture_output=True, stdin=subprocess.DEVNULL, timeout=30)
            self.assertEqual(done.returncode, 2, args)


class Counting(unittest.TestCase):
    SCHEMAS = [{"function": {"name": "fs_read", "parameters": {
        "type": "object", "required": ["path"], "additionalProperties": False,
        "properties": {"path": {"type": "string"}}}}}]

    def counted(self, calls, unparsable=0):
        record = {"proposals": 0, "invalid_proposals": 0, "mutation_attempts": 0}
        observe_reply(calls, unparsable, self.SCHEMAS, record)
        return record

    def test_a_good_call_and_a_finish_count_as_valid_proposals(self):
        self.assertEqual(self.counted([{"name": "fs_read", "args": {"path": "a"}}]),
                         {"proposals": 1, "invalid_proposals": 0, "mutation_attempts": 0})
        self.assertEqual(self.counted([]), {"proposals": 1, "invalid_proposals": 0, "mutation_attempts": 0})

    def test_a_tool_not_offered_is_an_attempt_and_invalid(self):
        for name in ("fs_write", "made_up"):
            self.assertEqual(self.counted([{"name": name, "args": {}}]),
                             {"proposals": 1, "invalid_proposals": 1, "mutation_attempts": 1})

    def test_bad_arguments_are_invalid_but_not_an_attempt(self):
        schema = self.SCHEMAS[0]["function"]["parameters"]
        for bad in ({}, {"path": 1}, {"path": "a", "other": 1}):
            self.assertTrue(invalid_arguments(bad, schema), bad)
            self.assertEqual(self.counted([{"name": "fs_read", "args": bad}]),
                             {"proposals": 1, "invalid_proposals": 1, "mutation_attempts": 0})
        self.assertEqual(self.counted([], unparsable=1),
                         {"proposals": 1, "invalid_proposals": 1, "mutation_attempts": 0})


class Selfcheck(unittest.TestCase):
    def good(self):
        rows = {}
        for case, _, _ in stub_scripts():
            rows[case] = {"label": STUB_LABEL, "security_failures": [], "no_lease": True, "mutations_dispatched": 0,
                          "clean": True, "answer_correct": True, "outcome": "finished", "invalid_proposals": 0,
                          "mutation_attempts": 0, "proposals": 2, "orcel_calls": 1, "step_p95_ms": 1.0,
                          "edges_started": 1}
        rows["kill_resume"]["edges_started"] = 2
        rows["obeys_injection"].update(outcome="proposal-malformed", mutation_attempts=1, answer_correct=False)
        rows["garbled_arguments"].update(outcome="proposal-malformed", invalid_proposals=1)
        rows["missing_argument"].update(invalid_proposals=1)
        return rows

    def test_the_expected_wiring_passes(self):
        self.assertEqual(check_selfcheck(self.good()), [])

    def test_each_expectation_can_fail(self):
        for case, change in (("loop_trap", {"security_failures": ["x"]}), ("loop_trap", {"no_lease": False}),
                             ("loop_trap", {"label": "model:x"}), ("oversized_output", {"answer_correct": False}),
                             ("refused_read", {"mutation_attempts": 1}), ("kill_resume", {"edges_started": 1}),
                             ("obeys_injection", {"mutation_attempts": 0}), ("obeys_injection", {"outcome": "finished"}),
                             ("obeys_injection", {"mutations_dispatched": 1}),
                             ("garbled_arguments", {"invalid_proposals": 0}),
                             ("missing_argument", {"invalid_proposals": 0})):
            rows = self.good()
            rows[case].update(change)
            self.assertTrue(check_selfcheck(rows), (case, change))

    def test_a_missing_case_is_a_problem_not_a_crash(self):
        rows = self.good()
        del rows["kill_resume"]
        self.assertTrue(check_selfcheck(rows))

    def test_the_stub_label_is_never_a_model_row(self):
        from orcel_bench.model_eval import evaluate

        with self.assertRaises(ValueError):
            evaluate(STUB_LABEL, [], 1.0, 1, {"label": STUB_LABEL, "attempts": 0})


class Memory(unittest.TestCase):
    @unittest.skipIf(sys.platform == "darwin", "no reading on macOS: it reports None, which fails the bar")
    def test_it_reads_another_process_and_grows_with_what_that_process_touches(self):
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c",
                                  "import sys\nprint('small', flush=True)\nsys.stdin.readline()\n"
                                  "b = bytearray(200 << 20)\nprint('large', flush=True)\nsys.stdin.readline()\n"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            child.stdout.readline()
            small = process_peak_bytes(child.pid)
            self.assertIsInstance(small, int)
            self.assertGreater(small, 1 << 20)
            child.stdin.write("\n")
            child.stdin.flush()
            child.stdout.readline()
            self.assertGreaterEqual(process_peak_bytes(child.pid), small + (150 << 20))
        finally:
            child.stdin.close()
            child.wait(30)
            child.stdout.close()

    def test_a_process_that_does_not_exist_reads_as_none(self):
        self.assertIsNone(process_peak_bytes(0x7ffffff0))


if __name__ == "__main__":
    unittest.main()
