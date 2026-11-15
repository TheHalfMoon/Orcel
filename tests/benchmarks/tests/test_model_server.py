"""M4a `model-run`: the pinned server's checks, holds, command line and cleanup,
the `--temp-root` check, and the real run's scoring, with no model and no
weights. Small stand-in files play the pinned ones and a loopback HTTP process
plays `llama-server`, so nothing here needs the real files."""

from __future__ import annotations

import hashlib
import io
import os
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

BENCH = Path(__file__).resolve().parent.parent
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from orcel_bench import model_hold, model_server  # noqa: E402
from orcel_bench.model_eval import LABEL, REPEATS, TASKS  # noqa: E402
from orcel_bench.model_server import (  # noqa: E402
    MODEL_LABEL, RUNNER, WEIGHTS, ModelServer, Pin, PinError, check_args, extract_runner, find_server, hold_extracted,
    hold_verified, server_args, server_env, verified_bytes, verify)


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


WINDOWS = sys.platform == "win32"
#: The interpreter itself, not a venv's launcher (which on Windows runs it as a
#: child process, so the listener would be another pid).
PYTHON = getattr(sys, "_base_executable", None) or sys.executable

#: The stand-in for llama-server: a loopback HTTP server that answers /health
#: and /props like the real one, on the port and with the model path it is given.
FAKE_SERVER = """
import http.server, json, sys
args = sys.argv[1:]
port = int(args[args.index("--port") + 1])
model = args[args.index("--model") + 1]
if "--fake-exit" in args:
    sys.exit(3)
if "--fake-other-model" in args:
    model = "C:/elsewhere/other.gguf"
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health" and "--fake-unhealthy" not in args:
            body = b'{"status": "ok"}'
        elif self.path == "/props":
            body = json.dumps({"model_path": model}).encode()
        else:
            self.send_response(503)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass
class Server(http.server.HTTPServer):
    allow_reuse_address = False
Server(("127.0.0.1", port), Handler).serve_forever()
"""


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

    @unittest.skipUnless(WINDOWS, "write and delete sharing is a Windows handle property")
    def test_a_held_file_can_be_read_but_not_written_renamed_or_deleted(self):
        path = self.file("w.gguf", b"weights")
        held = hold_verified(path, pin_for(path))
        try:
            self.assertEqual(path.read_bytes(), b"weights")
            with self.assertRaises(PermissionError):
                path.open("ab").close()
            with self.assertRaises(PermissionError):
                path.unlink()
            with self.assertRaises(PermissionError):
                path.rename(self.folder / "moved.gguf")
        finally:
            held.close()
        path.write_bytes(b"free again")

    @unittest.skipUnless(WINDOWS, "folder holds are Windows handles")
    def test_a_held_folder_cannot_be_renamed(self):
        inner = self.folder / "weights"
        inner.mkdir()
        hold = model_hold.hold_directory(inner)
        try:
            with self.assertRaises(PermissionError):
                inner.rename(self.folder / "other")
        finally:
            hold.close()

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
    def out(self) -> Path:
        return Path(tempfile.mkdtemp(dir=self.folder))

    def test_every_file_is_extracted_and_checked_and_the_server_found(self):
        out = self.out()
        hashes = extract_runner(zip_of({"llama-server.exe": b"exe", "ggml.dll": b"dll"}), out)
        exe, digest = find_server(out, hashes)
        self.assertEqual(exe, out / "llama-server.exe")
        self.assertEqual(digest, hashlib.sha256(b"exe").hexdigest())
        self.assertEqual((out / "ggml.dll").read_bytes(), b"dll")

    def test_a_server_changed_after_extraction_is_refused(self):
        out = self.out()
        hashes = extract_runner(zip_of({"llama-server.exe": b"exe"}), out)
        (out / "llama-server.exe").write_bytes(b"swapped")
        with self.assertRaisesRegex(PinError, "not the one from the zip"):
            find_server(out, hashes)

    def test_a_file_changed_or_planted_before_the_start_is_refused(self):
        out = self.out()
        hashes = extract_runner(zip_of({"llama-server.exe": b"exe", "ggml.dll": b"dll"}), out)
        for held in hold_extracted(out, hashes):
            held.close()
        (out / "ggml.dll").write_bytes(b"swapped")
        with self.assertRaisesRegex(PinError, "ggml.dll changed after extraction"):
            hold_extracted(out, hashes)
        (out / "ggml.dll").write_bytes(b"dll")
        (out / "version.dll").write_bytes(b"planted")
        with self.assertRaisesRegex(PinError, "extra \\['version.dll'\\]"):
            hold_extracted(out, hashes)
        (out / "version.dll").unlink()
        (out / "ggml.dll").unlink()
        with self.assertRaisesRegex(PinError, "missing \\['ggml.dll'\\]"):
            hold_extracted(out, hashes)

    def test_no_server_or_two_are_refused(self):
        for members in ({"ggml.dll": b"x"}, {"llama-server.exe": b"a", "bin/llama-server.exe": b"b"}):
            out = self.out()
            with self.assertRaisesRegex(PinError, "copies"):
                find_server(out, extract_runner(zip_of(members), out))

    def test_members_that_could_leave_the_folder_are_refused(self):
        for name in ("../evil.dll", "/abs.dll", "a/../../evil.dll", "C:/evil.dll", "a\\..\\..\\evil.dll"):
            out = self.out()
            with self.assertRaisesRegex(PinError, "unsafe member"):
                extract_runner(zip_of({name: b"x"}), out)
            self.assertFalse((self.folder / "evil.dll").exists())

    def test_names_windows_would_read_differently_are_refused(self):
        for name in ("CON", "nul.dll", "a/aux.txt", "COM1.dll", "lpt9", "Com\u00b9.dll", "conin$", "a.dll.",
                     "a.dll ", "dir./x.dll", "dir /x.dll", "a<b.dll", "a|b.dll", "a?.dll", "a*.dll", 'a".dll',
                     "a\tb.dll"):
            out = self.out()
            with self.assertRaises(PinError, msg=name):
                extract_runner(zip_of({name: b"x"}), out)
            self.assertEqual(list(out.iterdir()), [], name)

    def test_duplicate_and_case_colliding_members_are_refused(self):
        out = self.out()
        buffer = io.BytesIO()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # zipfile warns about the duplicate it is told to write
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("ggml.dll", b"one")
                archive.writestr("ggml.dll", b"two")
        with self.assertRaisesRegex(PinError, "twice"):
            extract_runner(buffer.getvalue(), out)
        for members in ({"llama-server.exe": b"a", "LLAMA-SERVER.EXE": b"b"},
                        {"Bin/a.dll": b"a", "bin/A.dll": b"b"}):
            out = self.out()
            with self.assertRaisesRegex(PinError, "twice"):
                extract_runner(zip_of(members), out)
            self.assertEqual(list(out.iterdir()), [])

    def test_too_many_members_too_many_bytes_or_too_long_a_path_is_refused(self):
        with mock.patch.object(model_server, "MAX_MEMBERS", 2):
            with self.assertRaisesRegex(PinError, "3 members"):
                extract_runner(zip_of({"a.dll": b"a", "b.dll": b"b", "c.dll": b"c"}), self.out())
        with mock.patch.object(model_server, "MAX_EXTRACTED_BYTES", 4):
            with self.assertRaisesRegex(PinError, "expands"):
                extract_runner(zip_of({"a.dll": b"0123456789"}), self.out())
        long_name = "d" * 120 + "/" + "e" * 120 + ".dll"
        with self.assertRaisesRegex(PinError, "too long"):
            extract_runner(zip_of({long_name: b"x"}), self.out())

    def test_a_broken_zip_is_a_pin_error(self):
        with self.assertRaisesRegex(PinError, "could not be extracted safely"):
            extract_runner(b"not a zip at all", self.out())

    def test_it_extracts_only_into_an_empty_folder(self):
        (self.folder / "there.txt").write_bytes(b"x")
        with self.assertRaisesRegex(PinError, "not empty"):
            extract_runner(zip_of({"llama-server.exe": b"exe"}), self.folder)


class Arguments(unittest.TestCase):
    def test_loopback_local_weights_offline_and_no_thinking_or_readback(self):
        args = server_args(Path("C:/r/llama-server.exe"), Path("C:/w/m.gguf"), 4242)
        check_args(args)
        self.assertEqual(args[args.index("--host") + 1], "127.0.0.1")
        self.assertEqual(args[args.index("--port") + 1], "4242")
        self.assertEqual(args[args.index("--model") + 1], str(Path("C:/w/m.gguf")))
        self.assertEqual(args[args.index("--ctx-size") + 1], "32768")
        self.assertEqual(args[args.index("--threads") + 1], "8")
        self.assertEqual(args[args.index("--reasoning") + 1], "off")
        for flag in ("--offline", "--no-webui", "--no-agent", "--no-slots"):
            self.assertIn(flag, args)
        self.assertFalse(any(arg.startswith(("-hf", "--hf", "http", "-mu", "--model-url")) for arg in args))

    def test_a_command_line_reaching_out_or_exposing_prompts_is_refused(self):
        base = server_args(Path("s.exe"), Path("m.gguf"), 4242)
        for extra in (["--hf-repo", "x/y"], ["-hf", "x/y"], ["--model-url", "http://x"], ["--tools", "all"],
                      ["--rpc", "10.0.0.1:50052"], ["--agent"], ["--log-prompts-dir", "p"], ["--hf-repo=x/y"],
                      ["--slots"], ["--props"], ["--slot-save-path", "s"], ["--metrics"]):
            with self.assertRaises(ValueError, msg=extra):
                check_args(base + extra)
        wide = list(base)
        wide[wide.index("--host") + 1] = "0.0.0.0"
        with self.assertRaisesRegex(ValueError, "127.0.0.1"):
            check_args(wide)
        with self.assertRaisesRegex(ValueError, "--no-slots"):
            check_args([arg for arg in base if arg != "--no-slots"])
        with self.assertRaises(ValueError):
            server_args(Path("s.exe"), Path("m.gguf"), 0)

    def test_the_environment_carries_nothing_that_steers_the_runner(self):
        with mock.patch.dict("os.environ", {"LLAMA_ARG_HF_REPO": "x/y", "HTTPS_PROXY": "http://p", "HF_TOKEN": "t",
                                            "SYSTEMROOT": "C:\\Windows"}):
            env = server_env(Path("C:/private"))
        self.assertEqual(set(env) - {"WINDIR"}, {"SYSTEMROOT", "TEMP", "TMP"})
        self.assertEqual(env["TEMP"], str(Path("C:/private")))


class Cleanup(Folder):
    """The server stops and its folder goes, whether the run ends well or not.
    The stand-in server is a real loopback HTTP process started from the exact
    command line `ModelServer` builds, after that command line is checked."""

    def fake_server(self, *fake_flags: str):
        real = subprocess.Popen
        test = self

        def popen(args, **kwargs):
            check_args(args)
            exe = Path(args[0])
            test.assertEqual(exe.name, "llama-server.exe")
            test.assertEqual(exe.parent.name, model_server.BIN)
            test.assertEqual(exe.parent.parent, Path(kwargs["cwd"]))
            test.assertEqual(args[args.index("--model") + 1], str(test.weights.resolve()))
            test.assertEqual(set(kwargs["env"]) - {"SYSTEMROOT", "WINDIR"}, {"TEMP", "TMP"})
            test.assertIs(kwargs["stdin"], subprocess.DEVNULL)
            test.seen = {"args": list(args), "cwd": kwargs["cwd"]}
            return real([PYTHON, "-I", "-B", "-c", FAKE_SERVER, *args[1:], *fake_flags], **kwargs)

        return popen

    def server(self, **kwargs):
        self.runner = self.file(RUNNER.file, zip_of({"llama-server.exe": b"exe", "ggml.dll": b"dll"}))
        self.weights = self.file(WEIGHTS.file, b"weights")
        patches = [mock.patch.object(model_server, "WEIGHTS", pin_for(self.weights)),
                   mock.patch.object(model_server, "RUNNER", pin_for(self.runner))]
        if not WINDOWS:  # the listener table is read through iphlpapi
            patches.append(mock.patch.object(model_hold, "listening_pids",
                                             lambda port: {self.started.process.pid}))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.started = ModelServer(self.weights, self.runner, **kwargs)
        return self.started

    def test_a_failure_inside_the_run_still_stops_the_server_and_removes_the_folder(self):
        server = self.server(health_timeout_s=30.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server()):
            with self.assertRaisesRegex(RuntimeError, "the run failed"):
                with server:
                    folder = server.folder
                    self.assertTrue((folder / model_server.BIN / "llama-server.exe").is_file())
                    self.assertIsNone(server.process.poll())
                    server.confirm()
                    raise RuntimeError("the run failed")
        self.assertIsNotNone(server.process.poll())
        self.assertTrue(server.removed)
        self.assertFalse(folder.exists())

    def test_a_server_that_exits_while_loading_is_an_error_and_is_cleaned_up(self):
        server = self.server()
        with mock.patch.object(subprocess, "Popen", self.fake_server("--fake-exit")):
            with self.assertRaisesRegex(model_server.ServerError, "exited with 3"):
                with server:
                    self.fail("started")
        self.assertFalse(server.folder.exists())

    def test_a_server_never_healthy_is_stopped_and_cleaned_up(self):
        server = self.server(health_timeout_s=3.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server("--fake-unhealthy")):
            with self.assertRaisesRegex(model_server.ServerError, "not healthy"):
                with server:
                    self.fail("started")
        self.assertIsNotNone(server.process.poll())
        self.assertFalse(server.folder.exists())

    def test_a_server_reporting_another_model_is_refused(self):
        server = self.server(health_timeout_s=30.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server("--fake-other-model")):
            with self.assertRaisesRegex(model_server.ServerError, "reports model"):
                with server:
                    self.fail("started")
        self.assertIsNotNone(server.process.poll())
        self.assertFalse(server.folder.exists())

    def test_another_listener_on_the_port_is_refused(self):
        server = self.server(health_timeout_s=30.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server()), \
                mock.patch.object(model_hold, "listening_pids", lambda port: {server.process.pid, 4}):
            with self.assertRaisesRegex(model_server.ServerError, "not only llama-server"):
                with server:
                    self.fail("started")
        self.assertIsNotNone(server.process.poll())
        self.assertFalse(server.folder.exists())

    @unittest.skipUnless(WINDOWS, "reads the real listener table")
    def test_a_port_taken_first_by_another_process_is_refused(self):
        squatter = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(squatter.close)
        squatter.bind(("127.0.0.1", 0))
        squatter.listen(1)
        port = squatter.getsockname()[1]
        self.assertEqual(model_hold.listening_pids(port), {os.getpid()})
        server = self.server(health_timeout_s=10.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server()), \
                mock.patch.object(model_server, "free_port", return_value=port):
            with self.assertRaisesRegex(model_server.ServerError, "exited|not only llama-server|not healthy"):
                with server:
                    self.fail("started")
        self.assertFalse(server.folder.exists())

    def test_a_changed_runner_file_before_the_start_is_refused(self):
        server = self.server()
        real_find = model_server.find_server

        def find_then_swap(folder, hashes):
            found = real_find(folder, hashes)
            (folder / "ggml.dll").write_bytes(b"swapped")
            return found

        with mock.patch.object(subprocess, "Popen") as popen, \
                mock.patch.object(model_server, "find_server", find_then_swap):
            with self.assertRaisesRegex(PinError, "ggml.dll changed after extraction"):
                with server:
                    self.fail("started")
            popen.assert_not_called()
        self.assertFalse(server.folder.exists())

    def test_a_server_that_ignores_terminate_is_killed(self):
        server = self.server(health_timeout_s=30.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server()), \
                mock.patch.object(model_server, "STOP_TIMEOUT_S", 1.0):
            with server:
                process = server.process
                patches = [mock.patch.object(process, "terminate"),
                           mock.patch.object(process, "kill", wraps=process.kill)]
                terminate, kill = (patch.start() for patch in patches)
                for patch in patches:
                    self.addCleanup(patch.stop)
        terminate.assert_called_once()
        kill.assert_called_once()
        self.assertIsNotNone(process.poll())
        self.assertFalse(server.folder.exists())

    def test_the_command_started_is_the_extracted_server_on_loopback(self):
        server = self.server(health_timeout_s=30.0)
        with mock.patch.object(subprocess, "Popen", self.fake_server()):
            with server:
                args = self.seen["args"]
                self.assertEqual(Path(args[0]), server.folder / model_server.BIN / "llama-server.exe")
                self.assertEqual(args[args.index("--host") + 1], "127.0.0.1")
                self.assertEqual(Path(self.seen["cwd"]), server.folder)
                self.assertNotIn(str(BENCH.parent.parent), self.seen["cwd"])
                self.assertEqual(server.provenance()["llama_server_sha256"], hashlib.sha256(b"exe").hexdigest())
                if WINDOWS:  # held from the hash until the server stops
                    with self.assertRaises(PermissionError):
                        self.weights.open("ab").close()
                    with self.assertRaises(PermissionError):
                        (server.folder / model_server.BIN / "ggml.dll").open("ab").close()
        self.weights.open("ab").close()


@unittest.skipUnless(WINDOWS, "job objects are Windows")
class KillOnClose(unittest.TestCase):
    def test_closing_the_job_ends_the_process(self):
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time; time.sleep(600)"])
        self.addCleanup(process.kill)
        job = model_hold.KillOnClose()
        job.assign(process)
        self.assertIsNone(process.poll())
        job.close()
        process.wait(10)
        self.assertIsNotNone(process.returncode)


class TempRoot(Folder):
    USER = "S-1-5-21-1-2-3-1001"

    def test_who_may_reach_a_folder(self):
        problem = model_hold.acl_others_problem
        mine = f"(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{self.USER})"
        self.assertIsNone(problem(f"O:{self.USER}D:P{mine}", self.USER))
        # Inherited entries for the same principals (a folder in the profile).
        self.assertIsNone(problem(f"O:{self.USER}D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;{self.USER})", self.USER))
        self.assertIsNone(problem(f"O:{self.USER}D:P{mine}(D;;FA;;;WD)", self.USER))
        for extra, why in (("(A;;FR;;;WD)", "grants WD"), ("(A;OICIID;0x1200a9;;;BU)", "grants BU"),
                           ("(A;;FW;;;AU)", "grants AU"), ("(A;OICI;FA;;;S-1-5-21-9-9-9-1002)", "grants S-1-5-21"),
                           ("(OA;;FA;;;WD)", "type OA")):
            self.assertIn(why, problem(f"O:{self.USER}D:P{mine}{extra}", self.USER))
        self.assertIn("owned by", problem(f"O:S-1-5-21-9-9-9-1002D:P{mine}", self.USER))
        self.assertIn("no DACL", problem(f"O:{self.USER}D:NO_ACCESS_CONTROL", self.USER))

    def test_a_new_temp_root_is_made_private_and_held(self):
        path = self.folder / "new" / "root"
        root, hold = model_hold.prepare_temp_root(path)
        try:
            self.assertEqual(root, Path(os.path.abspath(path)))
            if WINDOWS:
                from orcel_agent import winacl

                user = winacl.current_user_sid()
                self.assertIsNone(winacl.private_problem(winacl.security_of(root), user, winacl.sddl_form(user)))
                with self.assertRaises(PermissionError):
                    root.rename(root.parent / "moved")
            else:
                self.assertEqual(stat.S_IMODE(root.stat().st_mode) & 0o077, 0)
        finally:
            hold.close()

    def test_a_temp_root_another_account_can_reach_is_refused(self):
        path = self.folder / "open"
        path.mkdir()
        if WINDOWS:
            # Everyone may read and list it.
            subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)(R)"], check=True,
                           stdout=subprocess.DEVNULL)
        else:
            path.chmod(0o755)
        with self.assertRaisesRegex(OSError, "grants WD|open to other accounts"):
            model_hold.prepare_temp_root(path)

    def test_model_run_refuses_such_a_temp_root_before_anything_starts(self):
        try:
            from orcel_bench import model_real  # noqa: F401
        except ImportError as error:
            self.skipTest(f"orcel_agent not importable: {error}")
        from orcel_bench.__main__ import main

        path = self.folder / "open"
        path.mkdir()
        if WINDOWS:
            subprocess.run(["icacls", str(path), "/grant", "*S-1-1-0:(OI)(CI)(R)"], check=True,
                           stdout=subprocess.DEVNULL)
        else:
            path.chmod(0o755)
        argv = ["model-run", "--weights", "w.gguf", "--runner-zip", "r.zip", "--orceld", "o", "--edge", "e",
                "--temp-root", str(path), "--out", str(self.folder / "out.json")]
        with mock.patch("orcel_bench.model_real.main") as run, mock.patch("sys.stderr", io.StringIO()) as err, \
                mock.patch.object(sys, "version_info", (3, 12, 4)):
            self.assertEqual(main(argv), 2)
            run.assert_not_called()
        self.assertIn("refusing --temp-root", err.getvalue())
        with mock.patch.object(sys, "version_info", (3, 12, 3)), mock.patch("sys.stderr", io.StringIO()) as err:
            self.assertEqual(main(argv), 2)
        self.assertIn("3.12.4", err.getvalue())


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
        # Sorted only for a task that declares its answer order-free.
        self.assertEqual(candidates('["b.csv", "a.csv"]'), [["b.csv", "a.csv"], '["b.csv", "a.csv"]'])
        self.assertEqual(candidates('["b.csv", "a.csv"]', any_order=True),
                         [["b.csv", "a.csv"], ["a.csv", "b.csv"], '["b.csv", "a.csv"]'])
        self.assertEqual(candidates("[1, 2]", any_order=True), [[1, 2], "[1, 2]"])
        self.assertEqual(candidates("```json\n2\n```"), [2, "2"])
        self.assertEqual(candidates("ops-team"), ["ops-team"])
        self.assertEqual(candidates(None), [])

    def test_only_find_csv_declares_an_order_free_answer(self):
        declared = {case.split("/")[1] for case, _, task in self.real.tier_a_tasks() if self.real.order_free(task)}
        self.assertEqual(declared, {"find-csv"})

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
