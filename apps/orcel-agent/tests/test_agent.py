"""Orcel Agent M1: the client-side rules, the resume invariant (including a
real process kill), the private store, the stdio edge client, and the source
boundary."""

from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.agent import READ_ONLY_TOOLS, Agent  # noqa: E402
from orcel_agent.edge import MAX_FRAME_BYTES, Edge, EdgeError, ToolOutcome, ToolSpec, parse_tool_result  # noqa: E402
from orcel_agent.events import EventLog  # noqa: E402
from orcel_agent.journal import OUTCOME_UNKNOWN, DispatchJournal  # noqa: E402
from orcel_agent.planner import ScriptedPlanner, ToolCall  # noqa: E402
from orcel_agent.store import StoreError, new_run_id, open_store  # noqa: E402

SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
RUN = "0" * 32
BOTH = frozenset({"fs_read", "fs_write"})


class FakeEdge:
    """Lists tools and answers calls from a script; records what it was asked."""

    def __init__(self, tools: list[str], answers: Optional[dict[str, ToolOutcome]] = None, fail_on: Optional[str] = None):
        self.tools = tools
        self.answers = answers or {}
        self.fail_on = fail_on
        self.called: list[tuple[str, dict[str, Any]]] = []

    def list_tools(self) -> list[ToolSpec]:
        return [ToolSpec(name, SCHEMA) for name in self.tools]

    def call_tool(self, name: str, arguments: dict[str, Any], timeout_s: Optional[float] = None) -> ToolOutcome:
        self.called.append((name, arguments))
        if name == self.fail_on:
            raise EdgeError("the edge exited")
        return self.answers.get(name, ToolOutcome(ok=True, result={"text": "ok"}))


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name) / "agent"

    def tearDown(self) -> None:
        self._dir.cleanup()

    def agent(self, edge: FakeEdge, run_id: str = RUN, **kwargs: Any) -> Agent:
        store = open_store(self.root, run_id)
        kwargs.setdefault("keep_store", True)
        return Agent(edge, DispatchJournal(store.journal_path, store.check_capacity), EventLog(run_id), store=store, **kwargs)


class ClientRules(Scratch):
    def test_only_allowlisted_tools_reach_the_planner_or_the_edge(self) -> None:
        edge = FakeEdge(["fs_read", "fs_write", "process_spawn", "desktop_input_execute"])
        agent = self.agent(edge)
        self.assertEqual(sorted(spec.name for spec in agent.prepare()), ["fs_read"])
        result = agent.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": "a"})]))
        self.assertEqual(result.outcome, "proposal-outside-allowlist")
        self.assertEqual(edge.called, [], "a disallowed proposal never reaches the edge")

    def test_the_m1_allowlist_is_read_only_and_everything_else_is_mutating(self) -> None:
        self.assertEqual(
            sorted(READ_ONLY_TOOLS),
            ["fs_find", "fs_list", "fs_read", "fs_read_range", "fs_search", "fs_stat", "system_status", "workspace_get"],
        )
        agent = self.agent(FakeEdge([]))
        for tool in ("fs_write", "process_spawn", "git_push", "anything_new"):
            self.assertTrue(agent.is_mutating(tool), tool)

    def test_a_refused_call_is_never_dispatched_again(self) -> None:
        edge = FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=False, error_code="PATH_ESCAPE")})
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": "../x"}), ToolCall("fs_read", {"path": "../x"})])
        self.assertEqual(self.agent(edge).run("goal", plan).outcome, "repeat-refused")
        self.assertEqual(len(edge.called), 1)

    def test_a_refusal_is_visible_and_the_run_may_finish(self) -> None:
        edge = FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=False, error_code="PATH_ESCAPE")})
        result = self.agent(edge).run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "../x"})], answer="refused"))
        self.assertEqual((result.outcome, result.answer), ("finished", "refused"))
        self.assertEqual(result.steps[0].error_code, "PATH_ESCAPE")

    def test_the_approval_budget_is_counted_before_dispatch(self) -> None:
        # orceld answers an approved prompt with plain success.
        edge = FakeEdge(["fs_write"])
        calls = [ToolCall("fs_write", {"path": f"f{i}"}) for i in range(5)]
        result = self.agent(edge, allowlist=frozenset({"fs_write"}), max_approval_requests=3).run("goal", ScriptedPlanner(calls))
        self.assertEqual(result.outcome, "approval-budget")
        self.assertEqual((result.approval_requests, len(edge.called)), (3, 3), "a fourth request never reaches orceld")

    def test_a_denial_stops_the_run_and_is_never_asked_again(self) -> None:
        denied = FakeEdge(["fs_write"], {"fs_write": ToolOutcome(ok=False, error_code="APPROVAL_DENIED")})
        calls = [ToolCall("fs_write", {"path": f"f{i}"}) for i in range(3)]
        self.assertEqual(self.agent(denied, allowlist=frozenset({"fs_write"})).run("goal", ScriptedPlanner(calls)).outcome, "approval-denied")
        self.assertEqual(len(denied.called), 1)

    def test_the_step_budget_and_malformed_proposals(self) -> None:
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": str(i)}) for i in range(10)])
        self.assertEqual(self.agent(FakeEdge(["fs_read"]), max_steps=3).run("goal", plan).outcome, "step-budget")
        missing = ScriptedPlanner([ToolCall("fs_read", {})])
        self.assertEqual(self.agent(FakeEdge(["fs_read"]), "1" * 32).run("goal", missing).outcome, "proposal-malformed")

    def test_an_edge_failure_mid_call_is_unknown_and_stops_the_run(self) -> None:
        edge = FakeEdge(["fs_read"], fail_on="fs_read")
        agent = self.agent(edge)
        self.assertEqual(agent.run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "a"})])).outcome, "edge-failure")
        entries = agent.journal.entries()
        self.assertEqual([(e.answered, e.error_code) for e in entries], [(True, OUTCOME_UNKNOWN)])

    def test_finish_is_a_claim_and_the_store_is_deleted_when_the_run_ends(self) -> None:
        agent = self.agent(FakeEdge(["fs_read"]), keep_store=False)
        result = agent.run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "a"})], answer=42))
        self.assertEqual((result.outcome, result.answer), ("finished", 42))
        self.assertTrue(agent.events.events[-1]["data"]["claimed"])
        self.assertFalse((self.root / RUN).exists(), "deleted on completion")
        stopped = self.agent(FakeEdge(["fs_read"]), "2" * 32, keep_store=False)
        stopped.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": "a"})]))
        self.assertFalse((self.root / ("2" * 32)).exists(), "deleted when the run stops")


class ResumeInvariant(Scratch):
    def crash_during(self, tool: str, path: str = "report.md") -> None:
        """A dispatched call whose answer was never recorded (the process
        died after the journal write)."""
        agent = self.agent(FakeEdge([tool]), allowlist=frozenset({tool}))
        agent.prepare()
        agent.journal.dispatched(tool, {"path": path})

    def test_an_unknown_call_is_surfaced_once_and_its_replay_is_refused(self) -> None:
        self.crash_during("fs_write")
        edge = FakeEdge(["fs_read", "fs_write"])
        resumed = self.agent(edge, allowlist=BOTH)
        resumed.prepare()
        self.assertEqual([(s.call.tool, s.error_code) for s in resumed.steps], [("fs_write", OUTCOME_UNKNOWN)])
        self.assertEqual(edge.called, [])
        # Re-observing is allowed, the same mutation never is.
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": "report.md"}), ToolCall("fs_write", {"path": "report.md"})])
        self.assertEqual(resumed.run("goal", plan).outcome, "unknown-outcome-replay")
        self.assertEqual([name for name, _ in edge.called], ["fs_read"])
        again = self.agent(FakeEdge(["fs_read"]), allowlist=BOTH)
        again.prepare()
        self.assertEqual(again.steps, [], "surfaced once, not on every start")

    def test_a_different_mutation_needs_a_fresh_observation(self) -> None:
        self.crash_during("fs_write", "a.md")
        edge = FakeEdge(["fs_read", "fs_write"])
        blocked = self.agent(edge, allowlist=BOTH)
        self.assertEqual(blocked.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": "b.md"})])).outcome,
                         "reobserve-before-mutation")
        self.crash_during("fs_write", "c.md")
        edge = FakeEdge(["fs_read", "fs_write"])
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": "c.md"}), ToolCall("fs_write", {"path": "d.md"})], answer="done")
        self.assertEqual(self.agent(edge, allowlist=BOTH).run("goal", plan).outcome, "finished")

    def test_refusals_budgets_and_denials_survive_a_resume(self) -> None:
        first = self.agent(FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=False, error_code="PATH_ESCAPE")}))
        first.run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "../x"})]))
        resumed = self.agent(FakeEdge(["fs_read"]))
        self.assertEqual(resumed.run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "../x"})])).outcome, "repeat-refused")

        run = "3" * 32
        approved = self.agent(FakeEdge(["fs_write"]), run, allowlist=frozenset({"fs_write"}))
        approved.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": f"f{i}"}) for i in range(2)]))
        edge = FakeEdge(["fs_write"])
        resumed = self.agent(edge, run, allowlist=frozenset({"fs_write"}))
        outcome = resumed.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": f"g{i}"}) for i in range(5)])).outcome
        self.assertEqual((outcome, len(edge.called)), ("approval-budget", 1), "the budget counts across a resume")

        run = "4" * 32
        denied = self.agent(FakeEdge(["fs_write"], {"fs_write": ToolOutcome(ok=False, error_code="APPROVAL_DENIED")}),
                            run, allowlist=frozenset({"fs_write"}))
        denied.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": "a"})]))
        edge = FakeEdge(["fs_write"])
        outcome = self.agent(edge, run, allowlist=frozenset({"fs_write"})).run(
            "goal", ScriptedPlanner([ToolCall("fs_write", {"path": "b"})])).outcome
        self.assertEqual((outcome, edge.called), ("approval-denied", []), "never re-asks after a resume")

    def test_a_torn_final_line_is_repaired(self) -> None:
        store = open_store(self.root, RUN)
        journal = DispatchJournal(store.journal_path)
        journal.dispatched("fs_write", {"path": "a"})
        with store.journal_path.open("ab") as handle:
            handle.write(b'{"seq": 2, "state": "dispa')
        repaired = DispatchJournal(store.journal_path)
        self.assertEqual([e.seq for e in repaired.unanswered()], [1])
        repaired.resolve_unknown(1)
        self.assertEqual(DispatchJournal(store.journal_path).unanswered(), [], "the resolution is readable")

    def test_the_journal_holds_digests_not_content(self) -> None:
        agent = self.agent(FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=True, result={"text": "SECRET-CONTENT"})}))
        agent.run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "private/notes.txt"})]))
        text = (self.root / RUN / "dispatch.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("SECRET-CONTENT", text)
        self.assertNotIn("private/notes.txt", text)


SLOW_SERVER = r'''
import json, sys, time
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}}
    elif message["method"] == "tools/list":
        result = {"tools": [{"name": "fs_write", "inputSchema": {"type": "object", "required": ["path"]}}]}
    else:
        time.sleep(30)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
'''

AGENT_CHILD = r'''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from orcel_agent.agent import Agent
from orcel_agent.edge import Edge
from orcel_agent.events import EventLog
from orcel_agent.journal import DispatchJournal
from orcel_agent.planner import ToolCall
from orcel_agent.store import open_store
store = open_store(Path(sys.argv[2]), sys.argv[3])
edge = Edge([sys.executable, "-c", sys.argv[4]], {}, timeout_s=60)
edge.start()
agent = Agent(edge, DispatchJournal(store.journal_path), EventLog("child"), allowlist=frozenset({"fs_write"}))
agent.prepare()
agent.dispatch(ToolCall("fs_write", {"path": "report.md"}))
'''


class ProcessKill(Scratch):
    def test_killing_the_agent_mid_call_leaves_an_unknown_outcome_that_is_never_replayed(self) -> None:
        child = subprocess.Popen([sys.executable, "-c", AGENT_CHILD, str(ROOT), str(self.root), RUN, SLOW_SERVER])
        journal_path = self.root / RUN / "dispatch.jsonl"
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and not (journal_path.is_file() and "dispatched" in journal_path.read_text(encoding="utf-8")):
                time.sleep(0.1)
            self.assertTrue(journal_path.is_file(), "the child dispatched")
            time.sleep(0.5)
        finally:
            child.kill()
            child.wait()
        edge = FakeEdge(["fs_read", "fs_write"])
        resumed = self.agent(edge, allowlist=BOTH)
        resumed.prepare()
        self.assertEqual([(s.call.tool, s.error_code) for s in resumed.steps], [("fs_write", OUTCOME_UNKNOWN)])
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": "report.md"}), ToolCall("fs_write", {"path": "report.md"})])
        self.assertEqual(resumed.run("goal", plan).outcome, "unknown-outcome-replay")
        self.assertNotIn(("fs_write", {"path": "report.md"}), edge.called)


class PrivateStore(Scratch):
    def test_the_store_is_owner_only(self) -> None:
        store = open_store(self.root, RUN)
        if os.name != "nt":
            for path in (self.root, store.directory):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, path)
            return
        # Windows: the run directory inherits its root's ACL; no broad
        # principal may reach it (a protected DACL of its own is for the grain).
        listing = subprocess.run(["icacls", str(store.directory)], capture_output=True, text=True, check=True).stdout
        for broad in ("Everyone", "BUILTIN\\Users", "Authenticated Users", "NT AUTHORITY\\Authenticated Users"):
            self.assertNotIn(broad + ":", listing, listing)

    def test_the_size_cap_fails_closed(self) -> None:
        store = open_store(self.root, RUN, max_bytes=200)
        journal = DispatchJournal(store.journal_path, store.check_capacity)
        with self.assertRaises(StoreError):
            for index in range(20):
                journal.dispatched("fs_read", {"path": str(index)})

    def test_run_ids_are_validated(self) -> None:
        for bad in ("../x", "abc", "A" * 32, "0" * 31):
            with self.assertRaises(StoreError):
                open_store(self.root, bad)
        self.assertRegex(new_run_id(), r"^[0-9a-f]{32}$")

    def test_expiry_follows_the_newest_file_and_spares_live_runs(self) -> None:
        old = open_store(self.root, "a" * 32)
        old.journal_path.write_text("{}\n", encoding="utf-8")
        os.utime(old.journal_path, (0, 0))
        os.utime(old.directory, (0, 0))
        busy = open_store(self.root, "b" * 32)
        busy.journal_path.write_text("{}\n", encoding="utf-8")
        os.utime(busy.directory, (0, 0))  # an old directory, a fresh journal
        open_store(self.root, "c" * 32, ttl_s=3600)
        self.assertFalse(old.directory.exists(), "an expired run is removed")
        self.assertTrue(busy.directory.exists(), "a run with a fresh journal is kept")


FAKE_SERVER = r'''
import json, sys
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    method = message["method"]
    if method == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}, "serverInfo": {"name": "fake", "version": "0"}}
    elif method == "tools/list":
        result = {"tools": [{"name": "fs_read", "inputSchema": {"type": "object", "required": ["path"]}}]}
    elif method == "tools/call":
        path = message["params"]["arguments"].get("path")
        if path == "../escape":
            result = {"content": [{"type": "text", "text": json.dumps({"error": {"code": "PATH_ESCAPE", "message": "outside"}})}], "isError": True}
        elif path == "big":
            print("x" * (int(sys.argv[1]) + 10), flush=True)
            continue
        else:
            result = {"content": [{"type": "text", "text": json.dumps({"result": {"text": "hello"}, "evidence": {"bytes": 5}})}]}
        # A server request reusing our id is not our response.
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "method": "ping"}), flush=True)
    else:
        continue
    print("not json, ignored", flush=True)
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
'''


class StdioEdge(unittest.TestCase):
    def env(self) -> dict[str, str]:
        return {key: value for key, value in os.environ.items() if key in ("PATH", "SYSTEMROOT", "SystemRoot")}

    def test_the_edge_client_speaks_mcp_over_stdio(self) -> None:
        with Edge([sys.executable, "-c", FAKE_SERVER, str(MAX_FRAME_BYTES)], self.env(), timeout_s=20) as edge:
            self.assertEqual([tool.name for tool in edge.list_tools()], ["fs_read"])
            ok = edge.call_tool("fs_read", {"path": "a.txt"})
            self.assertEqual((ok.ok, ok.result, ok.evidence), (True, {"text": "hello"}, {"bytes": 5}))
            refused = edge.call_tool("fs_read", {"path": "../escape"})
            self.assertEqual((refused.ok, refused.error_code), (False, "PATH_ESCAPE"))
            with self.assertRaises(EdgeError):
                edge.call_tool("fs_read", {"path": "big"})

    def test_results_in_other_forms(self) -> None:
        plain = parse_tool_result({"isError": True, "content": [{"type": "text", "text": "Input validation error: path"}]})
        self.assertEqual((plain.ok, plain.error_code), (False, "INVALID_REQUEST"))
        with self.assertRaises(EdgeError):
            parse_tool_result({"content": []})
        with self.assertRaises(EdgeError):
            parse_tool_result({"content": [{"type": "text", "text": "not json"}]})

    def test_a_failed_start_leaves_no_process(self) -> None:
        started: list[subprocess.Popen[bytes]] = []
        real = subprocess.Popen

        def recording(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            process = real(*args, **kwargs)
            started.append(process)
            return process

        subprocess.Popen = recording  # type: ignore[misc]
        try:
            with self.assertRaises(EdgeError):
                Edge([sys.executable, "-c", "import time; time.sleep(30)"], self.env(), timeout_s=1).start()
            with self.assertRaises(EdgeError):
                Edge([sys.executable, "-c", "pass"], self.env(), timeout_s=10).start()
        finally:
            subprocess.Popen = real  # type: ignore[misc]
        self.assertEqual(len(started), 2)
        for process in started:
            self.assertIsNotNone(process.poll(), "the child was stopped")


class SourceBoundary(unittest.TestCase):
    """The agent spawns one child (the edge, in edge.py), runs no shell,
    opens no socket, loads no code dynamically, and writes files only in
    journal.py. Checked on the syntax tree of every module, recursively."""

    ALLOWED_IMPORTS = {
        "__future__", "dataclasses", "hashlib", "json", "os", "pathlib", "queue", "re", "shutil", "stat",
        "subprocess", "threading", "time", "typing", "uuid",
    }
    FORBIDDEN_CALLS = {"__import__", "eval", "exec", "compile", "open"}
    FORBIDDEN_OS = {"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "startfile", "kill"}

    def modules(self) -> list[Path]:
        found = sorted((ROOT / "orcel_agent").rglob("*.py"))
        self.assertGreaterEqual(len(found), 7)
        return found

    def test_imports_are_standard_and_minimal(self) -> None:
        for path in self.modules():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [(node.module or "").split(".")[0]]
                for name in names:
                    self.assertIn(name, self.ALLOWED_IMPORTS, f"{path.name}: import {name}")

    def test_no_execution_network_or_dynamic_code(self) -> None:
        subprocess_calls: list[str] = []
        for path in self.modules():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if isinstance(func, ast.Name):
                    if func.id == "open":
                        self.fail(f"{path.name}: builtin open")
                    self.assertNotIn(func.id, self.FORBIDDEN_CALLS, f"{path.name}: {func.id}()")
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    owner, attr = func.value.id, func.attr
                    if owner == "os":
                        self.assertNotIn(attr, self.FORBIDDEN_OS, f"{path.name}: os.{attr}")
                        self.assertFalse(attr.startswith(("exec", "spawn")), f"{path.name}: os.{attr}")
                        if attr == "open":
                            self.assertEqual(path.name, "journal.py", "only the journal opens files")
                    if owner == "subprocess":
                        subprocess_calls.append(f"{path.name}:{attr}")
                    self.assertNotEqual(owner, "importlib", f"{path.name}: importlib")
                if isinstance(func, ast.Attribute) and func.attr in ("open", "write_text", "write_bytes"):
                    self.assertEqual(path.name, "journal.py", f"{path.name}: .{func.attr}()")
                if isinstance(func, ast.Attribute) and func.attr in ("create_subprocess_exec", "create_subprocess_shell", "open_connection"):
                    self.fail(f"{path.name}: {func.attr}")
                for keyword in node.keywords:
                    if keyword.arg == "shell":
                        self.assertTrue(isinstance(keyword.value, ast.Constant) and keyword.value.value is False,
                                        f"{path.name}: shell must be False")
        self.assertEqual(subprocess_calls, ["edge.py:Popen"], "exactly one spawn: the edge")


if __name__ == "__main__":
    unittest.main()
