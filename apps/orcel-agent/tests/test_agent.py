"""Orcel Agent M1: the client-side rules, the resume invariant, the private
store, the stdio edge client, and the source boundary."""

from __future__ import annotations

import json
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.agent import READ_ONLY_TOOLS, Agent  # noqa: E402
from orcel_agent.edge import Edge, EdgeError, ToolOutcome, ToolSpec, parse_tool_result  # noqa: E402
from orcel_agent.events import EventLog  # noqa: E402
from orcel_agent.journal import OUTCOME_UNKNOWN, DispatchJournal  # noqa: E402
from orcel_agent.planner import Finish, ScriptedPlanner, ToolCall  # noqa: E402
from orcel_agent.store import StoreError, open_store  # noqa: E402

SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}


class FakeEdge:
    """Lists tools and answers calls from a script; records what it was asked."""

    def __init__(self, tools: list[str], answers: dict[str, ToolOutcome] | None = None, crash_on: str | None = None):
        self.tools = tools
        self.answers = answers or {}
        self.crash_on = crash_on
        self.called: list[tuple[str, dict[str, Any]]] = []

    def list_tools(self) -> list[ToolSpec]:
        return [ToolSpec(name, SCHEMA) for name in self.tools]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        self.called.append((name, arguments))
        if name == self.crash_on:
            raise RuntimeError("the agent process died here")
        return self.answers.get(name, ToolOutcome(ok=True, result={"text": "ok"}))


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name) / "agent"

    def tearDown(self) -> None:
        self._dir.cleanup()

    def agent(self, edge: FakeEdge, run_id: str = "run", **kwargs: Any) -> Agent:
        store = open_store(self.root, run_id)
        return Agent(edge, DispatchJournal(store.journal_path, store.check_capacity), EventLog(run_id), **kwargs)


class ClientRules(Scratch):
    def test_only_allowlisted_tools_reach_the_planner_or_the_edge(self) -> None:
        edge = FakeEdge(["fs_read", "fs_write", "process_spawn", "desktop_input_execute"])
        agent = self.agent(edge)
        offered = sorted(spec.name for spec in agent.prepare())
        self.assertEqual(offered, ["fs_read"])
        result = Agent.run(agent, "goal", ScriptedPlanner([ToolCall("fs_write", {"path": "a"})]))
        self.assertEqual(result.outcome, "proposal-outside-allowlist")
        self.assertEqual(edge.called, [], "a disallowed proposal never reaches the edge")

    def test_the_m1_allowlist_is_read_only(self) -> None:
        self.assertEqual(
            sorted(READ_ONLY_TOOLS),
            ["fs_find", "fs_list", "fs_read", "fs_read_range", "fs_search", "fs_stat", "system_status", "workspace_get"],
        )

    def test_a_refused_call_is_never_proposed_again(self) -> None:
        edge = FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=False, error_code="PATH_ESCAPE")})
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": "../x"}), ToolCall("fs_read", {"path": "../x"})])
        result = self.agent(edge).run("goal", plan)
        self.assertEqual(result.outcome, "repeat-refused")
        self.assertEqual(len(edge.called), 1)

    def test_a_refusal_is_visible_and_the_run_may_finish(self) -> None:
        edge = FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=False, error_code="PATH_ESCAPE")})
        result = self.agent(edge).run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "../x"})], answer="refused"))
        self.assertEqual((result.outcome, result.answer), ("finished", "refused"))
        self.assertEqual(result.steps[0].error_code, "PATH_ESCAPE")

    def test_the_approval_budget_and_a_denial_stop_the_run(self) -> None:
        edge = FakeEdge(["fs_write"], {"fs_write": ToolOutcome(ok=False, error_code="APPROVAL_REQUIRED")})
        calls = [ToolCall("fs_write", {"path": f"f{i}"}) for i in range(5)]
        agent = self.agent(edge, allowlist=frozenset({"fs_write"}), mutating=frozenset({"fs_write"}), max_approval_requests=3)
        result = agent.run("goal", ScriptedPlanner(calls))
        self.assertEqual(result.outcome, "approval-budget")
        self.assertEqual(result.approval_requests, 4)
        denied = FakeEdge(["fs_write"], {"fs_write": ToolOutcome(ok=False, error_code="APPROVAL_DENIED")})
        agent = self.agent(denied, "run2", allowlist=frozenset({"fs_write"}), mutating=frozenset({"fs_write"}))
        self.assertEqual(agent.run("goal", ScriptedPlanner(calls)).outcome, "approval-denied")
        self.assertEqual(len(denied.called), 1, "never re-asks after a denial")

    def test_the_step_budget_and_malformed_proposals(self) -> None:
        edge = FakeEdge(["fs_read"])
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": str(i)}) for i in range(10)])
        self.assertEqual(self.agent(edge, max_steps=3).run("goal", plan).outcome, "step-budget")
        missing = ScriptedPlanner([ToolCall("fs_read", {})])
        self.assertEqual(self.agent(FakeEdge(["fs_read"]), "run2").run("goal", missing).outcome, "proposal-malformed")

    def test_finish_is_a_claim_recorded_as_such(self) -> None:
        agent = self.agent(FakeEdge(["fs_read"]))
        result = agent.run("goal", ScriptedPlanner([], answer=42))
        self.assertEqual((result.outcome, result.answer), ("finished", 42))
        self.assertEqual(agent.events.events[-1]["kind"], "run.finished")
        self.assertTrue(agent.events.events[-1]["data"]["claimed"])


class ResumeInvariant(Scratch):
    def test_a_call_cut_off_by_a_crash_becomes_outcome_unknown_and_is_never_redispatched(self) -> None:
        crashing = FakeEdge(["fs_read", "fs_write"], crash_on="fs_write")
        agent = self.agent(crashing, allowlist=frozenset({"fs_read", "fs_write"}), mutating=frozenset({"fs_write"}))
        agent.prepare()
        with self.assertRaises(RuntimeError):
            agent.dispatch(ToolCall("fs_write", {"path": "report.md"}))

        # A new process resumes the same run.
        edge = FakeEdge(["fs_read", "fs_write"])
        resumed = self.agent(edge, allowlist=frozenset({"fs_read", "fs_write"}), mutating=frozenset({"fs_write"}))
        resumed.prepare()
        self.assertEqual([(s.call.tool, s.error_code) for s in resumed.steps], [("fs_write", OUTCOME_UNKNOWN)])
        self.assertEqual(edge.called, [], "the unknown call is not re-dispatched")
        # A mutation needs a fresh observation first.
        self.assertEqual(
            resumed.run("goal", ScriptedPlanner([ToolCall("fs_write", {"path": "report.md"})])).outcome,
            "reobserve-before-mutation",
        )

    def test_after_reobserving_a_mutation_may_be_proposed_and_unknowns_surface_once(self) -> None:
        crashing = FakeEdge(["fs_write"], crash_on="fs_write")
        agent = self.agent(crashing, allowlist=frozenset({"fs_write"}), mutating=frozenset({"fs_write"}))
        agent.prepare()
        with self.assertRaises(RuntimeError):
            agent.dispatch(ToolCall("fs_write", {"path": "a"}))
        edge = FakeEdge(["fs_read", "fs_write"])
        tools = frozenset({"fs_read", "fs_write"})
        resumed = self.agent(edge, allowlist=tools, mutating=frozenset({"fs_write"}))
        plan = ScriptedPlanner([ToolCall("fs_read", {"path": "a"}), ToolCall("fs_write", {"path": "a"})], answer="done")
        self.assertEqual(resumed.run("goal", plan).outcome, "finished")
        self.assertEqual([name for name, _ in edge.called], ["fs_read", "fs_write"])
        again = self.agent(FakeEdge(["fs_read"]), allowlist=tools)
        again.prepare()
        self.assertEqual(again.steps, [], "an unknown outcome is surfaced once, not on every start")

    def test_the_journal_holds_digests_not_content(self) -> None:
        agent = self.agent(FakeEdge(["fs_read"], {"fs_read": ToolOutcome(ok=True, result={"text": "SECRET-CONTENT"})}))
        agent.run("goal", ScriptedPlanner([ToolCall("fs_read", {"path": "private/notes.txt"})]))
        text = (self.root / "run" / "dispatch.jsonl").read_text(encoding="utf-8")
        self.assertNotIn("SECRET-CONTENT", text)
        self.assertNotIn("private/notes.txt", text)


class PrivateStore(Scratch):
    def test_the_store_is_owner_only(self) -> None:
        store = open_store(self.root, "run")
        if os.name != "nt":
            for path in (self.root, store.directory):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, path)

    def test_the_size_cap_fails_closed(self) -> None:
        store = open_store(self.root, "run", max_bytes=200)
        journal = DispatchJournal(store.journal_path, store.check_capacity)
        with self.assertRaises(StoreError):
            for index in range(20):
                journal.dispatched("fs_read", {"path": str(index)})

    def test_expired_runs_are_removed_and_completed_runs_deleted(self) -> None:
        old = open_store(self.root, "old")
        old.journal_path.write_text("{}\n", encoding="utf-8")
        os.utime(old.directory, (0, 0))
        fresh = open_store(self.root, "fresh", ttl_s=3600)
        self.assertFalse(old.directory.exists(), "an expired run is removed")
        fresh.delete()
        self.assertFalse(fresh.directory.exists())


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
            body, error = {"error": {"code": "PATH_ESCAPE", "message": "outside"}}, True
        else:
            body, error = {"result": {"text": "hello"}, "evidence": {"bytes": 5}}, False
        result = {"content": [{"type": "text", "text": json.dumps(body)}]}
        if error:
            result["isError"] = True
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "no"}}), flush=True)
        continue
    print("not json, ignored", flush=True)
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
'''


class StdioEdge(unittest.TestCase):
    def test_the_edge_client_speaks_mcp_over_stdio(self) -> None:
        env = {key: value for key, value in os.environ.items() if key in ("PATH", "SYSTEMROOT", "SystemRoot")}
        with Edge([sys.executable, "-c", FAKE_SERVER], env, timeout_s=20) as edge:
            self.assertEqual([tool.name for tool in edge.list_tools()], ["fs_read"])
            ok = edge.call_tool("fs_read", {"path": "a.txt"})
            self.assertEqual((ok.ok, ok.result, ok.evidence), (True, {"text": "hello"}, {"bytes": 5}))
            refused = edge.call_tool("fs_read", {"path": "../escape"})
            self.assertEqual((refused.ok, refused.error_code), (False, "PATH_ESCAPE"))

    def test_unexpected_results_and_a_dead_edge_fail_closed(self) -> None:
        with self.assertRaises(EdgeError):
            parse_tool_result({"content": []})
        with self.assertRaises(EdgeError):
            parse_tool_result({"content": [{"type": "text", "text": "not json"}]})
        with self.assertRaises(EdgeError):
            Edge([sys.executable, "-c", "pass"], {}, timeout_s=10).start()


class SourceBoundary(unittest.TestCase):
    """The agent spawns one child (the edge, in edge.py), runs no shell,
    opens no socket, and writes only through its private store."""

    def test_the_package_has_no_execution_or_network_primitive(self) -> None:
        package = ROOT / "orcel_agent"
        forbidden = [
            r"shell\s*=\s*True", r"\bos\.system\b", r"\bos\.popen\b", r"\bos\.exec", r"\bos\.spawn",
            r"\bimport socket\b", r"\bfrom socket\b", r"\burllib\b", r"\bhttp\.client\b", r"\bctypes\b",
            r"\bpickle\b", r"\beval\(", r"\bexec\(",
        ]
        spawners = []
        for path in sorted(package.glob("*.py")):
            text = path.read_text(encoding="utf-8")
            for pattern in forbidden:
                self.assertIsNone(re.search(pattern, text), f"{pattern} in {path.name}")
            if "subprocess" in text:
                spawners.append(path.name)
            if re.search(r"(?<![A-Za-z_])open\(|\.open\(|write_text|write_bytes", text):
                self.assertIn(path.name, {"journal.py"}, f"{path.name} writes files")
        self.assertEqual(spawners, ["edge.py"], "only the edge client spawns a process")
        edge = (package / "edge.py").read_text(encoding="utf-8")
        self.assertEqual(edge.count("subprocess.Popen("), 1)

    def test_no_third_party_import(self) -> None:
        allowed = {
            "__future__", "dataclasses", "hashlib", "json", "os", "pathlib", "queue", "shutil", "stat",
            "subprocess", "threading", "time", "typing", "uuid",
        }
        for path in sorted((ROOT / "orcel_agent").glob("*.py")):
            for line in path.read_text(encoding="utf-8").splitlines():
                match = re.match(r"\s*(?:from|import)\s+([A-Za-z_][\w]*)", line)
                if match and not line.lstrip().startswith("from ."):
                    self.assertIn(match.group(1), allowed, f"{path.name}: {line.strip()}")


if __name__ == "__main__":
    unittest.main()
