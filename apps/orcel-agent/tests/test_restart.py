"""Real process kills and restarts (Priority A, after the SG-000129 closeout).

Each case runs the agent in a child process against a scripted stdio MCP
server, kills that child with the operating system (SIGKILL on Unix,
TerminateProcess on Windows) while a call is in flight, and resumes the run
in a second, new child process from the kept store. The server appends every
`tools/call` it receives to a log, so whether a mutation reached the edge
twice is read from the server's side, not from the agent's own account.

The M3 case (the checkpointed chat planner, a scripted chat model, never a
model) runs in the locked dependency environment (ORCEL_AGENT_DEPS=1).
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEPS = os.environ.get("ORCEL_AGENT_DEPS") == "1"
RUN = "7" * 32

#: A scripted MCP server. argv: the call log, then a JSON map from
#: "tool:path" to "block" or "refuse:<CODE>" (anything else succeeds).
SERVER = r'''
import json, os, sys, time
log, behaviour = sys.argv[1], json.loads(sys.argv[2])
def note(line):
    with open(log, "a", encoding="utf-8") as f:
        f.write(line + "\n")
note(f"PID {os.getpid()}")
schema = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
tools = [{"name": n, "inputSchema": schema} for n in ("fs_read", "fs_write", "fs_list")]
for line in sys.stdin:
    message = json.loads(line)
    if "id" not in message:
        continue
    if message["method"] == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {}}
    elif message["method"] == "tools/list":
        result = {"tools": tools}
    else:
        name, args = message["params"]["name"], message["params"]["arguments"]
        key = f"{name}:{args.get('path')}"
        action = behaviour.get(key, "ok")
        note(f"CALL {key} {action}")
        if action == "block":
            time.sleep(60)
            continue
        if action.startswith("refuse:"):
            body = {"error": {"code": action.split(":", 1)[1], "message": "refused by the script"}}
            result = {"isError": True, "content": [{"type": "text", "text": json.dumps(body)}]}
        else:
            body = {"result": {"entries": [], "path": args.get("path")}, "evidence": {}}
            result = {"content": [{"type": "text", "text": json.dumps(body)}]}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)
'''

#: The gate (M1 loop) in a child process. argv: package root, store root,
#: run id, call log, server behaviour, allowlist, plan, result file.
GATE_CHILD = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from orcel_agent.agent import Agent, AgentStop
from orcel_agent.edge import Edge
from orcel_agent.events import EventLog
from orcel_agent.journal import DispatchJournal
from orcel_agent.planner import ScriptedPlanner, ToolCall
from orcel_agent.store import open_store
store = open_store(Path(sys.argv[2]), sys.argv[3])
edge = Edge([sys.executable, "-c", SERVER, sys.argv[4], sys.argv[5]], {}, timeout_s=90)
edge.start()
agent = Agent(edge, DispatchJournal(store.journal_path, store.check_capacity), EventLog("child"),
              allowlist=frozenset(json.loads(sys.argv[6])))
plan = ScriptedPlanner([ToolCall(tool, {"path": path}) for tool, path in json.loads(sys.argv[7])])
result = agent.run("goal", plan)
Path(sys.argv[8]).write_text(json.dumps({
    "outcome": result.outcome,
    "steps": [[s.call.tool, s.error_code, s.resumed] for s in result.steps],
}), encoding="utf-8")
'''.replace("SERVER", repr(SERVER))


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        base = Path(self._dir.name)
        self.root, self.log = base / "agent", base / "calls.log"
        self.servers: list[int] = []

    def tearDown(self) -> None:
        for pid in self.servers:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        self._dir.cleanup()

    def calls(self) -> list[str]:
        if not self.log.is_file():
            return []
        lines = self.log.read_text(encoding="utf-8").splitlines()
        self.servers = [int(line.split()[1]) for line in lines if line.startswith("PID ")]
        return [line[5:] for line in lines if line.startswith("CALL ")]

    def child(self, code: str, *argv: str) -> subprocess.Popen:
        return subprocess.Popen([sys.executable, "-I", "-B", "-c", code, str(ROOT), str(self.root), RUN,
                                 str(self.log), *argv])

    def kill_when_blocked(self, process: subprocess.Popen, key: str) -> None:
        """Wait until the server holds `key` unanswered, then kill the agent
        process (and the orphaned server) through the operating system."""
        deadline = time.monotonic() + 60
        try:
            while time.monotonic() < deadline and f"{key} block" not in self.calls():
                self.assertIsNone(process.poll(), f"the agent exited early: {self.calls()}")
                time.sleep(0.05)
            self.assertIn(f"{key} block", self.calls(), "the call was in flight")
        finally:
            process.kill()
            process.wait()
        self.calls()
        for pid in self.servers:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass

    def gate(self, behaviour: dict, plan: list, result: Path) -> subprocess.Popen:
        return self.child(GATE_CHILD, json.dumps(behaviour), json.dumps(["fs_read", "fs_write"]),
                          json.dumps(plan), str(result))

    def resume(self, plan: list) -> dict:
        result = Path(self._dir.name) / "resumed.json"
        process = self.gate({}, plan, result)
        self.assertEqual(process.wait(timeout=120), 0, "the resumed process finished")
        return json.loads(result.read_text(encoding="utf-8"))


class Restart(Harness):
    def test_a_write_cut_off_by_a_kill_is_unknown_and_never_reaches_the_edge_again(self) -> None:
        first = self.gate({"fs_write:x": "block"}, [["fs_read", "a"], ["fs_write", "x"]],
                          Path(self._dir.name) / "first.json")
        self.kill_when_blocked(first, "fs_write:x")
        resumed = self.resume([["fs_read", "a"], ["fs_write", "x"]])
        self.assertEqual(resumed["outcome"], "unknown-outcome-replay")
        self.assertEqual(resumed["steps"][:2], [["fs_read", None, True], ["fs_write", "OUTCOME_UNKNOWN", True]])
        self.assertEqual([c for c in self.calls() if c.startswith("fs_write")], ["fs_write:x block"],
                         "the server saw the write once, across both processes")

    def test_a_refusal_before_a_kill_stays_final_after_the_restart(self) -> None:
        first = self.gate({"fs_write:x": "refuse:POLICY_DENIED", "fs_read:y": "block"},
                          [["fs_write", "x"], ["fs_read", "y"]], Path(self._dir.name) / "first.json")
        self.kill_when_blocked(first, "fs_read:y")
        resumed = self.resume([["fs_write", "x"], ["fs_read", "y"], ["fs_write", "x"]])
        self.assertEqual(resumed["outcome"], "repeat-refused")
        self.assertEqual(resumed["steps"][0], ["fs_write", "POLICY_DENIED", True], "the refusal is evidence after it")
        self.assertEqual([c for c in self.calls() if c.startswith("fs_write")], ["fs_write:x refuse:POLICY_DENIED"])
        # The read the kill cut off was observed again (a read may be).
        self.assertEqual([c for c in self.calls() if c.startswith("fs_read")], ["fs_read:y block", "fs_read:y ok"])

    def test_a_completed_write_before_a_kill_is_never_dispatched_again(self) -> None:
        first = self.gate({"fs_read:y": "block"}, [["fs_write", "x"], ["fs_read", "y"]],
                          Path(self._dir.name) / "first.json")
        self.kill_when_blocked(first, "fs_read:y")
        resumed = self.resume([["fs_write", "x"], ["fs_read", "y"], ["fs_write", "x"]])
        self.assertEqual(resumed["outcome"], "completed-mutation-replay")
        self.assertEqual([c for c in self.calls() if c.startswith("fs_write")], ["fs_write:x ok"])


#: The checkpointed M3 chat planner in a child process, with a scripted chat
#: model. argv after the common four: server behaviour, the replies (a JSON
#: list of ["todos", [[content, status], ...]] / ["call", tool, path] /
#: ["done"]), the result file.
CHAT_CHILD = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import orcel_agent  # first: switches tracing off before LangChain loads
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage
from orcel_agent.chat_planner import ChatModelPlanner
from orcel_agent.checkpoint import PlannerCheckpoint
from orcel_agent.edge import Edge
from orcel_agent.entry import chat_agent
from orcel_agent.events import EventLog
from orcel_agent.journal import DispatchJournal
from orcel_agent.store import open_store

class Scripted(GenericFakeChatModel):
    seen: list = []

    def bind_tools(self, tools, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.seen.append(list(messages))
        return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

def reply(item, index):
    if item[0] == "todos":
        todos = [{"content": c, "status": s} for c, s in item[1]]
        return AIMessage(content="", tool_calls=[{"name": "write_todos", "args": {"todos": todos},
                                                  "id": f"t{index}", "type": "tool_call"}])
    if item[0] == "call":
        return AIMessage(content="", tool_calls=[{"name": item[1], "args": {"path": item[2]},
                                                  "id": f"c{index}", "type": "tool_call"}])
    return AIMessage(content="done")

store = open_store(Path(sys.argv[2]), sys.argv[3])
edge = Edge([sys.executable, "-c", SERVER, sys.argv[4], sys.argv[5]], {}, timeout_s=90)
edge.start()
replies = [reply(item, i) for i, item in enumerate(json.loads(sys.argv[6]))]
model = Scripted(messages=iter(replies))
model.seen = []
planner = ChatModelPlanner(model, checkpoint=PlannerCheckpoint(store))
agent = chat_agent(edge, DispatchJournal(store.journal_path, store.check_capacity), EventLog("child"),
                   store=store, allowlist=frozenset({"fs_list"}), keep_store=True)
result = agent.run("goal", planner)
Path(sys.argv[7]).write_text(json.dumps({
    "outcome": result.outcome,
    "todos": planner._plan.todos,
    # What the model was shown on its first call: restored todos are
    # replayed to it as a write_todos tool message.
    "first_call_todos": [str(m.content) for m in (model.seen[0] if model.seen else [])
                         if getattr(m, "name", None) == "write_todos"],
    "steps": [[s.call.tool, s.error_code, s.resumed] for s in result.steps],
    "checkpoint_kept": PlannerCheckpoint(store).load() is not None,
}), encoding="utf-8")
'''.replace("SERVER", repr(SERVER))


@unittest.skipUnless(DEPS, "the locked dependency environment (ORCEL_AGENT_DEPS=1)")
class ChatRestart(Harness):
    def test_the_m3_checkpoint_survives_a_real_kill_and_the_cut_off_call_is_surfaced(self) -> None:
        first = self.child(CHAT_CHILD, json.dumps({"fs_list:/b": "block"}),
                           json.dumps([["todos", [["list /a and /b", "in_progress"]]],
                                       ["call", "fs_list", "/a"], ["call", "fs_list", "/b"]]),
                           str(Path(self._dir.name) / "first.json"))
        self.kill_when_blocked(first, "fs_list:/b")
        result = Path(self._dir.name) / "resumed.json"
        second = self.child(CHAT_CHILD, json.dumps({}),
                            json.dumps([["call", "fs_list", "/c"],
                                        ["todos", [["list /a and /b", "completed"]]], ["done"]]), str(result))
        self.assertEqual(second.wait(timeout=120), 0, "the resumed process finished")
        resumed: dict[str, Any] = json.loads(result.read_text(encoding="utf-8"))
        # The planner state written before the kill was restored by a new
        # process, through the checkpoint file the kill left behind.
        replayed = resumed["first_call_todos"]
        self.assertEqual(len(replayed), 1, resumed)
        self.assertIn("list /a and /b", replayed[0])
        self.assertIn("in_progress", replayed[0])
        self.assertEqual(resumed["todos"], [{"content": "list /a and /b", "status": "completed"}])
        self.assertEqual(resumed["steps"][:2], [["fs_list", None, True], ["fs_list", "OUTCOME_UNKNOWN", True]])
        self.assertEqual(resumed["outcome"], "finished")
        self.assertTrue(resumed["checkpoint_kept"], "keep_store keeps the checkpoint for inspection")
        self.assertEqual(self.calls(), ["fs_list:/a ok", "fs_list:/b block", "fs_list:/c ok"])


if __name__ == "__main__":
    unittest.main()
