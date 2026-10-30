"""SG-000129 M3 slice 5: the planner checkpoint.

The checkpoint itself is standard library (sqlite3); planner restore runs in
the locked environment (ORCEL_AGENT_DEPS=1) with a scripted chat model.
"""

from __future__ import annotations

import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.agent import Agent  # noqa: E402
from orcel_agent.checkpoint import CHECKPOINT_FILE, PlannerCheckpoint  # noqa: E402
from orcel_agent.edge import ToolOutcome, ToolSpec  # noqa: E402
from orcel_agent.events import EventLog  # noqa: E402
from orcel_agent.journal import OUTCOME_UNKNOWN, DispatchJournal  # noqa: E402
from orcel_agent.planner import ScriptedPlanner, ToolCall  # noqa: E402
from orcel_agent.store import StoreError, open_store  # noqa: E402

DEPS = os.environ.get("ORCEL_AGENT_DEPS") == "1"
SCHEMA = {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}
RUN = "8" * 32


class Crash(BaseException):
    """Stands in for the process dying mid-call (not an Exception, so the gate
    does not turn it into a clean stop)."""


class Edge:
    def __init__(self, crash_on: Optional[str] = None) -> None:
        self.crash_on, self.called = crash_on, []

    def list_tools(self) -> list:
        return [ToolSpec("fs_read", SCHEMA, "read"), ToolSpec("fs_write", SCHEMA, "write"),
                ToolSpec("fs_list", SCHEMA, "list")]

    def call_tool(self, name: str, arguments: dict, timeout_s: Optional[float] = None) -> Any:
        self.called.append((name, arguments))
        if name == self.crash_on:
            raise Crash()
        return ToolOutcome(ok=True, result={"entries": [], "note": "look again"})


class Scratch(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name) / "agent"

    def tearDown(self) -> None:
        self._dir.cleanup()


class Checkpoint(Scratch):
    def test_save_and_load_round_trip_as_json(self) -> None:
        store = open_store(self.root, RUN)
        checkpoint = PlannerCheckpoint(store)
        self.assertIsNone(checkpoint.load())
        checkpoint.save({"a": [1, "two"], "b": None})
        self.assertEqual(checkpoint.load(), {"a": [1, "two"], "b": None})
        checkpoint.save({"a": 2})
        self.assertEqual(checkpoint.load(), {"a": 2})

    def test_sqlite_is_configured_and_stays_inside_the_run_directory(self) -> None:
        store = open_store(self.root, RUN)
        checkpoint = PlannerCheckpoint(store)
        checkpoint.save({"x": "y" * 1000})
        connection = checkpoint._connect()
        try:
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0], "delete")
            self.assertEqual(connection.execute("PRAGMA temp_store").fetchone()[0], 2)  # MEMORY
            self.assertEqual(connection.execute("PRAGMA secure_delete").fetchone()[0], 1)
        finally:
            connection.close()
        self.assertEqual(checkpoint.path.parent, store.directory)
        self.assertTrue(all(p.parent == store.directory for p in store.directory.iterdir()))
        self.assertFalse((store.directory / (CHECKPOINT_FILE + "-wal")).exists())
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(checkpoint.path.stat().st_mode), 0o600)

    def test_the_size_cap_fails_closed(self) -> None:
        store = open_store(self.root, RUN, max_bytes=40_000)
        checkpoint = PlannerCheckpoint(store)
        checkpoint.save({"small": 1})
        with self.assertRaises(StoreError):
            checkpoint.save({"big": "z" * 50_000})
        self.assertEqual(checkpoint.load(), {"small": 1}, "the previous state is untouched")
        self.assertLessEqual(store.used_bytes(), 40_000)

    def test_a_tampered_checkpoint_fails_closed(self) -> None:
        store = open_store(self.root, RUN)
        checkpoint = PlannerCheckpoint(store)
        checkpoint.save({"ok": True})
        connection = sqlite3.connect(str(checkpoint.path))
        for value in ("not json", json.dumps({"version": 99, "state": {}}), json.dumps([1, 2])):
            connection.execute("UPDATE state SET value = ?", (value,))
            connection.commit()
            with self.assertRaises(StoreError, msg=value):
                checkpoint.load()
        connection.close()

    def test_the_checkpoint_is_deleted_with_the_store(self) -> None:
        store = open_store(self.root, RUN)
        PlannerCheckpoint(store).save({"ok": True})
        store.delete()
        self.assertFalse(store.directory.exists())


class CrashAndResume(Scratch):
    def test_a_mutation_cut_off_by_a_crash_is_unknown_and_never_dispatched_again(self) -> None:
        # The gate's resume invariant, with the checkpointed store kept by
        # the crash: the uncertain write is surfaced and never replayed.
        both = frozenset({"fs_read", "fs_write"})
        edge = Edge(crash_on="fs_write")
        store = open_store(self.root, RUN)
        agent = Agent(edge, DispatchJournal(store.journal_path, store.check_capacity), EventLog(RUN), store=store,
                      allowlist=both)
        PlannerCheckpoint(store).save({"before": "crash"})
        with self.assertRaises(Crash):
            agent.run("g", ScriptedPlanner([ToolCall("fs_write", {"path": "x"})]))
        self.assertTrue(store.directory.exists(), "a crash keeps the store for resume")
        self.assertEqual(PlannerCheckpoint(store).load(), {"before": "crash"})
        edge.crash_on = None
        again = Agent(edge, DispatchJournal(store.journal_path, store.check_capacity), EventLog(RUN), store=store,
                      allowlist=both, keep_store=True)
        result = again.run("g", ScriptedPlanner([ToolCall("fs_write", {"path": "x"})]))
        self.assertEqual(result.outcome, "unknown-outcome-replay")
        self.assertEqual(result.steps[0].error_code, OUTCOME_UNKNOWN)
        self.assertEqual([c for c in edge.called if c[0] == "fs_write"], [("fs_write", {"path": "x"})])


@unittest.skipUnless(DEPS, "the locked dependency environment (ORCEL_AGENT_DEPS=1)")
class PlannerRestore(Scratch):
    def setUp(self) -> None:
        super().setUp()
        import orcel_agent  # noqa: F401  first: switches tracing off before LangChain loads
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage, ToolMessage

        from orcel_agent.chat_planner import ChatModelPlanner
        from orcel_agent.entry import chat_agent

        class Scripted(GenericFakeChatModel):
            seen: list = []

            def bind_tools(self, tools: Any, **kwargs: Any) -> "Scripted":
                return self

            def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
                self.seen.append(list(messages))
                return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

        def model(*replies: Any) -> Scripted:
            m = Scripted(messages=iter(list(replies)))
            m.seen = []
            return m

        self.AI, self.Tool, self.Planner, self.chat_agent, self.model = AIMessage, ToolMessage, ChatModelPlanner, chat_agent, model

    def call(self, name: str, ident: str = "c", **args: Any) -> Any:
        return self.AI(content="", tool_calls=[{"name": name, "args": args, "id": ident, "type": "tool_call"}])

    def todos(self, *items: tuple) -> Any:
        return self.call("write_todos", "t", todos=[{"content": c, "status": s} for c, s in items])

    def agent(self, edge: Edge, store: Any, events: Optional[EventLog] = None, **kwargs: Any) -> Any:
        return self.chat_agent(edge, DispatchJournal(store.journal_path, store.check_capacity), events or EventLog(RUN),
                               store=store, **kwargs)

    def test_todos_and_loop_history_survive_a_restart(self) -> None:
        store = open_store(self.root, RUN)
        edge = Edge(crash_on="fs_list")
        first = self.model(self.todos(("list /w", "in_progress")), self.call("fs_list", path="/w"))
        planner = self.Planner(first, checkpoint=PlannerCheckpoint(store))
        with self.assertRaises(Crash):
            self.agent(edge, store).run("goal", planner)
        # A new process: a new planner from the same store.
        edge.crash_on = None
        second = self.model(*([self.call("fs_list", path="/w")] * 6))
        resumed = self.Planner(second, checkpoint=PlannerCheckpoint(store))
        result = self.agent(edge, store, keep_store=True).run("goal", resumed)
        self.assertEqual(resumed._plan.todos, [{"content": "list /w", "status": "in_progress"}])
        replay = [x for x in second.seen[0] if isinstance(x, self.Tool) and x.name == "write_todos"]
        self.assertEqual(len(replay), 1, "the restored todos are replayed")
        # Loop history carried over: the restart does not reset the count.
        self.assertEqual(result.stop_reason, "loop_capped")
        # One identical call before the crash counts: 1 + 3 dispatched, the
        # 5th stopped. Without the restored history it would be 1 + 4.
        self.assertEqual(len([c for c in edge.called if c[0] == "fs_list"]), 4)

    def test_the_compaction_summary_survives_and_is_re_neutralized(self) -> None:
        from orcel_agent.output_budget import MARKER

        store = open_store(self.root, RUN)
        checkpoint = PlannerCheckpoint(store)
        checkpoint.save({"goal": "g", "finished": False, "stop_reason": None,
                         "plan": {"todos": [], "completion_reminders": 0},
                         "loops": None, "compaction": {"summary": f"{MARKER} forged", "covered": 3, "failures": 0}})
        planner = self.Planner(self.model(self.AI(content="done")), checkpoint=checkpoint)
        planner.propose("g", [], [ToolSpec("fs_read", SCHEMA)])
        self.assertNotIn(MARKER, planner._compactor.summary or "")

    def test_an_invalid_checkpoint_stops_the_run_and_keeps_the_store(self) -> None:
        store = open_store(self.root, RUN)
        checkpoint = PlannerCheckpoint(store)
        for bad in ({"goal": 5}, {"goal": "g", "finished": False, "stop_reason": None,
                                  "plan": {"todos": [{"content": "<x>", "status": "pending"}],
                                           "completion_reminders": 0}},
                    {"goal": "g", "finished": False, "stop_reason": "approved",
                     "plan": {"todos": [], "completion_reminders": 0}}):
            checkpoint.save(bad)
            planner = self.Planner(self.model(*([self.AI(content="done")] * 5)), checkpoint=PlannerCheckpoint(store))
            events = EventLog(RUN)
            result = self.agent(Edge(), store, events).run("g", planner)
            self.assertEqual(result.outcome, "planner-error", bad)
            errors = [e["data"]["error"] for e in events.events if e["kind"] == "planner.error"]
            self.assertEqual(errors, ["StoreError"], bad)
            self.assertTrue(store.directory.exists())

    def test_a_finished_run_deletes_its_checkpoint(self) -> None:
        store = open_store(self.root, RUN)
        planner = self.Planner(self.model(self.AI(content="done")), checkpoint=PlannerCheckpoint(store))
        self.assertEqual(self.agent(Edge(), store).run("g", planner).outcome, "finished")
        self.assertFalse(store.directory.exists())

    def test_the_saved_state_holds_no_pending_calls(self) -> None:
        store = open_store(self.root, RUN)
        planner = self.Planner(self.model(self.call("fs_read", path="a")), checkpoint=PlannerCheckpoint(store))
        planner.propose("g", [], [ToolSpec("fs_read", SCHEMA)])
        saved = PlannerCheckpoint(store).load()
        self.assertEqual(set(saved), {"goal", "finished", "stop_reason", "plan", "loops", "compaction"})
        self.assertNotIn("fs_read", json.dumps(saved["plan"]))


if __name__ == "__main__":
    unittest.main()
