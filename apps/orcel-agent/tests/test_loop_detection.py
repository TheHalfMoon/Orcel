"""SG-000129 slice 3: loop detection, ported from DeerFlow's
backend/tests/test_loop_detection_middleware.py at commit
81e1ab8dcc86574cfac0ecdfe3636b775a08c567 (MIT; see third_party/deer-flow/LICENSE).

Each test names the DeerFlow test it ports. They are rewritten against
`LoopDetector.track` (one detector per run) instead of the LangGraph
middleware hooks, with Orcel tool names. DeerFlow tests of run/thread
scoping, LRU eviction, fallback run ids, threading, run events, config
loading and graph integration have no counterpart here: the adapted detector
has none of that machinery.

The detector is standard library only; the planner integration tests at the
end need the locked environment (ORCEL_AGENT_DEPS=1).
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.loop_detection import (  # noqa: E402
    HARD_STOP_MSG,
    MAX_PENDING_WARNINGS,
    WARNING_MSG,
    LoopDetector,
    _hash_tool_calls,
)

DEPS = os.environ.get("ORCEL_AGENT_DEPS") == "1"


def read(path="/w/app.py", **args):
    return {"name": "fs_read_range", "args": {"path": path, **args}}


def listing(path="/w"):
    return {"name": "fs_list", "args": {"path": path}}


def hard(detector: LoopDetector, calls: list) -> bool:
    decision = detector.track(calls)
    return decision is not None and decision.hard_stop


class HashToolCalls(unittest.TestCase):
    """Ports TestHashToolCalls."""

    def test_same_calls_same_hash(self):
        self.assertEqual(_hash_tool_calls([listing()]), _hash_tool_calls([listing()]))

    def test_different_calls_different_hash(self):
        self.assertNotEqual(_hash_tool_calls([listing("/a")]), _hash_tool_calls([listing("/b")]))

    def test_order_independent(self):
        a = _hash_tool_calls([listing(), {"name": "fs_read", "args": {"path": "/tmp"}}])
        b = _hash_tool_calls([{"name": "fs_read", "args": {"path": "/tmp"}}, listing()])
        self.assertEqual(a, b)

    def test_empty_calls(self):
        self.assertTrue(_hash_tool_calls([]))

    def test_stringified_dict_args_match_dict_args(self):
        as_dict = read("/tmp/demo.py", start_line="1", max_lines="150")
        as_string = {"name": "fs_read_range", "args": '{"path":"/tmp/demo.py","start_line":"1","max_lines":"150"}'}
        self.assertEqual(_hash_tool_calls([as_dict]), _hash_tool_calls([as_string]))

    def test_non_finite_line_bound_does_not_crash(self):
        # A JSON 1e999 parses to float('inf'): an unusable bound, read as open-ended.
        self.assertEqual(_hash_tool_calls([read("/tmp/demo.py", start_line=float("inf"))]),
                         _hash_tool_calls([read("/tmp/demo.py")]))
        self.assertTrue(_hash_tool_calls([read("/tmp/demo.py", max_lines=float("inf"))]))

    def test_stringified_non_dict_args_do_not_crash(self):
        self.assertTrue(_hash_tool_calls([{"name": "fs_find", "args": '"*.py"'}]))
        self.assertTrue(_hash_tool_calls([{"name": "fs_find", "args": "*.py"}]))

    def test_find_and_search_patterns_affect_hash(self):
        for tool in ("fs_find", "fs_search"):
            self.assertNotEqual(_hash_tool_calls([{"name": tool, "args": {"path": "/w", "pattern": "a"}}]),
                                _hash_tool_calls([{"name": tool, "args": {"path": "/w", "pattern": "b"}}]))

    def test_write_and_edit_content_affect_hash(self):
        for tool in ("fs_write", "fs_edit"):
            self.assertNotEqual(_hash_tool_calls([{"name": tool, "args": {"path": "/a", "content": "v1"}}]),
                                _hash_tool_calls([{"name": tool, "args": {"path": "/a", "content": "v2"}}]))


class ReadRangeKey(unittest.TestCase):
    """Ports TestReadFileRangeKey: paging is progress, re-reading is a loop."""

    def test_adjacent_pages_are_distinct_calls(self):
        pages = [read(start_line=start, max_lines=40) for start in (1, 41, 81, 121, 161)]
        self.assertEqual(len({_hash_tool_calls([page]) for page in pages}), len(pages))

    def test_paging_through_a_file_does_not_hard_stop(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=5)
        for start in range(1, 401, 40):
            self.assertIsNone(detector.track([read(start_line=start, max_lines=40)]), start)

    def test_repeating_one_range_still_hard_stops(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=5)
        call = [read(start_line=1, max_lines=40)]
        self.assertFalse(any(hard(detector, call) for _ in range(4)))
        self.assertTrue(hard(detector, call))

    def test_rereading_the_same_page_counts_even_between_new_pages(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=3)
        repeated = [read(start_line=1, max_lines=40)]
        self.assertFalse(hard(detector, repeated))
        self.assertFalse(hard(detector, [read(start_line=41, max_lines=40)]))
        self.assertFalse(hard(detector, repeated))
        self.assertFalse(hard(detector, [read(start_line=81, max_lines=40)]))
        self.assertTrue(hard(detector, repeated))

    def test_omitted_count_matches_a_read_from_the_first_line(self):
        self.assertEqual(_hash_tool_calls([read(start_line=1)]), _hash_tool_calls([read()]))

    def test_omitted_count_is_not_a_single_line_read(self):
        self.assertNotEqual(_hash_tool_calls([read(start_line=10)]), _hash_tool_calls([read(start_line=10, max_lines=1)]))

    def test_line_bounds_are_clamped_to_the_first_line(self):
        self.assertEqual(_hash_tool_calls([read(start_line=0, max_lines=40)]),
                         _hash_tool_calls([read(start_line=1, max_lines=40)]))

    def test_unparsable_count_reads_as_open_ended(self):
        self.assertEqual(_hash_tool_calls([read(start_line=5, max_lines="oops")]), _hash_tool_calls([read(start_line=5)]))

    def test_different_paths_stay_distinct(self):
        self.assertNotEqual(_hash_tool_calls([read("/w/a.py", start_line=1, max_lines=40)]),
                            _hash_tool_calls([read("/w/b.py", start_line=1, max_lines=40)]))

    def test_whole_file_read_is_its_own_key(self):
        # Orcel-specific: fs_read reads the whole file; repeating it is a loop.
        detector = LoopDetector(warn_threshold=3, hard_limit=3)
        call = [{"name": "fs_read", "args": {"path": "/w/a.py"}}]
        self.assertFalse(hard(detector, call))
        self.assertFalse(hard(detector, call))
        self.assertTrue(hard(detector, call))


class GenericToolKey(unittest.TestCase):
    """Ports TestGenericToolKey: every argument that changes a call counts."""

    def test_non_salient_args_affect_hash(self):
        cases = [
            ("fs_search", {"path": "/w", "pattern": "foo", "max_results": 10}, {"path": "/w", "pattern": "foo", "max_results": 20}),
            ("fs_find", {"path": "/w", "pattern": "*.py", "max_depth": 1}, {"path": "/w", "pattern": "*.py", "max_depth": 3}),
            ("fs_list", {"path": "/w"}, {"path": "/w", "cursor": "next"}),
        ]
        for name, first, second in cases:
            self.assertNotEqual(_hash_tool_calls([{"name": name, "args": first}]),
                                _hash_tool_calls([{"name": name, "args": second}]), name)

    def test_ui_narration_does_not_affect_hash(self):
        for name, args in (("fs_list", {"path": "/w"}), ("fs_find", {"path": "/w", "pattern": "*.py"}),
                           ("fs_search", {"path": "/w", "pattern": "foo"})):
            self.assertEqual(_hash_tool_calls([{"name": name, "args": {**args, "description": "look"}}]),
                             _hash_tool_calls([{"name": name, "args": {**args, "description": "look again"}}]), name)

    def test_description_payload_affects_hash_elsewhere(self):
        self.assertNotEqual(_hash_tool_calls([{"name": "workspace_get", "args": {"description": "a"}}]),
                            _hash_tool_calls([{"name": "workspace_get", "args": {"description": "b"}}]))

    def test_paging_a_search_does_not_hard_stop(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=5)
        for page in range(10):
            call = {"name": "fs_search", "args": {"path": "/w", "pattern": "x", "cursor": str(page)}}
            self.assertFalse(hard(detector, [call]), page)

    def test_repeating_one_page_still_hard_stops(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=5)
        call = [{"name": "fs_search", "args": {"path": "/w", "pattern": "x", "cursor": "5"}}]
        self.assertFalse(any(hard(detector, call) for _ in range(4)))
        self.assertTrue(hard(detector, call))


class IdenticalCallSets(unittest.TestCase):
    """Ports TestLoopDetection (detection semantics, single scope)."""

    def test_no_tool_calls_returns_none(self):
        self.assertIsNone(LoopDetector().track([]))

    def test_below_threshold_returns_none(self):
        detector = LoopDetector(warn_threshold=3)
        self.assertIsNone(detector.track([listing()]))
        self.assertIsNone(detector.track([listing()]))

    def test_warn_at_threshold_is_queued_once(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=10)
        for _ in range(2):
            detector.track([listing()])
        decision = detector.track([listing()])
        self.assertEqual((decision.action, decision.message), ("warn", WARNING_MSG))
        self.assertEqual(detector.drain_warnings(), [WARNING_MSG])
        self.assertEqual(detector.drain_warnings(), [], "drained after injection")
        self.assertIsNone(detector.track([listing()]), "warned once per hash")
        self.assertEqual(detector.drain_warnings(), [])

    def test_hard_stop_at_limit(self):
        detector = LoopDetector(warn_threshold=2, hard_limit=4)
        decisions = [detector.track([listing()]) for _ in range(4)]
        self.assertTrue(decisions[-1].hard_stop)
        self.assertEqual(decisions[-1].message, HARD_STOP_MSG)
        self.assertEqual(decisions[-1].detection_layer, "identical_call_set")
        self.assertEqual([d.action for d in detector.decisions], ["warn", "hard_stop"])

    def test_different_calls_dont_trigger(self):
        detector = LoopDetector(warn_threshold=2, hard_limit=3)
        for index in range(10):
            self.assertIsNone(detector.track([listing(f"/{index}")]))

    def test_window_sliding(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=10, window_size=4)
        detector.track([listing("/a")])
        detector.track([listing("/a")])
        for index in range(4):
            detector.track([listing(f"/other{index}")])
        self.assertIsNone(detector.track([listing("/a")]), "earlier calls slid out of the window")

    def test_warned_hashes_are_pruned_to_the_window(self):
        detector = LoopDetector(warn_threshold=2, hard_limit=10, window_size=3)
        detector.track([listing("/a")])
        self.assertEqual(detector.track([listing("/a")]).action, "warn")
        for index in range(3):
            detector.track([listing(f"/b{index}")])
        detector.track([listing("/a")])
        self.assertEqual(detector.track([listing("/a")]).action, "warn", "a new burst warns again")

    def test_pending_warnings_are_capped(self):
        detector = LoopDetector(warn_threshold=1, hard_limit=100, window_size=50)
        for index in range(MAX_PENDING_WARNINGS + 3):
            detector.track([listing(f"/{index}")])
        self.assertEqual(len(detector.drain_warnings()), MAX_PENDING_WARNINGS)


class ToolFrequency(unittest.TestCase):
    """Ports TestToolFrequencyDetection and TestToolCallBatchDecisions."""

    def detector(self, **kwargs):
        kwargs.setdefault("warn_threshold", 100)
        kwargs.setdefault("hard_limit", 200)
        return LoopDetector(**kwargs)

    def test_below_freq_warn_returns_none(self):
        detector = self.detector(tool_freq_warn=5, tool_freq_hard_limit=10)
        for index in range(4):
            self.assertIsNone(detector.track([read(f"/{index}")]))

    def test_freq_warn_at_threshold_and_only_once(self):
        detector = self.detector(tool_freq_warn=5, tool_freq_hard_limit=10)
        decisions = [detector.track([read(f"/{index}")]) for index in range(7)]
        self.assertEqual(decisions[4].action, "warn")
        self.assertEqual(decisions[4].detection_layer, "tool_frequency")
        self.assertIn("fs_read_range", decisions[4].message)
        self.assertIsNone(decisions[5])
        self.assertIsNone(decisions[6])

    def test_freq_hard_stop_at_limit(self):
        detector = self.detector(tool_freq_warn=5, tool_freq_hard_limit=8)
        decisions = [detector.track([read(f"/{index}")]) for index in range(8)]
        self.assertTrue(decisions[-1].hard_stop)
        self.assertEqual(decisions[-1].detection_layer, "tool_frequency")
        self.assertEqual(decisions[-1].count, 8)

    def test_windowed_decay_avoids_hard_stop_when_interleaved(self):
        detector = self.detector(window_size=10, tool_freq_warn=6, tool_freq_hard_limit=8)
        for index in range(40):
            call = read(f"/{index}") if index % 2 == 0 else listing(f"/{index}")
            decision = detector.track([call])
            self.assertFalse(decision is not None and decision.hard_stop, index)

    def test_rapid_identical_tool_type_in_one_window_still_hard_stops(self):
        detector = self.detector(window_size=5, tool_freq_warn=3, tool_freq_hard_limit=6)
        decisions = [detector.track([read(f"/{index}")]) for index in range(6)]
        self.assertTrue(decisions[-1].hard_stop, "the frequency window is sized to the hard limit, not window_size")

    def test_different_tools_tracked_independently(self):
        detector = self.detector(tool_freq_warn=3, tool_freq_hard_limit=100)
        detector.track([read("/1")])
        detector.track([read("/2")])
        self.assertIsNone(detector.track([listing("/1")]))
        self.assertEqual(detector.track([read("/3")]).tool_names, ("fs_read_range",))

    def test_multi_tool_single_response_counted(self):
        detector = self.detector(tool_freq_warn=3, tool_freq_hard_limit=100)
        decision = detector.track([read("/1"), read("/2"), read("/3")])
        self.assertEqual(decision.detection_layer, "tool_frequency")

    def test_override_tool_uses_override_thresholds(self):
        detector = self.detector(tool_freq_warn=3, tool_freq_hard_limit=5,
                                 tool_freq_overrides={"fs_search": (10, 20)})
        for index in range(9):
            decision = detector.track([{"name": "fs_search", "args": {"path": "/w", "pattern": str(index)}}])
            self.assertIsNone(decision, index)

    def test_non_override_tool_falls_back_to_global(self):
        detector = self.detector(tool_freq_warn=3, tool_freq_hard_limit=5,
                                 tool_freq_overrides={"fs_search": (10, 20)})
        decisions = [detector.track([read(f"/{index}")]) for index in range(5)]
        self.assertTrue(decisions[-1].hard_stop)

    def test_hash_detection_takes_priority(self):
        detector = LoopDetector(warn_threshold=3, hard_limit=10, tool_freq_warn=3, tool_freq_hard_limit=100)
        decisions = [detector.track([listing("/same")]) for _ in range(3)]
        self.assertEqual(decisions[-1].detection_layer, "identical_call_set")

    def test_single_batch_crossing_both_thresholds_hard_stops(self):
        detector = LoopDetector(warn_threshold=1, hard_limit=10, tool_freq_warn=2, tool_freq_hard_limit=3)
        decision = detector.track([read("/1"), read("/2"), read("/3")])
        self.assertTrue(decision.hard_stop)

    def test_identical_call_warning_cannot_mask_frequency_hard_stop(self):
        detector = LoopDetector(warn_threshold=2, hard_limit=10, tool_freq_warn=100, tool_freq_hard_limit=4)
        batch = [read("/same"), read("/a"), read("/b")]
        detector.track(batch)
        decision = detector.track(batch)
        self.assertTrue(decision.hard_stop)
        self.assertEqual(decision.detection_layer, "tool_frequency")

    def test_other_tool_eviction_rearms_frequency_warning(self):
        detector = self.detector(window_size=4, tool_freq_warn=3, tool_freq_hard_limit=4)
        for index in range(3):
            detector.track([read(f"/{index}")])
        self.assertIn("fs_read_range", detector.drain_warnings()[0])
        for index in range(4):
            detector.track([listing(f"/{index}")])
        decisions = [detector.track([read(f"/x{index}")]) for index in range(3)]
        self.assertEqual(decisions[-1].action, "warn", "the decayed burst re-armed the warning")


@unittest.skipUnless(DEPS, "the locked dependency environment (ORCEL_AGENT_DEPS=1)")
class PlannerIntegration(unittest.TestCase):
    """The adapted hooks: warnings at the next model call, hard stop as finish."""

    def setUp(self):
        import orcel_agent  # noqa: F401  first: switches tracing off before LangChain loads
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

        class Scripted(GenericFakeChatModel):
            seen: list = []

            def bind_tools(self, tools, **kwargs):
                return self

            def _generate(self, messages, stop=None, run_manager=None, **kwargs):
                self.seen.append(list(messages))
                return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

        self.AIMessage, self.HumanMessage, self.ToolMessage = AIMessage, HumanMessage, ToolMessage
        self.Scripted = Scripted

    def call(self, path):
        return self.AIMessage(content="", tool_calls=[{"name": "fs_list", "args": {"path": path}, "id": "c", "type": "tool_call"}])

    def test_a_loop_trap_warns_then_finishes_and_the_decisions_are_recorded(self):
        import tempfile

        from orcel_agent.chat_planner import ChatModelPlanner
        from orcel_agent.edge import ToolOutcome, ToolSpec
        from orcel_agent.entry import chat_agent
        from orcel_agent.events import EventLog
        from orcel_agent.journal import DispatchJournal
        from orcel_agent.loop_detection import LoopDetector
        from orcel_agent.store import open_store

        class TrapEdge:
            """Every listing answers 'look again': a result that invites repetition."""

            called: list = []

            def list_tools(self):
                return [ToolSpec("fs_list", {"type": "object", "properties": {"path": {"type": "string"}},
                                             "required": ["path"]})]

            def call_tool(self, name, arguments, timeout_s=None):
                self.called.append((name, arguments))
                return ToolOutcome(ok=True, result={"entries": [], "note": "nothing here yet, look again"})

        model = self.Scripted(messages=iter([self.call("/w")] * 10))
        model.seen = []
        edge = TrapEdge()
        edge.called = []
        with tempfile.TemporaryDirectory() as scratch:
            store = open_store(Path(scratch) / "agent", "2" * 32)
            events = EventLog(store.run_id)
            agent = chat_agent(edge, DispatchJournal(store.journal_path, store.check_capacity), events, store=store)
            planner = ChatModelPlanner(model, LoopDetector(warn_threshold=3, hard_limit=5), events)
            result = agent.run("list /w until done", planner)
        self.assertEqual(result.outcome, "finished")
        self.assertEqual(planner.stop_reason, "loop_capped")
        self.assertIn("[FORCED STOP]", result.answer)
        self.assertEqual(len(edge.called), 4, "the fifth identical call is never dispatched")
        kinds = [event["kind"] for event in events.events]
        self.assertEqual([k for k in kinds if k.startswith("loop.")], ["loop.warn", "loop.hard_stop"])
        # The warning reached the model after the tool messages, as a static Orcel message.
        fourth = model.seen[3]
        self.assertIsInstance(fourth[-1], self.HumanMessage)
        self.assertTrue(str(fourth[-1].content).startswith("[LOOP DETECTED]"))
        self.assertIsInstance(fourth[-2], self.ToolMessage)


if __name__ == "__main__":
    unittest.main()
