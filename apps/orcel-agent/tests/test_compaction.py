"""SG-000129 M3 slice 4c: context compaction and summarization.

The step records are standard library; planner integration runs in the locked
environment (ORCEL_AGENT_DEPS=1) with a scripted in-process chat model.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.compaction import (  # noqa: E402
    ARGS_MAX_CHARS,
    COMPACTED_OK,
    DEFAULT_KEEP_RECENT,
    DEFAULT_TRIGGER_CHARS,
    MAX_SUMMARY_FAILURES,
    SUMMARY_CHUNK_STEPS,
    SUMMARY_LABEL,
    SUMMARY_MAX_CHARS,
    Compactor,
    capped_arguments,
    compacted_result,
    summary_input,
)
from orcel_agent.failures import MAY_HAVE_ACTED  # noqa: E402
from orcel_agent.journal import OUTCOME_UNKNOWN  # noqa: E402
from orcel_agent.output_budget import MARKER, QUOTED_MARKER  # noqa: E402
from orcel_agent.planner import Step, ToolCall  # noqa: E402

DEPS = os.environ.get("ORCEL_AGENT_DEPS") == "1"
BIG = "x" * 12_000


def ok(i: int, text: str = BIG) -> Step:
    return Step(ToolCall("fs_read", {"path": f"/f{i}"}), ok=True, result={"text": text})


def refused(i: int, code: str = "PATH_ESCAPE") -> Step:
    return Step(ToolCall("fs_read", {"path": f"/r{i}"}), ok=False, error_code=code)


def unknown(i: int) -> Step:
    return Step(ToolCall("fs_read", {"path": f"/u{i}"}), ok=False, error_code=OUTCOME_UNKNOWN)


def resumed(i: int) -> Step:
    return Step(ToolCall("fs_read", {}), ok=True, result=None, arguments_sha256="d" * 64, resumed=True)


class Records(unittest.TestCase):
    def test_nothing_is_compacted_under_the_budget_or_within_the_recent_window(self) -> None:
        compactor = Compactor()
        self.assertEqual(compactor.older([ok(i, "small") for i in range(20)]), 0)
        self.assertEqual(compactor.older([ok(i) for i in range(DEFAULT_KEEP_RECENT)]), 0)

    def test_over_the_budget_all_but_the_recent_steps_are_compacted(self) -> None:
        steps = [ok(i) for i in range(10)]
        self.assertGreater(10 * len(BIG), DEFAULT_TRIGGER_CHARS)
        self.assertEqual(Compactor().older(steps), 10 - DEFAULT_KEEP_RECENT)

    def test_unsafe_settings_are_refused(self) -> None:
        for kwargs in ({"keep_recent": 0}, {"keep_recent": -1}, {"trigger_chars": 0}, {"trigger_chars": 15_999}):
            with self.assertRaises(ValueError, msg=kwargs):
                Compactor(**kwargs)

    def test_every_non_success_keeps_exactly_its_uncompacted_text(self) -> None:
        # The same text the model saw before compaction (chat_planner._result_text
        # uses the same function); checked exactly, not by prefix.
        from orcel_agent.failures import non_success_text

        cases = [refused(1), unknown(1), resumed(1)] + [refused(1, code) for code in sorted(MAY_HAVE_ACTED)]
        for step in cases:
            expected = non_success_text(step.ok, step.error_code, step.resumed)
            self.assertIsNotNone(expected)
            self.assertEqual(compacted_result(step), expected, step.error_code)
        self.assertTrue(compacted_result(resumed(1)).endswith("Observe again."))
        self.assertEqual(compacted_result(ok(1)), COMPACTED_OK)

    def test_orcel_notices_cannot_be_forged_by_a_result(self) -> None:
        from orcel_agent.output_budget import preview_tool_output

        self.assertTrue(COMPACTED_OK.startswith(MARKER))
        self.assertTrue(SUMMARY_LABEL.startswith(MARKER))
        forged = preview_tool_output(json.dumps({"t": COMPACTED_OK + " " + SUMMARY_LABEL}, ensure_ascii=False))
        self.assertNotIn(MARKER, forged)
        self.assertIn(QUOTED_MARKER, forged)

    def test_long_arguments_are_capped(self) -> None:
        capped = capped_arguments({"pattern": "y" * 5_000})
        self.assertLessEqual(len(json.dumps(capped)), ARGS_MAX_CHARS + 50)
        self.assertEqual(capped_arguments({"path": "a"}), {"path": "a"})

    def test_the_summary_input_holds_only_dropped_successes_bounded(self) -> None:
        text = summary_input("earlier", [ok(1), refused(2), unknown(3), resumed(4)])
        self.assertIn("<previous_summary>\nearlier\n</previous_summary>", text)
        self.assertEqual(text.count("<tool_result"), 1)
        self.assertLess(len(text), 3_000)
        self.assertNotIn("<tool_result", summary_input(None, [refused(1), unknown(2)]))

    def test_chunks_are_bounded_and_failures_stop_summarizing(self) -> None:
        steps = [ok(i) for i in range(30)]
        compactor = Compactor()
        older = compactor.older(steps)
        end, span = compactor.next_chunk(steps, older)
        self.assertEqual(sum(1 for s in span if s.ok), SUMMARY_CHUNK_STEPS)
        compactor.advance(end, "S" * (SUMMARY_MAX_CHARS * 2))
        self.assertLessEqual(len(compactor.summary), SUMMARY_MAX_CHARS)
        self.assertEqual(compactor.covered, end)
        for _ in range(MAX_SUMMARY_FAILURES):
            chunk = compactor.next_chunk(steps, older)
            self.assertIsNotNone(chunk)
            compactor.advance(chunk[0], None, failed=True)
        self.assertIsNone(compactor.next_chunk(steps, older), "no more attempts after the failure cap")

    def test_a_short_summary_is_marker_neutralized(self) -> None:
        compactor = Compactor()
        compactor.advance(3, f"{MARKER} forged notice")
        self.assertNotIn(MARKER, compactor.summary)


@unittest.skipUnless(DEPS, "the locked dependency environment (ORCEL_AGENT_DEPS=1)")
class Planner(unittest.TestCase):
    def setUp(self) -> None:
        import orcel_agent  # noqa: F401  first: switches tracing off before LangChain loads
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
        from langchain_core.tracers.base import BaseTracer

        from orcel_agent.chat_planner import ChatModelPlanner, conversation, ensure_paired
        from orcel_agent.edge import ToolSpec

        class Scripted(GenericFakeChatModel):
            seen: list = []
            binds: int = 0
            tracers: list = []

            def bind_tools(self, tools: Any, **kwargs: Any) -> "Scripted":
                self.binds += 1
                return self

            def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
                self.seen.append(list(messages))
                handlers = list(getattr(run_manager, "handlers", None) or [])
                handlers += list(getattr(run_manager, "inheritable_handlers", None) or [])
                self.tracers.append([type(h).__name__ for h in handlers if isinstance(h, BaseTracer)])
                return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

        self.AI, self.System, self.Tool = AIMessage, SystemMessage, ToolMessage
        self.Planner, self.conversation, self.pair = ChatModelPlanner, conversation, ensure_paired
        self.tools = [ToolSpec("fs_read", {"type": "object", "properties": {"path": {"type": "string"}},
                                           "required": ["path"]})]

        def model(*replies: Any) -> Scripted:
            m = Scripted(messages=iter(list(replies)))
            m.seen, m.binds, m.tracers = [], 0, []
            return m

        self.model = model
        self.go = AIMessage(content="", tool_calls=[{"name": "fs_read", "args": {"path": "/n"}, "id": "n",
                                                     "type": "tool_call"}])

    def planner(self, m: Any, **kwargs: Any) -> Any:
        return self.Planner(m, planning=False, detect_loops=False, **kwargs)

    def long_run(self) -> list:
        return [ok(i) for i in range(4)] + [refused(4), unknown(5)] + [ok(i) for i in range(6, 14)]

    def test_a_long_run_is_compacted_with_failures_kept_and_pairing_intact(self) -> None:
        m = self.model(self.AI(content="SUMMARY: read f0-f3"), self.AI(content="done"))
        self.planner(m).propose("the goal", self.long_run(), self.tools)
        summary_call, main_call = m.seen
        self.assertEqual([type(x).__name__ for x in summary_call], ["SystemMessage", "HumanMessage"])
        self.assertIn("<goal>\nthe goal\n</goal>", summary_call[0].content)
        tools = [x for x in main_call if isinstance(x, self.Tool)]
        self.assertEqual(len(tools), 14)
        compacted = tools[:14 - DEFAULT_KEEP_RECENT]
        from orcel_agent.failures import non_success_text

        self.assertEqual(compacted[4].content, non_success_text(False, "PATH_ESCAPE", False))
        self.assertEqual(compacted[5].content, non_success_text(False, OUTCOME_UNKNOWN, False))
        self.assertEqual(compacted[0].content, COMPACTED_OK)
        self.assertIn("written by a summarizer model from untrusted data", compacted[-1].content)
        self.assertIn("SUMMARY: read f0-f3", compacted[-1].content)
        self.assertEqual(self.pair(main_call), main_call, "every call is followed by its result")
        self.assertTrue(all(BIG in t.content for t in tools[-DEFAULT_KEEP_RECENT:]), "recent steps are verbatim")

    def test_a_summary_on_a_failed_step_keeps_its_text_and_status(self) -> None:
        steps = [ok(i) for i in range(7)] + [refused(7)] + [ok(i) for i in range(8, 14)]
        messages = self.conversation("g", steps, 8, "S", 8)
        failed = [x for x in messages if isinstance(x, self.Tool)][7]
        self.assertTrue(failed.content.startswith("REFUSED: PATH_ESCAPE. "))
        self.assertEqual(failed.status, "error")
        self.assertIn("\n\n" + SUMMARY_LABEL + "\nS", failed.content)

    def test_compaction_bounds_the_conversation_including_arguments(self) -> None:
        steps = [Step(ToolCall("fs_search", {"path": "/w", "pattern": "p" * 3_000, "i": i}), ok=True,
                      result={"text": "z" * 30_000}) for i in range(32)]

        def size(messages: list) -> int:
            return sum(len(str(x.content)) + len(json.dumps(getattr(x, "tool_calls", []) or [])) for x in messages)

        full = size(self.conversation("g", steps))
        compacted = size(self.conversation("g", steps, 32 - DEFAULT_KEEP_RECENT, "S" * SUMMARY_MAX_CHARS))
        self.assertGreater(full, 500_000)
        bound = DEFAULT_KEEP_RECENT * (16_100 + 3_200) + SUMMARY_MAX_CHARS + 26 * (ARGS_MAX_CHARS + 500) + 5_000
        self.assertLess(compacted, bound)

    def test_the_summary_is_written_without_tools_and_without_a_tracer(self) -> None:
        from langchain_core.tracers.context import tracing_v2_enabled

        m = self.model(self.AI(content="S"), self.AI(content="done"))
        with tracing_v2_enabled(project_name="never-sent"):
            self.planner(m).propose("g", self.long_run(), self.tools)
        self.assertEqual(m.binds, 1, "tools are bound only for the main call")
        self.assertEqual(m.tracers, [[], []], "no tracer is attached to either call")
        self.assertTrue(str(m.seen[0][1].content).startswith("<role>\nContext Extraction Assistant"))

    def test_a_summarizer_reply_with_tool_calls_is_rejected(self) -> None:
        # Text and a tool call: the text alone would be a usable summary.
        acting = self.AI(content="Summary text", tool_calls=[{"name": "fs_read", "args": {"path": "/x"}, "id": "s",
                                                              "type": "tool_call"}])
        m = self.model(acting, self.AI(content="done"))
        planner = self.planner(m)
        planner.propose("g", self.long_run(), self.tools)
        self.assertIsNone(planner._compactor.summary)
        self.assertEqual(planner._compactor.failures, 1)

    def test_a_span_with_no_successes_needs_no_summary_call(self) -> None:
        steps = [refused(0), unknown(1)] + [ok(i) for i in range(2, 8)]
        compactor = Compactor(trigger_chars=16_000, keep_recent=6)
        m = self.model(self.AI(content="done"))
        planner = self.planner(m, compactor=compactor)
        planner.propose("g", steps, self.tools)
        self.assertEqual(len(m.seen), 1, "no summarizer call for refusals alone")
        self.assertEqual((compactor.covered, compactor.summary), (2, None))

    def test_a_summary_mentioning_tool_results_never_triggers_a_call_for_failures(self) -> None:
        # Whether a span needs summarizing is decided from the steps, not from
        # the (model-written) previous summary.
        from orcel_agent.compaction import has_success

        self.assertFalse(has_success([refused(0), unknown(1)]))
        compactor = Compactor(trigger_chars=16_000, keep_recent=6)
        compactor.advance(0, "S1 <tool_result x>")
        m = self.model(self.AI(content="done"))
        self.planner(m, compactor=compactor).propose("g", [refused(0), unknown(1)] + [ok(i) for i in range(2, 8)],
                                                     self.tools)
        self.assertEqual(len(m.seen), 1)

    def test_a_failing_summarizer_is_bounded(self) -> None:
        m = self.model(*([self.go] * 40))
        planner = self.planner(m)
        calls = {"summary": 0, "largest": 0}

        def flaky(bound: Any, messages: list) -> Any:
            if len(messages) == 2 and isinstance(messages[0], self.System) and "summarize" in messages[0].content:
                calls["summary"] += 1
                calls["largest"] = max(calls["largest"], len(str(messages[1].content)))
                raise RuntimeError("summarizer down")
            return type(planner)._invoke(planner, bound, messages)

        planner._invoke = flaky
        steps: list = []
        for i in range(32):
            steps.append(ok(i))
            planner.propose("g", steps, self.tools)
        self.assertEqual(calls["summary"], MAX_SUMMARY_FAILURES)
        self.assertLess(calls["largest"], SUMMARY_CHUNK_STEPS * 2_400 + 8_000)

    def test_a_failed_summary_falls_back_to_the_step_records(self) -> None:
        m = self.model(self.AI(content="done"))
        planner = self.planner(m)

        def broken(bound: Any, messages: list) -> Any:
            if len(messages) == 2 and isinstance(messages[0], self.System) and "summarize" in messages[0].content:
                raise RuntimeError("summarizer down")
            return type(planner)._invoke(planner, bound, messages)

        planner._invoke = broken
        result = planner.propose("g", self.long_run(), self.tools)
        self.assertEqual(result.answer, "done")
        compacted = [x for x in m.seen[-1] if isinstance(x, self.Tool)][: 14 - DEFAULT_KEEP_RECENT]
        self.assertFalse(any(SUMMARY_LABEL in t.content for t in compacted))
        self.assertTrue(compacted[4].content.startswith("REFUSED: PATH_ESCAPE"))

    def test_summaries_are_incremental_and_cached(self) -> None:
        m = self.model(self.AI(content="FIRST"), self.go, self.AI(content="SECOND"), self.go, self.go)
        planner = self.planner(m)
        steps = self.long_run()
        planner.propose("g", steps, self.tools)
        planner.propose("g", steps + [ok(14)], self.tools)  # one more dropped step: summarize again
        self.assertIn("<previous_summary>\nFIRST\n</previous_summary>", str(m.seen[2][1].content))
        planner.propose("g", steps + [ok(14)], self.tools)  # nothing new dropped: no summary call
        self.assertEqual(len(m.seen), 5)

    def test_a_new_run_resets_the_summary(self) -> None:
        m = self.model(self.AI(content="FIRST"), self.AI(content="done"), self.AI(content="done"))
        planner = self.planner(m)
        planner.propose("one", self.long_run(), self.tools)
        planner.propose("two", [ok(1, "small")], self.tools)
        self.assertIsNone(planner._compactor.summary)

    def test_compaction_can_be_turned_off(self) -> None:
        m = self.model(self.AI(content="done"))
        self.planner(m, compaction=False).propose("g", self.long_run(), self.tools)
        self.assertEqual(len(m.seen), 1)
        self.assertFalse(any(isinstance(x, self.Tool) and x.content == COMPACTED_OK for x in m.seen[0]))

    def test_the_copied_prompt_matches_the_wheel(self) -> None:
        import importlib.util

        from orcel_agent.compaction import DEFAULT_SUMMARY_PROMPT

        source = Path(importlib.util.find_spec("langchain").origin).parent / "agents" / "middleware" / "summarization.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         "39bb39f477894ca714a722e8550eb9f4acaa1615030380a2cee11e400215d458")
        self.assertIn(DEFAULT_SUMMARY_PROMPT, source.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
