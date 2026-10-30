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
    SUMMARY_MAX_CHARS,
    Compactor,
    capped_arguments,
    compacted_result,
    summary_input,
)
from orcel_agent.journal import OUTCOME_UNKNOWN  # noqa: E402
from orcel_agent.planner import Step, ToolCall  # noqa: E402

DEPS = os.environ.get("ORCEL_AGENT_DEPS") == "1"
BIG = "x" * 12_000


def ok(i: int, text: str = BIG) -> Step:
    return Step(ToolCall("fs_read", {"path": f"/f{i}"}), ok=True, result={"text": text})


def refused(i: int, code: str = "PATH_ESCAPE") -> Step:
    return Step(ToolCall("fs_read", {"path": f"/r{i}"}), ok=False, error_code=code)


def unknown(i: int) -> Step:
    return Step(ToolCall("fs_read", {"path": f"/u{i}"}), ok=False, error_code=OUTCOME_UNKNOWN)


class Records(unittest.TestCase):
    def test_nothing_is_compacted_under_the_budget_or_within_the_recent_window(self) -> None:
        compactor = Compactor()
        self.assertEqual(compactor.older([ok(i, "small") for i in range(20)]), 0)
        self.assertEqual(compactor.older([ok(i) for i in range(DEFAULT_KEEP_RECENT)]), 0)

    def test_over_the_budget_all_but_the_recent_steps_are_compacted(self) -> None:
        steps = [ok(i) for i in range(10)]
        self.assertGreater(10 * len(BIG), DEFAULT_TRIGGER_CHARS)
        self.assertEqual(Compactor().older(steps), 10 - DEFAULT_KEEP_RECENT)

    def test_failures_keep_their_exact_text(self) -> None:
        from orcel_agent.failures import failure_text

        self.assertEqual(compacted_result(refused(1)), failure_text("PATH_ESCAPE"))
        self.assertEqual(compacted_result(unknown(1)), failure_text(OUTCOME_UNKNOWN))
        self.assertEqual(compacted_result(ok(1)), COMPACTED_OK)

    def test_long_arguments_are_capped(self) -> None:
        capped = capped_arguments({"pattern": "y" * 5_000})
        self.assertLessEqual(len(json.dumps(capped)), ARGS_MAX_CHARS + 50)
        self.assertEqual(capped_arguments({"path": "a"}), {"path": "a"})

    def test_the_summary_input_holds_only_dropped_successes_bounded(self) -> None:
        text = summary_input("earlier", [ok(1), refused(2), unknown(3)])
        self.assertIn("<previous_summary>\nearlier\n</previous_summary>", text)
        self.assertEqual(text.count("<tool_result"), 1)
        self.assertLess(len(text), 3_000)

    def test_a_failed_summary_is_tried_once_and_falls_back(self) -> None:
        compactor = Compactor()
        self.assertTrue(compactor.needs_summary(4))
        compactor.record(4, None)
        self.assertFalse(compactor.needs_summary(4))
        self.assertEqual((compactor.summary, compactor.covered, compactor.failures), (None, 0, 1))
        compactor.record(5, "S" * (SUMMARY_MAX_CHARS * 2))
        self.assertLessEqual(len(compactor.summary), SUMMARY_MAX_CHARS)
        self.assertEqual(compactor.covered, 5)


@unittest.skipUnless(DEPS, "the locked dependency environment (ORCEL_AGENT_DEPS=1)")
class Planner(unittest.TestCase):
    def setUp(self) -> None:
        import orcel_agent  # noqa: F401  first: switches tracing off before LangChain loads
        from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
        from langchain_core.messages import AIMessage, ToolMessage

        from orcel_agent.chat_planner import ChatModelPlanner, conversation, ensure_paired
        from orcel_agent.edge import ToolSpec

        class Scripted(GenericFakeChatModel):
            seen: list = []
            binds: int = 0

            def bind_tools(self, tools: Any, **kwargs: Any) -> "Scripted":
                self.binds += 1
                return self

            def _generate(self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
                self.seen.append(list(messages))
                return super()._generate(messages, stop=stop, run_manager=run_manager, **kwargs)

        self.AI, self.Tool = AIMessage, ToolMessage
        self.Planner, self.conversation, self.pair = ChatModelPlanner, conversation, ensure_paired
        self.tools = [ToolSpec("fs_read", {"type": "object", "properties": {"path": {"type": "string"}},
                                           "required": ["path"]})]

        def model(*replies: Any) -> Scripted:
            m = Scripted(messages=iter(list(replies)))
            m.seen, m.binds = [], 0
            return m

        self.model = model

    def long_run(self) -> list:
        steps = [ok(i) for i in range(4)] + [refused(4), unknown(5)] + [ok(i) for i in range(6, 14)]
        return steps

    def test_a_long_run_is_compacted_with_failures_kept_and_pairing_intact(self) -> None:
        m = self.model(self.AI(content="SUMMARY: read f0-f3; f4 refused; f5 unknown"), self.AI(content="done"))
        planner = self.Planner(m, planning=False, detect_loops=False)
        planner.propose("g", self.long_run(), self.tools)
        summary_call, main_call = m.seen
        self.assertEqual(len(summary_call), 1, "the summary is a separate call with only its prompt")
        tools = [x for x in main_call if isinstance(x, self.Tool)]
        self.assertEqual(len(tools), 14)
        compacted = tools[:14 - DEFAULT_KEEP_RECENT]
        self.assertTrue(compacted[4].content.startswith("REFUSED: PATH_ESCAPE. "))
        self.assertTrue(compacted[5].content.startswith(OUTCOME_UNKNOWN))
        self.assertTrue(compacted[0].content.startswith(COMPACTED_OK))
        self.assertIn("written by you from untrusted data", compacted[-1].content)
        self.assertIn("SUMMARY: read f0-f3", compacted[-1].content)
        self.assertEqual(self.pair(main_call), main_call, "every call is followed by its result")
        self.assertTrue(all(BIG in t.content for t in tools[-DEFAULT_KEEP_RECENT:]), "recent steps are verbatim")

    def test_compaction_bounds_the_conversation(self) -> None:
        steps = [ok(i, "z" * 30_000) for i in range(32)]
        full = sum(len(str(x.content)) for x in self.conversation("g", steps))
        compacted = sum(len(str(x.content)) for x in self.conversation("g", steps, 32 - DEFAULT_KEEP_RECENT,
                                                                        "S" * SUMMARY_MAX_CHARS))
        self.assertGreater(full, 400_000)
        self.assertLess(compacted, DEFAULT_KEEP_RECENT * 16_100 + SUMMARY_MAX_CHARS + 32 * 300 + 5_000)

    def test_the_summary_is_written_without_tools_and_with_tracing_off(self) -> None:
        from langchain_core.tracers.context import tracing_v2_enabled

        m = self.model(self.AI(content="S"), self.AI(content="done"))
        with tracing_v2_enabled(project_name="never-sent"):
            self.Planner(m, planning=False, detect_loops=False).propose("g", self.long_run(), self.tools)
        self.assertEqual(m.binds, 1, "tools are bound only for the main call")
        self.assertTrue(str(m.seen[0][0].content).startswith("<role>\nContext Extraction Assistant"))

    def test_a_failed_summary_falls_back_to_the_step_records(self) -> None:
        class Failing:
            pass

        m = self.model(self.AI(content="done"))  # the summary call gets this; then the main call has nothing
        planner = self.Planner(m, planning=False, detect_loops=False)

        def broken(bound: Any, messages: list) -> Any:
            if len(messages) == 1:
                raise RuntimeError("summarizer down")
            return type(planner)._invoke(planner, bound, messages)

        planner._invoke = broken
        result = planner.propose("g", self.long_run(), self.tools)
        self.assertEqual(result.answer, "done")
        main = m.seen[-1]
        compacted = [x for x in main if isinstance(x, self.Tool)][: 14 - DEFAULT_KEEP_RECENT]
        self.assertFalse(any("Summary of earlier results" in t.content for t in compacted))
        self.assertTrue(compacted[4].content.startswith("REFUSED: PATH_ESCAPE"))

    def test_summaries_are_incremental_and_cached(self) -> None:
        go = self.AI(content="", tool_calls=[{"name": "fs_read", "args": {"path": "/next"}, "id": "n", "type": "tool_call"}])
        # The main replies are tool calls: a plain answer would finish the run
        # (and the next proposal would start a fresh one).
        m = self.model(self.AI(content="FIRST"), go, self.AI(content="SECOND"), go, go)
        planner = self.Planner(m, planning=False, detect_loops=False)
        steps = self.long_run()
        planner.propose("g", steps, self.tools)
        planner.propose("g", steps + [ok(14)], self.tools)  # one more dropped step: summarize again
        self.assertIn("<previous_summary>\nFIRST\n</previous_summary>", str(m.seen[2][0].content))
        planner.propose("g", steps + [ok(14)], self.tools)  # nothing new dropped: no summary call
        self.assertEqual(len(m.seen), 5)

    def test_a_new_run_resets_the_summary(self) -> None:
        m = self.model(self.AI(content="FIRST"), self.AI(content="done"), self.AI(content="done"))
        planner = self.Planner(m, planning=False, detect_loops=False)
        planner.propose("one", self.long_run(), self.tools)
        planner.propose("two", [ok(1, "small")], self.tools)
        self.assertIsNone(planner._compactor.summary)

    def test_compaction_can_be_turned_off(self) -> None:
        m = self.model(self.AI(content="done"))
        self.Planner(m, planning=False, detect_loops=False, compaction=False).propose("g", self.long_run(), self.tools)
        self.assertEqual(len(m.seen), 1)
        self.assertFalse(any(isinstance(x, self.Tool) and x.content.startswith(COMPACTED_OK) for x in m.seen[0]))

    def test_the_copied_prompt_matches_the_wheel(self) -> None:
        import importlib.util

        from orcel_agent.compaction import DEFAULT_SUMMARY_PROMPT

        source = Path(importlib.util.find_spec("langchain").origin).parent / "agents" / "middleware" / "summarization.py"
        self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),
                         "39bb39f477894ca714a722e8550eb9f4acaa1615030380a2cee11e400215d458")
        self.assertIn(DEFAULT_SUMMARY_PROMPT, source.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
