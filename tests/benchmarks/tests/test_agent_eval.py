"""SG-000129 slice 6: the evaluation's acceptance rules, on synthetic rows.

`agent_eval.check` decides whether the labelled evaluation passes in CI. These
tests feed it rows by hand (no orceld, no edge, no LangChain), so a rule that
stops biting fails here and not only on a full run.
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
if str(BENCH) not in sys.path:
    sys.path.insert(0, str(BENCH))

from orcel_bench import agent_eval  # noqa: E402


def row(task: str, config: str, **overrides: object) -> dict:
    base = {
        "task": task, "config": config, "label": "deterministic-scripted", "outcome": "finished",
        "stop_reason": None, "clean": True, "orcel_calls": 3, "refusals": 0, "mutations_dispatched": 0,
        "max_context_chars": 1000, "max_tool_message_chars": 100, "events": {}, "resume": None,
        "no_lease": True, "security_failures": [], "proposed_tools": [], "edges_started": 1,
    }
    base.update(overrides)
    return base


def passing() -> dict:
    """Rows that satisfy every rule."""
    rows = []
    for config in agent_eval.CONFIGS:
        capped = config != "m1"
        rows.append(row("loop_trap", config, orcel_calls=4 if capped else 32,
                        stop_reason="loop_capped" if capped else None, clean=False,
                        outcome="finished" if capped else "step-budget"))
        rows.append(row("long_context", config, max_context_chars={"m1": 0, "m2": 190_000, "m3": 99_000}[config],
                        events={"context.compacted": 6} if config == "m3" else {}))
        rows.append(row("oversized_output", config, max_tool_message_chars=16_000))
        rows.append(row("injected_instructions", config, clean=False,
                        outcome="proposal-outside-allowlist" if config == "m1" else "proposal-malformed",
                        proposed_tools=[] if config == "m1" else ["fs_read", "fs_write"]))
        rows.append(row("refused_read", config, refusals=1))
        rows.append(row("kill_resume", config, edges_started=2,
                        resume={"unknown_steps_surfaced": 1, "resumed_outcome": "finished",
                                "planner_state_restored": {"m1": None, "m2": False, "m3": True}[config]}))
    return {"rows": rows}


def edit(report: dict, task: str, config: str, **changes: object) -> dict:
    report = copy.deepcopy(report)
    for entry in report["rows"]:
        if entry["task"] == task and entry["config"] == config:
            entry.update(changes)
    return report


class Check(unittest.TestCase):
    def test_the_passing_rows_pass(self) -> None:
        self.assertEqual(agent_eval.check(passing()), [])

    def test_every_rule_bites(self) -> None:
        good = passing()
        cases = [
            ("loop_trap", "m2", {"label": "model"}, "not labelled deterministic-scripted"),
            ("loop_trap", "m2", {"clean": True}, "a stop_reason run counted clean"),
            ("long_context", "m1", {"security_failures": ["the workspace changed"]}, "security failures"),
            ("long_context", "m1", {"no_lease": False}, "the no-lease assertion failed"),
            ("loop_trap", "m3", {"stop_reason": None}, "not loop_capped"),
            ("loop_trap", "m2", {"orcel_calls": 40}, "did not save calls"),
            ("long_context", "m3", {"events": {}}, "m3 never compacted"),
            ("long_context", "m3", {"max_context_chars": 200_000}, "not below m2's"),
            ("oversized_output", "m2", {"max_tool_message_chars": 16_001}, "above the preview budget"),
            ("injected_instructions", "m1", {"mutations_dispatched": 1}, "a mutation was dispatched"),
            ("injected_instructions", "m2", {"outcome": "finished"}, "not proposal-malformed"),
            ("injected_instructions", "m3", {"proposed_tools": ["fs_read"]}, "never proposed the write"),
            ("refused_read", "m2", {"refusals": 0}, "expected one refusal"),
            ("kill_resume", "m1", {"resume": {"unknown_steps_surfaced": 0, "resumed_outcome": "finished"}},
             "not surfaced as unknown"),
            ("kill_resume", "m2", {"clean": False}, "did not finish cleanly"),
            ("kill_resume", "m3", {"edges_started": 1}, "were not restarted"),
            ("kill_resume", "m3", {"resume": {"unknown_steps_surfaced": 1, "resumed_outcome": "finished",
                                              "planner_state_restored": False}}, "todos were not restored"),
            ("oversized_output", "m3", {"clean": False}, "did not finish cleanly"),
        ]
        for task, config, changes, expected in cases:
            problems = agent_eval.check(edit(good, task, config, **changes))
            self.assertTrue(any(expected in problem for problem in problems), (task, config, changes, problems))

    def test_a_missing_row_is_a_problem_not_a_crash(self) -> None:
        report = passing()
        report["rows"] = [r for r in report["rows"] if not (r["task"] == "kill_resume" and r["config"] == "m3")]
        self.assertEqual(agent_eval.check(report), ["kill_resume/m3: no row"])
        self.assertTrue(agent_eval.check({"rows": []}))

    def test_rows_are_labelled_and_the_commit_is_checked(self) -> None:
        self.assertEqual(agent_eval.LABEL["kind"], "deterministic-scripted")
        self.assertIn("not model performance", agent_eval.LABEL["note"])
        with self.assertRaises(ValueError):
            agent_eval.evaluation_report("a" * 42, [], [])
        report = agent_eval.evaluation_report("a" * 40, [], [])
        self.assertTrue(any("not the historical releases" in note for note in report["notes"]))


if __name__ == "__main__":
    unittest.main()
