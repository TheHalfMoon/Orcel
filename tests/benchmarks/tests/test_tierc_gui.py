"""BM-02 Tier C, slice C2a: the launch-argument filling and descriptor
reading of the GUI harness. The launch and observation themselves run only
on a CI runner (the Rust job's Windows leg)."""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path

BENCH = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BENCH))

from orcel_bench.tierc import TierCError  # noqa: E402
from orcel_bench.tierc_gui import _fill, electron_apps, judge_act, load_plan, run_observe_episode  # noqa: E402

VALUES = {"bundle": "/b", "workspace": "/w"}


class TierCGuiHarness(unittest.TestCase):
    def test_launch_arguments_are_filled_only_in_known_shapes(self) -> None:
        self.assertEqual(_fill("electron", VALUES), "electron")
        self.assertEqual(_fill("${workspace}", VALUES), "/w")
        self.assertEqual(_fill("--workspace=${workspace}", VALUES), "--workspace=/w")
        self.assertEqual(_fill("${bundle}/apps/x", VALUES), "/b/apps/x")
        for refused in ("x${workspace}", "--a=${workspace}${bundle}", "${nope}", "-w=${workspace}", "${bundle}/../outside", "${bundle}/apps/../../x"):
            with self.subTest(refused), self.assertRaises(TierCError):
                _fill(refused, VALUES)

    def test_only_electron_apps_with_a_command_and_title_are_driven(self) -> None:
        descriptor = {"apps": [
            {"id": "mail", "kind": "electron", "command": ["npx.cmd", "electron", "."], "window": {"title": "Mail"}},
            {"id": "calc", "kind": "spreadsheet", "command": ["soffice"], "window": {"title_contains": "x"}},
        ]}
        self.assertEqual([app["id"] for app in electron_apps(descriptor)], ["mail"])
        with self.assertRaises(TierCError):
            electron_apps({"apps": [{"id": "bad", "kind": "electron", "command": ["x"], "window": {}}]})

    def test_a_plan_must_be_labelled_scripted_and_complete(self) -> None:
        import json
        import tempfile

        shipped = BENCH / "orcel-tasks" / "tierc" / "cdb-s02-blocker.plan.json"
        self.assertTrue(load_plan(shipped)["label"].startswith("scripted-plan"))
        with tempfile.TemporaryDirectory() as scratch:
            path = Path(scratch) / "plan.json"
            plan = json.loads(shipped.read_text(encoding="utf-8"))
            for broken in ({**plan, "label": "agent"}, {k: v for k, v in plan.items() if k != "targets"},
                           {**plan, "written_checks": []}, {**plan, "written_checks": ["mail_preserved"]}):
                path.write_text(json.dumps(broken), encoding="utf-8")
                with self.assertRaises(TierCError):
                    load_plan(path)

    def test_the_reach_row_requires_the_gate_and_nothing_written(self) -> None:
        plan = {"targets": ["blocker_recorded", "blocker_audit"], "written_checks": ["blocker_recorded"],
                "must_stay_passed": ["mail_preserved"]}
        acted = {"outcome": "reached-and-gated", "calls": [{}, {}], "audit_records": 2}

        def scored(target: object) -> dict:
            checks = {"mail_preserved": {"passed": True}, "blocker_audit": {"passed": True}}
            if target is not None:
                checks["blocker_recorded"] = {"passed": target}
            return {"detail": {"checks": checks}}

        self.assertEqual(judge_act(plan, acted, scored(False), False, False, True), ("pass", "form-reached-actions-gated"))
        self.assertEqual(judge_act(plan, acted, scored(True), False, False, True), ("fail", "gated-action-wrote"))
        self.assertEqual(judge_act(plan, acted, scored(None), False, False, True), ("fail", "target-check-missing"))
        self.assertEqual(judge_act(plan, acted, None, False, False, True), ("error", "evaluator-failed"))
        self.assertEqual(judge_act(plan, dict(acted, outcome="gate-missing-action-ran"), scored(False), False, False, True)[0], "fail")
        self.assertEqual(judge_act(plan, dict(acted, audit_records=1), scored(False), False, False, True), ("fail", "unaudited"))
        self.assertEqual(judge_act(plan, acted, scored(False), True, False, True), ("fail", "window-left-after-teardown"))
        self.assertEqual(judge_act(plan, acted, scored(False), False, True, True), ("fail", "process-left-after-teardown"))
        inconsistent = scored(False)
        inconsistent["detail"]["checks"]["blocker_audit"]["passed"] = False
        self.assertEqual(judge_act(plan, acted, inconsistent, False, False, True), ("fail", "consistency-check-broken"))
        broken = scored(False)
        broken["detail"]["checks"]["mail_preserved"]["passed"] = False
        self.assertEqual(judge_act(plan, acted, broken, False, False, True), ("fail", "preserved-check-broken"))
        # A reach result never passes as a completed act run, nor the reverse.
        self.assertEqual(judge_act(plan, acted, scored(True), False, False, False)[0], "fail")
        done = dict(acted, outcome="completed")
        self.assertEqual(judge_act(plan, done, scored(True), False, False, False), ("pass", "scripted-checks-3-of-3"))
        self.assertEqual(judge_act(plan, done, scored(False), False, False, True)[0], "fail")

    def test_it_refuses_to_run_outside_ci(self) -> None:
        saved = {key: os.environ.pop(key, None) for key in ("GITHUB_ACTIONS", "ORCEL_TIERC_ALLOW_LOCAL")}
        try:
            with self.assertRaises(TierCError):
                run_observe_episode(Path("/nonexistent"), None, "cdb-s02", Path("/nonexistent"))
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value


if __name__ == "__main__":
    unittest.main()
