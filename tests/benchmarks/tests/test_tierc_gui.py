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
from orcel_bench.tierc_gui import _fill, electron_apps, run_observe_episode  # noqa: E402

VALUES = {"bundle": "/b", "workspace": "/w"}


class TierCGuiHarness(unittest.TestCase):
    def test_launch_arguments_are_filled_only_in_known_shapes(self) -> None:
        self.assertEqual(_fill("electron", VALUES), "electron")
        self.assertEqual(_fill("${workspace}", VALUES), "/w")
        self.assertEqual(_fill("--workspace=${workspace}", VALUES), "--workspace=/w")
        self.assertEqual(_fill("${bundle}/apps/x", VALUES), "/b/apps/x")
        for refused in ("x${workspace}", "--a=${workspace}${bundle}", "${nope}", "-w=${workspace}"):
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
