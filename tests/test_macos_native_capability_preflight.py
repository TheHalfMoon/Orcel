"""Tests for macOS /2 hello-only, non-prompting qualification preflight."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/macos_native_capability_preflight.py"
SPEC = importlib.util.spec_from_file_location("mac_preflight", SCRIPT)
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


def hello():
    return {
        "id": 1, "ok": True, "protocol": "orcel-computer-host/2",
        "host": "orcel-native-host", "platform": "macos",
        "permissions": {"accessibility": True, "screen_recording": True,
                        "direct_capture_consent": False, "macos_background_spi": False},
        "capabilities": {
            "observe_window": {"support": "delivered"},
            "semantic_action": {"support": "delivered"},
            "capture_window": {"support": "unavailable", "reason": "permission_missing"},
            "input_click": {"support": "unavailable", "reason": "permission_missing"},
        },
    }


class MacPreflightTests(unittest.TestCase):
    def test_read_only_operations_eligible_without_direct_capture(self):
        result = mod.assess(hello())
        self.assertTrue(result["manual_test_preflight"]["XP-06"]["eligible_for_manual_test"])
        self.assertTrue(result["manual_test_preflight"]["XP-11"]["eligible_for_manual_test"])
        self.assertFalse(result["manual_test_preflight"]["XP-07"]["eligible_for_manual_test"])
        self.assertFalse(result["manual_test_preflight"]["XP-12"]["eligible_for_manual_test"])
        self.assertIn("direct_capture_consent", result["manual_test_preflight"]["XP-07"]["missing"])

    def test_all_grants_and_capabilities_make_manual_tests_eligible_not_qualified(self):
        frame = hello()
        frame["permissions"]["direct_capture_consent"] = True
        frame["capabilities"]["capture_window"]["support"] = "delivered"
        frame["capabilities"]["input_click"]["support"] = "delivered"
        result = mod.assess(frame)
        self.assertTrue(all(v["eligible_for_manual_test"] for v in result["manual_test_preflight"].values()))
        self.assertIn("No permission was requested", result["note"])
        self.assertNotIn("qualified", result["manual_test_preflight"]["XP-07"])

    def test_missing_accessibility_blocks_ax_and_semantic_actions(self):
        frame = hello()
        frame["permissions"]["accessibility"] = False
        result = mod.assess(frame)
        for xp in ("XP-06", "XP-11"):
            self.assertFalse(result["manual_test_preflight"][xp]["eligible_for_manual_test"])
            self.assertIn("accessibility", result["manual_test_preflight"][xp]["missing"])

    def test_reject_malformed_permission_and_non_mac_orcel(self):
        frame = hello()
        frame["permissions"]["direct_capture_consent"] = "false"
        with self.assertRaises(ValueError):
            mod.assess(frame)
        frame = hello()
        frame["platform"] = "windows"
        with self.assertRaises(ValueError):
            mod.assess(frame)
        frame = hello()
        frame["capabilities"]["semantic_action"] = {}
        with self.assertRaises(ValueError):
            mod.assess(frame)

    def test_real_cli_sends_only_hello_and_respects_require(self):
        with tempfile.TemporaryDirectory() as folder:
            fake = Path(folder) / "synthetic-host"
            data = json.dumps(hello())
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "frames=[json.loads(x) for x in sys.stdin if x.strip()]\n"
                "assert len(frames)==1 and frames[0]['op']=='hello'\n"
                "assert frames[0]['protocol']=='orcel-computer-host/2'\n"
                f"print({data!r})\n"
            )
            fake.chmod(0o700)
            available = subprocess.run(
                [sys.executable, str(SCRIPT), "--host", str(fake), "--require", "XP-06"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(available.returncode, 0, available.stderr)
            self.assertFalse(json.loads(available.stdout)["manual_test_preflight"]["XP-07"]["eligible_for_manual_test"])
            unavailable = subprocess.run(
                [sys.executable, str(SCRIPT), "--host", str(fake), "--require", "XP-07"],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(unavailable.returncode, 3)
            self.assertEqual(json.loads(unavailable.stdout)["protocol"], "orcel-computer-host/2")

    def test_missing_binary_fails_without_claiming_eligibility(self):
        with tempfile.TemporaryDirectory() as folder:
            out = subprocess.run(
                [sys.executable, str(SCRIPT), "--host", str(Path(folder) / "absent")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(out.returncode, 2)
            self.assertEqual(out.stdout, "")


if __name__ == "__main__":
    unittest.main()
