#!/usr/bin/env python3
"""Non-prompting macOS native-host capability preflight.

Reads only the Orcel /2 hello frame. Never requests a capture, input, approval,
permission grant, or system-preferences modification. Eligible != qualified.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


REQUIREMENTS = {
    "XP-06": ("observe_window", ("accessibility", "screen_recording")),
    "XP-07": ("capture_window", ("accessibility", "screen_recording", "direct_capture_consent")),
    "XP-11": ("semantic_action", ("accessibility",)),
    "XP-12": ("input_click", ("accessibility", "screen_recording", "direct_capture_consent")),
}


def assess(hello: dict) -> dict:
    if (
        hello.get("ok") is not True
        or hello.get("protocol") != "orcel-computer-host/2"
        or hello.get("host") != "orcel-native-host"
        or hello.get("platform") != "macos"
    ):
        raise ValueError("not a successful Orcel /2 macOS host hello frame")
    raw_permissions = hello.get("permissions")
    raw_capabilities = hello.get("capabilities")
    if not isinstance(raw_permissions, dict) or not isinstance(raw_capabilities, dict):
        raise ValueError("host response does not declare permissions and capabilities")
    permissions = {}
    for name in ("accessibility", "screen_recording", "direct_capture_consent", "macos_background_spi"):
        if not isinstance(raw_permissions.get(name), bool):
            raise ValueError("missing or nonboolean permission: " + name)
        permissions[name] = raw_permissions[name]
    xp = {}
    for name, (capability, grants) in REQUIREMENTS.items():
        cap = raw_capabilities.get(capability)
        if not isinstance(cap, dict) or not isinstance(cap.get("support"), str):
            raise ValueError("missing typed capability: " + capability)
        missing = [grant for grant in grants if not permissions[grant]]
        if cap["support"] != "delivered":
            missing.append("host capability " + capability + ": " + cap["support"])
        xp[name] = {"eligible_for_manual_test": not missing, "missing": missing}
    return {
        "protocol": "orcel-computer-host/2",
        "platform": "macos",
        "permissions": permissions,
        "manual_test_preflight": xp,
        "note": "Readiness only. No permission was requested or changed; no capability delivery was tested.",
    }


def get_hello(binary: Path) -> dict:
    if not binary.is_file():
        raise ValueError("native-host binary does not exist: " + str(binary))
    request = json.dumps({"id": 1, "protocol": "orcel-computer-host/2", "op": "hello"}) + "\n"
    # The binary owns stdin/stdout. Communicate closes stdin and waits; hello
    # is a read-only call with no possible system permission prompts.
    env = {k: v for k, v in os.environ.items() if k in {"HOME", "USER", "PATH", "LANG", "TMPDIR"}}
    result = subprocess.run(
        [str(binary)], input=request, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=12, check=False, env=env,
    )
    if result.returncode != 0:
        raise ValueError("native host exited unsuccessfully during hello")
    if len(result.stdout) > 65536:
        raise ValueError("native host returned an oversized hello frame")
    frames = [line for line in result.stdout.splitlines() if line.strip()]
    if len(frames) != 1:
        raise ValueError("expected exactly one native-host hello frame")
    frame = json.loads(frames[0])
    if not isinstance(frame, dict) or frame.get("id") != 1:
        raise ValueError("native host replied with an invalid request id")
    return frame


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True, help="Exact native-host executable to inspect")
    parser.add_argument("--require", choices=list(REQUIREMENTS), help="Fail closed if this manual test is not eligible")
    args = parser.parse_args(argv)
    try:
        outcome = assess(get_hello(args.host.resolve()))
    except (ValueError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print("preflight unavailable: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(outcome, indent=2, sort_keys=True))
    if args.require and not outcome["manual_test_preflight"][args.require]["eligible_for_manual_test"]:
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
