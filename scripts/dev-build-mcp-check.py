#!/usr/bin/env python3
"""Drives an unpacked Orcel development tarball as a local MCP client would, over
stdio, through its bin/orcel-mcp. Real launcher, edge and orceld, with a private
state root. It isn't Claude or Codex: this shows the build and the protocol, not
any client.

Usage: dev-build-mcp-check.py <unpacked-tarball>

Exits non-zero unless the tools are listed, a read works, a read outside the
workspace is refused, and a report stops at orceld's approval with nothing written.
No approval is given or simulated.
"""

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

ANSWER_TIMEOUT = 120
EXPECTED_OS = "macos" if sys.platform == "darwin" else "linux"
SECRET = "orcel-dev-check-must-not-reach-the-server"


class Session:
    def __init__(self, launcher: Path, env: dict) -> None:
        self.process = subprocess.Popen(
            [str(launcher)], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True
        )
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0

    def _read(self) -> None:
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def send(self, message: dict) -> None:
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", **message}) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict) -> dict:
        self.next_id += 1
        self.send({"id": self.next_id, "method": method, "params": params})
        while True:
            line = self.lines.get(timeout=ANSWER_TIMEOUT)
            if line is None:
                raise SystemExit(f"the server exited during {method}")
            message = json.loads(line)
            if message.get("id") == self.next_id:
                if "error" in message:
                    raise SystemExit(f"{method}: {message['error']}")
                return message["result"]

    def call(self, tool: str, arguments: dict) -> tuple:
        result = self.request("tools/call", {"name": tool, "arguments": arguments})
        return result.get("isError") is True, json.loads(result["content"][0]["text"])

    def close(self) -> int:
        self.process.stdin.close()
        try:
            return self.process.wait(30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise SystemExit("the server ignored the end of its input")


def require(condition: bool, what: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {what}")


def main() -> int:
    home = Path(sys.argv[1]).resolve()
    launcher = home / "bin" / "orcel-mcp"
    scratch = Path(tempfile.mkdtemp(prefix="orcel-dev-mcp-")).resolve()
    try:
        scratch.chmod(0o700)
        workspace = scratch / "ws"
        (workspace / "data").mkdir(parents=True)
        (workspace / "reports").mkdir()
        (workspace / "data" / "q3.csv").write_text("north,1250\n", encoding="utf-8")
        outside = scratch / "outside.txt"
        outside.write_text("private", encoding="utf-8")
        state = scratch / "state"
        state.mkdir(mode=0o700)

        refused = subprocess.run([str(launcher)], env={"PATH": os.environ["PATH"]},
                                 stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
        require(refused.returncode == 2 and "ORCEL_WORKSPACE_ROOT" in refused.stderr,
                "with no workspace, the launcher must refuse")

        env = {
            "PATH": os.environ["PATH"], "HOME": str(state), "XDG_STATE_HOME": str(state),
            "TMPDIR": str(state), "ORCEL_WORKSPACE_ROOT": str(workspace), "ORCEL_WORKSPACE_ID": "default",
            "ORCEL_DEV_CHECK_SECRET": SECRET,
        }
        session = Session(launcher, env)
        session.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "orcel-dev-build-check", "version": "1"},
        })
        session.send({"method": "notifications/initialized"})
        # By now the launcher has become the server. Only Linux shows this here.
        if sys.platform.startswith("linux"):
            seen = Path(f"/proc/{session.process.pid}/environ").read_text("latin-1")
            require(SECRET not in seen, "a client's other environment must not reach the server")
            require("ORCEL_WORKSPACE_ROOT=" in seen, "the workspace must reach the server")

        tools = sorted(tool["name"] for tool in session.request("tools/list", {})["tools"])
        for tool in ("system_status", "fs_read", "report_start", "report_commit"):
            require(tool in tools, f"{tool} is listed: {tools}")
        require(not any(name.startswith("browser_") for name in tools),
                f"a development tarball serves no live browser tool: {tools}")

        failed, status = session.call("system_status", {})
        require(not failed and status.get("os", status.get("result", {}).get("os")) == EXPECTED_OS,
                f"orceld answers on {EXPECTED_OS}: {status}")

        failed, read = session.call("fs_read", {"path": "data/q3.csv"})
        require(not failed and "north,1250" in json.dumps(read), f"a read in the workspace works: {read}")
        failed, escaped = session.call("fs_read", {"path": "../outside.txt"})
        require(failed and "private" not in json.dumps(escaped), f"a read outside is refused: {escaped}")

        failed, started = session.call("report_start", {
            "title": "Q3", "sources": ["data/q3.csv"], "folder": "reports",
        })
        require(not failed, f"report_start: {started}")
        task = started.get("task_id", started.get("result", {}).get("task_id"))
        content = "# Q3\n\nnorth 1250\n"
        failed, previewed = session.call("report_preview", {"task_id": task, "name": "q3.md", "content": content})
        require(not failed, f"report_preview: {previewed}")
        digest = previewed.get("sha256", previewed.get("result", {}).get("sha256"))
        # No person is here to answer, so orceld's approval must stop this.
        failed, committed = session.call("report_commit", {
            "task_id": task, "name": "q3.md", "content": content, "expected_sha256": digest,
        })
        require(failed, f"no approval, so no commit: {committed}")
        require(not (workspace / "reports" / "q3.md").exists(), "nothing was written")

        code = session.close()
        print(f"DEV-BUILD-MCP-EVIDENCE {EXPECTED_OS}: {len(tools)} tools, read, refusal, report stopped at "
              f"approval ({committed.get('error', {}).get('code', committed)}), exit {code} "
              "(the build and the protocol, not any client)")
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
