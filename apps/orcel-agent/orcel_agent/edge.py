"""The Orcel Agent's only tool source: one MCP stdio connection to the Orcel
edge (`apps/orcel-mcp`), which forwards every call to orceld.

Standard library only (M1 of
`docs/orcel/implementation-readiness/prep/DEERFLOW_ORCEL_AGENT_MASTER_PLAN.md`).
The agent spawns exactly one child, the edge; it opens no socket and runs no
shell. orceld decides every call; this client only forwards and reports.
"""

from __future__ import annotations

import json
import queue
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "orcel-agent", "version": "0.1.0"}


class EdgeError(Exception):
    """The edge could not be started, answered out of protocol, or timed out."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolOutcome:
    """One forwarded call: orceld's result, or its typed refusal."""

    ok: bool
    result: Any = None
    error_code: Optional[str] = None
    error_message: str = ""
    evidence: Any = None


@dataclass
class Edge:
    """A JSON-RPC 2.0 client over the edge's newline-delimited stdio."""

    command: Sequence[str]
    env: dict[str, str]
    timeout_s: float = 60.0
    _process: Optional[subprocess.Popen[bytes]] = field(default=None, init=False)
    _lines: "queue.Queue[Optional[bytes]]" = field(default_factory=queue.Queue, init=False)
    _next_id: int = field(default=0, init=False)

    def start(self) -> None:
        if self._process is not None:
            raise EdgeError("the edge is already running")
        try:
            # The single allowlisted spawn: an argument vector, never a shell.
            self._process = subprocess.Popen(
                list(self.command),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=dict(self.env),
                shell=False,
            )
        except OSError as error:
            raise EdgeError(f"the edge did not start: {error}") from error
        threading.Thread(target=self._read, daemon=True).start()
        self._request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
        )
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def _read(self) -> None:
        process = self._process
        assert process is not None and process.stdout is not None
        for line in process.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def _send(self, message: dict[str, Any]) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise EdgeError("the edge is not running")
        try:
            process.stdin.write(json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n")
            process.stdin.flush()
        except OSError as error:
            raise EdgeError(f"the edge closed its input: {error}") from error

    def _request(self, method: str, params: dict[str, Any]) -> Any:
        self._next_id += 1
        request_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            try:
                line = self._lines.get(timeout=self.timeout_s)
            except queue.Empty as error:
                raise EdgeError(f"the edge did not answer {method} in time") from error
            if line is None:
                raise EdgeError("the edge exited")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # not a protocol frame
            if message.get("id") != request_id:
                continue  # a notification or a server request: ignored
            if "error" in message:
                raise EdgeError(f"{method} failed: {message['error'].get('message', 'protocol error')}")
            return message.get("result")

    def list_tools(self) -> list[ToolSpec]:
        result = self._request("tools/list", {})
        return [ToolSpec(t["name"], t.get("inputSchema", {})) for t in result.get("tools", [])]

    def call_tool(self, name: str, arguments: dict[str, Any]) -> ToolOutcome:
        result = self._request("tools/call", {"name": name, "arguments": arguments})
        return parse_tool_result(result)

    def close(self) -> None:
        process = self._process
        self._process = None
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()

    def __enter__(self) -> "Edge":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def parse_tool_result(result: Any) -> ToolOutcome:
    """The edge's projection (`apps/orcel-mcp/src/result.ts`): one text item
    holding `{result, evidence}` on success, `{error: {code, message}}` with
    `isError` on refusal. Anything else is a protocol failure."""
    try:
        text = result["content"][0]["text"]
        body = json.loads(text)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise EdgeError("the edge returned an unexpected tool result") from error
    if result.get("isError"):
        error = body.get("error") or {}
        return ToolOutcome(
            ok=False,
            error_code=str(error.get("code", "INTERNAL_ERROR")),
            error_message=str(error.get("message", "")),
        )
    return ToolOutcome(ok=True, result=body.get("result"), evidence=body.get("evidence"))
