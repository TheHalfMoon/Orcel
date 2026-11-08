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
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "orcel-agent", "version": "0.1.0"}
#: Largest single frame accepted from the edge (as the benchmark client).
MAX_FRAME_BYTES = 8 << 20
#: orceld's broker may wait this long for a person (the edge's approval
#: timeout is 10 minutes); calls that can prompt use a longer deadline so the
#: agent never gives up while orceld may still act.
APPROVAL_CALL_TIMEOUT_S = 11 * 60.0

_TOO_LARGE = b"\x00too-large"


class EdgeError(Exception):
    """The edge could not be started, answered out of protocol, or timed out."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    input_schema: dict[str, Any]
    #: The edge's own description (SG-000129 slice 2: a chat model needs it).
    description: str = ""


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
        try:
            self._request(
                "initialize",
                {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": CLIENT_INFO},
                self.timeout_s,
            )
            self._send({"jsonrpc": "2.0", "method": "notifications/initialized"}, self.timeout_s)
        except BaseException:
            self.close()
            raise

    def _read(self) -> None:
        process = self._process
        assert process is not None and process.stdout is not None
        stdout = process.stdout
        try:
            while True:
                line = stdout.readline(MAX_FRAME_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_FRAME_BYTES:
                    self._lines.put(_TOO_LARGE)  # never buffer the rest
                    break
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        self._lines.put(None)

    def _send(self, message: dict[str, Any], timeout_s: float) -> None:
        process = self._process
        if process is None or process.stdin is None:
            raise EdgeError("the edge is not running")
        data = json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"
        failure: list[BaseException] = []

        def write() -> None:
            try:
                process.stdin.write(data)  # type: ignore[union-attr]
                process.stdin.flush()  # type: ignore[union-attr]
            except (OSError, ValueError) as error:
                failure.append(error)

        writer = threading.Thread(target=write, daemon=True)
        writer.start()
        writer.join(timeout_s)
        if writer.is_alive():
            raise EdgeError("the edge stopped reading its input")
        if failure:
            raise EdgeError(f"the edge closed its input: {failure[0]}")

    def _request(self, method: str, params: dict[str, Any], timeout_s: float) -> Any:
        self._next_id += 1
        request_id = self._next_id
        deadline = time.monotonic() + timeout_s
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, timeout_s)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EdgeError(f"the edge did not answer {method} in time")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty as error:
                raise EdgeError(f"the edge did not answer {method} in time") from error
            if line is None:
                raise EdgeError("the edge exited")
            if line == _TOO_LARGE:
                raise EdgeError("the edge sent a frame over the size limit")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # not a protocol frame
            # A response has our id and no method; anything else (a
            # notification, a server request reusing an id) is not ours.
            if not isinstance(message, dict) or "method" in message or message.get("id") != request_id:
                continue
            error = message.get("error")
            if error is not None:
                text = error.get("message", "protocol error") if isinstance(error, dict) else "protocol error"
                raise EdgeError(f"{method} failed: {text}")
            return message.get("result")

    def list_tools(self) -> list[ToolSpec]:
        result = self._request("tools/list", {}, self.timeout_s)
        tools = result.get("tools", []) if isinstance(result, dict) else []
        # A tool without an object schema is dropped (fail closed): the gate
        # could not check its arguments.
        return [ToolSpec(t["name"], t.get("inputSchema", {}), str(t.get("description") or "")[:2000])
                for t in tools if isinstance(t, dict) and "name" in t and isinstance(t.get("inputSchema", {}), dict)]

    def call_tool(self, name: str, arguments: dict[str, Any], timeout_s: Optional[float] = None) -> ToolOutcome:
        result = self._request("tools/call", {"name": name, "arguments": arguments}, timeout_s or self.timeout_s)
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
        except (OSError, ValueError, subprocess.TimeoutExpired):
            process.kill()
            process.wait()
        finally:
            if process.stdout is not None:
                process.stdout.close()

    def __enter__(self) -> "Edge":
        self.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


#: The MCP SDK's own plain-text rejections, made before anything reaches
#: orceld: certainly refused. Any other plain-text error (an orceld timeout
#: or exit inside the edge) may follow a call orceld ran, so it is a
#: protocol failure and takes the unknown-outcome path.
_SDK_REJECTIONS = ("Input validation error", "Invalid arguments", "MCP error -32602", "Tool ")


def parse_tool_result(result: Any) -> ToolOutcome:
    """The edge's projection (`apps/orcel-mcp/src/result.ts`): one text item
    holding `{result, evidence}` on success, `{error: {code, message}}` with
    `isError` on refusal. A plain-text `isError` from the MCP SDK's own
    validation is a typed refusal (`INVALID_REQUEST`). Anything else is a
    protocol failure."""
    is_error = isinstance(result, dict) and result.get("isError") is True
    try:
        text = result["content"][0]["text"]
        body = json.loads(text)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        text_value = None
        if is_error:
            try:
                text_value = str(result["content"][0]["text"])
            except (KeyError, IndexError, TypeError):
                text_value = None
        if text_value is not None and text_value.startswith(_SDK_REJECTIONS) and (
            not text_value.startswith("Tool ") or "not found" in text_value
        ):
            return ToolOutcome(ok=False, error_code="INVALID_REQUEST", error_message="the edge rejected the arguments")
        raise EdgeError("the edge returned an unexpected tool result") from error
    if is_error:
        error = body.get("error") if isinstance(body, dict) else None
        if not isinstance(error, dict):
            return ToolOutcome(ok=False, error_code="INVALID_REQUEST", error_message="the edge refused the call")
        return ToolOutcome(ok=False, error_code=str(error.get("code", "INTERNAL_ERROR")), error_message=str(error.get("message", "")))
    if not isinstance(body, dict):
        raise EdgeError("the edge returned an unexpected tool result")
    return ToolOutcome(ok=True, result=body.get("result"), evidence=body.get("evidence"))
