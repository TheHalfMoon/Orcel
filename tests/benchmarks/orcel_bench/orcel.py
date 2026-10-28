"""BM-02: a client for the real `orceld` binary, for driving benchmark tasks
through Orcel.

Orcel-owned. One `Orceld` is one orceld process over its stdio protocol (the
JSON-lines protocol the MCP edge uses), started on an episode's disposable
workspace with its own state directory and stopped at the end. Every call is
traced: capability, operation, outcome, error code and latency, never targets
or file contents. Nothing is mocked: a call that orceld refuses comes back as
`OrcelRefused` with orceld's own error code.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

#: How long one orceld call may take (shorter than the runner's plan phase,
#: so a hung orceld is reported as `orcel-timeout`, not as a plan timeout).
CALL_TIMEOUT_S = 15.0
#: How long orceld may take to stop.
STOP_TIMEOUT_S = 10.0
#: The largest response line accepted.
MAX_RESPONSE_BYTES = 8 << 20

#: The reader's marker for a response line over the limit.
_TOO_LARGE = b"\x00too-large"


class OrcelError(Exception):
    """The episode cannot go on: orceld crashed, hung or broke the protocol."""

    def __init__(self, observed: str, detail: str) -> None:
        super().__init__(f"{observed}: {detail}")
        self.observed = observed


class OrcelRefused(Exception):
    """orceld refused one call, with its own error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass
class Call:
    capability: str
    operation: str
    target: Optional[str]
    ok: bool
    code: Optional[str]
    millis: float


@dataclass
class Orceld:
    """A running orceld on `workspace`; use as a context manager."""

    binary: Path
    workspace: Path
    timeout: float = CALL_TIMEOUT_S
    #: Arguments after the binary (the real orceld takes none; tests of the
    #: runner's own failure handling start stand-in programs with them).
    args: tuple[str, ...] = ()
    calls: list[Call] = field(default_factory=list)
    _process: Optional[subprocess.Popen[bytes]] = None
    _lines: "queue.Queue[Optional[bytes]]" = field(default_factory=queue.Queue)
    _reader: Optional[threading.Thread] = None
    _state: Optional[Path] = None
    _count: int = 0
    #: orceld's own audit records for the episode, counted at the end.
    audit_records: int = 0

    def __enter__(self) -> "Orceld":
        self._state = Path(tempfile.mkdtemp(prefix="orcel-bench-state-"))
        scratch = self._state / "tmp"
        scratch.mkdir()
        env = {key: value for key, value in os.environ.items() if key in ("PATH", "SYSTEMROOT", "SystemRoot", "WINDIR")}
        env.update(
            {
                "ORCEL_WORKSPACE_ROOT": str(self.workspace),
                "ORCEL_WORKSPACE_ID": "default",
                "ORCEL_APP_API": "off",
                "ORCEL_AUDIT_PATH": str(self._state / "audit" / "audit.jsonl"),
                # Per-OS private state and scratch, never the user's own.
                "LOCALAPPDATA": str(self._state),
                "XDG_STATE_HOME": str(self._state),
                "HOME": str(self._state),
                "USERPROFILE": str(self._state),
                "TEMP": str(scratch),
                "TMP": str(scratch),
                "TMPDIR": str(scratch),
            }
        )
        # orceld's stderr is kept so a crash can say why (first line only,
        # in the trace, never in a report).
        self._stderr = (self._state / "orceld-stderr.log").open("wb")
        try:
            self._process = subprocess.Popen(
                [str(self.binary), *self.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                env=env,
            )
        except OSError as error:
            self._stderr.close()
            self._cleanup_state()
            raise OrcelError("orcel-crash", f"orceld did not start: {error}") from error
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        return self

    def _read(self) -> None:
        assert self._process is not None and self._process.stdout is not None
        stdout = self._process.stdout
        try:
            while True:
                line = stdout.readline(MAX_RESPONSE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_RESPONSE_BYTES:
                    # Never buffer the rest of an oversized line.
                    self._lines.put(_TOO_LARGE)
                    break
                self._lines.put(line)
        except (OSError, ValueError):
            pass
        self._lines.put(None)

    def stderr_head(self) -> str:
        """The first line orceld wrote to stderr, at most 300 characters."""
        if self._state is None:
            return ""
        try:
            text = (self._state / "orceld-stderr.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        return (text.splitlines() or [""])[0][:300]

    @property
    def audit_path(self) -> Optional[Path]:
        return self._state / "audit" / "audit.jsonl" if self._state else None

    def call(self, capability: str, operation: str, target: Optional[str], arguments: Optional[dict[str, Any]] = None) -> Any:
        """One request; the result on success, `OrcelRefused` on refusal."""
        process = self._process
        if process is None or process.stdin is None:
            raise OrcelError("orcel-crash", "orceld is not running")
        self._count += 1
        request = {
            "version": 1,
            "request_id": f"bench-{self._count}",
            "client_session_id": "orcel-bench",
            "workspace_id": "default",
            "capability": capability,
            "operation": operation,
            "target": target,
            "arguments": arguments or {},
        }
        started = time.perf_counter()
        try:
            process.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
            process.stdin.flush()
        except OSError as error:
            raise OrcelError("orcel-crash", f"orceld stopped reading: {error}") from error
        try:
            line = self._lines.get(timeout=self.timeout)
        except queue.Empty:
            raise OrcelError("orcel-timeout", f"no answer to {capability} within {self.timeout} s") from None
        millis = (time.perf_counter() - started) * 1000
        if line is None:
            try:
                process.wait(timeout=STOP_TIMEOUT_S)
            except subprocess.TimeoutExpired:
                raise OrcelError("orcel-crash", "orceld closed its output but did not exit") from None
            raise OrcelError("orcel-crash", f"orceld exited (code {process.poll()}): {self.stderr_head()}")
        if line is _TOO_LARGE:
            raise OrcelError("orcel-protocol", "response too large")
        try:
            response = json.loads(line)
        except json.JSONDecodeError as error:
            raise OrcelError("orcel-protocol", "response is not JSON") from error
        if not isinstance(response, dict) or response.get("request_id") != request["request_id"]:
            raise OrcelError("orcel-protocol", "response for another request")
        if response.get("ok") is True:
            self.calls.append(Call(capability, operation, target, True, None, millis))
            return response.get("result")
        error = response.get("error") or {}
        code = str(error.get("code", "UNKNOWN"))
        self.calls.append(Call(capability, operation, target, False, code, millis))
        raise OrcelRefused(code, str(error.get("message", "")))

    def __exit__(self, *exc: object) -> None:
        process = self._process
        try:
            if process is not None:
                try:
                    if process.stdin is not None:
                        process.stdin.close()
                    process.wait(timeout=STOP_TIMEOUT_S)
                except (OSError, subprocess.TimeoutExpired):
                    process.kill()
                    try:
                        process.wait(timeout=STOP_TIMEOUT_S)
                    except subprocess.TimeoutExpired:
                        pass
                if self._reader is not None:
                    self._reader.join(STOP_TIMEOUT_S)
                if process.stdout is not None:
                    process.stdout.close()
        finally:
            if getattr(self, "_stderr", None) is not None:
                self._stderr.close()
            audit = self.audit_path
            if audit is not None and audit.is_file():
                with audit.open("rb") as handle:
                    self.audit_records = sum(1 for _ in handle)
            self._cleanup_state()

    def _cleanup_state(self) -> None:
        if self._state is not None:
            shutil.rmtree(self._state, ignore_errors=True)
