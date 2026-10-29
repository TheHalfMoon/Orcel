"""The agent's dispatch journal: the resume invariant (master plan, section C).

Before a call is forwarded to the edge, a `dispatched` record is written;
after orceld answers, a `recorded` record. After a crash, a dispatched call
without its recorded answer has an unknown outcome: it is surfaced as
`outcome_unknown` and the planner must re-observe through orceld before it
may propose a mutation again. A call is never re-dispatched from this
journal. orceld's own journal stays the truth for actions; this file holds no
tool results or file content, only the tool name, an argument digest and the
error code.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

OUTCOME_UNKNOWN = "OUTCOME_UNKNOWN"


def digest(arguments: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(arguments, sort_keys=True).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Unanswered:
    seq: int
    tool: str
    arguments_sha256: str


class DispatchJournal:
    """Append-only JSON lines in the agent's private state directory."""

    def __init__(self, path: Path, capacity_check: Optional[Callable[[int], None]] = None) -> None:
        # The directory is the private run store (store.py), already created
        # owner-only; the journal never creates or widens it.
        if not path.parent.is_dir():
            raise FileNotFoundError(f"the run store {path.parent} does not exist")
        self.path = path
        self._capacity_check = capacity_check
        self._seq = 0
        for record in self._records():
            self._seq = max(self._seq, int(record.get("seq", 0)))

    def _records(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                # A torn final line from a crash: the call it named has no
                # recorded answer, which the scan below reports.
                continue
        return out

    def _append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        if self._capacity_check is not None:
            self._capacity_check(len(line.encode("utf-8")))
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())

    def dispatched(self, tool: str, arguments: dict[str, Any]) -> int:
        self._seq += 1
        self._append({"seq": self._seq, "state": "dispatched", "tool": tool, "arguments_sha256": digest(arguments)})
        return self._seq

    def recorded(self, seq: int, ok: bool, error_code: Optional[str]) -> None:
        self._append({"seq": seq, "state": "recorded", "ok": ok, "error_code": error_code})

    def unanswered(self) -> list[Unanswered]:
        dispatched: dict[int, Unanswered] = {}
        for record in self._records():
            seq = int(record.get("seq", 0))
            if record.get("state") == "dispatched":
                dispatched[seq] = Unanswered(seq, str(record.get("tool")), str(record.get("arguments_sha256")))
            elif record.get("state") in ("recorded", "resolved_unknown"):
                dispatched.pop(seq, None)
        return sorted(dispatched.values(), key=lambda item: item.seq)

    def resolve_unknown(self, seq: int) -> None:
        """The agent surfaced this call as `outcome_unknown`; it is never
        dispatched again from here."""
        self._append({"seq": seq, "state": "resolved_unknown"})
