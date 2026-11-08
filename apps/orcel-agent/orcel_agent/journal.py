"""The agent's dispatch journal: the resume invariant (master plan, section C).

Before a call is forwarded to the edge, a `dispatched` record is written;
after orceld answers, a `recorded` record. After a crash, a dispatched call
without its recorded answer has an unknown outcome: it is surfaced once as
`OUTCOME_UNKNOWN`, the planner must re-observe through orceld before any
mutation, and that exact mutation is never dispatched again. orceld's own
journal stays the truth for actions. This file holds no tool results or file
content: only the tool name, an argument digest, the outcome and the error
code, from which a resumed agent rebuilds its refusals and budgets.
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
class Entry:
    """One dispatched call and, when known, its answer."""

    seq: int
    tool: str
    arguments_sha256: str
    answered: bool
    ok: bool = False
    error_code: Optional[str] = None
    surfaced: bool = False


class DispatchJournal:
    """Append-only JSON lines in the agent's private run store."""

    def __init__(self, path: Path, capacity_check: Optional[Callable[[int], None]] = None) -> None:
        # The directory is the private run store (store.py), already created
        # owner-only; the journal never creates or widens it.
        if not path.parent.is_dir():
            raise FileNotFoundError(f"the run store {path.parent} does not exist")
        self.path = path
        self._capacity_check = capacity_check
        self._repair_torn_tail()
        self._seq = max((entry.seq for entry in self.entries()), default=0)

    def _repair_torn_tail(self) -> None:
        """A crash mid-write leaves a final line without its newline; cut it
        so the next record starts on a line of its own. The call it named
        stays dispatched and unanswered (its `dispatched` line is complete,
        or it was never written and the call never left the agent)."""
        if not self.path.is_file():
            return
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            with self.path.open("r+b") as handle:
                handle.truncate(data.rfind(b"\n") + 1)
                handle.flush()
                os.fsync(handle.fileno())

    def _append(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, sort_keys=True) + "\n"
        if self._capacity_check is not None:
            self._capacity_check(len(line.encode("utf-8")))
        created = not self.path.exists()
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line)
            handle.flush()
            os.fsync(handle.fileno())
        if created and os.name != "nt":
            # The new file's directory entry must survive a crash too.
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)

    def entries(self) -> list[Entry]:
        if not self.path.is_file():
            return []
        found: dict[int, Entry] = {}
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                record = json.loads(line)
                seq = int(record["seq"])
            except (ValueError, KeyError, TypeError):
                continue
            state = record.get("state")
            if state == "dispatched":
                found[seq] = Entry(seq, str(record.get("tool")), str(record.get("arguments_sha256")), answered=False)
            elif seq in found and state == "recorded":
                previous = found[seq]
                found[seq] = Entry(seq, previous.tool, previous.arguments_sha256, True,
                                   bool(record.get("ok")), record.get("error_code"), previous.surfaced)
            elif seq in found and state == "resolved_unknown":
                previous = found[seq]
                found[seq] = Entry(seq, previous.tool, previous.arguments_sha256, previous.answered,
                                   previous.ok, previous.error_code or OUTCOME_UNKNOWN, True)
        return [found[seq] for seq in sorted(found)]

    def dispatched(self, tool: str, arguments: dict[str, Any]) -> int:
        self._seq += 1
        self._append({"seq": self._seq, "state": "dispatched", "tool": tool, "arguments_sha256": digest(arguments)})
        return self._seq

    def recorded(self, seq: int, ok: bool, error_code: Optional[str]) -> None:
        self._append({"seq": seq, "state": "recorded", "ok": ok, "error_code": error_code})

    def unanswered(self) -> list[Entry]:
        """Dispatched calls with no recorded answer that were never surfaced."""
        return [entry for entry in self.entries() if not entry.answered and not entry.surfaced]

    def resolve_unknown(self, seq: int) -> None:
        """The agent surfaced this call as `outcome_unknown`; it is never
        dispatched again from here."""
        self._append({"seq": seq, "state": "resolved_unknown"})
