"""Durable planner state for the Orcel Agent (SG-000129 M3 slice 5).

One small SQLite file, `planner.sqlite`, inside the run's private store. It
holds the planner's own memory: todos, loop-detection history, the compaction
summary and the stop reason. The dispatch journal (journal.py) stays the
authority on what was dispatched, so a checkpoint can never cause a call to be
dispatched again; resuming always goes through the gate's resume invariant.

Store rules (spec decision "Rule change: what the agent's private store may
hold"):
- **Inside the run directory, counted against the cap.** The database and its
  rollback journal live there (journal_mode=DELETE); a capacity check of the
  real file sizes runs before each save, and `max_page_count` bounds the
  database from inside SQLite, so filling past the cap fails closed.
- **No temporary files elsewhere:** temp_store=MEMORY.
- **Deleted data is overwritten:** secure_delete=ON.
- **No extensions:** none are ever enabled or loaded.
- **Owner-only:** the directory is the store's (0700 on Unix); the files are
  0600 on Unix.
- **Deleted with the run, expiring after a crash** (store.py).

JSON only, never pickle: a checkpoint is data, so reading one back cannot run
code. A checkpoint that does not parse or validate fails closed (StoreError).

Why not langgraph-checkpoint-sqlite (recorded in the spec): there is no
LangGraph graph to checkpoint (the M1 loop stays the only dispatcher, slice 3),
and LangGraph's serializer can fall back to pickle.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any, Optional

from .store import RunStore, StoreError

CHECKPOINT_FILE = "planner.sqlite"
SCHEMA_VERSION = 1
_KEY = "planner"


class PlannerCheckpoint:
    """Save and load one run's planner state."""

    def __init__(self, store: RunStore) -> None:
        self._store = store

    @property
    def path(self) -> Path:
        return self._store.directory / CHECKPOINT_FILE

    def _files_bytes(self) -> int:
        total = 0
        for name in (CHECKPOINT_FILE, CHECKPOINT_FILE + "-journal"):
            candidate = self._store.directory / name
            if candidate.is_file():
                total += candidate.stat().st_size
        return total

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), isolation_level=None, timeout=5)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA secure_delete=ON")
            page = int(connection.execute("PRAGMA page_size").fetchone()[0])
            others = self._store.used_bytes() - self._files_bytes()
            pages = max((self._store.max_bytes - others) // page, 2)
            connection.execute(f"PRAGMA max_page_count={int(pages)}")
            connection.execute("CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        except BaseException:
            connection.close()
            raise
        if os.name != "nt":
            os.chmod(self.path, 0o600)
        return connection

    def save(self, state: dict[str, Any]) -> None:
        """Replace the saved state. Fails closed (StoreError) at the cap."""
        data = json.dumps({"version": SCHEMA_VERSION, "state": state}, ensure_ascii=False, sort_keys=True)
        # The new row, a copy in the rollback journal, and page overhead.
        self._store.check_capacity(2 * len(data.encode("utf-8")) + 16_384 - self._files_bytes())
        connection = self._connect()
        try:
            connection.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (_KEY, data))
        except sqlite3.DatabaseError as error:  # including SQLITE_FULL at max_page_count
            raise StoreError(f"the planner checkpoint could not be saved: {type(error).__name__}") from error
        finally:
            connection.close()

    def load(self) -> Optional[dict[str, Any]]:
        """The saved state, None when there is none; StoreError if invalid."""
        if not self.path.is_file():
            return None
        connection = self._connect()
        try:
            row = connection.execute("SELECT value FROM state WHERE key = ?", (_KEY,)).fetchone()
        except sqlite3.DatabaseError as error:
            raise StoreError("the planner checkpoint is unreadable") from error
        finally:
            connection.close()
        if row is None:
            return None
        try:
            document = json.loads(row[0])
        except ValueError as error:
            raise StoreError("the planner checkpoint is not valid JSON") from error
        if not isinstance(document, dict) or document.get("version") != SCHEMA_VERSION \
                or not isinstance(document.get("state"), dict):
            raise StoreError("the planner checkpoint has an unknown shape")
        return document["state"]
