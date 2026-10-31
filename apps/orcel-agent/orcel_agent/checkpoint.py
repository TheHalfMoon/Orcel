"""Durable planner state for the Orcel Agent (SG-000129 M3 slice 5).

One small SQLite file, `planner.sqlite`, inside the run's private store. It
holds the planner's own memory: todos, loop-detection history, the compaction
summary and the stop reason. The dispatch journal (journal.py) stays the
authority on what was dispatched, so a checkpoint can never cause a call to be
dispatched again; resuming always goes through the gate's resume invariant.

Store rules (spec decision "Rule change: what the agent's private store may
hold"):
- **Inside the run directory, counted against the cap.** The database and its
  rollback journal live there (journal_mode=DELETE, asserted); a capacity check
  of the real file sizes runs before each save, and `max_page_count` holds the
  database to half the remaining space, leaving room for the rollback journal,
  so filling past the cap fails closed.
- **No temporary files elsewhere:** temp_store=MEMORY.
- **Freed pages inside the database are zeroed:** secure_delete=ON. (This does
  not scrub the unlinked rollback journal or files the store later deletes.)
- **No extensions, no planted schema:** none is ever enabled; trusted_schema
  is OFF, and a database holding anything but the one `state` table fails
  closed.
- **No symlinks:** a symlinked database or journal fails closed.
- **Owner-only:** the directory is the store's (0700 on Unix; on Windows a
  protected owner-only DACL, slice 5b, that the files inherit); the files are
  0600 on Unix.
- **Deleted with the run, expiring after a crash** (store.py).

JSON only: a checkpoint is data, so reading one back cannot construct
arbitrary types or run code. A checkpoint that does not parse or validate
fails closed (StoreError); `discard()` removes it (the journal stays
authoritative, so discarding only forgets the planner's memory).

Why not langgraph-checkpoint-sqlite (recorded in the spec): there is no
LangGraph graph to checkpoint (the M1 loop stays the only dispatcher, slice 3),
and LangGraph's msgpack serializer allows arbitrary types on load by default.
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
_CREATE = "CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
#: The only schema accepted, exactly as SQLite records it.
_SCHEMA = {("table", "state", "CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
           ("index", "sqlite_autoindex_state_1", None)}


class PlannerCheckpoint:
    """Save and load one run's planner state."""

    def __init__(self, store: RunStore) -> None:
        self._store = store

    @property
    def path(self) -> Path:
        return self._store.directory / CHECKPOINT_FILE

    @property
    def _journal(self) -> Path:
        return self._store.directory / (CHECKPOINT_FILE + "-journal")

    def _files_bytes(self) -> int:
        return sum(p.stat().st_size for p in (self.path, self._journal) if p.is_file())

    def _refuse_links(self) -> None:
        if self.path.is_symlink() or self._journal.is_symlink():
            raise StoreError("the planner checkpoint is a link")

    def _connect(self) -> sqlite3.Connection:
        self._refuse_links()
        try:
            connection = sqlite3.connect(str(self.path), isolation_level=None, timeout=5)
        except sqlite3.Error as error:
            raise StoreError(f"the planner checkpoint cannot be opened: {type(error).__name__}") from error
        try:
            connection.execute("PRAGMA trusted_schema=OFF")
            mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()[0]
            if str(mode).lower() != "delete":
                raise StoreError(f"the planner checkpoint is in journal mode {mode}")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA secure_delete=ON")
            page = int(connection.execute("PRAGMA page_size").fetchone()[0])
            others = self._store.used_bytes() - self._files_bytes()
            pages = max((self._store.max_bytes - others) // (2 * page), 2)
            connection.execute(f"PRAGMA max_page_count={int(pages)}")
            schema = set(connection.execute("SELECT type, name, sql FROM sqlite_master").fetchall())
            if schema not in (set(), _SCHEMA):
                raise StoreError("the planner checkpoint holds an unexpected schema")
            connection.execute(_CREATE)
        except sqlite3.Error as error:
            connection.close()
            raise StoreError(f"the planner checkpoint is unusable: {type(error).__name__}") from error
        except BaseException:
            connection.close()
            raise
        if os.name != "nt":
            os.chmod(self.path, 0o600)
        return connection

    def save(self, state: dict[str, Any]) -> None:
        """Replace the saved state. Fails closed (StoreError) at the cap."""
        data = json.dumps({"version": SCHEMA_VERSION, "state": state}, ensure_ascii=False, sort_keys=True)
        # The new row, a copy in the rollback journal, and page overhead, on
        # top of the files as they are (the database does not shrink).
        self._store.check_capacity(2 * len(data.encode("utf-8")) + 16_384)
        connection = self._connect()
        try:
            connection.execute("INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)", (_KEY, data))
        except sqlite3.Error as error:  # including SQLITE_FULL at max_page_count
            raise StoreError(f"the planner checkpoint could not be saved: {type(error).__name__}") from error
        finally:
            connection.close()

    def load(self) -> Optional[dict[str, Any]]:
        """The saved state, None when there is none; StoreError if invalid."""
        self._refuse_links()
        if not self.path.is_file():
            return None
        connection = self._connect()
        try:
            row = connection.execute("SELECT value FROM state WHERE key = ?", (_KEY,)).fetchone()
        except sqlite3.Error as error:
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

    def discard(self) -> None:
        """Forget the planner's memory (recovery from a corrupt checkpoint).
        The dispatch journal is untouched and stays authoritative."""
        for path in (self.path, self._journal):
            if path.is_symlink() or path.is_file():
                path.unlink()
