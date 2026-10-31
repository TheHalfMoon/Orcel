"""The agent's private state store (master plan, section C: privacy).

One directory per run under a private root:
- **Owner-only.** Mode 0700 on Unix, checked after creation. On Windows
  (SG-000129 slice 5b) the root and each run directory are created with
  orceld's protected DACL (SYSTEM, Administrators and the user; nothing
  inherited; winacl.py), and read back and checked; an existing directory
  that is not private, or is a link or junction, fails closed.
- **Size-capped.** Writes beyond `max_bytes` fail closed.
- **Expiring.** A run whose newest file is older than `ttl_s` is removed
  when a store opens.
- **Deleted on completion** by the agent (`Agent.run`), unless kept for
  resume.

It holds the dispatch journal (tool names, argument digests and error codes)
and, from SG-000129 slice 5, the planner checkpoint (planner.sqlite: todos,
loop history and a compaction summary derived from tool results). Never raw
results, file contents or screenshots.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_BYTES = 1 << 20
DEFAULT_TTL_S = 24 * 3600
_RUN_ID = re.compile(r"[0-9a-f]{32}")


class StoreError(Exception):
    """The store cannot be made private, or a cap was reached."""


@dataclass
class RunStore:
    root: Path
    run_id: str
    max_bytes: int = DEFAULT_MAX_BYTES

    @property
    def directory(self) -> Path:
        return self.root / self.run_id

    @property
    def journal_path(self) -> Path:
        return self.directory / "dispatch.jsonl"

    def used_bytes(self) -> int:
        if not self.directory.is_dir():
            return 0
        return sum(path.stat().st_size for path in self.directory.iterdir() if path.is_file())

    def check_capacity(self, extra: int) -> None:
        if self.used_bytes() + extra > self.max_bytes:
            raise StoreError("the agent store reached its size cap")

    def delete(self) -> None:
        shutil.rmtree(self.directory, ignore_errors=True)


def _private_dir(path: Path) -> None:
    if os.name == "nt":
        _private_dir_windows(path)
        return
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise StoreError(f"the agent store is not private (mode {mode:o})")


def _private_dir_windows(path: Path) -> None:
    """Create `path` with orceld's protected owner-only DACL (slice 5b), or
    refuse an existing one that is not private, a link, or a junction."""
    from . import winacl

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        user = winacl.current_user_sid()
        winacl.create_private_dir(path, user)
        if os.lstat(path).st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT or not path.is_dir():
            raise StoreError("the agent store is a link, a junction or not a directory")
        problem = winacl.private_problem(winacl.security_of(path), user)
    except OSError as error:
        raise StoreError(f"the agent store cannot be made private: {error}") from error
    if problem is not None:
        raise StoreError(f"the agent store is not private: {problem}")


def _last_activity(run: Path) -> float:
    """The newest modification among a run's files (appending to the journal
    does not touch the directory's own mtime)."""
    times = [run.stat().st_mtime]
    times.extend(path.stat().st_mtime for path in run.iterdir() if path.is_file() and not path.is_symlink())
    return max(times)


def new_run_id() -> str:
    return uuid.uuid4().hex


def open_store(root: Path, run_id: str | None = None, *, ttl_s: float = DEFAULT_TTL_S,
               max_bytes: int = DEFAULT_MAX_BYTES, now: float | None = None) -> RunStore:
    """Open (or resume) one run's store under a private root, removing
    expired runs first."""
    run_id = run_id or new_run_id()
    if not _RUN_ID.fullmatch(run_id):
        raise StoreError("a run id is 32 lowercase hex characters")
    _private_dir(root)
    current = time.time() if now is None else now
    for entry in root.iterdir():
        if entry.name == run_id or entry.is_symlink() or not entry.is_dir() or not _RUN_ID.fullmatch(entry.name):
            continue
        if current - _last_activity(entry) > ttl_s:
            shutil.rmtree(entry, ignore_errors=True)
    store = RunStore(root, run_id, max_bytes)
    _private_dir(store.directory)
    return store
