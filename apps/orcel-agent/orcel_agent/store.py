"""The agent's private state store (master plan, section C: privacy).

One directory per run under a private root:
- **Owner-only.** Mode 0700 on Unix, checked after creation. On Windows the
  root lives in the user's private profile, as orceld's state does.
- **Size-capped.** Writes beyond `max_bytes` fail closed.
- **Expiring.** Runs older than `ttl_s` are removed when a store opens.
- **Deleted on completion** by default.

It holds only the dispatch journal: tool names, argument digests and error
codes, never tool results, file contents or screenshots.
"""

from __future__ import annotations

import os
import shutil
import stat
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MAX_BYTES = 1 << 20
DEFAULT_TTL_S = 24 * 3600


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
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(path, 0o700)
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise StoreError(f"the agent store is not private (mode {mode:o})")


def open_store(root: Path, run_id: str | None = None, *, ttl_s: float = DEFAULT_TTL_S,
               max_bytes: int = DEFAULT_MAX_BYTES, now: float | None = None) -> RunStore:
    """Open (or resume) one run's store under a private root, removing runs
    older than the TTL first."""
    _private_dir(root)
    current = time.time() if now is None else now
    for entry in root.iterdir():
        if entry.is_dir() and not entry.is_symlink() and current - entry.stat().st_mtime > ttl_s:
            shutil.rmtree(entry, ignore_errors=True)
    store = RunStore(root, run_id or uuid.uuid4().hex, max_bytes)
    _private_dir(store.directory)
    return store
