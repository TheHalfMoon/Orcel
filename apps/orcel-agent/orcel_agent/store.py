"""The agent's private state store (master plan, section C: privacy).

One directory per run under a private root:
- **Owner-only.** Mode 0700 on Unix, checked after creation. On Windows
  (SG-000129 slice 5b) the root and each run directory are created with
  orceld's protected DACL (SYSTEM, Administrators and the user; nothing
  inherited; winacl.py), and read back and checked; an existing directory
  that is not private, or is a link or junction, fails closed.
- **Held, with safe ancestors (Windows, slice 5c).** The root and run
  directories are checked through handles opened without following reparse
  points, and held open for the store's lifetime, so neither they nor any
  directory above them can be renamed or replaced after the check. Every
  directory above the root must follow orceld's ancestor rule: others may
  add entries, never delete, rename or re-point one.
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
from dataclasses import dataclass, field
from typing import Any
from pathlib import Path

DEFAULT_MAX_BYTES = 1 << 20
DEFAULT_TTL_S = 24 * 3600
_RUN_ID = re.compile(r"[0-9a-f]{32}")
#: The suffix an expiring run is renamed to before it is removed.
_EXPIRED = ".expired"


class StoreError(Exception):
    """The store cannot be made private, or a cap was reached."""


@dataclass
class RunStore:
    root: Path
    run_id: str
    max_bytes: int = DEFAULT_MAX_BYTES
    #: Windows: the root and run directories, held open by handle for the
    #: store's lifetime, so neither they nor any directory above them can be
    #: renamed or replaced after they were checked.
    _held: list[Any] = field(default_factory=list, repr=False, compare=False)
    #: Closed: a run no longer uses it. Its journal path and its capacity
    #: check (which every journal append and checkpoint save goes through)
    #: then refuse, so nothing writes to an unheld, unchecked store; a
    #: resumed run opens it again. Its directory path stays readable.
    _closed: bool = field(default=False, repr=False, compare=False)

    def _open(self) -> None:
        if self._closed:
            raise StoreError("the agent store was closed; open it again (open_store) to resume")

    @property
    def directory(self) -> Path:
        return self.root / self.run_id

    @property
    def journal_path(self) -> Path:
        self._open()
        return self.directory / "dispatch.jsonl"

    def used_bytes(self) -> int:
        self._open()
        if not self.directory.is_dir():
            return 0
        return sum(path.stat().st_size for path in self.directory.iterdir() if path.is_file())

    def check_capacity(self, extra: int) -> None:
        if self.used_bytes() + extra > self.max_bytes:
            raise StoreError("the agent store reached its size cap")

    def close(self) -> None:
        """Release the held directories (Windows) and refuse further use."""
        while self._held:
            self._held.pop().close()
        self._closed = True

    def delete(self) -> None:
        self.close()
        shutil.rmtree(self.root / self.run_id, ignore_errors=True)


def _private_dir(path: Path) -> Any:
    """Make `path` private. On Windows, the directory is returned held open
    (`winacl.HeldDirectory`); elsewhere None."""
    if os.name == "nt":
        return _private_dir_windows(path)
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        raise StoreError(f"the agent store is not private (mode {mode:o})")
    return None


def _private_dir_windows(path: Path) -> Any:
    """Create `path` with orceld's protected owner-only DACL (slice 5b), or
    refuse an existing one that is not private, a link, or a junction.

    Slice 5c: the directory is then opened by handle, without following a
    reparse point, and every check reads that handle, never the name. The
    handle is returned and kept for the store's lifetime: while it is open,
    the directory and every directory above it cannot be renamed or
    replaced. A failure closes it and raises."""
    from . import winacl

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        user = winacl.current_user_sid()
        winacl.create_private_dir(path, user)
        held = winacl.HeldDirectory(path)
    except (OSError, ValueError) as error:  # ValueError: a path holding NUL
        raise StoreError(f"the agent store {path} cannot be made private: {error}") from error
    try:
        if not held.plain_directory():
            raise StoreError(f"the agent store {path} is a link, a junction or not a directory")
        # Every directory on the way must be a real one: through a junction,
        # a link or a mount point the lexical parents checked below would not
        # be the directories the store really sits in. 8.3 short names (a
        # runner's TEMP) are expanded first; that follows no link.
        final = held.final_path()
        lexical = winacl.long_path(os.path.abspath(path))
        if os.path.normcase(os.path.normpath(final)) != os.path.normcase(os.path.normpath(lexical)):
            raise StoreError(f"the agent store {path} resolves to {final}: a junction, link or mount point "
                             "lies on its path")
        problem = winacl.private_problem(held.security(), user, winacl.sddl_form(user))
    except StoreError:
        held.close()
        raise
    except (OSError, ValueError) as error:
        held.close()
        raise StoreError(f"the agent store {path} cannot be made private: {error}") from error
    if problem is not None:
        held.close()
        # A directory made before slice 5b inherits its parent's ACL.
        raise StoreError(f"the agent store {path} is not private ({problem}); remove it to start a new store")
    return held


def _check_ancestors_windows(root: Path) -> None:
    """Slice 5c: every directory above the root must keep others from
    deleting, renaming or re-pointing what is below it (orceld's ancestor
    rule, `winacl.ancestor_problem`). Checked while the root is held, so none
    of them can be swapped afterwards."""
    from . import winacl

    try:
        user = winacl.current_user_sid()
        alias = winacl.sddl_form(user)
        for ancestor in Path(os.path.abspath(root)).parents:
            problem = winacl.ancestor_problem(winacl.security_of(ancestor), user, alias)
            if problem is not None:
                raise StoreError(f"the agent store's ancestor {ancestor} {problem}")
    except (OSError, ValueError) as error:
        raise StoreError(f"the agent store's ancestors cannot be checked: {error}") from error


def _last_activity(run: Path) -> float:
    """The newest modification among a run's files (appending to the journal
    does not touch the directory's own mtime)."""
    times = [run.stat().st_mtime]
    times.extend(path.stat().st_mtime for path in run.iterdir() if path.is_file() and not path.is_symlink())
    return max(times)


def _expire(root: Path, run_id: str, ttl_s: float, current: float) -> None:
    """Remove runs whose newest file is older than `ttl_s`, by claim first."""
    for entry in root.iterdir():
        if entry.is_symlink() or not entry.is_dir():
            continue
        # A claim an earlier expiry could not finish removing.
        if entry.name.endswith(_EXPIRED) and _RUN_ID.fullmatch(entry.name[: -len(_EXPIRED)]):
            shutil.rmtree(entry, ignore_errors=True)
            continue
        if entry.name == run_id or not _RUN_ID.fullmatch(entry.name):
            continue
        if current - _last_activity(entry) > ttl_s:
            # Claim the run by renaming it before anything is deleted. On
            # Windows (NTFS) a run still in use is held open (slice 5c) and
            # cannot be renamed, so it is skipped whole, never half-deleted.
            # On Unix nothing holds a run, so expiry relies on its newest
            # file's age alone, as before.
            claimed = entry.with_name(entry.name + _EXPIRED)
            try:
                os.rename(entry, claimed)
            except OSError:
                continue
            shutil.rmtree(claimed, ignore_errors=True)


def new_run_id() -> str:
    return uuid.uuid4().hex


def open_store(root: Path, run_id: str | None = None, *, ttl_s: float = DEFAULT_TTL_S,
               max_bytes: int = DEFAULT_MAX_BYTES, now: float | None = None) -> RunStore:
    """Open (or resume) one run's store under a private root, removing
    expired runs first."""
    run_id = run_id or new_run_id()
    if not _RUN_ID.fullmatch(run_id):
        raise StoreError("a run id is 32 lowercase hex characters")
    held_root = _private_dir(root)
    try:
        if held_root is not None:
            _check_ancestors_windows(root)
        _expire(root, run_id, ttl_s, time.time() if now is None else now)
    except BaseException:
        if held_root is not None:
            held_root.close()
        raise
    store = RunStore(root, run_id, max_bytes)
    if held_root is not None:
        store._held.append(held_root)
    try:
        held_run = _private_dir(store.directory)
    except StoreError:
        store.close()
        raise
    if held_run is not None:
        store._held.append(held_run)
    return store
