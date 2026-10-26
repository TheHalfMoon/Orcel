"""BM-02: a disposable file session for a task episode.

Orcel-owned. cua-bench gives a task a sandboxed desktop (a container or a VM);
an oracle-only dry run needs only files, so a session here is a fresh
temporary directory that is removed when the episode ends. A task names
files by relative path; an absolute path, a ``..`` segment or anything that
resolves outside the workspace is refused. Nothing runs a shell.
"""

from __future__ import annotations

import re
import shutil
import tempfile
from pathlib import Path, PurePosixPath

#: Largest file a task may write or read, in bytes.
MAX_FILE_BYTES = 1 << 20
#: One path segment.
_SEGMENT = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,99}")
#: Windows device names, refused everywhere so a task behaves the same on
#: every OS.
_DEVICES = {"CON", "PRN", "AUX", "NUL"} | {f"{name}{n}" for name in ("COM", "LPT") for n in range(1, 10)}


class SessionError(Exception):
    """A task asked for something a session does not allow."""


class FileSession:
    def __init__(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix="orcel-bench-")).resolve()
        self._closed = False

    @property
    def root(self) -> Path:
        return self._root

    def _path(self, relative: str) -> Path:
        if self._closed:
            raise SessionError("the session has ended")
        # Plain names only: no drive (`C:`), separator, stream (`a:b`),
        # trailing dot or space, or other character a platform reads
        # specially, and no `.` or `..` segment.
        if not isinstance(relative, str) or not relative or not all(
            _SEGMENT.fullmatch(part)
            and part not in (".", "..")
            and not part.endswith(".")
            and part.split(".")[0].upper() not in _DEVICES
            for part in relative.split("/")
        ):
            raise SessionError(f"not a relative path: {relative!r}")
        parts = PurePosixPath(relative)
        path = self._root.joinpath(*parts.parts)
        # Checked again through the real path, so a link inside the
        # workspace cannot lead out of it.
        resolved = path.resolve()
        if resolved != self._root and self._root not in resolved.parents:
            raise SessionError(f"outside the workspace: {relative!r}")
        return path

    async def write_file(self, relative: str, text: str) -> None:
        data = text.encode("utf-8")
        if len(data) > MAX_FILE_BYTES:
            raise SessionError(f"too large: {relative!r}")
        path = self._path(relative)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    async def read_file(self, relative: str) -> str:
        path = self._path(relative)
        if path.stat().st_size > MAX_FILE_BYTES:
            raise SessionError(f"too large: {relative!r}")
        return path.read_bytes().decode("utf-8")

    async def file_exists(self, relative: str) -> bool:
        return self._path(relative).is_file()

    async def rename(self, source: str, target: str) -> None:
        destination = self._path(target)
        if destination.exists():
            raise SessionError(f"already exists: {target!r}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._path(source).rename(destination)

    async def remove(self, relative: str) -> None:
        self._path(relative).unlink(missing_ok=True)

    async def list_files(self) -> list[str]:
        return sorted(
            path.relative_to(self._root).as_posix() for path in self._root.rglob("*") if path.is_file()
        )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            shutil.rmtree(self._root, ignore_errors=True)
