"""M4a: the Windows pieces `model_server` needs to keep what it checked the same
until the server is up, and to keep the server from outliving the harness.

- `HeldFile`: a file opened for reading with write and delete sharing denied.
  While the handle is open, no process (of any account) can write the file,
  rename it or delete it, so a hash taken through the handle stays true.
- `hold_directory`: a directory held open without delete sharing
  (`orcel_agent.winacl.HeldDirectory`): it, and every directory above it, can't
  be renamed or deleted while held, so a path under it keeps naming the same
  file.
- `private_folder`: a new folder with orceld's owner-only DACL
  (`winacl.create_private_dir`), held and read back through its handle.
- `temp_root_problem`: why a `--temp-root` lets another account read or write
  it (or swap it), or None.
- `KillOnClose`: a job object that ends the server when the harness's last
  handle to it closes, including when the harness itself is killed.
- `listening_pids`: which processes listen on a loopback TCP port.

Off Windows these fall back to what POSIX gives (`O_NOFOLLOW`, mode 0700,
`mkdtemp`), and the job object and listener table are unavailable; `model-run`
itself refuses to run off Windows.
"""

from __future__ import annotations

import os
import re
import secrets
import socket
import stat
import struct
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

_CHUNK = 1 << 20
_GENERIC_READ = 0x8000_0000
_FILE_SHARE_READ = 0x1
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_FLAG_OPEN_REPARSE_POINT = 0x0020_0000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x0800_0000
_ERROR_INSUFFICIENT_BUFFER = 122
_AF_INET = 2
_TCP_TABLE_OWNER_PID_LISTENER = 3
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000

_api: Optional[dict[str, Any]] = None


def _native() -> dict[str, Any]:
    """The kernel32 and iphlpapi functions used here, loaded on first use."""
    global _api
    if _api is None:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
        prototypes = {
            "CreateFileW": (kernel32, wintypes.HANDLE, [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                                        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD,
                                                        wintypes.HANDLE]),
            "CloseHandle": (kernel32, wintypes.BOOL, [wintypes.HANDLE]),
            "GetFinalPathNameByHandleW": (kernel32, wintypes.DWORD, [wintypes.HANDLE, wintypes.LPWSTR,
                                                                     wintypes.DWORD, wintypes.DWORD]),
            "CreateJobObjectW": (kernel32, wintypes.HANDLE, [wintypes.LPVOID, wintypes.LPCWSTR]),
            "SetInformationJobObject": (kernel32, wintypes.BOOL, [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                                                  wintypes.DWORD]),
            "AssignProcessToJobObject": (kernel32, wintypes.BOOL, [wintypes.HANDLE, wintypes.HANDLE]),
            "GetExtendedTcpTable": (iphlpapi, wintypes.DWORD, [wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD),
                                                               wintypes.BOOL, wintypes.ULONG, ctypes.c_int,
                                                               wintypes.ULONG]),
        }
        loaded = {}
        for name, (library, restype, argtypes) in prototypes.items():
            function = getattr(library, name)
            function.restype, function.argtypes = restype, argtypes
            loaded[name] = function
        _api = loaded
    return _api


def _fail(what: str) -> OSError:
    import ctypes

    code = ctypes.get_last_error()
    return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")


def _strip_prefix(text: str) -> str:
    for prefix in ("\\\\?\\UNC\\", "\\\\?\\"):
        if text.startswith(prefix):
            return ("\\\\" if "UNC" in prefix else "") + text[len(prefix):]
    return text


def _same_path(a: str, b: str) -> bool:
    return os.path.normcase(os.path.normpath(a)) == os.path.normcase(os.path.normpath(b))


def _winacl() -> Any:
    from .agent_client import _AGENT_ROOT  # noqa: F401  (puts the agent on sys.path)
    from orcel_agent import winacl

    return winacl


class HeldFile:
    """A regular file held open for reading. On Windows the handle denies write
    and delete sharing and doesn't follow a reparse point; once it is open, the
    file's bytes can't change and it can't be renamed or removed until `close`.
    `sha256`/`size` read through the handle, never by name."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.fd: Optional[int] = None
        if sys.platform == "win32":
            import msvcrt

            api = _native()
            handle = api["CreateFileW"](str(path), _GENERIC_READ, _FILE_SHARE_READ, None, _OPEN_EXISTING,
                                        _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT
                                        | _FILE_FLAG_SEQUENTIAL_SCAN, None)
            if not handle or handle == _invalid_handle():
                raise _fail(f"opening {path}")
            try:
                self.fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            except BaseException:
                api["CloseHandle"](handle)
                raise
            try:
                if not _same_path(self.final_path(), _winacl().long_path(os.path.abspath(path))):
                    raise OSError(0, f"{path} resolves elsewhere ({self.final_path()})")
            except BaseException:
                self.close()
                raise
        else:
            self.fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            if not stat.S_ISREG(os.fstat(self.fd).st_mode):
                raise OSError(0, f"{path} is not a regular file")
        except BaseException:
            self.close()
            raise

    def final_path(self) -> str:
        """The held file's path with every link resolved (Windows only)."""
        import ctypes
        import msvcrt

        buffer = ctypes.create_unicode_buffer(32768)
        length = _native()["GetFinalPathNameByHandleW"](msvcrt.get_osfhandle(self.fd), buffer, len(buffer), 0)
        if length == 0 or length >= len(buffer):
            raise _fail("GetFinalPathNameByHandleW")
        return _strip_prefix(buffer.value)

    def size(self) -> int:
        assert self.fd is not None
        return os.fstat(self.fd).st_size

    def sha256(self) -> str:
        import hashlib

        assert self.fd is not None
        digest = hashlib.sha256()
        os.lseek(self.fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(self.fd, _CHUNK)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __del__(self) -> None:
        self.close()


def _invalid_handle() -> int:
    import ctypes

    return ctypes.c_void_p(-1).value  # type: ignore[return-value]


class _NoHold:
    """What `hold_directory` returns off Windows: nothing to hold."""

    def close(self) -> None:
        pass


def hold_directory(path: Path) -> Any:
    """`path` held so it, and every directory above it, can't be renamed or
    deleted; refuses a link or junction, or a path that resolves elsewhere."""
    if sys.platform != "win32":
        return _NoHold()
    winacl = _winacl()
    held = winacl.HeldDirectory(path)
    try:
        if not held.plain_directory():
            raise OSError(0, f"{path} is a link, a junction or not a directory")
        if not _same_path(held.final_path(), winacl.long_path(os.path.abspath(path))):
            raise OSError(0, f"{path} resolves to {held.final_path()}")
    except BaseException:
        held.close()
        raise
    return held


def private_folder(parent: Path, prefix: str) -> tuple[Path, Any]:
    """A new folder under `parent` that only this account (with SYSTEM and
    Administrators) can open, and its hold. On Windows it gets orceld's private
    DACL at creation, is held, and the DACL is read back through the handle; any
    difference refuses it (and it is removed)."""
    if sys.platform != "win32":
        return Path(tempfile.mkdtemp(prefix=prefix, dir=parent)), _NoHold()
    winacl = _winacl()
    user = winacl.current_user_sid()
    for _ in range(100):
        path = parent / f"{prefix}{secrets.token_hex(8)}"
        if winacl.create_private_dir(path, user):
            break
    else:
        raise OSError(0, f"could not create a new folder under {parent}")
    try:
        held = hold_directory(path)
    except BaseException:
        os.rmdir(path)
        raise
    try:
        problem = winacl.private_problem(held.security(), user, winacl.sddl_form(user))
        if problem is not None:
            raise OSError(0, f"{path} is not private ({problem})")
    except BaseException:
        held.close()
        os.rmdir(path)
        raise
    return path, held


_SECURITY = re.compile(r"O:([A-Za-z0-9-]+)D:([A-Z]*)((?:\([^()]*\))*)")
#: OWNER RIGHTS and CREATOR OWNER stand for whoever owns the object or creates
#: an entry in it; the owner is checked on its own.
_OWNER_STANDINS = frozenset({"OW", "S-1-3-4", "CO", "S-1-3-0"})


def acl_others_problem(sddl: str, user: str, alias: Optional[str] = None) -> Optional[str]:
    """Why this owner and DACL (SDDL) let an account other than the user,
    SYSTEM or Administrators read, write or change the folder, or None. Deny
    entries only take access away and are skipped; an allow entry for anyone
    else, of any right, is refused; an entry type that can't be judged is
    refused. Unlike `winacl.private_problem`, inherited entries are allowed when
    they name only those principals (a folder in the user's profile)."""
    if "D:NO_ACCESS_CONTROL" in sddl:
        return "has no DACL, which grants everyone full access"
    match = _SECURITY.fullmatch(sddl)
    if match is None:
        return f"has an unrecognized security descriptor {sddl!r}"
    owner, _flags, aces = match.groups()
    trusted = {"SY", "BA", "S-1-5-18", "S-1-5-32-544", user} | ({alias} if alias else set())
    if owner not in trusted:
        return f"is owned by {owner}"
    for entry in re.findall(r"\(([^()]*)\)", aces):
        fields = entry.split(";")
        if len(fields) < 6:
            return f"has an unrecognized entry ({entry})"
        kind, sid = fields[0], fields[5]
        if kind in ("D", "OD", "XD"):
            continue
        if kind != "A":
            return f"has an access entry of type {kind} that cannot be judged"
        if sid not in trusted and sid not in _OWNER_STANDINS:
            return f"grants {sid} access"
    return None


def prepare_temp_root(path: Path) -> tuple[Path, Any]:
    """Makes (with the private DACL) or checks the `--temp-root` folder and
    returns it held. Refused: a folder another account can read or write, a
    link or junction, or one whose path resolves elsewhere. Off Windows: a
    folder that isn't ours or has any group or other permission bit."""
    path = Path(os.path.abspath(path))
    if sys.platform != "win32":
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode):
            raise OSError(0, f"{path} is a link or not a directory")
        if info.st_uid != os.geteuid():
            raise OSError(0, f"{path} is owned by another account")
        if info.st_mode & 0o077:
            raise OSError(0, f"{path} is open to other accounts (mode {stat.S_IMODE(info.st_mode):o})")
        return path, _NoHold()
    winacl = _winacl()
    user = winacl.current_user_sid()
    path.parent.mkdir(parents=True, exist_ok=True)
    winacl.create_private_dir(path, user)  # False when it already exists; checked below either way
    held = hold_directory(path)
    try:
        problem = acl_others_problem(held.security(), user, winacl.sddl_form(user))
        if problem is not None:
            raise OSError(0, f"{path} {problem}")
    except BaseException:
        held.close()
        raise
    return path, held


class KillOnClose:
    """A job object with kill-on-close: a process assigned to it ends when the
    last handle to the job closes, which the system does for the harness when
    it exits or is killed. Windows only."""

    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        class Basic(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class Extended(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", Basic), ("IoInfo", ctypes.c_uint64 * 6),
                        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

        api = _native()
        self.handle: Optional[int] = api["CreateJobObjectW"](None, None)
        if not self.handle:
            raise _fail("CreateJobObjectW")
        info = Extended()
        info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not api["SetInformationJobObject"](self.handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                                              ctypes.byref(info), ctypes.sizeof(info)):
            error = _fail("SetInformationJobObject")
            self.close()
            raise error

    def assign(self, process: Any) -> None:
        if not _native()["AssignProcessToJobObject"](self.handle, int(process._handle)):
            raise _fail("AssignProcessToJobObject")

    def close(self) -> None:
        if self.handle:
            _native()["CloseHandle"](self.handle)
            self.handle = None


def listening_pids(port: int, addresses: tuple[str, ...] = ("127.0.0.1", "0.0.0.0")) -> set[int]:
    """The pids of the processes listening on IPv4 TCP `port` at any of
    `addresses` (a listener on 0.0.0.0 also takes connections to 127.0.0.1).
    Windows only."""
    import ctypes
    from ctypes import wintypes

    api = _native()
    size = wintypes.DWORD(0)
    for _ in range(5):
        buffer = ctypes.create_string_buffer(max(size.value, 4))
        status = api["GetExtendedTcpTable"](buffer, ctypes.byref(size), False, _AF_INET,
                                            _TCP_TABLE_OWNER_PID_LISTENER, 0)
        if status == 0:
            break
        if status != _ERROR_INSUFFICIENT_BUFFER:
            raise OSError(status, f"GetExtendedTcpTable failed: {ctypes.FormatError(status).strip()}")
    else:
        raise OSError(0, "GetExtendedTcpTable kept growing")
    raw = buffer.raw
    (count,) = struct.unpack_from("<I", raw, 0)
    pids = set()
    for index in range(count):
        _state, local_addr, local_port, _ra, _rp, pid = struct.unpack_from("<6I", raw, 4 + 24 * index)
        if socket.ntohs(local_port & 0xFFFF) == port and socket.inet_ntoa(struct.pack("<I", local_addr)) in addresses:
            pids.add(pid)
    return pids
