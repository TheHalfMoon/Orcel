"""Owner-only Windows directories for the agent's private store (SG-000129
M3 slice 5b).

A store directory is created with a protected DACL of its own, the one orceld
gives its private directories (crates/orcel-platform/src/acl.rs,
`create_private_dir`): full control for SYSTEM, Administrators and the
current user, inherited by everything inside, and nothing inherited from the
parent. It is then read back and checked, so a directory that already exists
(made by someone else, or before this slice) is refused unless it is private.

The only module that uses ctypes (admitted by name in the source scan). It
calls only the advapi32 and kernel32 functions named in `FUNCTIONS`, loaded
on first use, so importing the agent loads no native code.
"""

from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes
from pathlib import Path
from typing import Any, Optional

#: Every native function this module may call, by library.
FUNCTIONS = {
    "advapi32": (
        "OpenProcessToken", "GetTokenInformation", "ConvertSidToStringSidW",
        "ConvertStringSecurityDescriptorToSecurityDescriptorW", "GetNamedSecurityInfoW",
        "ConvertSecurityDescriptorToStringSecurityDescriptorW", "GetSecurityInfo",
    ),
    "kernel32": (
        "GetCurrentProcess", "CloseHandle", "CreateDirectoryW", "LocalFree", "CreateFileW",
        "GetFileInformationByHandle",
    ),
}

#: orceld's private-directory DACL; {user} is the current user's SID.
PRIVATE_SDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{user})"
#: Who may hold an allow entry, or own the directory, besides the user.
TRUSTED = frozenset({"SY", "BA", "S-1-5-18", "S-1-5-32-544"})

_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1
_SE_FILE_OBJECT = 1
_OWNER_SECURITY_INFORMATION = 0x1
_DACL_SECURITY_INFORMATION = 0x4
_SDDL_REVISION_1 = 1
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_ALREADY_EXISTS = 183
# CreateFileW for a held directory: listing access (so the share mode is
# enforced), no FILE_SHARE_DELETE (so it cannot be renamed or deleted while
# held, nor can any directory above it), and never following a reparse point.
_DIRECTORY_ACCESS = 0x0002_0000 | 0x0080 | 0x0001  # READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY
_SHARE_READ_WRITE = 0x1 | 0x2
_OPEN_EXISTING = 3
_DIRECTORY_FLAGS = 0x0200_0000 | 0x0020_0000  # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
_INVALID_HANDLE = ctypes.c_void_p(-1).value
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class _FileInformation(ctypes.Structure):
    """BY_HANDLE_FILE_INFORMATION."""

    _fields_ = [("dwFileAttributes", wintypes.DWORD), ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME), ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD), ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD), ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD), ("nFileIndexLow", wintypes.DWORD)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL)]


_OUT = ctypes.POINTER(ctypes.c_void_p)
_PROTOTYPES = {
    "OpenProcessToken": (wintypes.BOOL, [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]),
    "GetTokenInformation": (wintypes.BOOL, [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                            ctypes.POINTER(wintypes.DWORD)]),
    "ConvertSidToStringSidW": (wintypes.BOOL, [wintypes.LPVOID, _OUT]),
    "ConvertStringSecurityDescriptorToSecurityDescriptorW": (
        wintypes.BOOL, [wintypes.LPCWSTR, wintypes.DWORD, _OUT, ctypes.POINTER(wintypes.ULONG)]),
    "GetNamedSecurityInfoW": (wintypes.DWORD, [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, _OUT, _OUT, _OUT,
                                               _OUT, _OUT]),
    "ConvertSecurityDescriptorToStringSecurityDescriptorW": (
        wintypes.BOOL, [wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, _OUT, ctypes.POINTER(wintypes.ULONG)]),
    "GetCurrentProcess": (wintypes.HANDLE, []),
    "CloseHandle": (wintypes.BOOL, [wintypes.HANDLE]),
    "CreateDirectoryW": (wintypes.BOOL, [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]),
    "LocalFree": (wintypes.LPVOID, [wintypes.LPVOID]),
    "CreateFileW": (wintypes.HANDLE, [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                                      wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]),
    "GetFileInformationByHandle": (wintypes.BOOL, [wintypes.HANDLE, ctypes.POINTER(_FileInformation)]),
    "GetSecurityInfo": (wintypes.DWORD, [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, _OUT, _OUT, _OUT, _OUT,
                                         _OUT]),
}

_api: Optional[dict[str, Any]] = None


def _functions() -> dict[str, Any]:
    global _api
    if _api is None:
        loaded = {}
        for library, names in FUNCTIONS.items():
            dll = ctypes.WinDLL(library, use_last_error=True)
            for name in names:
                function = getattr(dll, name)
                function.restype, function.argtypes = _PROTOTYPES[name]
                loaded[name] = function
        _api = loaded
    return _api


def _fail(what: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{what} failed: {ctypes.FormatError(code).strip()}")


def _take_string(api: dict[str, Any], pointer: ctypes.c_void_p) -> str:
    """A LocalAlloc'd wide string, freed once read."""
    try:
        return ctypes.wstring_at(pointer.value)
    finally:
        api["LocalFree"](pointer)


def current_user_sid() -> str:
    api = _functions()
    token = wintypes.HANDLE()
    if not api["OpenProcessToken"](api["GetCurrentProcess"](), _TOKEN_QUERY, ctypes.byref(token)):
        raise _fail("OpenProcessToken")
    try:
        needed = wintypes.DWORD()
        if not api["GetTokenInformation"](token, _TOKEN_USER, None, 0, ctypes.byref(needed)) \
                and ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise _fail("GetTokenInformation")
        pointer_size = ctypes.sizeof(ctypes.c_void_p)
        if needed.value < 2 * pointer_size:  # TOKEN_USER: a SID pointer and its attributes
            raise OSError(0, "GetTokenInformation returned a short TOKEN_USER")
        # Pointer-aligned, as TOKEN_USER is.
        buffer = (ctypes.c_void_p * (needed.value // pointer_size + 1))()
        if not api["GetTokenInformation"](token, _TOKEN_USER, buffer, needed, ctypes.byref(needed)):
            raise _fail("GetTokenInformation")
        sid = buffer[0]  # TOKEN_USER.User.Sid
        text = ctypes.c_void_p()
        if not api["ConvertSidToStringSidW"](sid, ctypes.byref(text)):
            raise _fail("ConvertSidToStringSidW")
        return _take_string(api, text)
    finally:
        api["CloseHandle"](token)


def create_private_dir(path: Path, user: str) -> bool:
    """Create `path` with the private DACL. False if it already exists
    (the caller checks it); OSError on any other failure."""
    api = _functions()
    descriptor = ctypes.c_void_p()
    if not api["ConvertStringSecurityDescriptorToSecurityDescriptorW"](
            PRIVATE_SDDL.format(user=user), _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise _fail("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
        if api["CreateDirectoryW"](os.path.abspath(path), ctypes.byref(attributes)):
            return True
        if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
            return False
        raise _fail("CreateDirectoryW")
    finally:
        api["LocalFree"](descriptor)


def security_of(path: Path) -> str:
    """The owner and DACL of `path`, as SDDL."""
    api = _functions()
    descriptor, unused = ctypes.c_void_p(), ctypes.c_void_p()
    status = api["GetNamedSecurityInfoW"](
        os.path.abspath(path), _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
        ctypes.byref(unused), ctypes.byref(unused), ctypes.byref(unused), ctypes.byref(unused),
        ctypes.byref(descriptor))
    if status != 0:
        raise OSError(status, f"GetNamedSecurityInfoW failed: {ctypes.FormatError(status).strip()}")
    try:
        text = ctypes.c_void_p()
        if not api["ConvertSecurityDescriptorToStringSecurityDescriptorW"](
                descriptor, _SDDL_REVISION_1, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                ctypes.byref(text), None):
            raise _fail("ConvertSecurityDescriptorToStringSecurityDescriptorW")
        return _take_string(api, text)
    finally:
        api["LocalFree"](descriptor)


def sddl_form(sid: str) -> str:
    """How SDDL text names `sid`: some accounts print as an alias (the
    built-in Administrator as LA, LocalService as LS, SYSTEM as SY)."""
    api = _functions()
    descriptor = ctypes.c_void_p()
    if not api["ConvertStringSecurityDescriptorToSecurityDescriptorW"](
            f"O:{sid}", _SDDL_REVISION_1, ctypes.byref(descriptor), None):
        raise _fail("ConvertStringSecurityDescriptorToSecurityDescriptorW")
    try:
        text = ctypes.c_void_p()
        if not api["ConvertSecurityDescriptorToStringSecurityDescriptorW"](
                descriptor, _SDDL_REVISION_1, _OWNER_SECURITY_INFORMATION, ctypes.byref(text), None):
            raise _fail("ConvertSecurityDescriptorToStringSecurityDescriptorW")
        owner = _take_string(api, text)
    finally:
        api["LocalFree"](descriptor)
    if not owner.startswith("O:"):
        raise OSError(0, f"unexpected owner text {owner!r}")
    return owner[2:]


class HeldDirectory:
    """A directory opened by handle and held: while it is open, it cannot be
    renamed or deleted, and neither can any directory above it."""

    def __init__(self, path: Path) -> None:
        api = _functions()
        handle = api["CreateFileW"](os.path.abspath(path), _DIRECTORY_ACCESS, _SHARE_READ_WRITE, None,
                                    _OPEN_EXISTING, _DIRECTORY_FLAGS, None)
        if handle is None or handle == _INVALID_HANDLE:
            raise _fail("CreateFileW")
        self.handle: Optional[int] = handle

    def plain_directory(self) -> bool:
        """A directory, and not a reparse point (a junction or a link), as
        the held handle itself reports."""
        api = _functions()
        info = _FileInformation()
        if not api["GetFileInformationByHandle"](self.handle, ctypes.byref(info)):
            raise _fail("GetFileInformationByHandle")
        attributes = info.dwFileAttributes
        return bool(attributes & _FILE_ATTRIBUTE_DIRECTORY) and not attributes & _FILE_ATTRIBUTE_REPARSE_POINT

    def security(self) -> str:
        """The owner and DACL of the held directory, read through its handle
        (never by name, so a swapped path cannot answer for it), as SDDL."""
        api = _functions()
        descriptor, unused = ctypes.c_void_p(), ctypes.c_void_p()
        status = api["GetSecurityInfo"](
            self.handle, _SE_FILE_OBJECT, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(unused), ctypes.byref(unused), ctypes.byref(unused), ctypes.byref(unused),
            ctypes.byref(descriptor))
        if status != 0:
            raise OSError(status, f"GetSecurityInfo failed: {ctypes.FormatError(status).strip()}")
        try:
            text = ctypes.c_void_p()
            if not api["ConvertSecurityDescriptorToStringSecurityDescriptorW"](
                    descriptor, _SDDL_REVISION_1, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
                    ctypes.byref(text), None):
                raise _fail("ConvertSecurityDescriptorToStringSecurityDescriptorW")
            return _take_string(api, text)
        finally:
            api["LocalFree"](descriptor)

    def close(self) -> None:
        if self.handle is not None:
            api = _functions()
            api["CloseHandle"](self.handle)
            self.handle = None

    def __del__(self) -> None:
        self.close()


_SECURITY = re.compile(r"O:([A-Za-z0-9-]+)D:([A-Z]*)((?:\([^()]*\))*)")


def private_problem(sddl: str, user: str, alias: Optional[str] = None) -> Optional[str]:
    """Why a directory's security (SDDL) is not private, or None when it is:
    owned by the user or a trusted principal, a protected DACL (nothing
    inherited), and only allow entries for the user and trusted principals,
    with the user among them. `alias` is the user's SDDL form when it is
    not the SID itself (sddl_form)."""
    match = _SECURITY.fullmatch(sddl)
    if match is None:
        return f"unrecognized security descriptor {sddl!r}"
    owner, flags, aces = match.groups()
    me = {user} | ({alias} if alias else set())
    allowed = TRUSTED | me
    if owner not in allowed:
        return f"owned by {owner}"
    if "P" not in flags:
        return "the DACL is not protected"
    entries = re.findall(r"\(([^()]*)\)", aces)
    seen = set()
    for entry in entries:
        fields = entry.split(";")
        if len(fields) < 6:
            return f"unrecognized entry ({entry})"
        kind, ace_flags, sid = fields[0], fields[1], fields[5]
        if kind != "A":
            return f"an entry of type {kind}"
        if "ID" in ace_flags:
            return "an inherited entry"
        if sid not in allowed:
            return f"access for {sid}"
        seen.add(sid)
    if not me & seen:
        return "no entry for the user"
    return None


# ---- Directories above the store: orceld's ancestor rule ----------------------
#
# Ported from orceld's own judge (crates/orcel-platform/src/acl.rs, `judge`
# with `Role::Ancestor`), so the agent and orceld agree on what an ancestor
# may grant. Another principal may add entries to a directory above the store
# (like a sticky /tmp), but never delete, rename or re-point one.

_DELETE = 0x0001_0000
_FILE_DELETE_CHILD = 0x0040
_WRITE_DAC = 0x0004_0000
_WRITE_OWNER = 0x0008_0000
_GENERIC_ALL = 0x1000_0000
#: Rights that let a holder replace, rename or re-point an entry below a
#: directory, or the directory itself.
REPLACE_RIGHTS = _DELETE | _FILE_DELETE_CHILD | _WRITE_DAC | _WRITE_OWNER | _GENERIC_ALL
#: Trusted besides the user: SYSTEM, Administrators, TrustedInstaller.
ANCESTOR_TRUSTED = frozenset({
    "SY", "BA", "S-1-5-18", "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
})
#: OWNER RIGHTS: whatever the separately checked owner holds.
_OWNER_RIGHTS = frozenset({"OW", "S-1-3-4"})
#: SDDL access-right strings and their masks (the two-letter forms are the
#: bits they name; for files they are the file-specific rights by value).
_RIGHTS = {
    "GA": 0x1000_0000, "GR": 0x8000_0000, "GW": 0x4000_0000, "GX": 0x2000_0000,
    "RC": 0x0002_0000, "SD": 0x0001_0000, "WD": 0x0004_0000, "WO": 0x0008_0000,
    "CC": 0x0001, "DC": 0x0002, "LC": 0x0004, "SW": 0x0008, "RP": 0x0010, "WP": 0x0020,
    "DT": 0x0040, "LO": 0x0080, "CR": 0x0100,
    "FA": 0x001F_01FF, "FR": 0x0012_0089, "FW": 0x0012_0116, "FX": 0x0012_00A0,
}


def rights_mask(rights: str) -> Optional[int]:
    """The access mask an SDDL rights field names, or None when any part of
    it is not understood (which fails closed)."""
    if rights.lower().startswith("0x"):
        try:
            return int(rights, 16)
        except ValueError:
            return None
    if not rights or len(rights) % 2:
        return None
    mask = 0
    for index in range(0, len(rights), 2):
        part = _RIGHTS.get(rights[index:index + 2])
        if part is None:
            return None
        mask |= part
    return mask


def ancestor_problem(sddl: str, user: str, alias: Optional[str] = None) -> Optional[str]:
    """Why a directory above the store lets another principal swap what is
    below it, or None when it does not (orceld's `Role::Ancestor`):
    - the owner is the user, SYSTEM, Administrators or TrustedInstaller;
    - there is a DACL (a NULL DACL grants everyone everything);
    - deny entries only take access away and inherit-only entries do not
      apply to the directory itself, so both are skipped;
    - any other entry type cannot be judged and is refused;
    - an allow entry for anyone else holds none of `REPLACE_RIGHTS`.
    `alias` is the user's SDDL form when it is not the SID itself."""
    trusted = ANCESTOR_TRUSTED | {user} | ({alias} if alias else set())
    if "D:NO_ACCESS_CONTROL" in sddl:
        return "has no DACL, which grants everyone full access"
    match = _SECURITY.fullmatch(sddl)
    if match is None:
        return f"unrecognized security descriptor {sddl!r}"
    owner, _flags, aces = match.groups()
    if owner not in trusted:
        return f"is owned by {owner}"
    for entry in re.findall(r"\(([^()]*)\)", aces):
        fields = entry.split(";")
        if len(fields) < 6:
            return f"has an unrecognized entry ({entry})"
        kind, ace_flags, rights, sid = fields[0], fields[1], fields[2], fields[5]
        tokens = {ace_flags[i:i + 2] for i in range(0, len(ace_flags), 2)}
        if "IO" in tokens or kind == "D":
            continue
        if kind != "A":
            return f"has an access entry of type {kind} that cannot be judged"
        if sid in trusted or sid in _OWNER_RIGHTS:
            continue
        mask = rights_mask(rights)
        if mask is None:
            return f"grants {sid} rights {rights!r} that cannot be judged"
        if mask & REPLACE_RIGHTS:
            return f"grants {sid} access {mask & REPLACE_RIGHTS:#x}"
    return None
