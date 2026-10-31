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
        "ConvertSecurityDescriptorToStringSecurityDescriptorW",
    ),
    "kernel32": ("GetCurrentProcess", "CloseHandle", "CreateDirectoryW", "LocalFree"),
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
        buffer = ctypes.create_string_buffer(needed.value)
        if not api["GetTokenInformation"](token, _TOKEN_USER, buffer, needed, ctypes.byref(needed)):
            raise _fail("GetTokenInformation")
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]  # TOKEN_USER.User.Sid
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


_SECURITY = re.compile(r"O:([A-Za-z0-9-]+)D:([A-Z]*)((?:\([^()]*\))*)")


def private_problem(sddl: str, user: str) -> Optional[str]:
    """Why a directory's security (SDDL) is not private, or None when it is:
    owned by the user or a trusted principal, a protected DACL (nothing
    inherited), and only allow entries for the user and trusted principals,
    with the user among them."""
    match = _SECURITY.fullmatch(sddl)
    if match is None:
        return f"unrecognized security descriptor {sddl!r}"
    owner, flags, aces = match.groups()
    allowed = TRUSTED | {user}
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
    if user not in seen:
        return "no entry for the user"
    return None
