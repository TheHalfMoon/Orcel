"""macOS extended ACLs on the agent store (#601): orceld's rule
(`crates/orcel-platform/src/macos_acl.rs`, #384 item 1).

The mode bits do not show an entry added with `chmod +a`, so the store's
owner and mode checks also refuse:
- on the store's own directories, any `allow` entry (orceld's
  `Refuse::AnyAllow`, the 0700 counterpart);
- on a directory above the store, an `allow` entry that grants a right which
  changes the directory or the entries below it (`Refuse::Write`).

Deny entries only take access away and are ignored. No ACL, or a file system
that holds none, passes; any other failure to read one fails closed.

The native surface is pinned: one library and the functions in `FUNCTIONS`
(tests/test_agent.py checks this file's source).
"""

from __future__ import annotations

import ctypes
import os
from typing import Any, Optional

LIBRARY = "/usr/lib/libSystem.B.dylib"
FUNCTIONS = ("acl_get_fd_np", "acl_get_link_np", "acl_get_entry", "acl_get_tag_type", "acl_get_permset",
             "acl_get_perm_np", "acl_free")

#: `<sys/acl.h>`.
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0
ACL_NEXT_ENTRY = -1
ACL_EXTENDED_ALLOW = 1
#: The `acl_perm_t` values that change an object or the entries below it
#: (orceld's `WRITE_PERMS`).
WRITE_PERMS = ((1 << 2, "write_data/add_file"), (1 << 4, "delete"), (1 << 5, "append_data/add_subdirectory"),
               (1 << 6, "delete_child"), (1 << 8, "write_attributes"), (1 << 10, "write_extattributes"),
               (1 << 12, "write_security"), (1 << 13, "change_owner"))
#: A file system that stores no ACLs, or an object without one.
_NO_ACL = {2, 45, 102}  # ENOENT, ENOTSUP, EOPNOTSUPP (Darwin)

_PROTOTYPES: dict[str, tuple[Any, list[Any]]] = {
    "acl_get_fd_np": (ctypes.c_void_p, [ctypes.c_int, ctypes.c_int]),
    "acl_get_link_np": (ctypes.c_void_p, [ctypes.c_char_p, ctypes.c_int]),
    "acl_get_entry": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p)]),
    "acl_get_tag_type": (ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]),
    "acl_get_permset": (ctypes.c_int, [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]),
    "acl_get_perm_np": (ctypes.c_int, [ctypes.c_void_p, ctypes.c_int]),
    "acl_free": (ctypes.c_int, [ctypes.c_void_p]),
}
_loaded: dict[str, Any] = {}


def _functions() -> dict[str, Any]:
    if not _loaded:
        dll = ctypes.CDLL(LIBRARY, use_errno=True)
        for name in FUNCTIONS:
            function = getattr(dll, name)
            function.restype, function.argtypes = _PROTOTYPES[name]
            _loaded[name] = function
    return _loaded


def problem(*, fd: Optional[int] = None, path: Optional[str] = None, any_allow: bool) -> Optional[str]:
    """Why the extended ACL of the directory open as `fd` (or at `path`,
    a final link not followed) is refused, or None. `any_allow` refuses every
    allow entry; otherwise only a write-granting one."""
    api = _functions()
    if fd is not None:
        acl = api["acl_get_fd_np"](fd, ACL_TYPE_EXTENDED)
    else:
        acl = api["acl_get_link_np"](os.fsencode(path or ""), ACL_TYPE_EXTENDED)
    if not acl:
        errno = ctypes.get_errno()
        if errno in _NO_ACL:
            return None
        return f"has an ACL that cannot be read (os error {errno})"
    try:
        entry_id = ACL_FIRST_ENTRY
        while True:
            entry = ctypes.c_void_p()
            if api["acl_get_entry"](acl, entry_id, ctypes.byref(entry)) != 0:
                return None  # past the last entry
            entry_id = ACL_NEXT_ENTRY
            tag = ctypes.c_int()
            if api["acl_get_tag_type"](entry, ctypes.byref(tag)) != 0:
                return "has an unreadable ACL entry"
            if tag.value != ACL_EXTENDED_ALLOW:
                continue
            if any_allow:
                return "has an ACL entry that grants access"
            permset = ctypes.c_void_p()
            if api["acl_get_permset"](entry, ctypes.byref(permset)) != 0:
                return "has an unreadable ACL entry"
            for perm, name in WRITE_PERMS:
                granted = api["acl_get_perm_np"](permset, perm)
                if granted == 1:
                    return f"has an ACL entry that grants {name}"
                if granted != 0:
                    return "has an unreadable ACL entry"
    finally:
        api["acl_free"](acl)
