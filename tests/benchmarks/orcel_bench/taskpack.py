"""BM-02: fetch a pinned third-party taskpack and verify it file by file.

A taskpack is not copied into Orcel. Its lock file
(tests/benchmarks/taskpacks/<name>.lock.json) pins the donor repository,
commit and subtree, and every file's path, git blob id, sha256 and size.
``fetch`` checks out exactly that subtree at that commit (sparse, no line
ending conversion) into a directory of the caller's choosing, then refuses
the result unless the files present are exactly the locked ones, byte for
byte. The licence travels with the files (the lock names it).

    python3 -m orcel_bench fetch-taskpack cua-driver-bench --into DIR [--from URL_OR_PATH]
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

LOCKS = Path(__file__).resolve().parent.parent / "taskpacks"


class TaskpackError(Exception):
    pass


def load_lock(name: str) -> dict:
    path = LOCKS / f"{name}.lock.json"
    if not path.is_file():
        raise TaskpackError(f"no lock file for taskpack {name!r}")
    return json.loads(path.read_text(encoding="utf-8"))


def _git(cwd: Path, *args: str) -> str:
    # Line endings are never converted: the lock pins the donor's bytes.
    command = ["git", "-c", "core.autocrlf=false", "-c", "core.eol=lf", "-C", str(cwd), *args]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise TaskpackError(f"git {' '.join(args[:2])} failed: {result.stderr.strip()[-500:]}")
    return result.stdout


def verify(lock: dict, root: Path) -> None:
    """Refuse ``root`` unless it holds exactly the locked files, byte for byte."""
    expected = {entry["path"]: entry for entry in lock["files"]}
    present = sorted(
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file() and ".git" not in path.parts
    )
    extra = sorted(set(present) - set(expected))
    missing = sorted(set(expected) - set(present))
    if extra or missing:
        raise TaskpackError(f"file set differs from the lock: extra {extra[:5]}, missing {missing[:5]}")
    for name in present:
        data = (root / name).read_bytes()
        entry = expected[name]
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        if len(data) != entry["bytes"] or blob != entry["git_blob"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise TaskpackError(f"{name} differs from the donor's blob {entry['git_blob']}")


def fetch(name: str, into: Path, source: str | None = None) -> Path:
    """Check out the locked taskpack into ``into`` (which must not exist)
    and verify it; returns the taskpack's root."""
    lock = load_lock(name)
    donor = lock["donor"]
    if into.exists():
        raise TaskpackError(f"{into} already exists")
    checkout = into.with_name(into.name + ".checkout")
    if checkout.exists():
        shutil.rmtree(checkout)
    checkout.mkdir(parents=True)
    try:
        _git(checkout, "init", "-q")
        _git(checkout, "remote", "add", "origin", source or donor["url"])
        _git(checkout, "sparse-checkout", "set", "--no-cone", f"/{donor['path']}/", f"/{donor['license_path']}")
        _git(checkout, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", donor["commit"])
        _git(checkout, "checkout", "-q", "--detach", donor["commit"])
        head = _git(checkout, "rev-parse", "HEAD").strip()
        if head != donor["commit"]:
            raise TaskpackError(f"checked out {head}, not {donor['commit']}")
        into.mkdir(parents=True)
        shutil.copytree(checkout / donor["path"], into, dirs_exist_ok=True)
        shutil.copyfile(checkout / donor["license_path"], into / "LICENSE")
    finally:
        shutil.rmtree(checkout, ignore_errors=True)
    try:
        verify(lock, into)
    except TaskpackError:
        shutil.rmtree(into, ignore_errors=True)
        raise
    return into
