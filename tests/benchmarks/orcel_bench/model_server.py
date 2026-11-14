"""M4a: the pinned model server for `model-run`, started by the harness, never by
the agent (`prep/M4-selection-package.md`, founder decision 3 of 2026-11-14).

Nothing here downloads anything. The two files are already on the machine and
are named by the person running the benchmark. Before every start:

- both files are hashed again, and a size or SHA-256 that isn't the pinned one
  refuses the run;
- the runner zip is read once into memory and hashed from those bytes, so the
  file can't change between the check and the extraction;
- its members are extracted into a fresh private temporary folder outside the
  repository (no absolute paths, no `..`), and every extracted file, including
  `llama-server.exe`, is checked against the verified zip's own bytes;
- `llama-server` is started on 127.0.0.1 only, on a free port, with the weights
  as a local file, no download or remote option, and an environment holding
  nothing but what Windows needs (so no `LLAMA_ARG_*` or proxy variable reaches
  it).

The server is always stopped and the extracted folder always removed afterwards,
even on failure.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Optional

from .model_memory import process_peak_bytes


@dataclass(frozen=True)
class Pin:
    """One file, by name, size and SHA-256."""

    file: str
    size: int
    sha256: str


#: Founder decision 3: exactly these two files, each verified before use.
WEIGHTS = Pin("Qwen3.5-4B-Q4_K_M.gguf", 2_740_937_888,
              "00fe7986ff5f6b463e62455821146049db6f9313603938a70800d1fb69ef11a4")
RUNNER = Pin("llama-b11567-bin-win-cpu-x64.zip", 19_502_550,
             "7039609f175cfa5427d085f6e986e4119ab62d552abd1386f4909bca48ac0cc5")
RUNNER_VERSION = "llama.cpp b11567 (win-cpu-x64)"
#: The repository and revision the weights were taken from: a third-party (Unsloth)
#: conversion of `Qwen/Qwen3.5-4B` @ 851bf6e806efd8d0a36b00ddf55e13ccb7b8cd0a.
MODEL_LABEL = "model:unsloth/Qwen3.5-4B-GGUF@e87f176479d0855a907a41277aca2f8ee7a09523"
SERVER_EXE = "llama-server.exe"
#: The package's working assumption: a 32k context.
CONTEXT = 32768
#: The reference machine has 8 cores (4 performance, 4 efficient, 12 threads).
THREADS = 8
#: The extracted runner is a few dozen files; anything far larger isn't it.
MAX_EXTRACTED_BYTES = 256 << 20
HEALTH_TIMEOUT_S = 600.0
STOP_TIMEOUT_S = 30.0
_CHUNK = 1 << 20


class PinError(RuntimeError):
    """A file isn't the pinned one, or the runner zip isn't safe to extract."""


class ServerError(RuntimeError):
    """The model server didn't start or didn't become healthy."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(path: Path, pin: Pin) -> None:
    """Refuses a file that isn't the pinned one: wrong name, size or SHA-256."""
    if path.name != pin.file:
        raise PinError(f"{path.name} is not the pinned file {pin.file}")
    if not path.is_file():
        raise PinError(f"{pin.file}: not a file")
    size = path.stat().st_size
    if size != pin.size:
        raise PinError(f"{pin.file}: {size} bytes, not the pinned {pin.size}")
    found = sha256_of(path)
    if found != pin.sha256:
        raise PinError(f"{pin.file}: SHA-256 {found}, not the pinned {pin.sha256}")


def verified_bytes(path: Path, pin: Pin) -> bytes:
    """The file's bytes, read once and checked from what was read."""
    if path.name != pin.file:
        raise PinError(f"{path.name} is not the pinned file {pin.file}")
    data = path.read_bytes()
    if len(data) != pin.size:
        raise PinError(f"{pin.file}: {len(data)} bytes, not the pinned {pin.size}")
    found = hashlib.sha256(data).hexdigest()
    if found != pin.sha256:
        raise PinError(f"{pin.file}: SHA-256 {found}, not the pinned {pin.sha256}")
    return data


def _member_path(name: str) -> PurePosixPath:
    """A zip member's relative path; anything that could land outside the folder
    is refused."""
    path = PurePosixPath(name.replace("\\", "/"))
    if not name or path.is_absolute() or ":" in name or any(part in ("", ".", "..") for part in path.parts):
        raise PinError(f"the runner zip has an unsafe member: {name!r}")
    return path


def extract_runner(data: bytes, into: Path) -> dict[str, str]:
    """Extracts the verified zip's files into `into` (which must be empty) and
    checks each written file against the zip's bytes. Returns {member: SHA-256}."""
    if any(into.iterdir()):
        raise PinError(f"{into} is not empty")
    hashes: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [info for info in archive.infolist() if not info.is_dir()]
        if sum(info.file_size for info in members) > MAX_EXTRACTED_BYTES:
            raise PinError("the runner zip expands to more than expected")
        for info in members:
            relative = _member_path(info.filename)
            target = into.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = archive.read(info)
            with target.open("xb") as handle:
                handle.write(content)
            expected = hashlib.sha256(content).hexdigest()
            if sha256_of(target) != expected:
                raise PinError(f"{relative} was not extracted intact")
            hashes[relative.as_posix()] = expected
    return hashes


def find_server(folder: Path, hashes: dict[str, str]) -> tuple[Path, str]:
    """The one `llama-server.exe` that came from the zip, and its SHA-256."""
    found = [name for name in hashes if PurePosixPath(name).name == SERVER_EXE]
    if len(found) != 1:
        raise PinError(f"the runner zip holds {len(found)} copies of {SERVER_EXE}, not one")
    path = folder.joinpath(*PurePosixPath(found[0]).parts)
    if sha256_of(path) != hashes[found[0]]:
        raise PinError(f"{SERVER_EXE} is not the one from the zip")
    return path, hashes[found[0]]


def free_port() -> int:
    """A port nothing on loopback holds right now."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def server_args(exe: Path, weights: Path, port: int, threads: int = THREADS, context: int = CONTEXT) -> list[str]:
    """The whole command line (flags as in b11567's `--help`). The weights are a
    local path; nothing names a remote model, a download or another host, and
    `--offline` stops any network access the runner would otherwise try. One
    slot, so one conversation's cache is kept between its steps, and no extra
    host-memory prompt cache (`--cache-ram 0`; its default is 8 GiB). Thinking
    is off (the package's rule). The web UI and the server's own agent tools
    stay off."""
    if not 0 < port < 65536:
        raise ValueError(f"not a port: {port}")
    return [str(exe),
            "--model", str(weights),
            "--host", "127.0.0.1", "--port", str(port),
            "--threads", str(threads), "--threads-batch", str(threads),
            "--ctx-size", str(context), "--parallel", "1", "--cache-ram", "0",
            "--jinja", "--reasoning", "off",
            "--no-webui", "--no-agent", "--offline"]


#: Arguments that must never appear: anything that fetches, reaches another
#: host, runs tools or writes prompts to disk.
FORBIDDEN_ARGS = ("--hf-repo", "-hf", "-hfr", "--hf-file", "-hff", "--hf-token", "-hft", "--model-url", "-mu",
                  "--hf-repo-draft", "-hfd", "-hfrd", "--spec-draft-hf", "--docker-repo", "-dr", "--rpc",
                  "--tools", "--tools-runtime", "--mcp-servers-config", "--mcp-servers-json", "--agent", "-ag",
                  "--ui-mcp-proxy", "--webui-mcp-proxy", "--log-prompts-dir", "--api-key", "--path")


def check_args(args: list[str]) -> None:
    """Refuses a command line that could reach beyond loopback or fetch a model."""
    if any(arg in FORBIDDEN_ARGS or arg.startswith(tuple(f"{flag}=" for flag in FORBIDDEN_ARGS)) for arg in args):
        raise ValueError("the server command names a remote model or download option")
    host = args[args.index("--host") + 1] if "--host" in args else None
    if host != "127.0.0.1":
        raise ValueError(f"the server must bind 127.0.0.1, not {host}")


def server_env(folder: Path) -> dict[str, str]:
    """Only what Windows needs to start a process and open a loopback socket;
    temporary files go to the private runner folder."""
    env = {key: os.environ[key] for key in ("SYSTEMROOT", "WINDIR") if key in os.environ}
    env["TEMP"] = env["TMP"] = str(folder)
    return env


def _health(port: int) -> Optional[int]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        response.read()
        return response.status
    except (OSError, http.client.HTTPException):
        return None
    finally:
        connection.close()


def remove_tree(folder: Path, attempts: int = 20) -> bool:
    """Removes the folder, retrying while Windows still holds a just-exited
    process's files."""
    for _ in range(attempts):
        shutil.rmtree(folder, ignore_errors=True)
        if not folder.exists():
            return True
        time.sleep(0.5)
    return not folder.exists()


class ModelServer:
    """`with ModelServer(weights, runner_zip) as server:` verifies, extracts,
    starts and waits for health; leaving the block reads the peak memory, stops
    the server and removes the extracted folder, whatever happened."""

    def __init__(self, weights: Path, runner_zip: Path, threads: int = THREADS, context: int = CONTEXT,
                 health_timeout_s: float = HEALTH_TIMEOUT_S) -> None:
        self.weights, self.runner_zip = weights.resolve(), runner_zip.resolve()
        self.threads, self.context, self.health_timeout_s = threads, context, health_timeout_s
        self.folder: Optional[Path] = None
        self.process: Optional[subprocess.Popen] = None
        self.port: Optional[int] = None
        self.server_sha256: Optional[str] = None
        self.peak_bytes: Optional[int] = None
        self.load_s: Optional[float] = None
        self.removed: Optional[bool] = None
        self._log: Any = None

    def provenance(self) -> dict[str, Any]:
        return {"label": MODEL_LABEL, "weights": WEIGHTS.file, "weights_sha256": WEIGHTS.sha256,
                "runner": RUNNER_VERSION, "runner_zip_sha256": RUNNER.sha256,
                "llama_server_sha256": self.server_sha256, "threads": self.threads, "context": self.context}

    def __enter__(self) -> "ModelServer":
        try:
            self.start()
        except BaseException:
            self.stop()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        self.stop()

    def start(self) -> None:
        verify(self.weights, WEIGHTS)
        data = verified_bytes(self.runner_zip, RUNNER)
        self.folder = Path(tempfile.mkdtemp(prefix="orcel-m4-runner-"))
        exe, self.server_sha256 = find_server(self.folder, extract_runner(data, self.folder))
        # Hashed again immediately before the start, as the decision asks.
        verify(self.weights, WEIGHTS)
        self.port = free_port()
        args = server_args(exe, self.weights, self.port, self.threads, self.context)
        check_args(args)
        self._log = (self.folder / "server.log").open("wb")
        started = time.perf_counter()
        self.process = subprocess.Popen(args, cwd=str(self.folder), env=server_env(self.folder),
                                        stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT)
        deadline = started + self.health_timeout_s
        while time.perf_counter() < deadline:
            if self.process.poll() is not None:
                raise ServerError(f"llama-server exited with {self.process.returncode}: {self.log_tail()}")
            if _health(self.port) == 200:
                self.load_s = round(time.perf_counter() - started, 3)
                return
            time.sleep(0.5)
        raise ServerError(f"llama-server was not healthy within {self.health_timeout_s} s: {self.log_tail()}")

    def log_tail(self, lines: int = 12) -> str:
        """The end of the server's own log, for a failure message. It holds load
        and error lines, not prompts."""
        if self.folder is None or not (self.folder / "server.log").is_file():
            return ""
        if self._log is not None:
            self._log.flush()
        text = (self.folder / "server.log").read_text(encoding="utf-8", errors="replace")
        return " | ".join(text.strip().splitlines()[-lines:])

    def read_peak(self) -> Optional[int]:
        """The server process's peak working set so far (a high-water mark)."""
        if self.process is not None and self.process.poll() is None:
            peak = process_peak_bytes(self.process.pid)
            if peak is not None:
                self.peak_bytes = max(peak, self.peak_bytes or 0)
        return self.peak_bytes

    def stop(self) -> None:
        try:
            if self.process is not None:
                self.read_peak()
                if self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(STOP_TIMEOUT_S)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(STOP_TIMEOUT_S)
        finally:
            if self._log is not None:
                self._log.close()
                self._log = None
            if self.folder is not None:
                self.removed = remove_tree(self.folder)
                if not self.removed:
                    print(f"model-run: could not remove {self.folder}", file=sys.stderr)
