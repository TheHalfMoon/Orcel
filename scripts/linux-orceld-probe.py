#!/usr/bin/env python3
"""XP-17 CI: one system.status request to orceld, over the user socket
(orceld.socket) or by running the binary with the request on stdin.

Usage:
  linux-orceld-probe.py socket <socket-path> <workspace-id>
  linux-orceld-probe.py exec <orceld-binary> <workspace-id>

Exits non-zero unless orceld answers ok with name "orceld" on Linux.
"""

import json
import socket
import subprocess
import sys


def request(workspace_id):
    return {
        "version": 1,
        "request_id": "xp17-probe",
        "client_session_id": "xp17-ci",
        "workspace_id": workspace_id,
        "capability": "system.status",
        "operation": "get",
        "target": None,
        "arguments": {},
    }


def over_socket(path, line):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(30)
        conn.connect(path)
        conn.sendall(line)
        data = b""
        while not data.endswith(b"\n"):
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    return data


def over_exec(binary, line):
    done = subprocess.run([binary], input=line, capture_output=True, timeout=30, check=False)
    sys.stderr.write(done.stderr.decode(errors="replace"))
    return done.stdout


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ("socket", "exec"):
        sys.exit(__doc__)
    mode, target, workspace_id = sys.argv[1:]
    line = (json.dumps(request(workspace_id)) + "\n").encode()
    raw = (over_socket if mode == "socket" else over_exec)(target, line)
    response = json.loads(raw.splitlines()[0])
    print(json.dumps(response, indent=1))
    result = response.get("result") or {}
    if not (response.get("ok") and result.get("name") == "orceld" and result.get("os") == "linux"):
        sys.exit("orceld did not answer system.status")


if __name__ == "__main__":
    main()
