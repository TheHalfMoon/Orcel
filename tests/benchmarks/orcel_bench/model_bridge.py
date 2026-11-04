"""M4a: the harness-side bridge between the agent's model adapter and a model
server. One JSON request per line on stdin, one JSON reply per line on stdout.

Standard library only, and it runs as its own process (`python -I -B`), so the
process hosting the agent opens no socket. The address isn't configurable beyond
a port: it only ever speaks to 127.0.0.1, it uses no proxy, and `http.client`
follows no redirect. A status other than 200 is an error.
"""

from __future__ import annotations

import http.client
import json
import sys

PATH = "/v1/chat/completions"
#: The largest reply it will pass on, a little under the edge's frame limit.
MAX_REPLY_BYTES = 4 << 20
TIMEOUT_S = 600


def forward(port: int, body: bytes) -> dict:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=TIMEOUT_S)
    try:
        connection.request("POST", PATH, body, {"Content-Type": "application/json"})
        response = connection.getresponse()
        reply = response.read(MAX_REPLY_BYTES + 1)
    finally:
        connection.close()
    if response.status != 200:
        return {"ok": False, "error": f"the model server answered {response.status}"}
    if len(reply) > MAX_REPLY_BYTES:
        return {"ok": False, "error": "the model server's reply is too large"}
    try:
        return {"ok": True, "response": json.loads(reply)}
    except ValueError:
        return {"ok": False, "error": "the model server's reply is not JSON"}


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "--port" or not argv[1].isdecimal() or not 0 < int(argv[1]) < 65536:
        print("usage: model_bridge.py --port <1-65535>", file=sys.stderr)
        return 2
    port = int(argv[1])
    for line in sys.stdin.buffer:
        try:
            reply = forward(port, line.strip())
        except (OSError, http.client.HTTPException) as error:
            reply = {"ok": False, "error": f"the model server is unreachable: {type(error).__name__}"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
