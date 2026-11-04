"""M4a: a stand-in for the model server, so the runner's wiring can be checked
with no model. **It is a fixed script, not a model, and nothing it produces says
anything about a model.** Rows it drives are labelled `stub-no-model`, a label
`model_eval.evaluate` refuses.

    python -I -B model_stub.py <script.json>

Prints its port, then answers until killed. The script is a list of replies,
chosen by the number of tool results in the conversation. A reply is one of:
`{"tool", "args"}`, `{"tool", "raw_args"}` (unparsable arguments), `{"text"}`,
`{"status"}` or `{"oversize"}`. A request offering no tools is a summarizer call.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import TCPServer

PATH = "/v1/chat/completions"


def completion(reply: dict) -> dict:
    if "text" in reply:
        message = {"role": "assistant", "content": reply["text"]}
    else:
        # `raw_args` goes out as it is: a broken string, or an object rather than a string.
        arguments = reply["raw_args"] if "raw_args" in reply else json.dumps(reply.get("args", {}))
        message = {"role": "assistant", "content": "", "tool_calls": [
            {"id": "stub", "type": "function", "function": {"name": reply["tool"], "arguments": arguments}}]}
    return {"choices": [{"message": message, "finish_reason": "stop"}]}


class _Server(HTTPServer):
    def server_bind(self) -> None:
        # HTTPServer's own also looks up the host's name, which can stall on a
        # hosted Mac. Nothing here needs that name.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def serve(script: list[dict]) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            done = sum(1 for message in request["messages"] if message["role"] == "tool")
            reply = {"text": "Earlier results were read."} if not request.get("tools") \
                else script[min(done, len(script) - 1)]
            status = reply.get("status", 200) if self.path == PATH else 404
            body = b"x" * reply["oversize"] if "oversize" in reply else json.dumps(completion(reply)).encode() \
                if "status" not in reply else b"{}"
            self.send_response(status)
            if status in (301, 302):
                self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            pass

    return _Server(("127.0.0.1", 0), Handler)


def main(argv: list[str]) -> int:
    server = serve(json.loads(Path(argv[0]).read_text(encoding="utf-8")))
    print(server.server_address[1], flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
