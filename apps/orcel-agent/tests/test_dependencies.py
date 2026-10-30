"""SG-000129 slice 1: the admitted dependency set.

These tests run in the environment built from `requirements.lock` (CI sets
ORCEL_AGENT_DEPS=1 there, and then nothing here may skip). In the standard
library environment of the M1 job they skip, except the tracing-switch test,
which needs nothing installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.quiet import CLEARED_PREFIXES, TRACING_OFF, silence_tracing  # noqa: E402

DEPS = os.environ.get("ORCEL_AGENT_DEPS") == "1"
needs_deps = unittest.skipUnless(DEPS, "the locked dependency environment (ORCEL_AGENT_DEPS=1)")

#: Never installed: no MCP library (the M1 client is the only edge session),
#: no tokenizer download, no model provider, no community tool collection.
FORBIDDEN_DISTRIBUTIONS = (
    "mcp", "langchain-mcp-adapters", "tiktoken", "langchain-community", "langchain-openai",
    "langchain-anthropic", "langchain-ollama", "langchain-google-genai", "langchain-aws",
    "openai", "anthropic", "ollama", "transformers", "huggingface-hub",
)

#: What a run inside the agent's process must never do. Python raises these
#: audit events before acting, so a hook that raises stops the action itself:
#: creating a socket at all, connecting, sending (UDP needs no connect), name
#: and address lookups, binding, starting a process, and loading native code
#: or SQLite extensions.
DENIED_EVENTS = (
    "socket.__new__", "socket.connect", "socket.sendto", "socket.sendmsg", "socket.bind",
    "socket.getaddrinfo", "socket.getnameinfo", "socket.gethostbyname", "socket.gethostbyname_ex",
    "socket.gethostbyaddr", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
    "os.startfile", "ctypes.dlopen", "sqlite3.enable_load_extension", "sqlite3.load_extension",
)

# Runs in a fresh interpreter whose environment asks for tracing everywhere.
# The hook is installed before any import and records every attempt (with the
# first caller outside the socket module), even one a library swallows. The
# report is printed by the first atexit handler, so it runs last: after
# langsmith's own exit-time flush, which is when a tracer would send.
# argv: denied events, the agent root, the checkpoint file, and the mode
# ("agent" imports orcel_agent first; "control" does not).
PROBE = r"""
import atexit, json, sys
DENIED = set(json.loads(sys.argv[1]))
attempts = []
state = {}
def report():
    state["attempts"] = attempts
    sys.stdout.write("\nREPORT " + json.dumps(state) + "\n")
    sys.stdout.flush()
atexit.register(report)
def hook(event, args):
    if event in DENIED:
        frame = sys._getframe(1)
        while frame is not None and frame.f_code.co_filename.replace("\\", "/").endswith("/socket.py"):
            frame = frame.f_back
        detail = None
        if event == "socket.bind" and isinstance(args[1], tuple):
            detail = list(args[1])
        if event == "socket.__new__":
            detail = int(args[1])
        attempts.append({"event": event, "detail": detail,
                         "file": frame.f_code.co_filename.replace("\\", "/") if frame else "",
                         "function": frame.f_code.co_name if frame else ""})
        raise PermissionError("denied by the SG-000129 egress test: " + event)
sys.addaudithook(hook)
sys.path.insert(0, sys.argv[2])

if sys.argv[4] == "agent":
    import orcel_agent  # switches tracing off before LangChain is imported
import langchain, langchain_core, langgraph
from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langsmith.utils import tracing_is_enabled

model = GenericFakeChatModel(messages=iter([AIMessage(content="scripted reply")]))
def call(state):
    return {"messages": [model.invoke(state["messages"])]}

graph = StateGraph(MessagesState)
graph.add_node("call", call)
graph.add_edge(START, "call")
graph.add_edge("call", END)
import sqlite3
connection = sqlite3.connect(sys.argv[3], check_same_thread=False)
try:
    app = graph.compile(checkpointer=SqliteSaver(connection))
    result = app.invoke({"messages": [HumanMessage(content="hello")]}, {"configurable": {"thread_id": "t"}})
    state["reply"] = result["messages"][-1].content
finally:
    connection.close()
state["tracing"] = bool(tracing_is_enabled())
"""


def urllib3_ipv6_probe(attempt: dict) -> bool:
    """urllib3 decides at import whether IPv6 works by creating an AF_INET6
    socket and binding it to loopback port 0 (util/connection.py, _has_ipv6),
    catching any failure. Refused like everything else, it just concludes "no
    IPv6". It is the one tolerated attempt, matched exactly."""
    if not (attempt["file"].endswith("/urllib3/util/connection.py") and attempt["function"] == "_has_ipv6"):
        return False
    if attempt["event"] == "socket.__new__":
        return attempt["detail"] == int(socket.AF_INET6)
    return attempt["event"] == "socket.bind" and attempt["detail"] in (["::1", 0], ["127.0.0.1", 0])


def run_probe(mode: str) -> dict:
    # This process imported orcel_agent and so silenced its own environment;
    # the child starts from one that asks for tracing in every spelling, so
    # only the child's own import can switch it off.
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith(CLEARED_PREFIXES)}
    env.update({name: "true" for name in TRACING_OFF if name.startswith(("LANGSMITH_", "LANGCHAIN_"))})
    env.update({
        "LANGSMITH_API_KEY": "lsv2-test", "LANGSMITH_ENDPOINT": "http://example.invalid",
        "OTEL_SDK_DISABLED": "false", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://example.invalid",
    })
    with tempfile.TemporaryDirectory() as scratch:
        run = subprocess.run(
            [sys.executable, "-I", "-c", PROBE, json.dumps(DENIED_EVENTS), str(ROOT),
             str(Path(scratch) / "checkpoints.sqlite"), mode],
            capture_output=True, text=True, timeout=180, env=env,
        )
    lines = [line for line in run.stdout.splitlines() if line.startswith("REPORT ")]
    if len(lines) != 1:
        raise AssertionError(f"no report (exit {run.returncode}): {run.stderr[-3000:]}")
    report = json.loads(lines[0][len("REPORT "):])
    report["returncode"] = run.returncode
    report["stderr"] = run.stderr[-3000:]
    return report


class TracingSwitches(unittest.TestCase):
    def test_every_tracing_variable_is_cleared_and_the_switches_are_off(self) -> None:
        saved = dict(os.environ)
        try:
            os.environ.update({
                "LANGSMITH_TRACING": "true", "LANGCHAIN_TRACING_V2": "true", "LANGSMITH_API_KEY": "lsv2-test",
                "langsmith_endpoint": "http://example.invalid", "LANGCHAIN_PROJECT": "p",
                "OTEL_EXPORTER_OTLP_ENDPOINT": "http://example.invalid", "OTEL_SDK_DISABLED": "false",
            })
            silence_tracing()
            for name, value in os.environ.items():
                if name.upper().startswith(CLEARED_PREFIXES):
                    self.assertEqual(TRACING_OFF.get(name), value, name)
            for name, value in TRACING_OFF.items():
                self.assertEqual(os.environ[name], value, name)
        finally:
            os.environ.clear()
            os.environ.update(saved)


@needs_deps
class LockedEnvironment(unittest.TestCase):
    def test_the_installed_set_is_the_lock_and_every_license_is_admitted(self) -> None:
        run = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "licenses.py"), "--check"],
                             capture_output=True, text=True, timeout=120)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_forbidden_distributions_are_absent(self) -> None:
        for name in FORBIDDEN_DISTRIBUTIONS:
            with self.assertRaises(PackageNotFoundError, msg=name):
                version(name)

    def test_the_donor_notice_and_ledger(self) -> None:
        ledger = json.loads((ROOT / "third_party" / "PROVENANCE.json").read_text(encoding="utf-8"))
        notice = ROOT / ledger["donor"]["license_file"]
        # Byte for byte: .gitattributes keeps third_party/ free of line-ending
        # conversion on every checkout.
        self.assertEqual(hashlib.sha256(notice.read_bytes()).hexdigest(), ledger["donor"]["license_sha256"])
        self.assertTrue(notice.read_text(encoding="utf-8").startswith("MIT License"))
        pin = ledger["donor"]["commit"]
        listed = set()
        for entry in ledger["files"]:
            self.assertEqual(set(entry), {"source", "source_blob", "destination", "decision", "modifications"}, entry)
            self.assertRegex(entry["source_blob"], r"^[0-9a-f]{40}$")
            self.assertIn(entry["decision"], ("COPY", "ADAPT"))
            self.assertTrue(entry["modifications"], entry["destination"])
            destination = ROOT / entry["destination"]
            head = destination.read_text(encoding="utf-8")[:600]
            self.assertIn(entry["source"], head, entry["destination"])
            self.assertIn(pin, head, entry["destination"])
            listed.add(destination.resolve())
        # The other direction: every file that says it came from DeerFlow is
        # in the ledger.
        for path in sorted((ROOT / "orcel_agent").rglob("*.py")):
            if "bytedance/deer-flow" in path.read_text(encoding="utf-8"):
                self.assertIn(path.resolve(), listed, f"{path.name} names DeerFlow but is not in the ledger")

    def test_langsmith_imported_first_is_refused(self) -> None:
        run = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                              "import langsmith; import orcel_agent", str(ROOT)],
                             capture_output=True, text=True, timeout=120)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("TracingAlreadyImported", run.stderr)


@needs_deps
class Egress(unittest.TestCase):
    def test_the_probe_detects_tracing_egress_when_it_is_not_switched_off(self) -> None:
        # Negative control: without the agent's import, the same environment
        # turns tracing on and langsmith tries to reach its endpoint; the hook
        # must see it. If this stops failing over, the egress test is blind.
        report = run_probe("control")
        self.assertTrue(report.get("tracing"), report)
        # langsmith's sender reaches its endpoint through urllib3, whose
        # create_connection resolves the host first: that lookup must be seen.
        outbound = [a for a in report["attempts"] if a["event"] in ("socket.getaddrinfo", "socket.connect")
                    and a["file"].endswith("/urllib3/util/connection.py") and a["function"] == "create_connection"]
        self.assertTrue(outbound, f"tracing was on but no outbound attempt was recorded: {report['attempts']}")

    def test_importing_and_running_a_scripted_graph_makes_no_connection(self) -> None:
        report = run_probe("agent")
        self.assertEqual(report["returncode"], 0, report["stderr"])
        others = [a for a in report["attempts"] if not urllib3_ipv6_probe(a)]
        self.assertEqual(others, [], "a socket, connection, lookup, send, process or native load was attempted")
        self.assertEqual(report["reply"], "scripted reply")
        self.assertFalse(report["tracing"], "tracing stayed on")


@unittest.skipUnless(os.environ.get("ORCEL_AGENT_NETNS") == "1", "the Linux network-namespace leg")
class NetworkNamespace(unittest.TestCase):
    """Runs inside `sudo unshare -n` after `setpriv` drops back to the runner.
    The namespace blocks egress the audit hooks cannot see (C code that
    swallows its own error); it does not detect it."""

    def test_not_root_and_no_route(self) -> None:
        self.assertNotEqual(os.geteuid(), 0, "the tests must not run as root")
        self.assertEqual(sorted(name for _, name in socket.if_nameindex()), ["lo"])
        with self.assertRaises(OSError):
            socket.create_connection(("192.0.2.1", 53), timeout=3)


if __name__ == "__main__":
    unittest.main()
