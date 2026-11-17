"""W2-02: the Agent-S-derived orchestrator (task graph, subtask state
machine, reflection, unexpected-dialog recovery, completion verification).

Ten deterministic synthetic multi-window tasks run through the real Agent
gate against a fake orceld desktop tool layer and a scripted model: no model,
no provider, no network. The fake uses the real tool argument shapes of
apps/orcel-mcp/src/desktop.ts (window ids `uia-win-...`, element actions by
`element_id`, `tree_generation` and `control_type` from the latest tree
read) and the real result shapes of orceld's UIA provider. Every task
asserts what orceld was asked to do, not only what the planner claimed.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orcel_agent.agent import DESKTOP_OBSERVE_TOOLS, Agent, AgentStop  # noqa: E402
from orcel_agent.edge import ToolOutcome, ToolSpec  # noqa: E402
from orcel_agent.events import EventLog  # noqa: E402
from orcel_agent.journal import DispatchJournal  # noqa: E402
from orcel_agent.orchestrator import (  # noqa: E402
    OrchestratorConfig,
    TaskOrchestrator,
    call_model_formatted,
    parse_action,
)
from orcel_agent.planner import ToolCall  # noqa: E402
from orcel_agent.store import open_store  # noqa: E402
from orcel_agent.task_graph import Dag, GraphError, Node, parse_dag, topological_sort  # noqa: E402
from orcel_agent.verification import (  # noqa: E402
    DialogTree,
    ExpectedWindow,
    SuccessCheck,
    TreeElement,
    Window,
    describe_windows,
    element_value_equals,
    find_unexpected_dialogs,
    parse_dialog_tree,
    recovery_call_is_safe,
    window_absent,
    window_present,
)

RUN = "1" * 32
DIALOG = "#32770"


def W(name: str) -> str:
    """A window id in orceld's format, derived from a readable name."""
    return "uia-win-" + hashlib.sha256(f"w:{name}".encode()).hexdigest()[:16]


def E(window: str, name: str) -> str:
    """An element id in orceld's format, derived from readable names."""
    return "uia-el-" + hashlib.sha256(f"e:{window}/{name}".encode()).hexdigest()[:16]


# The real argument shapes (apps/orcel-mcp/src/desktop.ts).
_WS = {"workspace_id": {"type": "string"}}
_WINDOW = {"window_id": {"type": "string"}, "window_generation": {"type": "integer"}}
_ELEMENT = {"element_id": {"type": "string"}, "tree_generation": {"type": "integer"}, "control_type": {"type": "string"}}
SCHEMAS = {
    "desktop_window_list": {"type": "object", "properties": dict(_WS), "additionalProperties": False},
    "desktop_window_tree": {"type": "object", "properties": {**_WS, **_WINDOW, "max_depth": {"type": "integer"},
                                                             "max_nodes": {"type": "integer"},
                                                             "root_element_id": {"type": "string"},
                                                             "tree_generation": {"type": "integer"}},
                            "required": ["window_id", "window_generation"], "additionalProperties": False},
    "desktop_element_invoke": {"type": "object", "properties": {**_WS, **_ELEMENT},
                               "required": ["element_id", "tree_generation", "control_type"],
                               "additionalProperties": False},
    "desktop_element_set_value": {"type": "object", "properties": {**_WS, **_ELEMENT, "value": {"type": "string"}},
                                  "required": ["element_id", "tree_generation", "control_type", "value"],
                                  "additionalProperties": False},
    "desktop_window_action": {"type": "object", "properties": {**_WS, **_WINDOW, "action": {"type": "string"}},
                              "required": ["window_id", "window_generation", "action"], "additionalProperties": False},
}
MUTATING = {"desktop_element_invoke", "desktop_element_set_value", "desktop_window_action"}
Hook = Callable[["FakeDesktop", dict[str, Any]], Optional[ToolOutcome]]


class FakeDesktop:
    """A fake orceld desktop tool layer with orceld's identities: typed
    windows with generations, element ids issued by tree reads and bound to
    that read's tree_generation, a modal-dialog block and per-element hooks.
    It records every call it is asked to make (the approval broker is
    assumed to approve)."""

    def __init__(self) -> None:
        self.windows: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.hooks: dict[str, Hook] = {}
        self.tree_counter = 0

    def add(self, name: str, title: str, cls: str = "AppWindow", exe: str = "app.exe",
            elements: Optional[dict[str, tuple[str, str, str]]] = None, sticky: bool = False) -> None:
        """elements: short name -> (UIA name, value, control type)."""
        self.windows[name] = {
            "title": title, "class": cls, "exe": exe, "generation": 1, "sticky": sticky, "tree_generation": 0,
            "elements": {short: {"name": n, "value": v, "control_type": c}
                         for short, (n, v, c) in (elements or {}).items()},
        }
        self.order.append(name)

    def remove(self, name: str) -> None:
        self.windows.pop(name, None)
        self.order.remove(name)

    def value(self, window: str, element: str) -> str:
        return self.windows[window]["elements"][element]["value"]

    def gen(self, window: str) -> int:
        return self.windows[window]["tree_generation"]

    def ctype(self, window: str, element: str) -> str:
        return self.windows[window]["elements"][element]["control_type"]

    def mutations(self) -> list[tuple[str, dict[str, Any]]]:
        return [call for call in self.calls if call[0] in MUTATING]

    def list_tools(self) -> list[ToolSpec]:
        return [ToolSpec(name, schema, f"fake {name}") for name, schema in SCHEMAS.items()]

    def _by_window_id(self, arguments: dict[str, Any]) -> Optional[str]:
        for name in self.order:
            if W(name) == arguments.get("window_id") and self.windows[name]["generation"] == arguments.get("window_generation"):
                return name
        return None

    def _by_element_id(self, arguments: dict[str, Any]) -> Optional[tuple[str, str]]:
        for name in self.order:
            for short in self.windows[name]["elements"]:
                if E(name, short) == arguments.get("element_id"):
                    return name, short
        return None

    def _blocked(self, window: str) -> bool:
        dialogs = [n for n in self.order if self.windows[n]["class"] == DIALOG]
        return bool(dialogs) and window not in dialogs

    def call_tool(self, name: str, arguments: dict[str, Any], timeout_s: Optional[float] = None) -> ToolOutcome:
        self.calls.append((name, dict(arguments)))
        if name == "desktop_window_list":
            return ToolOutcome(True, {"schema": "uia", "windows": [
                {"process_id": "p-" + n, "process_generation": 1, "exe_name": self.windows[n]["exe"],
                 "window_id": W(n), "window_generation": self.windows[n]["generation"],
                 "title": self.windows[n]["title"], "class": self.windows[n]["class"]} for n in self.order],
                "window_count": len(self.order), "protected_omitted": 0})
        if name in ("desktop_window_tree", "desktop_window_action"):
            window = self._by_window_id(arguments)
            if window is None:
                return ToolOutcome(False, error_code="TARGET_STALE")
            record = self.windows[window]
            if name == "desktop_window_tree":
                self.tree_counter += 1
                record["tree_generation"] = self.tree_counter
                return ToolOutcome(True, {
                    "schema": "uia", "window_id": W(window), "window_generation": record["generation"],
                    "tree_generation": self.tree_counter, "root_element_id": None, "truncated": False,
                    "nodes": [{"element_id": E(window, short), "window_id": W(window), "control_type": e["control_type"],
                               "name": e["name"], "value": e["value"], "tree_generation": self.tree_counter, "depth": 1}
                              for short, e in record["elements"].items()]})
            if self._blocked(window):
                return ToolOutcome(False, error_code="TARGET_STALE")
            if arguments["action"] == "close" and not record["sticky"]:
                self.remove(window)
            return ToolOutcome(True, {"action": arguments["action"]})
        found = self._by_element_id(arguments)
        if found is None:
            return ToolOutcome(False, error_code="TARGET_STALE")
        window, short = found
        record = self.windows[window]
        element = record["elements"][short]
        if (record["tree_generation"] == 0 or arguments.get("tree_generation") != record["tree_generation"]
                or arguments.get("control_type") != element["control_type"]):
            return ToolOutcome(False, error_code="TARGET_STALE")
        if self._blocked(window):
            return ToolOutcome(False, error_code="TARGET_STALE")
        if name == "desktop_element_set_value":
            element["value"] = arguments["value"]
            return ToolOutcome(True, {"element_id": arguments["element_id"], "set": True})
        hook = self.hooks.get(arguments["element_id"])
        outcome = hook(self, arguments) if hook else None
        return outcome or ToolOutcome(True, {"element_id": arguments["element_id"], "invoked": True})


Reply = Union[str, Callable[[FakeDesktop], str]]


def act(tool: str, **arguments: Any) -> str:
    return "I will act.\n```json\n" + json.dumps({"tool": tool, "arguments": arguments}) + "\n```"


def tree(window: str) -> str:
    return act("desktop_window_tree", window_id=W(window), window_generation=1)


def invoke(window: str, element: str) -> Reply:
    # Resolved when the model is asked, from the latest tree read (as a real
    # model would copy the ids and generation it was shown).
    return lambda d: act("desktop_element_invoke", element_id=E(window, element), tree_generation=d.gen(window),
                         control_type=d.ctype(window, element))


def set_value(window: str, element: str, value: str) -> Reply:
    return lambda d: act("desktop_element_set_value", element_id=E(window, element), tree_generation=d.gen(window),
                         control_type=d.ctype(window, element), value=value)


def tree_check(window: str, name: str, value: str) -> SuccessCheck:
    return SuccessCheck("desktop_window_tree", {"window_id": W(window), "window_generation": 1},
                        element_value_equals(name, value, window_id=W(window)), f"{name} is {value}")


def list_check(predicate: Callable[[Any], bool], description: str) -> SuccessCheck:
    return SuccessCheck("desktop_window_list", {}, predicate, description)


class ScriptedModel:
    """A deterministic stand-in for any provider. The manager plans the
    subtasks not yet listed as completed; the translator turns numbered plan
    lines into a chained DAG; the worker replies from a queue per subtask."""

    def __init__(self, plan: Sequence[tuple[str, str]], worker: dict[str, list[Reply]],
                 replans: Optional[dict[str, list[tuple[str, str]]]] = None,
                 reflection: Sequence[str] = (), recovery: Sequence[Reply] = (), translator_faults: int = 0) -> None:
        self.plan = list(plan)
        self.worker = {name: list(replies) for name, replies in worker.items()}
        self.replans = replans or {}
        self.reflection = list(reflection)
        self.recovery = list(recovery)
        self.translator_faults = translator_faults
        self.desktop: Optional[FakeDesktop] = None
        self.roles: list[str] = []
        self.seen: list[tuple[str, str]] = []
        self.exhausted: list[str] = []

    def _resolve(self, reply: Reply) -> str:
        if callable(reply):
            assert self.desktop is not None
            return reply(self.desktop)
        return reply

    def complete(self, role: str, messages: Sequence[dict[str, str]]) -> str:
        self.roles.append(role)
        last = messages[-1]["content"]
        self.seen.append((role, last))
        if role == "manager":
            failed = re.search(r"The subtask (.+?) cannot be completed", last)
            if failed and failed.group(1) in self.replans:
                self.plan = self.replans.pop(failed.group(1))
            section = last.split("Successfully Completed Subtasks:", 1)[-1].split("Future Remaining Subtasks:", 1)[0]
            done = set(re.findall(r"\*\*(.+?)\*\*", section)) if "Successfully Completed" in last else set()
            remaining = [(n, i) for n, i in self.plan if n not in done]
            if not remaining:
                return "All subtasks are complete."
            return "\n".join(f"{k + 1}. {n}: {i}" for k, (n, i) in enumerate(remaining))
        if role == "dag_translator":
            # After format feedback the request is no longer the last message.
            plan = next(m["content"] for m in messages if m["content"].startswith("Instruction: ")).split("Plan: ", 1)[1]
            nodes = [{"name": m.group(1), "info": m.group(2)} for m in re.finditer(r"^\d+\. (.+?): (.*)$", plan, re.M)]
            edges = [[nodes[k], nodes[k + 1]] for k in range(len(nodes) - 1)]
            if self.translator_faults > 0 and len(nodes) > 1:
                self.translator_faults -= 1
                edges.append([nodes[-1], nodes[0]])  # a cycle
            return "<json>" + json.dumps({"dag": {"nodes": nodes, "edges": edges}}) + "</json>"
        if role == "worker":
            text = next(m["content"] for m in reversed(messages) if "Current subtask:" in m["content"])
            name = re.findall(r"Current subtask: (.*)", text)[-1]
            queue = self.worker.get(name, [])
            if not queue:
                self.exhausted.append(name)
                return "FAIL"
            return self._resolve(queue.pop(0))
        if role == "reflection":
            return self.reflection.pop(0) if self.reflection else "Case 2. Continue as planned."
        if role == "recovery":
            return self._resolve(self.recovery.pop(0)) if self.recovery else "FAIL"
        raise AssertionError(role)


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name) / "agent"

    def tearDown(self) -> None:
        self._dir.cleanup()

    def run_task(self, desktop: FakeDesktop, model: ScriptedModel, checks: Sequence[SuccessCheck] = (),
                 expected: Sequence[ExpectedWindow] = (), config: Optional[OrchestratorConfig] = None):
        model.desktop = desktop
        store = open_store(self.root, RUN)
        events = EventLog(RUN)
        agent = Agent(desktop, DispatchJournal(store.journal_path, store.check_capacity), events, store=store,
                      allowlist=frozenset(SCHEMAS), observation_tools=DESKTOP_OBSERVE_TOOLS,
                      max_steps=64, max_approval_requests=20)
        planner = TaskOrchestrator(model, checks, expected, config, events)
        result = agent.run("synthetic task", planner)
        # Every call orceld saw came through the Agent gate, and the gate
        # counted only real actions as approval-bearing.
        self.assertEqual(len(desktop.calls), len(result.steps))
        self.assertEqual(result.approval_requests, len(desktop.mutations()))
        self.assertEqual(model.exhausted, [], "the scripted worker ran out of replies")
        # No action orceld was asked for used a stale or foreign identity.
        self.assertFalse([s for s in result.steps if s.error_code == "TARGET_STALE" and s.call.tool in MUTATING])
        return result, planner, events

    def kinds(self, events: EventLog) -> list[str]:
        return [event["kind"] for event in events.events]

    def assertVerified(self, result: Any) -> None:
        self.assertEqual(result.outcome, "finished")
        self.assertIsNone(result.stop_reason)
        self.assertTrue(result.answer["verified"], result.answer)
        self.assertEqual(result.answer["failed"], [])

    def assertNotVerified(self, result: Any, reason: str) -> None:
        self.assertEqual(result.outcome, "finished")
        self.assertEqual(result.stop_reason, reason)
        self.assertFalse(result.answer["verified"], result.answer)


def touches(call: tuple[str, dict[str, Any]], window: str) -> bool:
    arguments = call[1]
    return arguments.get("window_id") == W(window) or arguments.get("element_id") == E(window, "cancel")


class SyntheticMultiWindowTasks(Harness):
    """The ten W2-02 tasks."""

    def test_01_two_windows_success_with_a_cyclic_plan_repaired(self) -> None:
        desktop = FakeDesktop()
        desktop.add("notepad", "Untitled - Notepad", exe="notepad.exe", elements={"edit": ("Text Editor", "", "Edit")})
        desktop.add("calc", "Calculator", exe="calc.exe",
                    elements={"7": ("Seven", "", "Button"), "display": ("Display", "0", "Text")})
        desktop.hooks[E("calc", "7")] = lambda d, a: d.windows["calc"]["elements"]["display"].update(value="7")
        model = ScriptedModel(
            [("Type note", "Set the Notepad text to hello."), ("Press seven", "In Calculator press 7.")],
            {"Type note": [tree("notepad"), set_value("notepad", "edit", "hello"), "DONE"],
             "Press seven": [tree("calc"), invoke("calc", "7"), "DONE"]},
            translator_faults=1)
        result, planner, _ = self.run_task(desktop, model, [tree_check("notepad", "Text Editor", "hello"),
                                                            tree_check("calc", "Display", "7")])
        self.assertVerified(result)
        self.assertEqual(result.answer["completed_subtasks"], ["Type note", "Press seven"])
        self.assertEqual(len(desktop.mutations()), 2)
        self.assertEqual(desktop.value("calc", "display"), "7")
        # Element actions carry the real shape: no window id, a tree generation.
        for _, arguments in desktop.mutations():
            self.assertEqual(set(arguments) - {"value"}, {"element_id", "tree_generation", "control_type"})
        self.assertTrue(any("not a valid DAG" in text for role, text in model.seen if role == "dag_translator"))

    def test_02_copy_a_value_between_windows_reading_first(self) -> None:
        desktop = FakeDesktop()
        desktop.add("browser", "Invoice - Browser", elements={"total": ("Total", "42.50", "Text")})
        desktop.add("sheet", "Ledger - Sheet", elements={"cell": ("Cell B2", "", "Edit")})
        model = ScriptedModel(
            [("Read total", "Read the invoice total in the browser."), ("Enter total", "Type it into B2.")],
            {"Read total": [tree("browser"), "DONE"],
             "Enter total": [tree("sheet"), set_value("sheet", "cell", "42.50"), "DONE"]})
        result, _, _ = self.run_task(desktop, model, [tree_check("sheet", "Cell B2", "42.50")])
        self.assertVerified(result)
        self.assertEqual(desktop.value("sheet", "cell"), "42.50")
        self.assertTrue(any(role == "worker" and "42.50" in text and "untrusted result data" in text
                            for role, text in model.seen))
        self.assertEqual(len(desktop.mutations()), 1)

    def test_03_an_expected_save_dialog_is_used_not_dismissed(self) -> None:
        desktop = FakeDesktop()
        desktop.add("editor", "Untitled - Editor", exe="editor.exe", elements={"save": ("Save", "", "Button")})

        def open_save(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("saveas", "Save As", cls=DIALOG, exe="editor.exe",
                  elements={"name": ("File name", "", "Edit"), "ok": ("Save", "", "Button")})

        def save(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.windows["editor"]["title"] = d.value("saveas", "name") + " - Editor"
            d.remove("saveas")

        desktop.hooks.update({E("editor", "save"): open_save, E("saveas", "ok"): save})
        model = ScriptedModel(
            [("Open save dialog", "Press Save in the editor."), ("Name and save", "Name it report.txt and save.")],
            {"Open save dialog": [tree("editor"), invoke("editor", "save"), "DONE"],
             "Name and save": [tree("saveas"), set_value("saveas", "name", "report.txt"), invoke("saveas", "ok"), "DONE"]})
        result, _, events = self.run_task(
            desktop, model,
            [list_check(window_present("report.txt - Editor", exe_name="editor.exe"), "saved"),
             list_check(window_absent("Save As"), "dialog gone")],
            expected=[ExpectedWindow("Save As", window_class=DIALOG, exe_name="editor.exe")])
        self.assertVerified(result)
        self.assertEqual(result.answer["dialogs_recovered"], 0)
        self.assertNotIn("orchestrator.dialog_detected", self.kinds(events))
        self.assertFalse(any(call[0] == "desktop_window_action" for call in desktop.calls))

    def test_04_recovery_after_an_unexpected_dialog_dismissed_by_the_model(self) -> None:
        desktop = FakeDesktop()
        desktop.add("mail", "Inbox - Mail", exe="mail.exe", elements={"compose": ("New message", "", "Button")})

        def compose(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("compose", "New Message - Mail", exe="mail.exe", elements={"to": ("To", "", "Edit")})
            d.add("upd", "Update available", cls=DIALOG, exe="updater.exe",
                  elements={"cancel": ("Cancel", "", "Button"), "install": ("Install now", "", "Button")})

        desktop.hooks.update({E("mail", "compose"): compose, E("upd", "cancel"): lambda d, a: d.remove("upd")})
        model = ScriptedModel(
            [("Compose", "Open a new message."), ("Address", "Set To to a@example.test.")],
            {"Compose": [tree("mail"), invoke("mail", "compose"), "DONE"],
             "Address": [tree("compose"), set_value("compose", "to", "a@example.test"), "DONE"]},
            recovery=[invoke("upd", "cancel")])
        result, _, events = self.run_task(desktop, model, [tree_check("compose", "To", "a@example.test"),
                                                           list_check(window_absent("Update available"), "no dialog")])
        self.assertVerified(result)
        self.assertEqual(result.answer["dialogs_recovered"], 1)
        # Recovery read the dialog's own tree, then invoked its Cancel element
        # with that read's tree generation, in the real argument shape.
        tree_index = desktop.calls.index(("desktop_window_tree", {"window_id": W("upd"), "window_generation": 1}))
        cancel = [i for i, c in enumerate(desktop.calls) if c[1].get("element_id") == E("upd", "cancel")]
        self.assertEqual(len(cancel), 1)
        self.assertGreater(cancel[0], tree_index)
        self.assertEqual(desktop.calls[cancel[0]][1], {"element_id": E("upd", "cancel"), "tree_generation": 2,
                                                       "control_type": "Button"})
        self.assertFalse(any(c[1].get("element_id") == E("upd", "install") for c in desktop.calls))
        kinds = self.kinds(events)
        self.assertLess(kinds.index("orchestrator.dialog_detected"), kinds.index("orchestrator.dialog_recovered"))
        # The recovery prompt showed the dialog's application text sanitised.
        prompt = next(text for role, text in model.seen if role == "recovery")
        self.assertIn("name='Cancel'", prompt)
        self.assertIn("tree_generation=2", prompt)

    def test_05_an_unsafe_recovery_is_refused_and_the_dialog_is_closed_instead(self) -> None:
        desktop = FakeDesktop()
        desktop.add("site", "News - Browser", elements={"read": ("Read more", "", "Hyperlink")})
        desktop.add("notes", "Notes", elements={"body": ("Body", "", "Edit")})

        def read_more(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("perm", "Allow notifications?", cls=DIALOG,
                  elements={"allow": ("Allow", "", "Button"), "block": ("Block", "", "Button")})

        desktop.hooks[E("site", "read")] = read_more
        model = ScriptedModel(
            [("Open article", "Press Read more."), ("Take note", "Write seen in Notes.")],
            {"Open article": [tree("site"), invoke("site", "read"), "DONE"],
             "Take note": [tree("notes"), set_value("notes", "body", "seen"), "DONE"]},
            recovery=[invoke("perm", "allow")])
        result, _, events = self.run_task(desktop, model, [tree_check("notes", "Body", "seen")])
        self.assertVerified(result)
        self.assertFalse(any(c[1].get("element_id") == E("perm", "allow") for c in desktop.calls), "Allow never pressed")
        self.assertIn(("desktop_window_action", {"window_id": W("perm"), "window_generation": 1, "action": "close"}),
                      desktop.calls)
        self.assertIn("orchestrator.dialog_recovery_refused", self.kinds(events))
        self.assertIn("orchestrator.dialog_fallback_close", self.kinds(events))

    def test_06_a_dialog_that_will_not_go_away_stops_the_run_unverified(self) -> None:
        desktop = FakeDesktop()
        desktop.add("app", "Report - Writer", elements={"print": ("Print", "", "Button")})
        desktop.add("other", "Notes", elements={"body": ("Body", "", "Edit")})

        def print_(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("err", "Printer error", cls=DIALOG, sticky=True, elements={"cancel": ("Cancel", "", "Button")})

        desktop.hooks[E("app", "print")] = print_
        model = ScriptedModel(
            [("Print", "Press Print."), ("Note", "Write printed in Notes.")],
            {"Print": [tree("app"), invoke("app", "print"), "DONE"],
             "Note": [tree("other"), set_value("other", "body", "printed"), "DONE"]},
            recovery=[invoke("err", "cancel")])
        result, _, _ = self.run_task(desktop, model, [tree_check("other", "Body", "printed")])
        self.assertNotVerified(result, "dialog_unrecovered")
        self.assertEqual(desktop.value("other", "body"), "", "no work continued behind the dialog")
        recovery_calls = [c for c in desktop.mutations() if touches(c, "err")]
        self.assertEqual(len(recovery_calls), 2)
        # Each attempt re-read the dialog's tree first: tree, act, tree, act.
        err_calls = [c[0] for c in desktop.calls if touches(c, "err")]
        self.assertEqual(err_calls, ["desktop_window_tree", "desktop_element_invoke",
                                     "desktop_window_tree", "desktop_window_action"])
        self.assertEqual(len(model.worker["Note"]), 3, "the next subtask never started")

    def test_07_a_refused_action_fails_the_subtask_and_the_replan_succeeds(self) -> None:
        desktop = FakeDesktop()
        desktop.add("files", "Downloads - Explorer", exe="explorer.exe",
                    elements={"open": ("Open", "", "Button"), "file": ("report.pdf", "", "ListItem")})
        desktop.add("mail", "Inbox - Mail")
        desktop.hooks[E("files", "open")] = lambda d, a: ToolOutcome(False, error_code="CAPABILITY_DENIED")
        desktop.hooks[E("files", "file")] = lambda d, a: d.add("viewer", "report.pdf - Viewer", exe="viewer.exe")
        model = ScriptedModel(
            [("Open via button", "Press Open.")],
            {"Open via button": [tree("files"), invoke("files", "open")],
             "Open via file": [tree("files"), invoke("files", "file"), "DONE"]},
            replans={"Open via button": [("Open via file", "Invoke report.pdf directly.")]})
        result, planner, events = self.run_task(
            desktop, model, [list_check(window_present("report.pdf - Viewer", exe_name="viewer.exe"), "open")])
        self.assertVerified(result)
        self.assertEqual(result.answer["completed_subtasks"], ["Open via file"])
        self.assertIn("orchestrator.subtask_failed", self.kinds(events))
        self.assertTrue(any(role == "manager" and "Open via button cannot be completed" in text
                            for role, text in model.seen))
        self.assertGreaterEqual(planner.replans, 2)

    def test_08_done_without_acting_is_a_hallucinated_success_and_is_rejected(self) -> None:
        desktop = FakeDesktop()
        desktop.add("settings", "Settings", elements={"dark": ("Dark mode", "Off", "CheckBox")})
        desktop.add("help", "Help - Browser")
        model = ScriptedModel([("Enable dark mode", "Turn Dark mode on.")], {"Enable dark mode": ["DONE", "DONE"]})
        result, planner, events = self.run_task(desktop, model, [tree_check("settings", "Dark mode", "On")])
        self.assertNotVerified(result, "unverified_completion")
        self.assertEqual(result.answer["rejected_claims"], 2)
        self.assertEqual(result.answer["failed"], ["Dark mode is On"])
        self.assertEqual(desktop.mutations(), [], "nothing was done, and nothing is reported as done")
        self.assertEqual(self.kinds(events).count("orchestrator.claim_rejected"), 2)
        self.assertNotIn("orchestrator.verified", self.kinds(events))

    def test_09_a_reflection_saying_complete_does_not_make_it_so(self) -> None:
        desktop = FakeDesktop()
        desktop.add("form", "Signup - Browser", elements={"submit": ("Submit", "", "Button")})
        desktop.add("mail", "Inbox - Mail")
        # Submit does nothing: no welcome page appears.
        model = ScriptedModel([("Submit form", "Press Submit.")],
                              {"Submit form": [tree("form"), invoke("form", "submit"), "DONE", "DONE"]},
                              reflection=["Case 2. Continue.", "Case 3. The task has been successfully completed."])
        result, planner, _ = self.run_task(desktop, model, [list_check(window_present("Welcome"), "welcome shown")])
        self.assertNotVerified(result, "unverified_completion")
        self.assertTrue(any(r.startswith("Case 3") for r in planner.reflections))
        self.assertTrue(any(role == "worker" and "advisory: Orcel verifies completion itself" in text
                            for role, text in model.seen))
        self.assertEqual(len(desktop.mutations()), 1, "the identical action was not replayed")

    def test_10_without_success_checks_a_finish_is_never_clean(self) -> None:
        desktop = FakeDesktop()
        desktop.add("a", "Draft - Writer", elements={"body": ("Body", "", "Edit")})
        desktop.add("b", "Notes", elements={"body": ("Body", "", "Edit")})
        model = ScriptedModel(
            [("Write draft", "Write hi in the draft."), ("Write note", "Write hi in Notes.")],
            {"Write draft": [tree("a"), set_value("a", "body", "hi"), "DONE"],
             "Write note": [tree("b"), set_value("b", "body", "hi"), "DONE"]})
        result, _, events = self.run_task(desktop, model)
        self.assertNotVerified(result, "completion_unverified")
        self.assertEqual(result.answer["completed_subtasks"], ["Write draft", "Write note"])
        self.assertEqual(len(desktop.mutations()), 2)
        self.assertIn("orchestrator.completion_claimed", self.kinds(events))


class TaskGraph(unittest.TestCase):
    def test_parse_dag_reads_tags_then_fences_and_refuses_junk(self) -> None:
        body = json.dumps({"dag": {"nodes": [{"name": "a", "info": "x"}], "edges": []}})
        self.assertEqual(parse_dag(f"<json>{body}</json>").nodes, (Node("a", "x"),))
        self.assertEqual(parse_dag(f"```json\n{body}\n```").nodes, (Node("a", "x"),))
        for junk in ("no json", "<json>{</json>", "<json>[]</json>", '<json>{"dag": {"nodes": [{"info": "x"}]}}</json>',
                     '<json>{"dag": {"nodes": [], "edges": [[{"name": "a"}]]}}</json>'):
            self.assertIsNone(parse_dag(junk), junk)
        many = json.dumps({"dag": {"nodes": [{"name": str(i), "info": ""} for i in range(17)], "edges": []}})
        self.assertIsNone(parse_dag(f"<json>{many}</json>"))
        self.assertEqual(parse_dag('<json>{"dag": {"nodes": [], "edges": []}}</json>').nodes, ())

    def test_topological_sort_orders_and_refuses_cycles_unknowns_and_duplicates(self) -> None:
        a, b, c = Node("a", ""), Node("b", ""), Node("c", "")
        self.assertEqual(topological_sort(Dag((c, b, a), ((a, b), (b, c)))), [a, b, c])
        for bad in (Dag((a, b), ((a, b), (b, a))), Dag((a,), ((a, b),)), Dag((a, Node("a", "y")), ())):
            with self.assertRaises(GraphError):
                topological_sort(bad)


class Primitives(unittest.TestCase):
    def test_parse_action_accepts_one_call_or_a_sentinel(self) -> None:
        self.assertEqual(parse_action(" DONE "), "DONE")
        self.assertEqual(parse_action(tree("w")), ToolCall("desktop_window_tree", {"window_id": W("w"), "window_generation": 1}))
        for bad in ("click it", "```json\n[1]\n```", '```json\n{"tool": "x", "extra": 1}\n```'):
            self.assertIsNone(parse_action(bad), bad)

    def test_formatted_calls_feed_back_and_give_up_after_three(self) -> None:
        class Bad:
            def __init__(self) -> None:
                self.messages: list[list[dict[str, str]]] = []

            def complete(self, role: str, messages: Sequence[dict[str, str]]) -> str:
                self.messages.append(list(messages))
                return "nonsense"

        bad = Bad()
        self.assertIsNone(call_model_formatted(bad, "worker", [{"role": "user", "content": "go"}],
                                               [lambda r: (False, "must be JSON")]))
        self.assertEqual(len(bad.messages), 3)
        self.assertIn("must be JSON", bad.messages[1][-1]["content"])
        self.assertIn("not formatted correctly", bad.messages[1][-1]["content"])

    def dialog_tree(self) -> tuple[Window, DialogTree]:
        dialog = Window(W("d"), 3, "Save changes?", DIALOG)
        elements = {E("d", n): TreeElement(E("d", n), label, "Button")
                    for n, label in (("cancel", "Cancel"), ("close", "Close"), ("dismiss", "Dismiss"), ("ok", "OK"),
                                     ("yes", "Yes"), ("no", "No"), ("skip", "Skip"), ("later", "Later"),
                                     ("notnow", "Not now"))}
        return dialog, DialogTree(W("d"), 7, elements)

    def test_recovery_may_only_close_or_cancel_never_confirm_or_discard(self) -> None:
        dialog, dtree = self.dialog_tree()

        def ok(tool: str, **a: Any) -> bool:
            return recovery_call_is_safe(tool, a, dialog, dtree)

        def press(name: str, **extra: Any) -> bool:
            arguments = {"element_id": E("d", name), "tree_generation": 7, "control_type": "Button", **extra}
            return ok("desktop_element_invoke", **arguments)

        self.assertTrue(ok("desktop_window_action", window_id=W("d"), window_generation=3, action="close"))
        for name in ("cancel", "close", "dismiss"):
            self.assertTrue(press(name), name)
        # "No" on "Save changes?" discards work; OK and Yes confirm.
        for name in ("ok", "yes", "no", "skip", "later", "notnow"):
            self.assertFalse(press(name), name)
        self.assertFalse(ok("desktop_window_action", window_id=W("d"), window_generation=2, action="close"))
        self.assertFalse(ok("desktop_window_action", window_id=W("d"), window_generation=3, action="maximize"))
        self.assertFalse(ok("desktop_window_action", window_id=W("main"), window_generation=3, action="close"))

    def test_recovery_invoke_is_bound_to_the_dialogs_own_latest_tree(self) -> None:
        dialog, dtree = self.dialog_tree()
        good = {"element_id": E("d", "cancel"), "tree_generation": 7, "control_type": "Button"}
        self.assertTrue(recovery_call_is_safe("desktop_element_invoke", good, dialog, dtree))
        with_ws = {**good, "workspace_id": "ws"}
        self.assertTrue(recovery_call_is_safe("desktop_element_invoke", with_ws, dialog, dtree, "ws"))
        # A workspace must be absent or the configured one.
        self.assertFalse(recovery_call_is_safe("desktop_element_invoke", with_ws, dialog, dtree, "other"))
        self.assertFalse(recovery_call_is_safe("desktop_element_invoke", with_ws, dialog, dtree))
        close = {"window_id": W("d"), "window_generation": 3, "action": "close"}
        self.assertTrue(recovery_call_is_safe("desktop_window_action", {**close, "workspace_id": "ws"}, dialog, None, "ws"))
        self.assertFalse(recovery_call_is_safe("desktop_window_action", {**close, "workspace_id": "x"}, dialog, None, "ws"))
        # Only a Button named Cancel, Close or Dismiss: a link or menu item
        # with that name is refused even when the call names its own type.
        link = TreeElement(E("d", "link"), "Cancel", "Hyperlink")
        linked = DialogTree(dtree.window_id, dtree.tree_generation, {**dtree.elements, link.element_id: link})
        self.assertFalse(recovery_call_is_safe("desktop_element_invoke", {
            "element_id": link.element_id, "tree_generation": 7, "control_type": "Hyperlink"}, dialog, linked))
        for bad in ({**good, "tree_generation": 6},                    # a stale tree
                    {**good, "control_type": "Edit"},                  # a different control type
                    {**good, "element_id": E("main", "cancel")},       # another window's element
                    {**good, "window_id": W("d")},                     # not the real argument shape
                    {"element_id": E("d", "cancel")}):                 # incomplete
            self.assertFalse(recovery_call_is_safe("desktop_element_invoke", bad, dialog, dtree), bad)
        self.assertFalse(recovery_call_is_safe("desktop_element_invoke", good, dialog, None))
        self.assertFalse(recovery_call_is_safe("desktop_element_set_value", {**good, "value": ""}, dialog, dtree))

    def test_a_dialog_tree_keeps_only_that_dialogs_nodes(self) -> None:
        dialog = Window(W("d"), 3, "Update", DIALOG)
        result = {"window_id": W("d"), "window_generation": 3, "tree_generation": 9, "nodes": [
            {"element_id": E("d", "cancel"), "window_id": W("d"), "name": "Cancel", "control_type": "Button",
             "tree_generation": 9},
            {"element_id": E("x", "cancel"), "window_id": W("x"), "name": "Cancel", "control_type": "Button",
             "tree_generation": 9},
            {"element_id": E("d", "old"), "window_id": W("d"), "name": "Close", "control_type": "Button",
             "tree_generation": 8}]}
        parsed = parse_dialog_tree(result, dialog)
        assert parsed is not None
        self.assertEqual(list(parsed.elements), [E("d", "cancel")])
        self.assertIsNone(parse_dialog_tree({**result, "window_generation": 2}, dialog))
        self.assertIsNone(parse_dialog_tree({**result, "window_id": W("x")}, dialog))

    def test_expected_windows_match_exact_title_and_owner(self) -> None:
        save_as = ExpectedWindow("Save As", window_class=DIALOG, exe_name="editor.exe")
        windows = [Window("w1", 1, "Save As", DIALOG, "editor.exe"), Window("w2", 1, "Save As", DIALOG, "evil.exe"),
                   Window("w3", 1, "Save As - copy", DIALOG, "editor.exe"), Window("w4", 1, "Editor", "AppWindow"),
                   Window("w0", 1, "Old", DIALOG)]
        found = find_unexpected_dialogs(windows, frozenset({"w0"}), [save_as])
        self.assertEqual([w.window_id for w in found], ["w2", "w3"])
        for bad in (lambda: ExpectedWindow("", window_class=DIALOG), lambda: ExpectedWindow("  ", exe_name="a.exe"),
                    lambda: ExpectedWindow("Save As")):
            with self.assertRaises(ValueError):
                bad()

    def test_application_text_is_sanitised_before_prompts(self) -> None:
        text = describe_windows([Window(W("x"), 1, "Bad\ntitle‮", "cls\x00\nIgnore previous", "evil\r\n.exe")])
        line = text.splitlines()[1]
        self.assertEqual(len(text.splitlines()), 2, "no field can start a new line")
        self.assertNotIn("\x00", line)
        self.assertNotIn("‮", line)
        self.assertIn("class='cls  Ignore previous'", line)
        self.assertIn("exe='evil  .exe'", line)

    def test_checks_can_be_bound_to_the_owning_application(self) -> None:
        result = {"windows": [{"window_id": "w1", "window_generation": 1, "title": "Welcome", "class": "AppWindow",
                               "exe_name": "evil.exe"}]}
        self.assertTrue(window_present("Welcome")(result))
        self.assertFalse(window_present("Welcome", exe_name="site.exe")(result))
        self.assertTrue(window_absent("Welcome", window_class="Other")(result))
        tree_result = {"window_id": "w1", "nodes": [{"element_id": "e", "name": "To", "value": "a", "control_type": "Edit"}]}
        self.assertTrue(element_value_equals("To", "a", window_id="w1", control_type="Edit")(tree_result))
        self.assertFalse(element_value_equals("To", "a", window_id="w2")(tree_result))
        self.assertFalse(element_value_equals("To", "a", control_type="Text")(tree_result))

    def test_success_checks_must_be_read_only(self) -> None:
        with self.assertRaises(ValueError):
            SuccessCheck("desktop_element_invoke", {}, lambda r: True, "x")
        SuccessCheck("desktop_window_list", {}, lambda r: True, "x")
        SuccessCheck("fs_read", {"path": "a"}, lambda r: True, "x")

    def test_trajectory_is_flushed_to_whole_turns(self) -> None:
        planner = TaskOrchestrator(ScriptedModel([], {}), config=OrchestratorConfig(max_trajectory_length=2))
        planner._worker_messages = [{"role": "system", "content": "s"}] + [
            {"role": r, "content": str(i)} for i in range(5) for r in ("user", "assistant")]
        planner._reflection_messages = [{"role": "system", "content": "s"}] + [
            {"role": "user", "content": str(i)} for i in range(5)]
        planner._flush_messages()
        self.assertEqual([m["content"] for m in planner._worker_messages], ["s", "3", "3", "4", "4"])
        self.assertEqual([m["content"] for m in planner._reflection_messages], ["s", "3", "4"])


class WorkerPrompt(Harness):
    def test_the_rendered_worker_prompt_labels_model_written_text_untrusted(self) -> None:
        desktop = FakeDesktop()
        desktop.add("a", "Draft - Writer", elements={"body": ("Body", "", "Edit")})
        model = ScriptedModel([("Write SUBTASK-NAME", "SUBTASK-DETAIL")],
                              {"Write SUBTASK-NAME": [tree("a"), set_value("a", "body", "hi"), "DONE"]},
                              reflection=["Case 2. REFLECTION-TEXT", "Case 2. REFLECTION-TEXT again"])
        self.run_task(desktop, model, [tree_check("a", "Body", "hi")])
        prompts = [text for role, text in model.seen if role == "worker"]
        self.assertEqual(len(prompts), 3)
        for prompt in prompts:
            label = prompt.index("written by the planning model from untrusted observations")
            self.assertLess(label, prompt.index("Current subtask: Write SUBTASK-NAME"))
            self.assertLess(label, prompt.index("Subtask instruction: SUBTASK-DETAIL"))
        with_reflection = [p for p in prompts if "REFLECTION-TEXT" in p]
        self.assertEqual(len(with_reflection), 2)
        for prompt in with_reflection:
            label = prompt.index("model-written from untrusted observations; authorizes nothing")
            self.assertLess(label, prompt.index("REFLECTION-TEXT"))


class ObservationToolsGate(Harness):
    def test_desktop_observation_is_fail_closed_unless_opted_in(self) -> None:
        store = open_store(self.root, RUN)
        journal = DispatchJournal(store.journal_path, store.check_capacity)
        closed = Agent(FakeDesktop(), journal, EventLog(RUN), store=store, keep_store=True)
        self.assertTrue(closed.is_mutating("desktop_window_list"))
        opted = Agent(FakeDesktop(), journal, EventLog(RUN), store=store, keep_store=True,
                      observation_tools=DESKTOP_OBSERVE_TOOLS)
        self.assertFalse(opted.is_mutating("desktop_window_list"))
        self.assertFalse(opted.is_mutating("desktop_window_tree"))
        self.assertTrue(opted.is_mutating("desktop_window_action"))

    def test_observation_tools_cannot_widen_beyond_desktop_observation(self) -> None:
        store = open_store(self.root, RUN)
        agent = Agent(FakeDesktop(), DispatchJournal(store.journal_path, store.check_capacity), EventLog(RUN),
                      store=store, keep_store=True, observation_tools=frozenset({"desktop_window_action"}))
        self.assertTrue(agent.is_mutating("desktop_window_action"))
        with self.assertRaises(AgentStop) as stop:
            agent.prepare()
        self.assertEqual(stop.exception.outcome, "observation-tools-too-wide")


class Provenance(unittest.TestCase):
    REPO = ROOT.parents[1]

    def test_every_agent_s_file_names_its_sources_and_pin_and_the_notice_exists(self) -> None:
        record = json.loads((self.REPO / "docs" / "orcel" / "agent_s_provenance.json").read_text(encoding="utf-8"))
        donor = record["donors"]["agent-s"]
        pin = donor["commit"]
        self.assertRegex(pin, r"^[0-9a-f]{40}$")
        notice = (self.REPO / donor["notice"]).read_text(encoding="utf-8")
        self.assertIn(pin, notice)
        self.assertIn("Apache License", notice)
        listed = set()
        for entry in record["files"]:
            self.assertEqual(entry["donor"], "agent-s")
            self.assertIn(entry["decision"], ("COPY", "ADAPT"))
            self.assertEqual(set(entry["source"]), set(entry["source_blobs"]))
            for blob in entry["source_blobs"].values():
                self.assertRegex(blob, r"^[0-9a-f]{40}$")
            header = ast.get_docstring(ast.parse((self.REPO / entry["path"]).read_text(encoding="utf-8"))) or ""
            self.assertIn(pin, header, entry["path"])
            self.assertIn("simular-ai/Agent-S", header, entry["path"])
            for source in entry["source"]:
                self.assertIn(source, header, f"{entry['path']} does not name {source}")
            listed.add((self.REPO / entry["path"]).resolve())
        # The other direction: a module that says it was adapted from Agent S
        # is in the record.
        for path in sorted((ROOT / "orcel_agent").rglob("*.py")):
            if "Adapted from simular-ai/Agent-S" in path.read_text(encoding="utf-8"):
                self.assertIn(path.resolve(), listed, path.name)


if __name__ == "__main__":
    unittest.main()
