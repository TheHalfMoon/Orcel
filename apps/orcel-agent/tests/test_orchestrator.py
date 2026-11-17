"""W2-02: the Agent-S-derived orchestrator (task graph, subtask state
machine, reflection, unexpected-dialog recovery, completion verification).

Ten deterministic synthetic multi-window tasks run through the real Agent
gate against a fake orceld desktop tool layer and a scripted model: no model,
no provider, no network. Every task asserts what orceld was asked to do,
not only what the planner claimed.
"""

from __future__ import annotations

import ast
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Optional, Sequence

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
    SuccessCheck,
    Window,
    element_value_equals,
    find_unexpected_dialogs,
    recovery_call_is_safe,
    window_absent,
    window_present,
)

RUN = "1" * 32
WINDOW = {"window_id": {"type": "string"}, "window_generation": {"type": "integer"}}
SCHEMAS = {
    "desktop_window_list": {"type": "object", "properties": {"workspace_id": {"type": "string"}},
                            "additionalProperties": False},
    "desktop_window_tree": {"type": "object", "properties": dict(WINDOW),
                            "required": ["window_id", "window_generation"], "additionalProperties": False},
    "desktop_element_invoke": {"type": "object", "properties": {**WINDOW, "element_id": {"type": "string"}},
                               "required": ["window_id", "window_generation", "element_id"],
                               "additionalProperties": False},
    "desktop_element_set_value": {"type": "object",
                                  "properties": {**WINDOW, "element_id": {"type": "string"}, "value": {"type": "string"}},
                                  "required": ["window_id", "window_generation", "element_id", "value"],
                                  "additionalProperties": False},
    "desktop_window_action": {"type": "object", "properties": {**WINDOW, "action": {"type": "string"}},
                              "required": ["window_id", "window_generation", "action"], "additionalProperties": False},
}
MUTATING = {"desktop_element_invoke", "desktop_element_set_value", "desktop_window_action"}
DIALOG = "#32770"


class FakeDesktop:
    """A fake orceld desktop tool layer: typed windows with generations,
    UIA-like elements, a modal-dialog block, and per-element hooks. It
    records every call it is asked to make (the approval broker is assumed
    to approve)."""

    def __init__(self) -> None:
        self.windows: dict[str, dict[str, Any]] = {}
        self.order: list[str] = []
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.hooks: dict[str, Callable[["FakeDesktop", dict[str, Any]], Optional[ToolOutcome]]] = {}

    def add(self, window_id: str, title: str, cls: str = "AppWindow", exe: str = "app.exe",
            elements: Optional[dict[str, tuple[str, str]]] = None, sticky: bool = False) -> None:
        self.windows[window_id] = {
            "title": title, "class": cls, "exe": exe, "generation": 1, "sticky": sticky,
            "elements": {eid: {"name": name, "value": value} for eid, (name, value) in (elements or {}).items()},
        }
        self.order.append(window_id)

    def remove(self, window_id: str) -> None:
        self.windows.pop(window_id, None)
        self.order.remove(window_id)

    def value(self, window_id: str, element_id: str) -> str:
        return self.windows[window_id]["elements"][element_id]["value"]

    def mutations(self) -> list[tuple[str, dict[str, Any]]]:
        return [call for call in self.calls if call[0] in MUTATING]

    def list_tools(self) -> list[ToolSpec]:
        return [ToolSpec(name, schema, f"fake {name}") for name, schema in SCHEMAS.items()]

    def _window(self, arguments: dict[str, Any]) -> Optional[dict[str, Any]]:
        window = self.windows.get(arguments.get("window_id", ""))
        if window is None or window["generation"] != arguments.get("window_generation"):
            return None
        return window

    def call_tool(self, name: str, arguments: dict[str, Any], timeout_s: Optional[float] = None) -> ToolOutcome:
        self.calls.append((name, dict(arguments)))
        if name == "desktop_window_list":
            return ToolOutcome(True, {"windows": [
                {"window_id": wid, "window_generation": w["generation"], "title": w["title"], "class": w["class"],
                 "exe_name": w["exe"], "process_id": "p-" + wid, "process_generation": 1}
                for wid, w in ((wid, self.windows[wid]) for wid in self.order)]})
        window = self._window(arguments)
        if window is None:
            return ToolOutcome(False, error_code="TARGET_STALE")
        if name == "desktop_window_tree":
            return ToolOutcome(True, {"window_id": arguments["window_id"], "elements": [
                {"element_id": eid, "name": e["name"], "value": e["value"]} for eid, e in window["elements"].items()]})
        # A modal dialog blocks actions on every other window.
        blocking = [wid for wid in self.order if self.windows[wid]["class"] == DIALOG]
        if blocking and arguments["window_id"] not in blocking:
            return ToolOutcome(False, error_code="TARGET_STALE")
        if name == "desktop_window_action":
            if arguments["action"] == "close" and not window["sticky"]:
                self.remove(arguments["window_id"])
            return ToolOutcome(True, {"action": arguments["action"]})
        element = window["elements"].get(arguments.get("element_id", ""))
        if element is None:
            return ToolOutcome(False, error_code="TARGET_STALE")
        if name == "desktop_element_set_value":
            element["value"] = arguments["value"]
            return ToolOutcome(True, {"set": True})
        hook = self.hooks.get(arguments["element_id"])
        outcome = hook(self, arguments) if hook else None
        return outcome or ToolOutcome(True, {"invoked": True})


def act(tool: str, **arguments: Any) -> str:
    return "I will act.\n```json\n" + json.dumps({"tool": tool, "arguments": arguments}) + "\n```"


def invoke(window_id: str, element_id: str) -> str:
    return act("desktop_element_invoke", window_id=window_id, window_generation=1, element_id=element_id)


def set_value(window_id: str, element_id: str, value: str) -> str:
    return act("desktop_element_set_value", window_id=window_id, window_generation=1, element_id=element_id, value=value)


def tree(window_id: str) -> str:
    return act("desktop_window_tree", window_id=window_id, window_generation=1)


def tree_check(window_id: str, name: str, value: str) -> SuccessCheck:
    return SuccessCheck("desktop_window_tree", {"window_id": window_id, "window_generation": 1},
                        element_value_equals(name, value), f"{name} is {value}")


def list_check(predicate: Callable[[Any], bool], description: str) -> SuccessCheck:
    return SuccessCheck("desktop_window_list", {}, predicate, description)


class ScriptedModel:
    """A deterministic stand-in for any provider. The manager plans the
    subtasks not yet listed as completed; the translator turns numbered plan
    lines into a chained DAG; the worker replies from a queue per subtask."""

    def __init__(self, plan: Sequence[tuple[str, str]], worker: dict[str, list[str]],
                 replans: Optional[dict[str, list[tuple[str, str]]]] = None,
                 reflection: Sequence[str] = (), recovery: Sequence[str] = (), translator_faults: int = 0) -> None:
        self.plan = list(plan)
        self.worker = {name: list(replies) for name, replies in worker.items()}
        self.replans = replans or {}
        self.reflection = list(reflection)
        self.recovery = list(recovery)
        self.translator_faults = translator_faults
        self.roles: list[str] = []
        self.seen: list[tuple[str, str]] = []
        self.exhausted: list[str] = []

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
            return queue.pop(0)
        if role == "reflection":
            return self.reflection.pop(0) if self.reflection else "Case 2. Continue as planned."
        if role == "recovery":
            return self.recovery.pop(0) if self.recovery else "FAIL"
        raise AssertionError(role)


class Harness(unittest.TestCase):
    def setUp(self) -> None:
        self._dir = tempfile.TemporaryDirectory()
        self.root = Path(self._dir.name) / "agent"

    def tearDown(self) -> None:
        self._dir.cleanup()

    def run_task(self, desktop: FakeDesktop, model: ScriptedModel, checks: Sequence[SuccessCheck] = (),
                 expected: Sequence[str] = (), config: Optional[OrchestratorConfig] = None):
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


class SyntheticMultiWindowTasks(Harness):
    """The ten W2-02 tasks."""

    def test_01_two_windows_success_with_a_cyclic_plan_repaired(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-notepad", "Untitled - Notepad", elements={"e-edit": ("Text Editor", "")})
        desktop.add("w-calc", "Calculator", elements={"e-7": ("Seven", ""), "e-display": ("Display", "0")})
        desktop.hooks["e-7"] = lambda d, a: d.windows["w-calc"]["elements"]["e-display"].update(value="7")
        model = ScriptedModel(
            [("Type note", "Set the Notepad text to hello."), ("Press seven", "In Calculator press 7.")],
            {"Type note": [set_value("w-notepad", "e-edit", "hello"), "DONE"],
             "Press seven": [invoke("w-calc", "e-7"), "DONE"]},
            translator_faults=1)
        result, planner, _ = self.run_task(desktop, model, [tree_check("w-notepad", "Text Editor", "hello"),
                                                            tree_check("w-calc", "Display", "7")])
        self.assertVerified(result)
        self.assertEqual(result.answer["completed_subtasks"], ["Type note", "Press seven"])
        self.assertEqual(len(desktop.mutations()), 2)
        self.assertEqual(desktop.value("w-calc", "e-display"), "7")
        # The cyclic graph was fed back once and the translator asked again.
        self.assertTrue(any("not a valid DAG" in text for role, text in model.seen if role == "dag_translator"))

    def test_02_copy_a_value_between_windows_reading_first(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-browser", "Invoice - Browser", elements={"e-total": ("Total", "42.50")})
        desktop.add("w-sheet", "Ledger - Sheet", elements={"e-cell": ("Cell B2", "")})
        model = ScriptedModel(
            [("Read total", "Read the invoice total in the browser."), ("Enter total", "Type it into B2.")],
            {"Read total": [tree("w-browser"), "DONE"], "Enter total": [set_value("w-sheet", "e-cell", "42.50"), "DONE"]})
        result, _, _ = self.run_task(desktop, model, [tree_check("w-sheet", "Cell B2", "42.50")])
        self.assertVerified(result)
        self.assertEqual(desktop.value("w-sheet", "e-cell"), "42.50")
        # The worker saw the read's real result (as untrusted data).
        self.assertTrue(any(role == "worker" and "42.50" in text and "untrusted result data" in text
                            for role, text in model.seen))
        self.assertEqual(len(desktop.mutations()), 1)

    def test_03_an_expected_save_dialog_is_used_not_dismissed(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-editor", "Untitled - Editor", elements={"e-save": ("Save", "")})

        def open_save(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("w-saveas", "Save As", cls=DIALOG, elements={"e-name": ("File name", ""), "e-ok": ("Save", "")})

        def save(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.windows["w-editor"]["title"] = d.value("w-saveas", "e-name") + " - Editor"
            d.remove("w-saveas")

        desktop.hooks.update({"e-save": open_save, "e-ok": save})
        model = ScriptedModel(
            [("Open save dialog", "Press Save in the editor."), ("Name and save", "Name it report.txt and save.")],
            {"Open save dialog": [invoke("w-editor", "e-save"), "DONE"],
             "Name and save": [set_value("w-saveas", "e-name", "report.txt"), invoke("w-saveas", "e-ok"), "DONE"]})
        result, _, events = self.run_task(desktop, model, [list_check(window_present("report.txt - Editor"), "saved"),
                                                           list_check(window_absent("Save As"), "dialog gone")],
                                          expected=["Save As"])
        self.assertVerified(result)
        self.assertEqual(result.answer["dialogs_recovered"], 0)
        self.assertNotIn("orchestrator.dialog_detected", self.kinds(events))
        self.assertFalse(any(call[0] == "desktop_window_action" for call in desktop.calls))

    def test_04_recovery_after_an_unexpected_dialog_dismissed_by_the_model(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-mail", "Inbox - Mail", elements={"e-compose": ("New message", "")})

        def compose(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("w-compose", "New Message - Mail", elements={"e-to": ("To", "")})
            d.add("w-upd", "Update available", cls=DIALOG, elements={"e-later": ("Later", ""), "e-install": ("Install now", "")})

        desktop.hooks.update({"e-compose": compose, "e-later": lambda d, a: d.remove("w-upd")})
        model = ScriptedModel(
            [("Compose", "Open a new message."), ("Address", "Set To to a@example.test.")],
            {"Compose": [invoke("w-mail", "e-compose"), "DONE"],
             "Address": [set_value("w-compose", "e-to", "a@example.test"), "DONE"]},
            recovery=[invoke("w-upd", "e-later")])
        result, _, events = self.run_task(desktop, model, [tree_check("w-compose", "To", "a@example.test"),
                                                           list_check(window_absent("Update available"), "no dialog")])
        self.assertVerified(result)
        self.assertEqual(result.answer["dialogs_recovered"], 1)
        self.assertIn(("desktop_element_invoke", {"window_id": "w-upd", "window_generation": 1, "element_id": "e-later"}),
                      desktop.calls)
        self.assertFalse(any(c[1].get("element_id") == "e-install" for c in desktop.calls))
        kinds = self.kinds(events)
        self.assertLess(kinds.index("orchestrator.dialog_detected"), kinds.index("orchestrator.dialog_recovered"))
        # Recovery read the dialog's own tree before acting.
        self.assertIn(("desktop_window_tree", {"window_id": "w-upd", "window_generation": 1}), desktop.calls)

    def test_05_an_unsafe_recovery_is_refused_and_the_dialog_is_closed_instead(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-site", "News - Browser", elements={"e-read": ("Read more", "")})
        desktop.add("w-notes", "Notes", elements={"e-body": ("Body", "")})

        def read_more(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("w-perm", "Allow notifications?", cls=DIALOG, elements={"e-allow": ("Allow", ""), "e-block": ("Block", "")})

        desktop.hooks["e-read"] = read_more
        model = ScriptedModel(
            [("Open article", "Press Read more."), ("Take note", "Write seen in Notes.")],
            {"Open article": [invoke("w-site", "e-read"), "DONE"], "Take note": [set_value("w-notes", "e-body", "seen"), "DONE"]},
            recovery=[invoke("w-perm", "e-allow")])
        result, _, events = self.run_task(desktop, model, [tree_check("w-notes", "Body", "seen")])
        self.assertVerified(result)
        self.assertFalse(any(c[1].get("element_id") == "e-allow" for c in desktop.calls), "Allow was never pressed")
        self.assertIn(("desktop_window_action", {"window_id": "w-perm", "window_generation": 1, "action": "close"}),
                      desktop.calls)
        self.assertIn("orchestrator.dialog_recovery_refused", self.kinds(events))
        self.assertIn("orchestrator.dialog_fallback_close", self.kinds(events))

    def test_06_a_dialog_that_will_not_go_away_stops_the_run_unverified(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-app", "Report - Writer", elements={"e-print": ("Print", "")})
        desktop.add("w-other", "Notes", elements={"e-body": ("Body", "")})

        def print_(d: FakeDesktop, a: dict[str, Any]) -> None:
            d.add("w-err", "Printer error", cls=DIALOG, sticky=True, elements={"e-cancel": ("Cancel", "")})

        desktop.hooks["e-print"] = print_
        model = ScriptedModel(
            [("Print", "Press Print."), ("Note", "Write printed in Notes.")],
            {"Print": [invoke("w-app", "e-print"), "DONE"], "Note": [set_value("w-other", "e-body", "printed"), "DONE"]},
            recovery=[invoke("w-err", "e-cancel")])
        result, _, _ = self.run_task(desktop, model, [tree_check("w-other", "Body", "printed")])
        self.assertNotVerified(result, "dialog_unrecovered")
        self.assertEqual(desktop.value("w-other", "e-body"), "", "no work continued behind the dialog")
        recovery_calls = [c for c in desktop.mutations() if c[1]["window_id"] == "w-err"]
        self.assertEqual(len(recovery_calls), 2)
        self.assertEqual(model.worker["Note"], [set_value("w-other", "e-body", "printed"), "DONE"])

    def test_07_a_refused_action_fails_the_subtask_and_the_replan_succeeds(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-files", "Downloads - Explorer", elements={"e-open": ("Open", ""), "e-file": ("report.pdf", "")})
        desktop.add("w-mail", "Inbox - Mail")
        desktop.hooks["e-open"] = lambda d, a: ToolOutcome(False, error_code="CAPABILITY_DENIED")
        desktop.hooks["e-file"] = lambda d, a: d.add("w-viewer", "report.pdf - Viewer")
        model = ScriptedModel(
            [("Open via button", "Press Open.")],
            {"Open via button": [invoke("w-files", "e-open")], "Open via file": [invoke("w-files", "e-file"), "DONE"]},
            replans={"Open via button": [("Open via file", "Invoke report.pdf directly.")]})
        result, planner, events = self.run_task(desktop, model, [list_check(window_present("report.pdf - Viewer"), "open")])
        self.assertVerified(result)
        self.assertEqual(result.answer["completed_subtasks"], ["Open via file"])
        self.assertIn("orchestrator.subtask_failed", self.kinds(events))
        self.assertTrue(any(role == "manager" and "Open via button cannot be completed" in text
                            for role, text in model.seen))
        self.assertGreaterEqual(planner.replans, 2)

    def test_08_done_without_acting_is_a_hallucinated_success_and_is_rejected(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-settings", "Settings", elements={"e-dark": ("Dark mode", "Off")})
        desktop.add("w-help", "Help - Browser")
        model = ScriptedModel([("Enable dark mode", "Turn Dark mode on.")], {"Enable dark mode": ["DONE", "DONE"]})
        result, planner, events = self.run_task(desktop, model, [tree_check("w-settings", "Dark mode", "On")])
        self.assertNotVerified(result, "unverified_completion")
        self.assertEqual(result.answer["rejected_claims"], 2)
        self.assertEqual(result.answer["failed"], ["Dark mode is On"])
        self.assertEqual(desktop.mutations(), [], "nothing was done, and nothing is reported as done")
        self.assertEqual(self.kinds(events).count("orchestrator.claim_rejected"), 2)
        self.assertNotIn("orchestrator.verified", self.kinds(events))

    def test_09_a_reflection_saying_complete_does_not_make_it_so(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-form", "Signup - Browser", elements={"e-submit": ("Submit", "")})
        desktop.add("w-mail", "Inbox - Mail")
        # Submit does nothing: no welcome page appears.
        model = ScriptedModel([("Submit form", "Press Submit.")],
                              {"Submit form": [invoke("w-form", "e-submit"), "DONE", "DONE"]},
                              reflection=["Case 3. The task has been successfully completed."])
        result, planner, _ = self.run_task(desktop, model, [list_check(window_present("Welcome"), "welcome shown")])
        self.assertNotVerified(result, "unverified_completion")
        self.assertTrue(any(r.startswith("Case 3") for r in planner.reflections))
        self.assertTrue(any(role == "worker" and "advisory: Orcel verifies completion itself" in text
                            for role, text in model.seen))
        self.assertEqual(len(desktop.mutations()), 1, "the identical action was not replayed")

    def test_10_without_success_checks_a_finish_is_never_clean(self) -> None:
        desktop = FakeDesktop()
        desktop.add("w-a", "Draft - Writer", elements={"e-body": ("Body", "")})
        desktop.add("w-b", "Notes", elements={"e-body": ("Body", "")})
        model = ScriptedModel(
            [("Write draft", "Write hi in the draft."), ("Write note", "Write hi in Notes.")],
            {"Write draft": [set_value("w-a", "e-body", "hi"), "DONE"], "Write note": [set_value("w-b", "e-body", "hi"), "DONE"]})
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
        self.assertEqual(parse_action(tree("w")), ToolCall("desktop_window_tree", {"window_id": "w", "window_generation": 1}))
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

    def test_recovery_calls_are_limited_to_closing_or_dismissing_the_dialog(self) -> None:
        dialog = Window("w-d", 3, "Update", "#32770")
        names = {"e-later": "Later", "e-ok": "OK", "e-yes": "Yes"}
        ok = lambda tool, **a: recovery_call_is_safe(tool, a, dialog, names)  # noqa: E731
        self.assertTrue(ok("desktop_window_action", window_id="w-d", window_generation=3, action="close"))
        self.assertTrue(ok("desktop_element_invoke", window_id="w-d", element_id="e-later"))
        self.assertFalse(ok("desktop_window_action", window_id="w-d", window_generation=2, action="close"))
        self.assertFalse(ok("desktop_window_action", window_id="w-d", window_generation=3, action="maximize"))
        self.assertFalse(ok("desktop_element_invoke", window_id="w-d", element_id="e-ok"))
        self.assertFalse(ok("desktop_element_invoke", window_id="w-d", element_id="e-yes"))
        self.assertFalse(ok("desktop_element_invoke", window_id="w-main", element_id="e-later"))
        self.assertFalse(ok("desktop_element_set_value", window_id="w-d", element_id="e-later"))

    def test_only_new_unexpected_dialog_class_windows_count(self) -> None:
        windows = [Window("w1", 1, "Save As", "#32770"), Window("w2", 1, "Error", "#32770"),
                   Window("w3", 1, "Editor", "AppWindow"), Window("w0", 1, "Old", "#32770")]
        found = find_unexpected_dialogs(windows, frozenset({"w0"}), ["save as"])
        self.assertEqual([w.window_id for w in found], ["w2"])

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
