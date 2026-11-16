// SG-000119 slice A4: what each part of the window says, as plain node trees
// (dom.ts draws them with textContent only). Pure functions of the shell's
// sanitised answers: status, capabilities with their unavailable reasons,
// the device list (shown unavailable: orceld reserves devices.list and
// serves no device source), report tasks as metadata (never a title), the
// live timeline, and "path withheld" / "n fields withheld" wherever the
// sanitiser withheld something. Nothing here describes an approval, a
// control that acts, or a way to open a path.

import { h, type Node } from "./dom.js";
import {
  INCOMPATIBLE,
  MAX_CAPABILITIES,
  MAX_SOURCES,
  MAX_STEPS,
  MAX_TASKS,
  MAX_TIMELINE_ROWS,
  PATH_WITHHELD,
  bounded,
  bytesOf,
  count,
  durationOf,
  fieldText,
  hashOf,
  isRecord,
  numberOf,
  pathOf,
  plain,
  textOf,
  timeOf,
  unavailableText,
  withheldCount,
  words,
  type Capabilities,
  type Capability,
  type Check,
  type DocumentInfo,
  type FieldView,
  type Refusal,
  type Source,
  type Status,
  type Step,
  type TaskDetail,
  type TaskList,
  type TaskSummary,
  type ViewEvent,
} from "./model.js";
import type { Link } from "./timeline.js";

/** An answer as the page holds it. */
export type Answer<T> =
  | { state: "loading" }
  | { state: "ok"; value: T }
  | { state: "refused"; refusal: Refusal };

/** The class a field's value is drawn with: withheld and unexpected differ. */
function toneOf(value: FieldView): { class: string } | null {
  if (value.withheld) return { class: "withheld" };
  if (value.unexpected) return { class: "unexpected" };
  return null;
}

function row(term: string, value: FieldView): Node[] {
  return [h("dt", null, term), h("dd", toneOf(value), value.text)];
}

function note(text: string): Node {
  return h("p", { class: "note" }, text);
}

function withheldNote(value: unknown): Node[] {
  const text = withheldCount(value);
  return text ? [h("p", { class: "withheld" }, text)] : [];
}

function refusalNode(refusal: Refusal): Node {
  // INCOMPATIBLE is already a full sentence that names its state.
  const text = refusal.kind === "incompatible" ? refusal.text : `Unavailable: ${refusal.text}.`;
  return h("p", { class: "refusal", role: "note" }, text);
}

function loading(): Node {
  return note("Reading from orceld\u2026");
}

// ---------------------------------------------------------------------------
// Connection

/** The one-line connection state at the top of the window. */
export function connectionText(link: Link, hasCore: boolean): string {
  if (!hasCore) return "Not connected: this page runs only inside the Orcel Control Room shell.";
  switch (link.state) {
    case "connecting":
      return "Connecting to orceld\u2026";
    case "live":
      return "Connected to orceld. Live events are arriving.";
    case "unavailable":
      return `Unavailable: ${unavailableText(link.reason)}. This window keeps trying and shows orceld again when it returns.`;
    case "not_yours":
      return "Unavailable: orceld could not be confirmed as yours; nothing was sent to it.";
    case "incompatible":
      return INCOMPATIBLE;
    case "ended":
      return "Live events ended. Reopen the window to follow orceld again.";
  }
}

// ---------------------------------------------------------------------------
// Status

export function statusNodes(answer: Answer<Status>, link: Link): Node[] {
  if (link.state === "unavailable" || link.state === "not_yours") {
    return [note("orceld is unavailable, so no status is shown. The last reported values return when orceld does.")];
  }
  if (answer.state === "loading") return [loading()];
  if (answer.state === "refused") return [refusalNode(answer.refusal)];
  const status = answer.value;
  const text = (field: unknown) => fieldText<string>(field, textOf);
  const events = fieldText<Record<string, unknown>>(status.events, (value) =>
    isRecord(value)
      ? `epoch ${plain(value.epoch)}, sequence ${numberOf(value.oldest_seq)} to ${numberOf(value.head_seq)}, ring of ${numberOf(value.ring_capacity)}`
      : "",
  );
  const clients = fieldText<Record<string, unknown>>(status.clients, (value) =>
    isRecord(value) ? `${numberOf(value.active)} of ${numberOf(value.max)}` : "",
  );
  const wait = fieldText<Record<string, unknown>>(status.endpoint_wait, (value) =>
    isRecord(value) ? `since ${timeOf(value.since_ms)}, ${numberOf(value.attempts)} attempts` : "",
  );
  return [
    h("dl", { class: "facts" }, [
      ...row("Daemon", text(status.name)),
      ...row("Version", text(status.version)),
      ...row("App API", text(status.app_api)),
      ...row("Internal protocol", text(status.internal_protocol_version)),
      ...row("System", {
        text: [text(status.os).text, text(status.arch).text].join(" / "),
        withheld: text(status.os).withheld || text(status.arch).withheld,
        unexpected: text(status.os).unexpected === true || text(status.arch).unexpected === true,
      }),
      ...row("Mode", text(status.mode)),
      ...row("Policy revision", text(status.policy_revision)),
      ...row("Started", fieldText(status.started_at_ms, timeOf)),
      ...row("Uptime", fieldText(status.uptime_ms, durationOf)),
      ...row("Events", events),
      ...row("Clients", clients),
      ...(isRecord(status.endpoint_wait) && status.endpoint_wait.state !== "absent"
        ? row("Waited for its endpoint", wait)
        : []),
    ]),
    ...withheldNote(status.withheld),
  ];
}

// ---------------------------------------------------------------------------
// Capabilities and devices

export function capabilityNodes(answer: Answer<Capabilities>, link: Link): Node[] {
  if (link.state === "unavailable" || link.state === "not_yours") {
    return [note("orceld is unavailable, so no capabilities are shown.")];
  }
  if (answer.state === "loading") return [loading()];
  if (answer.state === "refused") return [refusalNode(answer.refusal)];
  const rows = bounded<Capability>(answer.value.capabilities, MAX_CAPABILITIES).filter(isRecord);
  const body = rows.map((capability) => {
    const available = capability.state === "available";
    const reason = available ? "" : textOf(capability.reason ?? "") || "no reason given";
    return h("tr", null, [
      h("th", { scope: "row" }, [h("code", null, textOf(capability.id))]),
      h("td", { class: available ? "available" : "unavailable" }, available ? "Available" : "Unavailable"),
      h("td", null, reason),
    ]);
  });
  return [
    rows.length === 0
      ? note("orceld reported no capabilities.")
      : h("table", null, [
          h("caption", null, "What orceld can do on this device, as it reports it"),
          h("thead", null, [
            h("tr", null, [
              h("th", { scope: "col" }, "Capability"),
              h("th", { scope: "col" }, "State"),
              h("th", { scope: "col" }, "Reason when unavailable"),
            ]),
          ]),
          h("tbody", null, body),
        ]),
    ...withheldNote(answer.value.withheld),
  ];
}

/** The device list: orceld reserves devices.list and answers METHOD_UNAVAILABLE. */
export function deviceNodes(): Node[] {
  return [
    h("dl", { class: "facts" }, [
      h("dt", null, "Device list"),
      h("dd", { class: "unavailable" }, "Unavailable: orceld reserves devices.list and does not serve it yet (METHOD_UNAVAILABLE)."),
    ]),
  ];
}

// ---------------------------------------------------------------------------
// Report tasks

function taskLine(task: TaskSummary): string {
  return `owner: ${words(task.owner)}; updated ${fieldText(task.updated_at_ms, timeOf).text}`;
}

/** A summary per task (no title: tasks are shown by state, owner and time). */
export function taskSummaryNodes(task: TaskSummary): Node[] {
  return [
    h("span", { class: "task-state" }, words(task.state)),
    h("span", { class: "task-meta" }, `${words(task.kind)} task ${textOf(task.task_id)}`),
    h("span", { class: "task-time" }, taskLine(task)),
  ];
}

export function taskListNodes(answer: Answer<TaskList>, stale: boolean): { nodes: Node[]; tasks: TaskSummary[] } {
  if (answer.state === "loading") return { nodes: [loading()], tasks: [] };
  if (answer.state === "refused") return { nodes: [refusalNode(answer.refusal)], tasks: [] };
  const tasks = bounded<TaskSummary>(answer.value.tasks, MAX_TASKS).filter(
    (task) => isRecord(task) && typeof task.task_id === "string" && /^[A-Za-z0-9_-]{1,128}$/u.test(task.task_id),
  );
  const nodes: Node[] = [];
  if (stale) nodes.push(note("orceld is unavailable; these are the tasks it last reported."));
  if (tasks.length === 0) nodes.push(note("orceld reports no report tasks."));
  nodes.push(...withheldNote(answer.value.withheld));
  return { nodes, tasks };
}

function documentRows(term: string, field: unknown): Node[] {
  if (!isRecord(field) || field.state === "absent") return row(term, { text: "none yet", withheld: false });
  if (field.state === "withheld") return row(term, { text: PATH_WITHHELD, withheld: true });
  const doc = (field as { value: DocumentInfo }).value;
  if (!isRecord(doc)) return row(term, { text: PATH_WITHHELD, withheld: true });
  return [
    ...row(`${term} name`, fieldText(doc.name, pathOf, PATH_WITHHELD)),
    ...row(`${term} destination`, fieldText(doc.destination, pathOf, PATH_WITHHELD)),
    ...row(`${term} SHA-256`, fieldText(doc.sha256, hashOf)),
    ...row(`${term} size`, fieldText(doc.bytes, bytesOf)),
  ];
}

function checkRows(field: unknown): Node[] {
  if (!isRecord(field) || field.state !== "shown" || !isRecord(field.value)) {
    return row("Check", { text: isRecord(field) && field.state === "withheld" ? "withheld" : "none yet", withheld: isRecord(field) && field.state === "withheld" });
  }
  const check = field.value as unknown as Check;
  return [
    ...row("Checker", { text: textOf(check.checker), withheld: false }),
    ...row("Check passed", fieldText<boolean>(check.passed, (value) => (typeof value === "boolean" ? (value ? "yes" : "no") : ""))),
    ...row("Checked destination", fieldText(check.destination, pathOf, PATH_WITHHELD)),
    ...row("Checked size", fieldText(check.bytes, bytesOf)),
    ...row("Checked SHA-256", fieldText(check.sha256, hashOf)),
    ...row("Sources unchanged", fieldText(check.sources_unchanged, numberOf)),
    ...row("Figures confirmed", fieldText(check.figures_confirmed, numberOf)),
    ...row("Checked at", fieldText(check.checked_at_ms, timeOf)),
  ];
}

function cell(value: FieldView, code = false): Node {
  const attrs = toneOf(value);
  return code && attrs === null ? h("td", attrs, [h("code", null, value.text)]) : h("td", attrs, value.text);
}

/** One task's detail: metadata only, never content or a title. */
export function taskDetailNodes(answer: Answer<TaskDetail>): Node[] {
  if (answer.state === "loading") return [loading()];
  if (answer.state === "refused") return [refusalNode(answer.refusal)];
  const task = answer.value;
  const sources = bounded<Source>(task.sources, MAX_SOURCES).filter(isRecord);
  const steps = bounded<Step>(task.steps, MAX_STEPS).filter(isRecord);
  return [
    h("dl", { class: "facts" }, [
      ...row("Task", { text: textOf(task.task_id), withheld: false }),
      ...row("Workspace", { text: textOf(task.workspace_id), withheld: false }),
      ...row("Kind", { text: words(task.kind), withheld: false }),
      ...row("State", { text: words(task.state), withheld: false }),
      ...row("Owner", { text: words(task.owner), withheld: false }),
      ...row("Created", fieldText(task.created_at_ms, timeOf)),
      ...row("Updated", fieldText(task.updated_at_ms, timeOf)),
      ...row("Folder", fieldText(task.folder, pathOf, PATH_WITHHELD)),
      ...documentRows("Proposal", task.proposal),
      ...documentRows("Report", task.report),
      ...checkRows(task.check),
    ]),
    sources.length === 0
      ? note("No sources reported.")
      : h("table", null, [
          h("caption", null, "Sources (workspace-relative paths, hashes and sizes only)"),
          h("thead", null, [
            h("tr", null, [h("th", { scope: "col" }, "Path"), h("th", { scope: "col" }, "SHA-256"), h("th", { scope: "col" }, "Size")]),
          ]),
          h(
            "tbody",
            null,
            sources.map((source) =>
              h("tr", null, [
                cell(fieldText(source.path, pathOf, PATH_WITHHELD)),
                cell(fieldText(source.sha256, hashOf), true),
                cell(fieldText(source.bytes, bytesOf)),
              ]),
            ),
          ),
        ]),
    steps.length === 0
      ? note("No steps recorded.")
      : h("table", null, [
          h("caption", null, "Steps"),
          h("thead", null, [
            h("tr", null, [
              h("th", { scope: "col" }, "Step"),
              h("th", { scope: "col" }, "Kind"),
              h("th", { scope: "col" }, "Outcome"),
              h("th", { scope: "col" }, "At"),
            ]),
          ]),
          h(
            "tbody",
            null,
            steps.map((step) =>
              h("tr", null, [
                h("td", null, textOf(step.step_id)),
                h("td", null, words(step.kind)),
                h("td", null, words(step.outcome)),
                cell(fieldText(step.at_ms, timeOf)),
              ]),
            ),
          ),
        ]),
    ...withheldNote(task.withheld),
  ];
}

// ---------------------------------------------------------------------------
// Timeline

function field(event: ViewEvent, name: string): { text: string; withheld: boolean } {
  return fieldText<unknown>(event[name], textOf);
}

/** One event as a sentence. Unknown kinds never reach the page (the sanitiser drops them). */
export function describeEvent(event: ViewEvent): string {
  switch (event.kind) {
    case "daemon.started":
      return `orceld started (mode ${field(event, "mode").text})`;
    case "request.completed": {
      const capability = field(event, "capability").text;
      const operation = field(event, "operation").text;
      const ok = isRecord(event.ok) && event.ok.state === "shown" ? event.ok.value === true : null;
      const failure = field(event, "failure_code");
      const outcome = ok === true ? "succeeded" : ok === false ? `failed${failure.text !== "not reported" ? ` (${failure.text})` : ""}` : "ended";
      return `Request ${capability} / ${operation} ${outcome}`;
    }
    case "app_api.endpoint_in_use":
      return "orceld waited for its endpoint";
    case "task.updated":
      return `Report task run ${textOf(event.run_id)}, step ${textOf(event.step_id)}: ${words(event.state)} (${words(event.step)}: ${words(event.outcome)})`;
    case "withheld":
      return "Event too large, withheld";
    default:
      return "Event withheld";
  }
}

export function timelineNodes(
  timelineEvents: ViewEvent[],
  counts: { withheldEvents: number; gaps: number; outOfOrder: number; lastSnapshot: { reason: string; head_seq: number } | null },
): Node[] {
  const nodes: Node[] = [];
  if (counts.lastSnapshot) {
    nodes.push(
      note(
        counts.lastSnapshot.reason === "epoch"
          ? `orceld restarted; the view recovered from its snapshot at sequence ${counts.lastSnapshot.head_seq}.`
          : `Some events were no longer available; the view recovered from orceld's snapshot at sequence ${counts.lastSnapshot.head_seq}.`,
      ),
    );
  }
  if (counts.gaps > 0) nodes.push(note(`The event queue overflowed ${counts.gaps === 1 ? "once" : `${counts.gaps} times`}; missed events were read again.`));
  if (counts.withheldEvents > 0) {
    nodes.push(h("p", { class: "withheld" }, counts.withheldEvents === 1 ? "1 event withheld" : `${counts.withheldEvents} events withheld`));
  }
  if (counts.outOfOrder > 0) {
    nodes.push(h("p", { class: "withheld" }, `${counts.outOfOrder} out-of-order ${counts.outOfOrder === 1 ? "event" : "events"} withheld`));
  }
  const total = timelineEvents.length;
  if (total === 0) {
    nodes.push(note("No events yet."));
    return nodes;
  }
  const shown = timelineEvents.slice(-MAX_TIMELINE_ROWS).reverse();
  if (total > shown.length) nodes.push(note(`Showing the newest ${shown.length} of ${total} events.`));
  nodes.push(
    h(
      "ol",
      { class: "events", "aria-label": "Events, newest first" },
      shown.map((event) => {
        const withheld = withheldCount(event.withheld);
        return h("li", null, [
          h("span", { class: "event-time" }, timeOf(event.at_ms)),
          h("span", { class: "event-seq" }, `#${count(event.seq) ?? ""}`),
          h("span", { class: "event-text" }, describeEvent(event)),
          ...(withheld ? [h("span", { class: "withheld" }, withheld)] : []),
        ]);
      }),
    ),
  );
  return nodes;
}
