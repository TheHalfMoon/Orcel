// SG-000119 A4: the view's rendering, over the compiled modules. Every value
// is plain text, bounded, and "path withheld" / "n fields withheld" appear
// where the sanitiser withheld something; the timeline uses the headless
// reducer's gap, duplicate and epoch rules.

import assert from "node:assert/strict";
import { test } from "node:test";

import type { Node } from "./dom.js";
import {
  INCOMPATIBLE,
  MAX_PATH_TEXT,
  MAX_TEXT,
  MAX_TIMELINE_ROWS,
  plain,
  refusalOf,
  textOf,
  UNEXPECTED,
  fieldText,
  unavailableText,
  words,
  type Capabilities,
  type Status,
  type TaskDetail,
  type TaskList,
} from "./model.js";
import {
  capabilityNodes,
  connectionText,
  deviceNodes,
  describeEvent,
  statusNodes,
  taskDetailNodes,
  taskListNodes,
  taskSummaryNodes,
  timelineNodes,
} from "./present.js";
import { apply, createTimeline, events, type Timeline } from "./timeline.js";

const live = { state: "live" } as const;
const EPOCH = "1a2b-18c3d4e5f6";
const NEXT_EPOCH = "2c3d-18c3d4e5f7";
const HASH = "a".repeat(64);

/** Every text in a node tree, in order. */
function texts(nodes: Node[]): string[] {
  return nodes.flatMap((node) => [...(node.text !== undefined ? [node.text] : []), ...texts(node.children ?? [])]);
}

function all(nodes: Node[]): Node[] {
  return nodes.flatMap((node) => [node, ...all(node.children ?? [])]);
}

const shown = <T>(value: T) => ({ state: "shown" as const, value });
const withheld = { state: "withheld" as const };
const absent = { state: "absent" as const };

function status(overrides: Partial<Status> = {}): Status {
  return {
    name: shown("orceld"),
    version: shown("0.9.0"),
    app_api: shown("orcel-app-api/1"),
    internal_protocol_version: shown("1"),
    os: shown("windows"),
    arch: shown("x86_64"),
    mode: shown("SG-000039_CLIPBOARD_WRITE"),
    policy_revision: shown("7"),
    started_at_ms: shown(1_763_000_000_000),
    uptime_ms: shown(3_723_000),
    events: shown({ epoch: EPOCH, head_seq: 12, oldest_seq: 1, ring_capacity: 1024 }),
    clients: shown({ active: 2, max: 8 }),
    endpoint_wait: absent,
    withheld: 0,
    ...overrides,
  };
}

function task(overrides: Partial<TaskDetail> = {}): TaskDetail {
  return {
    task_id: "rpt-2ccd856f3d0bd600ff06b6fc39dbc30f",
    workspace_id: "default",
    kind: "report",
    state: "proposed",
    owner: "this_session",
    created_at_ms: shown(1_763_000_000_000),
    updated_at_ms: shown(1_763_000_100_000),
    folder: shown("reports"),
    sources: [{ path: shown("data/q3.csv"), sha256: shown(HASH), bytes: shown(64) }],
    proposal: shown({ name: shown("q3.md"), destination: shown("reports/q3.md"), sha256: shown(HASH), bytes: shown(10) }),
    report: absent,
    check: absent,
    steps: [{ step_id: "s1", kind: "observe", outcome: "ok", at_ms: shown(1_763_000_000_000) }],
    withheld: 0,
    ...overrides,
  };
}

function event(seq: number, kind = "request.completed", epoch = EPOCH, extra: Record<string, unknown> = {}) {
  return {
    type: "event",
    event: {
      seq,
      epoch,
      at_ms: 1_763_000_000_000 + seq,
      kind,
      withheld: 0,
      capability: shown("files"),
      operation: shown("read"),
      ok: shown(true),
      failure_code: absent,
      ...extra,
    },
  };
}

function feed(items: unknown[], start: Timeline = createTimeline()): Timeline {
  return items.reduce<Timeline>((timeline, item) => apply(timeline, item).timeline, start);
}

test("plain text: control, format and separator characters replaced, then bounded", () => {
  assert.equal(plain("a\u0000b\u202Ec\u2066d\u200Be\u2028f\u0085g"), "a\uFFFDb\uFFFDc\uFFFDd\uFFFDe\uFFFDf\uFFFDg");
  assert.equal(plain("<b>bold</b> & <script>x()</script>"), "<b>bold</b> & <script>x()</script>");
  const long = "x".repeat(MAX_TEXT + 50);
  assert.equal(Array.from(plain(long)).length, MAX_TEXT);
  assert.ok(plain(long).endsWith("\u2026"));
  assert.equal(Array.from(plain("\u{1F600}".repeat(MAX_TEXT + 1))).length, MAX_TEXT);
  assert.equal(plain({ toString: () => "object" }), "");
  assert.equal(plain(Number.NaN), "");
});

test("status renders as text, withheld fields read 'withheld' and the count is shown", () => {
  const nodes = statusNodes(
    { state: "ok", value: status({ mode: withheld, policy_revision: absent, withheld: 3 }) },
    live,
  );
  const shownText = texts(nodes);
  assert.ok(shownText.includes("orcel-app-api/1"));
  assert.ok(shownText.includes("windows / x86_64"));
  assert.ok(shownText.includes("1 h 2 min 3 s"));
  assert.ok(shownText.includes(`epoch ${EPOCH}, sequence 1 to 12, ring of 1024`));
  assert.ok(shownText.includes("2 of 8"));
  assert.ok(shownText.includes("withheld"), "the withheld mode reads 'withheld'");
  assert.ok(shownText.includes("not reported"), "an absent field reads 'not reported'");
  assert.ok(shownText.includes("3 fields withheld"));
  assert.ok(!shownText.some((text) => text.includes("pid") || text.includes("endpoint")));
  const one = texts(statusNodes({ state: "ok", value: status({ withheld: 1 }) }, live));
  assert.ok(one.includes("1 field withheld"));
});

test("a shown value that formats to nothing reads 'not shown (unexpected value)', never 'withheld'", () => {
  assert.deepEqual(fieldText<string>(shown(""), textOf), { text: UNEXPECTED, withheld: false, unexpected: true });
  assert.deepEqual(fieldText<string>(shown({ x: 1 }), textOf), { text: UNEXPECTED, withheld: false, unexpected: true });
  assert.deepEqual(fieldText<string>(withheld, textOf), { text: "withheld", withheld: true });
  assert.deepEqual(fieldText<string>(withheld, textOf, "path withheld"), { text: "path withheld", withheld: true });
  assert.deepEqual(fieldText<string>(absent, textOf), { text: "not reported", withheld: false });

  // In the window: the unexpected values carry their own class, and nothing
  // reads "withheld" because nothing was withheld.
  const odd = statusNodes(
    { state: "ok", value: status({ version: shown(""), clients: shown("not a record") as unknown as Status["clients"] }) },
    live,
  );
  const unexpected = all(odd).filter((node) => node.text === UNEXPECTED);
  assert.equal(unexpected.length, 2);
  assert.ok(unexpected.every((node) => node.attrs?.class === "unexpected"));
  assert.ok(!texts(odd).includes("withheld"));
  assert.ok(!all(odd).some((node) => node.attrs?.class === "withheld"));

  // A withheld field is still drawn as withheld.
  const hidden = all(statusNodes({ state: "ok", value: status({ version: withheld }) }, live));
  assert.ok(hidden.some((node) => node.text === "withheld" && node.attrs?.class === "withheld"));
});

test("an incompatible orceld reads as one sentence, not 'Unavailable: Incompatible ...'", () => {
  const refusal = refusalOf({ error: "incompatible" });
  for (const nodes of [
    statusNodes({ state: "refused", refusal }, live),
    taskListNodes({ state: "refused", refusal }, false).nodes,
  ]) {
    const shownText = texts(nodes);
    assert.deepEqual(shownText, [INCOMPATIBLE]);
  }
  assert.equal(connectionText({ state: "incompatible" }, true), INCOMPATIBLE);
  const other = texts(statusNodes({ state: "refused", refusal: refusalOf({ error: "busy" }) }, live));
  assert.ok(other[0]?.startsWith("Unavailable: ") && other[0].endsWith("."), String(other[0]));
});

test("status says unavailable while orceld is, and never shows stale values as live", () => {
  const nodes = texts(statusNodes({ state: "ok", value: status() }, { state: "unavailable", reason: "not_running" }));
  assert.equal(nodes.length, 1);
  assert.match(nodes[0] as string, /orceld is unavailable/u);
  assert.ok(!nodes.includes("orcel-app-api/1"));
  assert.equal(
    connectionText({ state: "unavailable", reason: "not_running" }, true),
    "Unavailable: orceld is not running. This window keeps trying and shows orceld again when it returns.",
  );
  assert.equal(unavailableText("<script>"), "orceld is unavailable");
  assert.equal(unavailableText("toString"), "orceld is unavailable");
});

test("command refusals become fixed text; nothing of the refusal is echoed but a checked code", () => {
  assert.deepEqual(refusalOf({ error: "unavailable", reason: "timed_out" }), { kind: "unavailable", text: "orceld did not answer in time" });
  assert.equal(refusalOf({ error: "refused", code: "TASK_NOT_FOUND" }).text, "orceld refused the request (TASK_NOT_FOUND)");
  assert.equal(refusalOf({ error: "refused", code: "<img src=x>" }).text, "orceld refused the request");
  assert.equal(refusalOf("Command task_stop not allowed by ACL").text, "the shell refused the request");
  assert.equal(refusalOf({ error: "incompatible" }).kind, "incompatible");
  assert.equal(refusalOf({ error: "not_yours" }).kind, "not_yours");
});

test("capabilities show explicit unavailable reasons, bounded; the device list is unavailable", () => {
  const value: Capabilities = {
    os: shown("windows"),
    capabilities: [
      { id: "files.read", state: "available" },
      { id: "browser.observe", state: "unavailable", reason: "Edge 157 is not qualified\u202E" },
      { id: "clipboard.write", state: "unavailable", reason: null },
      ...Array.from({ length: 80 }, (_, i) => ({ id: `extra.${i}`, state: "available" as const })),
    ],
    withheld: 2,
  };
  const nodes = capabilityNodes({ state: "ok", value }, live);
  const shownText = texts(nodes);
  assert.ok(shownText.includes("Edge 157 is not qualified\uFFFD"));
  assert.ok(shownText.includes("no reason given"));
  assert.ok(shownText.includes("2 fields withheld"));
  assert.equal(all(nodes).filter((node) => node.tag === "tr").length, 64 + 1, "64 rows and the header");
  const devices = texts(deviceNodes());
  assert.ok(devices.some((text) => text.includes("devices.list") && text.startsWith("Unavailable")));
});

test("tasks are metadata only: no title, paths withheld as the sanitiser gives them", () => {
  const list: TaskList = {
    tasks: [
      { ...task(), title: "Q3 revenue for the board" } as unknown as TaskDetail,
      { ...task(), task_id: "../etc" },
    ],
    withheld: 4,
  };
  const { nodes, tasks } = taskListNodes({ state: "ok", value: list }, false);
  assert.equal(tasks.length, 1, "a task id outside the identifier rule is not listed");
  assert.ok(texts(nodes).includes("4 fields withheld"));
  const summary = texts(taskSummaryNodes(tasks[0]!));
  assert.ok(summary.includes("proposed"));
  assert.ok(!summary.join(" ").includes("Q3 revenue"));

  const detail = taskDetailNodes({
    state: "ok",
    value: task({
      folder: withheld,
      sources: [
        { path: withheld, sha256: withheld, bytes: shown(3) },
        { path: shown("data/q3.csv"), sha256: shown("not-a-hash"), bytes: absent },
      ],
      proposal: shown({ name: withheld, destination: shown("reports/q3.md"), sha256: shown(HASH), bytes: shown(10) }),
      report: withheld,
      withheld: 5,
      ...({ title: "Q3 revenue for the board" } as object),
    }),
  });
  const text = texts(detail);
  assert.ok(!text.join(" ").includes("Q3 revenue"), "no title");
  assert.equal(text.filter((t) => t === "path withheld").length, 4, "folder, source path, proposal name, report");
  assert.ok(text.includes("withheld"), "a withheld hash reads 'withheld'");
  assert.ok(text.includes("5 fields withheld"));
  assert.ok(text.includes("reports/q3.md"));
  assert.ok(text.includes(HASH));
});

test("long paths and texts are bounded; enums never echo unknown text", () => {
  const long = `data/${"d".repeat(2000)}.csv`;
  const text = texts(
    taskDetailNodes({ state: "ok", value: task({ folder: shown(long), steps: [{ step_id: "s1", kind: "other", outcome: "<b>x</b>", at_ms: absent }] }) }),
  );
  const folder = text.find((t) => t.startsWith("data/"));
  assert.equal(Array.from(folder ?? "").length, MAX_PATH_TEXT);
  assert.ok(text.includes("other"));
  assert.ok(!text.some((t) => t.includes("<b>")));
  assert.equal(words("approval_denied"), "approval denied");
  assert.equal(words("Not An Enum"), "other");
});

test("caps on tasks, sources and steps are applied again", () => {
  const many = Array.from({ length: 90 }, (_, i) => ({ ...task(), task_id: `t${i}` }));
  assert.equal(taskListNodes({ state: "ok", value: { tasks: many, withheld: 0 } }, false).tasks.length, 64);
  const detail = taskDetailNodes({
    state: "ok",
    value: task({
      sources: Array.from({ length: 70 }, () => ({ path: shown("a.csv"), sha256: shown(HASH), bytes: shown(1) })),
      steps: Array.from({ length: 40 }, (_, i) => ({ step_id: `s${i}`, kind: "observe", outcome: "ok", at_ms: absent })),
    }),
  });
  const tables = all(detail).filter((node) => node.tag === "tbody");
  assert.equal(tables[0]?.children?.length, 64);
  assert.equal(tables[1]?.children?.length, 32);
});

test("the timeline: events in order, duplicates ignored, a gap refused before the cursor moves", () => {
  let timeline = feed([event(1), event(2), event(2), event(3)]);
  assert.deepEqual(events(timeline).map((e) => e.seq), [1, 2, 3]);
  assert.equal(timeline.reducer.cursor, 3);
  assert.equal(timeline.link.state, "live");
  timeline = feed([event(5)], timeline);
  assert.equal(timeline.reducer.cursor, 3, "the gap did not move the cursor");
  assert.equal(timeline.outOfOrder, 1);
  timeline = feed([event(4), event(5)], timeline);
  assert.deepEqual(events(timeline).map((e) => e.seq), [1, 2, 3, 4, 5]);
  const foreign = feed([event(6, "request.completed", NEXT_EPOCH)], timeline);
  assert.deepEqual(events(foreign).map((e) => e.seq), [1, 2, 3, 4, 5], "an event of another epoch is ignored");
});

test("the timeline: a new epoch clears it and a snapshot resumes from its cursor", () => {
  let timeline = feed([event(1), event(2)]);
  timeline = feed([{ type: "unavailable", reason: "not_running" }], timeline);
  assert.equal(timeline.link.state, "unavailable");
  const cleared = apply(timeline, { type: "cleared" });
  assert.deepEqual(events(cleared.timeline), []);
  const snap = apply(cleared.timeline, {
    type: "event",
    event: {
      seq: 3,
      epoch: NEXT_EPOCH,
      at_ms: 1,
      kind: "snapshot",
      withheld: 0,
      reason: "epoch",
      head_seq: 3,
      oldest_seq: 1,
      status: shown(status()),
      resubscribe: { after_seq: 3, epoch: NEXT_EPOCH },
    },
  });
  assert.equal(snap.effects.refresh, true, "orceld came back: read everything again");
  assert.equal(snap.timeline.link.state, "live");
  assert.equal(snap.timeline.reducer.epoch, NEXT_EPOCH);
  assert.equal(snap.timeline.reducer.cursor, 3);
  assert.ok(snap.timeline.snapshotStatus);
  timeline = feed([event(4, "daemon.started", NEXT_EPOCH, { mode: shown("SG-000039_CLIPBOARD_WRITE") })], snap.timeline);
  assert.deepEqual(events(timeline).map((e) => e.seq), [4]);
  const text = texts(timelineNodes(events(timeline), timeline));
  assert.ok(text.some((t) => t.includes("orceld restarted; the view recovered from its snapshot at sequence 3")));
  assert.ok(text.includes("orceld started (mode SG-000039_CLIPBOARD_WRITE)"));
});

test("the timeline: a same-epoch snapshot keeps events; recovery after unavailable asks for a refresh", () => {
  let timeline = feed([event(1), event(2), { type: "unavailable", reason: "connection_lost" }]);
  const back = apply(timeline, event(3));
  assert.equal(back.effects.refresh, true);
  timeline = back.timeline;
  const snap = apply(timeline, {
    type: "event",
    event: { seq: 9, epoch: EPOCH, at_ms: 1, kind: "snapshot", withheld: 0, reason: "gap", head_seq: 9, oldest_seq: 5, status: withheld, resubscribe: { after_seq: 9, epoch: EPOCH } },
  });
  assert.deepEqual(events(snap.timeline).map((e) => e.seq), [1, 2, 3]);
  assert.equal(snap.timeline.reducer.cursor, 9);
  assert.equal(snap.timeline.snapshotStatus, null, "a withheld status is not shown");
  const updated = apply(snap.timeline, event(10, "task.updated", EPOCH, { run_id: "rpt-1", step_id: "s2", task_kind: "report", state: "committing", step: "write", outcome: "ok" }));
  assert.equal(updated.effects.refreshTasks, true);
});

test("the timeline shows withheld events and counts, newest first and bounded", () => {
  let timeline = feed([
    { type: "withheld" },
    { type: "gap" },
    event(1, "withheld", EPOCH, { of_kind: "request.completed", bytes: shown(70000) }),
    event(2, "app_api.endpoint_in_use"),
    { ...event(3), event: { ...event(3).event, withheld: 2 } },
  ]);
  const text = texts(timelineNodes(events(timeline), timeline));
  assert.ok(text.includes("1 event withheld"));
  assert.ok(text.includes("Event too large, withheld"));
  assert.ok(text.includes("orceld waited for its endpoint"));
  assert.ok(text.includes("2 fields withheld"));
  assert.ok(text.some((t) => t.startsWith("The event queue overflowed once")));
  timeline = feed(Array.from({ length: MAX_TIMELINE_ROWS + 30 }, (_, i) => event(i + 4)), timeline);
  const nodes = timelineNodes(events(timeline), timeline);
  const items = all(nodes).filter((node) => node.tag === "li");
  assert.equal(items.length, MAX_TIMELINE_ROWS);
  assert.equal(texts([items[0]!])[1], `#${MAX_TIMELINE_ROWS + 33}`, "newest first");
  assert.ok(texts(nodes).includes(`Showing the newest ${MAX_TIMELINE_ROWS} of ${MAX_TIMELINE_ROWS + 33} events.`));
});

test("event sentences use only fixed words and checked values", () => {
  assert.equal(
    describeEvent({ ...event(1).event, ok: shown(false), failure_code: shown("POLICY_DENIED") } as never),
    "Request files / read failed (POLICY_DENIED)",
  );
  assert.equal(
    describeEvent({ ...event(1).event, kind: "task.updated", run_id: "rpt-1", step_id: "s3", state: "approval_denied", step: "approval", outcome: "denied" } as never),
    "Report task run rpt-1, step s3: approval denied (approval: denied)",
  );
  assert.equal(describeEvent({ ...event(1).event, kind: "something.new" } as never), "Event withheld");
});

test("the connection line covers every state with fixed text", () => {
  assert.match(connectionText({ state: "connecting" }, true), /^Connecting/u);
  assert.match(connectionText(live, true), /^Connected to orceld/u);
  assert.match(connectionText({ state: "not_yours" }, true), /could not be confirmed as yours/u);
  assert.match(connectionText({ state: "incompatible" }, true), /^Incompatible orceld/u);
  assert.match(connectionText({ state: "ended" }, true), /^Live events ended/u);
  assert.match(connectionText(live, false), /^Not connected/u);
});
