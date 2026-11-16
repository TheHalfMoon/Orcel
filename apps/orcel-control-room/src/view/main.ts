// SG-000119 slice A4: the Control Room page. It reads orceld only through the
// shell's five read-only commands (app_status, app_capabilities, app_events,
// app_tasks, app_task), through Tauri's global `window.__TAURI__.core` (no
// npm package), and draws what they answer as text (dom.ts). It has no
// control that acts: no Stop, nothing that answers, shows or dismisses an
// approval, nothing that opens, reveals or resolves a path. Opening a task's
// details only reads that task's metadata.
//
// Calls it makes: on load, app_status, app_capabilities, app_tasks and
// app_events, once each. Afterwards it reads status, capabilities and tasks
// again only when orceld comes back after being unavailable or a snapshot
// arrives, and the task list again when a task.updated event arrives (each
// coalesced, so a burst of events reads at most twice); app_task when a task's
// details are opened, and again for open details when the list is read.

import { h, show, type DocumentLike, type ElementLike, type Node } from "./dom.js";
import { refusalOf, INCOMPATIBLE, type Capabilities, type Status, type TaskDetail, type TaskList, type TaskSummary } from "./model.js";
import {
  capabilityNodes,
  connectionText,
  deviceNodes,
  statusNodes,
  taskDetailNodes,
  taskListNodes,
  taskSummaryLabel,
  taskSummaryNodes,
  timelineNodes,
  type Answer,
} from "./present.js";
import { apply, createTimeline, events, type Timeline } from "./timeline.js";

interface ChannelLike {
  onmessage: (message: unknown) => void;
}

interface Core {
  invoke(command: string, args?: Record<string, unknown>): Promise<unknown>;
  Channel: new () => ChannelLike;
}

function tauriCore(): Core | null {
  const tauri = (globalThis as { __TAURI__?: { core?: Partial<Core> } }).__TAURI__;
  const core = tauri?.core;
  return core && typeof core.invoke === "function" && typeof core.Channel === "function" ? (core as Core) : null;
}

const core = tauriCore();
const doc = document as unknown as DocumentLike;

function byId(id: string): HTMLElement {
  const element = document.getElementById(id);
  if (!element) throw new Error(`the page has no #${id}`);
  return element;
}

const page = {
  connection: byId("connection"),
  data: byId("data"),
  status: byId("status-body"),
  capabilities: byId("capabilities-body"),
  devices: byId("devices-body"),
  tasks: byId("tasks-body"),
  taskList: byId("task-list"),
  timeline: byId("timeline-body"),
};

let status: Answer<Status> = { state: "loading" };
let capabilities: Answer<Capabilities> = { state: "loading" };
let tasks: Answer<TaskList> = { state: "loading" };
let timeline: Timeline = createTimeline();
let incompatible = false;
/** A read failed because orceld was unavailable: read again once it is back. */
let readAgain = false;
const details = new Map<string, Answer<TaskDetail>>();
const openTasks = new Set<string>();
let drawnTasks = "";

function put(container: HTMLElement, nodes: Node[]): void {
  show(doc, container as unknown as ElementLike, nodes);
}

async function read<T>(command: string, args?: Record<string, unknown>): Promise<Answer<T>> {
  if (!core) return { state: "loading" };
  try {
    const value = await core.invoke(command, args);
    return { state: "ok", value: value as T };
  } catch (error) {
    const refusal = refusalOf(error);
    if (refusal.kind === "incompatible") incompatible = true;
    if (refusal.kind === "unavailable" || refusal.kind === "not_yours") readAgain = true;
    return { state: "refused", refusal };
  }
}

// ---------------------------------------------------------------------------
// Drawing

function drawConnection(): void {
  page.connection.textContent = incompatible ? INCOMPATIBLE : connectionText(timeline.link, core !== null);
  page.data.hidden = core === null || incompatible || timeline.link.state === "incompatible";
}

function drawStatus(): void {
  put(page.status, statusNodes(status, timeline.link));
}

function drawCapabilities(): void {
  put(page.capabilities, capabilityNodes(capabilities, timeline.link));
}

function taskNode(task: TaskSummary): Node {
  const id = task.task_id;
  const answer = details.get(id) ?? { state: "loading" };
  return h("li", null, [
    h("details", { "data-task": id, ...(openTasks.has(id) ? { open: "" } : {}) }, [
      h("summary", { "data-task": id, "aria-label": taskSummaryLabel(task) }, taskSummaryNodes(task)),
      h("div", { class: "task-detail" }, taskDetailNodes(answer)),
    ]),
  ]);
}

function drawTasks(force = false): void {
  const stale = timeline.link.state === "unavailable" || timeline.link.state === "not_yours";
  const { nodes, tasks: list } = taskListNodes(tasks, stale);
  const key = JSON.stringify([nodes, list, [...details.entries()]]);
  if (!force && key === drawnTasks) return;
  drawnTasks = key;
  const focused = document.activeElement instanceof HTMLElement ? document.activeElement.getAttribute("data-task") : null;
  put(page.tasks, nodes);
  put(page.taskList, list.map(taskNode));
  for (const element of page.taskList.querySelectorAll<HTMLDetailsElement>("details[data-task]")) {
    element.addEventListener("toggle", () => onToggle(element));
  }
  if (focused) {
    for (const summary of page.taskList.querySelectorAll<HTMLElement>("summary[data-task]")) {
      if (summary.getAttribute("data-task") === focused) summary.focus();
    }
  }
}

let timelineQueued = false;
function drawTimeline(): void {
  if (timelineQueued) return;
  timelineQueued = true;
  setTimeout(() => {
    timelineQueued = false;
    put(page.timeline, timelineNodes(events(timeline), timeline));
  }, 100);
}

function drawAll(): void {
  drawConnection();
  drawStatus();
  drawCapabilities();
  drawTasks();
  drawTimeline();
}

// ---------------------------------------------------------------------------
// Reading

async function loadStatus(): Promise<void> {
  status = await read<Status>("app_status");
  drawConnection();
  drawStatus();
}

async function loadCapabilities(): Promise<void> {
  capabilities = await read<Capabilities>("app_capabilities");
  drawConnection();
  drawCapabilities();
}

async function loadTask(id: string): Promise<void> {
  const answer = await read<TaskDetail>("app_task", { task_id: id });
  details.set(id, answer);
  drawTasks();
}

async function loadTasks(): Promise<void> {
  tasks = await read<TaskList>("app_tasks");
  drawConnection();
  if (tasks.state === "ok" && Array.isArray(tasks.value.tasks)) {
    const known = new Set(tasks.value.tasks.map((task) => task.task_id));
    for (const id of [...openTasks]) {
      if (!known.has(id)) openTasks.delete(id);
    }
    for (const id of [...details.keys()]) {
      if (!known.has(id)) details.delete(id);
    }
  }
  drawTasks();
  await Promise.all([...openTasks].map((id) => loadTask(id)));
}

function onToggle(element: HTMLDetailsElement): void {
  const id = element.getAttribute("data-task");
  if (!id) return;
  if (element.open && !openTasks.has(id)) {
    openTasks.add(id);
    void loadTask(id);
  } else if (!element.open) {
    openTasks.delete(id);
  }
}

/** Runs `work`, and once more after it if asked again meanwhile. */
function coalesced(work: () => Promise<unknown>): () => void {
  let running = false;
  let again = false;
  const run = (): void => {
    if (running) {
      again = true;
      return;
    }
    running = true;
    void work().finally(() => {
      running = false;
      if (again) {
        again = false;
        run();
      }
    });
  };
  return run;
}

const refresh = coalesced(() => Promise.all([loadStatus(), loadCapabilities(), loadTasks()]));
const refreshTasks = coalesced(() => loadTasks());

function onItem(item: unknown): void {
  const before = timeline.link.state;
  const next = apply(timeline, item);
  timeline = next.timeline;
  if (timeline.snapshotStatus && next.effects.refresh) status = { state: "ok", value: timeline.snapshotStatus };
  if (timeline.link.state !== before) drawAll();
  else drawTimeline();
  if (next.effects.refresh || (readAgain && timeline.link.state === "live")) {
    readAgain = false;
    refresh();
  } else if (next.effects.refreshTasks) {
    refreshTasks();
  }
}

function subscribe(): void {
  if (!core) return;
  const channel = new core.Channel();
  channel.onmessage = onItem;
  core.invoke("app_events", { channel }).catch((error: unknown) => {
    const refusal = refusalOf(error);
    timeline = {
      ...timeline,
      link:
        refusal.kind === "incompatible"
          ? { state: "incompatible" }
          : refusal.kind === "not_yours"
            ? { state: "not_yours" }
            : { state: "ended" },
    };
    drawAll();
  });
}

put(page.devices, deviceNodes());
drawAll();
if (core) {
  void loadStatus();
  void loadCapabilities();
  void loadTasks();
  subscribe();
}
