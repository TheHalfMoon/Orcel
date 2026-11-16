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
import { h, show } from "./dom.js";
import { refusalOf, INCOMPATIBLE } from "./model.js";
import { capabilityNodes, connectionText, deviceNodes, statusNodes, taskDetailNodes, taskListNodes, taskSummaryNodes, timelineNodes, } from "./present.js";
import { apply, createTimeline, events } from "./timeline.js";
function tauriCore() {
    const tauri = globalThis.__TAURI__;
    const core = tauri?.core;
    return core && typeof core.invoke === "function" && typeof core.Channel === "function" ? core : null;
}
const core = tauriCore();
const doc = document;
function byId(id) {
    const element = document.getElementById(id);
    if (!element)
        throw new Error(`the page has no #${id}`);
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
let status = { state: "loading" };
let capabilities = { state: "loading" };
let tasks = { state: "loading" };
let timeline = createTimeline();
let incompatible = false;
/** A read failed because orceld was unavailable: read again once it is back. */
let readAgain = false;
const details = new Map();
const openTasks = new Set();
let drawnTasks = "";
function put(container, nodes) {
    show(doc, container, nodes);
}
async function read(command, args) {
    if (!core)
        return { state: "loading" };
    try {
        const value = await core.invoke(command, args);
        return { state: "ok", value: value };
    }
    catch (error) {
        const refusal = refusalOf(error);
        if (refusal.kind === "incompatible")
            incompatible = true;
        if (refusal.kind === "unavailable" || refusal.kind === "not_yours")
            readAgain = true;
        return { state: "refused", refusal };
    }
}
// ---------------------------------------------------------------------------
// Drawing
function drawConnection() {
    page.connection.textContent = incompatible ? INCOMPATIBLE : connectionText(timeline.link, core !== null);
    page.data.hidden = core === null || incompatible || timeline.link.state === "incompatible";
}
function drawStatus() {
    put(page.status, statusNodes(status, timeline.link));
}
function drawCapabilities() {
    put(page.capabilities, capabilityNodes(capabilities, timeline.link));
}
function taskNode(task) {
    const id = task.task_id;
    const answer = details.get(id) ?? { state: "loading" };
    return h("li", null, [
        h("details", { "data-task": id, ...(openTasks.has(id) ? { open: "" } : {}) }, [
            h("summary", { "data-task": id, "aria-label": `Report task ${id}` }, taskSummaryNodes(task)),
            h("div", { class: "task-detail" }, taskDetailNodes(answer)),
        ]),
    ]);
}
function drawTasks(force = false) {
    const stale = timeline.link.state === "unavailable" || timeline.link.state === "not_yours";
    const { nodes, tasks: list } = taskListNodes(tasks, stale);
    const key = JSON.stringify([nodes, list, [...details.entries()]]);
    if (!force && key === drawnTasks)
        return;
    drawnTasks = key;
    const focused = document.activeElement instanceof HTMLElement ? document.activeElement.getAttribute("data-task") : null;
    put(page.tasks, nodes);
    put(page.taskList, list.map(taskNode));
    for (const element of page.taskList.querySelectorAll("details[data-task]")) {
        element.addEventListener("toggle", () => onToggle(element));
    }
    if (focused) {
        for (const summary of page.taskList.querySelectorAll("summary[data-task]")) {
            if (summary.getAttribute("data-task") === focused)
                summary.focus();
        }
    }
}
let timelineQueued = false;
function drawTimeline() {
    if (timelineQueued)
        return;
    timelineQueued = true;
    setTimeout(() => {
        timelineQueued = false;
        put(page.timeline, timelineNodes(events(timeline), timeline));
    }, 100);
}
function drawAll() {
    drawConnection();
    drawStatus();
    drawCapabilities();
    drawTasks();
    drawTimeline();
}
// ---------------------------------------------------------------------------
// Reading
async function loadStatus() {
    status = await read("app_status");
    drawConnection();
    drawStatus();
}
async function loadCapabilities() {
    capabilities = await read("app_capabilities");
    drawConnection();
    drawCapabilities();
}
async function loadTask(id) {
    const answer = await read("app_task", { task_id: id });
    details.set(id, answer);
    drawTasks();
}
async function loadTasks() {
    tasks = await read("app_tasks");
    drawConnection();
    if (tasks.state === "ok" && Array.isArray(tasks.value.tasks)) {
        const known = new Set(tasks.value.tasks.map((task) => task.task_id));
        for (const id of [...openTasks]) {
            if (!known.has(id))
                openTasks.delete(id);
        }
        for (const id of [...details.keys()]) {
            if (!known.has(id))
                details.delete(id);
        }
    }
    drawTasks();
    await Promise.all([...openTasks].map((id) => loadTask(id)));
}
function onToggle(element) {
    const id = element.getAttribute("data-task");
    if (!id)
        return;
    if (element.open && !openTasks.has(id)) {
        openTasks.add(id);
        void loadTask(id);
    }
    else if (!element.open) {
        openTasks.delete(id);
    }
}
/** Runs `work`, and once more after it if asked again meanwhile. */
function coalesced(work) {
    let running = false;
    let again = false;
    const run = () => {
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
function onItem(item) {
    const before = timeline.link.state;
    const next = apply(timeline, item);
    timeline = next.timeline;
    if (timeline.snapshotStatus && next.effects.refresh)
        status = { state: "ok", value: timeline.snapshotStatus };
    if (timeline.link.state !== before)
        drawAll();
    else
        drawTimeline();
    if (next.effects.refresh || (readAgain && timeline.link.state === "live")) {
        readAgain = false;
        refresh();
    }
    else if (next.effects.refreshTasks) {
        refreshTasks();
    }
}
function subscribe() {
    if (!core)
        return;
    const channel = new core.Channel();
    channel.onmessage = onItem;
    core.invoke("app_events", { channel }).catch((error) => {
        const refusal = refusalOf(error);
        timeline = {
            ...timeline,
            link: refusal.kind === "incompatible"
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
