// SG-000119 slice A4: the live timeline, kept by the headless client's own
// reducer (src/agentkit/client/state.ts, CR-02): per-epoch cursors, a gap
// rejected before the cursor moves, duplicates and events of another epoch
// ignored, a snapshot moving the cursor and a new epoch clearing the
// timeline. The A1 client in Rust already enforces the same rules before
// anything reaches the page; the reducer is the page's second layer.
//
// The stream's items are the sanitiser's, so each event's fields are kept as
// the reducer event's `data` and read back only by present.ts.
import { applySnapshot, createControlRoomState, reduceEvent, } from "../agentkit/client/state.js";
import { count, isRecord } from "./model.js";
export function createTimeline() {
    return {
        reducer: createControlRoomState(),
        link: { state: "connecting" },
        withheldEvents: 0,
        gaps: 0,
        outOfOrder: 0,
        lastSnapshot: null,
        snapshotStatus: null,
    };
}
function isViewEvent(value) {
    return (isRecord(value) &&
        count(value.seq) !== null &&
        typeof value.epoch === "string" &&
        typeof value.kind === "string" &&
        count(value.at_ms) !== null);
}
function asReducerEvent(event) {
    return {
        seq: event.seq,
        epoch: event.epoch,
        run_id: null,
        step_id: null,
        kind: event.kind,
        at_ms: event.at_ms,
        data: event,
    };
}
/** The sanitised events of the current epoch, oldest first. */
export function events(timeline) {
    return timeline.reducer.events.map((event) => event.data);
}
/**
 * Applies one channel message. Returns the new timeline and what to read
 * again. Unknown message shapes change nothing.
 */
export function apply(timeline, item) {
    const none = { refresh: false, refreshTasks: false };
    if (!isRecord(item) || typeof item.type !== "string")
        return { timeline, effects: none };
    const message = item;
    const wasDown = timeline.link.state === "unavailable" || timeline.link.state === "not_yours";
    switch (message.type) {
        case "event": {
            const event = message.event;
            if (!isViewEvent(event))
                return { timeline: { ...timeline, withheldEvents: timeline.withheldEvents + 1 }, effects: none };
            const live = { ...timeline, link: { state: "live" } };
            if (event.kind === "snapshot")
                return snapshot(live, event);
            let reducer = live.reducer;
            // The first event of a subscription that began without a status: the
            // timeline adopts its epoch and starts just before it.
            if (reducer.epoch === null)
                reducer = { ...reducer, epoch: event.epoch, cursor: Math.max(0, event.seq - 1) };
            try {
                reducer = reduceEvent(reducer, asReducerEvent(event));
            }
            catch {
                return { timeline: { ...live, outOfOrder: live.outOfOrder + 1 }, effects: { refresh: wasDown, refreshTasks: false } };
            }
            return {
                timeline: { ...live, reducer },
                effects: { refresh: wasDown, refreshTasks: event.kind === "task.updated" },
            };
        }
        case "withheld":
            return { timeline: { ...timeline, link: { state: "live" }, withheldEvents: timeline.withheldEvents + 1 }, effects: { refresh: wasDown, refreshTasks: false } };
        case "cleared":
            // A new epoch: the timeline starts again; a snapshot follows.
            return { timeline: { ...timeline, reducer: createControlRoomState(), snapshotStatus: null }, effects: none };
        case "gap":
            return { timeline: { ...timeline, gaps: timeline.gaps + 1 }, effects: none };
        case "unavailable":
            return {
                timeline: { ...timeline, link: { state: "unavailable", reason: typeof message.reason === "string" ? message.reason : "" } },
                effects: none,
            };
        case "not_yours":
            return { timeline: { ...timeline, link: { state: "not_yours" } }, effects: none };
        case "incompatible":
            return { timeline: { ...timeline, link: { state: "incompatible" } }, effects: none };
        case "ended":
            return { timeline: { ...timeline, link: { state: "ended" } }, effects: none };
        default:
            return { timeline, effects: none };
    }
}
function snapshot(timeline, event) {
    const resubscribe = isRecord(event.resubscribe) ? event.resubscribe : null;
    const afterSeq = resubscribe ? count(resubscribe.after_seq) : null;
    const epoch = resubscribe && typeof resubscribe.epoch === "string" ? resubscribe.epoch : null;
    const headSeq = count(event.head_seq) ?? 0;
    if (afterSeq === null || epoch === null) {
        return { timeline: { ...timeline, withheldEvents: timeline.withheldEvents + 1 }, effects: { refresh: true, refreshTasks: false } };
    }
    const data = {
        reason: event.reason === "gap" ? "gap" : "epoch",
        head_seq: headSeq,
        oldest_seq: count(event.oldest_seq) ?? 0,
        // The view keeps the sanitised status itself (snapshotStatus); the
        // reducer only stores it.
        status: null,
        resubscribe: { after_seq: afterSeq, epoch },
    };
    const status = isRecord(event.status) && event.status.state === "shown" && isRecord(event.status.value)
        ? event.status.value
        : null;
    return {
        timeline: {
            ...timeline,
            reducer: applySnapshot(timeline.reducer, data),
            lastSnapshot: { reason: data.reason, head_seq: headSeq },
            snapshotStatus: status,
        },
        effects: { refresh: true, refreshTasks: false },
    };
}
