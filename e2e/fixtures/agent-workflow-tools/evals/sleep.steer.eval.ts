import { defineEval } from "@orcel/orcel/evals";

/**
 * The provided `sleep` tool races its timer against the call's
 * `abortSignal`. A steering message ends a ten-minute sleep at once, and
 * the same turn continues with the message and the interrupted result.
 */
export default defineEval({
  description: "Steering ends a sleep early without cancelling the turn.",
  async test(t) {
    // Keep the last completed stage in the eval's captured logs if its deadline aborts.
    // These monotonic timings contain no session IDs, messages, or event payloads.
    const startedAt = performance.now();
    const logStage = (stage: string) =>
      t.log(`sleep.steer stage=${stage} elapsedMs=${Math.round(performance.now() - startedAt)}`);

    logStage("session.create.start");
    const session = await t.session();
    logStage("session.create.done");
    logStage("initial-turn.start");
    const live = await session.start("WORKFLOW-SLEEP-START");
    logStage("initial-turn.started");
    logStage("sleep-action.wait");
    await live.waitForEvent("actions.requested", {
      data: {
        actions: (actions) =>
          actions.some((action) => action.kind === "tool-call" && action.toolName === "sleep"),
      },
    });

    logStage("sleep-action.observed");
    logStage("steering-turn.start");
    const update = await live.session.start(
      "Alice has the numbers now, so there is no need to wait.",
      {
        turnPolicy: "steer",
      },
    );
    logStage("steering-turn.started");
    logStage("initial-turn.result.wait");
    const turn = await live.result();
    logStage("initial-turn.result.done");
    logStage("steering-turn.result.wait");
    await update.result();
    logStage("steering-turn.result.done");

    turn.calledTool("sleep", { count: 1, output: { interrupted: true } });
    turn.event("message.received", { count: 2 });
    turn.event("turn.completed", { count: 1 });
    turn.notEvent("turn.cancelled");
    turn.messageIncludes("WORKFLOW-SLEEP-RESULT Stopped early because a new message arrived.");
    t.noFailedActions();
  },
});
