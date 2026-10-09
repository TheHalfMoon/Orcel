import { defineEval } from "@orcel/orcel/evals";

/**
 * `hold_deploy` rejects once its `abortSignal` aborts. A steering message
 * aborts it while the turn waits on the call, and the call settles as
 * `{ interrupted: true }` instead of failing. The same turn continues with
 * Alice's message.
 */
export default defineEval({
  description: "A steering message stops a waited workflow tool whose body rejects on abort.",
  async test(t) {
    // Preserve the last completed await stage when the original eval deadline fires.
    // Monotonic timings reveal no session IDs, message content, or tool payloads.
    const startedAt = performance.now();
    const logStage = (stage: string) =>
      t.log(
        `hold-deploy.steer stage=${stage} elapsedMs=${Math.round(performance.now() - startedAt)}`,
      );

    logStage("session.create.start");
    const session = await t.session();
    logStage("session.create.done");
    logStage("initial-turn.start");
    const live = await session.start("WORKFLOW-HOLD-START");
    logStage("initial-turn.started");
    logStage("hold-action.wait");
    await live.waitForEvent("actions.requested", {
      data: {
        actions: (actions) =>
          actions.some(
            (action) => action.kind === "tool-call" && action.toolName === "hold_deploy",
          ),
      },
    });

    logStage("hold-action.observed");
    logStage("steering-turn.start");
    const update = await live.session.start("Alice asks Bob to read the rollout notes first.", {
      turnPolicy: "steer",
    });
    logStage("steering-turn.started");
    logStage("initial-turn.result.wait");
    const turn = await live.result();
    logStage("initial-turn.result.done");
    logStage("steering-turn.result.wait");
    await update.result();
    logStage("steering-turn.result.done");

    turn.calledTool("hold_deploy", { count: 1, output: { interrupted: true } });
    turn.event("message.received", { count: 2 });
    turn.event("turn.completed", { count: 1 });
    turn.notEvent("turn.cancelled");
    turn.messageIncludes('WORKFLOW-HOLD-RESULT {"interrupted":true}');
    t.noFailedActions();
  },
});
