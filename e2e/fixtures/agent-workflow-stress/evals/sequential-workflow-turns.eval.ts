import { defineEval, type OrcelEvalSession } from "@orcel/orcel/evals";
import { equals } from "@orcel/orcel/evals/expect";

const TURN_COUNT = 100;
const PERFORMANCE_LOG_PREFIX = "ORCEL_WORKFLOW_STRESS_METRIC=";

export default defineEval({
  description: "Workflow stress: one durable session completes 100 sequential turns.",
  tags: ["stress", "workflow", "sequential"],

  async test(t) {
    let session: OrcelEvalSession | undefined;
    const samples: Array<{
      durationMs: number;
      turnNumber: number;
      topology: { streamEventCount: number };
    }> = [];

    for (let turnNumber = 1; turnNumber <= TURN_COUNT; turnNumber += 1) {
      const marker = `sequential-turn-${String(turnNumber).padStart(3, "0")}`;
      const startedAt = performance.now();
      const result = await (session === undefined ? t.send(marker) : session.send(marker));
      const durationMs = performance.now() - startedAt;
      const elapsedSeconds = durationMs / 1_000;

      const turn = result.expectOk();
      samples.push({
        durationMs,
        turnNumber,
        topology: { streamEventCount: turn.events.length },
      });

      t.log(
        `turn ${String(turnNumber).padStart(3, "0")}/${TURN_COUNT} completed in ${elapsedSeconds.toFixed(3)}s`,
      );

      session ??= result.session;

      await t.require(turn.sessionId, equals(session.sessionId));
      await t.require(turn.message, equals(`stress-ack:${turnNumber}:${marker}`));
    }

    t.log(
      `${PERFORMANCE_LOG_PREFIX}${JSON.stringify({
        fixture: "agent-workflow-stress",
        scenario: "sequential",
        schemaVersion: 1,
        sessionId: session?.sessionId,
        samples,
        unit: "milliseconds",
      })}`,
    );

    t.succeeded();
    t.event("session.started", { count: 1 });
    t.event("turn.started", { count: TURN_COUNT });
    t.event("turn.completed", { count: TURN_COUNT });
    t.notEvent("turn.failed");
  },
});
