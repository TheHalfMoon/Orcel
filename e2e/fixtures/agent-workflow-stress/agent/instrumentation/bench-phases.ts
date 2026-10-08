import { defineInstrumentation } from "@orcel/orcel/instrumentation";

import { createServerPhaseObserver } from "../lib/server-phase-observer";

/**
 * Opt-in stress fixture only. Default is silent and does not export telemetry.
 * The output is limited to event type, opaque correlation IDs and local timing.
 * Logs may be collected offline; there is no Vercel endpoint or paid exporter.
 */
let observer: ReturnType<typeof createServerPhaseObserver> | undefined;

export default defineInstrumentation({
  setup() {
    if (process.env.WORKFLOW_STRESS_SERVER_PHASES !== "1") return;
    observer = createServerPhaseObserver({
      emit(row) {
        process.stdout.write(`WORKFLOW_STRESS_SERVER_PHASE=${JSON.stringify(row)}\n`);
      },
    });
  },
  events: {
    "turn.started"(event) {
      observer?.observe(event);
    },
    "model.call.started"(event) {
      observer?.observe(event);
    },
    "turn.completed"(event) {
      observer?.observe(event);
    },
    "turn.cancelled"(event) {
      observer?.observe(event);
    },
    "turn.failed"(event) {
      observer?.observe(event);
    },
  },
});
