import { sleep } from "#compiled/@workflow/core/index.js";

import type { WorkflowToolContext } from "#public/tools/index.js";
import type { SleepToolInput, SleepToolOutput } from "#tools/provided/sleep.js";

/** Waits durably, and stops early when a new message arrives. */
export async function executeSleepTool(
  input: SleepToolInput,
  ctx: WorkflowToolContext,
): Promise<SleepToolOutput> {
  "use workflow";

  // Abort events are not replayed to listeners registered after an abort.
  // Avoid starting a durable timer when steering already interrupted this call.
  if (ctx.abortSignal.aborted) return { interrupted: true };

  let onAbort!: () => void;
  const interrupted = new Promise<"interrupted">((resolve) => {
    onAbort = () => resolve("interrupted");
    ctx.abortSignal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const elapsed = sleep(Math.ceil(input.seconds * 1_000)).then(() => "elapsed" as const);
    const woke = await Promise.race([elapsed, interrupted]);
    return woke === "elapsed" ? { waitedSeconds: input.seconds } : { interrupted: true };
  } finally {
    // A completed timer must not retain a listener on a still-live signal.
    ctx.abortSignal.removeEventListener("abort", onAbort);
  }
}
