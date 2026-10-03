import { defineTool } from "@orcel/orcel/tools";
import { never } from "@orcel/orcel/tools/approval";
import { z } from "zod";

const FALLBACK_TIMEOUT_MS = 90_000;

export default defineTool({
  description: "Waits until the delegated turn is cancelled.",
  inputSchema: z.object({}),
  approval: never(),
  execute(_input, ctx) {
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        resolve("wait-for-cancellation: fallback timeout reached without cancellation");
      }, FALLBACK_TIMEOUT_MS);
      const abort = (): void => {
        clearTimeout(timer);
        reject(ctx.abortSignal.reason);
      };
      if (ctx.abortSignal.aborted) return abort();
      ctx.abortSignal.addEventListener("abort", abort, { once: true });
    });
  },
});
