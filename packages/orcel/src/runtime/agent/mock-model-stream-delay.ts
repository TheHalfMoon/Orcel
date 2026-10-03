const MOCK_AUTHORED_MODELS_STREAM_DELAY_MS_ENV = "ORCEL_MOCK_AUTHORED_MODELS_STREAM_DELAY_MS";

interface MockStreamOptions {
  readonly abortSignal?: AbortSignal;
}

/** Adds optional test-only latency while still honoring model cancellation. */
export async function waitForMockStreamDelay(options: MockStreamOptions): Promise<void> {
  const rawDelay = process.env[MOCK_AUTHORED_MODELS_STREAM_DELAY_MS_ENV];
  if (rawDelay === undefined) return;

  const parsedDelay = Number.parseInt(rawDelay, 10);
  if (!Number.isFinite(parsedDelay) || parsedDelay <= 0) return;
  const delayMs = Math.min(parsedDelay, 10_000);
  const signal = options.abortSignal;

  await new Promise<void>((resolve, reject) => {
    const abort = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      reject(
        signal?.reason instanceof Error ? signal.reason : new Error("Mock model stream aborted."),
      );
    };
    const complete = (): void => {
      signal?.removeEventListener("abort", abort);
      resolve();
    };
    const timer = setTimeout(complete, delayMs);
    if (signal === undefined) return;
    if (signal.aborted) {
      abort();
      return;
    }
    signal.addEventListener("abort", abort, { once: true });
  });
}
