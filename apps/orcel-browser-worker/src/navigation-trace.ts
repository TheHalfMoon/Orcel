// #438: which stage a navigation reached, for the one case the host cannot
// see into: a navigation that times out with no connection at the listener.
// Stage names and milliseconds only, never a URL or page content, and bounded.
// It decides nothing; it is written to stderr only when a navigation times out.

const MAX_STAGES = 48;

let started = 0;
let dropped = 0;
let stages: string[] = [];

/// Starts a new timeline for the next navigation.
export function traceStart(now: number = Date.now()): void {
  started = now;
  dropped = 0;
  stages = [];
}

/// Records that `stage` was reached. `stage` is a fixed name from the code.
/// The newest stages are kept: the last one reached is what a stall shows.
export function traceMark(stage: string, now: number = Date.now()): void {
  stages.push(`${stage}+${now - started}ms`);
  if (stages.length > MAX_STAGES) {
    stages.shift();
    dropped += 1;
  }
}

/// The timeline so far, on one line.
export function traceLine(): string {
  const earlier = dropped > 0 ? `(${dropped} earlier) ` : "";
  return `navigation timeline: ${earlier}${stages.join(" ")}`;
}

/// #438: a stalled worker and a stalled engine look the same from a mark alone,
/// since a mark is when the worker saw the event. This records how long this
/// process's own event loop went without running. Returns the function that
/// stops watching and marks the largest gap.
export function traceWatchEventLoop(intervalMs = 250, clock: () => number = Date.now): () => void {
  let last = clock();
  let largest = 0;
  const timer = setInterval(() => {
    const now = clock();
    largest = Math.max(largest, now - last - intervalMs);
    last = now;
  }, intervalMs);
  timer.unref();
  return () => {
    clearInterval(timer);
    traceMark(`largest_event_loop_gap_${Math.max(largest, 0)}ms`, clock());
  };
}
