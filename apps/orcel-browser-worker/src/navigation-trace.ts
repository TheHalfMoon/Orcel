// #438: which stage a navigation reached, for the one case the host cannot
// see into: a navigation that times out with no connection at the listener.
// Stage names and milliseconds only, never a URL or page content, and bounded.
// It decides nothing; it is written to stderr only when a navigation times out.

const MAX_STAGES = 48;

let started = 0;
let stages: string[] = [];

/// Starts a new timeline for the next navigation.
export function traceStart(now: number = Date.now()): void {
  started = now;
  stages = [];
}

/// Records that `stage` was reached. `stage` is a fixed name from the code.
export function traceMark(stage: string, now: number = Date.now()): void {
  if (stages.length < MAX_STAGES) stages.push(`${stage}+${now - started}ms`);
}

/// The timeline so far, on one line.
export function traceLine(): string {
  return `navigation timeline: ${stages.join(" ")}`;
}
