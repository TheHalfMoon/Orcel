// #438: which stage a navigation reached, for the one case the host cannot
// see into: a navigation that times out with no connection at the listener.
// Stage names and milliseconds only, never a URL or page content, and bounded.
// It decides nothing; it is written to stderr only when a navigation times out.

import { cpus, type CpuInfo } from "node:os";

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

/// The share of all cores' time spent busy between two `os.cpus()` readings, as
/// a whole percentage, or null if the readings can't be compared.
export function cpuBusyPercent(before: CpuInfo[], after: CpuInfo[]): number | null {
  if (before.length === 0 || before.length !== after.length) return null;
  let busy = 0;
  let total = 0;
  after.forEach((cpu, index) => {
    const earlier = before[index]!.times;
    const idle = cpu.times.idle - earlier.idle;
    const all = (Object.keys(cpu.times) as (keyof CpuInfo["times"])[]).reduce(
      (sum, kind) => sum + cpu.times[kind] - earlier[kind],
      0
    );
    busy += all - idle;
    total += all;
  });
  return total > 0 ? Math.round((busy / total) * 100) : null;
}

/// #438: a mark is when this worker saw an event, so a stalled worker and a
/// stalled engine look the same, and a starved runner can cause either. This
/// watches how long this process's event loop went without running, and how busy
/// the whole machine was. Returns the function that stops and marks both.
export function traceWatchEventLoop(intervalMs = 250, clock: () => number = Date.now): () => void {
  const cpuBefore = cpus();
  let last = clock();
  let largest = 0;
  const measure = () => {
    const now = clock();
    largest = Math.max(largest, now - last - intervalMs);
    last = now;
  };
  const timer = setInterval(measure, intervalMs);
  timer.unref();
  return () => {
    clearInterval(timer);
    // The interval still open: a stall can run right up to the timeout.
    measure();
    traceMark(`largest_event_loop_gap_${Math.max(largest, 0)}ms`, clock());
    const busy = cpuBusyPercent(cpuBefore, cpus());
    if (busy !== null) traceMark(`system_cpu_busy_${busy}pct`, clock());
  };
}

/**
 * #584: the engine's network error code in a failed navigation's message, such as
 * `net::ERR_PROXY_CONNECTION_FAILED`, or "unknown". Only the code is kept: the rest of the
 * message can name the URL.
 */
export function netErrorCode(message: string): string {
  return /net::ERR_[A-Z0-9_]+/.exec(message)?.[0] ?? "unknown";
}

/// The only CDP methods a probe may send. Both are reads the browser process
/// answers by itself. The renderer is not asked: while a navigation is pending
/// the engine holds back what is sent to it, so a healthy renderer gives no
/// answer to `evaluate` either (measured on Edge 158). `Page.stopLoading`
/// would let it answer, but it would also cancel the navigation.
export const PROBE_METHODS = ["Page.getNavigationHistory", "Browser.getVersion"] as const;

/// What a probe needs from a CDP session.
export interface ProbeSession {
  send(method: (typeof PROBE_METHODS)[number]): Promise<unknown>;
  detach(): Promise<void>;
}

/// "answered" only if there was a result. A refusal is an "error": it can be
/// Playwright's own, for a page that is already closed.
function settled(work: Promise<unknown>): Promise<"answered" | "error"> {
  return work.then(
    () => "answered" as const,
    () => "error" as const
  );
}

/**
 * #584: whether the engine's browser process answers after a navigation stalled, as stage
 * marks: attaching a CDP session to the page, the page's navigation history, and the
 * browser's version. Each is "answered", "error" or "no_answer", within `ms` for all of them;
 * a probe that could not be sent because attaching did not succeed is "not_sent". Only
 * whether an answer came is kept, never the answer. It says nothing about the renderer.
 */
export async function probeBrowser(attach: () => Promise<ProbeSession>, ms = 2_000): Promise<string[]> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<"no_answer">((resolve) => {
    timer = setTimeout(() => resolve("no_answer"), ms);
  });
  const attaching = attach();
  const mark = (answer: string, history: string, version: string) => [
    `browser_attach_${answer}`,
    `browser_history_${history}`,
    `browser_version_${version}`
  ];
  try {
    const attached = await Promise.race([settled(attaching), deadline]);
    if (attached !== "answered") return mark(attached, "not_sent", "not_sent");
    const session = await attaching;
    const [history, version] = await Promise.all(PROBE_METHODS.map((method) => Promise.race([settled(session.send(method)), deadline])));
    return mark(attached, history!, version!);
  } finally {
    clearTimeout(timer);
    // Never waited for: detaching can wait behind a stalled page. It also lets
    // go of a session that attaches late.
    void attaching.then((session) => session.detach()).catch(() => {});
  }
}
