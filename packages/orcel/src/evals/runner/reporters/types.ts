import type { RuntimeTraceContext } from "#protocol/message.js";
import type {
  OrcelEval,
  OrcelEvalResult,
  OrcelEvalRunSummary,
  OrcelEvalTarget,
  OrcelEvalTraceContext,
} from "#evals/types.js";

/** Context delivered when one eval is scheduled for execution. */
export interface OrcelEvalStartEvent {
  readonly evaluation: OrcelEval;
  readonly startedAt: string;
  readonly target: OrcelEvalTarget;
}

/** Context delivered once the runner observes a session's first trace. */
export interface OrcelEvalSessionStartEvent extends OrcelEvalStartEvent {
  readonly primary: boolean;
  readonly sessionId: string;
  readonly traceContext: RuntimeTraceContext;
}

/** Additional run context delivered with a completed eval result. */
export interface OrcelEvalCompleteContext {
  readonly evaluation: OrcelEval;
  readonly target: OrcelEvalTarget;
  readonly traceContexts: readonly OrcelEvalTraceContext[];
}

/**
 * Reporter lifecycle interface. The runner calls these methods at defined
 * points during an eval run. Methods may return a promise for reporters
 * that perform asynchronous work (e.g. uploading to a remote service).
 *
 * Run-level reporters (console, JUnit) observe every eval in the run.
 * Eval-defined reporters observe only the evals that reference them.
 */
export interface EvalReporter {
  /**
   * The runner calls this once before any eval executes, with the evals
   * this reporter observes.
   */
  onRunStart(evaluations: readonly OrcelEval[], target: OrcelEvalTarget): void | Promise<void>;

  /** The runner calls this when an observed eval is scheduled. */
  onEvalStart?(event: OrcelEvalStartEvent): void | Promise<void>;

  /**
   * The runner calls this once per session when its first trace context is
   * observed. Sessions without trace instrumentation do not trigger it.
   */
  onSessionStart?(event: OrcelEvalSessionStartEvent): void | Promise<void>;

  /**
   * The runner calls this after each observed eval completes, with its
   * checks, scores, and verdict.
   */
  onEvalComplete(result: OrcelEvalResult, context?: OrcelEvalCompleteContext): void | Promise<void>;

  /**
   * The runner calls this once when the run finishes, with the aggregated
   * summary of the evals this reporter observes.
   */
  onRunComplete(summary: OrcelEvalRunSummary): void | Promise<void>;
}
