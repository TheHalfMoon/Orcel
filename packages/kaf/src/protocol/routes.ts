/**
 * Stable framework-owned route prefix reserved for kaf's runtime transport
 * surfaces.
 */
export const KAF_ROUTE_PREFIX = "/kaf/v1";

/** Reservation pattern for the production cron bridge's unguessable token. */
export const KAF_PRODUCTION_CRON_ROUTE_PATTERN = `${KAF_ROUTE_PREFIX}/cron/:token`;

/**
 * Stable framework-owned health route.
 */
export const KAF_HEALTH_ROUTE_PATH = `${KAF_ROUTE_PREFIX}/health`;

/**
 * Stable framework-owned route exposing the JSON inspection payload for
 * the current agent. The kaf channel registers and authenticates this route
 * with the same `auth` input as its session routes.
 */
export const KAF_INFO_ROUTE_PATH = `${KAF_ROUTE_PREFIX}/info`;

/** Stable route for creating ID-addressed sessions. */
export const KAF_SESSION_ROUTE_PATH = `${KAF_ROUTE_PREFIX}/session`;

/** Stable route pattern for sending a message to one exact session ID. */
export const KAF_SESSION_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:sessionId`;

/** Stable route pattern for cancelling one exact session ID. */
export const KAF_SESSION_CANCEL_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:sessionId/cancel`;

/** Stable route pattern for compacting one exact session ID. */
export const KAF_SESSION_COMPACT_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:sessionId/compact`;

/** Stable route pattern for clearing one exact session ID. */
export const KAF_SESSION_CLEAR_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:sessionId/clear`;

/** Stable route pattern for resetting one exact session ID. */
export const KAF_SESSION_RESET_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:sessionId/reset`;

/** Stable event-stream route pattern for one exact session ID. */
export const KAF_SESSION_STREAM_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:sessionId/stream`;

/**
 * Parent-origin proxy route for one remotely executed child session stream.
 */
export const KAF_SUBAGENT_STREAM_ROUTE_PATTERN = `${KAF_SESSION_ROUTE_PATH}/:parentSessionId/subagents/:callId/:childSessionId/stream`;

/**
 * Framework-owned route pattern for dispatching one authored schedule
 * exactly once from the dev server.
 *
 * Only registered when Nitro is running in dev mode — production builds
 * never mount this route. Smoke tests and human developers use it to
 * trigger a schedule out-of-band (without a cron firing) and recover the
 * resulting `{ scheduleId, sessionIds }` payload as JSON so they can
 * subscribe to {@link KAF_SESSION_STREAM_ROUTE_PATTERN} for each session.
 *
 * `:scheduleId` is the authored schedule's filesystem-derived name (e.g.
 * `agent/schedules/heartbeat.ts` -> `"heartbeat"`).
 */
export const KAF_DEV_DISPATCH_SCHEDULE_ROUTE_PATTERN = `${KAF_ROUTE_PREFIX}/dev/schedules/:scheduleId`;

/**
 * Dev-only route exposing the current runtime artifact revision.
 *
 * Local development clients use this to decide when an HMR rebuild has
 * published new runtime artifacts, so their next normal prompt can start a
 * fresh server-side session while in-flight sessions keep their original
 * snapshot.
 */
export const KAF_DEV_RUNTIME_ARTIFACTS_ROUTE_PATH = `${KAF_ROUTE_PREFIX}/dev/runtime-artifacts`;

/**
 * Dev-only route that flushes queued runtime artifact rebuilds before
 * returning the current revision.
 */
export const KAF_DEV_RUNTIME_ARTIFACTS_REBUILD_ROUTE_PATH = `${KAF_DEV_RUNTIME_ARTIFACTS_ROUTE_PATH}/rebuild`;

/** Dev-only route that acquires an idempotent authored-source suspension lease. */
export const KAF_DEV_RUNTIME_ARTIFACTS_SUSPEND_ROUTE_PATH = `${KAF_DEV_RUNTIME_ARTIFACTS_ROUTE_PATH}/suspend`;

/** Dev-only route that idempotently releases one authored-source suspension lease. */
export const KAF_DEV_RUNTIME_ARTIFACTS_RESUME_ROUTE_PATH = `${KAF_DEV_RUNTIME_ARTIFACTS_ROUTE_PATH}/resume`;

/**
 * Builds the dev-only schedule dispatch URL for one named authored
 * schedule. The path encodes the schedule id so reserved characters in
 * authored filenames round-trip safely.
 */
export function createKafDevDispatchSchedulePath(scheduleId: string): string {
  return `${KAF_ROUTE_PREFIX}/dev/schedules/${encodeURIComponent(scheduleId)}`;
}

/**
 * Stable framework-owned route pattern for receiving inbound IdP redirects
 * during in-turn interactive connection authorization.
 *
 * `:name` is the connection name, `:attemptId` identifies the exact challenge,
 * and `:token` is the workflow hook token minted by the workflow body so the
 * route handler can resume the suspended turn via `resumeHook(token, payload)`.
 *
 * The route is unauthenticated by design: an OAuth IdP follows this URL
 * via a 3xx redirect from the user's browser with no kaf credentials
 * attached. The token is the unguessable capability that authorizes the
 * resume; anyone who has it can deliver the callback payload, which is
 * exactly what the IdP needs to do.
 */
export const KAF_CONNECTION_CALLBACK_ROUTE_PATTERN = `${KAF_ROUTE_PREFIX}/connections/:name/callback/:attemptId/:token`;

/**
 * Stable framework-owned route pattern for terminal session callbacks.
 *
 * The `:token` segment is an unguessable workflow hook capability. The route
 * is unauthenticated by design and resumes the matching parked runtime action.
 */
export const KAF_CALLBACK_ROUTE_PATTERN = `${KAF_ROUTE_PREFIX}/callback/:token`;

/** Builds the ID-addressed message route for one session. */
export function createKafSessionRoutePath(sessionId: string): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(sessionId)}`;
}

/** Builds the ID-addressed cancel route for one session. */
export function createKafSessionCancelRoutePath(sessionId: string): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(sessionId)}/cancel`;
}

/** Builds the parent-origin stream path for one remote child session. */
export function createKafSubagentStreamRoutePath(input: {
  readonly callId: string;
  readonly childSessionId: string;
  readonly parentSessionId: string;
}): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(input.parentSessionId)}/subagents/${encodeURIComponent(input.callId)}/${encodeURIComponent(input.childSessionId)}/stream`;
}

/** Builds the ID-addressed compact route for one session. */
export function createKafSessionCompactRoutePath(sessionId: string): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(sessionId)}/compact`;
}

/** Builds the ID-addressed clear route for one session. */
export function createKafSessionClearRoutePath(sessionId: string): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(sessionId)}/clear`;
}

/** Builds the ID-addressed reset route for one session. */
export function createKafSessionResetRoutePath(sessionId: string): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(sessionId)}/reset`;
}

/** Builds the ID-addressed event-stream route for one session. */
export function createKafSessionStreamRoutePath(sessionId: string): string {
  return `${KAF_SESSION_ROUTE_PATH}/${encodeURIComponent(sessionId)}/stream`;
}

/**
 * Creates the stable framework-owned connection callback route path for
 * one (`name`, `attemptId`, `token`) tuple.
 *
 * The workflow body builds this path against {@link KAF_ROUTE_PREFIX} when
 * minting the redirect URL it hands to the IdP via `startAuthorization`.
 * The runtime's framework callback route handler matches the same path
 * pattern and forwards the projected request payload into
 * `resumeHook(token, payload)`.
 */
export function createKafConnectionCallbackRoutePath(
  name: string,
  attemptId: string,
  token: string,
): string {
  return `${KAF_ROUTE_PREFIX}/connections/${encodeURIComponent(name)}/callback/${encodeURIComponent(attemptId)}/${encodeURIComponent(token)}`;
}

/**
 * Creates the stable framework-owned terminal callback route path.
 */
export function createKafCallbackRoutePath(token: string): string {
  return `${KAF_ROUTE_PREFIX}/callback/${encodeURIComponent(token)}`;
}

/** Builds the capability path used to answer one remote child turn. */
export function createKafTaskInputRoutePath(token: string): string {
  return `${KAF_ROUTE_PREFIX}/task-input/${encodeURIComponent(token)}`;
}
