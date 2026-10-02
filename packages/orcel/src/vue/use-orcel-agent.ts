import { shallowRef, computed, onScopeDispose, type ComputedRef } from "vue";
import type { UserContent } from "ai";

import {
  attachOrcelAgentStore,
  detachOrcelAgentStore,
  OrcelAgentStore,
  type OrcelAgentStoreCallbacks,
  type OrcelAgentStoreSnapshot,
  type OrcelAgentStoreStatus,
  type PrepareSend,
} from "#client/orcel-agent-store.js";
import { resolveOrcelAgentHost } from "#client/agent-host.js";
import type { OrcelAgentReducer } from "#client/reducer.js";
import type { ClientSession } from "#client/session.js";
import { defaultMessageReducer, type OrcelMessageData } from "#client/message-reducer.js";
import type { MessageStreamEvent } from "#protocol/message.js";
import type {
  CancelSessionResult,
  ClientAuth,
  HeadersValue,
  RespondTurnOptions,
  SendTurnOptions,
  ClientSessionState,
} from "#client/types.js";

export type { PrepareSend };

/**
 * Lifecycle phase of a `useOrcelAgent` session: `"ready"` (idle), `"resuming"`
 * (checking an attached session), `"submitted"` (request sent, awaiting first
 * event), `"streaming"` (events arriving), or `"error"`.
 */
export type UseOrcelAgentStatus = OrcelAgentStoreStatus;

/**
 * Point-in-time projected state for an orcel agent session (`data`, `error`,
 * `events`, `session`, `status`).
 *
 * `useOrcelAgent` passes this shape to callbacks such as `onFinish`, but exposes
 * the same fields as individual reactive refs on its return value.
 */
export type UseOrcelAgentSnapshot<TData> = OrcelAgentStoreSnapshot<TData>;

/**
 * Reactive return value from `useOrcelAgent`.
 */
export interface UseOrcelAgentReturn<TData> {
  /** Request durable cancellation of the active turn while continuing to receive its events. */
  readonly cancel: () => Promise<CancelSessionResult>;
  /** Projected state: the reducer folds every stream event into this value. */
  readonly data: ComputedRef<TData>;
  /** Last transport-level error, or `undefined` when healthy. */
  readonly error: ComputedRef<Error | undefined>;
  /** Raw server events from this session (authoritative stream). */
  readonly events: ComputedRef<readonly MessageStreamEvent[]>;
  /** Replay the attached durable session and follow its in-flight turn, if any. */
  readonly resume: () => Promise<void>;
  /** Create the session without starting its first turn. */
  readonly prewarm: () => Promise<void>;
  /** Clear all state and start a new session. */
  readonly reset: () => void;
  /** Send a message with optional turn settings. */
  readonly send: <TOutput = unknown>(
    message: string | UserContent,
    options?: SendTurnOptions<TOutput>,
  ) => Promise<void>;
  /** Answer pending HITL input requests. */
  readonly respond: <TOutput = unknown>(
    inputResponses: Parameters<ClientSession["respond"]>[0],
    options?: RespondTurnOptions<TOutput>,
  ) => Promise<void>;
  /** Current session identity and stream cursor. */
  readonly session: ComputedRef<ClientSessionState | undefined>;
  /**
   * Lifecycle phase: `"ready"` (idle), `"resuming"` (checking an attached
   * session), `"submitted"` (request sent, awaiting first event), `"streaming"`
   * (events arriving), or `"error"`.
   */
  readonly status: ComputedRef<UseOrcelAgentStatus>;
}

/**
 * Configuration for creating or binding a Vue orcel agent session.
 *
 * Session configuration is read once when the composable creates its internal
 * store; to change the host, reducer, or session, remount the component. For
 * credentials or headers that must change without remounting, pass function
 * values to `auth` or `headers`; the client resolves those before each request.
 *
 * Lifecycle callbacks (`onError`, `onEvent`, `onFinish`, `onSessionChange`,
 * `prepareSend`) are inherited from {@link OrcelAgentStoreCallbacks} and synced on
 * every render.
 */
export interface UseOrcelAgentOptions<TData> extends OrcelAgentStoreCallbacks<TData> {
  /**
   * Named agent mounted by a framework integration such as `withEve({ agents })`.
   *
   * `agent: "support"` targets same-origin routes under
   * `/orcel/support/v1/...`. Do not combine with `host`.
   */
  readonly agent?: string;
  /** Authentication configuration; a function value is resolved per request. */
  readonly auth?: ClientAuth;
  /** Custom headers; a function value is resolved per request. */
  readonly headers?: HeadersValue;
  /**
   * Base URL used for orcel client requests. Do not combine with `agent`.
   *
   * By default, requests target same-origin orcel routes such as `/orcel/v1/...`.
   * Pass a same-origin prefix such as `/api` to use an app-owned proxy, or an
   * absolute origin to talk to an orcel server directly.
   *
   * @default ""
   */
  readonly host?: string;
  /** Ordered prefix of the session stream used to rehydrate projected state. */
  readonly initialEvents?: readonly MessageStreamEvent[];
  /** Prior session cursor to resume from on mount. */
  readonly initialSession?: ClientSessionState;
  /**
   * Project submitted user messages before orcel confirms them with a
   * `message.received` stream event.
   *
   * Optimistic events are reducer-facing projection events only. They are not
   * exposed through `events`, which remains the authoritative orcel stream.
   *
   * @default true
   */
  readonly optimistic?: boolean;
  /** Prewarm an owned session on mount and after reset. @default false */
  readonly prewarm?: boolean;
  /**
   * Projects stream events into `TData`.
   *
   * @default defaultMessageReducer()
   */
  readonly reducer?: OrcelAgentReducer<TData>;
  /** Replay the attached durable session after mount. Requires `initialSession` or `session`. */
  readonly resume?: boolean;
  /**
   * Externally owned {@link ClientSession} to bind instead of creating one.
   *
   * When set, `reset()` reuses this session rather than constructing a new one.
   */
  readonly session?: ClientSession;
}

export function useOrcelAgent(
  options?: UseOrcelAgentOptions<OrcelMessageData>,
): UseOrcelAgentReturn<OrcelMessageData>;

export function useOrcelAgent<TData>(
  options: UseOrcelAgentOptions<TData> & { readonly reducer: OrcelAgentReducer<TData> },
): UseOrcelAgentReturn<TData>;

/**
 * Vue composable that drives one orcel session and projects its event stream into
 * reactive UI state.
 *
 * Without a `reducer`, events project into `OrcelMessageData` via
 * `defaultMessageReducer()`; pass `reducer` to project into a custom `TData`.
 * Returns reactive refs (`data`, `error`, `events`, `session`, `status`) plus
 * `prewarm`, `send`, `respond`, `resume`, `cancel`, and `reset`. Configuration is read once on store creation;
 * remount to change it. On scope dispose, the in-flight request is detached and
 * the store unsubscribed.
 */
export function useOrcelAgent<TData>(
  options: UseOrcelAgentOptions<TData> = {},
): UseOrcelAgentReturn<TData> {
  if (options.resume && options.initialSession === undefined && options.session === undefined) {
    throw new Error("useOrcelAgent({ resume: true }) requires initialSession or session.");
  }
  const reducer = options.reducer ?? (defaultMessageReducer() as OrcelAgentReducer<TData>);

  const store = new OrcelAgentStore<TData>({
    auth: options.auth,
    headers: options.headers,
    host: resolveOrcelAgentHost({ agent: options.agent, host: options.host }),
    initialEvents: options.initialEvents,
    initialSession: options.initialSession,
    optimistic: options.optimistic,
    prewarm: options.prewarm,
    reducer,
    session: options.session,
  });

  store.setCallbacks({
    onError: options.onError,
    onEvent: options.onEvent,
    onFinish: options.onFinish,
    onSessionChange: options.onSessionChange,
    prepareSend: options.prepareSend,
  });

  const snapshot = shallowRef<OrcelAgentStoreSnapshot<TData>>(store.snapshot);

  if ("window" in globalThis) {
    const unsubscribe = store.subscribe(() => {
      snapshot.value = store.snapshot;
    });
    attachOrcelAgentStore(store);
    if (options.resume) void store.resume();

    onScopeDispose(() => {
      unsubscribe();
      detachOrcelAgentStore(store);
    });
  }

  return {
    cancel: () => store.cancel(),
    data: computed(() => snapshot.value.data),
    error: computed(() => snapshot.value.error),
    events: computed(() => snapshot.value.events),
    prewarm: () => store.prewarm(),
    reset: () => store.reset(),
    respond: <TOutput = unknown>(
      inputResponses: Parameters<ClientSession["respond"]>[0],
      options?: RespondTurnOptions<TOutput>,
    ) => store.send({ ...options, inputResponses }),
    resume: () => store.resume(),
    send: <TOutput = unknown>(message: string | UserContent, options?: SendTurnOptions<TOutput>) =>
      store.send({ ...options, message }),
    session: computed(() => snapshot.value.session),
    status: computed(() => snapshot.value.status),
  };
}
