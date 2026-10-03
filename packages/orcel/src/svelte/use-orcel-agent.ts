import { onMount } from "svelte";
import { createSubscriber } from "svelte/reactivity";
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
import { defaultMessageReducer, type OrcelMessageData } from "#client/message-reducer.js";
import type { OrcelAgentReducer } from "#client/reducer.js";
import type { ClientSession } from "#client/session.js";
import type {
  CancelSessionResult,
  ClientAuth,
  HeadersValue,
  RespondTurnOptions,
  SendTurnOptions,
  ClientSessionState,
} from "#client/types.js";
import type { MessageStreamEvent } from "#protocol/message.js";

export type { PrepareSend };

/**
 * Session lifecycle phase: `"ready"` (idle), `"resuming"` (checking an
 * attached session), `"submitted"` (request sent, awaiting the first stream
 * event), `"streaming"` (events arriving), or `"error"`.
 */
export type UseOrcelAgentStatus = OrcelAgentStoreStatus;

/**
 * Immutable point-in-time view of an orcel agent session: projected `data`, the
 * last `error`, the raw `events` stream, the `session` cursor, and `status`.
 * `useOrcelAgent` passes this snapshot to the `onFinish` callback.
 */
export type UseOrcelAgentSnapshot<TData> = OrcelAgentStoreSnapshot<TData>;

/**
 * Reactive return value from `useOrcelAgent`.
 *
 * The state properties are Svelte 5 rune-friendly getters. Read them from a
 * template, `$derived`, or `$effect` and Svelte will update when orcel streams
 * new events.
 */
export interface UseOrcelAgentReturn<TData> {
  /** Request durable cancellation of the active turn while continuing to receive its events. */
  readonly cancel: () => Promise<CancelSessionResult>;
  /** Projected state built by reducing every stream event through the reducer. */
  readonly data: TData;
  /** Last transport-level error, or `undefined` when healthy. */
  readonly error: Error | undefined;
  /** Raw server events received during this session (authoritative stream). */
  readonly events: readonly MessageStreamEvent[];
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
  readonly session: ClientSessionState | undefined;
  /**
   * Lifecycle phase: `"ready"` (idle), `"resuming"` (checking an attached
   * session), `"submitted"` (request sent, awaiting first event), `"streaming"`
   * (events arriving), or `"error"`.
   */
  readonly status: UseOrcelAgentStatus;
}

/**
 * Configuration for a Svelte orcel agent session.
 *
 * Read once when `useOrcelAgent` creates its store; create a new binding to
 * change host, reducer, or session. To rotate credentials or headers without
 * recreating the binding, pass function values to `auth` or `headers`, which
 * the client resolves before each HTTP request.
 */
export interface UseOrcelAgentOptions<TData> extends OrcelAgentStoreCallbacks<TData> {
  /**
   * Named agent mounted by a framework integration such as `withEve({ agents })`.
   *
   * `agent: "support"` targets same-origin routes under
   * `/orcel/support/v1/...`. Do not combine with `host`.
   */
  readonly agent?: string;
  /**
   * Credentials for the auto-created session. Pass function values to refresh
   * per request. Ignored when `session` is supplied.
   */
  readonly auth?: ClientAuth;
  /**
   * Custom headers for the auto-created session. Pass a function to resolve
   * fresh values per request. Ignored when `session` is supplied.
   */
  readonly headers?: HeadersValue;
  /**
   * Base URL for orcel client requests. Do not combine with `agent`. Empty targets same-origin orcel routes
   * such as `/orcel/v1/...`; a same-origin prefix like `/api` routes through an
   * app-owned proxy; an absolute origin hits an orcel server directly.
   *
   * @default ""
   */
  readonly host?: string;
  /** Ordered prefix of the session stream used to rehydrate projected state. */
  readonly initialEvents?: readonly MessageStreamEvent[];
  /** Seed session identity and stream cursor for resuming a prior conversation. */
  readonly initialSession?: ClientSessionState;
  /**
   * Project submitted user messages before orcel confirms them with a
   * `message.received` stream event. Optimistic events are reducer-facing
   * projection only and never appear in `events`, which stays the
   * authoritative orcel stream.
   *
   * @default true
   */
  readonly optimistic?: boolean;
  /** Prewarm an owned session on mount and after reset. @default false */
  readonly prewarm?: boolean;
  /**
   * Projects stream events into `TData`. Defaults to {@link defaultMessageReducer},
   * which fixes `TData` to {@link OrcelMessageData}.
   */
  readonly reducer?: OrcelAgentReducer<TData>;
  /** Replay the attached durable session after mount. Requires `initialSession` or `session`. */
  readonly resume?: boolean;
  /**
   * Pre-built client session to bind to. When omitted, the binding creates its
   * own session from `auth`, `headers`, and `host`.
   */
  readonly session?: ClientSession;
}

class SvelteOrcelAgent<TData> implements UseOrcelAgentReturn<TData> {
  #snapshot: OrcelAgentStoreSnapshot<TData>;
  readonly #store: OrcelAgentStore<TData>;
  readonly #subscribe: () => void;

  constructor(store: OrcelAgentStore<TData>) {
    this.#store = store;
    this.#snapshot = store.snapshot;
    this.#subscribe = createSubscriber((update) => {
      if (!("window" in globalThis)) return;

      const unsubscribe = store.subscribe(() => {
        this.#snapshot = store.snapshot;
        update();
      });

      return () => {
        unsubscribe();
      };
    });
  }

  get data(): TData {
    this.#subscribe();
    return this.#snapshot.data;
  }

  get error(): Error | undefined {
    this.#subscribe();
    return this.#snapshot.error;
  }

  get events(): readonly MessageStreamEvent[] {
    this.#subscribe();
    return this.#snapshot.events;
  }

  get session(): ClientSessionState | undefined {
    this.#subscribe();
    return this.#snapshot.session;
  }

  get status(): UseOrcelAgentStatus {
    this.#subscribe();
    return this.#snapshot.status;
  }

  cancel = (): Promise<CancelSessionResult> => {
    return this.#store.cancel();
  };

  reset = (): void => {
    this.#store.reset();
  };

  prewarm = (): Promise<void> => {
    return this.#store.prewarm();
  };

  resume = (): Promise<void> => {
    return this.#store.resume();
  };

  respond = <TOutput = unknown>(
    inputResponses: Parameters<ClientSession["respond"]>[0],
    options?: RespondTurnOptions<TOutput>,
  ): Promise<void> => {
    return this.#store.send({ ...options, inputResponses });
  };

  send = <TOutput = unknown>(
    message: string | UserContent,
    options?: SendTurnOptions<TOutput>,
  ): Promise<void> => {
    return this.#store.send({ ...options, message });
  };
}

export function useOrcelAgent(
  options?: UseOrcelAgentOptions<OrcelMessageData>,
): UseOrcelAgentReturn<OrcelMessageData>;

export function useOrcelAgent<TData>(
  options: UseOrcelAgentOptions<TData> & { readonly reducer: OrcelAgentReducer<TData> },
): UseOrcelAgentReturn<TData>;

/**
 * Svelte 5 binding that drives an orcel session and projects its events into
 * rune-friendly reactive data.
 *
 * Without a `reducer`, projects to {@link OrcelMessageData} via
 * {@link defaultMessageReducer}; pass a `reducer` for a different `TData`.
 * Configuration is read once; create a new binding to change host, reducer,
 * or session.
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
  if ("window" in globalThis)
    onMount(() => {
      attachOrcelAgentStore(store);
      if (options.resume) void store.resume();
      return () => detachOrcelAgentStore(store);
    });

  return new SvelteOrcelAgent(store);
}
