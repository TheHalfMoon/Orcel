import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";

import {
  attachKafAgentStore,
  detachKafAgentStore,
  KafAgentStore,
  type KafAgentStoreCallbacks,
  type KafAgentStoreSnapshot,
  type KafAgentStoreStatus,
  type PrepareSend,
} from "#client/kaf-agent-store.js";
import { resolveKafAgentHost } from "#client/agent-host.js";
import type { KafAgentReducer } from "#client/reducer.js";
import type { ClientSession } from "#client/session.js";
import { defaultMessageReducer, type KafMessageData } from "#client/message-reducer.js";
import type { MessageStreamEvent } from "#protocol/message.js";
import type { UserContent } from "ai";
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
 * Lifecycle status of an kaf agent session.
 *
 * - `"ready"`: idle, accepting a new turn.
 * - `"resuming"`: checking an attached session for events; submission is disabled.
 * - `"submitted"`: a turn was sent, no stream events received yet.
 * - `"streaming"`: stream events are arriving for the active turn.
 * - `"error"`: the last turn ended in a terminal failure (see `snapshot.error`).
 */
export type UseKafAgentStatus = KafAgentStoreStatus;

/**
 * Snapshot of an kaf agent session: `data` (the reducer projection), `events`
 * (the authoritative server stream), `session` (resumable cursor), `status`,
 * and `error`.
 */
export type UseKafAgentSnapshot<TData> = KafAgentStoreSnapshot<TData>;

/**
 * Snapshot plus commands returned by `useKafAgent`.
 */
export interface UseKafAgentHelpers<TData> extends UseKafAgentSnapshot<TData> {
  /** Requests durable cancellation of the active turn while continuing to receive its events. */
  readonly cancel: () => Promise<CancelSessionResult>;
  /** Replays the attached durable session and follows its in-flight turn, if any. */
  readonly resume: () => Promise<void>;
  /** Creates the session without starting its first turn. */
  readonly prewarm: () => Promise<void>;
  /** Resets the session: detaches any local stream and clears events and projected data. */
  readonly reset: () => void;
  /** Sends a message. While a turn is active, pass `turnPolicy: "steer"` to replace it. */
  readonly send: <TOutput = unknown>(
    message: string | UserContent,
    options?: SendTurnOptions<TOutput>,
  ) => Promise<void>;
  /** Answers pending HITL input requests. Rejects if a turn is already in flight. */
  readonly respond: <TOutput = unknown>(
    inputResponses: Parameters<ClientSession["respond"]>[0],
    options?: RespondTurnOptions<TOutput>,
  ) => Promise<void>;
}

/**
 * Configuration for creating or binding a React kaf agent session.
 *
 * Session configuration is read when the hook creates its internal store;
 * remount the component to point at a different host, reducer, or session.
 * Lifecycle callbacks update on every render.
 *
 * For credentials or headers that must change without remounting, pass function
 * values to `auth` or `headers`; the client resolves those before each request.
 */
export interface UseKafAgentOptions<TData> extends KafAgentStoreCallbacks<TData> {
  /**
   * Named agent mounted by a framework integration such as `withEve({ agents })`.
   *
   * `agent: "support"` targets same-origin routes under
   * `/kaf/support/v1/...`. Do not combine with `host`.
   */
  readonly agent?: string;
  readonly auth?: ClientAuth;
  readonly headers?: HeadersValue;
  /**
   * Base URL for kaf client requests. Do not combine with `agent`.
   *
   * Defaults to same-origin kaf routes such as `/kaf/v1/...`. Pass a same-origin
   * prefix such as `/api` for an app-owned proxy, or an absolute origin to talk
   * to an kaf server directly.
   *
   * @default ""
   */
  readonly host?: string;
  /** Ordered prefix of the session stream used to rehydrate projected state. */
  readonly initialEvents?: readonly MessageStreamEvent[];
  readonly initialSession?: ClientSessionState;
  /**
   * Project submitted user messages before kaf confirms them with a
   * `message.received` stream event.
   *
   * Optimistic events are reducer-facing projection events only. They are not
   * exposed through `events`, which remains the authoritative kaf stream.
   *
   * @default true
   */
  readonly optimistic?: boolean;
  /**
   * Prewarm an owned session when true. React observes this value across renders;
   * changing it from false to true prepares the current session, and reset checks
   * the latest rendered value before preparing the next session.
   *
   * Changing the value to false does not discard an existing session or abort
   * session creation already in flight.
   *
   * @default false
   */
  readonly prewarm?: boolean;
  readonly reducer?: KafAgentReducer<TData>;
  /**
   * Replay the attached durable session after mount and follow its in-flight
   * turn, if any. Requires `initialSession` or `session`.
   *
   * @default false
   */
  readonly resume?: boolean;
  readonly session?: ClientSession;
}

export function useKafAgent(
  options?: UseKafAgentOptions<KafMessageData>,
): UseKafAgentHelpers<KafMessageData>;

export function useKafAgent<TData>(
  options: UseKafAgentOptions<TData> & { readonly reducer: KafAgentReducer<TData> },
): UseKafAgentHelpers<TData>;

/**
 * React hook that drives an kaf session and projects its event stream into UI data.
 *
 * Returns the current snapshot (`data`, `events`, `session`, `status`, `error`)
 * plus the commands `prewarm`, `send`, `respond`, `resume`, `cancel`, and `reset`. With no reducer, `data` is the
 * built-in `UIMessage` projection from {@link defaultMessageReducer} (`TData`
 * is {@link KafMessageData}); pass a reducer to project into your own shape and
 * infer `TData`.
 *
 * Session-shaping options (`host`, `reducer`, `session`, `initialEvents`,
 * `initialSession`, `auth`, `headers`, `optimistic`, `resume`) are read once
 * when the store is created; remount to change them. `prewarm` and lifecycle
 * callbacks (`onError`, `onEvent`, `onFinish`, `onSessionChange`, `prepareSend`)
 * refresh on every render.
 */
export function useKafAgent<TData>(
  options: UseKafAgentOptions<TData> = {},
): UseKafAgentHelpers<TData> {
  const storeRef = useRef<KafAgentStore<TData> | undefined>(undefined);
  const resumeOnMountRef = useRef(options.resume ?? false);
  const [autoResumePending, setAutoResumePending] = useState(resumeOnMountRef.current);
  const [prewarmResetGeneration, setPrewarmResetGeneration] = useState(0);
  const shouldPrewarm = options.prewarm ?? false;

  if (!storeRef.current) {
    if (
      resumeOnMountRef.current &&
      options.initialSession === undefined &&
      options.session === undefined
    ) {
      throw new Error("useKafAgent({ resume: true }) requires initialSession or session.");
    }
    const reducer = options.reducer ?? (defaultMessageReducer() as KafAgentReducer<TData>);
    storeRef.current = new KafAgentStore({
      auth: options.auth,
      headers: options.headers,
      host: resolveKafAgentHost({ agent: options.agent, host: options.host }),
      initialEvents: options.initialEvents,
      initialSession: options.initialSession,
      optimistic: options.optimistic,
      reducer,
      session: options.session,
    });
  }

  const store = storeRef.current;
  store.setCallbacks({
    onError: options.onError,
    onEvent: options.onEvent,
    onFinish: options.onFinish,
    onSessionChange: options.onSessionChange,
    prepareSend: options.prepareSend,
  });

  const subscribe = useCallback(
    (onStoreChange: () => void) => store.subscribe(onStoreChange),
    [store],
  );
  const snapshot = useSyncExternalStore(
    subscribe,
    () => store.snapshot,
    () => store.snapshot,
  );

  useEffect(() => {
    const timeout = setTimeout(() => attachKafAgentStore(store), 0);
    return () => {
      clearTimeout(timeout);
      detachKafAgentStore(store);
    };
  }, [store]);
  useEffect(() => {
    if (!shouldPrewarm) return;
    const timeout = setTimeout(() => void store.prewarm().catch(() => {}), 0);
    return () => clearTimeout(timeout);
  }, [prewarmResetGeneration, shouldPrewarm, store]);
  useEffect(() => {
    if (!resumeOnMountRef.current) return;
    let active = true;
    const finish = () => {
      if (active) setAutoResumePending(false);
    };
    const timeout = setTimeout(() => void store.resume().then(finish, finish), 0);
    return () => {
      active = false;
      clearTimeout(timeout);
    };
  }, [store]);

  const cancel = useCallback(() => store.cancel(), [store]);
  const reset = useCallback(() => {
    store.reset();
    setPrewarmResetGeneration((generation) => generation + 1);
  }, [store]);
  const prewarm = useCallback(() => store.prewarm(), [store]);
  const resume = useCallback(() => store.resume(), [store]);
  const send = useCallback(
    <TOutput = unknown>(message: string | UserContent, options?: SendTurnOptions<TOutput>) => {
      return store.send({ ...options, message });
    },
    [store],
  );
  const respond = useCallback(
    <TOutput = unknown>(
      inputResponses: Parameters<ClientSession["respond"]>[0],
      options?: RespondTurnOptions<TOutput>,
    ) => store.send({ ...options, inputResponses }),
    [store],
  );
  const visibleSnapshot =
    autoResumePending && snapshot.status === "ready"
      ? { ...snapshot, status: "resuming" as const }
      : snapshot;

  return useMemo(
    () => ({
      ...visibleSnapshot,
      cancel,
      prewarm,
      reset,
      respond,
      resume,
      send,
    }),
    [cancel, prewarm, reset, respond, resume, send, visibleSnapshot],
  );
}
