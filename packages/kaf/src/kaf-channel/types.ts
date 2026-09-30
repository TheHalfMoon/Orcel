import type { UserContent } from "ai";

import type { SessionAuthContext, TurnPolicy } from "#channel/types.js";
import type { TrustedForwarders } from "#channel/forwarded-principal.js";
import type { AuthFn } from "#public/channels/auth.js";
import type { UploadPolicyInput } from "#public/channels/upload-policy.js";
import type {
  AudienceContext,
  Channel,
  ChannelContinuationOps,
  ChannelEvents,
  ChannelMethod,
} from "#public/definitions/channel.js";
import type { ChannelAudience } from "#shared/channel-audience.js";

export type { ForwardedAssertion, TrustedForwarders } from "#channel/forwarded-principal.js";

/**
 * Event-handler channel context exposed by `kafChannel({ events })`. The default kaf HTTP channel
 * has no platform-specific state, so handlers receive optional continuation routing here and the
 * `SessionContext` third argument from {@link ChannelEvents}.
 */
export type KafEventContext = ChannelContinuationOps;

/** Runtime stream-event handlers supported by `kafChannel({ events })`. */
export type KafChannelEvents = ChannelEvents<KafEventContext>;

export interface KafChannelCorsOptions {
  /**
   * Allowed request origin. Pass a single origin string, an exact-origin list,
   * `"null"`, or `"*"`. Omit for `"*"`.
   */
  readonly origin?: "*" | "null" | string | readonly string[];
  /** Methods emitted on preflight responses. Omit for `"*"`. */
  readonly methods?: "*" | readonly ChannelMethod[];
  /** Request headers emitted on preflight responses. Omit for `"*"`. */
  readonly allowedHeaders?: "*" | readonly string[];
  /** Response headers exposed to browser callers. Omit for `"*"`. */
  readonly exposedHeaders?: "*" | readonly string[];
  /** Whether to emit `access-control-allow-credentials: true`. */
  readonly credentials?: boolean;
  /** Max age, in seconds, emitted on preflight responses. */
  readonly maxAge?: number | false;
  /** Preflight response status code. Defaults to 204. */
  readonly preflightStatus?: number;
}

/**
 * Higher-level CORS policy for the default kaf HTTP channel. Pass `true` for
 * fully permissive browser access, or pass an options object to narrow it.
 */
export type KafChannelCors = boolean | KafChannelCorsOptions;

/** Low-level kaf HTTP handle exposed to `kafChannel({ onMessage })`. */
export interface KafHandle {
  /** Route-auth result for the request; `onMessage` chooses session auth by returning `{ auth }`. */
  readonly caller: SessionAuthContext | null;
  /** Replay-stable identity of a trusted remote-subagent create operation. */
  readonly invocation?: { readonly operationId: string };
  readonly request: Request;
  /** Existing runtime session id for follow-up requests. */
  readonly sessionId?: string;
}

/** Pre-dispatch context passed to `kafChannel({ onMessage })`. */
export interface KafMessageContext {
  readonly kaf: KafHandle;
}

/**
 * Result of `kafChannel({ onMessage })`. The object dispatches the inbound message,
 * optionally prepending `context` strings as user messages.
 */
export type KafMessageResult = {
  readonly auth: SessionAuthContext | null;
  readonly context?: readonly string[];
  /** Sets the title when creating a workflow or sending its first message after prewarming. */
  readonly title?: string;
};

/** Synchronous or asynchronous `onMessage` result. */
export type KafMessageResultOrPromise = KafMessageResult | Promise<KafMessageResult>;

/**
 * Default `onMessage` auth projection: returns {@link KafHandle.caller} unchanged as the
 * runtime session auth when {@link KafChannelInput.onMessage} is omitted. Call it from a custom `onMessage` to inherit the default while adding `context`.
 */
export function defaultKafAuth(ctx: KafMessageContext): SessionAuthContext | null {
  return ctx.kaf.caller;
}

/**
 * Configuration for {@link kafChannel}. Only {@link auth} is required;
 * `uploadPolicy`, `onMessage`, and `events` refine the default HTTP behavior.
 */
export interface KafChannelInput {
  /**
   * Route auth policy: a single {@link AuthFn} or an ordered array walked by {@link routeAuth}.
   * The first entry returning a {@link SessionAuthContext} wins; `null` / `undefined` skips to
   * the next; exhaustion (including the empty array) rejects with 401. Include `none()` last for anonymous traffic.
   */
  readonly auth: AuthFn<Request> | readonly AuthFn<Request>[];
  /**
   * Conversation audience classification, fixed when the session is created.
   *
   * By default, `user`, `service`, and `runtime` principals are `private`.
   * Anonymous callers and every other principal type are `unknown`, which
   * trace consumers treat as non-public.
   *
   * Pass a constant audience, or a function receiving the authenticated
   * principal, channel, and deployment environment. Continuation
   * turns from a different caller do not reclassify an existing session.
   */
  readonly audience?:
    | ChannelAudience
    | ((input: Omit<AudienceContext<undefined>, "state">) => ChannelAudience);
  /**
   * The trusted-forwarders policy: which transport-authenticated callers may
   * assert a forwarded principal, callback-marked public trace audience, or
   * remote parent lineage. The predicate receives the *verified* route-auth
   * principal of the forwarder and must match it precisely (for example
   * `(forwarder) => forwarder.subject === vercelSubject({ teamSlug, projectName })`).
   * A permissive predicate lets any authenticated forwarder assert any principal,
   * public trace audience, or remote lineage.
   *
   * The second argument carries what the forwarder asserts. `assertion.principal`
   * holds the stamped `current` and `initiator` contexts the forwarder asserts,
   * so a receiver can limit a forwarder to the identities it may speak for, such as
   * one authenticator and issuer. `initiator` takes effect only on session
   * creation; on continuation it is the asserted value, not the session's pinned
   * initiator. `assertion.principal` is absent when the predicate decides remote
   * parent lineage for a request that forwards no principal.
   *
   * When a trusted forwarder's assertion is accepted on session creation, the
   * forwarded principal replaces `session.auth.current` and
   * `session.auth.initiator`. On continuation, only `session.auth.current`
   * changes; the initiator remains pinned to the session's creator. The
   * forwarder is recorded on accepted contexts as the `kaf:forwarded-by`
   * attribute. An accepted public audience is evaluated by this deployment's
   * trace policies; the default records model and tool content. Omit the option
   * to reject forwarded principals with 403 and ignore forwarded audience and
   * remote lineage.
   */
  readonly trustedForwarders?: TrustedForwarders;
  /**
   * Attachment policy for inbound file parts. Omit for the framework default (25 MB cap, all media
   * types); `"disabled"` rejects every attachment; a partial config is merged onto the default. Violations reject with 413 (too large) or 415 (bad type).
   */
  readonly uploadPolicy?: UploadPolicyInput;
  /**
   * Browser CORS policy for the kaf HTTP routes. Omit or pass `false` to leave
   * CORS untouched, pass `true` for fully permissive CORS, or pass an options
   * object to narrow the policy.
   */
  readonly cors?: KafChannelCors;
  /** Policy for follow-up messages that arrive while a turn is active. */
  readonly turnPolicy?: TurnPolicy;
  /**
   * Pre-dispatch hook for inbound kaf HTTP messages. Runs after route auth and body
   * parsing, before runtime dispatch. Message-free creation skips this hook and
   * parks before session initialization. The first message supplies auth and context
   * for initialization and its first turn.
   */
  readonly onMessage?: (
    ctx: KafMessageContext,
    message: string | UserContent,
  ) => KafMessageResultOrPromise;
  /**
   * Runtime stream-event handlers for the default kaf HTTP channel. Handlers receive
   * the event data, {@link KafEventContext}, and `SessionContext` (the same shape as custom channels).
   */
  readonly events?: KafChannelEvents;
}

/**
 * Concrete return type of {@link kafChannel}. Named so consumers can default-export an
 * `kafChannel(...)` call under `declaration: true` without TypeScript falling back to an
 * internal path for `Channel`.
 */
export interface KafChannel extends Channel {}
