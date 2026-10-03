import type { HeadersValue } from "#client/types.js";
import type { OutboundAuthFn } from "#public/agents/auth.js";
import { ORCEL_SESSION_ROUTE_PATH } from "#protocol/routes.js";

/**
 * Base URL of a remote orcel deployment, either a static string or a function
 * resolved at runtime. Use the function form to read `process.env` for a URL
 * known only once the deployment runs. A string is baked into the compiled
 * manifest; a function is invoked when the runtime resolves the agent graph.
 */
export type RemoteAgentUrl = string | (() => string | Promise<string>);

/**
 * Public definition for a remote orcel agent. The compiler lowers it to a
 * subagent tool.
 */
export interface RemoteAgentDefinition {
  readonly auth?: OutboundAuthFn;
  /**
   * The parent agent reads this as the lowered subagent tool's description.
   */
  readonly description: string;
  /**
   * Forwards the dispatching turn's session principal to the remote
   * deployment as the `forwardedPrincipal` session-request body field, so
   * each remote turn runs as the same end user as the parent (per-user
   * Connect, local subagents, and further remote hops all see that active
   * principal). Session creation forwards current and initiator identity;
   * continuation forwards only the active caller and leaves the remote
   * session's initiator pinned. Defaults to `false` — forwarding identity to
   * another deployment is an explicit decision, never ambient.
   *
   * When the parent trace is sampled and its audience is public, the same
   * option adds `orcel.audience=public` to W3C Baggage. A receiver that accepts
   * this deployment through `orcelChannel({ trustedForwarders })` uses that
   * audience for its own trace policy. Only principal and public-audience
   * metadata cross the wire, never tokens or credentials — {@link auth} keeps
   * authenticating *this* deployment to the remote.
   * a receiver that refuses the forwarder (or accepts no forwarded principal
   * at all) rejects with 403 and the dispatch fails.
   */
  readonly forwardPrincipal?: boolean;
  readonly headers?: HeadersValue;
  readonly kind: "remote";
  /**
   * Route orcel appends to `url` for the create-session request. Defaults to the
   * framework create-session route (`/orcel/v1/session`).
   */
  readonly path: string;
  /**
   * Whether orcel exposes this remote agent to the parent model as a tool.
   * Defaults to `true`; `false` keeps it callable from workflow tools.
   */
  readonly tool?: boolean;
  /**
   * Base URL of the remote orcel deployment to call. Accepts a static string
   * (baked at compile time) or a function resolved at runtime — use the
   * function form to read a URL from `process.env`.
   */
  readonly url: RemoteAgentUrl;
}

/**
 * Authored input that {@link defineRemoteAgent} accepts. orcel derives identity
 * from the file path under `agent/subagents/`; authored definitions do not
 * carry a `name` field.
 */
export type RemoteAgentDefinitionInput = Omit<RemoteAgentDefinition, "kind" | "path"> & {
  readonly path?: string;
};

/**
 * Defines a remote orcel agent that the parent can call as a subagent tool. The
 * compiler lowers it at compile time from the file path under `agent/subagents/`.
 *
 * Stamps `kind: "remote"` and, when `path` is omitted, defaults it to the
 * framework create-session route (`/orcel/v1/session`) on the target `url`.
 */
export function defineRemoteAgent(input: RemoteAgentDefinitionInput): RemoteAgentDefinition {
  return {
    ...input,
    kind: "remote",
    path: input.path ?? ORCEL_SESSION_ROUTE_PATH,
  };
}
