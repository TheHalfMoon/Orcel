import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { KernelClient, type RemoteDispatchContext } from "../kernel.js";
import {
  buildOrcelServer,
  closeAllServerKernels,
  localTransportContext,
  tunnelTransportContext,
  type TransportContext
} from "../server.js";
import {
  TRANSPORT_ENV,
  TUNNEL_ROUTE_ENV,
  TUNNEL_TRANSPORT,
  parseTunnelRoute,
  tunnelRemoteContext
} from "../tunnel_route.js";

/** What one stdio process serves, fixed at transport start. */
export interface StdioSessionConfig {
  readonly context: TransportContext;
  /** Remote context stamped on every `orceld` request; null for local. */
  readonly remote: RemoteDispatchContext | null;
  /** Local profile stamped on every `orceld` request; null for remote. */
  readonly profile: string | null;
  readonly defaultWorkspace: string;
}

/**
 * Select the stdio session from the launch environment. Without
 * `ORCEL_MCP_TRANSPORT` this is a local client (Claude Desktop, Codex, ...)
 * with its locally configured profile. The tunnel host always sets it to
 * `tunnel` (#395): the remote `core` profile and the tunnel's remote route,
 * and `ORCEL_TOOL_SURFACE_PROFILE` is ignored. Any other value fails closed.
 */
export function stdioSessionConfig(env: NodeJS.ProcessEnv = process.env): StdioSessionConfig {
  const defaultWorkspace = env.ORCEL_DEFAULT_WORKSPACE ?? "default";
  const transport = env[TRANSPORT_ENV];
  if (transport === undefined) {
    const context = localTransportContext(env);
    return { context, remote: null, profile: context.toolSurfaceProfile, defaultWorkspace };
  }
  if (transport !== TUNNEL_TRANSPORT) {
    throw new Error(`TRANSPORT_UNAVAILABLE: unknown ${TRANSPORT_ENV}`);
  }
  const route = parseTunnelRoute(env[TUNNEL_ROUTE_ENV]);
  return {
    context: tunnelTransportContext(route.paired.providerKind),
    remote: tunnelRemoteContext(route),
    profile: null,
    defaultWorkspace
  };
}

/** The server factory the stdio transport serves; tests inject the kernel. */
export function stdioServerFactory(
  config: StdioSessionConfig,
  kernelFactory: (config: StdioSessionConfig) => KernelClient = (c) =>
    new KernelClient(undefined, c.remote, c.profile),
  tracked: Set<KernelClient> = new Set()
) {
  return function createServer() {
    const kernel = kernelFactory(config);
    tracked.add(kernel);
    const server = buildOrcelServer(kernel, config.defaultWorkspace, config.context);
    const previousOnClose = server.server.onclose;
    server.server.onclose = () => {
      tracked.delete(kernel);
      if (previousOnClose) {
        previousOnClose();
      } else {
        kernel.close();
      }
    };
    return server;
  };
}

/**
 * Start the supported stdio transport using the authoritative builder.
 *
 * It creates tools exclusively through `buildOrcelServer`, and adds no
 * independent tool authority and no transport-controlled tool fields.
 */
export function startStdioTransport() {
  const tracked = new Set<KernelClient>();
  const config = stdioSessionConfig();

  const handle = serveStdio(stdioServerFactory(config, undefined, tracked));
  process.stderr.write(
    `[orcel-mcp] serving Orcel SG-000017 tools over stdio (${config.context.transportKind}, ${config.context.toolSurfaceProfile})\n`
  );

  function shutdown(): void {
    for (const client of tracked) {
      try {
        client.close();
      } catch {
        // Fail closed on shutdown.
      }
    }
    tracked.clear();
    closeAllServerKernels();
    void handle.close().finally(() => process.exit(0));
  }

  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);

  return { handle, shutdown };
}
