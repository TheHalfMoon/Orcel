import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { registerClipboardNetworkTools } from "./clipboard_network.js";
import { registerDesktopTools } from "./desktop.js";
import { registerFsMutationTools } from "./fs_mutation.js";
import { registerGitFetchTools } from "./git_fetch.js";
import { registerGitMutationTools } from "./git_mutation.js";
import { registerGitPushTools } from "./git_push.js";
import { KernelClient } from "./kernel.js";
import { processSpawnInputSchema } from "./process.js";
import { projectKernelResult } from "./result.js";
import { registerReportTools } from "./report.js";
import { registerWebSearchTools } from "./web_search.js";
import { registerLiveBrowserTools } from "./browser_live.js";
import {
  TOOL_CONTRACT,
  TOOL_SURFACE_PROFILE_ENV,
  localProfileFromConfig,
  profileTools,
  remoteProfileForProvider,
  securitySchemesFor,
  type ToolSurfaceProfile
} from "./tool_contract.js";

/**
 * Transport identity for the local MCP edge.
 *
 * These fields are request context supplied by the transport adapter.
 * They are never caller-controlled tool fields and never grant authority.
 * The frozen vocabulary comes from SG-000047:
 * transport_kind, provider_kind, tool_surface_profile.
 */
export type TransportKind = "stdio" | "loopback_http" | "relay" | "tunnel";

/** Remote transports serve only the profile mapped for their provider. */
export function isRemoteTransport(kind: TransportKind): boolean {
  return kind === "relay" || kind === "tunnel";
}

export interface TransportContext {
  readonly transportKind: TransportKind;
  readonly providerKind: string;
  readonly toolSurfaceProfile: ToolSurfaceProfile;
}

/**
 * Local transports (stdio and loopback HTTP) serve the `desktop_structured`
 * profile, which adds the local-only tools to `core`. The relay transport
 * serves `core` only.
 */
export function defaultTransportContext(): TransportContext {
  return {
    transportKind: "stdio",
    providerKind: "generic",
    toolSurfaceProfile: "desktop_structured"
  };
}

/**
 * A local transport's context: `desktop_structured` unless the local
 * configuration (`ORCEL_TOOL_SURFACE_PROFILE` in the MCP client's server
 * launch environment) selects `browser_structured`. Read once, at transport
 * start; an unknown value fails startup.
 */
export function localTransportContext(env: NodeJS.ProcessEnv = process.env): TransportContext {
  return {
    ...defaultTransportContext(),
    toolSurfaceProfile: localProfileFromConfig(env[TOOL_SURFACE_PROFILE_ENV])
  };
}

/**
 * #395: the ChatGPT Secure MCP Tunnel's context. It is remote, so it serves
 * the `core` profile; no local configuration can select another one.
 */
export function tunnelTransportContext(providerKind: string): TransportContext {
  return {
    transportKind: "tunnel",
    providerKind,
    toolSurfaceProfile: "core"
  };
}

/**
 * Resolve the tools a transport context may register. A remote transport
 * (the relay or the tunnel) may serve only the profile mapped for its
 * provider kind, which is `core` for every known provider; unknown provider
 * kinds and unmapped profiles fail closed.
 */
export function allowedToolsFor(context: TransportContext): ReadonlySet<string> {
  if (isRemoteTransport(context.transportKind)) {
    const mapped = remoteProfileForProvider(context.providerKind);
    if (mapped === null || mapped !== context.toolSurfaceProfile) {
      throw new Error("TOOL_SURFACE_DENIED: the remote provider kind or tool surface profile is not mapped");
    }
  }
  return profileTools(context.toolSurfaceProfile);
}

/**
 * Wrap the server so every registration is checked against the tool
 * contract: a tool without a contract entry fails startup, a tool outside
 * the profile is not registered, and the contract's title and annotations
 * are attached on every transport.
 */
function contractGatedServer(server: McpServer, allowed: ReadonlySet<string>): McpServer {
  const registerTool = (name: string, config: Record<string, unknown>, handler: unknown): unknown => {
    const entry = TOOL_CONTRACT[name];
    if (entry === undefined) {
      throw new Error(`tool ${name} has no SG-000065 contract entry`);
    }
    if (!allowed.has(name)) {
      return undefined;
    }
    const { title, ...hints } = entry.annotations;
    const meta = securitySchemesFor(name);
    return (server.registerTool as unknown as (n: string, c: Record<string, unknown>, h: unknown) => unknown).call(
      server,
      name,
      { ...config, title, annotations: { title, ...hints }, ...(meta === null ? {} : { _meta: { securitySchemes: meta } }) },
      handler
    );
  };
  return new Proxy(server, {
    get(target, property, receiver) {
      if (property === "registerTool") {
        return registerTool;
      }
      return Reflect.get(target, property, receiver) as unknown;
    }
  });
}

/**
 * The closed Orcel v0.1 public MCP tool catalog.
 * Adding a tool requires a governed grain. Transport adapters must not
 * register tools independently; they must reuse `registerOrcelTools`.
 */
export const CANONICAL_TOOL_NAMES: readonly string[] = [
  "browser_click",
  "browser_download",
  "browser_download_preview",
  "browser_navigate",
  "browser_observe",
  "browser_page_open",
  "clipboard_read",
  "clipboard_write",
  "desktop_cursor_get",
  "desktop_element_invoke",
  "desktop_element_scroll",
  "desktop_element_select",
  "desktop_element_set_value",
  "desktop_element_toggle",
  "desktop_input_execute",
  "desktop_window_action",
  "desktop_window_capture",
  "desktop_window_list",
  "desktop_window_tree",
  "fs_edit",
  "fs_find",
  "fs_list",
  "fs_mkdir",
  "fs_move",
  "fs_read",
  "fs_read_range",
  "fs_remove",
  "fs_search",
  "fs_stat",
  "fs_write",
  "fs_write_preview",
  "git_branch_create",
  "git_commit",
  "git_diff",
  "git_fetch",
  "git_fetch_preview",
  "git_log",
  "git_push",
  "git_push_preview",
  "git_stage",
  "git_status",
  "git_unstage",
  "process_spawn",
  "report_commit",
  "report_preview",
  "report_start",
  "system_status",
  "task_resume_summary",
  "web_fetch",
  "web_search",
  "workspace_get"
];

const activeKernels = new Set<KernelClient>();

function trackKernel(kernel: KernelClient): void {
  activeKernels.add(kernel);
}

function untrackKernel(kernel: KernelClient): void {
  activeKernels.delete(kernel);
}

/**
 * Close all kernels tracked by the server builder.
 * Transport shutdown paths call this to preserve v0.1 SIGINT/SIGTERM behavior.
 */
export function closeAllServerKernels(): void {
  for (const tracked of activeKernels) {
    try {
      tracked.close();
    } catch {
      // Fail closed on shutdown; the transport is terminating.
    }
  }
  activeKernels.clear();
}

/**
 * Register the complete authoritative tool catalog on the given server.
 *
 * This is the single source of truth for tool registration. The schemas,
 * descriptions, capability mappings, and timeouts below are byte-compatible
 * with the Orcel v0.1 public surface. Transport-specific code must call this
 * function and must not call `server.registerTool` directly.
 */
export function registerOrcelTools(
  server: McpServer,
  kernel: KernelClient,
  defaultWorkspace: string,
  context: TransportContext = defaultTransportContext()
): void {
  server = contractGatedServer(server, allowedToolsFor(context));
  const workspaceSchema = z.object({
    workspace_id: z.string().min(1).default(defaultWorkspace)
  });

  server.registerTool(
    "system_status",
    {
      description: "Read Orcel daemon status. This tool does not mutate the computer.",
      inputSchema: workspaceSchema
    },
    async ({ workspace_id }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "system.status",
          operation: "get"
        })
      )
  );

  server.registerTool(
    "workspace_get",
    {
      description: "Read the configured trusted workspace metadata.",
      inputSchema: workspaceSchema
    },
    async ({ workspace_id }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "workspace.get",
          operation: "get"
        })
      )
  );

  server.registerTool(
    "fs_stat",
    {
      description: "Read metadata for a relative path inside a trusted workspace.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1)
      })
    },
    async ({ workspace_id, path }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "fs.stat",
          operation: "stat",
          target: path
        })
      )
  );

  server.registerTool(
    "fs_list",
    {
      description: "List one directory inside a trusted workspace without following symlinks.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1).default(".")
      })
    },
    async ({ workspace_id, path }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "fs.list",
          operation: "list",
          target: path
        })
      )
  );

  server.registerTool(
    "fs_read",
    {
      description: "Read one bounded UTF-8 text file inside a trusted workspace.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1)
      })
    },
    async ({ workspace_id, path }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "fs.read",
          operation: "read",
          target: path
        })
      )
  );

  server.registerTool(
    "fs_search",
    {
      description:
        "Search bounded UTF-8 text files inside a trusted workspace. Symlinks are not followed.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1).default("."),
        query: z.string().min(1),
        max_results: z.number().int().min(1).max(200).default(50)
      })
    },
    async ({ workspace_id, path, query, max_results }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "fs.search",
          operation: "search",
          target: path,
          arguments: { query, max_results }
        })
      )
  );

  server.registerTool(
    "fs_write_preview",
    {
      description:
        "Preview an exact UTF-8 file write. This does not mutate the computer and returns the current/new SHA-256 values required for an approved write.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1),
        content: z.string().max(2 * 1024 * 1024)
      })
    },
    async ({ workspace_id, path, content }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "fs.write",
          operation: "preview",
          target: path,
          arguments: { content }
        })
      )
  );

  server.registerTool(
    "fs_write",
    {
      description:
        "Write exact UTF-8 content inside a trusted workspace after an independent local Orcel approval. Existing files require the current SHA-256 from fs_write_preview.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1),
        content: z.string().max(2 * 1024 * 1024),
        expected_current_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional(),
        create_if_missing: z.boolean().default(false)
      })
    },
    async ({
      workspace_id,
      path,
      content,
      expected_current_sha256,
      create_if_missing
    }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "fs.write",
          operation: "write",
          target: path,
          arguments: {
            content,
            expected_current_sha256,
            create_if_missing
          },
          timeoutMs: 5 * 60_000
        })
      )
  );

  server.registerTool(
    "process_spawn",
    {
      description:
        "Execute one argv-only process after fresh local approval inside the selected trusted workspace. No shell string, caller environment, stdin payload, background mode, or process network authority is exposed.",
      inputSchema: processSpawnInputSchema
    },
    async ({
      workspace_id,
      executable,
      argv,
      cwd,
      timeout_ms,
      stdout_bytes,
      stderr_bytes,
      stdin_policy,
      network_class
    }) => {
      const processKernel = new KernelClient(undefined, null, kernel.profile);
      trackKernel(processKernel);
      try {
        return projectKernelResult(
          await processKernel.call({
            workspaceId: workspace_id,
            capability: "process.spawn",
            operation: "spawn",
            arguments: {
              executable,
              argv,
              cwd,
              timeout_ms,
              stdout_bytes,
              stderr_bytes,
              stdin_policy,
              network_class
            },
            timeoutMs: timeout_ms + 5 * 60_000
          })
        );
      } finally {
        untrackKernel(processKernel);
        processKernel.close();
      }
    }
  );

  server.registerTool(
    "git_status",
    {
      description:
        "Read Git working-tree and branch status for a repository inside a trusted workspace. This tool does not mutate Git state.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1).default(".")
      })
    },
    async ({ workspace_id, path }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.status",
          operation: "status",
          target: path
        })
      )
  );

  server.registerTool(
    "git_diff",
    {
      description:
        "Read a bounded Git diff for a repository inside a trusted workspace. External diff and textconv are disabled.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1).default("."),
        staged: z.boolean().default(false)
      })
    },
    async ({ workspace_id, path, staged }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.diff",
          operation: "diff",
          target: path,
          arguments: { staged }
        })
      )
  );

  server.registerTool(
    "git_log",
    {
      description:
        "Read bounded Git commit history for a repository inside a trusted workspace.",
      inputSchema: z.object({
        workspace_id: z.string().min(1).default(defaultWorkspace),
        path: z.string().min(1).default("."),
        max_count: z.number().int().min(1).max(100).default(20)
      })
    },
    async ({ workspace_id, path, max_count }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.log",
          operation: "log",
          target: path,
          arguments: { max_count }
        })
      )
  );

  registerGitMutationTools(server, kernel, defaultWorkspace);
  registerFsMutationTools(server, kernel, defaultWorkspace);
  registerDesktopTools(server, kernel, defaultWorkspace);
  registerClipboardNetworkTools(server, kernel, defaultWorkspace);
  registerWebSearchTools(server, kernel, defaultWorkspace);
  registerReportTools(server, kernel, defaultWorkspace);
  // SG-000108 slice 3c: registered only where the profile lists them.
  registerLiveBrowserTools(server, kernel, defaultWorkspace);
  registerGitFetchTools(server, kernel, defaultWorkspace);
  registerGitPushTools(server, kernel, defaultWorkspace);
}

/**
 * GHSA-46jr-4wx8-v453: the SDK validates every array element and object
 * member of a `tools/call` payload, so a request within the body bound
 * could exhaust memory. The largest legitimate input is `git_stage` with
 * 128 paths and four other fields; anything above this bound is refused
 * before schema validation, on every transport.
 */
export const MAX_TOOL_INPUT_ELEMENTS = 1024;

/**
 * Build a Orcel MCP server using the authoritative tool catalog.
 *
 * The caller supplies the kernel so tests can inject a stub without
 * spawning `orceld`. Transport adapters must use this builder and must not
 * register tools independently.
 */
export function buildOrcelServer(
  kernel: KernelClient,
  defaultWorkspace: string,
  context: TransportContext = defaultTransportContext()
): McpServer {
  const server = new McpServer(
    {
      name: "orcel",
      version: "0.2.0"
    },
    { maxToolInputElements: MAX_TOOL_INPUT_ELEMENTS }
  );

  trackKernel(kernel);
  registerOrcelTools(server, kernel, defaultWorkspace, context);

  server.server.onclose = () => {
    untrackKernel(kernel);
    kernel.close();
  };

  return server;
}
