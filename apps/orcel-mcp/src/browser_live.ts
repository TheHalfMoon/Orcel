import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { KernelClient } from "./kernel.js";
import { projectKernelResult } from "./result.js";
import { TOOL_CONTRACT } from "./tool_contract.js";

/**
 * SG-000108 slice 3c: the live isolated browser. Registered only under the
 * `browser_structured` profile, which only local configuration selects
 * (`ORCEL_TOOL_SURFACE_PROFILE`); never remote. Each tool forwards exactly
 * one SG-000079 qualified shape, and `orceld` is the sole authority: its
 * profile gate, its policy and its approval broker decide every call, and
 * only a development build of the live browser reaches a real browser (every other build
 * answers typed unavailable).
 *
 * - The page lives in Orcel's own isolated profile on the installed,
 *   verified Edge or Chrome; it never touches the user's browser.
 * - Navigation, link activation and downloads each need fresh local Orcel
 *   approval bound to the exact page generation, node and destination.
 * - Observations carry node identities and keyed digests only: page text
 *   never leaves the isolated browser. `latest_dated_link` is the host's
 *   own selection of the link whose name carries the latest ISO date.
 * - Downloads are create-only into the workspace's approved download root,
 *   size-bounded and verified, and are never opened or executed.
 * - There is no script evaluation, DevTools, selector or coordinate input.
 */
const APPROVAL_TIMEOUT_MS = 10 * 60_000;
const OBSERVE_TIMEOUT_MS = 4 * 60_000;
const MAX_URL_CHARS = 2048;

const pageId = z.string().min(4).max(128).regex(/^pg-[A-Za-z0-9_-]+$/, { message: "page_id is an Orcel page id (pg-...)" });
const nodeId = z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/, { message: "node_id is an observed node id" });
const generation = z.number().int().min(0);
const fileName = z
  .string()
  .min(1)
  .max(255)
  .refine((value) => !/[\\:*?"<>|\p{Cc}]/u.test(value) && !value.startsWith("/") && !value.split("/").includes(".."), {
    message: "file_name is a relative name inside the approved download folder"
  });

const workspace = (defaultWorkspace: string) => z.string().min(1).default(defaultWorkspace);

export function browserPageSchema(defaultWorkspace: string) {
  return z.object({ workspace_id: workspace(defaultWorkspace) });
}

export function browserNavigateSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    page_id: pageId,
    url: z
      .string()
      .min(1)
      .max(MAX_URL_CHARS)
      .refine((value) => value.startsWith("https://"), { message: "url must use https://" }),
    expected_generation: generation
  });
}

export function browserObserveSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    page_id: pageId,
    expected_generation: generation
  });
}

export function browserClickSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    page_id: pageId,
    node_id: nodeId,
    expected_generation: generation
  });
}

export function browserDownloadSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    page_id: pageId,
    node_id: nodeId,
    file_name: fileName,
    expected_generation: generation
  });
}

export function registerLiveBrowserTools(server: McpServer, kernel: KernelClient, defaultWorkspace: string): void {
  // Each tool forwards exactly its contract shape (judge, slice 3c): the
  // capability and operation come from TOOL_CONTRACT, never from here.
  const forward = async (tool: string, workspaceId: string, args: Record<string, unknown>, timeoutMs: number) => {
    const entry = TOOL_CONTRACT[tool];
    if (entry === undefined) {
      throw new Error(`tool ${tool} has no SG-000065 contract entry`);
    }
    return projectKernelResult(
      await kernel.call({ workspaceId, capability: entry.capability, operation: entry.operation, arguments: args, timeoutMs })
    );
  };

  server.registerTool(
    "browser_page_open",
    {
      description:
        "Open a page in Orcel's isolated browser (its own profile on the installed Edge or Chrome, never your browser). Returns page_id and generation 0; nothing is loaded until browser_navigate. Opening a page ends the previous one.",
      inputSchema: browserPageSchema(defaultWorkspace)
    },
    async ({ workspace_id }) => forward("browser_page_open", workspace_id, {}, APPROVAL_TIMEOUT_MS)
  );

  server.registerTool(
    "browser_navigate",
    {
      description:
        "Navigate the isolated page to one public HTTPS URL, after fresh local Orcel approval bound to the page generation and the address Orcel pinned for the site. A new site starts a fresh isolated lifetime; earlier node ids go stale. Returns the committed URL, status and the new generation.",
      inputSchema: browserNavigateSchema(defaultWorkspace)
    },
    async ({ workspace_id, page_id, url, expected_generation }) =>
      forward("browser_navigate", workspace_id, { page_id, url, expected_generation }, APPROVAL_TIMEOUT_MS)
  );

  server.registerTool(
    "browser_observe",
    {
      description:
        "Observe the isolated page: bounded node identities, roles and keyed digests only (page text never leaves the isolated browser), plus latest_dated_link, Orcel's own pick of the link whose name carries the latest ISO date, if any.",
      inputSchema: browserObserveSchema(defaultWorkspace)
    },
    async ({ workspace_id, page_id, expected_generation }) =>
      forward("browser_observe", workspace_id, { page_id, expected_generation }, OBSERVE_TIMEOUT_MS)
  );

  server.registerTool(
    "browser_click",
    {
      description:
        "Open one observed link on the isolated page (links only), after fresh local Orcel approval bound to the page generation, the node and the link's destination on the same site.",
      inputSchema: browserClickSchema(defaultWorkspace)
    },
    async ({ workspace_id, page_id, node_id, expected_generation }) =>
      forward("browser_click", workspace_id, { page_id, node_id, expected_generation }, APPROVAL_TIMEOUT_MS)
  );

  server.registerTool(
    "browser_download_preview",
    {
      description:
        "Preview downloading the document behind one observed link: the source, the approved download folder and the file name the approval will name. Writes nothing and asks for nothing.",
      inputSchema: browserDownloadSchema(defaultWorkspace)
    },
    async ({ workspace_id, page_id, node_id, file_name, expected_generation }) =>
      forward("browser_download_preview", workspace_id, { page_id, node_id, file_name, expected_generation }, OBSERVE_TIMEOUT_MS)
  );

  server.registerTool(
    "browser_download",
    {
      description:
        "Download the document behind one observed link, create-only, into the workspace's approved download folder as file_name, after fresh local Orcel approval. The file is size-bounded and verified, and returned as its SHA-256 and size; it is never opened or run.",
      inputSchema: browserDownloadSchema(defaultWorkspace)
    },
    async ({ workspace_id, page_id, node_id, file_name, expected_generation }) =>
      forward("browser_download", workspace_id, { page_id, node_id, file_name, expected_generation }, APPROVAL_TIMEOUT_MS)
  );
}
