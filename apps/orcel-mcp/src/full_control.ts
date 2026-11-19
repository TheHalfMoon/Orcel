import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { KernelClient } from "./kernel.js";
import { projectKernelResult } from "./result.js";

/**
 * SG132_SLICE9.md: the Full Control tools (option B of
 * FC_TOOL_SURFACE_OPTIONS.md, the SG-000132 amendment "Full Control file
 * writes covered by the lease, and the fc_* tool surface" of 2026-11-19).
 *
 * One local-only tool per orceld `fc-worker` operation, plus the read-only
 * `fc_status`. Each forwards exactly one `fc.fs`, `fc.process`, `fc.git` or
 * `fc.status` request; orceld (SG132_SLICE8.md) refuses it unless the
 * request is local, a Full User lease from the Orcel authority service
 * covers it (executor, this client's reference, roots), and the service's
 * audit-first `Authorize` admits it. Program runs and Git changes ask a
 * fresh Windows approval on every call; file writes and folder creation
 * are covered by the lease and ask nothing; reads ask nothing. This module
 * grants, renews and approves nothing.
 *
 * The bounds below repeat orceld's (`WorkerOp::check_arguments`, the
 * worker's and the Git provider's rules); orceld checks them again.
 */
const MAX_PATH_CHARS = 1024;
const MAX_LIST_ENTRIES = 1000;
const MAX_TEXT_BYTES = 256 * 1024;
const MAX_PROCESS_ARGS = 64;
const MAX_ARG_CHARS = 8 * 1024;
const MAX_PROCESS_TIMEOUT_MS = 50_000;
const MAX_PROCESS_OUTPUT_BYTES = 64 * 1024;
const MAX_GIT_LOG = 100;
const MAX_GIT_PATHS = 128;
const MAX_GIT_PATH_BYTES = 4096;
const MAX_COMMIT_MESSAGE_BYTES = 8 * 1024;
const MAX_BRANCH_BYTES = 255;

/** Every `fc.*` request shape a tool here sends (orceld's `FC_SHAPES`). */
export const FULL_CONTROL_KERNEL_SHAPES = [
  ["fc.fs", "stat"],
  ["fc.fs", "list"],
  ["fc.fs", "read_text"],
  ["fc.fs", "write_text"],
  ["fc.fs", "mkdir"],
  ["fc.process", "run"],
  ["fc.git", "git_status"],
  ["fc.git", "git_diff"],
  ["fc.git", "git_log"],
  ["fc.git", "git_add"],
  ["fc.git", "git_unstage"],
  ["fc.git", "git_commit"],
  ["fc.git", "git_branch_create"],
  ["fc.status", "get"]
] as const;

const hasControl = (value: string): boolean => [...value].some((c) => (c.codePointAt(0) ?? 0) < 0x20 || c === "\u007f");
const utf8 = (value: string): number => Buffer.byteLength(value, "utf8");

const workspace = (defaultWorkspace: string) => z.string().min(1).default(defaultWorkspace);

/** An absolute drive path, as orceld's dispatch path check requires. */
const absolutePath = z
  .string()
  .min(1)
  .max(MAX_PATH_CHARS)
  .regex(/^[A-Za-z]:[\\/]/, "an absolute drive path such as C:\\work\\file.txt")
  .refine((value) => !hasControl(value), "no control characters");

const gitPaths = z
  .array(
    z
      .string()
      .min(1)
      .refine((value) => utf8(value) <= MAX_GIT_PATH_BYTES, "a path is at most 4096 bytes")
      .refine((value) => !/[\0\n\r\t]/.test(value), "no control data")
      .refine((value) => !value.startsWith(":"), "no pathspec magic")
  )
  .min(1)
  .max(MAX_GIT_PATHS)
  .refine((paths) => new Set(paths).size === paths.length, "no duplicate paths");

export function fcPathSchema(defaultWorkspace: string) {
  return z.object({ workspace_id: workspace(defaultWorkspace), path: absolutePath });
}

export function fcListSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    path: absolutePath,
    max_entries: z.number().int().min(1).max(MAX_LIST_ENTRIES).default(200)
  });
}

export function fcReadSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    path: absolutePath,
    max_bytes: z.number().int().min(1).max(MAX_TEXT_BYTES).default(64 * 1024)
  });
}

export function fcWriteSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    path: absolutePath,
    text: z.string().refine((value) => utf8(value) <= MAX_TEXT_BYTES, "text is at most 262144 UTF-8 bytes"),
    create_new: z.boolean().default(false)
  });
}

export function fcRunSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    program: absolutePath.refine((value) => /\.exe$/i.test(value), "program is an absolute path to an .exe"),
    args: z
      .array(
        z
          .string()
          .max(MAX_ARG_CHARS)
          .refine((value) => !value.includes("\0"), "an argument has no NUL")
      )
      .max(MAX_PROCESS_ARGS)
      .default([]),
    cwd: absolutePath,
    timeout_ms: z.number().int().min(1).max(MAX_PROCESS_TIMEOUT_MS).default(30_000),
    max_output_bytes: z.number().int().min(1).max(MAX_PROCESS_OUTPUT_BYTES).default(MAX_PROCESS_OUTPUT_BYTES)
  });
}

export function fcRepositorySchema(defaultWorkspace: string) {
  return z.object({ workspace_id: workspace(defaultWorkspace), repository: absolutePath });
}

export function fcDiffSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    repository: absolutePath,
    staged: z.boolean().default(false)
  });
}

export function fcLogSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    repository: absolutePath,
    max_count: z.number().int().min(1).max(MAX_GIT_LOG).default(20)
  });
}

export function fcPathsSchema(defaultWorkspace: string) {
  return z.object({ workspace_id: workspace(defaultWorkspace), repository: absolutePath, paths: gitPaths });
}

export function fcCommitSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    repository: absolutePath,
    message: z
      .string()
      .refine((value) => value.trim().length > 0, "the message is not empty")
      .refine((value) => utf8(value) <= MAX_COMMIT_MESSAGE_BYTES, "the message is at most 8192 bytes")
      .refine((value) => !value.includes("\0"), "the message has no NUL")
  });
}

export function fcBranchSchema(defaultWorkspace: string) {
  return z.object({
    workspace_id: workspace(defaultWorkspace),
    repository: absolutePath,
    branch: z
      .string()
      .min(1)
      .refine((value) => utf8(value) <= MAX_BRANCH_BYTES, "the branch name is at most 255 bytes")
      .refine((value) => !/[\0\n\r\t]/.test(value), "no control data")
      .refine((value) => !value.startsWith("-"), "the branch name does not start with -")
  });
}

export function fcStatusSchema(defaultWorkspace: string) {
  return z.object({ workspace_id: workspace(defaultWorkspace) });
}

const LEASE =
  "Needs an active Full Control lease from the Orcel authority service that covers this client (see fc_status for its reference), and paths inside the lease's roots; refuses otherwise (LEASE_REQUIRED without a covering lease, CAPABILITY_DENIED for a lease bound to another client or a refused shape, PATH_ESCAPE outside the roots). Local only.";
const ASKS = "Asks the person a fresh Windows approval on every call.";
const COVERED = "Covered by the lease: no per-call approval (founder decision, SG-000132 amendment of 2026-11-19).";
const READS = "Read-only; asks nothing.";

export function registerFullControlTools(server: McpServer, kernel: KernelClient, defaultWorkspace: string): void {
  // Each tool sends one worker operation: `{op, ...fields}`, with no target.
  const send = async (
    workspaceId: string,
    shape: { capability: string; operation: string },
    fields: Record<string, unknown>
  ) =>
    projectKernelResult(
      await kernel.call({
        workspaceId,
        capability: shape.capability,
        operation: shape.operation,
        arguments: { op: shape.operation, ...fields }
      })
    );

  server.registerTool(
    "fc_status",
    {
      description:
        "Show the active Full Control leases this client can use (executors, roots, expiry, and which fc_* families they cover) and this client's reference (client_ref), which the person names when granting a lease (orcel full-control grant --client <client_ref>). Read-only; grants nothing; asks nothing. Local only.",
      inputSchema: fcStatusSchema(defaultWorkspace)
    },
    async ({ workspace_id }) =>
      projectKernelResult(
        await kernel.call({ workspaceId: workspace_id, capability: "fc.status", operation: "get", arguments: {} })
      )
  );

  server.registerTool(
    "fc_fs_stat",
    {
      description: `Read the kind, size and read-only flag of one absolute path under Full Control. ${READS} ${LEASE}`,
      inputSchema: fcPathSchema(defaultWorkspace)
    },
    async ({ workspace_id, path }) => send(workspace_id, { capability: "fc.fs", operation: "stat" }, { path })
  );

  server.registerTool(
    "fc_fs_list",
    {
      description: `List one folder (at most 1000 entries, sorted, truncation reported) under Full Control. ${READS} ${LEASE}`,
      inputSchema: fcListSchema(defaultWorkspace)
    },
    async ({ workspace_id, path, max_entries }) => send(workspace_id, { capability: "fc.fs", operation: "list" }, { path, max_entries })
  );

  server.registerTool(
    "fc_fs_read",
    {
      description: `Read one UTF-8 text file (at most 262144 bytes, truncation reported) under Full Control. ${READS} ${LEASE}`,
      inputSchema: fcReadSchema(defaultWorkspace)
    },
    async ({ workspace_id, path, max_bytes }) => send(workspace_id, { capability: "fc.fs", operation: "read_text" }, { path, max_bytes })
  );

  server.registerTool(
    "fc_fs_write",
    {
      description: `Write one UTF-8 text file (at most 262144 bytes; replaces its content, or create_new to refuse an existing file) under Full Control. ${COVERED} Never writes inside .git or Orcel's own state. ${LEASE}`,
      inputSchema: fcWriteSchema(defaultWorkspace)
    },
    async ({ workspace_id, path, text, create_new }) =>
      send(workspace_id, { capability: "fc.fs", operation: "write_text" }, { path, text, create_new })
  );

  server.registerTool(
    "fc_fs_mkdir",
    {
      description: `Create one folder (its parent must exist) under Full Control. ${COVERED} Never inside .git or Orcel's own state. ${LEASE}`,
      inputSchema: fcPathSchema(defaultWorkspace)
    },
    async ({ workspace_id, path }) => send(workspace_id, { capability: "fc.fs", operation: "mkdir" }, { path })
  );

  server.registerTool(
    "fc_process_run",
    {
      description: `Run one program (an absolute .exe inside the roots, no shell) with an argument list and working folder, for at most 50 s and 65536 bytes of output, inside a Job Object, under Full Control. ${ASKS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcRunSchema(defaultWorkspace)
    },
    async ({ workspace_id, program, args, cwd, timeout_ms, max_output_bytes }) =>
      send(workspace_id, { capability: "fc.process", operation: "run" }, { program, args, cwd, timeout_ms, max_output_bytes })
  );

  server.registerTool(
    "fc_git_status",
    {
      description: `Git status of one repository inside the roots under Full Control. ${READS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcRepositorySchema(defaultWorkspace)
    },
    async ({ workspace_id, repository }) => send(workspace_id, { capability: "fc.git", operation: "git_status" }, { repository })
  );

  server.registerTool(
    "fc_git_diff",
    {
      description: `Git diff (working tree, or staged) of one repository inside the roots under Full Control. ${READS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcDiffSchema(defaultWorkspace)
    },
    async ({ workspace_id, repository, staged }) => send(workspace_id, { capability: "fc.git", operation: "git_diff" }, { repository, staged })
  );

  server.registerTool(
    "fc_git_log",
    {
      description: `Git log (at most 100 commits) of one repository inside the roots under Full Control. ${READS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcLogSchema(defaultWorkspace)
    },
    async ({ workspace_id, repository, max_count }) =>
      send(workspace_id, { capability: "fc.git", operation: "git_log" }, { repository, max_count })
  );

  server.registerTool(
    "fc_git_stage",
    {
      description: `Stage 1 to 128 repository-relative paths in one repository under Full Control. ${ASKS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcPathsSchema(defaultWorkspace)
    },
    async ({ workspace_id, repository, paths }) => send(workspace_id, { capability: "fc.git", operation: "git_add" }, { repository, paths })
  );

  server.registerTool(
    "fc_git_unstage",
    {
      description: `Unstage 1 to 128 repository-relative paths in one repository under Full Control. ${ASKS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcPathsSchema(defaultWorkspace)
    },
    async ({ workspace_id, repository, paths }) => send(workspace_id, { capability: "fc.git", operation: "git_unstage" }, { repository, paths })
  );

  server.registerTool(
    "fc_git_commit",
    {
      description: `Commit what is staged in one repository, with a message of at most 8192 bytes, under Full Control. ${ASKS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcCommitSchema(defaultWorkspace)
    },
    async ({ workspace_id, repository, message }) =>
      send(workspace_id, { capability: "fc.git", operation: "git_commit" }, { repository, message })
  );

  server.registerTool(
    "fc_git_branch_create",
    {
      description: `Create one branch at the current commit of one repository and switch to it under Full Control. ${ASKS} The lease must include programs (shells). ${LEASE}`,
      inputSchema: fcBranchSchema(defaultWorkspace)
    },
    async ({ workspace_id, repository, branch }) =>
      send(workspace_id, { capability: "fc.git", operation: "git_branch_create" }, { repository, branch })
  );
}
