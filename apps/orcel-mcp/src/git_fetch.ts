import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { GIT_OFF } from "./git_off.js";
import { KernelClient } from "./kernel.js";
import { projectKernelResult } from "./result.js";

const EXPECTED_HEAD = /^[0-9a-f]{40}$/;
const EXPECTED_PRIOR = /^([0-9a-f]{40}|ABSENT)$/;
const POLICY_ID = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const BRANCH = /^[A-Za-z0-9._/-]{1,255}$/;
const APPROVAL_TIMEOUT_MS = 10 * 60_000;

const workspaceId = (defaultWorkspace: string) =>
  z.string().min(1).default(defaultWorkspace);

const repositoryPath = z.string().min(1).max(4096).default(".");
const policyId = z.string().min(1).max(64).regex(POLICY_ID);
const branchName = z
  .string()
  .min(1)
  .max(255)
  .regex(BRANCH)
  .refine((value) => !value.startsWith("refs/"), {
    message: "branch must be a short name, not a full ref"
  })
  .refine((value) => !value.startsWith("-") && !value.startsWith("/") && !value.startsWith("."), {
    message: "branch has an unsafe leading component"
  })
  .refine((value) => !value.endsWith("/") && !value.endsWith(".") && !value.endsWith(".lock"), {
    message: "branch has an unsafe trailing component"
  })
  .refine(
    (value) =>
      !value.includes("//") &&
      !value.includes("..") &&
      !value.includes("@{") &&
      !value.includes(" "),
    { message: "branch contains an unsafe sequence" }
  );
const expectedHead = z.string().regex(EXPECTED_HEAD);
const expectedPrior = z.string().regex(EXPECTED_PRIOR);

export function gitFetchPreviewSchema(defaultWorkspace: string) {
  return z
    .object({
      workspace_id: workspaceId(defaultWorkspace),
      path: repositoryPath,
      policy_id: policyId,
      branch: branchName
    })
    .strict();
}

export function gitFetchSchema(defaultWorkspace: string) {
  return z
    .object({
      workspace_id: workspaceId(defaultWorkspace),
      path: repositoryPath,
      policy_id: policyId,
      branch: branchName,
      expected_head: expectedHead,
      expected_prior: expectedPrior
    })
    .strict();
}

export function registerGitFetchTools(
  server: McpServer,
  kernel: KernelClient,
  defaultWorkspace: string
): void {
  server.registerTool(
    "git_fetch_preview",
    {
      description:
        GIT_OFF +
        "Preview one bounded Git HTTPS fetch without DNS, network, approval, or mutation. Returns the exact HEAD, deterministic Orcel-owned destination ref, and current prior state required for an approved fetch.",
      inputSchema: gitFetchPreviewSchema(defaultWorkspace)
    },
    async ({ workspace_id, path, policy_id, branch }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.fetch.preview",
          operation: "preview",
          target: path,
          arguments: { policy_id, branch },
          timeoutMs: APPROVAL_TIMEOUT_MS
        })
      )
  );

  server.registerTool(
    "git_fetch",
    {
      description:
        GIT_OFF +
        "Fetch one validated branch ref from one workspace-bound HTTPS destination into its Orcel-owned remote-tracking ref after fresh local approval, public-address pinning, and post-approval revalidation. Push remains denied.",
      inputSchema: gitFetchSchema(defaultWorkspace)
    },
    async ({
      workspace_id,
      path,
      policy_id,
      branch,
      expected_head,
      expected_prior
    }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.fetch",
          operation: "fetch",
          target: path,
          arguments: { policy_id, branch, expected_head, expected_prior },
          timeoutMs: APPROVAL_TIMEOUT_MS
        })
      )
  );
}
