import type { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { GIT_OFF } from "./git_off.js";
import { KernelClient } from "./kernel.js";
import { projectKernelResult } from "./result.js";

const EXPECTED_HEAD = /^[0-9a-f]{40}$/;
const EXPECTED_PRIOR = /^([0-9a-f]{40}|ABSENT)$/;
const POLICY_ID = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const BRANCH = /^[A-Za-z0-9._/-]{1,255}$/;
const CREDENTIAL_REFERENCE = /^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?$/;
const APPROVAL_TIMEOUT_MS = 10 * 60_000;

const workspaceId = (defaultWorkspace: string) =>
  z.string().min(1).default(defaultWorkspace);

const repositoryPath = z.string().min(1).max(4096).default(".");
const policyId = z.string().min(1).max(64).regex(POLICY_ID);
const credentialReference = z
  .string()
  .min(1)
  .max(64)
  .regex(CREDENTIAL_REFERENCE)
  .refine((value) => !value.includes("://") && !value.includes("@"), {
    message: "credential_reference must be an opaque reference id, never a raw secret or URL"
  });
const branchName = z
  .string()
  .min(1)
  .max(255)
  .regex(BRANCH)
  .refine((value) => !value.startsWith("refs/"), {
    message: "branch must be a short name, not a full ref"
  })
  .refine((value) => !value.includes(":"), {
    message: "branch must not contain refspec separators"
  })
  .refine((value) => !value.includes("+"), {
    message: "branch must not contain force markers"
  })
  .refine((value) => !value.includes("*") && !value.includes("^") && !value.includes("?"), {
    message: "branch must not contain wildcard characters"
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

export function gitPushPreviewSchema(defaultWorkspace: string) {
  return z
    .object({
      workspace_id: workspaceId(defaultWorkspace),
      path: repositoryPath,
      policy_id: policyId,
      source_branch: branchName,
      dest_branch: branchName,
      credential_reference: credentialReference
    })
    .strict();
}

export function gitPushSchema(defaultWorkspace: string) {
  return z
    .object({
      workspace_id: workspaceId(defaultWorkspace),
      path: repositoryPath,
      policy_id: policyId,
      source_branch: branchName,
      dest_branch: branchName,
      expected_head: expectedHead,
      expected_prior: expectedPrior,
      credential_reference: credentialReference
    })
    .strict();
}

export function registerGitPushTools(
  server: McpServer,
  kernel: KernelClient,
  defaultWorkspace: string
): void {
  server.registerTool(
    "git_push_preview",
    {
      description:
        GIT_OFF +
        "Preview one bounded Git HTTPS push without DNS, network, approval, mutation, or secret access. Returns the exact HEAD, source and destination refs, and current tracking prior required for an approved push.",
      inputSchema: gitPushPreviewSchema(defaultWorkspace)
    },
    async ({ workspace_id, path, policy_id, source_branch, dest_branch, credential_reference }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.push.preview",
          operation: "preview",
          target: path,
          arguments: { policy_id, source_branch, dest_branch, credential_reference },
          timeoutMs: APPROVAL_TIMEOUT_MS
        })
      )
  );

  server.registerTool(
    "git_push",
    {
      description:
        GIT_OFF +
        "Push one validated local branch ref to one validated remote branch ref on one workspace-bound HTTPS destination after fresh local approval, public-address pinning, and post-approval revalidation. Force push, deletion, wildcard refspecs, arbitrary URLs, and raw credentials are denied; authentication uses protected credential references only.",
      inputSchema: gitPushSchema(defaultWorkspace)
    },
    async ({
      workspace_id,
      path,
      policy_id,
      source_branch,
      dest_branch,
      expected_head,
      expected_prior,
      credential_reference
    }) =>
      projectKernelResult(
        await kernel.call({
          workspaceId: workspace_id,
          capability: "git.push",
          operation: "push",
          target: path,
          arguments: {
            policy_id,
            source_branch,
            dest_branch,
            expected_head,
            expected_prior,
            credential_reference
          },
          timeoutMs: APPROVAL_TIMEOUT_MS
        })
      )
  );
}
