import { describe, expect, it, vi } from "vitest";

import type { KafProjectContext } from "#internal/project-context.js";

const { findKafProjectContext } = vi.hoisted(() => ({
  findKafProjectContext: vi.fn<() => Promise<KafProjectContext | undefined>>(),
}));

vi.mock("#internal/project-context.js", () => ({ findKafProjectContext }));
vi.mock("#services/dev-client/runtime-artifacts.js", () => ({
  resumeDevelopmentRuntimeArtifacts: vi.fn(),
  suspendDevelopmentRuntimeArtifacts: vi.fn(),
}));

import { runInteractiveDevelopmentUi } from "./run-interactive-ui.js";

describe("runInteractiveDevelopmentUi", () => {
  it("preserves the selected workspace member when the server owns the workspace root", async () => {
    const memberRoot = "/workspace/agents/bar";
    findKafProjectContext.mockResolvedValue({
      environmentRoot: "/workspace",
      kind: "workspace-member",
      member: { appRoot: memberRoot, name: "bar" },
      workspace: {
        root: "/workspace",
        members: [{ appRoot: memberRoot, name: "bar" }],
      },
    });
    const runDevelopmentTui = vi.fn(async () => {});

    await runInteractiveDevelopmentUi({
      applicationRoot: memberRoot,
      options: {},
      runDevelopmentTui,
      server: { appRoot: "/workspace", serverUrl: "http://localhost:2000" },
    });

    expect(findKafProjectContext).toHaveBeenCalledWith(memberRoot);
    expect(runDevelopmentTui).toHaveBeenCalledWith(
      expect.objectContaining({
        target: {
          agentRoot: memberRoot,
          kind: "local",
          serverUrl: "http://localhost:2000",
          workspaceRoot: "/workspace",
        },
      }),
    );
  });
});
