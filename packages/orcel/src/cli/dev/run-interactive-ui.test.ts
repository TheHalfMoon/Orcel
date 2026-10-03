import { describe, expect, it, vi } from "vitest";

import type { OrcelProjectContext } from "#internal/project-context.js";

const { findOrcelProjectContext } = vi.hoisted(() => ({
  findOrcelProjectContext: vi.fn<() => Promise<OrcelProjectContext | undefined>>(),
}));

vi.mock("#internal/project-context.js", () => ({ findOrcelProjectContext }));
vi.mock("#services/dev-client/runtime-artifacts.js", () => ({
  resumeDevelopmentRuntimeArtifacts: vi.fn(),
  suspendDevelopmentRuntimeArtifacts: vi.fn(),
}));

import { runInteractiveDevelopmentUi } from "./run-interactive-ui.js";

describe("runInteractiveDevelopmentUi", () => {
  it("preserves the selected workspace member when the server owns the workspace root", async () => {
    const memberRoot = "/workspace/agents/bar";
    findOrcelProjectContext.mockResolvedValue({
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

    expect(findOrcelProjectContext).toHaveBeenCalledWith(memberRoot);
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
