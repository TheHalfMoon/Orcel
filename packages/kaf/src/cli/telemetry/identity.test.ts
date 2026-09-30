import { describe, expect, it } from "vitest";

import { hashKafTelemetryProject, resolveKafTelemetryProjectId } from "#cli/telemetry/identity.js";

const identity = { installationId: "installation_123", projectSalt: "project_salt_123" };

describe("kaf CLI telemetry identity", () => {
  it("uses the Git remote before environment and working-directory fallbacks", async () => {
    const projectId = await resolveKafTelemetryProjectId({
      cwd: "/project",
      repositoryUrl: "https://example.com/environment.git",
      identity,
      getGitRemote: async () => "git@example.com:owner/project.git",
    });

    expect(projectId).toBe(hashKafTelemetryProject(identity, "git@example.com:owner/project.git"));
    expect(projectId).not.toBe("git@example.com:owner/project.git");
  });

  it("uses the repository environment variable before the working directory", async () => {
    const projectId = await resolveKafTelemetryProjectId({
      cwd: "/project",
      repositoryUrl: "https://example.com/environment.git",
      identity,
      getGitRemote: async () => undefined,
    });

    expect(projectId).toBe(
      hashKafTelemetryProject(identity, "https://example.com/environment.git"),
    );
  });

  it("uses the working directory when no repository identifier is available", async () => {
    const projectId = await resolveKafTelemetryProjectId({
      cwd: "/project",
      identity,
      getGitRemote: async () => undefined,
    });

    expect(projectId).toBe(hashKafTelemetryProject(identity, "/project"));
  });

  it("uses different hashes for different salts", () => {
    expect(hashKafTelemetryProject(identity, "project")).not.toBe(
      hashKafTelemetryProject({ ...identity, projectSalt: "other_salt" }, "project"),
    );
  });
});
