import { describe, expect, it } from "vitest";

import {
  createDevelopmentWorkflowWorldPluginSource,
  createWorkflowWorldPluginSource,
} from "#internal/application/compiled-artifacts.js";

describe("createWorkflowWorldPluginSource", () => {
  it("imports a configured world package and delegates its construction to Workflow", () => {
    const source = createWorkflowWorldPluginSource({
      compiledArtifactsBootstrapPath: "/app/.orcel/compile/compiled-artifacts-bootstrap.mjs",
      configuredWorld: "@acme/orcel-world",
      defaultWorld: "vercel",
    });

    expect(source).toContain('import "/app/.orcel/compile/compiled-artifacts-bootstrap.mjs";');
    expect(source).toContain('import * as workflowWorldModule from "@acme/orcel-world";');
    expect(source).toContain("import { validateWorkflowWorld } from ");
    expect(source).toContain(
      "const workflowWorld = await createWorldFromModule(workflowWorldModule);",
    );
    expect(source).toContain(
      'validateWorkflowWorld({ packageName: "@acme/orcel-world", world: workflowWorld });',
    );
    expect(source).not.toContain("resolveLocalWorkflowWorldDataDirectory");
    expect(source).toContain("setWorld(workflowWorld);");
    expect(source).toContain("await getWorld();");
    expect(source).toContain("await workflowWorld.start?.();");
  });

  it("configures the vendored local World with orcel's app-local data resolver", () => {
    const source = createWorkflowWorldPluginSource({
      compiledArtifactsBootstrapPath: "/app/.orcel/compile/bootstrap.mjs",
      configuredWorld: undefined,
      defaultWorld: "local",
    });

    expect(source).toContain("/compiled/@workflow/world-local/index.js");
    expect(source).toContain("resolveLocalWorkflowWorldDataDirectory(process.cwd())");
    expect(source).toContain("applyLocalWorkflowWorldDeliveryTimeoutDefaults");
    expect(source.indexOf("applyLocalWorkflowWorldDeliveryTimeoutDefaults();")).toBeLessThan(
      source.indexOf("workflowWorldModule.createWorld"),
    );
    expect(source).not.toContain("createWorldFromModule(workflowWorldModule)");
  });

  it("selects the vendored Vercel World with Workflow's selector", () => {
    const source = createWorkflowWorldPluginSource({
      compiledArtifactsBootstrapPath: "/app/.orcel/compile/bootstrap.mjs",
      configuredWorld: undefined,
      defaultWorld: "vercel",
    });

    expect(source).toContain("/compiled/@workflow/world-vercel/index.js");
    expect(source).toMatch(/headers: \{ "User-Agent": "orcel\/.+" \}/);
    expect(source).toContain("applyVercelWorkflowWorldDefaults(workflowWorld);");
    expect(source.indexOf("applyVercelWorkflowWorldDefaults(workflowWorld);")).toBeLessThan(
      source.indexOf("setWorld(workflowWorld);"),
    );
  });
});

describe("createDevelopmentWorkflowWorldPluginSource", () => {
  it("installs the parent-backed World without starting a local World in the worker", () => {
    const source = createDevelopmentWorkflowWorldPluginSource({
      compiledArtifactsBootstrapPath: "/app/.orcel/host/bootstrap.mjs",
      configuredWorld: undefined,
    });

    expect(source).toContain("createDevelopmentWorkflowWorld");
    expect(source).toContain("setWorld(createDevelopmentWorkflowWorld());");
    expect(source).not.toContain("@workflow/world-local");
    expect(source).not.toContain("workflowWorld.start");
  });

  it("keeps explicitly configured remote Worlds inside the worker", () => {
    const source = createDevelopmentWorkflowWorldPluginSource({
      compiledArtifactsBootstrapPath: "/app/.orcel/host/bootstrap.mjs",
      configuredWorld: "@acme/orcel-world",
    });

    expect(source).toContain('import * as workflowWorldModule from "@acme/orcel-world";');
    expect(source).toContain("await workflowWorld.start?.();");
  });
});
