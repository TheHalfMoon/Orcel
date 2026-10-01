import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

function replaceAllLiteral(relativePath, before, after) {
  const file = path.join(root, relativePath);
  const input = fs.readFileSync(file, "utf8");
  const output = input.split(before).join(after);
  if (output !== input) fs.writeFileSync(file, output);
}

function ensureReplacement(relativePath, before, after) {
  const file = path.join(root, relativePath);
  const input = fs.readFileSync(file, "utf8");
  if (input.includes(after)) return;
  if (!input.includes(before)) {
    throw new Error(`${relativePath}: expected repair target was not found.`);
  }
  fs.writeFileSync(file, input.replace(before, after));
}

// Keep generic Git helpers generic. The migration changed the expected URL but
// left the fixture owner as Vercel, producing an impossible assertion.
replaceAllLiteral(
  "packages/kaf/src/shared/git.test.ts",
  "https://github.com/TheHalfMoon/kaf.git",
  "https://github.com/vercel/kaf.git",
);
replaceAllLiteral(
  "packages/kaf/src/public/channels/github/checkout.test.ts",
  "https://github.com/TheHalfMoon/kaf.git",
  "https://github.com/vercel/kaf.git",
);

// Project-owned protocol/runtime namespaces are Kaf-owned after the cutover.
replaceAllLiteral(
  "packages/kaf/src/harness/authorization.test.ts",
  "kaf%3Ainbox%3Av1%3Aeve%3Asession%3Asession-1%3Ainbox",
  "kaf%3Ainbox%3Av1%3Akaf%3Asession%3Asession-1%3Ainbox",
);
replaceAllLiteral(
  "packages/kaf/src/internal/workflow/queue-namespace.test.ts",
  "__eve776561746865722d6167656e74_wkf_workflow_",
  "__kaf776561746865722d6167656e74_wkf_workflow_",
);
replaceAllLiteral(
  "packages/kaf/src/internal/nitro/host/configure-nitro-routes.ts",
  "__eveGetWorkflowWorld",
  "__kafGetWorkflowWorld",
);
replaceAllLiteral(
  "packages/kaf/src/internal/nitro/host/configure-nitro-routes.ts",
  "__eveWorkflow",
  "__kafWorkflow",
);
replaceAllLiteral(
  "packages/kaf/src/internal/nitro/host/configure-nitro-routes.test.ts",
  "const __eveWorkflowWorld = await __eveGetWorkflowWorld();",
  "const __kafWorkflowWorld = await __kafGetWorkflowWorld();",
);
replaceAllLiteral(
  "packages/kaf/src/internal/nitro/host/configure-nitro-routes.test.ts",
  "__eveWorkflowWorld.registerHandler(\"__eve746573742d6167656e74_wkf_workflow_\", POST);",
  "__kafWorkflowWorld.registerHandler(\"__kaf746573742d6167656e74_wkf_workflow_\", POST);",
);

// Preserve ordinary English while correcting Kaf-owned fixture identity.
replaceAllLiteral(
  "packages/kaf/src/cli/ui/output.test.ts",
  "[KAFNT] beforeafter red",
  "[EVENT] beforeafter red",
);
replaceAllLiteral(
  "packages/kaf/src/internal/application/import-specifier.test.ts",
  "test%20eve",
  "test%20kaf",
);
replaceAllLiteral(
  "packages/kaf/src/cli/dev/tui/blocks.test.ts",
  String.raw`\u00a0eve\u00a0logo.`,
  String.raw`\u00a0kaf\u00a0logo.`,
);

// Tighten future full imports so uppercase English words such as EVENT are not
// interpreted as EVE branding. EVE_ is already handled explicitly; this rule
// retains EVEFoo/EVE2-style project identifiers without matching EVENT.
replaceAllLiteral(
  ".kaf-migration/bootstrap.mjs",
  '.replace(/^EVE(?=[A-Z0-9])/g, "KAF")',
  '.replace(/^EVE(?=_|[A-Z][a-z]|\\d)/g, "KAF")',
);
replaceAllLiteral(
  ".kaf-migration/bootstrap.mjs",
  '.replace(/\\bEVE(?=[A-Z0-9_])/g, "KAF")',
  '.replace(/\\bEVE(?=_|[A-Z][a-z]|\\d)/g, "KAF")',
);
ensureReplacement(
  ".kaf-migration/bootstrap.mjs",
  "const identityResidualPattern = /\\b(?:eve|Eve|EVE)\\b|\\b(?:eve|Eve|EVE)(?=[A-Z0-9_])|(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)|(?<=_)eve(?=_|$)/g;",
  "const identityResidualPattern = /\\b(?:eve|Eve|EVE)\\b|\\b(?:eve|Eve)(?=[A-Z0-9_])|\\bEVE(?=_|[A-Z][a-z]|\\d)|(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)|(?<=_)eve(?=_|$)/g;",
);
ensureReplacement(
  ".kaf-migration/audit-identity.mjs",
  '  { label: "Eve-prefixed symbol", pattern: /\\b(?:eve|Eve|EVE)(?=[A-Z0-9_])/g },',
  '  { label: "Eve-prefixed symbol", pattern: /\\b(?:eve|Eve)(?=[A-Z0-9_])/g },\n  { label: "EVE-prefixed symbol", pattern: /\\bEVE(?=_|[A-Z][a-z]|\\d)/g },',
);

// The Connect manifest compiler function is owned by @vercel/connect and its
// public API retains Eve in the symbol name. Preserve it exactly while keeping
// Kaf-owned snapshots, messages, and runtime identity branded as Kaf.
for (const relativePath of [
  "packages/kaf/src/internal/external-resources.ts",
  "packages/kaf/src/internal/external-resources.scenario.test.ts",
]) {
  replaceAllLiteral(
    relativePath,
    "experimental_createConnectManifestFromKafResources",
    "experimental_createConnectManifestFromEveResources",
  );
}
replaceAllLiteral(
  ".kaf-migration/bootstrap.mjs",
  'const externalProviderApiLiterals = ["@vercel/connect/eve"];',
  'const externalProviderApiLiterals = ["@vercel/connect/eve", "experimental_createConnectManifestFromEveResources"];',
);
replaceAllLiteral(
  ".kaf-migration/audit-identity.mjs",
  'const externalProviderApiLiterals = ["@vercel/connect/eve"];',
  'const externalProviderApiLiterals = ["@vercel/connect/eve", "experimental_createConnectManifestFromEveResources", "eve-external-resources"];',
);
replaceAllLiteral(
  ".kaf-migration/audit-identity.mjs",
  'const externalProviderApiLiterals = ["@vercel/connect/eve", "experimental_createConnectManifestFromEveResources"];',
  'const externalProviderApiLiterals = ["@vercel/connect/eve", "experimental_createConnectManifestFromEveResources", "eve-external-resources"];',
);
ensureReplacement(
  "packages/kaf/src/internal/external-resources.ts",
  'const CONNECT_MANIFEST_FILENAME = "vercel-connect-manifest.json";',
  'const CONNECT_MANIFEST_FILENAME = "vercel-connect-manifest.json";\nconst CONNECT_EVE_RESOURCES_SNAPSHOT_KIND = "eve-external-resources";',
);
ensureReplacement(
  "packages/kaf/src/internal/external-resources.ts",
  '    return parseJsonObject(\n      compiler.experimental_createConnectManifestFromEveResources(input.snapshot),\n    );',
  '    const connectSnapshot = {\n      ...input.snapshot,\n      kind: CONNECT_EVE_RESOURCES_SNAPSHOT_KIND,\n    };\n    return parseJsonObject(\n      compiler.experimental_createConnectManifestFromEveResources(connectSnapshot),\n    );',
);

// Kaf owns its public GHCR image. Keep the separate Vercel Container Registry
// coordinate unchanged because it is a provider-specific integration surface.
for (const relativePath of [
  "packages/kaf/src/execution/sandbox/bindings/kaf-image.ts",
  "packages/kaf/src/execution/sandbox/bindings/kaf-image.test.ts",
  ".github/workflows/release.yml",
]) {
  replaceAllLiteral(relativePath, "ghcr.io/vercel/kaf", "ghcr.io/thehalfmoon/kaf");
}

// pnpm does not expose a local tarball under the historical alias in the same
// way as a published npm alias. The compatibility check still validates the
// manifest alias, then binds the local Kaf install to that historical package
// coordinate so @vercel/connect can resolve its current bare `eve` import.
ensureReplacement(
  "scripts/check-template-compatibility.mjs",
  "  rmSync,\n  writeFileSync,",
  "  rmSync,\n  symlinkSync,\n  writeFileSync,",
);
ensureReplacement(
  "scripts/check-template-compatibility.mjs",
  '    run("pnpm", ["install", "--no-frozen-lockfile"], { cwd: destination });\n    run("pnpm", ["typecheck"], { cwd: destination });',
  '    run("pnpm", ["install", "--no-frozen-lockfile"], { cwd: destination });\n    if (manifest.dependencies["@vercel/connect"]) {\n      const compatibilityPath = join(destination, "node_modules", historicalFrameworkPackage);\n      rmSync(compatibilityPath, { force: true, recursive: true });\n      symlinkSync(join(destination, "node_modules", "kaf"), compatibilityPath, "junction");\n    }\n    run("pnpm", ["typecheck"], { cwd: destination });',
);

// Prepublish template qualification must not depend on a Kaf image already
// existing in GHCR. Build the package-owned sandbox image locally under the
// exact reference the packed Kaf package resolves, so Docker's if-not-present
// policy exercises the real Kaf image without a registry pull.
ensureReplacement(
  "scripts/check-template-compatibility.mjs",
  "  const tarball = join(packedDirectory, tarballs[0]);\n\n  const templates =",
  `  const tarball = join(packedDirectory, tarballs[0]);\n  const packageManifest = JSON.parse(readFileSync(join(packageDirectory, "package.json"), "utf8"));\n  const sandboxImageTag = String(packageManifest.version ?? "").split("+", 1)[0];\n  if (sandboxImageTag.length === 0) {\n    throw new Error("Kaf package version is required to build the local sandbox image");\n  }\n  const localSandboxImage = \`ghcr.io/thehalfmoon/kaf:\${sandboxImageTag}\`;\n  run("docker", [\n    "build",\n    "--file",\n    join(packageDirectory, "Dockerfile"),\n    "--tag",\n    localSandboxImage,\n    packageDirectory,\n  ]);\n\n  const templates =`,
);

console.log("Kaf final parity repair inputs applied successfully.");