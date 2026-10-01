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
  "packages/kaf/src/internal/nitro/host/configure-nitro-routes.test.ts",
  "const __eveWorkflowWorld = await __eveGetWorkflowWorld();",
  "const __kafWorkflowWorld = await __kafGetWorkflowWorld();",
);
replaceAllLiteral(
  "packages/kaf/src/internal/nitro/host/configure-nitro-routes.test.ts",
  "__eveWorkflowWorld.registerHandler(\"__eve746573742d6167656e74_wkf_workflow_\", POST);",
  "__kafWorkflowWorld.registerHandler(\"__kaf746573742d6167656e74_wkf_workflow_\", POST);",
);

// Preserve ordinary English and fixture content. These were false positives
// from the broad Eve-prefix migration rule, not project identity.
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
  "\u00a0eve\u00a0logo.",
  "\u00a0kaf\u00a0logo.",
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

console.log("Kaf final parity repair inputs applied successfully.");
