import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

function ensureReplacement(relativePath, before, after) {
  const file = path.join(root, relativePath);
  const input = fs.readFileSync(file, "utf8");
  const beforeCount = input.split(before).length - 1;
  const afterCount = input.split(after).length - 1;

  if (afterCount > 0) {
    const embeddedBeforeCount = after.includes(before) ? afterCount : 0;
    const staleBeforeCount = beforeCount - embeddedBeforeCount;
    if (staleBeforeCount === 0) return false;
    throw new Error(
      `${relativePath}: replacement is already present but ${staleBeforeCount} stale repair target(s) remain.`,
    );
  }

  if (beforeCount !== 1) {
    throw new Error(`${relativePath}: expected exactly one repair target, found ${beforeCount}.`);
  }

  fs.writeFileSync(file, input.replace(before, after));
  return true;
}

function replaceAllLiteral(relativePath, before, after) {
  const file = path.join(root, relativePath);
  const input = fs.readFileSync(file, "utf8");
  const output = input.split(before).join(after);
  if (output !== input) fs.writeFileSync(file, output);
}

function replaceLiteralInTree(dir, before, after) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (
      entry.name === ".git" ||
      entry.name === ".kaf-migration" ||
      entry.name === "node_modules" ||
      entry.name === "dist"
    ) {
      continue;
    }
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      replaceLiteralInTree(file, before, after);
      continue;
    }
    if (!entry.isFile()) continue;
    const buffer = fs.readFileSync(file);
    if (buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0)) continue;
    const input = buffer.toString("utf8");
    if (!input.includes(before)) continue;
    fs.writeFileSync(file, input.split(before).join(after));
  }
}

const oldConsole = path.join(
  root,
  "apps/frameworks/sveltekit/src/lib/EveAgentConsole.svelte",
);
const newConsole = path.join(
  root,
  "apps/frameworks/sveltekit/src/lib/KafAgentConsole.svelte",
);
if (fs.existsSync(oldConsole)) {
  if (fs.existsSync(newConsole)) {
    throw new Error("Both EveAgentConsole.svelte and KafAgentConsole.svelte exist.");
  }
  fs.renameSync(oldConsole, newConsole);
} else if (!fs.existsSync(newConsole)) {
  throw new Error("Expected the Svelte agent console fixture to exist.");
}

ensureReplacement(
  "packages/kaf/src/execution/tool-auth.integration.test.ts",
  "kaf%3Ainbox%3Av1%3Aeve%3Asession%3Asession_auth%3Ainbox",
  "kaf%3Ainbox%3Av1%3Akaf%3Asession%3Asession_auth%3Ainbox",
);

const oldIdentityName = `function identityName(name) {
  return renameInternalScope(name)
    .replace(/(^|[-_.])EVE(?=$|[-_.])/g, "$1KAF")
    .replace(/(^|[-_.])Eve(?=$|[-_.])/g, "$1Kaf")
    .replace(/(^|[-_.])eve(?=$|[-_.])/g, "$1kaf");
}`;
const newIdentityName = `function identityName(name) {
  return renameInternalScope(name)
    .replace(/^EVE(?=[A-Z0-9])/g, "KAF")
    .replace(/^Eve(?=[A-Z0-9])/g, "Kaf")
    .replace(/^eve(?=[A-Z0-9])/g, "kaf")
    .replace(/(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)/g, "Kaf")
    .replace(/(^|[-_.])EVE(?=$|[-_.])/g, "$1KAF")
    .replace(/(^|[-_.])Eve(?=$|[-_.])/g, "$1Kaf")
    .replace(/(^|[-_.])eve(?=$|[-_.])/g, "$1kaf");
}`;
ensureReplacement(".kaf-migration/bootstrap.mjs", oldIdentityName, newIdentityName);

const bootstrapPath = path.join(root, ".kaf-migration/bootstrap.mjs");
let bootstrapText = fs.readFileSync(bootstrapPath, "utf8");
if (!bootstrapText.includes("const evePackageToken =")) {
  ensureReplacement(
    ".kaf-migration/bootstrap.mjs",
    "const externalEvePackages = new Set();",
    "const evePackageToken = /(^|[\\/_\\-.])eve($|[_.-])/i;\nconst externalEvePackages = new Set();",
  );
  bootstrapText = fs.readFileSync(bootstrapPath, "utf8");
}
if (!bootstrapText.includes("if (evePackageToken.test(dependencyName)")) {
  ensureReplacement(
    ".kaf-migration/bootstrap.mjs",
    "if (/eve/i.test(dependencyName) && !internalPackageNames.has(dependencyName)) {",
    "if (evePackageToken.test(dependencyName) && !internalPackageNames.has(dependencyName)) {",
  );
  bootstrapText = fs.readFileSync(bootstrapPath, "utf8");
}
if (!bootstrapText.includes("const externalProviderApiLiterals =")) {
  ensureReplacement(
    ".kaf-migration/bootstrap.mjs",
    "const protectedLiterals = [...externalEvePackages].sort((a, b) => b.length - a.length);",
    "const externalProviderApiLiterals = [\"@vercel/connect/eve\"];\nconst protectedLiterals = [...new Set([...externalEvePackages, ...externalProviderApiLiterals])].sort(\n  (a, b) => b.length - a.length,\n);",
  );
}

// @vercel/connect exposes this external compatibility API under the literal
// subpath "eve". Renaming it to "kaf" breaks package resolution, so preserve
// the upstream provider API while Kaf's own imports continue to use "kaf/*".
replaceLiteralInTree(root, "@vercel/connect/kaf", "@vercel/connect/eve");

const changelogPath = path.join(root, "packages/kaf/CHANGELOG.md");
const changelog = fs.readFileSync(changelogPath, "utf8");
const repairedChangelog = changelog.replace(/\bwithEve\b/g, "withKaf");
if (repairedChangelog !== changelog) fs.writeFileSync(changelogPath, repairedChangelog);
if (/\bwithEve\b/.test(fs.readFileSync(changelogPath, "utf8"))) {
  throw new Error("packages/kaf/CHANGELOG.md still contains project-owned withEve identity.");
}

ensureReplacement(
  "packages/kaf/README.md",
  "kaf is a filesystem-first framework for durable backend agents on Vercel.",
  "Kaf is a filesystem-first framework for durable backend AI agents that run anywhere.",
);
ensureReplacement(
  "packages/kaf/README.md",
  "kaf is currently a preview and subject to the Vercel beta terms; the framework, APIs, documentation, and behavior may change before general availability.",
  "Kaf is under active development; the framework, APIs, documentation, and behavior may change before the first stable release.",
);
replaceAllLiteral("packages/kaf/README.md", "an kaf agent", "a Kaf agent");
replaceAllLiteral("packages/kaf/README.md", "an kaf project", "a Kaf project");

console.log("Kaf parity repair inputs applied successfully.");
