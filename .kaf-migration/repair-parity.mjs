import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

function ensureReplacement(relativePath, before, after) {
  const file = path.join(root, relativePath);
  const input = fs.readFileSync(file, "utf8");
  const beforeCount = input.split(before).length - 1;
  const afterCount = input.split(after).length - 1;

  if (beforeCount === 0 && afterCount > 0) return false;
  if (beforeCount !== 1) {
    throw new Error(`${relativePath}: expected exactly one repair target, found ${beforeCount}.`);
  }

  fs.writeFileSync(file, input.replace(before, after));
  return true;
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

ensureReplacement(
  ".kaf-migration/bootstrap.mjs",
  "const externalEvePackages = new Set();",
  "const evePackageToken = /(^|[\\/_\\-.])eve($|[_.-])/i;\nconst externalEvePackages = new Set();",
);
ensureReplacement(
  ".kaf-migration/bootstrap.mjs",
  "if (/eve/i.test(dependencyName) && !internalPackageNames.has(dependencyName)) {",
  "if (evePackageToken.test(dependencyName) && !internalPackageNames.has(dependencyName)) {",
);

const changelogPath = path.join(root, "packages/kaf/CHANGELOG.md");
const changelog = fs.readFileSync(changelogPath, "utf8");
const repairedChangelog = changelog.replace(/\bwithEve\b/g, "withKaf");
if (repairedChangelog !== changelog) fs.writeFileSync(changelogPath, repairedChangelog);
if (/\bwithEve\b/.test(fs.readFileSync(changelogPath, "utf8"))) {
  throw new Error("packages/kaf/CHANGELOG.md still contains project-owned withEve identity.");
}

console.log("Kaf parity repair inputs applied successfully.");
