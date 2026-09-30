import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

function replaceOnce(relativePath, before, after) {
  const file = path.join(root, relativePath);
  const input = fs.readFileSync(file, "utf8");
  const count = input.split(before).length - 1;
  if (count !== 1) {
    throw new Error(`${relativePath}: expected exactly one repair target, found ${count}.`);
  }
  fs.writeFileSync(file, input.replace(before, after));
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

replaceOnce(
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
replaceOnce(".kaf-migration/bootstrap.mjs", oldIdentityName, newIdentityName);

console.log("Kaf parity repair inputs applied successfully.");
