import fs from "node:fs";
import path from "node:path";

const root = process.cwd();

const binaryExts = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
  ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".mp3", ".mp4", ".mov", ".webm", ".lockb",
]);

const provenanceFiles = new Set([
  "NOTICE",
  "UPSTREAM.md",
  ".github/workflows/bootstrap-eve-to-kaf.yml",
]);
const provenanceLiterals = ["generated/eve-full-import-9c36b7c"];

function walk(dir, visitor) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(file, visitor);
    else if (entry.isFile()) visitor(file);
  }
}

function isTextFile(file, buffer) {
  if (binaryExts.has(path.extname(file).toLowerCase())) return false;
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
}

const manifests = [];
walk(root, (file) => {
  if (path.basename(file) !== "package.json") return;
  try {
    manifests.push(JSON.parse(fs.readFileSync(file, "utf8")));
  } catch {
    // Other repository guards own manifest syntax failures.
  }
});

const internalPackageNames = new Set(
  manifests.map((manifest) => manifest.name).filter((name) => typeof name === "string"),
);
const dependencyFields = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
const evePackageToken = /(^|[/_\-.])eve($|[_.-])/i;
const externalEvePackages = new Set();
for (const manifest of manifests) {
  for (const field of dependencyFields) {
    const dependencies = manifest[field];
    if (!dependencies || typeof dependencies !== "object") continue;
    for (const dependencyName of Object.keys(dependencies)) {
      if (evePackageToken.test(dependencyName) && !internalPackageNames.has(dependencyName)) {
        externalEvePackages.add(dependencyName);
      }
    }
  }
}

const protectedLiterals = [...externalEvePackages, ...provenanceLiterals].sort(
  (a, b) => b.length - a.length,
);
const forbiddenIdentity = [
  { label: "standalone Eve identity", pattern: /\b(?:eve|Eve|EVE)\b/g },
  { label: "Eve-prefixed symbol", pattern: /\b(?:eve|Eve|EVE)(?=[A-Z0-9_])/g },
  { label: "embedded Eve symbol", pattern: /(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)/g },
  { label: "underscore Eve token", pattern: /(?<=_)eve(?=_|$)/g },
];
const forbiddenOwnership = [
  { label: "Vercel project ownership badge", pattern: /MADE(?:%20|\s)+BY(?:%20|\s)+Vercel/gi },
  { label: "Vercel security mailbox", pattern: /responsible\.disclosure@vercel\.com/gi },
  { label: "Vercel beta terms applied to Kaf", pattern: /Vercel beta terms/gi },
];

function maskProtectedLiterals(text) {
  let output = text;
  for (const literal of protectedLiterals) output = output.split(literal).join("__KAF_ALLOWED_EXTERNAL_OR_PROVENANCE__");
  return output;
}

function isProvenancePath(relative) {
  if (provenanceFiles.has(relative)) return true;
  if (relative.startsWith(".kaf-migration/")) return true;
  return /(^|\/)LICENSE(?:\.[^/]*)?$/.test(relative);
}

const violations = [];
walk(root, (file) => {
  const relative = path.relative(root, file).split(path.sep).join("/");
  if (isProvenancePath(relative)) return;
  const buffer = fs.readFileSync(file);
  if (!isTextFile(file, buffer)) return;
  const text = maskProtectedLiterals(buffer.toString("utf8"));

  for (const rule of [...forbiddenIdentity, ...forbiddenOwnership]) {
    rule.pattern.lastIndex = 0;
    const matches = [...text.matchAll(rule.pattern)];
    if (!matches.length) continue;
    violations.push({ file: relative, rule: rule.label, count: matches.length });
  }
});

const result = {
  externalEvePackages: [...externalEvePackages].sort(),
  allowedProvenanceLiterals: provenanceLiterals,
  violationCount: violations.reduce((sum, item) => sum + item.count, 0),
  violations,
};
console.log(JSON.stringify(result, null, 2));

if (violations.length) {
  console.error(`[kaf:identity-audit] FAIL: ${result.violationCount} project-identity hit(s) remain.`);
  process.exit(1);
}

console.log("[kaf:identity-audit] ok — Kaf project identity is clean outside explicit provenance and external package coordinates.");
