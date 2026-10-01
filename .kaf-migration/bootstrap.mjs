import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const root = process.cwd();
const upstream = process.argv[2];
if (!upstream || !fs.existsSync(upstream)) {
  throw new Error("Usage: node .kaf-migration/bootstrap.mjs <upstream-eve-dir>");
}

const preserved = new Map();
for (const rel of [
  "UPSTREAM.md",
  ".kaf-migration/bootstrap.mjs",
  ".kaf-migration/audit-identity.mjs",
  ".kaf-migration/repair-parity.mjs",
  ".kaf-migration/repair-final-parity.mjs",
  ".github/workflows/bootstrap-eve-to-kaf.yml",
  ".github/workflows/kaf-parity-repair.yml",
  ".github/workflows/kaf-import-qualification.yml",
]) {
  const file = path.join(root, rel);
  if (fs.existsSync(file)) preserved.set(rel, fs.readFileSync(file));
}

function walkPackageJsonFiles(dir, visitor) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules") continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkPackageJsonFiles(file, visitor);
      continue;
    }
    if (entry.isFile() && entry.name === "package.json") visitor(file);
  }
}

const internalPackageNames = new Set();
walkPackageJsonFiles(upstream, (file) => {
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  if (typeof manifest.name === "string") internalPackageNames.add(manifest.name);
});

const internalPackageScopes = new Set(
  [...internalPackageNames]
    .filter((name) => name.startsWith("@") && name.includes("/"))
    .map((name) => name.slice(0, name.indexOf("/"))),
);

const dependencyFields = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];
const evePackageToken = /(^|[/_\-.])eve($|[_.-])/i;
const externalEvePackages = new Set();
walkPackageJsonFiles(upstream, (file) => {
  const manifest = JSON.parse(fs.readFileSync(file, "utf8"));
  for (const field of dependencyFields) {
    const dependencies = manifest[field];
    if (!dependencies || typeof dependencies !== "object") continue;
    for (const dependencyName of Object.keys(dependencies)) {
      if (evePackageToken.test(dependencyName) && !internalPackageNames.has(dependencyName)) {
        externalEvePackages.add(dependencyName);
      }
    }
  }
});

function removeExceptGit(dir) {
  for (const name of fs.readdirSync(dir)) {
    if (name === ".git") continue;
    fs.rmSync(path.join(dir, name), { recursive: true, force: true });
  }
}

function copyTree(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name === ".git") continue;
    const from = path.join(src, entry.name);
    const to = path.join(dst, entry.name);
    if (entry.isDirectory()) copyTree(from, to);
    else if (entry.isSymbolicLink()) fs.symlinkSync(fs.readlinkSync(from), to);
    else fs.copyFileSync(from, to);
  }
}

function renameInternalScope(name) {
  if (!internalPackageScopes.has(name)) return name;
  return name
    .replace(/^@EVE(?=$|[-_.])/g, "@KAF")
    .replace(/^@Eve(?=$|[-_.])/g, "@Kaf")
    .replace(/^@eve(?=$|[-_.])/g, "@kaf");
}

function identityName(name) {
  return renameInternalScope(name)
    .replace(/^EVE(?=_|[A-Z][a-z]|\d)/g, "KAF")
    .replace(/^Eve(?=[A-Z0-9])/g, "Kaf")
    .replace(/^eve(?=[A-Z0-9])/g, "kaf")
    .replace(/(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)/g, "Kaf")
    .replace(/(^|[-_.])EVE(?=$|[-_.])/g, "$1KAF")
    .replace(/(^|[-_.])Eve(?=$|[-_.])/g, "$1Kaf")
    .replace(/(^|[-_.])eve(?=$|[-_.])/g, "$1kaf");
}

function renamePaths(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === ".kaf-migration") continue;
    const oldPath = path.join(dir, entry.name);
    if (entry.isDirectory()) renamePaths(oldPath);
    const nextName = identityName(entry.name);
    if (nextName !== entry.name) fs.renameSync(oldPath, path.join(dir, nextName));
  }
}

const binaryExts = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
  ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".mp3", ".mp4", ".mov", ".webm", ".lockb",
]);

// External provider API coordinates are not project branding. Preserve the
// exact upstream literal when it is part of a third-party package API.
const externalProviderApiLiterals = [
  "@vercel/connect/eve",
  "experimental_createConnectManifestFromEveResources",
  "@github-tools/sdk/eve",
  "buildEveToolMap",
];
const protectedLiterals = [...new Set([...externalEvePackages, ...externalProviderApiLiterals])].sort(
  (a, b) => b.length - a.length,
);

function isTextFile(file, buffer) {
  if (binaryExts.has(path.extname(file).toLowerCase())) return false;
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
}

function renameIdentityTokens(text) {
  return text
    .replaceAll("@eve-internal/", "@kaf-internal/")
    .replaceAll("@eve/", "@kaf/")
    .replaceAll("eve-source", "kaf-source")
    .replaceAll("EVE_", "KAF_")
    .replace(/\.eve(?=$|[/\\._-])/g, ".kaf")
    .replace(/\bEVE(?=_|[A-Z][a-z]|\d)/g, "KAF")
    .replace(/\bEve(?=[A-Z0-9_])/g, "Kaf")
    .replace(/\beve(?=[A-Z0-9_])/g, "kaf")
    .replace(/(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)/g, "Kaf")
    .replace(/(?<=_)eve(?=_|$)/g, "kaf")
    .replace(/\bEVE\b/g, "KAF")
    .replace(/\bEve\b/g, "Kaf")
    .replace(/\beve\b/g, "kaf");
}

function transformText(input) {
  const placeholders = new Map();
  let text = input;
  protectedLiterals.forEach((literal, index) => {
    const token = `__KAF_PROTECTED_${index}_${crypto.createHash("sha1").update(literal).digest("hex")}__`;
    placeholders.set(token, literal);
    text = text.replaceAll(literal, token);
  });

  text = text
    .replaceAll("git+https://github.com/vercel/eve.git", "git+https://github.com/TheHalfMoon/kaf.git")
    .replaceAll("https://github.com/vercel/eve", "https://github.com/TheHalfMoon/kaf")
    .replaceAll("https://eve.dev/", "https://kaf.dev/")
    .replaceAll("https://eve.dev", "https://kaf.dev");
  text = renameIdentityTokens(text);

  for (const [token, literal] of placeholders) text = text.replaceAll(token, literal);
  return text;
}

let textFiles = 0;
let transformedFiles = 0;
let totalFiles = 0;

function transformTree(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === ".kaf-migration") continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      transformTree(file);
      continue;
    }
    if (!entry.isFile()) continue;
    totalFiles += 1;
    if (["LICENSE", "NOTICE"].includes(path.basename(file))) continue;
    const before = fs.readFileSync(file);
    if (!isTextFile(file, before)) continue;
    textFiles += 1;
    const input = before.toString("utf8");
    const output = transformText(input);
    if (output !== input) {
      fs.writeFileSync(file, output);
      transformedFiles += 1;
    }
  }
}

removeExceptGit(root);
copyTree(upstream, root);
renamePaths(root);
transformTree(root);

// Apply Kaf-specific compatibility corrections after the generic identity
// transform. These are semantic adaptations, not branding substitutions.
{
  const docsCheckerPath = path.join(root, "scripts/check-docs.mjs");
  let docsChecker = fs.readFileSync(docsCheckerPath, "utf8");
  docsChecker = docsChecker
    .replaceAll(
      "https://github.com/TheHalfMoon/kaf" + "$" + "{sourceUrl}",
      "https://kaf.invalid" + "$" + "{sourceUrl}",
    )
    .replaceAll(
      "https://github.com/TheHalfMoon/kaf/docs/channels/overview",
      "https://kaf.invalid/docs/channels/overview",
    );
  fs.writeFileSync(docsCheckerPath, docsChecker);

  const slackChannelPath = path.join(
    root,
    "apps/templates/kaf-chat-template/agent/channels/slack.ts",
  );
  let slackChannelSource = fs.readFileSync(slackChannelPath, "utf8");
  slackChannelSource = slackChannelSource
    .replace(
      'import { connectSlackCredentials } from "@vercel/connect/eve";\nimport { slackChannel } from "kaf/channels/slack";',
      'import { getToken } from "@vercel/connect";\nimport { vercelOidc } from "kaf/channels/auth";\nimport { slackChannel } from "kaf/channels/slack";',
    )
    .replace(
      "  credentials: connectSlackCredentials(slackConnector),",
      '  credentials: {\n    botToken: () => getToken(slackConnector, { subject: { type: "app" } }),\n    webhookVerifier: vercelOidc(),\n  },',
    );
  fs.writeFileSync(slackChannelPath, slackChannelSource);

  const githubToolsPath = path.join(
    root,
    "apps/templates/personal-agent-template/agent/tools/github.ts",
  );
  if (fs.existsSync(githubToolsPath)) {
    let githubToolsSource = fs.readFileSync(githubToolsPath, "utf8");
    githubToolsSource = githubToolsSource
      .replace(
        'import { buildEveToolMap } from "@github-tools/sdk/eve";',
        'import { buildEveToolMap as buildKafToolMap } from "@github-tools/sdk/eve";',
      )
      .replace("return buildEveToolMap(", "return buildKafToolMap(");
    fs.writeFileSync(githubToolsPath, githubToolsSource);
  }

  // @vercel/connect currently imports the framework by its historical bare
  // package name. Keep that provider compatibility name scoped to templates
  // and point it at the exact same Kaf package range rather than shipping Eve.
  for (const relative of [
    "apps/templates/kaf-chat-template/package.json",
    "apps/templates/kaf-slack-agent-template/package.json",
    "apps/templates/personal-agent-template/package.json",
  ]) {
    const manifestPath = path.join(root, relative);
    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
    if (manifest.dependencies?.["@vercel/connect"] && manifest.dependencies.kaf) {
      manifest.dependencies.eve = `npm:kaf@${manifest.dependencies.kaf}`;
      fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    }
  }

  const composeTestPath = path.join(root, "apps/docs/lib/templates/compose.test.ts");
  let composeTest = fs.readFileSync(composeTestPath, "utf8");
  composeTest = composeTest.replace(
    'owner: "vercel",\n        repo: "kaf",',
    'owner: "TheHalfMoon",\n        repo: "kaf",',
  );
  fs.writeFileSync(composeTestPath, composeTest);
}

for (const [rel, data] of preserved) {
  const target = path.join(root, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, data);
}

const upstreamNotice = fs.readFileSync(path.join(upstream, "NOTICE"), "utf8");
fs.writeFileSync(
  path.join(root, "NOTICE"),
  `Kaf\nCopyright 2026 TheHalfMoon and contributors\n\n` +
    `Kaf is derived from the eve project originally developed by Vercel, Inc.\n` +
    `Initial migration base: vercel/eve@9c36b7c280fda89ae678cabfd8d906f4bde2216f.\n\n` +
    `Upstream notice follows unchanged:\n\n${upstreamNotice}`,
);
fs.copyFileSync(path.join(upstream, "LICENSE"), path.join(root, "LICENSE"));

const identityResidualPattern = /\b(?:eve|Eve|EVE)\b|\b(?:eve|Eve)(?=[A-Z0-9_])|\bEVE(?=_|[A-Z][a-z]|\d)|(?<=[a-z0-9_])Eve(?=[A-Z0-9_]|$)|(?<=_)eve(?=_|$)/g;
const residuals = [];
const staleInternalScopePaths = [];
function scanResiduals(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === ".kaf-migration") continue;
    const file = path.join(dir, entry.name);
    if (internalPackageScopes.has(entry.name) && renameInternalScope(entry.name) !== entry.name) {
      staleInternalScopePaths.push(path.relative(root, file));
    }
    if (entry.isDirectory()) {
      scanResiduals(file);
      continue;
    }
    if (!entry.isFile() || ["LICENSE", "NOTICE"].includes(entry.name)) continue;
    const buffer = fs.readFileSync(file);
    if (!isTextFile(file, buffer)) continue;
    const text = buffer.toString("utf8");
    const matches = text.match(identityResidualPattern);
    if (matches) residuals.push({ file: path.relative(root, file), count: matches.length });
  }
}
scanResiduals(root);

if (staleInternalScopePaths.length > 0) {
  throw new Error(
    `Stale project-owned package-scope paths remain after migration: ${staleInternalScopePaths.join(", ")}`,
  );
}

const report = [
  "# Kaf Full-Import Report",
  "",
  "- Upstream: `vercel/eve@9c36b7c280fda89ae678cabfd8d906f4bde2216f`",
  `- Files copied: ${totalFiles}`,
  `- Text files inspected: ${textFiles}`,
  `- Text files transformed: ${transformedFiles}`,
  `- External Eve package/provider API literals preserved: ${protectedLiterals.length}`,
  `- Stale project-owned package-scope paths: ${staleInternalScopePaths.length}`,
  `- Residual project-identity hits outside LICENSE/NOTICE: ${residuals.reduce((n, item) => n + item.count, 0)}`,
  "",
  "## Preserved external package/provider API literals",
  "",
  protectedLiterals.length ? protectedLiterals.map((item) => `- \`${item}\``).join("\n") : "None.",
  "",
  "## Residual identity hits",
  "",
  residuals.length ? residuals.map((item) => `- \`${item.file}\`: ${item.count}`).join("\n") : "None.",
  "",
  "## Rename policy",
  "",
  "Project-owned eve identity is renamed to Kaf. Project-owned GitHub URLs are redirected to TheHalfMoon/kaf, while docs-site origins retain origin semantics as kaf.dev.",
  "Project-owned package scopes are discovered from upstream workspace manifests and renamed consistently in both text and paths.",
  "Actual external package coordinates and provider API literals are preserved when they are not owned by Kaf.",
  "Actual `@vercel/*` dependencies and Vercel provider/service names remain intact because renaming them would break runtime behavior.",
  "Apache-2.0 LICENSE is copied byte-for-byte from upstream; upstream NOTICE is retained verbatim beneath Kaf attribution.",
  "",
].join("\n");
fs.mkdirSync(path.join(root, ".kaf-migration"), { recursive: true });
fs.writeFileSync(path.join(root, ".kaf-migration", "REPORT.md"), report);

console.log(JSON.stringify({
  totalFiles,
  textFiles,
  transformedFiles,
  protectedExternalLiterals: protectedLiterals.length,
  staleInternalScopePaths: staleInternalScopePaths.length,
  residualFiles: residuals.length,
}, null, 2));