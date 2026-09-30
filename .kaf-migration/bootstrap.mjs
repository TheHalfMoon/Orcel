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
  ".github/workflows/bootstrap-eve-to-kaf.yml",
]) {
  const file = path.join(root, rel);
  if (fs.existsSync(file)) preserved.set(rel, fs.readFileSync(file));
}

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

function identityName(name) {
  return name.replaceAll("EVE", "KAF").replaceAll("Eve", "Kaf").replaceAll("eve", "kaf");
}

function renamePaths(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === ".kaf-migration") continue;
    const oldPath = path.join(dir, entry.name);
    if (entry.isDirectory()) renamePaths(oldPath);
    const nextName = identityName(entry.name);
    if (nextName !== entry.name) {
      const nextPath = path.join(dir, nextName);
      fs.renameSync(oldPath, nextPath);
    }
  }
}

const binaryExts = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
  ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".mp3", ".mp4", ".mov", ".webm", ".lockb",
]);

const protectedLiterals = [
  "@stripe/link-integrations-eve",
  "Copyright 2026 Vercel, Inc. and contributors",
  "Copyright 2023 Vercel, Inc.",
];

function isTextFile(file, buffer) {
  if (binaryExts.has(path.extname(file).toLowerCase())) return false;
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
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
    .replaceAll("https://github.com/vercel/eve", "https://github.com/TheHalfMoon/kaf")
    .replaceAll("git+https://github.com/vercel/eve.git", "git+https://github.com/TheHalfMoon/kaf.git")
    .replaceAll("https://eve.dev/", "https://github.com/TheHalfMoon/kaf/")
    .replaceAll("https://eve.dev", "https://github.com/TheHalfMoon/kaf")
    .replaceAll("@eve-internal/", "@kaf-internal/")
    .replaceAll("@eve/", "@kaf/")
    .replaceAll("eve-source", "kaf-source")
    .replaceAll("EVE_", "KAF_")
    .replaceAll(".eve", ".kaf")
    .replaceAll("Eve", "Kaf")
    .replaceAll("EVE", "KAF")
    .replaceAll("eve", "kaf");

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
    if (path.basename(file) === "LICENSE" || path.basename(file) === "NOTICE") continue;
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

const residuals = [];
function scanResiduals(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === ".kaf-migration") continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanResiduals(file);
      continue;
    }
    if (!entry.isFile() || ["LICENSE", "NOTICE"].includes(entry.name)) continue;
    const buffer = fs.readFileSync(file);
    if (!isTextFile(file, buffer)) continue;
    const text = buffer.toString("utf8");
    const matches = text.match(/\b(?:eve|Eve|EVE)\b/g);
    if (matches) residuals.push({ file: path.relative(root, file), count: matches.length });
  }
}
scanResiduals(root);

const report = [
  "# Kaf Full-Import Report",
  "",
  "- Upstream: `vercel/eve@9c36b7c280fda89ae678cabfd8d906f4bde2216f`",
  `- Files copied: ${totalFiles}`,
  `- Text files inspected: ${textFiles}`,
  `- Text files transformed: ${transformedFiles}`,
  `- Residual whole-word eve identity hits outside LICENSE/NOTICE: ${residuals.reduce((n, item) => n + item.count, 0)}`,
  "",
  "## Residual identity hits",
  "",
  residuals.length ? residuals.map((item) => `- \`${item.file}\`: ${item.count}`).join("\n") : "None.",
  "",
  "## Rename policy",
  "",
  "Project-owned eve identity is renamed to Kaf. Project-owned GitHub URLs are redirected to TheHalfMoon/kaf.",
  "Actual `@vercel/*` dependencies and Vercel provider/service names remain intact because renaming them would break runtime behavior.",
  "Apache-2.0 LICENSE is copied byte-for-byte from upstream; upstream NOTICE is retained verbatim beneath Kaf attribution.",
  "",
].join("\n");
fs.mkdirSync(path.join(root, ".kaf-migration"), { recursive: true });
fs.writeFileSync(path.join(root, ".kaf-migration", "REPORT.md"), report);

console.log(JSON.stringify({ totalFiles, textFiles, transformedFiles, residuals: residuals.length }, null, 2));
