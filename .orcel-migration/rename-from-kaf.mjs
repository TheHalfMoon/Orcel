import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const binaryExts = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
  ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".mp3", ".mp4", ".mov", ".webm", ".lockb",
]);

function isTextFile(file, buffer) {
  if (binaryExts.has(path.extname(file).toLowerCase())) return false;
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
}

function renameIdentityName(name) {
  return name
    .replace(/^KAF(?=_|[A-Z][a-z]|\d)/g, "ORCEL")
    .replace(/^Kaf(?=[A-Z0-9])/g, "Orcel")
    .replace(/^kaf(?=[A-Z0-9])/g, "orcel")
    .replace(/(?<=[a-z0-9_])Kaf(?=[A-Z0-9_]|$)/g, "Orcel")
    .replace(/(^|[-_.])KAF(?=$|[-_.])/g, "$1ORCEL")
    .replace(/(^|[-_.])Kaf(?=$|[-_.])/g, "$1Orcel")
    .replace(/(^|[-_.])kaf(?=$|[-_.])/g, "$1orcel");
}

function renameIdentityText(text) {
  return text
    .replaceAll("@kaf-internal/", "@orcel-internal/")
    .replaceAll("@kaf/", "@orcel/")
    .replaceAll("kaf-source", "orcel-source")
    .replaceAll("KAF_", "ORCEL_")
    .replace(/\.kaf(?=$|[/\\._-])/g, ".orcel")
    .replace(/\bKAF(?=_|[A-Z][a-z]|\d)/g, "ORCEL")
    .replace(/\bKaf(?=[A-Z0-9_])/g, "Orcel")
    .replace(/\bkaf(?=[A-Z0-9_])/g, "orcel")
    .replace(/(?<=[a-z0-9_])Kaf(?=[A-Z0-9_]|$)/g, "Orcel")
    .replace(/(?<=_)kaf(?=_|$)/g, "orcel")
    .replace(/\bKAF\b/g, "ORCEL")
    .replace(/\bKaf\b/g, "Orcel")
    .replace(/\bkaf\b/g, "orcel");
}

function walkText(dir, visitor) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === ".orcel-migration") continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkText(file, visitor);
      continue;
    }
    if (!entry.isFile() || path.basename(file) === "LICENSE") continue;
    const buffer = fs.readFileSync(file);
    if (isTextFile(file, buffer)) visitor(file, buffer.toString("utf8"));
  }
}

function renamePaths(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === ".orcel-migration" || entry.name === ".kaf-migration") continue;
    const oldPath = path.join(dir, entry.name);
    if (entry.isDirectory()) renamePaths(oldPath);
    const nextName = renameIdentityName(entry.name);
    if (nextName !== entry.name) {
      const nextPath = path.join(dir, nextName);
      if (fs.existsSync(nextPath)) throw new Error(`Refusing to overwrite existing path during Orcel rename: ${nextPath}`);
      fs.renameSync(oldPath, nextPath);
    }
  }
}

function writeHistoricalEvidence() {
  const legacyRoot = path.join(root, ".orcel-migration", "legacy");
  fs.mkdirSync(legacyRoot, { recursive: true });
  for (const [sourceName, targetName] of [
    ["QUALIFICATION.md", "initial-import-qualification.md"],
    ["REPORT.md", "initial-import-report.md"],
  ]) {
    const source = path.join(root, ".kaf-migration", sourceName);
    const target = path.join(legacyRoot, targetName);
    if (!fs.existsSync(source) || fs.existsSync(target)) continue;
    const original = fs.readFileSync(source, "utf8");
    fs.writeFileSync(
      target,
      `# Historical pre-Orcel migration evidence\n\nThis file preserves evidence from the temporary Kaf-named migration phase verbatim. It is provenance, not current Orcel identity.\n\n---\n\n${original}`,
    );
  }
}

function replaceInFile(relative, transform) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file)) throw new Error(`Expected file is missing: ${relative}`);
  const before = fs.readFileSync(file, "utf8");
  const after = transform(before);
  if (after !== before) fs.writeFileSync(file, after);
}

writeHistoricalEvidence();

// Obsolete bootstrap/parity workflows would re-import upstream and are intentionally
// removed. Orcel continues from the already-imported exact Eve lineage instead.
for (const relative of [
  ".github/workflows/bootstrap-eve-to-kaf.yml",
  ".github/workflows/kaf-parity-repair.yml",
]) {
  fs.rmSync(path.join(root, relative), { force: true });
}

walkText(root, (file, text) => {
  const output = renameIdentityText(text);
  if (output !== text) fs.writeFileSync(file, output);
});
renamePaths(root);

// Vercel's framework identifier is an external platform contract. The product is
// Orcel, but Vercel CLI must continue to receive the historical `eve` framework.
replaceInFile("packages/orcel/src/shared/vercel-services.ts", (text) =>
  text
    .replaceAll('service.framework === "orcel"', 'service.framework === "eve"')
    .replaceAll('framework: "orcel"', 'framework: "eve"')
    .replaceAll('framework "orcel"', 'framework "eve"')
    .replaceAll('framework \'orcel\'', 'framework \'eve\''),
);
replaceInFile("packages/orcel/src/internal/vercel/orcel-service-contribution.ts", (text) =>
  text.replaceAll('framework: "orcel"', 'framework: "eve"'),
);

// The runtime image is still an upstream Vercel/Eve compatibility coordinate.
// Orcel-specific environment variables are first-class while historical Eve
// variables remain supported as provider compatibility aliases.
replaceInFile("packages/orcel/src/execution/sandbox/bindings/orcel-image.ts", () => `import { packageVersion } from "../../../package-version.js";\n\nconst upstreamEveImage =\n  process.env.VERCEL_EVE_IMAGE ||\n  process.env.EVE_IMAGE ||\n  \`ghcr.io/vercel/eve:\${packageVersion}\`;\n\nexport const VERCEL_ORCEL_IMAGE = process.env.VERCEL_ORCEL_IMAGE || upstreamEveImage;\n\nexport const ORCEL_IMAGE = process.env.ORCEL_IMAGE || VERCEL_ORCEL_IMAGE;\n`);

// @vercel/connect/eve imports the framework package by the historical bare name.
// Scenario apps that exercise that provider boundary install the exact same Orcel
// tarball under the compatibility alias instead of pulling a second framework.
replaceInFile("packages/orcel/src/internal/testing/scenario-app.ts", (text) => {
  const needle = '      [ORCEL_PACKAGE_NAME]: `file:./${tarballFileName}`,\n      ...input.descriptor.dependencies,';
  if (!text.includes(needle)) return text;
  return text.replace(
    needle,
    '      [ORCEL_PACKAGE_NAME]: `file:./${tarballFileName}`,\n      ...(input.descriptor.dependencies?.["@vercel/connect"]\n        ? { eve: `file:./${tarballFileName}` }\n        : {}),\n      ...input.descriptor.dependencies,',
  );
});

// Vercel service configuration literals can also appear in fixtures and tests.
walkText(root, (file, text) => {
  if (!file.includes(`${path.sep}vercel${path.sep}`) && !file.includes("vercel-services")) return;
  const output = text
    .replaceAll('framework: "orcel"', 'framework: "eve"')
    .replaceAll('framework === "orcel"', 'framework === "eve"')
    .replaceAll('"framework": "orcel"', '"framework": "eve"');
  if (output !== text) fs.writeFileSync(file, output);
});

// Add Bun to the exact job that runs Bun-backed Scenario tests. Pin the action
// commit for deterministic supply-chain evidence.
replaceInFile(".github/workflows/orcel-import-qualification.yml", (text) => {
  if (text.includes("oven-sh/setup-bun@")) return text;
  const needle = "      - name: Install dependencies from lockfile\n        run: pnpm install --frozen-lockfile\n";
  const replacement =
    "      - name: Setup Bun for Scenario compatibility\n" +
    "        uses: oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6 # v2\n\n" +
    needle;
  const index = text.indexOf(needle);
  if (index === -1) throw new Error("Could not locate the static-and-unit dependency-install step.");
  return text.slice(0, index) + replacement + text.slice(index + needle.length);
});

// Current legal notice gets Orcel identity; the appended upstream notice remains
// otherwise untouched and continues to preserve Vercel/Eve attribution.
replaceInFile("NOTICE", (text) =>
  text
    .replace(/^Kaf\nCopyright 2026 TheHalfMoon and contributors/m, "Orcel\nCopyright 2026 TheHalfMoon and contributors")
    .replace(/^Kaf is derived from the eve project/m, "Orcel is derived from the eve project"),
);

// Remove obsolete Kaf-named migration tooling only after preserving its evidence.
fs.rmSync(path.join(root, ".kaf-migration"), { recursive: true, force: true });

console.log("[orcel:identity-migration] project-owned Kaf identity rewritten to Orcel; external Eve/Vercel compatibility contracts preserved.");
