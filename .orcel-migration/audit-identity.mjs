import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const binaryExts = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
  ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".mp3", ".mp4", ".mov", ".webm", ".lockb",
]);
const kafIdentity = /\b(?:kaf|Kaf|KAF)\b|\b(?:kaf|Kaf)(?=[A-Z0-9_])|\bKAF(?=_|[A-Z][a-z]|\d)|(?<=[a-z0-9_])Kaf(?=[A-Z0-9_]|$)|(?<=_)(?:kaf|Kaf|KAF)(?=[A-Za-z0-9_]|$)|%3[aA](?:kaf|Kaf|KAF)(?=%3[aA]|[A-Za-z0-9_]|$)|%20(?:kaf|Kaf|KAF)(?=[/%]|[A-Za-z0-9_]|$)|\\u[0-9a-fA-F]{4}(?:kaf|Kaf|KAF)(?=\\u[0-9a-fA-F]{4}|[A-Za-z0-9_]|$)/g;
const kafPathToken = /(^|[-_.])(?:kaf|Kaf|KAF)(?=$|[-_.])|^(?:kaf|Kaf|KAF)(?=[A-Z0-9_])/;

function isTextFile(file, buffer) {
  if (binaryExts.has(path.extname(file).toLowerCase())) return false;
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
}

const violations = [];

// Project-owned authored binary fixture must encode ORCEL-BINARY-ASSET, not the historical Eve payload.
const authoredBundlingEval = fs.readFileSync(path.join(root, "e2e/fixtures/agent-authored-bundling/evals/authored-bundling.eval.ts"), "utf8");
if (!authoredBundlingEval.includes("data:application/octet-stream;base64,T1JDRUwtQklOQVJZLUFTU0VUCg==") || authoredBundlingEval.includes("RVZFLUJJTkFSWS1BU1NFVAo=")) {
  violations.push({ file: "e2e/fixtures/agent-authored-bundling/evals/authored-bundling.eval.ts", rule: "authored-bundling binary fixture must use Orcel identity", count: 1 });
}
const eveEvidence = new Map();
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === ".git" || entry.name === "node_modules" || entry.name === "dist") continue;
    const file = path.join(dir, entry.name);
    const relative = path.relative(root, file).split(path.sep).join("/");
    const isLegacyEvidence = relative.startsWith(".orcel-migration/legacy/");
    const isMigrationTool = relative.startsWith(".orcel-migration/");
    if (!isLegacyEvidence && !isMigrationTool && kafPathToken.test(entry.name)) {
      violations.push({ file: relative, rule: "stale project-owned Kaf path" });
    }
    if (entry.isDirectory()) {
      walk(file);
      continue;
    }
    if (!entry.isFile() || isLegacyEvidence || isMigrationTool || entry.name === "LICENSE") continue;
    const buffer = fs.readFileSync(file);
    if (!isTextFile(file, buffer)) continue;
    const text = buffer.toString("utf8");
    if (
      text.includes('framework: "orcel"') ||
      text.includes('"framework": "orcel"') ||
      text.includes('framework=orcel')
    ) {
      violations.push({ file: relative, rule: "stale Orcel-mutated Vercel framework identifier" });
    }
    kafIdentity.lastIndex = 0;
    const kafMatches = [...text.matchAll(kafIdentity)];
    if (kafMatches.length) violations.push({ file: relative, rule: "stale project-owned Kaf identity", count: kafMatches.length });

    const eveMatches = text.match(/\b(?:eve|Eve|EVE)\b|@vercel\/connect\/eve|@github-tools\/sdk\/eve|ghcr\.io\/vercel\/eve|VERCEL_EVE_IMAGE|EVE_IMAGE/g);
    if (eveMatches?.length) eveEvidence.set(relative, eveMatches.length);
  }
}
walk(root);

function assertFile(relative, predicate, rule) {
  const file = path.join(root, relative);
  if (!fs.existsSync(file)) {
    violations.push({ file: relative, rule: `${rule}: missing file` });
    return;
  }
  const text = fs.readFileSync(file, "utf8");
  if (!predicate(text)) violations.push({ file: relative, rule });
}

assertFile(
  "packages/orcel/src/setup/vercel-project-framework.ts",
  (text) =>
    text.includes('const VERCEL_EVE_FRAMEWORK_PRESET = "eve";') &&
    !text.includes('const ORCEL_FRAMEWORK_PRESET = "orcel";'),
  "Vercel project setup must use the external `eve` framework preset for standalone Orcel",
);
assertFile(
  "packages/orcel/src/shared/vercel-services.ts",
  (text) => text.includes('framework: "eve"') && !text.includes('framework: "orcel"'),
  "Vercel service framework must preserve external `eve` identifier",
);
assertFile(
  "packages/orcel/src/internal/vercel/orcel-service-contribution.ts",
  (text) => text.includes('framework: "eve"') && !text.includes('framework: "orcel"'),
  "Vercel service diagnostics must preserve external `eve` identifier",
);
assertFile(
  "packages/orcel/src/execution/sandbox/bindings/orcel-image.test.ts",
  (text) =>
    text.includes("ghcr.io/vercel/eve:") &&
    text.includes("vcr.vercel.com/vercel/eve/base:") &&
    !text.includes("ghcr.io/thehalfmoon/orcel") &&
    !text.includes("vcr.vercel.com/vercel/orcel/base"),
  "sandbox image tests must assert the retained external Eve image coordinates",
);
assertFile(
  "packages/orcel/src/execution/sandbox/bindings/orcel-image.ts",
  (text) =>
    text.includes('const GHCR_ORCEL_SANDBOX_IMAGE_REPOSITORY = "ghcr.io/vercel/eve";') &&
    text.includes('return `${GHCR_ORCEL_SANDBOX_IMAGE_REPOSITORY}:${resolveOrcelSandboxImageTag()}`;') &&
    !text.includes("ghcr.io/thehalfmoon/orcel"),
  "runtime image must preserve the available upstream Vercel/Eve coordinate",
);
assertFile(
  "packages/orcel/src/internal/testing/scenario-app.ts",
  (text) =>
    text.includes('? { eve: `file:./${tarballFileName}` }') &&
    text.includes('"--config.auto-install-peers=false"'),
  "scenario apps must use the Orcel tarball for Eve compatibility and disable registry peer auto-install",
);
assertFile(
  ".github/workflows/orcel-import-qualification.yml",
  (text) =>
    text.includes("name: Orcel Import Qualification") &&
    text.includes("oven-sh/setup-bun@0c5077e51419868618aeaa5fe8019c62421857d6"),
  "qualification workflow must use Orcel identity and install pinned Bun for Scenario tests",
);

for (const relative of [
  "apps/templates/orcel-chat-template/package.json",
  "apps/templates/orcel-slack-agent-template/package.json",
  "apps/templates/personal-agent-template/package.json",
]) {
  assertFile(
    relative,
    (text) => /"eve"\s*:\s*"npm:orcel@/.test(text),
    "@vercel/connect compatibility alias must point historical Eve name at Orcel",
  );
}

for (const obsolete of [
  ".kaf-migration",
  ".github/workflows/bootstrap-eve-to-kaf.yml",
  ".github/workflows/kaf-parity-repair.yml",
  ".github/workflows/kaf-import-qualification.yml",
]) {
  if (fs.existsSync(path.join(root, obsolete))) violations.push({ file: obsolete, rule: "obsolete Kaf migration surface remains" });
}

const result = {
  violationCount: violations.reduce((sum, item) => sum + (item.count ?? 1), 0),
  violations,
  retainedEveVercelCompatibilityAndProvenanceFiles: [...eveEvidence.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([file, count]) => ({ file, count })),
};
console.log(JSON.stringify(result, null, 2));
if (violations.length) {
  console.error(`[orcel:identity-audit] FAIL: ${result.violationCount} violation(s).`);
  process.exit(1);
}
console.log("[orcel:identity-audit] ok — Orcel identity is clean and required Eve/Vercel compatibility coordinates are explicitly retained.");
