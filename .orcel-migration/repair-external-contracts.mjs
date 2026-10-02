import fs from "node:fs";
import path from "node:path";

const root = process.cwd();
const checkOnly = process.argv.includes("--check");
const binaryExts = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tgz",
  ".woff", ".woff2", ".ttf", ".eot", ".wasm", ".mp3", ".mp4", ".mov", ".webm", ".lockb",
]);

function isTextFile(file, buffer) {
  if (binaryExts.has(path.extname(file).toLowerCase())) return false;
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
}

function repair(text) {
  return text
    // eve-bench is an upstream/private Vercel compatibility service. The old
    // Eve→Kaf import renamed these coordinates even though Orcel does not own them.
    .replaceAll("vercel-labs/orcel-bench", "vercel-labs/eve-bench")
    .replaceAll("ORCEL_BENCH_", "EVE_BENCH_")
    .replaceAll(".orcel-bench-action", ".eve-bench-action")
    .replaceAll("orcel-bench", "eve-bench")
    // These provider/runtime coordinates are owned by Vercel, not Orcel.
    .replaceAll("@vercel/connect/orcel", "@vercel/connect/eve")
    .replaceAll("ghcr.io/vercel/orcel", "ghcr.io/vercel/eve")
    // The benchmark must evaluate the candidate repository, not a fabricated
    // `vercel/orcel` coordinate produced by the historical blind rename.
    .replaceAll("agent-repository: vercel/orcel", "agent-repository: ${{ github.repository }}")
    // eve-bench owns the harness identifier even though the local package path is
    // project-owned and is correctly renamed to packages/orcel-code.
    .replaceAll("default: orcel-code,opencode,pi", "default: eve-code,opencode,pi")
    .replaceAll("contenders: orcel-code@baseline,orcel-code@head", "contenders: eve-code@baseline,eve-code@head");
}

const changed = [];
const staleExternal = [];

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (
      entry.name === ".git" ||
      entry.name === "node_modules" ||
      entry.name === "dist" ||
      entry.name === ".orcel-migration"
    ) continue;
    const file = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(file);
      continue;
    }
    if (!entry.isFile() || path.basename(file) === "LICENSE") continue;
    const buffer = fs.readFileSync(file);
    if (!isTextFile(file, buffer)) continue;
    const before = buffer.toString("utf8");
    const after = repair(before);
    if (after !== before) {
      changed.push(path.relative(root, file).split(path.sep).join("/"));
      if (!checkOnly) fs.writeFileSync(file, after);
    }
    const inspected = checkOnly ? before : after;
    for (const token of [
      "vercel-labs/orcel-bench",
      "ORCEL_BENCH_",
      ".orcel-bench-action",
      "orcel-bench",
      "@vercel/connect/orcel",
      "ghcr.io/vercel/orcel",
      "agent-repository: vercel/orcel",
    ]) {
      if (inspected.includes(token)) staleExternal.push({ file: path.relative(root, file).split(path.sep).join("/"), token });
    }
  }
}

walk(root);

if (checkOnly && changed.length) {
  console.error(JSON.stringify({ changed, staleExternal }, null, 2));
  throw new Error("External compatibility repair is not idempotent; repairable Orcel-mutated provider coordinates remain.");
}
if (staleExternal.length) {
  console.error(JSON.stringify({ staleExternal }, null, 2));
  throw new Error("Stale Orcel-mutated external compatibility coordinates remain.");
}

const benchmark = path.join(root, ".github", "workflows", "orcel-code-benchmark.yml");
if (fs.existsSync(benchmark)) {
  const text = fs.readFileSync(benchmark, "utf8");
  for (const required of [
    "repository: vercel-labs/eve-bench",
    "secrets.EVE_BENCH_SSH_KEY",
    "secrets.EVE_BENCH_BLOB_READ_WRITE_TOKEN",
    "agent-repository: ${{ github.repository }}",
    "agent-paths: '[\"packages/orcel-code\"]'",
    "default: eve-code,opencode,pi",
  ]) {
    if (!text.includes(required)) throw new Error(`Benchmark compatibility contract missing: ${required}`);
  }
}

console.log(`[orcel:external-contracts] ${checkOnly ? "check" : "repair"} ok; changed=${changed.length}`);
