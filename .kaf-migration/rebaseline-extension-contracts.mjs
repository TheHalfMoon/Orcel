import { execFileSync } from "node:child_process";
import { readFile, rm } from "node:fs/promises";
import { join, relative } from "node:path";

import {
  COMPATIBILITY_SOURCE,
  REPORT_ROOT,
  REPO_ROOT,
  parseCapabilityConfiguration,
  toPosix,
} from "../scripts/extension-contracts/configuration.mjs";

function existsOnMain(relativePath) {
  try {
    execFileSync("git", ["cat-file", "-e", `origin/main:${relativePath}`], {
      cwd: REPO_ROOT,
      stdio: "ignore",
    });
    return true;
  } catch {
    return false;
  }
}

const source = await readFile(COMPATIBILITY_SOURCE, "utf8");
const configuration = parseCapabilityConfiguration(source);
const removed = [];

for (const [capability, currentEpoch] of Object.entries(configuration.current)) {
  const reportPath = join(REPORT_ROOT, capability, `v${currentEpoch}.json`);
  const relativePath = toPosix(relative(REPO_ROOT, reportPath));

  if (existsOnMain(relativePath)) {
    throw new Error(
      `Refusing to rebaseline published Kaf contract metadata: ${relativePath} already exists on origin/main.`,
    );
  }

  await rm(reportPath, { force: true });
  removed.push(relativePath);
}

console.log(
  JSON.stringify(
    {
      action: "initial-kaf-contract-rebaseline",
      removedCurrentMetadata: removed,
    },
    null,
    2,
  ),
);
