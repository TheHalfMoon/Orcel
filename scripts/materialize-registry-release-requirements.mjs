import { readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";

const registryPath = join("apps", "docs", "registry.json");
const requirementsPath = join("apps", "docs", "registry.staged-requirements.json");
const orcelPackagePath = join("packages", "orcel", "package.json");
const versionPattern = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u;

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function materializeRegistryRequirements(registry, requirements, orcelVersion) {
  if (!isRecord(registry) || !Array.isArray(registry.items)) {
    throw new Error("registry must contain an items array");
  }
  if (!isRecord(requirements) || !Array.isArray(requirements.items)) {
    throw new Error("registry release requirements must contain an items array");
  }
  if (typeof orcelVersion !== "string" || !versionPattern.test(orcelVersion)) {
    throw new Error(`invalid orcel release version: ${String(orcelVersion)}`);
  }

  const known = new Map(registry.items.filter(isRecord).map((item) => [item.name, item]));
  for (const name of requirements.items) {
    if (typeof name !== "string") throw new Error("registry release item names must be strings");
    const item = known.get(name);
    if (item === undefined)
      throw new Error(`registry release requirement names unknown item ${name}`);
    if (!isRecord(item.meta) || !isRecord(item.meta.orcel)) {
      throw new Error(`registry item ${name} has no orcel metadata`);
    }
    item.meta.orcel.requires = `>=${orcelVersion}`;
  }
  return registry;
}

export async function materializeRegistryReleaseRequirements(paths = {}) {
  const resolvedRegistryPath = paths.registryPath ?? registryPath;
  const resolvedRequirementsPath = paths.requirementsPath ?? requirementsPath;
  const resolvedOrcelPackagePath = paths.packagePath ?? orcelPackagePath;

  // An absent sidecar means this release has no registry requirements to stage.
  try {
    await stat(resolvedRequirementsPath);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }

  const [registryText, requirementsText, packageText] = await Promise.all([
    readFile(resolvedRegistryPath, "utf8"),
    readFile(resolvedRequirementsPath, "utf8"),
    readFile(resolvedOrcelPackagePath, "utf8"),
  ]);
  const registry = materializeRegistryRequirements(
    JSON.parse(registryText),
    JSON.parse(requirementsText),
    JSON.parse(packageText).version,
  );
  await writeFile(resolvedRegistryPath, `${JSON.stringify(registry, null, 2)}\n`);
  // This sidecar is one-release intent, not a standing policy. Deleting it
  // makes the generated release PR consume the intent exactly once.
  await rm(resolvedRequirementsPath);
}

if (import.meta.main) await materializeRegistryReleaseRequirements();
