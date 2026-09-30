import { readFile } from "node:fs/promises";

const registryPath = new URL("../apps/docs/registry.json", import.meta.url);
const kafPackagePath = new URL("../packages/kaf/package.json", import.meta.url);
const minimumVersionPattern = /^>=(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/u;
const versionPattern = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/u;

function parseVersion(version, pattern) {
  const match = pattern.exec(version);
  if (match === null) return undefined;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4],
  };
}

function compareVersions(left, right) {
  for (const key of ["major", "minor", "patch"]) {
    if (left[key] !== right[key]) return left[key] < right[key] ? -1 : 1;
  }
  if (left.prerelease === right.prerelease) return 0;
  if (left.prerelease === undefined) return 1;
  if (right.prerelease === undefined) return -1;
  return left.prerelease.localeCompare(right.prerelease, "en");
}

export function validatePublicRegistryRequirements(registry, kafVersion) {
  const published = parseVersion(kafVersion, versionPattern);
  if (published === undefined)
    throw new Error(`invalid Kaf package version: ${String(kafVersion)}`);
  if (!Array.isArray(registry?.items)) throw new Error("registry must contain an items array");

  const errors = [];
  for (const item of registry.items) {
    const requirement = item?.meta?.kaf?.requires;
    if (requirement === undefined) continue;
    const minimum = parseVersion(requirement, minimumVersionPattern);
    if (minimum === undefined) {
      errors.push(`${item.name}: unsupported Kaf requirement ${JSON.stringify(requirement)}`);
    } else if (compareVersions(minimum, published) > 0) {
      errors.push(`${item.name}: requires ${requirement}, but packages/kaf is ${kafVersion}`);
    }
  }
  if (errors.length > 0) {
    throw new Error(
      [
        "apps/docs/registry.json must not require an unpublished Kaf version.",
        ...errors,
        "Add affected items to apps/docs/registry.staged-requirements.json; the Changesets release process will materialize them after selecting the Kaf version.",
      ].join("\n"),
    );
  }
}

export async function validatePublicRegistryRequirementsFromFiles(paths = {}) {
  const resolvedRegistryPath = paths.registryPath ?? registryPath;
  const resolvedKafPackagePath = paths.packagePath ?? kafPackagePath;
  const [registryText, packageText] = await Promise.all([
    readFile(resolvedRegistryPath, "utf8"),
    readFile(resolvedKafPackagePath, "utf8"),
  ]);
  validatePublicRegistryRequirements(JSON.parse(registryText), JSON.parse(packageText).version);
}

if (import.meta.main) await validatePublicRegistryRequirementsFromFiles();
