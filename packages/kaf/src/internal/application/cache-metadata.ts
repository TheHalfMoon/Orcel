import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";

const KAF_CACHE_METADATA_FILE = "kaf-cache.json";

/**
 * Clears one kaf-owned cache directory when its recorded kaf version is missing
 * or differs from the currently installed package version.
 */
export async function prepareKafVersionedCacheDirectory(directoryPath: string): Promise<void> {
  const cachedKafVersion = await readKafCacheVersion(directoryPath);
  const kafVersion = resolveInstalledPackageInfo().version;

  if (cachedKafVersion !== null && cachedKafVersion === kafVersion) {
    return;
  }

  await rm(directoryPath, {
    force: true,
    recursive: true,
  });
}

/**
 * Writes the current installed kaf version into one kaf-owned cache directory.
 */
export async function writeKafVersionedCacheMetadata(directoryPath: string): Promise<void> {
  await mkdir(directoryPath, {
    recursive: true,
  });
  await writeFile(
    join(directoryPath, KAF_CACHE_METADATA_FILE),
    `${JSON.stringify(
      {
        kafVersion: resolveInstalledPackageInfo().version,
      },
      null,
      2,
    )}\n`,
  );
}

async function readKafCacheVersion(directoryPath: string): Promise<string | null> {
  try {
    const parsed = JSON.parse(
      await readFile(join(directoryPath, KAF_CACHE_METADATA_FILE), "utf8"),
    ) as {
      kafVersion?: unknown;
    };
    return typeof parsed.kafVersion === "string" ? parsed.kafVersion : null;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return null;
    }

    return null;
  }
}
