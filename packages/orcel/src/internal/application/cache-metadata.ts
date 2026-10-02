import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { resolveInstalledPackageInfo } from "#internal/application/package.js";

const ORCEL_CACHE_METADATA_FILE = "orcel-cache.json";

/**
 * Clears one orcel-owned cache directory when its recorded orcel version is missing
 * or differs from the currently installed package version.
 */
export async function prepareOrcelVersionedCacheDirectory(directoryPath: string): Promise<void> {
  const cachedOrcelVersion = await readOrcelCacheVersion(directoryPath);
  const orcelVersion = resolveInstalledPackageInfo().version;

  if (cachedOrcelVersion !== null && cachedOrcelVersion === orcelVersion) {
    return;
  }

  await rm(directoryPath, {
    force: true,
    recursive: true,
  });
}

/**
 * Writes the current installed orcel version into one orcel-owned cache directory.
 */
export async function writeOrcelVersionedCacheMetadata(directoryPath: string): Promise<void> {
  await mkdir(directoryPath, {
    recursive: true,
  });
  await writeFile(
    join(directoryPath, ORCEL_CACHE_METADATA_FILE),
    `${JSON.stringify(
      {
        orcelVersion: resolveInstalledPackageInfo().version,
      },
      null,
      2,
    )}\n`,
  );
}

async function readOrcelCacheVersion(directoryPath: string): Promise<string | null> {
  try {
    const parsed = JSON.parse(
      await readFile(join(directoryPath, ORCEL_CACHE_METADATA_FILE), "utf8"),
    ) as {
      orcelVersion?: unknown;
    };
    return typeof parsed.orcelVersion === "string" ? parsed.orcelVersion : null;
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return null;
    }

    return null;
  }
}
