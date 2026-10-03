import {
  cp,
  mkdir,
  readdir,
  readFile,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import type { Dirent } from "node:fs";
import { dirname, join, relative } from "node:path";

import {
  ORCEL_SHARED_SERVER_FUNCTION_PATH,
  ORCEL_WORKFLOW_FLOW_ROUTE_PATH,
  isOrcelVercelFunctionPath,
  normalizeOrcelVercelRoutes,
} from "#internal/workflow-bundle/orcel-service-route-output.js";

// just-bash and microsandbox are optional peer dependencies (the
// opt-in local sandbox engines) loaded lazily from the application's
// install; just-bash additionally exposes native optional codecs for
// xz/zstd support. All of these must stay external so workflow step
// bundles neither fail resolving an absent optional install nor try to
// inline platform-specific `.node` artifacts.
export const WORKFLOW_STEP_EXTERNAL_PACKAGES = [
  "@mongodb-js/zstd",
  "just-bash",
  "microsandbox",
  "node-liblzma",
] as const;

/**
 * Packages that must stay external during the initial workflow builder
 * pass so `node:*` transitive dependencies do not fail the workflow VM check.
 * Nitro performs the final bundling/tracing pass for hosted output.
 */
export const WORKFLOW_BUILDER_DEFERRED_PACKAGES = ["@chat-adapter/slack", "chat"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Recreates the queue-triggered flow function from Nitro's completed server
 * output while retaining its route-specific Vercel configuration.
 *
 * Nitro copies function-rule output without preserving relative symlink text,
 * which can turn traced `.nf3` package links into absolute paths inside orcel's
 * disposable build workspace. Materializing after Nitro finishes keeps those
 * links relative so the published function remains self-contained.
 */
export async function materializeVercelWorkflowFunctionOutput(outputDir: string): Promise<void> {
  const functionsDir = join(outputDir, "functions");
  const rootServerFunctionPath = await realpath(join(functionsDir, "__server.func"));
  const flowFunctionPath = join(functionsDir, `${ORCEL_WORKFLOW_FLOW_ROUTE_PATH.slice(1)}.func`);
  const flowFunctionConfig = await readFile(join(flowFunctionPath, ".vc-config.json"));
  const stagingPath = `${flowFunctionPath}.orcel-staging`;

  await rm(stagingPath, {
    force: true,
    recursive: true,
  });
  await cp(rootServerFunctionPath, stagingPath, {
    recursive: true,
    verbatimSymlinks: true,
  });
  await writeFile(join(stagingPath, ".vc-config.json"), flowFunctionConfig);
  await rm(flowFunctionPath, {
    force: true,
    recursive: true,
  });
  await rename(stagingPath, flowFunctionPath);
}

/**
 * Keeps only orcel-owned Vercel function output and rewrites orcel route function
 * symlinks to a shared orcel-owned server function.
 *
 * Nitro emits generic app routes such as `index.func -> ./__server.func` for
 * orcel's standalone landing page. In a multi-service Next.js deployment those
 * root aliases collide with Next's own functions. The Next integration only
 * proxies orcel's `/orcel/v1/**` transport routes, so Vercel output should expose
 * those route functions and workflow trigger functions, not orcel's root page.
 *
 * Nitro also dedupes every route function through `__server.func`. Preserve
 * that model by copying the shared target once into the orcel-owned tree and
 * repointing orcel route aliases at it before pruning the root target.
 */
export async function normalizeOrcelVercelFunctionOutput(
  outputDir: string,
  options: { readonly servicePrefix?: string } = {},
): Promise<void> {
  const functionsDir = join(outputDir, "functions");
  const sharedFunctionPath = await prepareSharedOrcelServerFunction(functionsDir);

  if (sharedFunctionPath !== null) {
    await repointOrcelFunctionSymlinksInDirectory(functionsDir, sharedFunctionPath);
  }
  await pruneNonOrcelFunctionEntries(functionsDir, functionsDir);
  await pruneNonOrcelVercelRoutes(outputDir, options.servicePrefix);
}

async function prepareSharedOrcelServerFunction(functionsDir: string): Promise<string | null> {
  const rootServerFunctionPath = join(functionsDir, "__server.func");
  const sharedFunctionPath = join(functionsDir, ORCEL_SHARED_SERVER_FUNCTION_PATH);
  let sourcePath: string;

  try {
    sourcePath = await realpath(rootServerFunctionPath);
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return null;
    }

    throw error;
  }

  const stagingPath = `${sharedFunctionPath}.orcel-staging`;

  await mkdir(dirname(sharedFunctionPath), {
    recursive: true,
  });
  await rm(stagingPath, {
    force: true,
    recursive: true,
  });
  await cp(sourcePath, stagingPath, {
    dereference: true,
    recursive: true,
  });
  await rm(sharedFunctionPath, {
    force: true,
    recursive: true,
  });
  await rename(stagingPath, sharedFunctionPath);

  return sharedFunctionPath;
}

async function repointOrcelFunctionSymlinksInDirectory(
  directoryPath: string,
  sharedFunctionPath: string,
  functionsDir: string = directoryPath,
): Promise<void> {
  let entries: Dirent<string>[];

  try {
    entries = await readdir(directoryPath, { withFileTypes: true });
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }

    throw error;
  }

  await Promise.all(
    entries.map(async (entry) => {
      const entryPath = join(directoryPath, entry.name);
      const relativeFunctionPath = normalizeVercelOutputPath(relative(functionsDir, entryPath));

      if (entry.isSymbolicLink()) {
        if (entry.name.endsWith(".func") && isOrcelVercelFunctionPath(relativeFunctionPath)) {
          await repointFunctionSymlink(entryPath, sharedFunctionPath);
        }
        return;
      }

      if (entry.isDirectory() && !entry.name.endsWith(".func")) {
        await repointOrcelFunctionSymlinksInDirectory(entryPath, sharedFunctionPath, functionsDir);
      }
    }),
  );
}

async function repointFunctionSymlink(
  functionPath: string,
  sharedFunctionPath: string,
): Promise<void> {
  await rm(functionPath, {
    force: true,
    recursive: true,
  });
  await symlink(
    normalizeVercelOutputPath(relative(dirname(functionPath), sharedFunctionPath)),
    functionPath,
    "dir",
  );
}

async function pruneNonOrcelFunctionEntries(
  functionsDir: string,
  directoryPath: string,
): Promise<void> {
  let entries: Dirent<string>[];

  try {
    entries = await readdir(directoryPath, { withFileTypes: true });
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }

    throw error;
  }

  await Promise.all(
    entries.map(async (entry) => {
      const entryPath = join(directoryPath, entry.name);
      const relativeFunctionPath = normalizeVercelOutputPath(relative(functionsDir, entryPath));

      if (entry.name.endsWith(".func")) {
        if (!isOrcelVercelFunctionPath(relativeFunctionPath)) {
          await rm(entryPath, {
            force: true,
            recursive: true,
          });
        }
        return;
      }

      if (entry.isDirectory()) {
        await pruneNonOrcelFunctionEntries(functionsDir, entryPath);
      }
    }),
  );
}

async function pruneNonOrcelVercelRoutes(
  outputDir: string,
  servicePrefix: string | undefined,
): Promise<void> {
  const configPath = join(outputDir, "config.json");
  let parsed: unknown;

  try {
    parsed = JSON.parse(await readFile(configPath, "utf8"));
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return;
    }

    throw error;
  }

  if (!isRecord(parsed) || !Array.isArray(parsed.routes)) {
    return;
  }

  parsed.routes = normalizeOrcelVercelRoutes(parsed.routes, servicePrefix);
  await writeFile(configPath, `${JSON.stringify(parsed, null, 2)}\n`);
}

function normalizeVercelOutputPath(path: string): string {
  return path.replaceAll("\\", "/");
}
