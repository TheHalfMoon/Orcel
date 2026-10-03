#!/usr/bin/env node
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { execFileSync } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const templatesDirectory = join(repoRoot, "apps", "templates");
const temporaryDirectory = mkdtempSync(join(tmpdir(), "orcel-template-compatibility-"));
const historicalFrameworkPackage = ["e", "ve"].join("");

const run = (command, args, options = {}) => {
  process.stdout.write(`$ ${command} ${args.join(" ")}\n`);
  execFileSync(command, args, { cwd: repoRoot, stdio: "inherit", ...options });
};

try {
  const packageDirectory = join(repoRoot, "packages", "orcel");
  const packedDirectory = join(temporaryDirectory, "packed");
  run("pnpm", ["--dir", packageDirectory, "pack", "--pack-destination", packedDirectory]);

  const tarballs = readdirSync(packedDirectory).filter((file) => file.endsWith(".tgz"));
  if (tarballs.length !== 1) {
    throw new Error(
      `Expected one orcel tarball in ${packedDirectory}, found ${tarballs.join(", ") || "none"}`,
    );
  }
  const tarball = join(packedDirectory, tarballs[0]);
  const packageManifest = JSON.parse(readFileSync(join(packageDirectory, "package.json"), "utf8"));
  const sandboxImageTag = String(packageManifest.version ?? "").split("+", 1)[0];
  if (sandboxImageTag.length === 0) {
    throw new Error("Orcel package version is required to build the local sandbox image");
  }
  const localSandboxImage = `ghcr.io/thehalfmoon/orcel:${sandboxImageTag}`;
  run("docker", [
    "build",
    "--file",
    join(packageDirectory, "Dockerfile"),
    "--tag",
    localSandboxImage,
    packageDirectory,
  ]);

  const templates = readdirSync(templatesDirectory, { withFileTypes: true })
    .filter(
      (entry) =>
        entry.isDirectory() && existsSync(join(templatesDirectory, entry.name, "package.json")),
    )
    .map((entry) => entry.name)
    .sort();
  if (templates.length === 0) throw new Error(`No templates found in ${templatesDirectory}`);

  for (const template of templates) {
    const source = join(templatesDirectory, template);
    const destination = join(temporaryDirectory, template);
    cpSync(source, destination, {
      filter: (path) =>
        !["node_modules", ".next", ".nuxt", ".output", ".orcel", ".vercel"].includes(basename(path)),
      recursive: true,
    });

    const manifestPath = join(destination, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (!manifest.dependencies?.orcel) {
      throw new Error(`Template "${template}" does not declare orcel in dependencies`);
    }
    manifest.dependencies.orcel = `file:${tarball}`;
    if (manifest.dependencies["@vercel/connect"]) {
      const compatibilitySpecifier = manifest.dependencies[historicalFrameworkPackage];
      if (!compatibilitySpecifier?.startsWith("npm:orcel@")) {
        throw new Error(
          `Template "${template}" uses @vercel/connect but is missing its documented Orcel compatibility alias`,
        );
      }
      // Bind the provider's historical bare package coordinate to the exact
      // same local Orcel tarball so parity tests never depend on a registry build.
      manifest.dependencies[historicalFrameworkPackage] = `file:${tarball}`;
    }
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    process.stdout.write(`\nChecking ${template} against ${tarballs[0]}\n`);
    run("pnpm", ["install", "--no-frozen-lockfile"], { cwd: destination });
    if (manifest.dependencies["@vercel/connect"]) {
      const compatibilityPath = join(destination, "node_modules", historicalFrameworkPackage);
      rmSync(compatibilityPath, { force: true, recursive: true });
      symlinkSync(join(destination, "node_modules", "orcel"), compatibilityPath, "junction");
    }
    run("pnpm", ["typecheck"], { cwd: destination });
    run("pnpm", ["exec", "orcel", "build"], { cwd: destination });
    run("pnpm", ["build"], { cwd: destination });
  }
} finally {
  rmSync(temporaryDirectory, { force: true, recursive: true });
}
