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
const temporaryDirectory = mkdtempSync(join(tmpdir(), "kaf-template-compatibility-"));
const historicalFrameworkPackage = ["e", "ve"].join("");

const run = (command, args, options = {}) => {
  process.stdout.write(`$ ${command} ${args.join(" ")}\n`);
  execFileSync(command, args, { cwd: repoRoot, stdio: "inherit", ...options });
};

try {
  const packageDirectory = join(repoRoot, "packages", "kaf");
  const packedDirectory = join(temporaryDirectory, "packed");
  run("pnpm", ["--dir", packageDirectory, "pack", "--pack-destination", packedDirectory]);

  const tarballs = readdirSync(packedDirectory).filter((file) => file.endsWith(".tgz"));
  if (tarballs.length !== 1) {
    throw new Error(
      `Expected one kaf tarball in ${packedDirectory}, found ${tarballs.join(", ") || "none"}`,
    );
  }
  const tarball = join(packedDirectory, tarballs[0]);

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
        !["node_modules", ".next", ".nuxt", ".output", ".kaf", ".vercel"].includes(basename(path)),
      recursive: true,
    });

    const manifestPath = join(destination, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (!manifest.dependencies?.kaf) {
      throw new Error(`Template "${template}" does not declare kaf in dependencies`);
    }
    manifest.dependencies.kaf = `file:${tarball}`;
    if (manifest.dependencies["@vercel/connect"]) {
      const compatibilitySpecifier = manifest.dependencies[historicalFrameworkPackage];
      if (!compatibilitySpecifier?.startsWith("npm:kaf@")) {
        throw new Error(
          `Template "${template}" uses @vercel/connect but is missing its documented Kaf compatibility alias`,
        );
      }
      // Bind the provider's historical bare package coordinate to the exact
      // same local Kaf tarball so parity tests never depend on a registry build.
      manifest.dependencies[historicalFrameworkPackage] = `file:${tarball}`;
    }
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);

    process.stdout.write(`\nChecking ${template} against ${tarballs[0]}\n`);
    run("pnpm", ["install", "--no-frozen-lockfile"], { cwd: destination });
    if (manifest.dependencies["@vercel/connect"]) {
      const compatibilityPath = join(destination, "node_modules", historicalFrameworkPackage);
      rmSync(compatibilityPath, { force: true, recursive: true });
      symlinkSync(join(destination, "node_modules", "kaf"), compatibilityPath, "junction");
    }
    run("pnpm", ["typecheck"], { cwd: destination });
    run("pnpm", ["exec", "kaf", "build"], { cwd: destination });
    run("pnpm", ["build"], { cwd: destination });
  }
} finally {
  rmSync(temporaryDirectory, { force: true, recursive: true });
}
