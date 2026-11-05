#!/usr/bin/env node
// Writes a provenance record for a packaged Orcel release: source revision,
// build workflow and run, toolchain versions, dependency lock digests,
// artifact digests, and the SBOM digest. It records only what it observes;
// fields that are unavailable (for example outside GitHub Actions) are null.
// The signed, verifiable statement is the GitHub artifact attestation made by
// the release workflow; this file is a human-readable companion to it.
//
// Usage:
//   node scripts/provenance.mjs --release <release-dir> --artifact <file> [--artifact <file>...]
//        --sbom <sbom.json> --out <provenance.json> [--reproducibility <result.json>]

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function fail(message) {
  console.error(`provenance: ${message}`);
  process.exit(1);
}

function values(name) {
  const out = [];
  process.argv.forEach((arg, index) => {
    if (arg === name) {
      const value = process.argv[index + 1];
      if (!value) fail(`${name} requires a value`);
      out.push(resolve(value));
    }
  });
  return out;
}

function one(name, required = true) {
  const found = values(name);
  if (required && found.length !== 1) fail(`${name} <value> is required once`);
  return found[0] ?? null;
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function run(command, args) {
  try {
    return execFileSync(command, args, { cwd: repo, stdio: ["ignore", "pipe", "ignore"] }).toString().trim();
  } catch {
    return null;
  }
}

function npmVersion() {
  // Windows layouts ship npm next to node.exe; Unix layouts under lib/.
  const cli = [
    join(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js"),
    join(dirname(dirname(process.execPath)), "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ].find((path) => existsSync(path));
  if (!cli) return null;
  try {
    return execFileSync(process.execPath, [cli, "--version"]).toString().trim();
  } catch {
    return null;
  }
}

const release = one("--release");
const sbom = one("--sbom");
const out = one("--out");
const reproducibility = one("--reproducibility", false);
const artifacts = values("--artifact");
if (artifacts.length === 0) fail("at least one --artifact is required");
const manifest = JSON.parse(readFileSync(join(release, "manifest.json"), "utf8"));
const env = process.env;
const record = {
  schema: "orcel-provenance-v1",
  product: { name: "orcel", version: manifest.version },
  source: {
    repository: env.GITHUB_REPOSITORY ? `${env.GITHUB_SERVER_URL}/${env.GITHUB_REPOSITORY}` : null,
    revision: run("git", ["rev-parse", "HEAD"]),
    ref: env.GITHUB_REF ?? null,
    worktree_clean: run("git", ["status", "--porcelain"]) === ""
  },
  build: {
    workflow: env.GITHUB_WORKFLOW_REF ?? null,
    run_id: env.GITHUB_RUN_ID ?? null,
    run_attempt: env.GITHUB_RUN_ATTEMPT ?? null,
    runner_os: env.RUNNER_OS ?? process.platform,
    runner_arch: env.RUNNER_ARCH ?? process.arch
  },
  toolchain: {
    rustc: run("rustc", ["-vV"]),
    cargo: run("cargo", ["-V"]),
    node: process.version,
    npm: npmVersion(),
    // The compiler of the Windows app, whose version floats with the runner image.
    dotnet_sdk: run("dotnet", ["--version"])
  },
  locks: {
    "Cargo.lock": sha256File(join(repo, "Cargo.lock")),
    "package-lock.json": existsSync(join(repo, "package-lock.json")) ? sha256File(join(repo, "package-lock.json")) : null
  },
  release_manifest: { file: "manifest.json", sha256: sha256File(join(release, "manifest.json")) },
  artifacts: artifacts.map((path) => ({ name: basename(path), sha256: sha256File(path) })),
  sbom: { name: basename(sbom), sha256: sha256File(sbom), format: "CycloneDX 1.5 JSON" },
  reproducibility: reproducibility ? JSON.parse(readFileSync(reproducibility, "utf8")) : null,
  signing: "unsigned binaries; integrity by SHA-256 manifest verification and a GitHub build-provenance attestation"
};
writeFileSync(out, `${JSON.stringify(record, null, 2)}\n`);
console.log(`provenance: ${record.artifacts.length} artifacts -> ${out}`);
