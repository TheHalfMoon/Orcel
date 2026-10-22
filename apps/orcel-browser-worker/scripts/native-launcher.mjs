#!/usr/bin/env node
// Runs the SG-000108 native launcher tests (crates/orcel-browser-host
// worker_launch_tests.rs) against the built worker and the installed Edge.
// They are ignored in a plain `cargo test` because they need this worker
// build; on non-Windows hosts they are skipped, since only Windows results
// count as evidence. Run after `npm --prefix apps/orcel-browser-worker test`
// (which builds dist/).

import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Every native test must run: a filter that matches nothing (for example
// after a module rename) exits 0 and would otherwise pass vacuously.
const EXPECTED_TESTS = 27;
const EXPECTED_WORKER_HOST_TESTS = 8;
const EXPECTED_ORCELD_LIVE_TESTS = 5;

const app = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repo = resolve(app, "..", "..");
const main = join(app, "dist", "main.js");

if (process.platform !== "win32") {
  process.stdout.write("browser-launcher:native skipped: native launcher tests are Windows-only evidence\n");
  process.exit(0);
}
if (!existsSync(main)) {
  process.stderr.write(`browser-launcher:native: ${main} is missing; build the worker first\n`);
  process.exit(1);
}
const result = spawnSync(
  "cargo",
  ["test", "-p", "orcel-browser-host", "--lib", "native_tests", "--", "--ignored", "--test-threads=1", "--nocapture"],
  {
    cwd: repo,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: false,
    env: { ...process.env, ORCEL_SG108_NODE: process.execPath, ORCEL_SG108_WORKER_MAIN: main }
  }
);
if (result.error) {
  process.stderr.write(`browser-launcher:native: could not run cargo: ${result.error.message}\n`);
  process.exit(1);
}
process.stdout.write(result.stdout ?? "");
if (result.status !== 0) {
  process.exit(result.status ?? 1);
}
const summary = /test result: ok\. (\d+) passed; 0 failed; 0 ignored/.exec(result.stdout ?? "");
if (!summary || Number(summary[1]) !== EXPECTED_TESTS) {
  process.stderr.write(
    `browser-launcher:native: expected ${EXPECTED_TESTS} native tests to pass, saw ${summary ? summary[1] : "none"}\n`
  );
  process.exit(1);
}

// SG-000108 product caller (slice 1a): the real `orcel-browser-host
// --worker` binary under supervision. A separate build with the test-only
// `live-browser-test` feature, which release builds never enable.
// The worker-mode unit tests compile only with the feature: run them too.
const featureLib = spawnSync(
  "cargo",
  ["test", "-p", "orcel-browser-host", "--features", "live-browser-test", "--lib"],
  { cwd: repo, stdio: ["ignore", "pipe", "inherit"], encoding: "utf8", maxBuffer: 64 * 1024 * 1024, shell: false }
);
process.stdout.write(featureLib.stdout ?? "");
if (featureLib.error || featureLib.status !== 0 || !/test result: ok\. \d+ passed; 0 failed/.test(featureLib.stdout ?? "")) {
  process.stderr.write("browser-launcher:native: the live-browser-test unit tests failed\n");
  process.exit(1);
}
const workerHost = spawnSync(
  "cargo",
  [
    "test", "-p", "orcel-browser-host", "--features", "live-browser-test", "--test", "sg000108_worker_host",
    "--", "--ignored", "--test-threads=1", "--nocapture"
  ],
  {
    cwd: repo,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: false,
    env: { ...process.env, ORCEL_SG108_NODE: process.execPath, ORCEL_SG108_WORKER_MAIN: main }
  }
);
if (workerHost.error) {
  process.stderr.write(`browser-launcher:native: could not run cargo: ${workerHost.error.message}\n`);
  process.exit(1);
}
process.stdout.write(workerHost.stdout ?? "");
if (workerHost.status !== 0) {
  process.exit(workerHost.status ?? 1);
}
const workerSummary = /test result: ok\. (\d+) passed; 0 failed; 0 ignored/.exec(workerHost.stdout ?? "");
// A silent skip never counts as evidence: each lifetime test reports either
// its journey or a managed-policy refusal. On the evidence host (no managed
// policy) ORCEL_SG108_REQUIRE_JOURNEY=1 requires the journeys themselves.
const workerOut = workerHost.stdout ?? "";
const journeys = [
  "SG108-EVIDENCE worker host observation",
  "SG108-EVIDENCE worker host journey",
  "SG108-EVIDENCE worker host binding",
  "SG108-EVIDENCE worker host click",
  "SG108-EVIDENCE worker host trimmed observation"
];
// Under a managed policy, every test that opens a lifetime (the four
// journeys and the mid-lifetime shutdown) reports the refusal itself.
const policyRefusals = workerOut.split("SG108-EVIDENCE worker host: managed policy present").length - 1;
const refusedByPolicy = policyRefusals >= journeys.length + 1;
const journeysSeen = journeys.every((line) => workerOut.includes(line));
if (!journeysSeen && !refusedByPolicy) {
  process.stderr.write("browser-launcher:native: the worker-host tests reported neither their journeys nor a managed-policy refusal\n");
  process.exit(1);
}
if (process.env.ORCEL_SG108_REQUIRE_JOURNEY === "1" && !journeysSeen) {
  process.stderr.write("browser-launcher:native: ORCEL_SG108_REQUIRE_JOURNEY=1, yet the worker-host journeys did not run\n");
  process.exit(1);
}

// SG-000108 product caller (slice 1b): orceld drives the worker-mode host
// under the approval broker. The host binary is built with the test-only
// feature first; orceld's tests receive its path (a test-only source).
const hostBuild = spawnSync(
  "cargo",
  ["build", "-p", "orcel-browser-host", "--features", "live-browser-test", "--bin", "orcel-browser-host"],
  { cwd: repo, stdio: ["ignore", "inherit", "inherit"], shell: false }
);
if (hostBuild.error || hostBuild.status !== 0) {
  process.stderr.write("browser-launcher:native: could not build the worker-mode host binary\n");
  process.exit(1);
}
const targetDir = process.env.CARGO_TARGET_DIR ? resolve(repo, process.env.CARGO_TARGET_DIR) : join(repo, "target");
const hostBinary = join(targetDir, "debug", "orcel-browser-host.exe");
const orceldLive = spawnSync(
  "cargo",
  [
    "test", "-p", "orceld", "--features", "live-browser-test", "--bin", "orceld", "live_browser::native",
    "--", "--ignored", "--test-threads=1", "--nocapture"
  ],
  {
    cwd: repo,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: false,
    env: { ...process.env, ORCEL_SG108_NODE: process.execPath, ORCEL_SG108_WORKER_MAIN: main, ORCEL_SG108_HOST_BINARY: hostBinary }
  }
);
process.stdout.write(orceldLive.stdout ?? "");
if (orceldLive.error || orceldLive.status !== 0) {
  process.exit(orceldLive.status ?? 1);
}
const orceldOut = orceldLive.stdout ?? "";
const orceldSummary = /test result: ok\. (\d+) passed; 0 failed; 0 ignored/.exec(orceldOut);
if (!orceldSummary || Number(orceldSummary[1]) !== EXPECTED_ORCELD_LIVE_TESTS) {
  process.stderr.write(
    `browser-launcher:native: expected ${EXPECTED_ORCELD_LIVE_TESTS} orceld live tests to pass, saw ${orceldSummary ? orceldSummary[1] : "none"}\n`
  );
  process.exit(1);
}
const orceldJourneys = ["SG108-EVIDENCE orceld live journey", "SG108-EVIDENCE orceld live denial", "SG108-EVIDENCE orceld live lost", "SG108-EVIDENCE orceld live suspended", "SG108-EVIDENCE orceld live restart"];
const orceldJourneysSeen = orceldJourneys.every((line) => orceldOut.includes(line));
const orceldRefusals = orceldOut.split("SG108-EVIDENCE orceld live: managed policy present").length - 1;
if (!orceldJourneysSeen && orceldRefusals < orceldJourneys.length) {
  process.stderr.write("browser-launcher:native: the orceld live tests reported neither their journeys nor managed-policy refusals\n");
  process.exit(1);
}
if (process.env.ORCEL_SG108_REQUIRE_JOURNEY === "1" && !orceldJourneysSeen) {
  process.stderr.write("browser-launcher:native: ORCEL_SG108_REQUIRE_JOURNEY=1, yet the orceld live journeys did not run\n");
  process.exit(1);
}
if (!workerSummary || Number(workerSummary[1]) !== EXPECTED_WORKER_HOST_TESTS) {
  process.stderr.write(
    `browser-launcher:native: expected ${EXPECTED_WORKER_HOST_TESTS} worker-host tests to pass, saw ${workerSummary ? workerSummary[1] : "none"}\n`
  );
  process.exit(1);
}
