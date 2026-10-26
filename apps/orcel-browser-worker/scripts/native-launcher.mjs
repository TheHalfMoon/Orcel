#!/usr/bin/env node
// Runs the SG-000108 native launcher tests (crates/orcel-browser-host
// worker_launch_tests.rs) against the built worker and the installed Edge.
// They are ignored in a plain `cargo test` because they need this worker
// build; on non-Windows hosts they are skipped, since only Windows results
// count as evidence. Run after `npm --prefix apps/orcel-browser-worker test`
// (which builds dist/).

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runtimePin } from "./dev-pin.mjs";

// Every native test must run: a filter that matches nothing (for example
// after a module rename) exits 0 and would otherwise pass vacuously.
const EXPECTED_TESTS = 30;
const EXPECTED_WORKER_HOST_TESTS = 8;
const EXPECTED_ORCELD_LIVE_TESTS = 5;
const EXPECTED_DEV_HOST_TESTS = 3;

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

// SG-000108 slice 3b-ii: the `live-browser-dev` host binary, which runs only
// the worker runtime its build pinned. Its unit tests first, then its native
// tests twice: built with a pin of another tree (every lifetime refused,
// typed), then with the runtime's real pin (scripts/dev-pin.mjs). Rustc
// tracks the pin variables, so each pass rebuilds the binary with its pin.
const devLib = spawnSync(
  "cargo",
  ["test", "-p", "orcel-browser-host", "--features", "live-browser-dev", "--lib"],
  { cwd: repo, stdio: ["ignore", "pipe", "inherit"], encoding: "utf8", maxBuffer: 64 * 1024 * 1024, shell: false }
);
process.stdout.write(devLib.stdout ?? "");
if (devLib.error || devLib.status !== 0 || !/test result: ok\. \d+ passed; 0 failed/.test(devLib.stdout ?? "")) {
  process.stderr.write("browser-launcher:native: the live-browser-dev unit tests failed\n");
  process.exit(1);
}
// The dev-only unit tests must have run, not merely compiled out (#428).
for (const name of [
  "a_public_open_admits_only_public_https_and_refuses_before_any_profile",
  "a_development_build_has_no_fixture_open",
  "a_compiled_runtime_is_whole_and_well_formed_or_absent"
]) {
  if (!(devLib.stdout ?? "").split("\n").some((line) => line.startsWith("test ") && (line.includes(`::${name} ... ok`) || line.includes(` ${name} ... ok`)))) {
    process.stderr.write(`browser-launcher:native: the live-browser-dev unit test ${name} did not run\n`);
    process.exit(1);
  }
}
// orceld's live unit tests compile only with a live feature, so the
// default `cargo test` never runs them (slice 3c found a stale vector
// there). Run them here, and require each to have run.
const orceldUnits = spawnSync(
  "cargo",
  [
    "test", "-p", "orceld", "--features", "live-browser-dev", "--bin", "orceld",
    "--", "live_browser::tests", "profile_gate::tests", "live_browser_shapes_reach_the_live_route_only_through_the_gate"
  ],
  { cwd: repo, stdio: ["ignore", "pipe", "inherit"], encoding: "utf8", maxBuffer: 64 * 1024 * 1024, shell: false }
);
process.stdout.write(orceldUnits.stdout ?? "");
if (orceldUnits.error || orceldUnits.status !== 0 || !/test result: ok\. \d+ passed; 0 failed/.test(orceldUnits.stdout ?? "")) {
  process.stderr.write("browser-launcher:native: orceld's live unit tests failed\n");
  process.exit(1);
}
for (const name of [
  "the_approval_digest_covers_both_halves",
  "host_refusals_map_onto_closed_failure_codes",
  "wi05_only_a_committed_download_is_handed_to_the_document_parser",
  "the_six_live_shapes_are_gated",
  "a_live_shape_needs_a_local_browser_structured_request",
  "live_browser_shapes_reach_the_live_route_only_through_the_gate"
]) {
  if (!(orceldUnits.stdout ?? "").split("\n").some((line) => line.startsWith("test ") && line.includes(`::${name} ... ok`))) {
    process.stderr.write(`browser-launcher:native: orceld's live unit test ${name} did not run\n`);
    process.exit(1);
  }
}
const pin = runtimePin(process.execPath, app);
const otherTree = createHash("sha256").update(`another tree than ${pin.ORCEL_LIVE_BROWSER_TREE_SHA256}`).digest("hex");
for (const [expect, tree] of [["mismatch", otherTree], ["match", pin.ORCEL_LIVE_BROWSER_TREE_SHA256]]) {
  const dev = spawnSync(
    "cargo",
    [
      "test", "-p", "orcel-browser-host", "--features", "live-browser-dev", "--test", "sg000108_dev_host",
      "--", "--ignored", "--test-threads=1", "--nocapture"
    ],
    {
      cwd: repo,
      stdio: ["ignore", "pipe", "inherit"],
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
      shell: false,
      env: {
        ...process.env,
        ...pin,
        ORCEL_LIVE_BROWSER_TREE_SHA256: tree,
        ORCEL_SG108_DEV_PIN: expect,
        ORCEL_SG108_NODE: process.execPath,
        ORCEL_SG108_WORKER_MAIN: main
      }
    }
  );
  const devOut = dev.stdout ?? "";
  process.stdout.write(devOut);
  if (dev.error || dev.status !== 0) {
    process.exit(dev.status ?? 1);
  }
  const devSummary = /test result: ok\. (\d+) passed; 0 failed; 0 ignored/.exec(devOut);
  if (!devSummary || Number(devSummary[1]) !== EXPECTED_DEV_HOST_TESTS) {
    process.stderr.write(
      `browser-launcher:native: expected ${EXPECTED_DEV_HOST_TESTS} dev-host tests to pass (${expect}), saw ${devSummary ? devSummary[1] : "none"}\n`
    );
    process.exit(1);
  }
  const lifetime = expect === "match" ? "SG108-EVIDENCE dev host public lifetime" : "SG108-EVIDENCE dev host refused: pin mismatch";
  const refused = ["SG108-EVIDENCE dev host: managed policy present", "SG108-EVIDENCE dev host refused: node folder writable"];
  if (!devOut.includes("SG108-EVIDENCE dev host pin agreement:")) {
    process.stderr.write(`browser-launcher:native: the dev-host pin agreement did not run (${expect})\n`);
    process.exit(1);
  }
  if (!devOut.includes("SG108-EVIDENCE dev host: --node and --worker-main refused")) {
    process.stderr.write(`browser-launcher:native: the dev host accepted runtime arguments (${expect})\n`);
    process.exit(1);
  }
  if (!devOut.includes(lifetime) && !refused.some((line) => devOut.includes(line))) {
    process.stderr.write(`browser-launcher:native: the dev-host tests reported neither their lifetime nor a typed refusal (${expect})\n`);
    process.exit(1);
  }
  if (process.env.ORCEL_SG108_REQUIRE_JOURNEY === "1" && !devOut.includes(lifetime)) {
    process.stderr.write(`browser-launcher:native: ORCEL_SG108_REQUIRE_JOURNEY=1, yet the dev-host lifetime did not run (${expect})\n`);
    process.exit(1);
  }
}

// SG-000108 slice 3c: the public journey through orceld's kernel caller
// (handle_envelope: profile gate, live policy, live dispatch) under the real
// approval broker, driving the dev host binary the pass above just built
// with the runtime's real pin. It reaches a public HTTPS site.
const journey = spawnSync(
  "cargo",
  [
    "test", "-p", "orceld", "--features", "live-browser-dev", "--bin", "orceld", "live_dispatch::native",
    "--", "--ignored", "--test-threads=1", "--nocapture"
  ],
  {
    cwd: repo,
    stdio: ["ignore", "pipe", "inherit"],
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    shell: false,
    env: { ...process.env, ORCEL_SG108_HOST_BINARY: hostBinary }
  }
);
const journeyOut = journey.stdout ?? "";
process.stdout.write(journeyOut);
if (journey.error || journey.status !== 0) {
  process.exit(journey.status ?? 1);
}
if (!/test result: ok\. 1 passed; 0 failed; 0 ignored/.test(journeyOut)) {
  process.stderr.write("browser-launcher:native: expected the public journey test to pass\n");
  process.exit(1);
}
const journeyRan = journeyOut.includes("SG108-EVIDENCE public journey:");
if (!journeyRan && !journeyOut.includes("SG108-EVIDENCE public journey refused:")) {
  process.stderr.write("browser-launcher:native: the public journey reported neither its download nor a managed-policy refusal\n");
  process.exit(1);
}
if (process.env.ORCEL_SG108_REQUIRE_JOURNEY === "1" && !journeyRan) {
  process.stderr.write("browser-launcher:native: ORCEL_SG108_REQUIRE_JOURNEY=1, yet the public journey did not run\n");
  process.exit(1);
}
if (!journeyRan) {
  // Passing on the refusal is right for CI (a managed policy), but it is
  // not evidence of the journey: say so where nobody can miss it.
  process.stdout.write("SG108-WARNING the public journey was NOT exercised on this host (typed refusal only); evidence requires ORCEL_SG108_REQUIRE_JOURNEY=1\n");
}
