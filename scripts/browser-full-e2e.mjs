#!/usr/bin/env node
// SG-000135 OB-01 end-to-end mission (acceptance FA-C, provisional), Windows
// only. docs/orcel/implementation-readiness/prep/OB01_E2E.md says how to run it.
//
// A local MCP client (this script, speaking newline-delimited JSON-RPC over
// stdio) drives orcel-mcp (local transport, `browser_full` profile), which
// starts orceld, whose Orcel Browser Session Broker supervises the browser
// host and worker, which launch the installed, qualified Edge headless,
// through a pipe, in an Orcel-managed ephemeral profile, against the
// test-only HTTPS fixture on 127.0.0.1:443 (fixture.test; no internet).
//
// Mission: browser_session_create, browser_open (the fixture form),
// browser_snapshot, browser_fill (a text field), browser_select (an option),
// browser_verify (the form), browser_click (a link to a second page),
// browser_verify (the second page), browser_extract, then (SG-000135 OB-03)
// browser_screenshot, browser_tabs new (a second tab on the secret-field
// page, a navigation with its own approval), browser_tabs list,
// browser_screenshot of the second tab (its secret fields must be painted
// over, checked on the decoded pixels), browser_tabs switch back,
// browser_verify, browser_tabs close (the second tab), then (SG-000135
// OB-08, SG-000132 slice 2) Full Access: the Orcel authority service (here
// its console harness, `orcel-authority --console`, trusting this run's
// orceld) issues a browser lease for this session on https://fixture.test
// after the owner's grant (this script speaks the authority pipe as
// `orcel browser grant` does); orceld checks the lease's ECDSA signature
// with the service's public key and asks the service's Authorize before each
// covered action. 25 routine actions (open, fill, select, click on an
// ordinary link) then finish with zero Orcel prompts, each receipted with
// the lease; a click on a link named "Submit order" still asks; the owner
// revokes the lease (through orceld's local path, which asks the service),
// the very next action is refused lease_invalid with nothing sent, and the
// one after asks again. Then browser_task_status and browser_close. Then: the provisional
// receipts chain is recomputed here,
// the session's folder (its profile) must be gone, no Edge of this run may
// be left, and orceld must end when the MCP session ends.
//
// Two consent modes, never mixed:
//   --consent scripted  TEST HARNESS. Builds orceld with the test-only
//                       `browser-full-scripted-consent` feature: the real
//                       approval broker and ledger, with the SOFT consent
//                       decided by the approval crate's existing test-support
//                       soft decider (approve only the mission's four action
//                       titles whose whole target is https://fixture.test;
//                       deny everything else) and every
//                       prompt's dialog text recorded. The authority's
//                       console harness is built with the test-only
//                       `authority-scripted-consent` feature, which stands
//                       in for the unlock, the service-rendered confirmation
//                       (answered Yes, its text logged) and Windows Hello.
//                       No dialog is shown. This is scripted consent, not
//                       human acceptance.
//   --consent founder   FOUNDER RUN. Builds orceld WITHOUT that feature: every
//                       approval is a real Orcel dialog that the person at the
//                       PC answers. This script never answers, clicks or
//                       scripts a dialog; it only waits and records. The
//                       OB-08 Full Access part needs the installed authority
//                       service trusting this orceld, so a founder run skips
//                       it and records why.
//
// Both builds also enable the test-only `live-browser-test` feature, so
// browser_open of https://fixture.test/ reaches the loopback fixture (a
// development build alone admits only public HTTPS). Neither is a release or
// development build.
//
// Options: --consent scripted|founder (required), --skip-build (use the
// binaries already built for this mode), --evidence <dir> (default: a new
// folder under the user's home), --keep-state (keep the isolated state root).
// Environment: CARGO_TARGET_DIR is honoured. node_modules for
// apps/orcel-browser-worker and the root workspace must already be installed.

import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { inflateSync } from "node:zlib";
import { runtimePin } from "../apps/orcel-browser-worker/scripts/dev-pin.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workerApp = join(repo, "apps", "orcel-browser-worker");
const FIXTURE = "https://fixture.test";
const FORM_URL = `${FIXTURE}/ob01-form`;
const DONE_URL = `${FIXTURE}/ob01-done`;
const NAME_VALUE = "Ada Lovelace";
const CITY_OPTION = "Porto";
const DONE_TEXT = "OB-01 mission second page reached";
const SECRET_URL = `${FIXTURE}/ob03-secret`;
const EXPECTED_TOOLS = [
  "browser_session_create", "browser_open", "browser_snapshot", "browser_click", "browser_fill",
  "browser_select", "browser_verify", "browser_extract", "browser_screenshot", "browser_tabs",
  "browser_close", "browser_task_status"
];
/// The mission's approved actions: open, fill, select, click, and the new
/// tab's navigation (OB-03), then (OB-08) the submit link and the open after
/// the revoke. The 25 routine actions under the lease ask nothing.
const APPROVED_ACTIONS = 7;
/// SG-000135 OB-08: the Full Access pages and the routine actions to run.
const OB08_FORM_URL = `${FIXTURE}/ob08-form`;
const OB08_NEXT_URL = `${FIXTURE}/ob08-next`;
const OB08_SUBMITTED_URL = `${FIXTURE}/ob08-submitted`;
const OB08_ROUTINE_ACTIONS = 25;
const LEASE_FAMILIES = ["navigate", "click", "type", "select", "tabs"];
const OB08_POST_URL = `${FIXTURE}/ob08-scripts`;
/// The session's task label, which the lease must name.
const SESSION_TASK = "OB-01 E2E fixture mission";
// Longer than the MCP edge's own 10-minute approval timeout, so a dialog that
// waits for a person ends as orceld's answer, not as this client giving up.
const CALL_TIMEOUT_MS = 11 * 60_000;
const RECEIPT_DOMAIN = "orcel-ob01-receipt/2";
/** The MCP session of this run, ended on every exit path. */
let activeClient = null;

function fail(message) {
  throw new Error(`OB01-E2E FAILED: ${message}`);
}

function require_(condition, message) {
  if (!condition) fail(message);
}

function parseArgs(argv) {
  const options = { consent: null, skipBuild: false, evidence: null, keepState: false };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--consent") options.consent = argv[++index] ?? null;
    else if (arg === "--skip-build") options.skipBuild = true;
    else if (arg === "--evidence") options.evidence = argv[++index] ?? null;
    else if (arg === "--keep-state") options.keepState = true;
    else fail(`unknown argument ${arg}`);
  }
  if (options.consent !== "scripted" && options.consent !== "founder") {
    fail("--consent scripted (test harness) or --consent founder (real dialogs) is required");
  }
  return options;
}

function run(command, args, env = process.env) {
  const result = spawnSync(command, args, { cwd: repo, stdio: "inherit", env, shell: false });
  require_(!result.error && result.status === 0, `${command} ${args.join(" ")} failed`);
}

/// Each consent mode builds into its own target folder (under
/// CARGO_TARGET_DIR, or the repository's target), so a founder run, even
/// with --skip-build, can never pick up the scripted-consent orceld.
function targetDir(consent) {
  const base = process.env.CARGO_TARGET_DIR ? resolve(repo, process.env.CARGO_TARGET_DIR) : join(repo, "target");
  return join(base, `ob01-${consent}`);
}

/// Build the worker, orcel-mcp, the browser host (both live features, the
/// worker runtime pin compiled in) and orceld for the chosen consent mode.
function build(consent, pin) {
  for (const modules of [join(workerApp, "node_modules", "playwright-core"), join(repo, "node_modules", "@modelcontextprotocol")]) {
    require_(existsSync(modules), `${modules} is missing: install the locked dependencies first (see OB01_E2E.md)`);
  }
  // npm is a .cmd on Windows, which runs only through a shell: fixed
  // command lines, no argument from anywhere else.
  const npmRun = (commandLine) => {
    const result = spawnSync(commandLine, { cwd: repo, stdio: "inherit", shell: true });
    require_(!result.error && result.status === 0, `${commandLine} failed`);
  };
  npmRun("npm --prefix apps/orcel-browser-worker run build");
  npmRun("npm run build --workspace @orcel/mcp");
  // The pin covers dist/, so it is computed after the worker build.
  const fresh = runtimePin(process.execPath, workerApp);
  Object.assign(pin, fresh);
  const env = { ...process.env, ...pin, CARGO_TARGET_DIR: targetDir(consent) };
  const live = "live-browser-test,live-browser-dev";
  run("cargo", ["build", "--locked", "-p", "orcel-browser-host", "--features", live, "--bin", "orcel-browser-host"], env);
  // OB-08 review: a lease covers nothing without the takeover gate. Leases
  // come from the authority service only (SG-000132 slice 2).
  const ob08 = "browser-takeover-gate";
  const features = consent === "scripted" ? `${live},${ob08},browser-full-scripted-consent` : `${live},${ob08}`;
  run("cargo", ["build", "--locked", "-p", "orceld", "--features", features, "--bin", "orceld"], env);
  if (consent === "scripted") {
    run("cargo", ["build", "--locked", "-p", "orcel-authority", "--features", "authority-scripted-consent", "--bin", "orcel-authority"], env);
  }
}

/// SG-000132 slice 2, scripted runs only: the authority service's console
/// harness, trusting this run's orceld, with the test-only scripted consent
/// standing in for the unlock, the confirmation and Windows Hello.
async function startAuthority(paths, built) {
  const binary = join(built, "orcel-authority.exe");
  require_(existsSync(binary), `the scripted authority harness is built: ${binary}`);
  const child = spawn(binary, [
    "--console", "--state-dir", join(paths.root, "authority-console"),
    "--pipe-suffix", `ob08-${process.pid}`,
    "--trusted-orceld", paths.orceld,
    "--e2e-scripted-consent", paths.authorityConsentLog
  ], { cwd: repo, stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk.toString("utf8")));
  const ready = await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`the authority harness did not start: ${stderr}`)), 30_000);
    createInterface({ input: child.stdout }).once("line", (text) => {
      clearTimeout(timer);
      resolvePromise(JSON.parse(text));
    });
  });
  require_(ready.ready === true && ready.mode === "console", `the authority harness is ready: ${JSON.stringify(ready)}`);
  return { child, expectation: { pipe: ready.pipe, pid: ready.pid, owner_sid: ready.owner_sid } };
}

/// One request on the authority pipe (a u32 little-endian length, then
/// JSON), as `orcel browser grant` sends it.
function authorityCall(pipe, request) {
  return new Promise((resolvePromise, reject) => {
    const socket = connect(pipe);
    const body = Buffer.from(JSON.stringify(request), "utf8");
    const header = Buffer.alloc(4);
    header.writeUInt32LE(body.length, 0);
    let received = Buffer.alloc(0);
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error(`the authority did not answer ${request.op}`));
    }, 15_000);
    socket.on("connect", () => socket.write(Buffer.concat([header, body])));
    socket.on("data", (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length >= 4 && received.length >= 4 + received.readUInt32LE(0)) {
        clearTimeout(timer);
        socket.end();
        resolvePromise(JSON.parse(received.subarray(4, 4 + received.readUInt32LE(0)).toString("utf8")));
      }
    });
    socket.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

/// The owner's grant, as `orcel browser grant` runs it: record the intent,
/// wait for the confirmed window, then sign the challenge. Here the
/// scripted consent stands in for the unlock and the Yes, and the scripted
/// presence `SHA-256("orcel-e2e-scripted-presence/1\n" || challenge)` for
/// Windows Hello; nothing else changes.
async function ownerGrant(pipe, scope, task) {
  const begun = await authorityCall(pipe, {
    op: "grant_begin", origin: "owner_cli", scope, minutes: 30, principal_id: scope.client_ref, task
  });
  require_(begun.ok === true, `the authority recorded the grant intent: ${JSON.stringify(begun)}`);
  const intentId = begun.result.intent_id;
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const status = await authorityCall(pipe, { op: "intent_status", intent_id: intentId });
    require_(status.ok === true, `the grant intent is pending: ${JSON.stringify(status)}`);
    if (status.result.state === "awaiting_presence") {
      const text = status.result.confirmation_text;
      require_(createHash("sha256").update(text, "utf8").digest("hex") === status.result.confirmation_text_digest, "the confirmation text matches its digest");
      const challenge = Buffer.from(status.result.challenge_hex, "hex");
      const signature = createHash("sha256").update(Buffer.concat([Buffer.from("orcel-e2e-scripted-presence/1\n", "utf8"), challenge])).digest("hex");
      const done = await authorityCall(pipe, { op: "presence_complete", intent_id: intentId, code: begun.result.code, signature_hex: signature });
      require_(done.ok === true, `the authority issued the lease: ${JSON.stringify(done)}`);
      return { lease: done.result.lease, confirmation: text };
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  return fail("the scripted grant never reached the presence step");
}

/// The test-only loopback fixture; resolves with its certificate's SPKI hash.
function startFixture() {
  const child = spawn(process.execPath, [join(workerApp, "scripts", "https-fixture.mjs")], {
    cwd: repo,
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });
  const hits = [];
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk.toString("utf8")));
  const ready = new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`the fixture did not start (is 127.0.0.1:443 free?) ${stderr}`)), 60_000);
    createInterface({ input: child.stdout }).on("line", (line) => {
      if (line.startsWith("READY ")) {
        clearTimeout(timer);
        resolvePromise(line.slice("READY ".length).trim());
      } else if (line.startsWith("HIT ")) {
        hits.push(line.slice(4));
      }
    });
    child.on("exit", (code) => {
      clearTimeout(timer);
      reject(new Error(`the fixture exited (code ${code}): ${stderr}`));
    });
  });
  return { child, hits, ready };
}

/// A minimal MCP client over stdio (newline-delimited JSON-RPC).
class McpClient {
  constructor(command, args, env) {
    this.child = spawn(command, args, { cwd: repo, stdio: ["pipe", "pipe", "pipe"], env, windowsHide: true });
    this.nextId = 0;
    this.pending = new Map();
    this.stderr = [];
    this.exit = new Promise((resolvePromise) => this.child.on("exit", (code) => resolvePromise(code)));
    this.child.stderr.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      this.stderr.push(text);
      process.stderr.write(text.replace(/^/gm, "  | "));
    });
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        return;
      }
      const waiter = this.pending.get(message.id);
      if (waiter) {
        this.pending.delete(message.id);
        clearTimeout(waiter.timer);
        waiter.resolve(message);
      }
    });
  }

  send(message) {
    this.child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", ...message })}\n`);
  }

  request(method, params, timeoutMs = 60_000) {
    this.nextId += 1;
    const id = this.nextId;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`${method} timed out after ${timeoutMs} ms`));
      }, timeoutMs);
      this.pending.set(id, { resolve: resolvePromise, timer });
      this.send({ id, method, params });
    });
  }

  async call(tool, args) {
    const started = Date.now();
    const message = await this.request("tools/call", { name: tool, arguments: args }, CALL_TIMEOUT_MS);
    const ms = Date.now() - started;
    if (message.error) return { tool, ok: false, ms, body: { error: message.error } };
    const result = message.result ?? {};
    let body;
    try {
      body = JSON.parse(result.content?.[0]?.text ?? "null");
    } catch {
      body = { raw: result.content?.[0]?.text };
    }
    // OB-03: a screenshot's PNG is MCP image content beside the JSON.
    const images = (result.content ?? []).filter((item) => item.type === "image");
    return { tool, ok: result.isError !== true, ms, body, images };
  }

  async close() {
    this.child.stdin.end();
    const timer = setTimeout(() => this.child.kill(), 30_000);
    const code = await this.exit;
    clearTimeout(timer);
    return code;
  }
}

/// SG-000135 OB-08: the owner's local lease management, as the lifecycle
/// CLI would send it: a second orceld of this build, on this run's state,
/// with no tool surface profile, one request, then its input closes. In a
/// founder run its STRONG prompt is the real Windows Hello the founder
/// answers; this script never answers it.
async function ownerRequest(paths, env, capability, operation, args) {
  const ownerEnv = { ...env, ORCEL_APP_API: "off" };
  delete ownerEnv.ORCEL_TOOL_SURFACE_PROFILE;
  const child = spawn(paths.orceld, [], { cwd: repo, stdio: ["pipe", "pipe", "pipe"], env: ownerEnv, windowsHide: true });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk.toString("utf8")));
  const exited = new Promise((resolvePromise) => child.on("exit", (code) => resolvePromise(code)));
  const line = await new Promise((resolvePromise, reject) => {
    const timer = setTimeout(() => reject(new Error(`the owner's ${capability} timed out: ${stderr}`)), CALL_TIMEOUT_MS);
    createInterface({ input: child.stdout }).once("line", (text) => {
      clearTimeout(timer);
      resolvePromise(text);
    });
    child.stdin.write(`${JSON.stringify({
      version: 1,
      request_id: `ob08-owner-${operation}`,
      client_session_id: "ob08-owner",
      workspace_id: "default",
      capability,
      operation,
      arguments: args
    })}\n`);
  });
  child.stdin.end();
  await exited;
  return JSON.parse(line);
}

/// Every node of a snapshot, flattened.
function flatten(nodes, out = []) {
  for (const node of nodes ?? []) {
    out.push(node);
    flatten(node.children, out);
  }
  return out;
}

/// Recompute a receipt's digest exactly as orceld's broker does
/// (crates/orceld/src/browser_broker.rs receipt_digest).
function receiptDigest(receipt) {
  const optional = (value) => (value === null || value === undefined ? "\u0000" : `\u0001${value}`);
  const parts = [
    RECEIPT_DOMAIN, String(receipt.seq), receipt.session_id, receipt.action, optional(receipt.page_id),
    optional(receipt.generation_before), optional(receipt.generation_after), receipt.outcome,
    optional(receipt.failure_code), receipt.evidence_kind, optional(receipt.evidence_sha256),
    optional(receipt.record_id), optional(receipt.lease_id), String(receipt.at_ms), receipt.previous_sha256
  ];
  const hash = createHash("sha256");
  for (const part of parts) {
    const bytes = Buffer.from(part, "utf8");
    const length = Buffer.alloc(8);
    length.writeBigUInt64BE(BigInt(bytes.length));
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

/// OB-03: decode an 8-bit, non-interlaced RGB or RGBA PNG; returns its
/// size and a pixel reader.
function decodePng(png) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  require_(png.length > 33 && png.subarray(0, 8).equals(signature) && png.toString("latin1", 12, 16) === "IHDR", "the screenshot is a PNG");
  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  require_(png[24] === 8 && png[28] === 0 && (png[25] === 2 || png[25] === 6), "the PNG is 8-bit RGB(A), not interlaced");
  const channels = png[25] === 6 ? 4 : 3;
  const data = [];
  for (let offset = 8; offset < png.length; ) {
    const length = png.readUInt32BE(offset);
    if (png.toString("latin1", offset + 4, offset + 8) === "IDAT") data.push(png.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
  }
  const raw = inflateSync(Buffer.concat(data));
  const stride = width * channels;
  const out = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    for (let x = 0; x < stride; x++) {
      const value = raw[y * (stride + 1) + 1 + x];
      const left = x >= channels ? out[y * stride + x - channels] : 0;
      const up = y > 0 ? out[(y - 1) * stride + x] : 0;
      const upLeft = y > 0 && x >= channels ? out[(y - 1) * stride + x - channels] : 0;
      let predicted = 0;
      if (filter === 1) predicted = left;
      else if (filter === 2) predicted = up;
      else if (filter === 3) predicted = (left + up) >> 1;
      else if (filter === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upLeft);
        predicted = pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
      }
      out[y * stride + x] = (value + predicted) & 0xff;
    }
  }
  return { width, height, pixel: (x, y) => [...out.subarray(y * stride + x * channels, y * stride + x * channels + 3)] };
}

/// OB-03: a screenshot step's checked PNG: one image, its digest the
/// reply's, its size the reply's.
function screenshotOf(step) {
  require_(step.ok && step.images.length === 1 && step.images[0].mimeType === "image/png", `browser_screenshot returns one PNG image: ${JSON.stringify(step.body)}`);
  const png = Buffer.from(step.images[0].data, "base64");
  const result = step.body.result;
  require_(result.png_base64 === undefined, "the image is never inside the JSON");
  require_(createHash("sha256").update(png).digest("hex") === result.sha256 && png.length === result.bytes, "the image is the one whose digest the reply names");
  const decoded = decodePng(png);
  require_(decoded.width === result.width && decoded.height === result.height, "the PNG's size is the reply's");
  return { png, decoded, result };
}

/// Edge processes whose command line names `root` (this run's isolated state).
function edgeProcessesUnder(root) {
  const script = "Get-CimInstance Win32_Process -Filter \"Name='msedge.exe'\" | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress";
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf8", windowsHide: true });
  if (result.status !== 0 || !result.stdout.trim()) return [];
  const parsed = JSON.parse(result.stdout);
  const list = Array.isArray(parsed) ? parsed : [parsed];
  const needle = root.toLowerCase();
  return list.filter((entry) => (entry.CommandLine ?? "").toLowerCase().includes(needle));
}

function listDirs(path) {
  try {
    return readdirSync(path).filter((name) => statSync(join(path, name)).isDirectory());
  } catch {
    return [];
  }
}

async function mission(options, paths, fixtureSpki, fixture) {
  const steps = [];
  const record = (step, extra = {}) => {
    steps.push({ tool: step.tool, ok: step.ok, ms: step.ms, ...extra });
    const outcome = step.ok ? "ok" : `refused ${step.body?.error?.code ?? "?"}`;
    process.stdout.write(`OB01-E2E step ${steps.length} ${step.tool}: ${outcome} in ${step.ms} ms\n`);
  };
  const expectOk = (step, what) => {
    require_(step.ok, `${what}: ${JSON.stringify(step.body)}`);
    return step.body.result;
  };
  const env = {
    PATH: process.env.PATH ?? process.env.Path ?? "",
    PATHEXT: process.env.PATHEXT ?? "",
    SystemRoot: process.env.SystemRoot ?? "C:\\Windows",
    WINDIR: process.env.WINDIR ?? "C:\\Windows",
    COMSPEC: process.env.COMSPEC ?? "",
    TEMP: process.env.TEMP ?? "",
    TMP: process.env.TMP ?? "",
    ProgramFiles: process.env.ProgramFiles ?? "",
    "ProgramFiles(x86)": process.env["ProgramFiles(x86)"] ?? "",
    PROGRAMDATA: process.env.PROGRAMDATA ?? "",
    NUMBER_OF_PROCESSORS: process.env.NUMBER_OF_PROCESSORS ?? "",
    PROCESSOR_ARCHITECTURE: process.env.PROCESSOR_ARCHITECTURE ?? "",
    // Orcel's state (approval ledger, audit, broker sessions and profiles)
    // lives under this run's own root, never the user's real state.
    USERPROFILE: paths.root,
    LOCALAPPDATA: join(paths.root, "AppData", "Local"),
    APPDATA: join(paths.root, "AppData", "Roaming"),
    ORCEL_TOOL_SURFACE_PROFILE: "browser_full",
    ORCEL_DAEMON: paths.orceld,
    ORCEL_WORKSPACE_ROOT: paths.workspace,
    ORCEL_WORKSPACE_ID: "default",
    ORCEL_E2E_FIXTURE_SPKI: fixtureSpki
  };
  if (options.consent === "scripted") {
    env.ORCEL_E2E_CONSENT_LOG = paths.consentLog;
    // SG-000132 slice 2: orceld's lease source talks to this run's
    // authority console harness (test builds only).
    env.ORCEL_E2E_AUTHORITY = JSON.stringify(paths.authority.expectation);
  }

  const started = Date.now();
  const client = new McpClient(process.execPath, [join(repo, "apps", "orcel-mcp", "dist", "entrypoints", "stdio.js")], env);
  activeClient = client;
  const init = await client.request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "orcel-ob01-e2e", version: "1" }
  });
  require_(!init.error, `initialize: ${JSON.stringify(init.error)}`);
  client.send({ method: "notifications/initialized" });
  const listed = await client.request("tools/list", {});
  const tools = (listed.result?.tools ?? []).map((tool) => tool.name);
  for (const name of EXPECTED_TOOLS) require_(tools.includes(name), `${name} is listed: ${tools.join(", ")}`);

  const create = await client.call("browser_session_create", { task: SESSION_TASK });
  record(create);
  const session = expectOk(create, "browser_session_create").session_id;
  if (options.consent === "scripted") {
    // The build must be the scripted-consent one: otherwise a real dialog
    // would appear with nobody to answer it. Checked before any approval.
    const log = existsSync(paths.consentLog) ? readFileSync(paths.consentLog, "utf8") : "";
    require_(log.includes("\"scripted_consent_started\""), "orceld is not the scripted-consent build (no consent log header); stopping before any approval");
  } else {
    process.stdout.write("OB01-E2E founder run: 5 Orcel approval dialogs follow (open, fill, select, click, open the second tab), then (OB-08) one Windows Hello prompt for Full Access and two more dialogs (the submit link, the open after the revoke). Read each and answer it yourself.\n");
  }

  const open = await client.call("browser_open", { session_id: session, url: FORM_URL });
  record(open);
  const opened = expectOk(open, "browser_open");
  require_(opened.url === FORM_URL && opened.status === 200, `browser_open committed the form: ${JSON.stringify(opened)}`);

  // While the session lives: its folder holds its profile, and its Edge is
  // headless, pipe-driven, in that profile, with no remote debugging port.
  const sessionDir = join(paths.brokerRoot, "sessions", session.split("-")[1], session);
  const liveProfiles = listDirs(join(sessionDir, "profiles"));
  const edge = edgeProcessesUnder(paths.root);
  const edgeMain = edge.filter((entry) => !/--type=/.test(entry.CommandLine ?? ""));
  const edgeFacts = {
    session_dir_exists: existsSync(sessionDir),
    profiles: liveProfiles.length,
    edge_processes: edge.length,
    browser_processes: edgeMain.length,
    headless: edgeMain.length > 0 && edgeMain.every((entry) => /--headless/.test(entry.CommandLine)),
    pipe: edgeMain.length > 0 && edgeMain.every((entry) => /--remote-debugging-pipe/.test(entry.CommandLine)),
    remote_debugging_port: edge.some((entry) => /--remote-debugging-port/.test(entry.CommandLine ?? "")),
    profile_in_session_dir: edgeMain.length > 0 && edgeMain.every((entry) => (entry.CommandLine ?? "").toLowerCase().includes(sessionDir.toLowerCase()))
  };
  process.stdout.write(`OB01-E2E live session: ${JSON.stringify(edgeFacts)}\n`);
  require_(edgeFacts.session_dir_exists && edgeFacts.profiles >= 1, "the session folder holds its profile while it lives");
  require_(edgeFacts.browser_processes >= 1 && edgeFacts.headless && edgeFacts.pipe && !edgeFacts.remote_debugging_port, "Edge runs headless over a pipe with no remote debugging port");
  require_(edgeFacts.profile_in_session_dir, "Edge's profile is inside the session's own folder");

  const snap = await client.call("browser_snapshot", { session_id: session });
  record(snap);
  const observed = expectOk(snap, "browser_snapshot");
  const nodes = flatten(observed.nodes);
  const textbox = nodes.find((node) => node.role === "textbox" && node.untrusted_name?.text === "Full name");
  const combobox = nodes.find((node) => node.role === "combobox" && node.untrusted_name?.text === "City");
  const links = nodes.filter((node) => node.role === "link");
  require_(textbox && combobox && links.length === 1, `the snapshot shows the field, the list and one link: ${JSON.stringify(nodes.map((node) => [node.node_id, node.role, node.untrusted_name?.text]))}`);
  let generation = observed.generation;

  const fill = await client.call("browser_fill", { session_id: session, node_id: textbox.node_id, value: NAME_VALUE, expected_generation: generation });
  record(fill);
  expectOk(fill, "browser_fill");
  require_(!JSON.stringify(fill.body).includes(NAME_VALUE), "the fill reply never carries the value");

  const select = await client.call("browser_select", { session_id: session, node_id: combobox.node_id, option: CITY_OPTION, expected_generation: generation });
  record(select);
  expectOk(select, "browser_select");

  const verifyForm = await client.call("browser_verify", {
    session_id: session,
    expected_generation: generation,
    checks: [
      { kind: "url_is", url: FORM_URL },
      { kind: "value_equals", node_id: textbox.node_id, value: NAME_VALUE },
      { kind: "value_equals", node_id: combobox.node_id, value: CITY_OPTION }
    ]
  });
  record(verifyForm);
  const formReport = expectOk(verifyForm, "browser_verify (form)");
  require_(formReport.verified === true, `the form holds the filled value and the chosen option: ${JSON.stringify(formReport.results)}`);

  const click = await client.call("browser_click", { session_id: session, node_id: links[0].node_id, expected_generation: generation });
  record(click);
  const clicked = expectOk(click, "browser_click");
  require_(clicked.url === DONE_URL && clicked.generation > generation, `the link opened the second page: ${JSON.stringify(clicked)}`);
  generation = clicked.generation;

  const verifyDone = await client.call("browser_verify", {
    session_id: session,
    expected_generation: generation,
    checks: [
      { kind: "url_is", url: DONE_URL },
      { kind: "text_visible", text: DONE_TEXT }
    ]
  });
  record(verifyDone);
  const doneReport = expectOk(verifyDone, "browser_verify (second page)");
  require_(doneReport.verified === true, `the second page is the result: ${JSON.stringify(doneReport.results)}`);

  const extract = await client.call("browser_extract", { session_id: session, expected_generation: generation });
  record(extract);
  const extracted = expectOk(extract, "browser_extract");
  require_(typeof extracted.text === "string" && extracted.text.includes(DONE_TEXT) && extracted.truncated === false, `the extract holds the second page's text: ${JSON.stringify(extracted)}`);

  // SG-000135 OB-03: a screenshot of the page, a second tab, a masked
  // screenshot of it, switch back, close it.
  const shot = await client.call("browser_screenshot", { session_id: session, expected_generation: generation });
  record(shot);
  const firstShot = screenshotOf(shot);
  require_(firstShot.decoded.width === 1280 && firstShot.decoded.height === 720 && firstShot.result.truncated === false, `the viewport screenshot is 1280 x 720: ${JSON.stringify(firstShot.result)}`);
  const firstPage = opened.page_id;

  const tabNew = await client.call("browser_tabs", { session_id: session, action: "new", url: SECRET_URL });
  record(tabNew);
  const newTabs = expectOk(tabNew, "browser_tabs new");
  require_(newTabs.tabs.length === 2 && newTabs.navigation?.url === SECRET_URL && newTabs.navigation?.status === 200, `the second tab opened the secret-field page: ${JSON.stringify(newTabs)}`);
  const secondTab = newTabs.tabs.find((tab) => tab.active);
  require_(secondTab && secondTab.page_id !== firstPage && newTabs.active_page_id === secondTab.page_id, "the new tab is active, with its own page id");

  const tabList = await client.call("browser_tabs", { session_id: session, action: "list" });
  record(tabList);
  const tabsListed = expectOk(tabList, "browser_tabs list");
  require_(tabsListed.tabs.length === 2 && tabsListed.tabs.some((tab) => tab.page_id === firstPage && !tab.active && tab.url === DONE_URL), `both tabs are listed, the first inactive: ${JSON.stringify(tabsListed.tabs)}`);

  const secretShot = await client.call("browser_screenshot", { session_id: session, expected_generation: secondTab.generation });
  record(secretShot);
  const masked = screenshotOf(secretShot);
  const at = (top) => masked.decoded.pixel(200, top + 24);
  const maskFacts = { ordinary: at(20), password: at(100), one_time_code: at(180), card_number: at(260), secret_name: at(340) };
  process.stdout.write(`OB03-E2E mask pixels: ${JSON.stringify(maskFacts)}\n`);
  require_(JSON.stringify(maskFacts.ordinary) === "[0,255,0]", "the ordinary field keeps its colour (positive control)");
  for (const name of ["password", "one_time_code", "card_number", "secret_name"]) {
    require_(JSON.stringify(maskFacts[name]) === "[0,0,0]", `the ${name} field is painted over`);
  }

  const tabSwitch = await client.call("browser_tabs", { session_id: session, action: "switch", page_id: firstPage });
  record(tabSwitch);
  const switched = expectOk(tabSwitch, "browser_tabs switch");
  require_(switched.active_page_id === firstPage, `the first tab is active again: ${JSON.stringify(switched)}`);

  const verifyBack = await client.call("browser_verify", { session_id: session, expected_generation: generation, checks: [{ kind: "url_is", url: DONE_URL }, { kind: "text_visible", text: DONE_TEXT }] });
  record(verifyBack);
  require_(expectOk(verifyBack, "browser_verify (first tab again)").verified === true, "the first tab still holds the second page");

  const tabClose = await client.call("browser_tabs", { session_id: session, action: "close", page_id: secondTab.page_id });
  record(tabClose);
  const afterClose = expectOk(tabClose, "browser_tabs close");
  require_(afterClose.tabs.length === 1 && afterClose.tabs[0].page_id === firstPage && afterClose.tabs[0].active, `one tab is left, the first: ${JSON.stringify(afterClose)}`);
  const ob03 = {
    viewport_png_bytes: firstShot.png.length,
    viewport_sha256: firstShot.result.sha256,
    masked_png_bytes: masked.png.length,
    masked_sha256: masked.result.sha256,
    mask_pixels: maskFacts,
    tabs_after_new: newTabs.tabs.length,
    tabs_after_close: afterClose.tabs.length
  };

  // SG-000135 OB-08: Full Access. The authority service issues a lease for
  // this session after the owner's grant; the agent can only read it. A
  // founder run skips it: the installed service trusts only the installed
  // orceld, never this test build.
  const softPrompts = () =>
    options.consent === "scripted" && existsSync(paths.consentLog)
      ? readFileSync(paths.consentLog, "utf8").trim().split("\n").map((line) => JSON.parse(line)).filter((line) => line.event === "soft_prompt")
      : [];
  const clientRef = expectOk(create, "browser_session_create").client_ref;
  require_(/^cl-[0-9a-f]{32}$/.test(clientRef ?? ""), `the session names its client reference: ${clientRef}`);
  let ob08;
  if (options.consent === "scripted") {
  // orceld issues nothing, whoever asks.
  const refusedIssue = await ownerRequest(paths, env, "browser.lease.issue", "issue", {
    session_id: session, client_ref: clientRef, origins: [FIXTURE], families: LEASE_FAMILIES, minutes: 30, task: SESSION_TASK
  });
  require_(refusedIssue.ok === false && /authority service/.test(refusedIssue.error?.message ?? ""), `orceld refuses to issue a lease: ${JSON.stringify(refusedIssue)}`);
  const granted = await ownerGrant(paths.authority.expectation.pipe, {
    kind: "browser_full_access",
    client_ref: clientRef,
    session_id: session,
    origins: [FIXTURE],
    families: LEASE_FAMILIES,
    task: SESSION_TASK
  }, SESSION_TASK);
  const leaseId = granted.lease.body.lease_id;
  require_(/^al-[0-9a-f]{32}$/.test(leaseId) && JSON.stringify(granted.lease.body.scope.origins) === JSON.stringify([FIXTURE]), `the service's lease names the fixture origin: ${JSON.stringify(granted.lease.body.scope)}`);
  require_(/^[0-9a-f]{128}$/.test(granted.lease.signature), "the lease carries the service's ECDSA P-256 signature");
  const leased = await client.call("browser_task_status", { session_id: session });
  record(leased);
  const leaseStatus = expectOk(leased, "browser_task_status (lease)").full_access;
  require_(leaseStatus?.active === true && leaseStatus.lease_id === leaseId && leaseStatus.routine_only === true, `the agent reads the lease, read-only: ${JSON.stringify(leaseStatus)}`);
  require_(!JSON.stringify(leaseStatus).includes("S-1-"), "the status names no Windows user");

  const promptsBefore = softPrompts().length;
  let routine = 0;
  const openForm = async () => {
    const step = await client.call("browser_open", { session_id: session, url: OB08_FORM_URL });
    record(step);
    const result = expectOk(step, "browser_open (lease)");
    require_(result.url === OB08_FORM_URL && result.receipt?.lease_id === leaseId && result.receipt?.record_id === null, `the open ran under the lease: ${JSON.stringify(result.receipt)}`);
    routine += 1;
    return result;
  };
  const formNodes = async () => {
    const step = await client.call("browser_snapshot", { session_id: session });
    record(step);
    const snapped = expectOk(step, "browser_snapshot (lease)");
    const all = flatten(snapped.nodes);
    const field = all.find((node) => node.role === "textbox" && node.untrusted_name?.text === "Full name");
    const list = all.find((node) => node.role === "combobox" && node.untrusted_name?.text === "City");
    const formLinks = all.filter((node) => node.role === "link");
    require_(field && list && formLinks.length === 2, `the routine page shows its field, list and two links: ${JSON.stringify(all.map((node) => [node.node_id, node.role]))}`);
    return { generation: snapped.generation, field, list, next: formLinks[0], submit: formLinks[1] };
  };
  for (let round = 0; round < 6; round += 1) {
    await openForm();
    const form = await formNodes();
    const fillStep = await client.call("browser_fill", { session_id: session, node_id: form.field.node_id, value: `Round ${round}`, expected_generation: form.generation });
    record(fillStep);
    const filled = expectOk(fillStep, "browser_fill (lease)");
    require_(filled.approval === "lease" && filled.lease_id === leaseId && filled.record_id === null, `the fill ran under the lease: ${JSON.stringify(filled)}`);
    routine += 1;
    const selectStep = await client.call("browser_select", { session_id: session, node_id: form.list.node_id, option: round % 2 === 0 ? "Porto" : "Faro", expected_generation: form.generation });
    record(selectStep);
    const selected = expectOk(selectStep, "browser_select (lease)");
    require_(selected.approval === "lease" && selected.lease_id === leaseId, `the select ran under the lease: ${JSON.stringify(selected)}`);
    routine += 1;
    const nextStep = await client.call("browser_click", { session_id: session, node_id: form.next.node_id, expected_generation: form.generation });
    record(nextStep);
    const nexted = expectOk(nextStep, "browser_click (lease)");
    require_(nexted.url === OB08_NEXT_URL && nexted.receipt?.lease_id === leaseId, `the ordinary link ran under the lease: ${JSON.stringify(nexted)}`);
    routine += 1;
  }
  // OB-08 review: a page whose scripts post on input and on click. The
  // fill and the click run under the lease, and neither post leaves.
  const postOpen = await client.call("browser_open", { session_id: session, url: OB08_POST_URL });
  record(postOpen);
  require_(expectOk(postOpen, "browser_open (posting page)").receipt?.lease_id === leaseId, "the posting page opened under the lease");
  const postSnap = await client.call("browser_snapshot", { session_id: session });
  record(postSnap);
  const postObserved = expectOk(postSnap, "browser_snapshot (posting page)");
  const postNodes = flatten(postObserved.nodes);
  const note = postNodes.find((node) => node.role === "textbox" && node.untrusted_name?.text === "Note");
  const postLink = postNodes.find((node) => node.role === "link");
  require_(note && postLink, `the posting page shows its field and link: ${JSON.stringify(postNodes.map((node) => [node.node_id, node.role]))}`);
  const noteStep = await client.call("browser_fill", { session_id: session, node_id: note.node_id, value: "Hello", expected_generation: postObserved.generation });
  record(noteStep);
  require_(expectOk(noteStep, "browser_fill (posting page)").approval === "lease", "the fill on the posting page ran under the lease");
  const postClick = await client.call("browser_click", { session_id: session, node_id: postLink.node_id, expected_generation: postObserved.generation });
  record(postClick);
  const postClicked = expectOk(postClick, "browser_click (posting page)");
  require_(postClicked.url === OB08_NEXT_URL && postClicked.receipt?.lease_id === leaseId, `the link was navigated under the lease: ${JSON.stringify(postClicked)}`);
  // Give any late script request the time to reach the fixture.
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 1500));
  const leaked = fixture.hits.filter((hit) => hit.includes("/ob08-sink") || hit.includes("/ob08-beacon"));
  require_(leaked.length === 0, `no page post or beacon left under the lease: ${leaked.join(", ")}`);
  await openForm();
  require_(routine === OB08_ROUTINE_ACTIONS, `${OB08_ROUTINE_ACTIONS} routine actions ran under the lease: ${routine}`);
  const routinePrompts = softPrompts().length - promptsBefore;
  require_(routinePrompts === 0, `the routine actions raised no Orcel prompt: ${routinePrompts}`);

  // A link named as a submit is never routine: it asks, once.
  const submitForm = await formNodes();
  const submitStep = await client.call("browser_click", { session_id: session, node_id: submitForm.submit.node_id, expected_generation: submitForm.generation });
  record(submitStep);
  const submitted = expectOk(submitStep, "browser_click (submit)");
  require_(submitted.url === OB08_SUBMITTED_URL && submitted.receipt?.lease_id === null && typeof submitted.receipt?.record_id === "string", `the submit asked and ran on its own approval: ${JSON.stringify(submitted.receipt)}`);
  const submitPrompts = softPrompts().slice(promptsBefore);
  if (options.consent === "scripted") {
    require_(submitPrompts.length === 1 && submitPrompts[0].target === OB08_SUBMITTED_URL, `the submit raised exactly one prompt: ${JSON.stringify(submitPrompts)}`);
  }

  // The owner revokes: the very next action is refused, nothing sent.
  const revoked = await ownerRequest(paths, env, "browser.lease.revoke", "revoke", { lease_id: leaseId });
  require_(revoked.ok === true && revoked.result.revoked === 1, `the owner revoked the lease: ${JSON.stringify(revoked)}`);
  const afterRevoke = await client.call("browser_open", { session_id: session, url: OB08_FORM_URL });
  record(afterRevoke);
  require_(!afterRevoke.ok && afterRevoke.body?.error?.code === "CAPABILITY_DENIED" && /lease_invalid/.test(afterRevoke.body?.error?.message ?? ""), `the next action after the revoke is refused lease_invalid: ${JSON.stringify(afterRevoke.body)}`);
  const askedAgain = await client.call("browser_open", { session_id: session, url: OB08_FORM_URL });
  record(askedAgain);
  const reopened = expectOk(askedAgain, "browser_open (after revoke)");
  require_(reopened.receipt?.lease_id === null && typeof reopened.receipt?.record_id === "string", `after the revoke the open asks again: ${JSON.stringify(reopened.receipt)}`);
  if (options.consent === "scripted") {
    require_(softPrompts().length - promptsBefore === 2, "the submit and the open after the revoke are the only prompts since the lease");
  }
  ob08 = {
    issued_by: "orcel_authority_service (console harness, scripted consent)",
    lease_signature: granted.lease.signature,
    confirmation_text: granted.confirmation,
    lease_id: leaseId,
    lease_session: session,
    routine_actions: routine,
    routine_prompts: routinePrompts,
    posting_page_leaks: 0,
    submit_asked: true,
    revoke_refused: afterRevoke.body?.error?.message,
    asked_after_revoke: true
  };
  } else {
    ob08 = { skipped: "a founder run uses real dialogs; Full Access needs the installed authority service, which trusts only the installed orceld, never this test build" };
  }

  const status = await client.call("browser_task_status", { session_id: session });
  record(status);
  const state = expectOk(status, "browser_task_status");
  const receipts = state.receipts ?? [];
  let previous = "";
  for (const receipt of receipts) {
    require_(receipt.provisional === true && receipt.previous_sha256 === previous, `receipt ${receipt.seq} chains to the one before`);
    require_(receiptDigest(receipt) === receipt.receipt_sha256, `receipt ${receipt.seq}'s digest recomputes`);
    // OB-08: the one action after the revoke is refused, nothing sent.
    const refusedAfterRevoke = receipt.outcome === "refused" && receipt.failure_code === "CAPABILITY_DENIED" && receipt.action === "browser_open";
    require_(receipt.outcome === "done" || refusedAfterRevoke, `receipt ${receipt.seq} (${receipt.action}) is done: ${receipt.outcome}`);
    require_(!(receipt.record_id && receipt.lease_id), `receipt ${receipt.seq} names an approval or a lease, never both`);
    previous = receipt.receipt_sha256;
  }
  const actions = receipts.map((receipt) => receipt.action);
  const ob08Round = ["browser_open", "browser_snapshot", "browser_fill", "browser_select", "browser_click"];
  const fullAccessRun = options.consent === "scripted";
  const expectedActions = [
    "browser_open", "browser_snapshot", "browser_fill", "browser_select", "browser_verify", "browser_click", "browser_verify", "browser_extract",
    "browser_screenshot", "browser_tabs", "browser_tabs", "browser_screenshot", "browser_tabs", "browser_verify", "browser_tabs",
    ...(fullAccessRun
      ? [
          ...Array.from({ length: 6 }, () => ob08Round).flat(),
          "browser_open", "browser_snapshot", "browser_fill", "browser_click",
          "browser_open", "browser_snapshot", "browser_click", "browser_open", "browser_open"
        ]
      : [])
  ];
  require_(JSON.stringify(actions) === JSON.stringify(expectedActions), `the receipts are the mission's actions: ${actions.join(", ")}`);
  require_(state.last_receipt_sha256 === previous, "the chain head is the last receipt");
  const approved = receipts.filter((receipt) => receipt.record_id);
  const approvedExpected = fullAccessRun ? APPROVED_ACTIONS : APPROVED_ACTIONS - 2;
  require_(approved.length === approvedExpected, `${approvedExpected} actions carry an approval record (open, fill, select, click, the new tab, and with Full Access the submit and the open after the revoke): ${approved.length}`);
  const leasedReceipts = receipts.filter((receipt) => receipt.lease_id);
  const leasedExpected = fullAccessRun ? OB08_ROUTINE_ACTIONS + 3 : 0;
  require_(leasedReceipts.length === leasedExpected && leasedReceipts.every((receipt) => receipt.lease_id === ob08.lease_id && receipt.outcome === "done"), `every routine action is receipted with the lease: ${leasedReceipts.length}`);
  // OB-03: a screenshot's receipt keeps its digest only.
  const shotReceipts = receipts.filter((receipt) => receipt.action === "browser_screenshot");
  require_(
    shotReceipts.length === 2 &&
      shotReceipts[0].evidence_kind === "screenshot" &&
      shotReceipts[0].evidence_sha256 === ob03.viewport_sha256 &&
      shotReceipts[1].evidence_sha256 === ob03.masked_sha256 &&
      !JSON.stringify(receipts).includes("png_base64"),
    "each screenshot receipt holds the image's digest and nothing of the image"
  );

  const close = await client.call("browser_close", { session_id: session });
  record(close);
  const closed = expectOk(close, "browser_close");
  require_(closed.worker_ended === true && closed.profile_removed === true && closed.reason === "closed", `the session ended and its profile was removed: ${JSON.stringify(closed)}`);
  require_(!existsSync(sessionDir), `the session folder is gone from disk: ${sessionDir}`);
  const after = await client.call("browser_task_status", { session_id: session });
  require_(!after.ok && after.body?.error?.code === "TARGET_STALE", `the closed session's id is refused: ${JSON.stringify(after.body)}`);

  const exitCode = await client.close();
  const leftEdge = edgeProcessesUnder(paths.root);
  const leftSessions = listDirs(join(paths.brokerRoot, "sessions")).flatMap((instance) => listDirs(join(paths.brokerRoot, "sessions", instance)));
  require_(leftEdge.length === 0, `no Edge of this run is left: ${leftEdge.map((entry) => entry.ProcessId).join(", ")}`);
  require_(leftSessions.length === 0, `no session folder is left: ${leftSessions.join(", ")}`);

  return {
    consent: options.consent,
    total_ms: Date.now() - started,
    tools_listed: tools.length,
    steps,
    live_session: edgeFacts,
    receipts,
    receipts_count: receipts.length,
    chain_head: previous,
    approvals_recorded: approved.map((receipt) => ({ action: receipt.action, record_id: receipt.record_id })),
    close: closed,
    closed_id_refused: after.body?.error?.code,
    mcp_exit_code: exitCode,
    edge_left: leftEdge.length,
    session_folders_left: leftSessions.length,
    ob03,
    ob08,
    fixture_hits: fixture.hits.filter((hit) => hit.includes("/ob01-") || hit.includes("/ob08-"))
  };
}

async function main() {
  require_(process.platform === "win32", "this mission is Windows-only evidence");
  const options = parseArgs(process.argv.slice(2));
  const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*$/, "");
  const root = join(homedir(), `orcel-ob01-e2e-${options.consent}-${stamp}`);
  const evidenceDir = options.evidence ? resolve(options.evidence) : join(homedir(), `orcel-ob01-e2e-evidence-${options.consent}-${stamp}`);
  const pin = {};
  if (!options.skipBuild) build(options.consent, pin);
  const built = join(targetDir(options.consent), "debug");
  const orceld = join(built, "orceld.exe");
  require_(existsSync(orceld) && existsSync(join(built, "orcel-browser-host.exe")), `orceld and the browser host are built in ${built}`);
  const paths = {
    root,
    orceld,
    workspace: join(root, "workspace"),
    brokerRoot: join(root, ".orcel", "browser-profile", "live", "broker"),
    consentLog: join(evidenceDir, "consent.jsonl"),
    authorityConsentLog: join(evidenceDir, "authority-consent.jsonl"),
    authority: null
  };
  mkdirSync(paths.workspace, { recursive: true });
  mkdirSync(evidenceDir, { recursive: true });
  const fixture = startFixture();
  let summary;
  try {
    if (options.consent === "scripted") paths.authority = await startAuthority(paths, built);
    const spki = await fixture.ready;
    summary = await mission(options, paths, spki, fixture);
    const ledger = join(root, ".orcel");
    summary.approval_ledger_files = existsSync(ledger) ? readdirSync(ledger) : [];
    if (options.consent === "scripted") {
      const lines = readFileSync(paths.consentLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
      const prompts = lines.filter((line) => line.event === "soft_prompt");
      require_(prompts.length === APPROVED_ACTIONS && prompts.every((prompt) => prompt.decision === "approved"), `seven scripted SOFT prompts, each approved: ${prompts.length}`);
      summary.scripted_prompts = prompts.map((prompt) => ({ action: prompt.action, target: prompt.target }));
      // OB-08: orceld asks no STRONG prompt at all (the service issues).
      const strong = lines.filter((line) => line.event === "strong_presence");
      require_(strong.length === 0, `orceld asked no STRONG prompt: ${JSON.stringify(strong)}`);
      // SG-000132 slice 2: the authority's one scripted confirmation, for
      // exactly this session's browser grant on the fixture origin.
      const confirmations = readFileSync(paths.authorityConsentLog, "utf8").trim().split("\n").map((line) => JSON.parse(line));
      require_(
        confirmations.length === 1 &&
          confirmations[0].title === "Orcel Authority" &&
          confirmations[0].text.includes(`session ${summary.ob08.lease_session}`) &&
          confirmations[0].text.includes(`origins [${FIXTURE}]`),
        `one scripted authority confirmation, for this browser grant: ${JSON.stringify(confirmations)}`
      );
      summary.scripted_authority_confirmations = confirmations;
    }
    writeFileSync(join(evidenceDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
    const steps = summary.steps.map((step) => `${step.tool}=${step.ok ? "ok" : "refused"}/${step.ms}ms`).join(" ");
    process.stdout.write(
      `OB01-E2E-EVIDENCE ${options.consent} consent: ${steps}; ${summary.receipts_count} receipts chained (head ${summary.chain_head.slice(0, 16)}), ` +
        `${summary.approvals_recorded.length} approval records, profile removed, ${summary.edge_left} Edge left, ` +
        `${summary.session_folders_left} session folders left, MCP exit ${summary.mcp_exit_code}, ${summary.total_ms} ms; evidence ${evidenceDir}` +
        (options.consent === "scripted" ? " (SCRIPTED consent: not human acceptance)\n" : "\n")
    );
  } finally {
    if (activeClient !== null && activeClient.child.exitCode === null) {
      // A failed run still ends its MCP session: orceld ends the broker
      // sessions and removes their profiles when its input closes.
      await activeClient.close().catch(() => {});
    }
    fixture.child.stdin.end();
    fixture.child.kill();
    if (paths.authority !== null) {
      paths.authority.child.stdin.end();
      paths.authority.child.kill();
    }
    if (!options.keepState) {
      try {
        rmSync(root, { recursive: true, force: true, maxRetries: 5, retryDelay: 500 });
      } catch (error) {
        process.stderr.write(`OB01-E2E: could not remove the state root ${root}: ${error.message}
`);
      }
    }
  }
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
