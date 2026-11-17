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
// browser_verify (the second page), browser_extract, browser_task_status,
// browser_close. Then: the provisional receipts chain is recomputed here,
// the session's folder (its profile) must be gone, no Edge of this run may
// be left, and orceld must end when the MCP session ends.
//
// Two consent modes, never mixed:
//   --consent scripted  TEST HARNESS. Builds orceld with the test-only
//                       `browser-full-scripted-consent` feature: the real
//                       approval broker and ledger, with the SOFT consent
//                       decided by the approval crate's existing test-support
//                       soft decider (approve only isolated browser prompts on
//                       https://fixture.test; deny everything else) and every
//                       prompt's dialog text recorded. No dialog is shown.
//                       This is scripted consent, not human acceptance.
//   --consent founder   FOUNDER RUN. Builds orceld WITHOUT that feature: every
//                       approval is a real Orcel dialog that the person at the
//                       PC answers. This script never answers, clicks or
//                       scripts a dialog; it only waits and records.
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
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { runtimePin } from "../apps/orcel-browser-worker/scripts/dev-pin.mjs";

const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workerApp = join(repo, "apps", "orcel-browser-worker");
const FIXTURE = "https://fixture.test";
const FORM_URL = `${FIXTURE}/ob01-form`;
const DONE_URL = `${FIXTURE}/ob01-done`;
const NAME_VALUE = "Ada Lovelace";
const CITY_OPTION = "Porto";
const DONE_TEXT = "OB-01 mission second page reached";
const EXPECTED_TOOLS = [
  "browser_session_create", "browser_open", "browser_snapshot", "browser_click", "browser_fill",
  "browser_select", "browser_verify", "browser_extract", "browser_close", "browser_task_status"
];
// Longer than the MCP edge's own 10-minute approval timeout, so a dialog that
// waits for a person ends as orceld's answer, not as this client giving up.
const CALL_TIMEOUT_MS = 11 * 60_000;
const RECEIPT_DOMAIN = "orcel-ob01-receipt/1";
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

function targetDir() {
  return process.env.CARGO_TARGET_DIR ? resolve(repo, process.env.CARGO_TARGET_DIR) : join(repo, "target");
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
  const env = { ...process.env, ...pin };
  const live = "live-browser-test,live-browser-dev";
  run("cargo", ["build", "-p", "orcel-browser-host", "--features", live, "--bin", "orcel-browser-host"], env);
  const features = consent === "scripted" ? `${live},browser-full-scripted-consent` : live;
  run("cargo", ["build", "-p", "orceld", "--features", features, "--bin", "orceld"], env);
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
    return { tool, ok: result.isError !== true, ms, body };
  }

  async close() {
    this.child.stdin.end();
    const timer = setTimeout(() => this.child.kill(), 30_000);
    const code = await this.exit;
    clearTimeout(timer);
    return code;
  }
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
    optional(receipt.record_id), String(receipt.at_ms), receipt.previous_sha256
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
  if (options.consent === "scripted") env.ORCEL_E2E_CONSENT_LOG = paths.consentLog;

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

  const create = await client.call("browser_session_create", { task: "OB-01 E2E fixture mission" });
  record(create);
  const session = expectOk(create, "browser_session_create").session_id;
  if (options.consent === "scripted") {
    // The build must be the scripted-consent one: otherwise a real dialog
    // would appear with nobody to answer it. Checked before any approval.
    const log = existsSync(paths.consentLog) ? readFileSync(paths.consentLog, "utf8") : "";
    require_(log.includes("\"scripted_consent_started\""), "orceld is not the scripted-consent build (no consent log header); stopping before any approval");
  } else {
    process.stdout.write("OB01-E2E founder run: 4 Orcel approval dialogs follow (open, fill, select, click). Read each and answer it yourself.\n");
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

  const status = await client.call("browser_task_status", { session_id: session });
  record(status);
  const state = expectOk(status, "browser_task_status");
  const receipts = state.receipts ?? [];
  let previous = "";
  for (const receipt of receipts) {
    require_(receipt.provisional === true && receipt.previous_sha256 === previous, `receipt ${receipt.seq} chains to the one before`);
    require_(receiptDigest(receipt) === receipt.receipt_sha256, `receipt ${receipt.seq}'s digest recomputes`);
    require_(receipt.outcome === "done", `receipt ${receipt.seq} (${receipt.action}) is done: ${receipt.outcome}`);
    previous = receipt.receipt_sha256;
  }
  const actions = receipts.map((receipt) => receipt.action);
  const expectedActions = ["browser_open", "browser_snapshot", "browser_fill", "browser_select", "browser_verify", "browser_click", "browser_verify", "browser_extract"];
  require_(JSON.stringify(actions) === JSON.stringify(expectedActions), `the receipts are the mission's actions: ${actions.join(", ")}`);
  require_(state.last_receipt_sha256 === previous, "the chain head is the last receipt");
  const approved = receipts.filter((receipt) => receipt.record_id);
  require_(approved.length === 4, `four actions carry an approval record (open, fill, select, click): ${approved.length}`);

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
    fixture_hits: fixture.hits.filter((hit) => hit.includes("/ob01-"))
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
  const orceld = join(targetDir(), "debug", "orceld.exe");
  require_(existsSync(orceld) && existsSync(join(targetDir(), "debug", "orcel-browser-host.exe")), `orceld and the browser host are built in ${targetDir()}`);
  const paths = {
    root,
    orceld,
    workspace: join(root, "workspace"),
    brokerRoot: join(root, ".orcel", "browser-profile", "live", "broker"),
    consentLog: join(evidenceDir, "consent.jsonl")
  };
  mkdirSync(paths.workspace, { recursive: true });
  mkdirSync(evidenceDir, { recursive: true });
  const fixture = startFixture();
  let summary;
  try {
    const spki = await fixture.ready;
    summary = await mission(options, paths, spki, fixture);
    const ledger = join(root, ".orcel");
    summary.approval_ledger_files = existsSync(ledger) ? readdirSync(ledger) : [];
    if (options.consent === "scripted") {
      const prompts = readFileSync(paths.consentLog, "utf8").trim().split("\n").map((line) => JSON.parse(line)).filter((line) => line.event === "soft_prompt");
      require_(prompts.length === 4 && prompts.every((prompt) => prompt.decision === "approved"), `four scripted SOFT prompts, each approved: ${prompts.length}`);
      summary.scripted_prompts = prompts.map((prompt) => ({ action: prompt.action, target: prompt.target }));
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
