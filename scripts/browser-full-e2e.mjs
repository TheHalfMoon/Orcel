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
// browser_verify, browser_tabs close (the second tab), then
// browser_task_status and browser_close. Then: the provisional receipts chain is recomputed here,
// the session's folder (its profile) must be gone, no Edge of this run may
// be left, and orceld must end when the MCP session ends.
//
// SG-000135 OB-04 adds, natively:
//   - Shadow check on that mission (FA-E Shadow half, SH-1 short form): the
//     foreground window, cursor position and clipboard sequence number are
//     read (read-only Win32 calls) before browser_session_create and after
//     browser_close and must be unchanged, and no Edge window of this run is
//     visible while the session lives. If the person at the PC gave any
//     input meanwhile (GetLastInputInfo moved), the three comparisons are
//     recorded as inconclusive, never as passed.
//   - Persistent profiles across orceld restarts (FA-H): two Orcel-managed
//     profiles are created (owner-approved writes); a session on the first
//     receives a persistent cookie; the MCP session ends (orceld exits); a
//     new MCP session (a new orceld) refuses the old session id, and a new
//     session on the same profile still sends the cookie.
//   - Two concurrent sessions on different profiles (SH-8, FA-F): the
//     second profile has no cookie of the first, its own cookie never
//     reaches the first, and a second session on a held profile is refused.
//     Both profiles are then deleted (owner-approved writes).
//   - Visible mode: a session with mode visible opens a real headed Edge
//     window titled as an Orcel agent session; it must not take the
//     foreground (and, with no human input, the foreground is unchanged).
//     Nothing in this script sends keyboard or mouse input.
//
// Two consent modes, never mixed:
//   --consent scripted  TEST HARNESS. Builds orceld with the test-only
//                       `browser-full-scripted-consent` feature: the real
//                       approval broker and ledger, with the SOFT consent
//                       decided by the approval crate's existing test-support
//                       soft decider (approve only the mission's four action
//                       titles whose whole target is https://fixture.test;
//                       deny everything else) and every
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
/// tab's navigation (OB-03).
const APPROVED_ACTIONS = 5;
// Longer than the MCP edge's own 10-minute approval timeout, so a dialog that
// waits for a person ends as orceld's answer, not as this client giving up.
const CALL_TIMEOUT_MS = 11 * 60_000;
const RECEIPT_DOMAIN = "orcel-ob01-receipt/1";
/// SG-000135 OB-04: the harness's own profile names (the scripted consent
/// approves profile writes for `ob04-e2e-*` only).
const KEEP_PROFILE = "ob04-e2e-keep";
const OTHER_PROFILE = "ob04-e2e-other";
const VISIBLE_TITLE = "Orcel agent session";
const OB04_TOOLS = ["browser_profiles", "browser_profile_create", "browser_profile_delete"];
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
  const features = consent === "scripted" ? `${live},browser-full-scripted-consent` : live;
  run("cargo", ["build", "--locked", "-p", "orceld", "--features", features, "--bin", "orceld"], env);
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

/// SG-000135 OB-04: a read-only desktop probe. Reads the foreground window,
/// the cursor position, the clipboard sequence number and the last-input
/// tick, and lists the visible top-level windows (title and z-order) of the
/// given process ids only. It calls no API that changes anything.
const PROBE_CS = String.raw`
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class OrcelOb04Probe {
  [StructLayout(LayoutKind.Sequential)] public struct POINT { public int X; public int Y; }
  [StructLayout(LayoutKind.Sequential)] public struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
  public delegate bool EnumProc(IntPtr hwnd, IntPtr lparam);
  [DllImport("user32.dll")] static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] static extern bool GetCursorPos(out POINT point);
  [DllImport("user32.dll")] static extern uint GetClipboardSequenceNumber();
  [DllImport("user32.dll")] static extern bool GetLastInputInfo(ref LASTINPUTINFO info);
  [DllImport("user32.dll")] static extern bool EnumWindows(EnumProc proc, IntPtr lparam);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr hwnd);
  [DllImport("user32.dll")] static extern bool IsIconic(IntPtr hwnd);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int max);
  // JSON is built without backslash escapes in this source: quote and
  // backslash are written by their character codes.
  static readonly char Quote = (char)34;
  static readonly char Backslash = (char)92;
  static string Str(string value) {
    StringBuilder b = new StringBuilder();
    b.Append(Quote);
    foreach (char c in value) {
      if (c == Quote || c == Backslash) { b.Append(Backslash); b.Append(c); }
      else if (c < ' ') { b.Append(' '); }
      else { b.Append(c); }
    }
    b.Append(Quote);
    return b.ToString();
  }
  static string Key(string name) { return Str(name) + ":"; }
  public static string Probe(int[] pids) {
    IntPtr fg = GetForegroundWindow();
    uint fgPid;
    GetWindowThreadProcessId(fg, out fgPid);
    POINT cursor;
    GetCursorPos(out cursor);
    LASTINPUTINFO input = new LASTINPUTINFO();
    input.cbSize = (uint)Marshal.SizeOf(input);
    GetLastInputInfo(ref input);
    uint sequence = GetClipboardSequenceNumber();
    List<string> windows = new List<string>();
    int z = 0;
    int fgZ = -1;
    EnumWindows(delegate (IntPtr h, IntPtr l) {
      if (IsWindowVisible(h)) {
        if (h == fg) { fgZ = z; }
        uint pid;
        GetWindowThreadProcessId(h, out pid);
        if (Array.IndexOf(pids, (int)pid) >= 0) {
          StringBuilder title = new StringBuilder(512);
          GetWindowText(h, title, 512);
          windows.Add("{" + Key("hwnd") + h.ToInt64() + "," + Key("pid") + pid + "," + Key("z") + z + "," + Key("minimized") + (IsIconic(h) ? "true" : "false") + "," + Key("title") + Str(title.ToString()) + "}");
        }
        z++;
      }
      return true;
    }, IntPtr.Zero);
    return "{" + Key("foreground") + fg.ToInt64() + "," + Key("foreground_pid") + fgPid + "," + Key("foreground_z") + fgZ + "," + Key("cursor") + "[" + cursor.X + "," + cursor.Y + "]," + Key("clipboard_sequence") + sequence + "," + Key("last_input_tick") + input.dwTime + "," + Key("windows") + "[" + string.Join(",", windows.ToArray()) + "]}";
  }
}
`;

function desktopProbe(pids = []) {
  const list = pids.map((pid) => String(Number(pid) | 0)).join(",");
  const script = `Add-Type -TypeDefinition @'\n${PROBE_CS}\n'@\n[OrcelOb04Probe]::Probe([int[]]@(${list}))`;
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], { encoding: "utf8", windowsHide: true });
  require_(result.status === 0 && result.stdout.trim(), `the desktop probe ran: ${result.stderr}`);
  return JSON.parse(result.stdout.trim());
}

/// SG-000135 OB-04: compare two desktop probes. With no human input in
/// between, the foreground window, cursor and clipboard sequence must be
/// equal; with human input, the comparison is inconclusive (never passed).
function desktopUnchanged(before, after) {
  const human = before.last_input_tick !== after.last_input_tick;
  const facts = {
    human_input_during: human,
    foreground_unchanged: before.foreground === after.foreground,
    cursor_unchanged: before.cursor[0] === after.cursor[0] && before.cursor[1] === after.cursor[1],
    clipboard_unchanged: before.clipboard_sequence === after.clipboard_sequence
  };
  facts.verdict = human ? "inconclusive (the person gave input)" : facts.foreground_unchanged && facts.cursor_unchanged && facts.clipboard_unchanged ? "unchanged" : "CHANGED";
  return facts;
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
  const env = missionEnv(options, paths, fixtureSpki);
  const started = Date.now();
  return await runMission(options, paths, fixture, env, steps, record, expectOk, started);
}

/// The environment every MCP session of this run gets: the run's own state
/// root, the browser_full profile and the fixture's certificate.
function missionEnv(options, paths, fixtureSpki) {
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
  return env;
}

async function runMission(options, paths, fixture, env, steps, record, expectOk, started) {
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

  // SG-000135 OB-04: the desktop as the mission starts.
  const desktopBefore = desktopProbe();
  const create = await client.call("browser_session_create", { task: "OB-01 E2E fixture mission" });
  record(create);
  const created = expectOk(create, "browser_session_create");
  const session = created.session_id;
  require_(created.mode === "shadow" && created.no_interference === true && created.profile_mode === "ephemeral", `a session is Shadow and ephemeral by default: ${JSON.stringify(created)}`);
  if (options.consent === "scripted") {
    // The build must be the scripted-consent one: otherwise a real dialog
    // would appear with nobody to answer it. Checked before any approval.
    const log = existsSync(paths.consentLog) ? readFileSync(paths.consentLog, "utf8") : "";
    require_(log.includes("\"scripted_consent_started\""), "orceld is not the scripted-consent build (no consent log header); stopping before any approval");
  } else {
    process.stdout.write("OB01-E2E founder run: 5 Orcel approval dialogs follow (open, fill, select, click, open the second tab). Read each and answer it yourself.\n");
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
  // SG-000135 OB-04: a Shadow session shows no window at all.
  const shadowWindows = desktopProbe(edge.map((entry) => entry.ProcessId)).windows;
  require_(shadowWindows.length === 0, `a Shadow session has no visible window: ${JSON.stringify(shadowWindows)}`);

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
  const expectedActions = [
    "browser_open", "browser_snapshot", "browser_fill", "browser_select", "browser_verify", "browser_click", "browser_verify", "browser_extract",
    "browser_screenshot", "browser_tabs", "browser_tabs", "browser_screenshot", "browser_tabs", "browser_verify", "browser_tabs"
  ];
  require_(JSON.stringify(actions) === JSON.stringify(expectedActions), `the receipts are the mission's actions: ${actions.join(", ")}`);
  require_(state.last_receipt_sha256 === previous, "the chain head is the last receipt");
  const approved = receipts.filter((receipt) => receipt.record_id);
  require_(approved.length === APPROVED_ACTIONS, `five actions carry an approval record (open, fill, select, click, the new tab): ${approved.length}`);
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
  // SG-000135 OB-04: the desktop after the whole Shadow mission.
  const shadowDesktop = desktopUnchanged(desktopBefore, desktopProbe());
  process.stdout.write(`OB04-E2E shadow desktop: ${JSON.stringify(shadowDesktop)}\n`);
  require_(shadowDesktop.verdict !== "CHANGED", `the Shadow mission left the foreground window, cursor and clipboard as they were: ${JSON.stringify(shadowDesktop)}`);

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
    shadow_desktop: shadowDesktop,
    shadow_visible_windows: shadowWindows.length,
    fixture_hits: fixture.hits.filter((hit) => hit.includes("/ob01-"))
  };
}

/// SG-000135 OB-04: one MCP session (its own orceld) for the OB-04 phases.
async function openClient(env, label) {
  const client = new McpClient(process.execPath, [join(repo, "apps", "orcel-mcp", "dist", "entrypoints", "stdio.js")], env);
  activeClient = client;
  const init = await client.request("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: `orcel-ob04-e2e-${label}`, version: "1" }
  });
  require_(!init.error, `initialize: ${JSON.stringify(init.error)}`);
  client.send({ method: "notifications/initialized" });
  const listed = await client.request("tools/list", {});
  const tools = (listed.result?.tools ?? []).map((tool) => tool.name);
  for (const name of [...EXPECTED_TOOLS, ...OB04_TOOLS]) require_(tools.includes(name), `${name} is listed: ${tools.join(", ")}`);
  return client;
}

/// SG-000135 OB-04: persistent profiles across an orceld restart, two
/// concurrent sessions on different profiles, and a Visible session.
async function ob04Missions(options, paths, env) {
  const steps = [];
  let approvals = 0;
  const call = async (client, tool, args, approved = false) => {
    const step = await client.call(tool, args);
    steps.push({ tool, ok: step.ok, ms: step.ms });
    const outcome = step.ok ? "ok" : `refused ${step.body?.error?.code ?? "?"}`;
    process.stdout.write(`OB04-E2E step ${steps.length} ${tool}: ${outcome} in ${step.ms} ms\n`);
    if (approved && step.ok) approvals += 1;
    return step;
  };
  const ok = (step, what) => {
    require_(step.ok, `${what}: ${JSON.stringify(step.body)}`);
    return step.body.result;
  };
  const refused = (step, code, what) => {
    require_(!step.ok && step.body?.error?.code === code, `${what} is refused ${code}: ${JSON.stringify(step.body)}`);
  };
  /// Open `path` on the fixture and check the page shows `text`.
  const openAndSee = async (client, session, path, text) => {
    const opened = ok(await call(client, "browser_open", { session_id: session, url: `${FIXTURE}${path}` }, true), `browser_open ${path}`);
    const seen = ok(
      await call(client, "browser_verify", { session_id: session, expected_generation: opened.generation, checks: [{ kind: "text_visible", text }] }),
      `browser_verify ${path}`
    );
    return seen.verified === true;
  };
  const profilesRoot = join(paths.root, ".orcel", "browser-profile", "live", "named-profiles");
  if (options.consent === "founder") {
    process.stdout.write("OB04-E2E founder run: Orcel approval dialogs follow for two profile creations, seven page openings and two profile deletions. Read each and answer it yourself.\n");
  }

  // Phase 1 (FA-H, first orceld): two profiles; a cookie in the first.
  const first = await openClient(env, "first");
  const empty = ok(await call(first, "browser_profiles", {}), "browser_profiles");
  require_(Array.isArray(empty.profiles) && empty.profiles.length === 0, `no profile exists yet: ${JSON.stringify(empty)}`);
  ok(await call(first, "browser_profile_create", { name: KEEP_PROFILE }, true), "browser_profile_create keep");
  ok(await call(first, "browser_profile_create", { name: OTHER_PROFILE }, true), "browser_profile_create other");
  refused(await call(first, "browser_profile_create", { name: KEEP_PROFILE }), "INVALID_REQUEST", "a second profile of one name");
  refused(await call(first, "browser_session_create", { profile: "ob04-e2e-missing" }), "TARGET_STALE", "a session on a missing profile");
  const keepCreate = ok(await call(first, "browser_session_create", { task: "OB-04 keep", profile: KEEP_PROFILE }), "browser_session_create keep");
  require_(keepCreate.profile_mode === "persistent" && keepCreate.profile === KEEP_PROFILE && keepCreate.mode === "shadow", `the session holds the persistent profile: ${JSON.stringify(keepCreate)}`);
  const firstSession = keepCreate.session_id;
  require_(await openAndSee(first, firstSession, "/ob04-show", "OB-04 cookie is absent"), "a new profile has no cookie");
  require_(await openAndSee(first, firstSession, "/ob04-set-alpha", "OB-04 cookie set to alpha"), "the cookie is set");
  require_(await openAndSee(first, firstSession, "/ob04-show", "OB-04 cookie is alpha"), "the cookie is sent back in the same session");
  const edgeKeep = edgeProcessesUnder(paths.root).filter((entry) => !/--type=/.test(entry.CommandLine ?? ""));
  const keepData = join(profilesRoot, KEEP_PROFILE, "data").toLowerCase();
  require_(edgeKeep.length >= 1 && edgeKeep.every((entry) => (entry.CommandLine ?? "").toLowerCase().includes(keepData)) && edgeKeep.every((entry) => /--headless/.test(entry.CommandLine)), `Edge runs headless in the persistent profile's data folder: ${JSON.stringify(edgeKeep.map((entry) => entry.CommandLine))}`);
  const closedKeep = ok(await call(first, "browser_close", { session_id: firstSession }), "browser_close keep");
  require_(closedKeep.profile_kept === true && closedKeep.profile === KEEP_PROFILE && closedKeep.worker_ended === true, `the persistent profile is kept at close: ${JSON.stringify(closedKeep)}`);
  const listedFirst = ok(await call(first, "browser_profiles", {}), "browser_profiles after close");
  require_(listedFirst.profiles.map((profile) => profile.name).join(",") === `${KEEP_PROFILE},${OTHER_PROFILE}` && listedFirst.profiles.every((profile) => profile.in_use === false), `both profiles are listed, none in use: ${JSON.stringify(listedFirst)}`);
  const firstExit = await first.close();
  require_(edgeProcessesUnder(paths.root).length === 0, "no Edge is left after the first orceld");
  require_(existsSync(join(profilesRoot, KEEP_PROFILE, "data")), "the persistent profile's data folder outlives the orceld");

  // Phase 2 (a new orceld): the old id is refused; the cookie is kept;
  // two concurrent sessions on different profiles share nothing.
  const second = await openClient(env, "second");
  refused(await call(second, "browser_task_status", { session_id: firstSession }), "TARGET_STALE", "the earlier orceld's session id");
  const keepAgain = ok(await call(second, "browser_session_create", { task: "OB-04 keep again", profile: KEEP_PROFILE }), "browser_session_create keep again");
  const otherCreate = ok(await call(second, "browser_session_create", { task: "OB-04 other", profile: OTHER_PROFILE }), "browser_session_create other");
  const keepSession = keepAgain.session_id;
  const otherSession = otherCreate.session_id;
  const restartKept = await openAndSee(second, keepSession, "/ob04-show", "OB-04 cookie is alpha");
  require_(restartKept, "the cookie survived the orceld restart in its profile");
  require_(await openAndSee(second, otherSession, "/ob04-show", "OB-04 cookie is absent"), "the other profile has no cookie of the first");
  require_(await openAndSee(second, otherSession, "/ob04-set-beta", "OB-04 cookie set to beta"), "the other profile sets its own cookie");
  require_(await openAndSee(second, keepSession, "/ob04-show", "OB-04 cookie is alpha"), "the other profile's cookie never reaches the first");
  const edgeBoth = edgeProcessesUnder(paths.root).filter((entry) => !/--type=/.test(entry.CommandLine ?? ""));
  const otherData = join(profilesRoot, OTHER_PROFILE, "data").toLowerCase();
  const isolation = {
    browser_processes: edgeBoth.length,
    keep_profile_processes: edgeBoth.filter((entry) => (entry.CommandLine ?? "").toLowerCase().includes(keepData)).length,
    other_profile_processes: edgeBoth.filter((entry) => (entry.CommandLine ?? "").toLowerCase().includes(otherData)).length
  };
  require_(isolation.keep_profile_processes === 1 && isolation.other_profile_processes === 1, `each session runs its own Edge in its own profile: ${JSON.stringify(isolation)}`);
  const status = ok(await call(second, "browser_task_status", { session_id: otherSession }), "browser_task_status other");
  require_(status.profile === OTHER_PROFILE && status.profile_mode === "persistent", `the status names the profile: ${JSON.stringify({ profile: status.profile, profile_mode: status.profile_mode })}`);
  refused(await call(second, "browser_profile_delete", { name: KEEP_PROFILE }), "TARGET_STALE", "deleting a profile a session holds");
  ok(await call(second, "browser_close", { session_id: otherSession }), "browser_close other");
  refused(await call(second, "browser_session_create", { profile: KEEP_PROFILE }), "TARGET_STALE", "a second live session on one profile");
  ok(await call(second, "browser_close", { session_id: keepSession }), "browser_close keep again");
  ok(await call(second, "browser_profile_delete", { name: OTHER_PROFILE }, true), "browser_profile_delete other");
  ok(await call(second, "browser_profile_delete", { name: KEEP_PROFILE }, true), "browser_profile_delete keep");
  const listedAfter = ok(await call(second, "browser_profiles", {}), "browser_profiles after delete");
  require_(listedAfter.profiles.length === 0, `both profiles are gone: ${JSON.stringify(listedAfter)}`);
  require_(!existsSync(join(profilesRoot, KEEP_PROFILE)) && !existsSync(join(profilesRoot, OTHER_PROFILE)), "the profile folders are removed");
  const secondExit = await second.close();
  require_(edgeProcessesUnder(paths.root).length === 0, "no Edge is left after the second orceld");

  // Phase 3: a Visible session opens a real headed window of its own.
  const third = await openClient(env, "visible");
  const visibleBefore = desktopProbe();
  const visibleCreate = ok(await call(third, "browser_session_create", { task: "OB-04 visible", mode: "visible" }), "browser_session_create visible");
  require_(visibleCreate.mode === "visible" && visibleCreate.no_interference === false, `a Visible session never claims no-interference: ${JSON.stringify(visibleCreate)}`);
  const visibleSession = visibleCreate.session_id;
  require_(await openAndSee(third, visibleSession, "/ob01-form", "Orcel Browser mission"), "the Visible session opens the fixture form");
  const edgeVisible = edgeProcessesUnder(paths.root);
  const edgeVisibleMain = edgeVisible.filter((entry) => !/--type=/.test(entry.CommandLine ?? ""));
  const visibleProbe = desktopProbe(edgeVisible.map((entry) => entry.ProcessId));
  const named = visibleProbe.windows.filter((window) => window.title.includes(VISIBLE_TITLE));
  const visible = {
    browser_processes: edgeVisibleMain.length,
    headed: edgeVisibleMain.length > 0 && edgeVisibleMain.every((entry) => !/--headless/.test(entry.CommandLine ?? "")),
    window_name_flag: edgeVisibleMain.length > 0 && edgeVisibleMain.every((entry) => (entry.CommandLine ?? "").includes(`--window-name=${VISIBLE_TITLE}`) || (entry.CommandLine ?? "").includes(`"--window-name=${VISIBLE_TITLE}"`)),
    pipe: edgeVisibleMain.length > 0 && edgeVisibleMain.every((entry) => /--remote-debugging-pipe/.test(entry.CommandLine ?? "")),
    remote_debugging_port: edgeVisible.some((entry) => /--remote-debugging-port/.test(entry.CommandLine ?? "")),
    windows: visibleProbe.windows,
    titled_windows: named.length,
    took_foreground: visibleProbe.windows.some((window) => window.hwnd === visibleProbe.foreground),
    above_foreground: visibleProbe.foreground_z >= 0 && visibleProbe.windows.some((window) => window.z < visibleProbe.foreground_z),
    desktop: desktopUnchanged(visibleBefore, visibleProbe)
  };
  process.stdout.write(`OB04-E2E visible session: ${JSON.stringify(visible)}\n`);
  require_(visible.headed && visible.pipe && !visible.remote_debugging_port, "the Visible Edge is headed, pipe-driven, with no remote debugging port");
  require_(visible.titled_windows >= 1, `the Visible session has a window titled ${VISIBLE_TITLE}`);
  require_(!visible.took_foreground, "the Visible window did not take the foreground");
  require_(visible.desktop.verdict !== "CHANGED" || (visible.desktop.foreground_unchanged && visible.desktop.cursor_unchanged), `the Visible session left the foreground and cursor as they were: ${JSON.stringify(visible.desktop)}`);
  ok(await call(third, "browser_close", { session_id: visibleSession }), "browser_close visible");
  const thirdExit = await third.close();
  const windowsLeft = desktopProbe(edgeVisible.map((entry) => entry.ProcessId)).windows.length;
  require_(windowsLeft === 0 && edgeProcessesUnder(paths.root).length === 0, "the Visible window and its Edge are gone after close");
  return {
    steps,
    approvals,
    restart_kept_cookie: restartKept,
    isolation,
    visible,
    mcp_exit_codes: [firstExit, secondExit, thirdExit]
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
    consentLog: join(evidenceDir, "consent.jsonl")
  };
  mkdirSync(paths.workspace, { recursive: true });
  mkdirSync(evidenceDir, { recursive: true });
  const fixture = startFixture();
  let summary;
  try {
    const spki = await fixture.ready;
    summary = await mission(options, paths, spki, fixture);
    summary.ob04 = await ob04Missions(options, paths, missionEnv(options, paths, spki));
    const ledger = join(root, ".orcel");
    summary.approval_ledger_files = existsSync(ledger) ? readdirSync(ledger) : [];
    if (options.consent === "scripted") {
      const prompts = readFileSync(paths.consentLog, "utf8").trim().split("\n").map((line) => JSON.parse(line)).filter((line) => line.event === "soft_prompt");
      const expectedPrompts = APPROVED_ACTIONS + summary.ob04.approvals;
      require_(prompts.length === expectedPrompts && prompts.every((prompt) => prompt.decision === "approved"), `${expectedPrompts} scripted SOFT prompts, each approved: ${prompts.length}`);
      summary.scripted_prompts = prompts.map((prompt) => ({ action: prompt.action, target: prompt.target }));
    }
    writeFileSync(join(evidenceDir, "summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
    const steps = summary.steps.map((step) => `${step.tool}=${step.ok ? "ok" : "refused"}/${step.ms}ms`).join(" ");
    const ob04 = summary.ob04;
    process.stdout.write(
      `OB04-E2E-EVIDENCE ${options.consent} consent: shadow desktop ${summary.shadow_desktop.verdict}, ${summary.shadow_visible_windows} Shadow windows; ` +
        `cookie kept across orceld restart ${ob04.restart_kept_cookie}; isolation ${JSON.stringify(ob04.isolation)}; ` +
        `visible: ${ob04.visible.titled_windows} titled window(s), took foreground ${ob04.visible.took_foreground}, above foreground ${ob04.visible.above_foreground}, desktop ${ob04.visible.desktop.verdict}; ` +
        `${ob04.approvals} OB-04 approvals, MCP exits ${ob04.mcp_exit_codes.join("/")}\n`
    );
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
