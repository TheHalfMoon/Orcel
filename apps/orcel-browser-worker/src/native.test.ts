// SG-000108 native confinement probes against the installed Edge.
//
// These run the real engine with the exact confinement argv (the shape that
// crates/orcel-browser-host/src/confinement.rs builds and that launchRefusal
// accepts). Layers 1 (resolver pinning) and 2 (no-route proxy) are probed
// with no policy route at all, as the decision record requires. On Windows a
// missing engine fails the suite; elsewhere the suite is skipped because only
// Windows results count as evidence. Fixtures are owned local servers, and
// each probe that could pass vacuously has a positive control.

import assert from "node:assert/strict";
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createSocket } from "node:dgram";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer as createHttpServer, type Server } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { createServer as createTcpServer, connect, type Server as TcpServer } from "node:net";
import { networkInterfaces, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { chromium, type BrowserContext } from "playwright-core";
import { splitWindowsCommandLine } from "./cmdline.js";
import { installRoutes } from "./routes.js";
import { originOf, type RouteQuery } from "./routing.js";
import { denyServiceWorkerScripts } from "./service-workers.js";
import { encodeFrame, FrameDecoder, launchRefusal, type HostFrame, type WorkerFrame } from "./protocol.js";

const EDGE_CANDIDATES = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
];
const isWindows = process.platform === "win32";
const engine = EDGE_CANDIDATES.find((path) => existsSync(path));
const skip = isWindows ? false : "native probes are Windows-only evidence";
const WORKER_MAIN = join(dirname(fileURLToPath(import.meta.url)), "main.js");
const FIXTURE_PORT = 443;
const WEBRTC_POLICY = "--webrtc-ip-handling-policy=disable_non_proxied_udp";

const FROZEN = [
  "--headless",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-extensions",
  "--disable-background-networking",
  "--disable-sync",
  "--no-service-autorun"
];

interface Destination {
  host: string;
  pin: string;
}

/// The confinement argv, built exactly as confinement.rs builds it.
function confinedArgv(profile: string, destinations: Destination[]): string[] {
  const rules = destinations
    .map(({ host, pin }) => `MAP ${host} ${pin.includes(":") ? `[${pin}]` : pin}:${FIXTURE_PORT}`)
    .concat("MAP * ~NOTFOUND")
    .join(", ");
  const bypass = [...destinations.map((d) => d.host), "<-loopback>"].join(";");
  return [
    ...FROZEN,
    `--user-data-dir=${profile}`,
    "--remote-debugging-pipe",
    `--host-resolver-rules=${rules}`,
    "--proxy-server=http://0.0.0.0:9",
    `--proxy-bypass-list=${bypass}`,
    WEBRTC_POLICY,
    "--disable-quic",
    "--disable-blink-features=SharedWorker",
    "--disable-features=MediaRouter,DialMediaRouteProvider,CastMediaRouteProvider,msImplicitSignin,msEdgeOSAccountInfoSubstrate,msEdgeOnlineAccounts,msOneAuthWAM,msLoadOneAuthInBackground,msIdentityCore,WebRtcHideLocalIpsWithMdns",
    "about:blank"
  ];
}

const FIXTURE: Destination[] = [{ host: "fixture.test", pin: "127.0.0.1" }];
const TWO_SITES: Destination[] = [...FIXTURE, { host: "other.test", pin: "127.0.0.1" }];

/// Per-test cleanup that runs last-in, first-out and always runs every step
/// (node:test runs `t.after` hooks in registration order and a failing hook
/// skips the rest, which would leave an engine or a server alive). The test
/// body's own failure takes precedence over a cleanup failure.
class Cleanup {
  private readonly steps: Array<() => unknown> = [];

  after(step: () => unknown): void {
    this.steps.push(step);
  }

  async run(): Promise<void> {
    let first: unknown = null;
    for (const step of this.steps.reverse()) {
      try {
        await step();
      } catch (error) {
        first ??= error;
      }
    }
    if (first !== null) throw first;
  }
}

function nativeTest(name: string, body: (t: Cleanup) => Promise<void>, todo?: string): void {
  // A hang guard above every event wait a test makes (#374).
  test(name, { skip, todo, timeout: 300_000 }, async () => {
    const cleanup = new Cleanup();
    let failure: unknown = null;
    try {
      await body(cleanup);
    } catch (error) {
      failure = error;
    }
    try {
      await cleanup.run();
    } catch (error) {
      failure ??= error;
    }
    if (failure !== null) throw failure;
  });
}

function requireEngine(): string {
  assert.ok(engine, `no Edge engine found at ${EDGE_CANDIDATES.join(" or ")}`);
  return engine;
}

function cleanEnv(): { SystemRoot: string; SystemDrive: string; PATH: string; TEMP: string; TMP: string } {
  const root = process.env.SystemRoot ?? "C:\\Windows";
  return {
    SystemRoot: root,
    SystemDrive: process.env.SystemDrive ?? "C:",
    PATH: `${root}\\System32`,
    TEMP: process.env.TEMP ?? `${root}\\Temp`,
    TMP: process.env.TMP ?? `${root}\\Temp`
  };
}

function launchFrame(profile: string, destinations: Destination[]): Extract<HostFrame, { frame: "launch" }> {
  const env = cleanEnv();
  const frame = {
    frame: "launch" as const,
    engine: requireEngine(),
    profile_dir: profile,
    argv: confinedArgv(profile, destinations),
    env: { SystemRoot: env.SystemRoot, PATH: env.PATH, TEMP: env.TEMP }
  };
  assert.equal(launchRefusal(frame), null, "the probe argv must satisfy the worker contract");
  return frame;
}

/// Command lines of engine processes using `profile` (every engine child
/// carries --user-data-dir with the profile). A failing query throws instead
/// of reporting "no processes".
function engineCommandLines(profile: string): string[] {
  const leaf = profile.split("\\").pop() ?? profile;
  const out = execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `$ErrorActionPreference='Stop'; Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like '*${leaf}*' } | ForEach-Object { $_.CommandLine }`
    ],
    { encoding: "utf8" }
  );
  return out.split(/\r?\n/).filter((line) => line.trim().length > 0);
}

/// #374: how long a test waits for an event before it fails. A hang guard
/// only: the waits return as soon as their event happens, so a loaded
/// runner can be slow without failing, and an event that never comes still
/// fails the test.
const EVENT_DEADLINE_MS = 90_000;

/// Whether every engine process using `profile` has exited: a query for
/// them, a wait on those processes themselves (Wait-Process waits on their
/// handles), and again for any that appeared meanwhile, until none remain or
/// the deadline passes. Not a fixed-interval loop of process queries, each of
/// which costs seconds on a loaded runner.
function engineExited(profile: string, timeoutMs: number = EVENT_DEADLINE_MS): boolean {
  const leaf = profile.split("\\").pop() ?? profile;
  const seconds = Math.max(1, Math.ceil(timeoutMs / 1000));
  const out = execFileSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      `$ErrorActionPreference='Stop'; $q = { @(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | Where-Object { $_.CommandLine -like '*${leaf}*' }) }; $deadline = (Get-Date).AddSeconds(${seconds}); $p = & $q; while ($p.Count -gt 0 -and (Get-Date) -lt $deadline) { $left = [Math]::Max(1, [int]($deadline - (Get-Date)).TotalSeconds); Wait-Process -Id $p.ProcessId -Timeout $left -ErrorAction SilentlyContinue; $p = & $q }; $p.Count`
    ],
    { encoding: "utf8", timeout: timeoutMs + 60_000 }
  );
  const count = out.trim();
  assert.match(count, /^\d+$/, `engine process query answered ${JSON.stringify(count)}`);
  return Number(count) === 0;
}

async function waitFor(condition: () => boolean, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (condition()) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  return condition();
}

/// A fresh profile removed only after every engine process using it is gone,
/// so cleanup never replaces the real failure with a locked-file error.
function profileFor(t: Cleanup, label: string): string {
  const profile = mkdtempSync(join(tmpdir(), `sg108-${label}-`));
  t.after(async () => {
    engineExited(profile);
    rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 250 });
  });
  return profile;
}

class WorkerProcess {
  readonly child: ChildProcess;
  readonly replies: WorkerFrame[] = [];
  private readonly decoder = new FrameDecoder();
  private waiters: Array<() => void> = [];
  readonly exited: Promise<number | null>;

  constructor(t: Cleanup, nodeFlags: string[] = ["--disable-sigusr1"]) {
    this.child = spawn(process.execPath, [...nodeFlags, WORKER_MAIN], { env: cleanEnv(), stdio: ["pipe", "pipe", "pipe"] });
    this.child.stdout?.on("data", (chunk: Buffer) => {
      for (const frame of this.decoder.push(chunk)) this.replies.push(frame as WorkerFrame);
      for (const waiter of this.waiters.splice(0)) waiter();
    });
    this.child.stderr?.resume();
    this.exited = new Promise((resolve) => this.child.on("exit", (code) => resolve(code)));
    t.after(() => this.stop());
  }

  send(frame: HostFrame): void {
    this.child.stdin?.write(encodeFrame(frame));
  }

  async reply(count: number, timeoutMs = 45_000): Promise<WorkerFrame> {
    const deadline = Date.now() + timeoutMs;
    while (this.replies.length < count) {
      assert.ok(Date.now() < deadline, `timed out waiting for reply ${count}: ${JSON.stringify(this.replies)}`);
      await new Promise<void>((resolve) => {
        this.waiters.push(resolve);
        setTimeout(resolve, 500);
      });
    }
    return this.replies[count - 1] as WorkerFrame;
  }

  async stop(): Promise<void> {
    if (this.child.exitCode === null && this.child.signalCode === null) this.child.kill();
    await this.exited;
  }
}

function listen(t: Cleanup, server: Server | TcpServer, port: number, host: string): Promise<void> {
  // Track sockets so teardown never waits on a keep-alive connection held by
  // an engine that is closed later in the same teardown.
  const sockets = new Set<import("node:net").Socket>();
  server.on("connection", (socket: import("node:net").Socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  t.after(
    () =>
      new Promise<void>((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      })
  );
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port, host, ipv6Only: host === "::" }, () => resolve());
  });
}

async function launchDirect(
  t: Cleanup,
  profile: string,
  args: string[],
  options: { serviceWorkers?: "allow" | "block" } = {}
): Promise<BrowserContext> {
  const context = await chromium.launchPersistentContext(profile, {
    executablePath: requireEngine(),
    ignoreDefaultArgs: true,
    args,
    env: cleanEnv(),
    headless: true,
    timeout: 30_000,
    ...options
  });
  t.after(() => context.close());
  return context;
}

nativeTest("the worker drives the installed engine with exactly the host argv and leaves nothing behind", async (t) => {
  const profile = profileFor(t, "native");
  const worker = new WorkerProcess(t);
  worker.send({ frame: "hello", generation: 12 });
  assert.deepEqual(await worker.reply(1), { frame: "hello", generation: 12, worker: "orcel-browser-worker" });
  const launch = launchFrame(profile, FIXTURE);
  worker.send(launch);
  assert.deepEqual(await worker.reply(2), { frame: "launched" });

  const lines = engineCommandLines(profile);
  const browsers = lines.filter((line) => !line.includes("--type="));
  assert.equal(browsers.length, 1, `exactly one browser process: ${JSON.stringify(browsers)}`);
  assert.deepEqual(splitWindowsCommandLine(browsers[0] ?? ""), [launch.engine, ...launch.argv]);
  for (const line of lines) {
    for (const forbidden of ["--remote-debugging-port", "--remote-debugging-address", "--enable-automation"]) {
      assert.equal(line.includes(forbidden), false, `${forbidden} in ${line}`);
    }
  }
  worker.send({ frame: "ping", nonce: "native" });
  assert.deepEqual(await worker.reply(3), { frame: "pong", nonce: "native" });
  worker.send({ frame: "shutdown" });
  assert.deepEqual(await worker.reply(4), { frame: "bye" });
  assert.equal(await worker.exited, 0);
  assert.ok(engineExited(profile), "engine processes remain after shutdown");
});

nativeTest("killing the worker takes the engine down with its pipe", async (t) => {
  const profile = profileFor(t, "native-kill");
  const worker = new WorkerProcess(t);
  worker.send({ frame: "hello", generation: 12 });
  await worker.reply(1);
  worker.send(launchFrame(profile, FIXTURE));
  assert.deepEqual(await worker.reply(2), { frame: "launched" });
  assert.ok(engineCommandLines(profile).length > 0, "the engine is running before the kill");
  worker.child.kill("SIGKILL");
  await worker.exited;
  // The host's kill-on-close Job Object (slice 2b-ii) is the guarantee;
  // this proves the engine also exits on its own when the pipe closes.
  assert.ok(engineExited(profile), "engine survived the worker");
});

nativeTest("resolver pinning and the no-route proxy confine traffic without any policy route", async (t) => {
  const hits: string[] = [];
  const fixture = createHttpServer((request, response) => {
    hits.push(`${request.headers.host ?? ""}${request.url ?? ""}`);
    response.setHeader("content-type", "text/html");
    response.end("<p>fixture</p>");
  });
  await listen(t, fixture, FIXTURE_PORT, "127.0.0.1");
  const accepts: Record<string, number> = {};
  for (const host of ["0.0.0.0", "127.0.0.1", "::"]) {
    const trap = createTcpServer((socket) => {
      accepts[host] = (accepts[host] ?? 0) + 1;
      socket.destroy();
    });
    await listen(t, trap, 9, host);
    accepts[host] = 0;
  }
  const profile = profileFor(t, "native-net");
  const context = await launchDirect(t, profile, confinedArgv(profile, FIXTURE));
  const open = async (url: string): Promise<string> => {
    const page = await context.newPage();
    try {
      const response = await page.goto(url, { timeout: 10_000, waitUntil: "commit" });
      return `ok ${response?.status() ?? 0}`;
    } catch (error) {
      return `fail ${String((error as Error).message).split("\n")[0]}`;
    } finally {
      await page.close();
    }
  };
  assert.match(await open("http://fixture.test/admitted"), /^ok 200/);
  // Another port of the admitted name lands on the pinned port.
  assert.match(await open("http://fixture.test:8080/other-port"), /^ok 200/);
  // Every other destination is refused by the no-route proxy (layer 2), and
  // nothing reaches the fixture or a port-9 listener.
  for (const url of [
    "http://unmapped.test/",
    "http://example.com/",
    "http://127.0.0.1/",
    `http://127.0.0.1:${FIXTURE_PORT}/literal`,
    "http://[::1]/",
    "http://10.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[fd00:ec2::254]/"
  ]) {
    assert.match(await open(url), /^fail .*net::ERR_PROXY_CONNECTION_FAILED/, url);
  }
  assert.deepEqual(accepts, { "0.0.0.0": 0, "127.0.0.1": 0, "::": 0 }, "nothing reached a port-9 listener");
  assert.deepEqual(
    hits.filter((hit) => !hit.endsWith("/favicon.ico")),
    ["fixture.test/admitted", "fixture.test:8080/other-port"]
  );
});

nativeTest("WebRTC sends no UDP and opens no TURN connection, and the probe detects both without the policy", async (t) => {
  const lan = Object.values(networkInterfaces())
    .flat()
    .find((address) => address && address.family === "IPv4" && !address.internal)?.address;
  assert.ok(lan, "a non-loopback IPv4 address is required for the LAN STUN case");
  // One STUN trap per target address, so the control proves each target is
  // individually observable.
  const packets: Record<"loopback" | "lan", number> = { loopback: 0, lan: 0 };
  const trap = async (key: "loopback" | "lan", address: string): Promise<number> => {
    const socket = createSocket("udp4");
    socket.on("message", () => packets[key]++);
    await new Promise<void>((resolve) => socket.bind(0, address, () => resolve()));
    t.after(() => new Promise<void>((resolve) => socket.close(() => resolve())));
    return (socket.address() as { port: number }).port;
  };
  const loopbackPort = await trap("loopback", "127.0.0.1");
  const lanPort = await trap("lan", lan);
  let tcpConnections = 0;
  const fixture = createHttpServer((_request, response) => response.end("<p>fixture</p>"));
  fixture.on("connection", () => tcpConnections++);
  await listen(t, fixture, FIXTURE_PORT, "127.0.0.1");
  const servers = [`stun:127.0.0.1:${loopbackPort}`, `stun:${lan}:${lanPort}`, `turn:127.0.0.1:${FIXTURE_PORT}?transport=tcp`];

  const gather = async (label: string, adjust: (arg: string) => string) => {
    const profile = profileFor(t, `native-rtc-${label}`);
    const context = await launchDirect(t, profile, confinedArgv(profile, FIXTURE).map(adjust));
    const page = await context.newPage();
    await page.goto("http://fixture.test/", { waitUntil: "commit" });
    packets.loopback = 0;
    packets.lan = 0;
    const tcpBefore = tcpConnections;
    const candidates = await page.evaluate(async (urls: string[]) => {
      const types: string[] = [];
      for (const url of urls) {
        const server = url.startsWith("turn:") ? { urls: url, username: "u", credential: "c" } : { urls: url };
        const connection = new RTCPeerConnection({ iceServers: [server] });
        connection.createDataChannel("probe");
        connection.onicecandidate = (event) => {
          if (event.candidate) types.push(event.candidate.type ?? "unknown");
        };
        await connection.setLocalDescription(await connection.createOffer());
        // Wait for gathering to finish (bounded), not a fixed sleep.
        await new Promise<void>((resolve) => {
          const done = () => connection.iceGatheringState === "complete" && resolve();
          connection.onicegatheringstatechange = done;
          done();
          setTimeout(resolve, 8000);
        });
        await new Promise((resolve) => setTimeout(resolve, 300));
        connection.close();
      }
      return types;
    }, servers);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const result = { candidates, packets: { ...packets }, tcp: tcpConnections - tcpBefore };
    await context.close();
    return result;
  };

  const confined = await gather("confined", (arg) => arg);
  assert.deepEqual(confined, { candidates: [], packets: { loopback: 0, lan: 0 }, tcp: 0 }, "WebRTC must gather nothing and send nothing");
  // Positive control: the same probe with the default WebRTC policy (outside
  // the contract) does gather candidates and reach the STUN listener, so the
  // empty result above is not an artifact of headless Edge or the timing.
  const control = await gather("control", (arg) => (arg === WEBRTC_POLICY ? "--webrtc-ip-handling-policy=default" : arg));
  assert.ok(
    control.candidates.length > 0 && control.packets.loopback > 0 && control.packets.lan > 0,
    `control did not reach both STUN traps: ${JSON.stringify(control)}`
  );
});

nativeTest("a same-user process cannot activate the worker's inspector when it runs with --disable-sigusr1", async (t) => {
  const listening = (port: number) =>
    new Promise<boolean>((resolve) => {
      const socket = connect({ host: "127.0.0.1", port }, () => {
        socket.destroy();
        resolve(true);
      });
      socket.on("error", () => resolve(false));
    });
  const debugProcess = (process as unknown as { _debugProcess?: (pid: number) => void })._debugProcess;
  assert.equal(typeof debugProcess, "function", "process._debugProcess is required for this probe");
  const attempt = async (flags: string[]) => {
    const worker = new WorkerProcess(t, flags);
    // The worker is fully started once it answers hello.
    worker.send({ frame: "hello", generation: 12 });
    await worker.reply(1);
    const before = await listening(9229);
    let threw = false;
    try {
      debugProcess?.(worker.child.pid ?? 0);
    } catch {
      threw = true;
    }
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const after = await listening(9229);
    await worker.stop();
    return { before, threw, after };
  };
  const guarded = await attempt(["--disable-sigusr1"]);
  assert.deepEqual(guarded, { before: false, threw: true, after: false }, "activation must be refused with no listener");
  // Negative control: the worker refuses to start without the flag, so the
  // control activates a plain Node process instead.
  const plain = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { env: cleanEnv(), stdio: "ignore" });
  t.after(() => plain.kill());
  await new Promise((resolve) => setTimeout(resolve, 750));
  const controlBefore = await listening(9229);
  debugProcess?.(plain.pid ?? 0);
  // #374: until the activated inspector listens (the positive control), not
  // a fixed time.
  const controlDeadline = Date.now() + EVENT_DEADLINE_MS;
  let controlAfter = await listening(9229);
  while (!controlAfter && Date.now() < controlDeadline) {
    await new Promise((resolve) => setTimeout(resolve, 100));
    controlAfter = await listening(9229);
  }
  assert.deepEqual({ before: controlBefore, after: controlAfter }, { before: false, after: true }, "the probe detects an activated inspector");
});

// ---------------------------------------------------------------------------
// HTTPS fixture probes (slice 2b-ii-b). QUIC, WebTransport and the
// service-worker block need a secure context, so the fixture origin is served
// over TLS with a throwaway certificate that only these direct test launches
// trust (--ignore-certificate-errors-spki-list). The production argv carries
// no certificate flag.

interface TlsFixture {
  key: Buffer;
  cert: Buffer;
  spki: string;
}

/// A fresh self-signed certificate for fixture.test, made with the OpenSSL
/// that ships with Git for Windows (present on GitHub's Windows runners).
function tlsFixture(t: Cleanup): TlsFixture {
  const candidates = ["C:\\Program Files\\Git\\usr\\bin\\openssl.exe", "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe"];
  const openssl = candidates.find((path) => existsSync(path));
  assert.ok(openssl, "OpenSSL (Git for Windows) is required for the HTTPS fixture");
  const dir = mkdtempSync(join(tmpdir(), "sg108-tls-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  execFileSync(
    openssl,
    [
      "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
      "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"), "-days", "2",
      "-subj", "/CN=fixture.test", "-addext", "subjectAltName=DNS:fixture.test,DNS:other.test"
    ],
    { stdio: "ignore" }
  );
  const cert = readFileSync(join(dir, "cert.pem"));
  const der = new X509Certificate(cert).publicKey.export({ type: "spki", format: "der" });
  return { key: readFileSync(join(dir, "key.pem")), cert, spki: createHash("sha256").update(der).digest("base64") };
}

const SERVICE_WORKER_PAGE = `<!doctype html><body><script>
(async () => {
  const results = [];
  try { await navigator.serviceWorker.register("/sw-direct.js"); results.push("direct:ok"); }
  catch (error) { results.push("direct:" + error.name); }
  try { await ServiceWorkerContainer.prototype.register.call(navigator.serviceWorker, "/sw-proto.js"); results.push("proto:ok"); }
  catch (error) { results.push("proto:" + error.name); }
  document.title = results.join(" ");
})();
</script></body>`;

/// The HTTPS fixture on 127.0.0.1:443 (advertising HTTP/3) and UDP listeners
/// on 127.0.0.1:443 (the admitted name's pinned address) and 127.0.0.1:4433
/// (reachable only as an IP literal) that count every datagram.
async function httpsFixture(
  t: Cleanup,
  tls: TlsFixture
): Promise<{ hits: string[]; admittedUdp: () => number; literalUdp: () => number }> {
  const hits: string[] = [];
  const server = createHttpsServer({ key: tls.key, cert: tls.cert }, (request, response) => {
    const url = request.url ?? "";
    hits.push(`${(request.headers.host ?? "").split(":")[0]}${url}`);
    response.setHeader("alt-svc", 'h3=":443"; ma=86400');
    if (url.endsWith(".js")) {
      response.setHeader("content-type", "text/javascript");
      response.end("self.addEventListener('fetch', () => {});");
      return;
    }
    response.setHeader("content-type", "text/html");
    const pages: Record<string, string> = {
      "/sw": SERVICE_WORKER_PAGE,
      "/sw-cross": `<!doctype html><body><iframe src="https://other.test/sw"></iframe></body>`
    };
    response.end(pages[url] ?? "<p>secure fixture</p>");
  });
  await listen(t, server, FIXTURE_PORT, "127.0.0.1");
  const counts = new Map<number, number>();
  const socketErrors: Error[] = [];
  for (const port of [FIXTURE_PORT, 4433]) {
    counts.set(port, 0);
    const udp = createSocket("udp4");
    t.after(
      () =>
        new Promise<void>((resolve) => {
          try {
            udp.close(() => resolve());
          } catch {
            resolve(); // never bound, or already closed
          }
        })
    );
    udp.on("message", () => counts.set(port, (counts.get(port) ?? 0) + 1));
    await new Promise<void>((resolve, reject) => {
      udp.once("error", reject);
      udp.bind(port, "127.0.0.1", () => {
        udp.off("error", reject);
        udp.on("error", (error) => socketErrors.push(error));
        resolve();
      });
    });
  }
  t.after(() => assert.deepEqual(socketErrors, [], "a UDP listener failed"));
  return { hits, admittedUdp: () => counts.get(FIXTURE_PORT) ?? 0, literalUdp: () => counts.get(4433) ?? 0 };
}

/// Running web service workers by URL. Edge's built-in component extension
/// runs its own (chrome-extension://) service worker even with
/// --disable-extensions; that is not a page registration and is excluded.
/// URLs (not Worker objects) keep a failing assertion's diff small.
function webServiceWorkers(context: BrowserContext): string[] {
  return context
    .serviceWorkers()
    .map((worker) => worker.url())
    .filter((url) => url.startsWith("http"));
}

/// Try a WebTransport session from an open page; the outcome name only.
async function tryWebTransport(context: BrowserContext, url: string): Promise<string> {
  const page = await context.newPage();
  try {
    await page.goto("https://fixture.test/", { timeout: EVENT_DEADLINE_MS });
    return await page.evaluate(async (target) => {
      try {
        const transport = new WebTransport(target);
        await Promise.race([
          transport.ready,
          new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), 4_000))
        ]);
        return "open";
      } catch (error) {
        return (error as Error).name;
      }
    }, url);
  } finally {
    await page.close();
  }
}

function confinedHttpsArgv(profile: string, spki: string): string[] {
  return [...confinedArgv(profile, FIXTURE).slice(0, -1), `--ignore-certificate-errors-spki-list=${spki}`, "about:blank"];
}

nativeTest("over HTTPS the confined engine sends no Alt-Svc QUIC and no WebTransport to IP literals; the control does", async (t) => {
  const tls = tlsFixture(t);
  const fixture = await httpsFixture(t, tls);

  const profile = profileFor(t, "native-https");
  const context = await launchDirect(t, profile, confinedHttpsArgv(profile, tls.spki));
  // Two navigations: the first learns the h3 Alt-Svc advertisement, the
  // second would use HTTP/3 if --disable-quic did not hold.
  for (const path of ["/first", "/second"]) {
    const page = await context.newPage();
    const response = await page.goto(`https://fixture.test${path}`, { timeout: EVENT_DEADLINE_MS });
    assert.equal(response?.status(), 200, path);
    await page.close();
  }
  await new Promise((resolve) => setTimeout(resolve, 700));
  assert.equal(fixture.admittedUdp(), 0, "Alt-Svc upgraded the confined engine to QUIC");
  // An IP literal is refused by the no-route proxy. The outcome must be a
  // WebTransport failure: a missing API would make the zero count vacuous.
  assert.equal(await tryWebTransport(context, "https://127.0.0.1:4433/x"), "WebTransportError");
  await new Promise((resolve) => setTimeout(resolve, 700));
  assert.equal(fixture.literalUdp(), 0, "WebTransport reached an IP literal under confinement");

  // Positive control: without the confinement flags (no proxy, QUIC on), the
  // same WebTransport attempt sends UDP to the literal, so the probe detects it.
  const controlProfile = profileFor(t, "native-https-control");
  const control = await launchDirect(t, controlProfile, [
    ...FROZEN,
    `--user-data-dir=${controlProfile}`,
    "--remote-debugging-pipe",
    `--host-resolver-rules=MAP fixture.test 127.0.0.1:${FIXTURE_PORT}`,
    "--enable-quic",
    `--ignore-certificate-errors-spki-list=${tls.spki}`,
    "about:blank"
  ]);
  // With QUIC enabled, the same two navigations upgrade to HTTP/3 through
  // the Alt-Svc advertisement, so a zero count above is not vacuous.
  for (const path of ["/first", "/second"]) {
    const page = await control.newPage();
    await page.goto(`https://fixture.test${path}`, { timeout: EVENT_DEADLINE_MS });
    await page.close();
  }
  assert.ok(await waitFor(() => fixture.admittedUdp() > 0, EVENT_DEADLINE_MS), "the control made no Alt-Svc QUIC attempt");
  await tryWebTransport(control, "https://127.0.0.1:4433/x");
  assert.ok(await waitFor(() => fixture.literalUdp() > 0, EVENT_DEADLINE_MS), "the control sent no UDP, so the probe proves nothing");
});

// Accepted residual risk #300 (founder decision 2026-10-11): WebTransport
// to an admitted name reaches that name's host-pinned address, uninspected
// by the policy route. The boundary that must hold: nothing beyond admitted
// names. The admitted case is observed (not asserted absent) so a change in
// engine behavior is visible in the log.
nativeTest("WebTransport reaches nothing beyond admitted names under confinement", async (t) => {
  const tls = tlsFixture(t);
  const fixture = await httpsFixture(t, tls);
  const profile = profileFor(t, "native-https-wt");
  const context = await launchDirect(t, profile, confinedHttpsArgv(profile, tls.spki));
  // Unadmitted names resolve nowhere (MAP * ~NOTFOUND); IP literals are
  // refused by the no-route proxy.
  for (const url of ["https://unmapped.test/x", "https://example.com/x", "https://127.0.0.1:4433/x"]) {
    assert.equal(await tryWebTransport(context, url), "WebTransportError", url);
  }
  await new Promise((resolve) => setTimeout(resolve, 700));
  assert.equal(fixture.literalUdp(), 0, "WebTransport reached an IP literal");
  assert.equal(fixture.admittedUdp(), 0, "a non-admitted WebTransport attempt reached the admitted pin");
  await tryWebTransport(context, "https://fixture.test/x");
  await new Promise((resolve) => setTimeout(resolve, 700));
  console.error(`SG108-EVIDENCE accepted residual #300: admitted-name WebTransport datagrams=${fixture.admittedUdp()}`);
});

nativeTest("the worker's service-worker denial refuses same-origin registration, and the control registers", async (t) => {
  const tls = tlsFixture(t);
  const fixture = await httpsFixture(t, tls);
  const scripts = (): string[] => fixture.hits.filter((hit) => hit.endsWith(".js"));

  // Exactly the production configuration (entry.ts): serviceWorkers "allow"
  // plus denyServiceWorkerScripts. The page tries direct and prototype
  // registration.
  const profile = profileFor(t, "native-sw");
  const context = await launchDirect(t, profile, confinedHttpsArgv(profile, tls.spki), { serviceWorkers: "allow" });
  await denyServiceWorkerScripts(context);
  const page = await context.newPage();
  await page.goto("https://fixture.test/sw", { timeout: EVENT_DEADLINE_MS });
  await page.waitForFunction(() => document.title.includes("proto:"), undefined, { timeout: EVENT_DEADLINE_MS });
  const outcome = await page.title();
  await new Promise((resolve) => setTimeout(resolve, 1_000));
  const registered = await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length);
  await page.close();
  assert.match(outcome, /^direct:TypeError proto:TypeError$/, outcome);
  assert.equal(registered, 0, "a service worker registered");
  assert.deepEqual(scripts(), [], "a service-worker script reached the fixture");

  // Positive control: the same configuration without the denial route
  // registers the worker and fetches its scripts.
  const controlProfile = profileFor(t, "native-sw-control");
  const control = await launchDirect(t, controlProfile, confinedHttpsArgv(controlProfile, tls.spki), {
    serviceWorkers: "allow"
  });
  const controlPage = await control.newPage();
  await controlPage.goto("https://fixture.test/sw", { timeout: EVENT_DEADLINE_MS });
  await controlPage.waitForFunction(() => document.title.includes("proto:"), undefined, { timeout: EVENT_DEADLINE_MS });
  assert.match(await controlPage.title(), /proto:ok/);
  assert.ok(await waitFor(() => scripts().length > 0, EVENT_DEADLINE_MS), "the control fetched no service-worker script");
  await controlPage.close();
});

nativeTest("the route stack refuses service workers even when the policy allows everything", async (t) => {
  // Pins the route order of installRoutes: the service-worker denial must
  // run before the policy route, whatever the policy answers.
  const tls = tlsFixture(t);
  const fixture = await httpsFixture(t, tls);
  const profile = profileFor(t, "native-route-order");
  const context = await launchDirect(t, profile, confinedHttpsArgv(profile, tls.spki), { serviceWorkers: "allow" });
  const primary = context.pages()[0] ?? (await context.newPage());
  await installRoutes(context, () => primary, { decide: async () => true });
  await primary.goto("https://fixture.test/sw", { timeout: EVENT_DEADLINE_MS });
  await primary.waitForFunction(() => document.title.includes("proto:"), undefined, { timeout: EVENT_DEADLINE_MS });
  assert.match(await primary.title(), /^direct:TypeError proto:TypeError$/);
  assert.deepEqual(fixture.hits.filter((hit) => hit.endsWith(".js")), [], "a service-worker script was fetched");
  assert.deepEqual(webServiceWorkers(context), [], "a web service worker is running");
});

nativeTest("a cross-site iframe is refused by the policy route, so it cannot register a service worker", async (t) => {
  const tls = tlsFixture(t);
  const fixture = await httpsFixture(t, tls);
  const profile = profileFor(t, "native-sw-cross");
  const args = [...confinedArgv(profile, TWO_SITES).slice(0, -1), `--ignore-certificate-errors-spki-list=${tls.spki}`, "about:blank"];
  const context = await launchDirect(t, profile, args, { serviceWorkers: "allow" });
  const primary = context.pages()[0] ?? (await context.newPage());
  // The host's frame rule (SG-000075 mediate_frame: exact origin), proven
  // for the host in worker_navigation.rs; every other kind is allowed here
  // so only the frame decision is under test.
  const asked: Array<RouteQuery & { allowed: boolean }> = [];
  await installRoutes(context, () => primary, {
    decide: async (query) => {
      const allowed = query.kind !== "frame" || originOf(query.url) === query.origin;
      asked.push({ ...query, allowed });
      return allowed;
    }
  });
  await primary.goto("https://fixture.test/sw-cross", { timeout: EVENT_DEADLINE_MS });
  // #374: until the cross-site frame was asked about (checked below), then
  // what must not happen has time to fail to appear.
  await waitFor(() => asked.some((q) => q.kind === "frame" && q.url === "https://other.test/sw"), EVENT_DEADLINE_MS);
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  // The cross-site frame was asked about and refused, and never contacted.
  assert.ok(
    asked.some((q) => q.kind === "frame" && q.url === "https://other.test/sw" && q.origin === "https://fixture.test" && !q.allowed),
    `the cross-site frame was not refused: ${JSON.stringify(asked)}`
  );
  assert.deepEqual(fixture.hits.filter((hit) => hit.startsWith("other.test")), [], "other.test was contacted");
  assert.deepEqual(fixture.hits.filter((hit) => hit.endsWith(".js")), [], "a service-worker script was fetched");
  assert.deepEqual(webServiceWorkers(context), [], "a web service worker is running");
});
