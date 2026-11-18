import assert from "node:assert/strict";
import { test } from "node:test";
import type { Piece } from "./extract/pieces.js";
import { validLaunch } from "./fixtures.js";
import { encodeFrame, type WorkerFrame } from "./protocol.js";
import type { VerifyProbe, VerifyResult } from "./verify.js";
import type { FormAction } from "./actions/form.js";
import { NavigationError, TabError, Worker, type EngineSession, type Launcher, type LaunchSpec, type RoutePolicy, type TabsState, describeLaunchError } from "./worker.js";
import { MAX_SCREENSHOT_PIECE_CHARS, ScreenshotError } from "./screenshot.js";
import type { BoundedOutline } from "./outline/capture.js";
import type { SchemaField, SchemaValue } from "./outline/schema-extract.js";
import type { ChallengeReport } from "./challenge.js";

class FakeEngine implements EngineSession {
  closed = 0;
  private exitListener: (() => void) | null = null;
  navigations: string[] = [];
  navigateBehavior: (url: string) => Promise<{ url: string; status: number }> = async (url) => ({ url, status: 200 });
  async close(): Promise<void> {
    this.closed++;
  }
  fetchBehavior: (url: string) => Promise<{ url: string; status: number; media: string; text: string; truncated: boolean }> = async (url) => ({
    url,
    status: 200,
    media: "text/plain",
    text: "User-agent: *",
    truncated: false
  });
  async fetchText(url: string): Promise<{ tab: number; url: string; status: number; media: string; text: string; truncated: boolean }> {
    return { tab: this.tab, ...(await this.fetchBehavior(url)) };
  }
  tab = 1;
  async navigate(url: string): Promise<{ tab: number; url: string; status: number }> {
    this.navigations.push(url);
    return { tab: this.tab, ...(await this.navigateBehavior(url)) };
  }
  observeBehavior: () => Promise<{ url: string; snapshot: { nodes: never[]; truncated: boolean } }> = async () => ({
    url: "https://fixture.test/",
    snapshot: { nodes: [], truncated: false }
  });
  async observe(): Promise<{ tab: number; url: string; snapshot: { nodes: never[]; truncated: boolean } }> {
    return { tab: this.tab, ...(await this.observeBehavior()) };
  }
  outlineBehavior: () => Promise<{ url: string; outline: BoundedOutline }> = async () => ({
    url: "https://fixture.test/",
    outline: { nodes: [{ id: "0-4", role: "heading", name: "Fees", xpath: "/html[1]/body[1]/h1[1]", children: [] }], truncated: false }
  });
  async outline(): Promise<{ tab: number; url: string; outline: BoundedOutline }> {
    return { tab: this.tab, ...(await this.outlineBehavior()) };
  }
  schemaFields: SchemaField[][] = [];
  schemaBehavior: (fields: SchemaField[]) => Promise<{ url: string; truncated: boolean; values: SchemaValue[] }> = async (fields) => ({
    url: "https://fixture.test/",
    truncated: false,
    values: fields.map((field) => ({ key: field.key, found: true, text: "Fees" }))
  });
  async extractSchema(fields: SchemaField[]): Promise<{ tab: number; url: string; truncated: boolean; values: SchemaValue[] }> {
    this.schemaFields.push(fields);
    return { tab: this.tab, ...(await this.schemaBehavior(fields)) };
  }
  discoverBehavior: () => Promise<{ url: string; truncated: boolean; tools: never[] }> = async () => ({
    url: "https://fixture.test/",
    truncated: false,
    tools: []
  });
  async discover(): Promise<{ tab: number; url: string; truncated: boolean; tools: never[] }> {
    return { tab: this.tab, ...(await this.discoverBehavior()) };
  }
  extractBehavior: () => Promise<{ url: string; truncated: boolean; pieces: Piece[] }> = async () => ({
    url: "https://fixture.test/",
    truncated: false,
    pieces: [{ chunk: 0, content: "# Page" }]
  });
  async extract(): Promise<{ tab: number; url: string; truncated: boolean; pieces: Piece[] }> {
    return { tab: this.tab, ...(await this.extractBehavior()) };
  }
  executions: Array<{ tool: string; fields: unknown }> = [];
  executeBehavior: () => Promise<{ url: string; status: number; structured: string[]; structuredComplete: boolean }> = async () => ({
    url: "https://fixture.test/search?q=rust",
    status: 200,
    structured: ['{"results":1}'],
    structuredComplete: true
  });
  async execute(tool: string, fields: unknown): Promise<{ tab: number; url: string; status: number; structured: string[]; structuredComplete: boolean }> {
    this.executions.push({ tool, fields });
    return { tab: this.tab, ...(await this.executeBehavior()) };
  }
  activations: string[] = [];
  activateBehavior: (ref: string) => Promise<{ url: string; status: number }> = async () => ({ url: "https://fixture.test/next", status: 200 });
  async activate(ref: string): Promise<{ tab: number; url: string; status: number }> {
    this.activations.push(ref);
    return { tab: this.tab, ...(await this.activateBehavior(ref)) };
  }
  downloadBehavior: (ref: string, path: string) => Promise<{ url: string; name: string; media: string; bytes: number }> = async () => ({
    url: "https://fixture.test/r.pdf",
    name: "r.pdf",
    media: "application/pdf",
    bytes: 10
  });
  async download(ref: string, path: string): Promise<{ tab: number; url: string; name: string; media: string; bytes: number }> {
    return { tab: this.tab, ...(await this.downloadBehavior(ref, path)) };
  }
  verifyBehavior: (probes: VerifyProbe[]) => Promise<{ url: string; results: VerifyResult[] }> = async (probes) => ({
    url: "https://fixture.test/",
    results: probes.map(() => ({ result: "visible", count: 1 }))
  });
  async verify(probes: VerifyProbe[]): Promise<{ tab: number; url: string; results: VerifyResult[] }> {
    return { tab: this.tab, ...(await this.verifyBehavior(probes)) };
  }
  challengeCalls: Array<{ url: string; status: number }> = [];
  challengeBehavior: () => Promise<{ url: string; report: ChallengeReport }> = async () => ({
    url: "https://fixture.test/",
    report: { kind: "none", signals: [], truncated: false }
  });
  async challenge(url: string, status: number): Promise<{ tab: number; url: string; report: ChallengeReport }> {
    this.challengeCalls.push({ url, status });
    return { tab: this.tab, ...(await this.challengeBehavior()) };
  }
  dialogLog: { dialogs: Array<{ kind: "alert" | "confirm" | "prompt" | "beforeunload"; url: string; message: string; accepted: boolean }>; truncated: boolean } = {
    dialogs: [],
    truncated: false
  };
  takeDialogs() {
    const out = this.dialogLog;
    this.dialogLog = { dialogs: [], truncated: false };
    return out;
  }
  uploads: Array<{ ref: string; path: string }> = [];
  uploadBehavior: () => Promise<{ url: string }> = async () => ({ url: "https://fixture.test/upload" });
  async upload(ref: string, path: string): Promise<{ tab: number; url: string }> {
    this.uploads.push({ ref, path });
    return { tab: this.tab, ...(await this.uploadBehavior()) };
  }
  waitBehavior: () => Promise<{ url: string; met: boolean }> = async () => ({ url: "https://fixture.test/form", met: true });
  async waitForText(): Promise<{ tab: number; url: string; met: boolean }> {
    return { tab: this.tab, ...(await this.waitBehavior()) };
  }
  formActions: Array<{ ref: string; act: FormAction; acceptConfirm?: string }> = [];
  formBehavior: () => Promise<{ url: string; navigated?: boolean }> = async () => ({ url: "https://fixture.test/form" });
  async formAction(ref: string, act: FormAction, _target?: unknown, acceptConfirm?: string): Promise<{ tab: number; url: string; navigated?: boolean }> {
    this.formActions.push(acceptConfirm === undefined ? { ref, act } : { ref, act, acceptConfirm });
    return { tab: this.tab, ...(await this.formBehavior()) };
  }
  shots: boolean[] = [];
  screenshotBehavior: (fullPage: boolean) => Promise<{ png: Buffer; width: number; height: number; truncated: boolean }> = async () => ({
    png: Buffer.from("png-bytes"),
    width: 1280,
    height: 720,
    truncated: false
  });
  async screenshot(fullPage: boolean): Promise<{ tab: number; url: string; png: Buffer; width: number; height: number; truncated: boolean }> {
    this.shots.push(fullPage);
    return { tab: this.tab, url: "https://fixture.test/", ...(await this.screenshotBehavior(fullPage)) };
  }
  tabCalls: string[] = [];
  tabState: TabsState = { active: 1, tabs: [{ tab: 1, url: "https://fixture.test/" }] };
  tabBehavior: (call: string) => Promise<TabsState> = async () => this.tabState;
  tabNew(): Promise<TabsState> {
    this.tabCalls.push("new");
    return this.tabBehavior("new");
  }
  tabSwitch(tab: number): Promise<TabsState> {
    this.tabCalls.push(`switch ${tab}`);
    return this.tabBehavior(`switch ${tab}`);
  }
  tabClose(tab: number): Promise<TabsState> {
    this.tabCalls.push(`close ${tab}`);
    return this.tabBehavior(`close ${tab}`);
  }
  tabs(): TabsState {
    this.tabCalls.push("list");
    return this.tabState;
  }
  onUnexpectedExit(listener: () => void): void {
    this.exitListener = listener;
  }
  crash(): void {
    this.exitListener?.();
  }
}

function harness(launchBehavior: (spec: LaunchSpec) => Promise<EngineSession> = async () => new FakeEngine()) {
  const sent: WorkerFrame[] = [];
  const exits: number[] = [];
  const launches: LaunchSpec[] = [];
  const policies: RoutePolicy[] = [];
  const launcher: Launcher = {
    launch(spec, policy) {
      launches.push(spec);
      policies.push(policy);
      return launchBehavior(spec);
    }
  };
  const worker = new Worker(launcher, (frame) => {
    // Encoded like the real worker's send, so an oversized frame throws.
    encodeFrame(frame);
    sent.push(frame);
  }, (code) => exits.push(code));
  return { worker, sent, exits, launches, policies };
}

test("hello, launch, ping and shutdown follow the closed lifecycle", async () => {
  const engine = new FakeEngine();
  const { worker, sent, exits, launches } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  await worker.receive({ frame: "ping", nonce: "n1" });
  await worker.receive({ frame: "shutdown" });
  assert.deepEqual(sent, [
    { frame: "hello", generation: 20, worker: "orcel-browser-worker" },
    { frame: "launched" },
    { frame: "pong", nonce: "n1" },
    { frame: "bye" }
  ]);
  assert.deepEqual(exits, [0]);
  assert.equal(engine.closed, 1);
  // The launcher received the host argv unchanged.
  assert.deepEqual(launches[0]?.argv, validLaunch().argv);
  // Frames after close do nothing.
  await worker.receive({ frame: "ping", nonce: "n2" });
  assert.equal(sent.length, 4);
});

test("anything before hello, a wrong generation, or a second hello fails closed", async () => {
  for (const first of [validLaunch(), { frame: "ping", nonce: "n" }, { frame: "hello", generation: 17 }, { frame: "hello", generation: 18 }, { frame: "bogus" }]) {
    const { worker, sent, exits, launches } = harness();
    await worker.receive(first);
    assert.deepEqual(sent, [{ frame: "error", code: "protocol_violation" }]);
    assert.deepEqual(exits, [1]);
    assert.equal(launches.length, 0);
  }
  const { worker, sent, exits } = harness();
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive({ frame: "hello", generation: 20 });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
  assert.deepEqual(exits, [1]);
});

test("a refused launch never reaches the launcher", async () => {
  const { worker, sent, exits, launches } = harness();
  await worker.receive({ frame: "hello", generation: 20 });
  const launch = validLaunch();
  launch.argv.splice(9, 0, "--remote-debugging-port=9222");
  await worker.receive(launch);
  assert.equal(launches.length, 0);
  assert.deepEqual(sent.at(-1), { frame: "error", code: "launch_refused" });
  assert.deepEqual(exits, [1]);
});

test("only one engine per worker lifetime", async () => {
  const engine = new FakeEngine();
  const { worker, sent, exits, launches } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  await worker.receive(validLaunch());
  assert.equal(launches.length, 1);
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  assert.deepEqual(exits, [1]);
  assert.equal(engine.closed, 1);
});

test("launch failure, engine exit, violations and end of input all close the engine", async () => {
  {
    const { worker, sent, exits } = harness(async () => {
      throw new Error("no engine");
    });
    await worker.receive({ frame: "hello", generation: 20 });
    await worker.receive(validLaunch());
    assert.deepEqual(sent.at(-1), { frame: "error", code: "launch_failed" });
    assert.deepEqual(exits, [1]);
  }
  {
    // #438: the reason reaches the diagnostic sink, bounded, one line.
    const lines: string[] = [];
    const worker = new Worker(
      { launch: async () => { throw Object.assign(new Error("browserType.launch: Timeout 30000ms exceeded.\n=== logs ===\nsecret-ish detail"), { name: "TimeoutError" }); } },
      () => {},
      () => {},
      (line) => lines.push(line)
    );
    await worker.receive({ frame: "hello", generation: 20 });
    await worker.receive(validLaunch());
    assert.deepEqual(lines, ["orcel-browser-worker: launch failed: TimeoutError: browserType.launch: Timeout 30000ms exceeded."]);
    assert.equal(Array.from(describeLaunchError("x".repeat(2000))).length, 1025);
    assert.equal(describeLaunchError(new Error("a\u0007b")), "Error: a b");
    // C1, DEL, line separators and bidi controls are removed too.
    assert.equal(describeLaunchError(new Error("a\u0085b\u007fc\u2028d\u202ee")), "Error: a b c d e");
    // A thrown value that cannot be printed never breaks the typed failure.
    assert.equal(describeLaunchError(Object.create(null)), "unprintable");
    assert.equal(describeLaunchError(42), "number: 42");
    // The bound counts code points, never splitting a surrogate pair.
    const long = describeLaunchError("\u{1F600}".repeat(2000));
    assert.equal(Array.from(long).length, 1025);
    assert.ok(!/[\ud800-\udfff](?![\udc00-\udfff])/.test(long.replace(/[\ud800-\udbff][\udc00-\udfff]/g, "")));
  }
  {
    const engine = new FakeEngine();
    const { worker, sent, exits } = harness(async () => engine);
    await worker.receive({ frame: "hello", generation: 20 });
    await worker.receive(validLaunch());
    engine.crash();
    await worker.receive({ frame: "ping", nonce: "after" });
    assert.deepEqual(sent.at(-1), { frame: "error", code: "engine_exited" });
    assert.deepEqual(exits, [1]);
  }
  {
    const engine = new FakeEngine();
    const { worker, sent, exits } = harness(async () => engine);
    await worker.receive({ frame: "hello", generation: 20 });
    await worker.receive(validLaunch());
    await worker.violation();
    assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
    assert.deepEqual(exits, [1]);
    assert.equal(engine.closed, 1);
  }
  {
    const engine = new FakeEngine();
    const { worker, sent, exits } = harness(async () => engine);
    await worker.receive({ frame: "hello", generation: 20 });
    await worker.receive(validLaunch());
    await worker.endOfInput();
    assert.deepEqual(sent.at(-1), { frame: "launched" });
    assert.deepEqual(exits, [0]);
    assert.equal(engine.closed, 1);
  }
});

test("a shutdown queued behind a slow launch closes the launched engine", async () => {
  const engine = new FakeEngine();
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => (release = resolve));
  const { worker, sent, exits } = harness(async () => {
    await gate;
    return engine;
  });
  await worker.receive({ frame: "hello", generation: 20 });
  const launching = worker.receive(validLaunch());
  const shutdown = worker.receive({ frame: "shutdown" });
  release();
  await launching;
  await shutdown;
  assert.deepEqual(sent.slice(1), [{ frame: "launched" }, { frame: "bye" }]);
  assert.deepEqual(exits, [0]);
  assert.equal(engine.closed, 1);
});

test("an unexpected error in a step fails the worker closed exactly once", async () => {
  const engine = new FakeEngine();
  const exits: number[] = [];
  let sends = 0;
  const worker = new Worker(
    { launch: async () => engine },
    () => {
      sends++;
      if (sends === 3) throw new Error("broken pipe");
    },
    (code) => exits.push(code)
  );
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  await worker.receive({ frame: "ping", nonce: "boom" });
  await worker.receive({ frame: "ping", nonce: "after" });
  assert.deepEqual(exits, [1]);
  assert.equal(engine.closed, 1);
});

async function launched(engine = new FakeEngine()) {
  const h = harness(async () => engine);
  await h.worker.receive({ frame: "hello", generation: 20 });
  await h.worker.receive(validLaunch());
  return { ...h, engine, policy: h.policies[0] as RoutePolicy };
}

const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

test("navigation runs outside the queue and reports its outcome", async () => {
  const { worker, sent, engine } = await launched();
  let finish: (value: { url: string; status: number }) => void = () => {};
  engine.navigateBehavior = () => new Promise((resolve) => (finish = resolve));
  await worker.receive({ frame: "navigate", nav_id: 1, url: "https://fixture.test/a" });
  // Ping is answered while the navigation is still running.
  await worker.receive({ frame: "ping", nonce: "during" });
  assert.deepEqual(sent.at(-1), { frame: "pong", nonce: "during" });
  // A second navigation while one runs is refused as busy.
  await worker.receive({ frame: "navigate", nav_id: 2, url: "https://fixture.test/b" });
  assert.deepEqual(sent.at(-1), { frame: "navigation_failed", nav_id: 2, reason: "busy" });
  finish({ url: "https://fixture.test/a", status: 200 });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "navigated", nav_id: 1, tab: 1, url: "https://fixture.test/a", status: 200 });
  assert.deepEqual(engine.navigations, ["https://fixture.test/a"]);
});

test("navigation failures are typed", async () => {
  for (const [error, reason] of [
    [new NavigationError("denied"), "denied"],
    [new NavigationError("timeout"), "timeout"],
    [new Error("anything else"), "failed"]
  ] as const) {
    const { worker, sent, engine } = await launched();
    engine.navigateBehavior = async () => {
      throw error;
    };
    await worker.receive({ frame: "navigate", nav_id: 7, url: "https://fixture.test/x" });
    await settle();
    assert.deepEqual(sent.at(-1), { frame: "navigation_failed", nav_id: 7, reason });
  }
});

test("navigate before launch fails closed", async () => {
  const { worker, sent, exits } = harness();
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive({ frame: "navigate", nav_id: 1, url: "https://fixture.test/" });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  assert.deepEqual(exits, [1]);
});

test("route requests are described to the host and only its answer applies", async () => {
  const { worker, sent, policy } = await launched();
  const allowed = policy.decide({ kind: "document", url: "https://fixture.test/a", origin: "" });
  const refused = policy.decide({ kind: "frame", url: "https://other.test/f", origin: "https://fixture.test" });
  assert.deepEqual(sent.slice(-2), [
    { frame: "route_request", request_id: 1, kind: "document", url: "https://fixture.test/a", origin: "", method: "GET", content_type: "", body: "", body_bytes: 0 },
    { frame: "route_request", request_id: 2, kind: "frame", url: "https://other.test/f", origin: "https://fixture.test", method: "GET", content_type: "", body: "", body_bytes: 0 }
  ]);
  // Decisions bypass the queue and may arrive in any order.
  await worker.receive({ frame: "route_decision", request_id: 2, allow: false });
  await worker.receive({ frame: "route_decision", request_id: 1, allow: true });
  assert.equal(await allowed, true);
  assert.equal(await refused, false);
  // A late or duplicate answer for a known id is ignored; an id never
  // issued is a violation.
  await worker.receive({ frame: "route_decision", request_id: 1, allow: true });
  assert.notDeepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
  await worker.receive({ frame: "route_decision", request_id: 99, allow: true });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
});

test("SG-000122 A6: a main-frame document hop is marked on the wire, every other hop is not", async () => {
  const { worker, sent, policy } = await launched();
  const main = policy.decide({ kind: "redirect", url: "https://fixture.test/thanks", origin: "https://fixture.test", mainDocument: true });
  const image = policy.decide({ kind: "redirect", url: "https://fixture.test/img.png", origin: "https://fixture.test" });
  assert.deepEqual(sent.slice(-2), [
    { frame: "route_request", request_id: 1, kind: "redirect", url: "https://fixture.test/thanks", origin: "https://fixture.test", method: "GET", content_type: "", body: "", body_bytes: 0, main_document: true },
    { frame: "route_request", request_id: 2, kind: "redirect", url: "https://fixture.test/img.png", origin: "https://fixture.test", method: "GET", content_type: "", body: "", body_bytes: 0 }
  ]);
  await worker.receive({ frame: "route_decision", request_id: 1, allow: true });
  await worker.receive({ frame: "route_decision", request_id: 2, allow: true });
  assert.equal(await main, true);
  assert.equal(await image, true);
});

test("oversized or control-character requests are refused without asking", async () => {
  const { sent, policy } = await launched();
  const before = sent.length;
  assert.equal(await policy.decide({ kind: "subresource", url: `https://fixture.test/${"a".repeat(3000)}`, origin: "https://fixture.test" }), false);
  assert.equal(await policy.decide({ kind: "subresource", url: "https://fixture.test/\u0000", origin: "https://fixture.test" }), false);
  assert.equal(await policy.decide({ kind: "document", url: "", origin: "" }), false);
  assert.equal(sent.length, before, "a refused request reached the host");
});

test("pending decisions are refused when the worker closes", async () => {
  const { worker, policy } = await launched();
  const waiting = policy.decide({ kind: "document", url: "https://fixture.test/a", origin: "" });
  await worker.receive({ frame: "shutdown" });
  assert.equal(await waiting, false);
  // Nothing is asked after close.
  assert.equal(await policy.decide({ kind: "document", url: "https://fixture.test/b", origin: "" }), false);
});

test("a route decision before launch is a violation", async () => {
  const { worker, sent, exits } = harness();
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive({ frame: "route_decision", request_id: 1, allow: true });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
  assert.deepEqual(exits, [1]);
});

test("observe reports a bounded snapshot or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  engine.observeBehavior = async () => ({ url: "https://fixture.test/r", snapshot: { nodes: [], truncated: true } });
  await worker.receive({ frame: "observe", obs_id: 3 });
  assert.deepEqual(sent.at(-1), { frame: "observed", obs_id: 3, tab: 1, url: "https://fixture.test/r", truncated: true, nodes: [] });
  engine.observeBehavior = async () => {
    throw new Error("snapshot timed out");
  };
  await worker.receive({ frame: "observe", obs_id: 4 });
  assert.deepEqual(sent.at(-1), { frame: "observation_failed", obs_id: 4 });
});

test("BR-07: verify reports one result per probe or a typed failure, and needs a launch", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive({ frame: "verify", ver_id: 1, probes: [{ probe: "visible_text", text: "Done" }] });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  const second = harness(async () => engine);
  await second.worker.receive({ frame: "hello", generation: 20 });
  await second.worker.receive(validLaunch());
  const probes = [
    { probe: "visible_role", role: "button", name: "Pay" },
    { probe: "value", ref: "e3" }
  ];
  engine.verifyBehavior = async () => ({
    url: "https://fixture.test/r",
    results: [
      { result: "visible", count: 0 },
      { result: "unavailable", reason: "secret" }
    ]
  });
  await second.worker.receive({ frame: "verify", ver_id: 2, probes });
  assert.deepEqual(second.sent.at(-1), {
    frame: "verified",
    tab: 1,
    ver_id: 2,
    url: "https://fixture.test/r",
    results: [
      { result: "visible", count: 0 },
      { result: "unavailable", reason: "secret" }
    ]
  });
  // A result count that does not match the probes, or an engine error, is a typed failure.
  engine.verifyBehavior = async () => ({ url: "https://fixture.test/r", results: [] });
  await second.worker.receive({ frame: "verify", ver_id: 3, probes });
  assert.deepEqual(second.sent.at(-1), { frame: "verification_failed", ver_id: 3 });
  engine.verifyBehavior = async () => {
    throw new Error("engine gone");
  };
  await second.worker.receive({ frame: "verify", ver_id: 4, probes });
  assert.deepEqual(second.sent.at(-1), { frame: "verification_failed", ver_id: 4 });
});

test("OB-07: a challenge check answers a closed report, and fails typed while a navigation runs or the engine errs", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive({ frame: "challenge", chl_id: 1, url: "", status: 0 });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  const second = harness(async () => engine);
  await second.worker.receive({ frame: "hello", generation: 20 });
  await second.worker.receive(validLaunch());
  engine.challengeBehavior = async () => ({
    url: "https://fixture.test/login",
    report: { kind: "sign_in", signals: ["password_field", "http_auth"], truncated: false }
  });
  await second.worker.receive({ frame: "challenge", chl_id: 2, url: "https://fixture.test/login", status: 401 });
  assert.deepEqual(engine.challengeCalls.at(-1), { url: "https://fixture.test/login", status: 401 });
  assert.deepEqual(second.sent.at(-1), {
    frame: "challenge_report",
    chl_id: 2,
    tab: 1,
    url: "https://fixture.test/login",
    kind: "sign_in",
    signals: ["password_field", "http_auth"],
    truncated: false
  });
  engine.challengeBehavior = async () => {
    throw new Error("capture timed out");
  };
  await second.worker.receive({ frame: "challenge", chl_id: 3, url: "", status: 0 });
  assert.deepEqual(second.sent.at(-1), { frame: "challenge_failed", chl_id: 3 });
  // While a navigation runs, nothing is classified.
  let release: () => void = () => {};
  engine.navigateBehavior = (url) => new Promise((resolve) => (release = () => resolve({ url, status: 200 })));
  void second.worker.receive({ frame: "navigate", nav_id: 4, url: "https://fixture.test/next" });
  await new Promise((resolve) => setImmediate(resolve));
  const calls = engine.challengeCalls.length;
  await second.worker.receive({ frame: "challenge", chl_id: 5, url: "", status: 0 });
  assert.deepEqual(second.sent.at(-1), { frame: "challenge_failed", chl_id: 5 });
  assert.equal(engine.challengeCalls.length, calls);
  release();
});

test("BR-02: a form action runs outside the queue, is busy during a navigation, and reports a typed outcome", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  await worker.receive({ frame: "form_action", form_id: 1, action: "fill", ref: "e4", value: "Ada" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "form_done", form_id: 1, tab: 1, url: "https://fixture.test/form" });
  assert.deepEqual(engine.formActions.at(-1), { ref: "e4", act: { action: "fill", value: "Ada" } });
  engine.formBehavior = async () => {
    throw new NavigationError("denied");
  };
  await worker.receive({ frame: "form_action", form_id: 2, action: "check", ref: "e5", checked: true, role: "checkbox", name: "Terms" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "form_failed", form_id: 2, reason: "denied" });
  // While a navigation runs, a form action is busy.
  let release = (): void => {};
  engine.navigateBehavior = (url) => new Promise((resolve) => (release = () => resolve({ url, status: 200 })));
  await worker.receive({ frame: "navigate", nav_id: 3, url: "https://fixture.test/next" });
  await worker.receive({ frame: "form_action", form_id: 4, action: "select", ref: "e6", values: ["Lisbon"] });
  assert.deepEqual(sent.at(-1), { frame: "form_failed", form_id: 4, reason: "busy" });
  release();
});

test("SG-000122 A6: an Enter says whether its submission committed a document; other actions never do", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  engine.formBehavior = async () => ({ url: "https://fixture.test/order", navigated: true });
  await worker.receive({ frame: "form_action", form_id: 1, action: "enter", ref: "e4" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "form_done", form_id: 1, tab: 1, url: "https://fixture.test/order", navigated: true });
  engine.formBehavior = async () => ({ url: "https://fixture.test/form" });
  await worker.receive({ frame: "form_action", form_id: 2, action: "enter", ref: "e4" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "form_done", form_id: 2, tab: 1, url: "https://fixture.test/form", navigated: false });
  // A fill's reply carries no navigation, whatever the engine claims.
  engine.formBehavior = async () => ({ url: "https://fixture.test/form", navigated: true });
  await worker.receive({ frame: "form_action", form_id: 3, action: "fill", ref: "e4", value: "Ada" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "form_done", form_id: 3, tab: 1, url: "https://fixture.test/form" });
});

test("BR-02: a bounded wait runs outside the queue, one at a time, and reports whether it was met", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  let release = (): void => {};
  engine.waitBehavior = () => new Promise((resolve) => (release = () => resolve({ url: "https://fixture.test/form", met: false })));
  await worker.receive({ frame: "wait_for", wait_id: 1, text: "Saved", appear: true, timeout_ms: 2000 });
  // Ping is answered while the wait runs; a second wait is refused.
  await worker.receive({ frame: "ping", nonce: "n1" });
  assert.deepEqual(sent.at(-1), { frame: "pong", nonce: "n1" });
  await worker.receive({ frame: "wait_for", wait_id: 2, text: "Saved", appear: true, timeout_ms: 2000 });
  assert.deepEqual(sent.at(-1), { frame: "wait_failed", wait_id: 2 });
  release();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "waited", wait_id: 1, tab: 1, url: "https://fixture.test/form", met: false });
});

test("BR-03: an upload runs outside the queue and reports a typed outcome", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  await worker.receive({ frame: "upload", up_id: 1, ref: "e3", path: "C:\\staging\\up-1\\report.txt" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "uploaded", up_id: 1, tab: 1, url: "https://fixture.test/upload" });
  assert.deepEqual(engine.uploads, [{ ref: "e3", path: "C:\\staging\\up-1\\report.txt" }]);
  engine.uploadBehavior = async () => {
    throw new NavigationError("denied");
  };
  await worker.receive({ frame: "upload", up_id: 2, ref: "e4", path: "C:\\staging\\up-1\\report.txt" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "upload_failed", up_id: 2, reason: "denied" });
});

test("BR-05: dismissed dialogs are reported once", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive(validLaunch());
  engine.dialogLog = { dialogs: [{ kind: "confirm", url: "https://fixture.test/", message: "Delete this item?", accepted: false }], truncated: false };
  await worker.receive({ frame: "dialogs", dlg_id: 1 });
  assert.deepEqual(sent.at(-1), {
    frame: "dialogs_seen",
    dlg_id: 1,
    dialogs: [{ kind: "confirm", url: "https://fixture.test/", message: "Delete this item?", accepted: false }],
    truncated: false
  });
  await worker.receive({ frame: "dialogs", dlg_id: 2 });
  assert.deepEqual(sent.at(-1), { frame: "dialogs_seen", dlg_id: 2, dialogs: [], truncated: false });
});

test("W2-03: outline reports bounded nodes or a typed failure, and never runs during a navigation", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "outline", out_id: 2 });
  assert.deepEqual(sent.at(-1), {
    frame: "outlined",
    out_id: 2,
    tab: 1,
    url: "https://fixture.test/",
    truncated: false,
    nodes: [{ id: "0-4", role: "heading", name: "Fees", xpath: "/html[1]/body[1]/h1[1]", children: [] }]
  });
  engine.outlineBehavior = async () => {
    throw new Error("the outline timed out");
  };
  await worker.receive({ frame: "outline", out_id: 3 });
  assert.deepEqual(sent.at(-1), { frame: "outline_failed", out_id: 3 });
  // A page URL longer than the bound fails instead of breaking the frame.
  engine.outlineBehavior = async () => ({ url: `https://fixture.test/${"a".repeat(2100)}`, outline: { nodes: [], truncated: false } });
  await worker.receive({ frame: "outline", out_id: 4 });
  assert.deepEqual(sent.at(-1), { frame: "outline_failed", out_id: 4 });
  // While a navigation runs, the document is being replaced.
  let release: () => void = () => {};
  engine.navigateBehavior = (url) => new Promise((resolve) => (release = () => resolve({ url, status: 200 })));
  await worker.receive({ frame: "navigate", nav_id: 1, url: "https://fixture.test/next" });
  await worker.receive({ frame: "outline", out_id: 5 });
  assert.deepEqual(sent.at(-1), { frame: "outline_failed", out_id: 5 });
  await worker.receive({ frame: "extract_schema", xs_id: 6, fields: [{ key: "title", take: "text", role: "heading" }] });
  assert.deepEqual(sent.at(-1), { frame: "schema_extraction_failed", xs_id: 6 });
  release();
  await settle();
});

test("W2-03: extract_schema reports one value per field or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  const fields = [
    { key: "title", take: "text", role: "heading", name: "Fees" },
    { key: "rows", take: "texts", xpath: "/html[1]/body[1]/ul[1]" }
  ];
  await worker.receive({ frame: "extract_schema", xs_id: 7, fields });
  assert.deepEqual(engine.schemaFields.at(-1), fields);
  assert.deepEqual(sent.at(-1), {
    frame: "schema_extracted",
    xs_id: 7,
    tab: 1,
    url: "https://fixture.test/",
    truncated: false,
    values: [
      { key: "title", found: true, text: "Fees" },
      { key: "rows", found: true, text: "Fees" }
    ]
  });
  // A session that answers with the wrong number of values fails the frame.
  engine.schemaBehavior = async () => ({ url: "https://fixture.test/", truncated: false, values: [] });
  await worker.receive({ frame: "extract_schema", xs_id: 8, fields });
  assert.deepEqual(sent.at(-1), { frame: "schema_extraction_failed", xs_id: 8 });
  engine.schemaBehavior = async () => {
    throw new Error("the outline timed out");
  };
  await worker.receive({ frame: "extract_schema", xs_id: 9, fields });
  assert.deepEqual(sent.at(-1), { frame: "schema_extraction_failed", xs_id: 9 });
});

test("W2-03: outline and extract_schema before launch fail closed", async () => {
  for (const frame of [{ frame: "outline", out_id: 1 }, { frame: "extract_schema", xs_id: 1, fields: [{ key: "k", take: "text", role: "heading" }] }]) {
    const { worker, sent, exits } = harness();
    await worker.receive({ frame: "hello", generation: 20 });
    await worker.receive(frame);
    assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
    assert.deepEqual(exits, [1]);
  }
});

test("observe before launch fails closed", async () => {
  const { worker, sent, exits } = harness();
  await worker.receive({ frame: "hello", generation: 20 });
  await worker.receive({ frame: "observe", obs_id: 1 });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  assert.deepEqual(exits, [1]);
});

test("activation runs outside the queue and reports a typed outcome", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "activate", act_id: 1, ref: "e5" });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "activated", act_id: 1, tab: 1, url: "https://fixture.test/next", status: 200 });
  assert.deepEqual(engine.activations, ["e5"]);
  engine.activateBehavior = async () => {
    throw new NavigationError("denied");
  };
  await worker.receive({ frame: "activate", act_id: 2, ref: "f1e2" });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "activation_failed", act_id: 2, reason: "denied" });
});

test("malformed activation refs are protocol violations", async () => {
  for (const ref of ["", "e", "button", "e5;drop", "../e1", "f1", "e1234567"]) {
    const { worker, sent } = await launched();
    await worker.receive({ frame: "activate", act_id: 1, ref });
    assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" }, ref);
  }
});

test("downloads report the captured document or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "download", dl_id: 1, ref: "e5", path: "C:\\s\\dl-1.part" });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "downloaded", dl_id: 1, tab: 1, url: "https://fixture.test/r.pdf", name: "r.pdf", media: "application/pdf", bytes: 10 });
  engine.downloadBehavior = async () => {
    throw new NavigationError("timeout");
  };
  await worker.receive({ frame: "download", dl_id: 2, ref: "e5", path: "C:\\s\\dl-2.part" });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "download_failed", dl_id: 2, reason: "timeout" });
});

test("discover reports bounded tools or a typed failure, and needs a launch", async () => {
  const { worker, sent, engine } = await launched();
  engine.discoverBehavior = async () => ({ url: "https://fixture.test/t", truncated: true, tools: [] });
  await worker.receive({ frame: "discover", disc_id: 2 });
  assert.deepEqual(sent.at(-1), { frame: "discovered", disc_id: 2, tab: 1, url: "https://fixture.test/t", truncated: true, tools: [] });
  engine.discoverBehavior = async () => {
    throw new Error("snapshot failed");
  };
  await worker.receive({ frame: "discover", disc_id: 3 });
  assert.deepEqual(sent.at(-1), { frame: "discovery_failed", disc_id: 3 });
  const fresh = harness();
  await fresh.worker.receive({ frame: "hello", generation: 20 });
  await fresh.worker.receive({ frame: "discover", disc_id: 1 });
  assert.deepEqual(fresh.sent.at(-1), { frame: "error", code: "not_ready" });
});

test("a text fetch reports the document's text or a typed failure, and is busy during a navigation", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "fetch_text", fetch_id: 3, url: "https://fixture.test/robots.txt" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "fetched_text", fetch_id: 3, tab: 1, url: "https://fixture.test/robots.txt", status: 200, media: "text/plain", text: "User-agent: *", truncated: false });
  engine.fetchBehavior = async () => {
    throw new NavigationError("denied");
  };
  await worker.receive({ frame: "fetch_text", fetch_id: 4, url: "https://fixture.test/x" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "fetch_failed", fetch_id: 4, reason: "denied" });
  let finish: (value: { url: string; status: number }) => void = () => {};
  engine.navigateBehavior = () => new Promise((resolve) => (finish = resolve));
  await worker.receive({ frame: "navigate", nav_id: 9, url: "https://fixture.test/slow" });
  await worker.receive({ frame: "fetch_text", fetch_id: 5, url: "https://fixture.test/robots.txt" });
  assert.deepEqual(sent.at(-1), { frame: "fetch_failed", fetch_id: 5, reason: "busy" });
  finish({ url: "https://fixture.test/slow", status: 200 });
});

test("extraction is served in pieces on request, released after the last, or fails typed", async () => {
  const { worker, sent, engine } = await launched();
  engine.extractBehavior = async () => ({ url: "https://fixture.test/a", truncated: true, pieces: [{ chunk: 0, content: "one" }, { chunk: 0, content: "two" }, { chunk: 1, content: "three" }] });
  await worker.receive({ frame: "extract", ext_id: 4, links: false, images: false });
  assert.deepEqual(sent.at(-1), { frame: "extracted", ext_id: 4, tab: 1, url: "https://fixture.test/a", truncated: true, piece: 0, total: 3, chunk: 0, content: "one" });
  // Another id, or a piece past the end, fails without dropping the pieces.
  await worker.receive({ frame: "extract_more", ext_id: 5, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 5 });
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 9 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 4 });
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 1 });
  assert.equal((sent.at(-1) as { content: string }).content, "two");
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 2 });
  assert.deepEqual(sent.at(-1), { frame: "extracted", ext_id: 4, tab: 1, url: "https://fixture.test/a", truncated: true, piece: 2, total: 3, chunk: 1, content: "three" });
  // The last piece releases the extraction.
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 4 });
  // A new extraction replaces an unfinished one.
  await worker.receive({ frame: "extract", ext_id: 6, links: true, images: false });
  await worker.receive({ frame: "extract", ext_id: 7, links: false, images: false });
  await worker.receive({ frame: "extract_more", ext_id: 6, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 6 });
  engine.extractBehavior = async () => {
    throw new Error("capture failed");
  };
  await worker.receive({ frame: "extract", ext_id: 8, links: false, images: false });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 8 });
  engine.extractBehavior = async () => ({ url: "https://fixture.test/", truncated: false, pieces: [] });
  await worker.receive({ frame: "extract", ext_id: 9, links: false, images: false });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 9 });
  // A URL the page lengthened itself fails typed, and nothing is kept.
  engine.extractBehavior = async () => ({ url: "https://fixture.test/" + "a".repeat(3000), truncated: false, pieces: [{ chunk: 0, content: "x" }, { chunk: 0, content: "y" }] });
  await worker.receive({ frame: "extract", ext_id: 10, links: false, images: false });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 10 });
  await worker.receive({ frame: "extract_more", ext_id: 10, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 10 });
  const fresh = harness();
  await fresh.worker.receive({ frame: "hello", generation: 20 });
  await fresh.worker.receive({ frame: "extract", ext_id: 1, links: false, images: false });
  assert.deepEqual(fresh.sent.at(-1), { frame: "error", code: "not_ready" });
});

test("execution runs outside the queue and reports the opened document or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  const fields = [{ name: "q", control: "text", values: ["rust"] }];
  await worker.receive({ frame: "execute", exec_id: 1, tool: "search", fields });
  await settle();
  assert.deepEqual(engine.executions, [{ tool: "search", fields }]);
  assert.deepEqual(sent.at(-1), { frame: "executed", exec_id: 1, tab: 1, url: "https://fixture.test/search?q=rust", status: 200, structured: ['{"results":1}'], structured_complete: true });
  // An outcome too large to send becomes a typed failure, not a crash.
  engine.executeBehavior = async () => ({ url: "https://fixture.test/x", status: 200, structured: ["x".repeat(70_000)], structuredComplete: true });
  await worker.receive({ frame: "execute", exec_id: 3, tool: "search", fields });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "execution_failed", exec_id: 3, reason: "failed" });
  engine.executeBehavior = async () => {
    throw new NavigationError("denied");
  };
  await worker.receive({ frame: "execute", exec_id: 2, tool: "search", fields });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "execution_failed", exec_id: 2, reason: "denied" });
});

test("OB-03: a screenshot is served in bounded pieces on request, released after the last, or fails typed", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "screenshot", shot_id: 1, full_page: false });
  assert.deepEqual(engine.shots, [false]);
  assert.deepEqual(sent.at(-1), {
    frame: "screenshot_piece",
    shot_id: 1,
    tab: 1,
    url: "https://fixture.test/",
    piece: 0,
    total: 1,
    width: 1280,
    height: 720,
    bytes: 9,
    truncated: false,
    data: Buffer.from("png-bytes").toString("base64")
  });
  // One piece: nothing is kept.
  await worker.receive({ frame: "screenshot_more", shot_id: 1, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 1, reason: "failed" });
  // A PNG larger than one piece: each piece decodes on its own and the
  // pieces join to the PNG.
  const big = Buffer.alloc(100_000, 7);
  engine.screenshotBehavior = async () => ({ png: big, width: 1280, height: 4096, truncated: true });
  await worker.receive({ frame: "screenshot", shot_id: 2, full_page: true });
  const first = sent.at(-1) as { total: number; data: string; truncated: boolean };
  assert.equal(first.total, 3);
  assert.equal(first.truncated, true);
  assert.ok(first.data.length <= MAX_SCREENSHOT_PIECE_CHARS && first.data.length % 4 === 0);
  const parts = [Buffer.from(first.data, "base64")];
  await worker.receive({ frame: "screenshot_more", shot_id: 9, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 9, reason: "failed" });
  for (const piece of [1, 2]) {
    await worker.receive({ frame: "screenshot_more", shot_id: 2, piece });
    const frame = sent.at(-1) as { piece: number; data: string };
    assert.equal(frame.piece, piece);
    parts.push(Buffer.from(frame.data, "base64"));
  }
  assert.ok(Buffer.concat(parts).equals(big));
  // The last piece released it.
  await worker.receive({ frame: "screenshot_more", shot_id: 2, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 2, reason: "failed" });
  // The engine's typed refusals cross as they are.
  for (const reason of ["busy", "oversized", "failed"] as const) {
    engine.screenshotBehavior = async () => {
      throw new ScreenshotError(reason);
    };
    await worker.receive({ frame: "screenshot", shot_id: 3, full_page: false });
    assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 3, reason });
  }
  engine.screenshotBehavior = async () => {
    throw new Error("engine fault");
  };
  await worker.receive({ frame: "screenshot", shot_id: 4, full_page: false });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 4, reason: "failed" });
  // A PNG past the piece bound is refused, never sent.
  engine.screenshotBehavior = async () => ({ png: Buffer.alloc(3 * 1024 * 1024), width: 1, height: 1, truncated: false });
  await worker.receive({ frame: "screenshot", shot_id: 5, full_page: false });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 5, reason: "oversized" });
});

test("OB-03: no screenshot and no tab change while a navigation is in flight", async () => {
  const { worker, sent, engine } = await launched();
  let finish: (value: { url: string; status: number }) => void = () => {};
  engine.navigateBehavior = () => new Promise((resolve) => (finish = resolve));
  await worker.receive({ frame: "navigate", nav_id: 1, url: "https://fixture.test/slow" });
  await worker.receive({ frame: "screenshot", shot_id: 1, full_page: false });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 1, reason: "busy" });
  assert.deepEqual(engine.shots, []);
  for (const frame of [{ frame: "tab_new", tab_req: 1 }, { frame: "tab_switch", tab_req: 2, tab: 1 }, { frame: "tab_close", tab_req: 3, tab: 1 }]) {
    await worker.receive(frame);
    assert.deepEqual(sent.at(-1), { frame: "tab_failed", tab_req: frame.tab_req, reason: "busy" });
  }
  // Listing reads only the registry.
  await worker.receive({ frame: "tabs", tab_req: 4 });
  assert.deepEqual(sent.at(-1), { frame: "tabs_state", tab_req: 4, active: 1, tabs: [{ tab: 1, url: "https://fixture.test/" }] });
  assert.deepEqual(engine.tabCalls, ["list"]);
  finish({ url: "https://fixture.test/slow", status: 200 });
  await settle();
  await worker.receive({ frame: "screenshot", shot_id: 2, full_page: false });
  assert.equal((sent.at(-1) as { frame: string }).frame, "screenshot_piece");
});

test("OB-03: tab frames reach the engine and answer the tabs or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  const two: TabsState = { active: 2, tabs: [{ tab: 1, url: "https://fixture.test/" }, { tab: 2, url: "about:blank" }] };
  engine.tabBehavior = async () => two;
  await worker.receive({ frame: "tab_new", tab_req: 1 });
  assert.deepEqual(sent.at(-1), { frame: "tabs_state", tab_req: 1, ...two });
  await worker.receive({ frame: "tab_switch", tab_req: 2, tab: 1 });
  await worker.receive({ frame: "tab_close", tab_req: 3, tab: 2 });
  assert.deepEqual(engine.tabCalls, ["new", "switch 1", "close 2"]);
  for (const reason of ["cap", "last", "unknown_tab", "failed"] as const) {
    engine.tabBehavior = async () => {
      throw new TabError(reason);
    };
    await worker.receive({ frame: "tab_close", tab_req: 4, tab: 9 });
    assert.deepEqual(sent.at(-1), { frame: "tab_failed", tab_req: 4, reason });
  }
  engine.tabBehavior = async () => {
    throw new Error("engine fault");
  };
  await worker.receive({ frame: "tab_new", tab_req: 5 });
  assert.deepEqual(sent.at(-1), { frame: "tab_failed", tab_req: 5, reason: "failed" });
  const fresh = harness();
  await fresh.worker.receive({ frame: "hello", generation: 20 });
  await fresh.worker.receive({ frame: "tabs", tab_req: 1 });
  assert.deepEqual(fresh.sent.at(-1), { frame: "error", code: "not_ready" });
});

test("OB-03: every action reply names the tab it acted on", async () => {
  const { worker, sent, engine } = await launched();
  engine.tab = 3;
  const tabOf = () => (sent.at(-1) as { tab?: number }).tab;
  await worker.receive({ frame: "discover", disc_id: 9 });
  assert.equal(tabOf(), 3, "discovered");
  await worker.receive({ frame: "fetch_text", fetch_id: 9, url: "https://fixture.test/robots.txt" });
  await settle();
  assert.equal(tabOf(), 3, "fetched_text");
  await worker.receive({ frame: "execute", exec_id: 9, tool: "search", fields: [] });
  await settle();
  assert.equal(tabOf(), 3, "executed");
  await worker.receive({ frame: "download", dl_id: 9, ref: "e1", path: "C:\\s\\a.part" });
  await settle();
  assert.equal(tabOf(), 3, "downloaded");
  await worker.receive({ frame: "upload", up_id: 9, ref: "e1", path: "C:\\s\\a.txt" });
  await settle();
  assert.equal(tabOf(), 3, "uploaded");
  await worker.receive({ frame: "wait_for", wait_id: 9, text: "x", appear: true, timeout_ms: 10 });
  await settle();
  assert.equal(tabOf(), 3, "waited");
  await worker.receive({ frame: "observe", obs_id: 9 });
  assert.equal((sent.at(-1) as { tab: number }).tab, 3);
  await worker.receive({ frame: "screenshot", shot_id: 9, full_page: false });
  assert.deepEqual([(sent.at(-1) as { tab: number }).tab, (sent.at(-1) as { url: string }).url], [3, "https://fixture.test/"]);
  await worker.receive({ frame: "verify", ver_id: 9, probes: [{ probe: "visible_text", text: "x" }] });
  assert.equal((sent.at(-1) as { tab: number }).tab, 3);
  // With no active tab (its page closed itself), the engine refuses typed.
  engine.observeBehavior = async () => {
    throw new NavigationError("stale");
  };
  await worker.receive({ frame: "observe", obs_id: 10 });
  assert.deepEqual(sent.at(-1), { frame: "observation_failed", obs_id: 10 });
  engine.screenshotBehavior = async () => {
    throw new ScreenshotError("busy");
  };
  await worker.receive({ frame: "screenshot", shot_id: 10, full_page: false });
  assert.deepEqual(sent.at(-1), { frame: "screenshot_failed", shot_id: 10, reason: "busy" });
});
