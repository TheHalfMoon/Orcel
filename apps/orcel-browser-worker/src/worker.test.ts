import assert from "node:assert/strict";
import { test } from "node:test";
import type { Piece } from "./extract/pieces.js";
import { validLaunch } from "./fixtures.js";
import { encodeFrame, type WorkerFrame } from "./protocol.js";
import type { VerifyProbe, VerifyResult } from "./verify.js";
import { NavigationError, Worker, type EngineSession, type Launcher, type LaunchSpec, type RoutePolicy } from "./worker.js";

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
  fetchText(url: string): Promise<{ url: string; status: number; media: string; text: string; truncated: boolean }> {
    return this.fetchBehavior(url);
  }
  navigate(url: string): Promise<{ url: string; status: number }> {
    this.navigations.push(url);
    return this.navigateBehavior(url);
  }
  observeBehavior: () => Promise<{ url: string; snapshot: { nodes: never[]; truncated: boolean } }> = async () => ({
    url: "https://fixture.test/",
    snapshot: { nodes: [], truncated: false }
  });
  observe(): Promise<{ url: string; snapshot: { nodes: never[]; truncated: boolean } }> {
    return this.observeBehavior();
  }
  discoverBehavior: () => Promise<{ url: string; truncated: boolean; tools: never[] }> = async () => ({
    url: "https://fixture.test/",
    truncated: false,
    tools: []
  });
  discover(): Promise<{ url: string; truncated: boolean; tools: never[] }> {
    return this.discoverBehavior();
  }
  extractBehavior: () => Promise<{ url: string; truncated: boolean; pieces: Piece[] }> = async () => ({
    url: "https://fixture.test/",
    truncated: false,
    pieces: [{ chunk: 0, content: "# Page" }]
  });
  extract(): Promise<{ url: string; truncated: boolean; pieces: Piece[] }> {
    return this.extractBehavior();
  }
  executions: Array<{ tool: string; fields: unknown }> = [];
  executeBehavior: () => Promise<{ url: string; status: number; structured: string[]; structuredComplete: boolean }> = async () => ({
    url: "https://fixture.test/search?q=rust",
    status: 200,
    structured: ['{"results":1}'],
    structuredComplete: true
  });
  execute(tool: string, fields: unknown): Promise<{ url: string; status: number; structured: string[]; structuredComplete: boolean }> {
    this.executions.push({ tool, fields });
    return this.executeBehavior();
  }
  activations: string[] = [];
  activateBehavior: (ref: string) => Promise<{ url: string; status: number }> = async () => ({ url: "https://fixture.test/next", status: 200 });
  activate(ref: string): Promise<{ url: string; status: number }> {
    this.activations.push(ref);
    return this.activateBehavior(ref);
  }
  downloadBehavior: (ref: string, path: string) => Promise<{ url: string; name: string; media: string; bytes: number }> = async () => ({
    url: "https://fixture.test/r.pdf",
    name: "r.pdf",
    media: "application/pdf",
    bytes: 10
  });
  download(ref: string, path: string): Promise<{ url: string; name: string; media: string; bytes: number }> {
    return this.downloadBehavior(ref, path);
  }
  verifyBehavior: (probes: VerifyProbe[]) => Promise<{ url: string; results: VerifyResult[] }> = async (probes) => ({
    url: "https://fixture.test/",
    results: probes.map(() => ({ result: "visible", count: 1 }))
  });
  verify(probes: VerifyProbe[]): Promise<{ url: string; results: VerifyResult[] }> {
    return this.verifyBehavior(probes);
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
  await worker.receive({ frame: "hello", generation: 10 });
  await worker.receive(validLaunch());
  await worker.receive({ frame: "ping", nonce: "n1" });
  await worker.receive({ frame: "shutdown" });
  assert.deepEqual(sent, [
    { frame: "hello", generation: 10, worker: "orcel-browser-worker" },
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
  for (const first of [validLaunch(), { frame: "ping", nonce: "n" }, { frame: "hello", generation: 9 }, { frame: "hello", generation: 11 }, { frame: "bogus" }]) {
    const { worker, sent, exits, launches } = harness();
    await worker.receive(first);
    assert.deepEqual(sent, [{ frame: "error", code: "protocol_violation" }]);
    assert.deepEqual(exits, [1]);
    assert.equal(launches.length, 0);
  }
  const { worker, sent, exits } = harness();
  await worker.receive({ frame: "hello", generation: 10 });
  await worker.receive({ frame: "hello", generation: 10 });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
  assert.deepEqual(exits, [1]);
});

test("a refused launch never reaches the launcher", async () => {
  const { worker, sent, exits, launches } = harness();
  await worker.receive({ frame: "hello", generation: 10 });
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
  await worker.receive({ frame: "hello", generation: 10 });
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
    await worker.receive({ frame: "hello", generation: 10 });
    await worker.receive(validLaunch());
    assert.deepEqual(sent.at(-1), { frame: "error", code: "launch_failed" });
    assert.deepEqual(exits, [1]);
  }
  {
    const engine = new FakeEngine();
    const { worker, sent, exits } = harness(async () => engine);
    await worker.receive({ frame: "hello", generation: 10 });
    await worker.receive(validLaunch());
    engine.crash();
    await worker.receive({ frame: "ping", nonce: "after" });
    assert.deepEqual(sent.at(-1), { frame: "error", code: "engine_exited" });
    assert.deepEqual(exits, [1]);
  }
  {
    const engine = new FakeEngine();
    const { worker, sent, exits } = harness(async () => engine);
    await worker.receive({ frame: "hello", generation: 10 });
    await worker.receive(validLaunch());
    await worker.violation();
    assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
    assert.deepEqual(exits, [1]);
    assert.equal(engine.closed, 1);
  }
  {
    const engine = new FakeEngine();
    const { worker, sent, exits } = harness(async () => engine);
    await worker.receive({ frame: "hello", generation: 10 });
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
  await worker.receive({ frame: "hello", generation: 10 });
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
  await worker.receive({ frame: "hello", generation: 10 });
  await worker.receive(validLaunch());
  await worker.receive({ frame: "ping", nonce: "boom" });
  await worker.receive({ frame: "ping", nonce: "after" });
  assert.deepEqual(exits, [1]);
  assert.equal(engine.closed, 1);
});

async function launched(engine = new FakeEngine()) {
  const h = harness(async () => engine);
  await h.worker.receive({ frame: "hello", generation: 10 });
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
  assert.deepEqual(sent.at(-1), { frame: "navigated", nav_id: 1, url: "https://fixture.test/a", status: 200 });
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
  await worker.receive({ frame: "hello", generation: 10 });
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
  await worker.receive({ frame: "hello", generation: 10 });
  await worker.receive({ frame: "route_decision", request_id: 1, allow: true });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "protocol_violation" });
  assert.deepEqual(exits, [1]);
});

test("observe reports a bounded snapshot or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  engine.observeBehavior = async () => ({ url: "https://fixture.test/r", snapshot: { nodes: [], truncated: true } });
  await worker.receive({ frame: "observe", obs_id: 3 });
  assert.deepEqual(sent.at(-1), { frame: "observed", obs_id: 3, url: "https://fixture.test/r", truncated: true, nodes: [] });
  engine.observeBehavior = async () => {
    throw new Error("snapshot timed out");
  };
  await worker.receive({ frame: "observe", obs_id: 4 });
  assert.deepEqual(sent.at(-1), { frame: "observation_failed", obs_id: 4 });
});

test("BR-07: verify reports one result per probe or a typed failure, and needs a launch", async () => {
  const engine = new FakeEngine();
  const { worker, sent } = harness(async () => engine);
  await worker.receive({ frame: "hello", generation: 10 });
  await worker.receive({ frame: "verify", ver_id: 1, probes: [{ probe: "visible_text", text: "Done" }] });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  const second = harness(async () => engine);
  await second.worker.receive({ frame: "hello", generation: 10 });
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

test("observe before launch fails closed", async () => {
  const { worker, sent, exits } = harness();
  await worker.receive({ frame: "hello", generation: 10 });
  await worker.receive({ frame: "observe", obs_id: 1 });
  assert.deepEqual(sent.at(-1), { frame: "error", code: "not_ready" });
  assert.deepEqual(exits, [1]);
});

test("activation runs outside the queue and reports a typed outcome", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "activate", act_id: 1, ref: "e5" });
  await settle();
  assert.deepEqual(sent.at(-1), { frame: "activated", act_id: 1, url: "https://fixture.test/next", status: 200 });
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
  assert.deepEqual(sent.at(-1), { frame: "downloaded", dl_id: 1, url: "https://fixture.test/r.pdf", name: "r.pdf", media: "application/pdf", bytes: 10 });
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
  assert.deepEqual(sent.at(-1), { frame: "discovered", disc_id: 2, url: "https://fixture.test/t", truncated: true, tools: [] });
  engine.discoverBehavior = async () => {
    throw new Error("snapshot failed");
  };
  await worker.receive({ frame: "discover", disc_id: 3 });
  assert.deepEqual(sent.at(-1), { frame: "discovery_failed", disc_id: 3 });
  const fresh = harness();
  await fresh.worker.receive({ frame: "hello", generation: 10 });
  await fresh.worker.receive({ frame: "discover", disc_id: 1 });
  assert.deepEqual(fresh.sent.at(-1), { frame: "error", code: "not_ready" });
});

test("a text fetch reports the document's text or a typed failure, and is busy during a navigation", async () => {
  const { worker, sent, engine } = await launched();
  await worker.receive({ frame: "fetch_text", fetch_id: 3, url: "https://fixture.test/robots.txt" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(sent.at(-1), { frame: "fetched_text", fetch_id: 3, url: "https://fixture.test/robots.txt", status: 200, media: "text/plain", text: "User-agent: *", truncated: false });
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
  assert.deepEqual(sent.at(-1), { frame: "extracted", ext_id: 4, url: "https://fixture.test/a", truncated: true, piece: 0, total: 3, chunk: 0, content: "one" });
  // Another id, or a piece past the end, fails without dropping the pieces.
  await worker.receive({ frame: "extract_more", ext_id: 5, piece: 1 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 5 });
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 9 });
  assert.deepEqual(sent.at(-1), { frame: "extraction_failed", ext_id: 4 });
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 1 });
  assert.equal((sent.at(-1) as { content: string }).content, "two");
  await worker.receive({ frame: "extract_more", ext_id: 4, piece: 2 });
  assert.deepEqual(sent.at(-1), { frame: "extracted", ext_id: 4, url: "https://fixture.test/a", truncated: true, piece: 2, total: 3, chunk: 1, content: "three" });
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
  await fresh.worker.receive({ frame: "hello", generation: 10 });
  await fresh.worker.receive({ frame: "extract", ext_id: 1, links: false, images: false });
  assert.deepEqual(fresh.sent.at(-1), { frame: "error", code: "not_ready" });
});

test("execution runs outside the queue and reports the opened document or a typed failure", async () => {
  const { worker, sent, engine } = await launched();
  const fields = [{ name: "q", control: "text", values: ["rust"] }];
  await worker.receive({ frame: "execute", exec_id: 1, tool: "search", fields });
  await settle();
  assert.deepEqual(engine.executions, [{ tool: "search", fields }]);
  assert.deepEqual(sent.at(-1), { frame: "executed", exec_id: 1, url: "https://fixture.test/search?q=rust", status: 200, structured: ['{"results":1}'], structured_complete: true });
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
