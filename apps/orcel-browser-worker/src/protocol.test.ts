import assert from "node:assert/strict";
import { test } from "node:test";
import {
  encodeFrame,
  FrameDecoder,
  launchRefusal,
  MAX_FRAME_BYTES,
  parseHostFrame,
  ProtocolViolation,
} from "./protocol.js";
import { validLaunch } from "./fixtures.js";

function frameBytes(json: string): Buffer {
  const body = Buffer.from(json, "utf8");
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length, 0);
  return Buffer.concat([prefix, body]);
}

test("frames round-trip and decode incrementally across chunk boundaries", () => {
  const bytes = Buffer.concat([encodeFrame({ frame: "ping", nonce: "n-1" }), encodeFrame({ frame: "shutdown" })]);
  const decoder = new FrameDecoder();
  const seen: unknown[] = [];
  for (const byte of bytes) seen.push(...decoder.push(Buffer.from([byte])));
  assert.deepEqual(seen, [{ frame: "ping", nonce: "n-1" }, { frame: "shutdown" }]);
  assert.equal(decoder.pendingBytes, 0);
});

test("length bounds and non-JSON bodies are violations before buffering", () => {
  const oversized = Buffer.alloc(4);
  oversized.writeUInt32LE(MAX_FRAME_BYTES + 1, 0);
  assert.throws(() => new FrameDecoder().push(oversized), ProtocolViolation);
  assert.throws(() => new FrameDecoder().push(Buffer.alloc(4)), ProtocolViolation);
  assert.throws(() => new FrameDecoder().push(frameBytes("{not json")), ProtocolViolation);
  assert.throws(() => encodeFrame({ frame: "ping", nonce: "x".repeat(MAX_FRAME_BYTES) }), ProtocolViolation);
});

test("BR-02: form actions are closed, bounded and exact", () => {
  assert.deepEqual(parseHostFrame({ frame: "form_action", form_id: 3, action: "fill", ref: "e4", value: "" }), {
    frame: "form_action",
    form_id: 3,
    ref: "e4",
    act: { action: "fill", value: "" }
  });
  assert.deepEqual(
    parseHostFrame({ frame: "form_action", form_id: 3, action: "select", ref: "e4", values: ["Lisbon"], role: "combobox", name: "City" }),
    { frame: "form_action", form_id: 3, ref: "e4", act: { action: "select", values: ["Lisbon"] }, target: { role: "combobox", name: "City" } }
  );
  assert.deepEqual(parseHostFrame({ frame: "form_action", form_id: 3, action: "check", ref: "e4", checked: false }), {
    frame: "form_action",
    form_id: 3,
    ref: "e4",
    act: { action: "check", checked: false }
  });
  for (const bad of [
    { frame: "form_action", form_id: 3, action: "type", ref: "e4", value: "x" },
    { frame: "form_action", form_id: 3, action: "fill", ref: "e4" },
    { frame: "form_action", form_id: 3, action: "fill", ref: "e4", value: "x", checked: true },
    { frame: "form_action", form_id: 3, action: "fill", ref: "f1e4", value: "x" },
    { frame: "form_action", form_id: 3, action: "fill", ref: "css=#a", value: "x" },
    { frame: "form_action", form_id: 3, action: "fill", ref: "e4", value: "a\nb" },
    { frame: "form_action", form_id: 3, action: "fill", ref: "e4", value: "x".repeat(1025) },
    { frame: "form_action", form_id: 3, action: "fill", ref: "e4", value: 5 },
    { frame: "form_action", form_id: 3, action: "select", ref: "e4", values: [] },
    { frame: "form_action", form_id: 3, action: "select", ref: "e4", values: [""] },
    { frame: "form_action", form_id: 3, action: "select", ref: "e4", values: Array.from({ length: 17 }, () => "a") },
    { frame: "form_action", form_id: 3, action: "check", ref: "e4", checked: "true" },
    { frame: "form_action", form_id: 3, action: "check", ref: "e4", checked: true, role: "checkbox" },
    { frame: "form_action", form_id: 0, action: "check", ref: "e4", checked: true }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});

test("BR-02: press keys come from a closed list; hover has no input; waits are bounded", () => {
  assert.deepEqual(parseHostFrame({ frame: "form_action", form_id: 5, action: "press", ref: "e2", key: "Enter" }), {
    frame: "form_action",
    form_id: 5,
    ref: "e2",
    act: { action: "press", key: "Enter" }
  });
  assert.deepEqual(parseHostFrame({ frame: "form_action", form_id: 7, action: "press", ref: "e2", key: "Enter", accept_confirm: "Delete this item?" }), {
    frame: "form_action",
    form_id: 7,
    ref: "e2",
    act: { action: "press", key: "Enter" },
    accept_confirm: "Delete this item?"
  });
  for (const bad of ["", "a\nb", "x".repeat(1025), 5]) {
    assert.throws(() => parseHostFrame({ frame: "form_action", form_id: 7, action: "press", ref: "e2", key: "Enter", accept_confirm: bad }), ProtocolViolation);
  }
  assert.deepEqual(parseHostFrame({ frame: "form_action", form_id: 6, action: "hover", ref: "e3" }), {
    frame: "form_action",
    form_id: 6,
    ref: "e3",
    act: { action: "hover" }
  });
  assert.deepEqual(parseHostFrame({ frame: "wait_for", wait_id: 1, text: "Saved", appear: false, timeout_ms: 8000 }), {
    frame: "wait_for",
    wait_id: 1,
    text: "Saved",
    appear: false,
    timeout_ms: 8000
  });
  for (const bad of [
    { frame: "form_action", form_id: 5, action: "press", ref: "e2", key: "a" },
    { frame: "form_action", form_id: 5, action: "press", ref: "e2", key: "Control+A" },
    { frame: "form_action", form_id: 5, action: "press", ref: "e2", key: "Backspace" },
    { frame: "form_action", form_id: 5, action: "press", ref: "e2" },
    { frame: "form_action", form_id: 5, action: "hover", ref: "e2", key: "Enter" },
    { frame: "form_action", form_id: 5, action: "toString", ref: "e2" },
    { frame: "wait_for", wait_id: 1, text: "Saved", appear: true, timeout_ms: 8001 },
    { frame: "wait_for", wait_id: 1, text: "Saved", appear: true, timeout_ms: 0 },
    { frame: "wait_for", wait_id: 1, text: "", appear: true, timeout_ms: 100 },
    { frame: "wait_for", wait_id: 1, text: "Saved", appear: "yes", timeout_ms: 100 },
    { frame: "wait_for", wait_id: 1, text: "Saved", appear: true, timeout_ms: 100, ms: 1 }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});

test("BR-03: uploads carry an absolute host path and a main-frame ref only", () => {
  assert.deepEqual(parseHostFrame({ frame: "upload", up_id: 1, ref: "e3", path: "C:\\s\\up-1\\a.txt" }), {
    frame: "upload",
    up_id: 1,
    ref: "e3",
    path: "C:\\s\\up-1\\a.txt"
  });
  for (const bad of [
    { frame: "upload", up_id: 1, ref: "e3", path: "a.txt" },
    { frame: "upload", up_id: 1, ref: "f1e3", path: "C:\\s\\a.txt" },
    { frame: "upload", up_id: 1, ref: "e3" },
    { frame: "upload", up_id: 1, ref: "e3", path: "C:\\s\\a.txt", url: "https://x" },
    { frame: "upload", up_id: 0, ref: "e3", path: "C:\\s\\a.txt" }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});

test("BR-07: verify probes are closed, bounded and exact", () => {
  const probes = [
    { probe: "visible_role", role: "button", name: "Pay now" },
    { probe: "visible_text", text: "Order confirmed" },
    { probe: "value", ref: "e12" },
    { probe: "checked", ref: "f1e3" }
  ];
  assert.deepEqual(parseHostFrame({ frame: "verify", ver_id: 7, probes }), { frame: "verify", ver_id: 7, probes });
  for (const bad of [
    { frame: "verify", ver_id: 7, probes: [] },
    { frame: "verify", ver_id: 7, probes: Array.from({ length: 17 }, () => probes[1]) },
    { frame: "verify", ver_id: 0, probes },
    { frame: "verify", ver_id: 7, probes, extra: 1 },
    { frame: "verify", ver_id: 7, probes: [{ probe: "evaluate", script: "1" }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "visible_text", text: "" }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "visible_text", text: "x".repeat(1025) }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "visible_text", text: "a\nb" }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "visible_role", role: "Button", name: "x" }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "visible_role", role: "button" }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "value", ref: "css=#a" }] },
    { frame: "verify", ver_id: 7, probes: [{ probe: "checked", ref: "e1", value: "x" }] }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});

test("the host vocabulary is closed and exact", () => {
  assert.deepEqual(parseHostFrame({ frame: "hello", generation: 15 }), { frame: "hello", generation: 15 });
  const parsed = parseHostFrame(validLaunch());
  assert.deepEqual(JSON.parse(JSON.stringify(parsed)), validLaunch());
  assert.equal(parsed.frame === "launch" && Object.getPrototypeOf(parsed.env), null);
  for (const raw of [
    null,
    [],
    "hello",
    { generation: 15 },
    { frame: "navigate", url: "https://example.com" },
    { frame: "evaluate", script: "1+1" },
    { frame: "cdp", method: "Runtime.evaluate" },
    { frame: "hello", generation: 15, extra: true },
    { frame: "hello", generation: "1" },
    { frame: "hello" },
    { frame: "shutdown", now: true },
    { frame: "ping", nonce: "" },
    { frame: "ping", nonce: "a b" },
    { frame: "ping", nonce: "x".repeat(65) },
    { ...validLaunch(), extra: 1 },
    { ...validLaunch(), argv: [] },
    { ...validLaunch(), argv: "--headless" },
    { ...validLaunch(), argv: [...validLaunch().argv, 7] },
    { ...validLaunch(), argv: Array(65).fill("--headless") },
    { ...validLaunch(), engine: "C:\\x\\msedge.exe\u0000" },
    { ...validLaunch(), env: { PATH: 1 } },
    { ...validLaunch(), env: [] },
    { ...validLaunch(), env: Object.fromEntries(Array.from({ length: 17 }, (_, i) => [`K${i}`, "v"])) }
  ]) {
    assert.throws(() => parseHostFrame(raw), ProtocolViolation, JSON.stringify(raw)?.slice(0, 80));
  }
  // A prototype-polluting key is just an unexpected field.
  assert.throws(() => parseHostFrame(JSON.parse('{"frame":"shutdown","__proto__":{"x":1}}')), ProtocolViolation);
});

test("a launch frame must match the SG-000108 confinement contract", () => {
  assert.equal(launchRefusal(validLaunch()), null);
  const mutate = (change: (launch: ReturnType<typeof validLaunch>) => void) => {
    const launch = validLaunch();
    change(launch);
    return launchRefusal(launch);
  };
  const replaceArg = (prefix: string, value: string) => (launch: ReturnType<typeof validLaunch>) => {
    const index = launch.argv.findIndex((arg) => arg.startsWith(prefix));
    launch.argv[index] = value;
  };
  const refusals = [
    mutate((l) => (l.engine = "msedge.exe")),
    mutate((l) => (l.engine = "C:\\tools\\node.exe")),
    mutate((l) => (l.engine = "C:\\x\\..\\msedge.exe")),
    mutate((l) => (l.engine = "\\\\server\\share\\msedge.exe")),
    mutate((l) => (l.profile_dir = "relative\\profile")),
    mutate((l) => (l.env = { ...l.env, NODE_OPTIONS: "--require x" })),
    mutate((l) => (l.env = { ...l.env, USERPROFILE: "C:\\Users\\me" })),
    mutate((l) => l.argv.splice(0, 1)),
    mutate((l) => l.argv.splice(8, 1)),
    mutate((l) => l.argv.splice(9, 0, "--remote-debugging-port=9222")),
    mutate((l) => l.argv.splice(9, 0, "--enable-automation")),
    mutate(replaceArg("--user-data-dir=", "--user-data-dir=C:\\Users\\me\\AppData\\Local\\Microsoft\\Edge\\User Data")),
    mutate(replaceArg("--host-resolver-rules=", "--host-resolver-rules=MAP example.com 93.184.215.14:443")),
    mutate(replaceArg("--proxy-server=", "--proxy-server=http://127.0.0.1:9")),
    mutate(replaceArg("--proxy-bypass-list=", "--proxy-bypass-list=*;<-loopback>")),
    mutate(replaceArg("--proxy-bypass-list=", "--proxy-bypass-list=example.com")),
    mutate(replaceArg("--webrtc-ip-handling-policy=", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp")),
    mutate(replaceArg("--webrtc-ip-handling-policy=", "--webrtc-ip-handling-policy=default")),
    mutate(replaceArg("--disable-quic", "--enable-quic")),
    // #324: the disabled network-reaching features, exactly.
    mutate((l) => l.argv.splice(l.argv.findIndex((arg) => arg.startsWith("--disable-features=")), 1)),
    mutate(replaceArg("--disable-features=", "--disable-features=MediaRouter")),
    mutate(replaceArg("--disable-features=", "--enable-features=MediaRouter")),
    mutate(replaceArg("about:blank", "https://example.com/"))
  ];
  for (const [index, reason] of refusals.entries()) {
    assert.equal(typeof reason, "string", `case ${index} was accepted`);
  }
});

test("resolver rules and bypass list must equal the host grammar exactly", () => {
  const withArgs = (resolver: string, bypass: string) => {
    const launch = validLaunch();
    launch.argv[9] = `--host-resolver-rules=${resolver}`;
    launch.argv[11] = `--proxy-bypass-list=${bypass}`;
    return launchRefusal(launch);
  };
  // Accepted: several destinations, IPv4 and bracketed IPv6 pins, names in order.
  assert.equal(
    withArgs(
      "MAP example.com 93.184.215.14:443, MAP docs.example.org [2606:2800:21f:cb07:6820:80da:af6b:8b2c]:443, MAP * ~NOTFOUND",
      "example.com;docs.example.org;<-loopback>"
    ),
    null
  );
  const refused: Array<[string, string]> = [
    // Reviewer-demonstrated bypasses of the previous shape-only check.
    ["MAP example.com 93.184.215.14:443, MAP * ~NOTFOUND", "10.0.0.0/8;example.com;<-loopback>"],
    ["MAP *.com 10.0.0.1:80, MAP * ~NOTFOUND", "*.com;<-loopback>"],
    ["MAP example.com 93.184.215.14:443, EXCLUDE evil.example, MAP * ~NOTFOUND", "example.com;<-loopback>"],
    // Wrong port, unbracketed IPv6, bad address, bad or duplicate names.
    ["MAP example.com 93.184.215.14:8443, MAP * ~NOTFOUND", "example.com;<-loopback>"],
    ["MAP example.com 2606:2800::1:443, MAP * ~NOTFOUND", "example.com;<-loopback>"],
    ["MAP example.com 999.1.1.1:443, MAP * ~NOTFOUND", "example.com;<-loopback>"],
    ["MAP example.com [::ffff:zz]:443, MAP * ~NOTFOUND", "example.com;<-loopback>"],
    ["MAP example.com [fe80::1%eth0]:443, MAP * ~NOTFOUND", "example.com;<-loopback>"],
    ["MAP Example.com 93.184.215.14:443, MAP * ~NOTFOUND", "Example.com;<-loopback>"],
    ["MAP a.123 93.184.215.14:443, MAP * ~NOTFOUND", "a.123;<-loopback>"],
    ["MAP example.com 93.184.215.14:443, MAP example.com 93.184.215.15:443, MAP * ~NOTFOUND", "example.com;example.com;<-loopback>"],
    // Missing or extra catch-all, empty map.
    ["MAP example.com 93.184.215.14:443", "example.com;<-loopback>"],
    ["MAP * ~NOTFOUND", "<-loopback>"],
    ["MAP example.com 93.184.215.14:443, MAP * ~NOTFOUND, MAP evil.example 10.0.0.1:443", "example.com;<-loopback>"],
    // Bypass list not exactly the mapped names in order.
    ["MAP a.example 93.184.215.14:443, MAP b.example 93.184.215.14:443, MAP * ~NOTFOUND", "b.example;a.example;<-loopback>"],
    ["MAP example.com 93.184.215.14:443, MAP * ~NOTFOUND", "example.com;evil.example;<-loopback>"],
    ["MAP example.com 93.184.215.14:443, MAP * ~NOTFOUND", "example.com"],
    ["MAP example.com 93.184.215.14:443, MAP * ~NOTFOUND", "example.com;<-loopback>;<local>"]
  ];
  for (const [resolver, bypass] of refused) {
    assert.equal(typeof withArgs(resolver, bypass), "string", `${resolver} | ${bypass}`);
  }
  const tooMany = Array.from({ length: 17 }, (_, i) => `MAP h${i}.example 93.184.215.14:443`);
  assert.equal(
    typeof withArgs([...tooMany, "MAP * ~NOTFOUND"].join(", "), [...tooMany.map((_, i) => `h${i}.example`), "<-loopback>"].join(";")),
    "string"
  );
});

test("paths with dot segments are refused and invalid UTF-8 is a violation", () => {
  for (const profile of ["C:\\x\\..", "C:\\x\\.\\y", "C:\\x\\\\y", "C:\\x\\..\\y"]) {
    const launch = validLaunch();
    launch.profile_dir = profile;
    launch.argv[7] = `--user-data-dir=${profile}`;
    assert.equal(typeof launchRefusal(launch), "string", profile);
  }
  const body = Buffer.from([0x7b, 0x22, 0x66, 0xff, 0x22, 0x7d]);
  const prefix = Buffer.alloc(4);
  prefix.writeUInt32LE(body.length, 0);
  assert.throws(() => new FrameDecoder().push(Buffer.concat([prefix, body])), ProtocolViolation);
});

test("navigation frames are exact, bounded and https-only", () => {
  assert.deepEqual(parseHostFrame({ frame: "navigate", nav_id: 1, url: "https://fixture.test/a" }), {
    frame: "navigate",
    nav_id: 1,
    url: "https://fixture.test/a"
  });
  assert.deepEqual(parseHostFrame({ frame: "route_decision", request_id: 3, allow: false }), {
    frame: "route_decision",
    request_id: 3,
    allow: false
  });
  for (const bad of [
    { frame: "navigate", nav_id: 0, url: "https://fixture.test/" },
    { frame: "navigate", nav_id: 1.5, url: "https://fixture.test/" },
    { frame: "navigate", nav_id: "1", url: "https://fixture.test/" },
    { frame: "navigate", nav_id: 1, url: "http://fixture.test/" },
    { frame: "navigate", nav_id: 1, url: "javascript:alert(1)" },
    { frame: "navigate", nav_id: 1, url: `https://fixture.test/${"a".repeat(2100)}` },
    { frame: "navigate", nav_id: 1, url: "https://fixture.test/\n" },
    { frame: "navigate", nav_id: 1, url: "https://fixture.test/", extra: 1 },
    { frame: "route_decision", request_id: 1, allow: "yes" },
    { frame: "route_decision", request_id: -1, allow: true },
    { frame: "route_decision", request_id: 1 },
    { frame: "route_request", request_id: 1, kind: "document", url: "https://x.test/", origin: "" }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});

test("a trusted test certificate is accepted only with loopback fixture pins", () => {
  const spki = "--ignore-certificate-errors-spki-list=9WXyCO8+Q/VzmaLHa1slFXl6NaVXmdAETaqFwlDDoQo=";
  const withCertificate = (argv: string[]): string[] => [...argv.slice(0, -1), spki, argv[argv.length - 1] as string];
  const publicLaunch = validLaunch(); // pins a public address
  const loopbackArgv = publicLaunch.argv.map((arg) =>
    arg.startsWith("--host-resolver-rules=") ? arg.replace("93.184.215.14", "127.0.0.1") : arg
  );
  assert.equal(launchRefusal({ ...publicLaunch, argv: loopbackArgv }), null, "the loopback base argv must itself be valid");
  assert.equal(launchRefusal({ ...publicLaunch, argv: withCertificate(loopbackArgv) }), null);
  // A public pin makes the certificate flag a refusal.
  assert.match(launchRefusal({ ...publicLaunch, argv: withCertificate(publicLaunch.argv) }) ?? "", /loopback fixture pins/);
  // Malformed hashes, other flags in that slot, and a second extra flag.
  for (const bad of ["--ignore-certificate-errors-spki-list=abc", "--ignore-certificate-errors", "--no-sandbox"]) {
    assert.notEqual(launchRefusal({ ...publicLaunch, argv: [...loopbackArgv.slice(0, -1), bad, "about:blank"] }), null, bad);
  }
  assert.notEqual(launchRefusal({ ...publicLaunch, argv: [...withCertificate(loopbackArgv).slice(0, -1), spki, "about:blank"] }), null);
});

test("download frames carry a strict ref and an absolute .part staging path", () => {
  assert.deepEqual(parseHostFrame({ frame: "download", dl_id: 1, ref: "e5", path: "C:\\stage\\dl-1.part" }), {
    frame: "download",
    dl_id: 1,
    ref: "e5",
    path: "C:\\stage\\dl-1.part"
  });
  for (const bad of [
    { frame: "download", dl_id: 1, ref: "e5", path: "dl-1.part" },
    { frame: "download", dl_id: 1, ref: "e5", path: "C:\\stage\\report.pdf" },
    { frame: "download", dl_id: 1, ref: "e5", path: "\\server\share\dl.part" },
    { frame: "download", dl_id: 1, ref: "x", path: "C:\\stage\\dl-1.part" },
    { frame: "download", dl_id: 0, ref: "e5", path: "C:\\stage\\dl-1.part" },
    { frame: "download", dl_id: 1, ref: "e5", path: "C:\\stage\\dl-1.part", extra: 1 }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad));
  }
});

test("discover frames carry only a positive id", () => {
  assert.deepEqual(parseHostFrame({ frame: "discover", disc_id: 4 }), { frame: "discover", disc_id: 4 });
  for (const bad of [{ frame: "discover", disc_id: 0 }, { frame: "discover", disc_id: 1, script: "x" }, { frame: "discover" }]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad));
  }
});

test("fetch_text frames carry a positive id and an https URL", () => {
  const ok = { frame: "fetch_text", fetch_id: 2, url: "https://fixture.test/robots.txt" };
  assert.deepEqual(parseHostFrame(ok), ok);
  for (const bad of [
    { frame: "fetch_text", fetch_id: 0, url: "https://fixture.test/robots.txt" },
    { frame: "fetch_text", fetch_id: 1, url: "http://fixture.test/robots.txt" },
    { frame: "fetch_text", fetch_id: 1, url: "https://fixture.test/" + "a".repeat(3000) },
    { frame: "fetch_text", fetch_id: 1, url: "https://fixture.test/", method: "POST" }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad));
  }
});

test("extract frames carry a positive id, boolean options and a bounded piece", () => {
  const ok = { frame: "extract", ext_id: 2, links: true, images: false };
  assert.deepEqual(parseHostFrame(ok), ok);
  assert.deepEqual(parseHostFrame({ frame: "extract_more", ext_id: 2, piece: 95 }), { frame: "extract_more", ext_id: 2, piece: 95 });
  for (const bad of [
    { frame: "extract", ext_id: 0, links: true, images: false },
    { frame: "extract", ext_id: 1, links: "yes", images: false },
    { frame: "extract", ext_id: 1, links: true },
    { frame: "extract", ext_id: 1, links: true, images: false, selector: "body" },
    { frame: "extract_more", ext_id: 1, piece: 0 },
    { frame: "extract_more", ext_id: 1, piece: 96 },
    { frame: "extract_more", ext_id: 1 }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad));
  }
});

test("execute frames carry a valid tool name and bounded typed fields", () => {
  const ok = { frame: "execute", exec_id: 3, tool: "search_reports", fields: [{ name: "q", control: "text", values: ["rust"] }] };
  assert.deepEqual(parseHostFrame(ok), ok);
  for (const bad of [
    { ...ok, tool: "bad name" },
    { ...ok, tool: 'x"]' },
    { ...ok, exec_id: 0 },
    { ...ok, fields: [{ name: "q", control: "hidden", values: ["x"] }] },
    { ...ok, fields: [{ name: "q", control: "text", values: [1] }] },
    { ...ok, fields: [{ name: "q\u0007", control: "text", values: ["x"] }] },
    { ...ok, fields: [{ name: "q", control: "text", values: ["x"], script: "y" }] },
    { ...ok, fields: Array.from({ length: 33 }, (_, i) => ({ name: `f${i}`, control: "text", values: [] })) },
    { ...ok, fields: [{ name: "q", control: "text", values: ["x".repeat(1025)] }] },
    { ...ok, extra: true }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});

test("BR-01 activate and download frames may carry the approved role and name, both or neither", () => {
  const path = "C:\\stage\\dl-2.part";
  assert.deepEqual(parseHostFrame({ frame: "activate", act_id: 1, ref: "e5" }), { frame: "activate", act_id: 1, ref: "e5" });
  assert.deepEqual(parseHostFrame({ frame: "activate", act_id: 1, ref: "e5", role: "link", name: "Annual review" }), {
    frame: "activate",
    act_id: 1,
    ref: "e5",
    target: { role: "link", name: "Annual review" }
  });
  assert.deepEqual(parseHostFrame({ frame: "download", dl_id: 2, ref: "e7", path, role: "link", name: "Q3.pdf" }), {
    frame: "download",
    dl_id: 2,
    ref: "e7",
    path,
    target: { role: "link", name: "Q3.pdf" }
  });
  for (const bad of [
    { frame: "activate", act_id: 1, ref: "e5", role: "link" },
    { frame: "activate", act_id: 1, ref: "e5", name: "x" },
    { frame: "activate", act_id: 1, ref: "e5", role: "Link", name: "x" },
    { frame: "activate", act_id: 1, ref: "e5", role: "link", name: "" },
    { frame: "activate", act_id: 1, ref: "e5", role: "link", name: "a\u0000b" },
    { frame: "activate", act_id: 1, ref: "e5", role: "link", name: "x".repeat(1025) },
    { frame: "download", dl_id: 2, ref: "e7", path, role: "link" }
  ]) {
    assert.throws(() => parseHostFrame(bad), ProtocolViolation, JSON.stringify(bad).slice(0, 80));
  }
});
