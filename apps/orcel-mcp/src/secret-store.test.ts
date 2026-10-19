import assert from "node:assert/strict";
import test from "node:test";
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateDeviceKeyPair, privateKeyMatchesIdentity, publicDeviceIdentity } from "./device_identity.js";
import { buildDaemonEnv, type KernelResponse } from "./kernel.js";
import { enableRemote } from "./remote_enrollment.js";
import { DEVICE_KEY_SECRET, KernelSecretStore, type KernelCall, type SecretName, type SecretStore } from "./secret_store.js";
import { LEGACY_PLAINTEXT_KEY_MESSAGE, loadDeviceKey } from "./uplink_state.js";

const DEVICE = "dev-" + "c".repeat(32);

class MemorySecrets implements SecretStore {
  readonly values = new Map<string, string>();
  puts = 0;
  async get(name: SecretName): Promise<string | null> {
    return this.values.get(name) ?? null;
  }
  async put(name: SecretName, value: string): Promise<void> {
    this.puts += 1;
    this.values.set(name, value);
  }
}

/** A relay that accepts every device registration. */
const relay = async (): Promise<Response> => new Response(JSON.stringify({ ok: true }), { status: 201 });

function everyFile(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? everyFile(join(dir, entry.name)) : [join(dir, entry.name)]
  );
}

/** Run `body` with every stderr/stdout write and console line captured. */
async function captured<T>(body: () => Promise<T>): Promise<{ result: T; output: string }> {
  const lines: string[] = [];
  const stderr = process.stderr.write.bind(process.stderr);
  const stdout = process.stdout.write.bind(process.stdout);
  const original = { error: console.error, warn: console.warn, info: console.info, debug: console.debug };
  const keep = (chunk: unknown) => {
    lines.push(String(chunk));
    return true;
  };
  process.stderr.write = keep as typeof process.stderr.write;
  process.stdout.write = keep as typeof process.stdout.write;
  console.error = console.warn = console.info = console.debug = (...args: unknown[]) => void lines.push(args.map(String).join(" "));
  try {
    const result = await body();
    return { result, output: lines.join("\n") };
  } finally {
    process.stderr.write = stderr;
    process.stdout.write = stdout;
    Object.assign(console, original);
  }
}

test("XP-19 enable keeps the private key in the secret store and writes only the public identity", async () => {
  const dir = mkdtempSync(join(tmpdir(), "orcel-xp19-enable-"));
  const deviceKeyPath = join(dir, "device", "device_key.json");
  const uplinkPath = join(dir, "remote", "uplink.json");
  const secrets = new MemorySecrets();
  const { result: first, output } = await captured(() =>
    enableRemote({ relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", deviceKeyPath, uplinkPath, secrets, fetch: relay, nowMs: 1 })
  );
  assert.equal(first.created, true);
  const privateKey = secrets.values.get(DEVICE_KEY_SECRET);
  assert.ok(privateKey !== undefined && privateKey.length > 0, "the private key went to the secret store");
  const record = JSON.parse(readFileSync(deviceKeyPath, "utf8")) as Record<string, unknown>;
  assert.deepEqual(Object.keys(record).sort(), ["createdAtMs", "deviceId", "epoch", "publicKeyJwkBase64"]);
  assert.ok(privateKeyMatchesIdentity(privateKey, String(record.publicKeyJwkBase64)));
  const privateD = (JSON.parse(Buffer.from(privateKey, "base64").toString("utf8")) as { d: string }).d;
  for (const file of everyFile(dir)) {
    const text = readFileSync(file, "utf8");
    assert.ok(!text.includes(privateKey) && !text.includes(privateD), `${file} holds private key material`);
  }
  assert.ok(!output.includes(privateKey) && !output.includes(privateD), "no private key material in any log line");

  // A second enable reuses the stored key and stores nothing new.
  const second = await enableRemote({ relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", deviceKeyPath, uplinkPath, secrets, fetch: relay, nowMs: 2 });
  assert.equal(second.created, false);
  assert.equal(second.deviceId, first.deviceId);
  assert.equal(secrets.puts, 1);
  assert.equal((await loadDeviceKey(deviceKeyPath, secrets)).privateKeyJwkBase64, privateKey);
});

test("XP-19 a plaintext key from an earlier version is refused until the user migrates it", async () => {
  const dir = mkdtempSync(join(tmpdir(), "orcel-xp19-legacy-"));
  const deviceKeyPath = join(dir, "device_key.json");
  const pair = generateDeviceKeyPair(DEVICE, 1, 1);
  writeFileSync(deviceKeyPath, JSON.stringify(pair));
  const secrets = new MemorySecrets();
  await assert.rejects(loadDeviceKey(deviceKeyPath, secrets), (error: Error) => error.message === LEGACY_PLAINTEXT_KEY_MESSAGE);
  await assert.rejects(
    enableRemote({ relayOrigin: "https://relay.orcel.example", defaultWorkspace: "default", deviceKeyPath, uplinkPath: join(dir, "uplink.json"), secrets, fetch: relay, nowMs: 1 }),
    /migrate-secrets/
  );
  assert.equal(secrets.puts, 0, "the edge never moves a plaintext key itself");
  assert.equal(readFileSync(deviceKeyPath, "utf8"), JSON.stringify(pair), "the edge leaves migration to orceld");
});

test("XP-19 a stored key that does not match the device identity is refused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "orcel-xp19-mismatch-"));
  const deviceKeyPath = join(dir, "device_key.json");
  const pair = generateDeviceKeyPair(DEVICE, 1, 1);
  writeFileSync(deviceKeyPath, JSON.stringify(publicDeviceIdentity(pair)));
  const secrets = new MemorySecrets();
  secrets.values.set(DEVICE_KEY_SECRET, generateDeviceKeyPair(DEVICE, 1, 1).privateKeyJwkBase64);
  await assert.rejects(loadDeviceKey(deviceKeyPath, secrets), /does not match/);
  secrets.values.set(DEVICE_KEY_SECRET, Buffer.from("{}").toString("base64"));
  await assert.rejects(loadDeviceKey(deviceKeyPath, secrets), /does not match/);
  secrets.values.set(DEVICE_KEY_SECRET, pair.privateKeyJwkBase64);
  assert.equal((await loadDeviceKey(deviceKeyPath, secrets)).deviceId, DEVICE);
});

test("XP-19 the kernel client sends values only in the request body and never echoes them in errors", async () => {
  const value = "xp19-edge-canary-" + Date.now().toString(16);
  const sent: Parameters<KernelCall>[0][] = [];
  const answer = (response: Partial<KernelResponse>): KernelCall => async (input) => {
    sent.push(input);
    return { version: 1, request_id: "r", ok: false, ...response } as KernelResponse;
  };
  const stored = new KernelSecretStore(answer({ ok: true, result: { stored: true } }), "default");
  await stored.put(DEVICE_KEY_SECRET, value);
  assert.deepEqual(sent[0], {
    workspaceId: "default",
    capability: "secret",
    operation: "put",
    target: DEVICE_KEY_SECRET,
    arguments: { value },
    timeoutMs: 60_000
  });
  const reader = new KernelSecretStore(answer({ ok: true, result: { value } }), "default");
  assert.equal(await reader.get(DEVICE_KEY_SECRET), value);
  assert.equal(sent[1]?.operation, "get");
  assert.deepEqual(sent[1]?.arguments, {});
  const missing = new KernelSecretStore(answer({ ok: true, result: { value: null } }), "default");
  assert.equal(await missing.get(DEVICE_KEY_SECRET), null);

  const echoing = new KernelSecretStore(
    answer({ ok: false, error: { code: "PROVIDER_UNAVAILABLE", message: `store said ${value}` } }),
    "default"
  );
  await assert.rejects(echoing.put(DEVICE_KEY_SECRET, value), (error: Error) => {
    assert.match(error.message, /^SECRET_STORE_PROVIDER_UNAVAILABLE: /);
    assert.ok(!error.message.includes(value));
    return true;
  });
  const unavailable = new KernelSecretStore(
    answer({ ok: false, error: { code: "PROVIDER_UNAVAILABLE", message: "XP-19 secret store unavailable: no Secret Service keyring is reachable on the D-Bus session bus" } }),
    "default"
  );
  await assert.rejects(unavailable.get(DEVICE_KEY_SECRET), /unavailable: no Secret Service keyring/);
});

test("XP-19 orceld gets the per-user state and session bus variables, never a secret-like one", () => {
  const env = buildDaemonEnv({
    HOME: "/home/u",
    XDG_STATE_HOME: "/home/u/.local/state",
    XDG_RUNTIME_DIR: "/run/user/1000",
    DBUS_SESSION_BUS_ADDRESS: "unix:path=/run/user/1000/bus",
    ORCEL_DEVICE_KEY_SECRET: "must-not-leak",
    ORCEL_DAEMON: "/opt/orcel/orceld"
  });
  assert.equal(env.HOME, "/home/u");
  assert.equal(env.XDG_STATE_HOME, "/home/u/.local/state");
  assert.equal(env.XDG_RUNTIME_DIR, "/run/user/1000");
  assert.equal(env.DBUS_SESSION_BUS_ADDRESS, "unix:path=/run/user/1000/bus");
  assert.equal(env.ORCEL_DEVICE_KEY_SECRET, undefined);
});

test("XP-19 no edge source writes the private key to a file, argv or the environment", () => {
  const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
  for (const file of ["remote_enrollment.ts", "uplink_state.ts", "secret_store.ts", "transports/relay_device.ts", "entrypoints/remote_admin.ts"]) {
    const text = readFileSync(join(src, file), "utf8");
    assert.ok(!/JSON\.stringify\(pair\)/.test(text), `${file} serializes the whole key pair`);
    assert.ok(!/process\.env\.[A-Z_]*\s*=/.test(text), `${file} sets an environment variable`);
    assert.ok(!/spawn\([^)]*privateKey/.test(text), `${file} passes key material in argv`);
  }
});
