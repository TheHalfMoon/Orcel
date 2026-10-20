import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

import {
  EndpointRefusedError,
  assertPrivateUnixEndpoint,
  connectEndpoint,
  currentUserSid,
  instanceSuffix,
  unixSocketPath,
  unixStateRoot,
  windowsPipeName,
} from "./orceld-transport.js";

const unixOnly = process.platform === "win32" ? "Unix socket rules" : false;
const windowsOnly = process.platform === "win32" ? false : "Windows pipe rules";

test("the Unix endpoint follows orcel_platform's state root rules", () => {
  assert.equal(
    unixStateRoot("darwin", { HOME: "/Users/a" }),
    "/Users/a/Library/Application Support/Orcel",
  );
  assert.equal(unixStateRoot("linux", { HOME: "/home/a" }), "/home/a/.local/state/orcel");
  assert.equal(unixStateRoot("linux", { HOME: "/home/a", XDG_STATE_HOME: "/s" }), "/s/orcel");
  // A relative or dotted XDG_STATE_HOME is ignored, as XDG requires.
  assert.equal(unixStateRoot("linux", { HOME: "/home/a", XDG_STATE_HOME: "rel" }), "/home/a/.local/state/orcel");
  assert.equal(unixStateRoot("linux", { HOME: "/home/a", XDG_STATE_HOME: "/s/../t" }), "/home/a/.local/state/orcel");
  assert.throws(() => unixStateRoot("linux", { HOME: "home" }), EndpointRefusedError);
  assert.throws(() => unixStateRoot("darwin", {}), EndpointRefusedError);
  assert.equal(
    unixSocketPath("linux", { HOME: "/h", ORCEL_APP_API_INSTANCE: "t-1" }),
    "/h/.local/state/orcel/run/app-api-t-1.sock",
  );
});

test("instance suffixes and pipe names match orceld", () => {
  assert.equal(instanceSuffix(undefined), "");
  assert.equal(instanceSuffix("abc-1"), "-abc-1");
  for (const bad of ["", "A", "a/b", "x".repeat(33), "a.b"]) {
    assert.throws(() => instanceSuffix(bad), EndpointRefusedError);
  }
  assert.equal(windowsPipeName("S-1-5-21-1-2-3-1001", {}), "\\\\.\\pipe\\orcel-S-1-5-21-1-2-3-1001-app");
  assert.equal(
    windowsPipeName("S-1-5-21-1-2-3-1001", { ORCEL_APP_API_INSTANCE: "x" }),
    "\\\\.\\pipe\\orcel-S-1-5-21-1-2-3-1001-app-x",
  );
  assert.throws(() => windowsPipeName("S-1-5-21\\..\\x", {}), EndpointRefusedError);
});

test("an endpoint another user could have placed is refused before connecting", { skip: unixOnly }, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "orcel-cr02-ep-"));
  try {
    const run = path.join(root, "run");
    await mkdir(run, { mode: 0o700 });
    const socketPath = path.join(run, "app-api.sock");
    // Missing.
    await assert.rejects(assertPrivateUnixEndpoint(socketPath), EndpointRefusedError);
    // A regular file.
    await writeFile(socketPath, "");
    await assert.rejects(assertPrivateUnixEndpoint(socketPath), /is not a socket/u);
    await rm(socketPath);
    // A symbolic link to a socket elsewhere.
    await symlink("/dev/null", socketPath);
    await assert.rejects(assertPrivateUnixEndpoint(socketPath), /is not a socket/u);
    await rm(socketPath);
    // A directory others can reach.
    await chmod(run, 0o755);
    await writeFile(socketPath, "");
    await assert.rejects(assertPrivateUnixEndpoint(socketPath), /grants group or other access/u);
    // A symlinked run directory.
    const linked = path.join(root, "linked");
    await symlink(run, linked);
    await assert.rejects(
      assertPrivateUnixEndpoint(path.join(linked, "app-api.sock")),
      /is not a directory/u,
    );
    // connectEndpoint applies the same checks, so no connection is tried.
    await assert.rejects(connectEndpoint(socketPath), EndpointRefusedError);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("the pipe name carries this user's SID; another account's pipe is not ours", { skip: windowsOnly }, async () => {
  const sid = await currentUserSid();
  assert.match(sid, /^S-1-5-/u);
  // SYSTEM's name for the same instance: this user never reaches it.
  const foreign = windowsPipeName("S-1-5-18", { ORCEL_APP_API_INSTANCE: "cr02-none" });
  await assert.rejects(connectEndpoint(foreign, { connectTimeoutMs: 2_000, allowUnverifiedWindowsPipe: true }));
});
