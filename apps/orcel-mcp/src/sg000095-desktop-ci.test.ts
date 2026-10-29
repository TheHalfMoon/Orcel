import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import test from "node:test";

const repo = resolve(import.meta.dirname, "..", "..", "..");
const hostDir = join(repo, "apps", "orcel-computer-host");

test("SG-000095 disposable-window suite runs in the single native Go qualification", () => {
  // SG-000094 owns the only go test ./... invocation. Starting a second
  // concurrent process from a separate Node test file makes two independent
  // Windows UI automation test runners compete for the same foreground and
  // human-input tick. We mechanically prove SG-000095 is included in the
  // existing full Go qualification instead of launching another runner.
  const native = readFileSync(
    join(hostDir, "native_input_qualification_windows_test.go"),
    "utf8"
  );
  const qualifier = readFileSync(
    join(repo, "apps", "orcel-mcp", "src", "sg000094-host-ci.test.ts"),
    "utf8"
  );
  for (const name of [
    "TestSG95NativeSemanticValueAndInputAgainstDisposableApp",
    "TestSG95NativeWindowLifecycleOnDisposableApp",
    "TestSG95NativeFreshnessAndBoundsFailClosed"
  ]) {
    assert.match(native, new RegExp("func " + name + "\\("), name);
  }
  assert.ok(
    qualifier.includes('const unit = go(["test", "./..."]);'),
    "SG-000094 must execute the full SG-000095 Go suite exactly once"
  );

  // Slow shared Windows CI runners must not turn a valid disposable WinForms
  // startup into a false failure after 15 seconds, nor wait indefinitely.
  const helper = readFileSync(
    join(hostDir, "native_qualification_windows_test.go"),
    "utf8"
  );
  assert.match(helper, /case <-time\.After\(45 \* time\.Second\)/);
  assert.match(helper, /strings\.HasPrefix\(line, "READY:"\)/);
  assert.match(helper, /cmd\.Process\.Kill\(\)/);
});

test("SG-000095 native mutation source stays private, bounded, and excludes donor widening", () => {
  const required = [
    "native_actions_windows.go",
    "native_input_windows.go",
    "native_window_actions_windows.go",
    "native_input_qualification_windows_test.go"
  ];
  for (const name of required) {
    assert.equal(existsSync(join(hostDir, name)), true, name);
  }
  const source = required
    .filter((name) => !name.endsWith("_test.go"))
    .map((name) => readFileSync(join(hostDir, name), "utf8"))
    .join("\n");

  assert.match(source, /SendInput/);
  assert.match(source, /GetLastInputInfo/);
  assert.match(source, /expected.*input/i);
  assert.match(source, /semantic/i);
  assert.match(source, /window_close/);

  // Semantic UIA resolution may touch hostile provider trees; enforce
  // finite traversal ceilings before dispatch. SG-000128 slice 1b (recorded
  // rule change): the lookup uses the bounded root search, so an element
  // orceld issued from a scoped read is found; the observation caps stay.
  const semantic = readFileSync(join(hostDir, "native_actions_windows.go"), "utf8");
  assert.match(semantic, /depth > maxRootSearchDepth/);
  assert.match(semantic, /\*remaining <= 0/);
  assert.match(semantic, /remaining := maxRootSearchNodes/);
  const bounds = readFileSync(join(hostDir, "protocol.go"), "utf8");
  assert.match(bounds, /maxTreeNodes = 256\b/);
  assert.match(bounds, /maxTreeDepth = 8\b/);
  assert.match(bounds, /maxRootSearchNodes = 4096\b/);
  assert.match(bounds, /maxRootSearchDepth = 64\b/);
  assert.match(semantic, /walkerSlotGetNextSiblingElement/);
  assert.match(semantic, /findElementByRuntimeID\(uiaElement\{current\}, walker, key, depth\+1, remaining\)/);
  assert.doesNotMatch(semantic, /walkerChildren\(walker, root\)/);
  assert.match(semantic, /Hidden\/provider-only siblings must consume traversal budget too/);
  assert.match(semantic, /oleRelease\(next\)/);

  for (const forbidden of [
    /ListenAndServe\s*\(/,
    /\bnet\.Listen\s*\(/,
    /["']net\/http["']/,
    /["']os\/exec["']/,
    /ffmpeg\.exe/i,
    /CreateProcess|ShellExecute/i,
    /runas/i,
    /TrustedInstaller/i,
    /SYSTEM authority/i
  ]) {
    assert.doesNotMatch(source, forbidden);
  }
});

test("SG-000095 authority can be granted only by local lifecycle code, never MCP or relay", () => {
  const desktop = readFileSync(join(repo, "apps", "orcel-mcp", "src", "desktop.ts"), "utf8");
  const lifecycle = readFileSync(join(repo, "crates", "orcel-lifecycle", "src", "full_control.rs"), "utf8");
  const daemon = readFileSync(join(repo, "crates", "orceld", "src", "sg000039_main.rs"), "utf8");

  assert.match(lifecycle, /ApprovalPrompt::new_strong/);
  assert.match(lifecycle, /grant_full_user/);
  assert.match(lifecycle, /active_runtime_session/);
  assert.doesNotMatch(desktop, /grant_full_user|issue_full_control|LocalGrantProof|full-control grant/);
  assert.match(daemon, /is_full_user_desktop_shape/);
  assert.match(daemon, /Remote Full Control remains unavailable|remote full control/i);
});
