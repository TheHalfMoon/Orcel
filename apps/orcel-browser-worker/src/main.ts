// SG-000108 worker bootstrap. It imports nothing but the startup checks and
// the resolve guard (built-ins only), refuses an unsupported Node with the
// typed startup message, installs the guard, closes the ways code could run
// outside it, and only then loads the worker (entry.js), so every module the
// worker and playwright-core resolve passes the guard.
//
// playwright-core's bundled `ws` also probes optional native add-ons at
// import time; these switches tell it not to look for them at all (the
// guard would refuse them anyway).

import { startupRefusal } from "./environment.js";
import { closeUnguardedRuntimes, installResolveGuard } from "./resolve-guard.js";

const startup = startupRefusal(process.execArgv, process.version);
if (startup !== null) {
  process.stderr.write(`orcel-browser-worker: refused to start: ${startup}\n`);
  process.exit(2);
}
process.env.WS_NO_BUFFER_UTIL = "1";
process.env.WS_NO_UTF_8_VALIDATE = "1";
try {
  installResolveGuard();
  closeUnguardedRuntimes();
} catch (error) {
  process.stderr.write(`orcel-browser-worker: refused to start: ${String((error as Error).message)}\n`);
  process.exit(2);
}
await import("./entry.js");
