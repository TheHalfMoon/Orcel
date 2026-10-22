// SG-000108 worker bootstrap. It imports nothing but the resolve guard,
// installs it, and only then loads the worker (entry.js), so every module
// the worker and playwright-core resolve passes the guard.
//
// playwright-core's bundled `ws` also probes optional native add-ons at
// import time; these switches tell it not to look for them at all (the
// guard would refuse them anyway).

import { installResolveGuard } from "./resolve-guard.js";

process.env.WS_NO_BUFFER_UTIL = "1";
process.env.WS_NO_UTF_8_VALIDATE = "1";
installResolveGuard();
await import("./entry.js");
