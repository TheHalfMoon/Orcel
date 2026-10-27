/// #438: how long Playwright may take to start the engine. Hosted CI
/// runners have exceeded 30 s on a cold start
/// (`launchPersistentContext: Timeout 30000ms exceeded`). The host's own
/// launch deadline (`WORKER_LAUNCH_TIMEOUT` in
/// crates/orcel-browser-host/src/worker_launch.rs, 60 s) must stay above
/// this; a host test checks it.
export const ENGINE_LAUNCH_TIMEOUT_MS = 50_000;
