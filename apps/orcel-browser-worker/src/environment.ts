// SG-000108 worker environment hygiene.
//
// The host must start the worker with an environment built from an
// allowlist, never inherited: Node itself acts on variables such as
// NODE_OPTIONS (for example `--require`) before any worker code runs, so this
// in-process check cannot stop them (verified natively). It is a second line
// for variables Node does not consume at startup (Playwright debugging and
// download switches, proxies, key logging) and makes a misconfigured launch
// fail loudly. Names are compared case-insensitively, as on Windows.

const REFUSED_PREFIXES = ["NODE_", "PLAYWRIGHT_", "PW_", "ELECTRON_"];
const REFUSED_NAMES = [
  "DEBUG",
  "DEBUG_COLORS",
  "DEBUG_FD",
  "UV_THREADPOOL_SIZE",
  "SSLKEYLOGFILE",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  // OpenSSL reads these at startup (configuration, providers, trust roots).
  "OPENSSL_CONF",
  "OPENSSL_MODULES",
  "OPENSSL_ENGINES",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR"
];

/// Names of refused variables present in `env` (empty when clean).
export function refusedWorkerVariables(env: Record<string, string | undefined>): string[] {
  const refused: string[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const upper = name.toUpperCase();
    if (REFUSED_PREFIXES.some((prefix) => upper.startsWith(prefix)) || REFUSED_NAMES.includes(upper)) {
      refused.push(name);
    }
  }
  return refused.sort();
}

/// Minimum Node version: --disable-sigusr1 exists from 22.14, and
/// `module.registerHooks` (the resolve guard) from 22.15.
export const MIN_NODE_VERSION: readonly [number, number] = [22, 15];

/// Why the worker must not start under this Node, or null. The worker
/// requires --disable-sigusr1 (otherwise a same-user process can activate
/// the inspector, which opens a 127.0.0.1:9229 listener; verified natively)
/// and the resolve guard needs `module.registerHooks`: Node 22.15 or later.
export function startupRefusal(execArgv: readonly string[], nodeVersion: string): string | null {
  const match = /^v?(\d+)\.(\d+)\./.exec(nodeVersion);
  const [major, minor] = match ? [Number(match[1]), Number(match[2])] : [0, 0];
  const [needMajor, needMinor] = MIN_NODE_VERSION;
  if (major < needMajor || (major === needMajor && minor < needMinor)) {
    return `Node ${nodeVersion} is older than ${needMajor}.${needMinor}`;
  }
  // Exactly this one flag: a later --no-disable-sigusr1 would re-enable
  // activation (verified natively), and no --inspect*, --require, --import or
  // other Node option may accompany it.
  if (execArgv.length !== 1 || execArgv[0] !== "--disable-sigusr1") {
    return "Node must be started with exactly --disable-sigusr1";
  }
  return null;
}
