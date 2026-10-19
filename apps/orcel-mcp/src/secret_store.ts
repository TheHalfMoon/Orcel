/**
 * XP-19 edge client for the `orceld` secret store.
 *
 * The edge never writes a secret to a file. It asks `orceld` (the sole
 * authority, spawned over a private stdio pipe) to store or return a value
 * under a fixed name; `orceld` keeps it in DPAPI (Windows), the keychain
 * (macOS) or the Secret Service (Linux), and answers unavailable when no
 * platform store exists, never with a plaintext fallback.
 *
 * Values travel only in the request and response bodies on that pipe: never
 * in argv, the environment, an error message or a log line.
 */
import { KernelClient, type KernelResponse } from "./kernel.js";

/** The Ed25519 device private key (SG-000053 JWK, base64). */
export const DEVICE_KEY_SECRET = "device.key";

export const SECRET_NAMES = [DEVICE_KEY_SECRET] as const;
export type SecretName = (typeof SECRET_NAMES)[number];

export interface SecretStore {
  /** The stored value, or null when nothing is stored under `name`. */
  get(name: SecretName): Promise<string | null>;
  put(name: SecretName, value: string): Promise<void>;
}

export type KernelCall = (input: {
  workspaceId: string;
  capability: string;
  operation: string;
  target: string;
  arguments: Record<string, unknown>;
  timeoutMs: number;
}) => Promise<KernelResponse>;

/**
 * A failure message safe to show or log: the orceld failure code and its
 * fixed message, with any occurrence of `value` removed in case a caller
 * passed one through.
 */
function failure(response: KernelResponse, value?: string): Error {
  const code = response.error?.code ?? "PROVIDER_UNAVAILABLE";
  let message = response.error?.message ?? "the secret store did not answer";
  if (value !== undefined && value.length > 0) {
    message = message.split(value).join("[redacted]");
  }
  return new Error(`SECRET_STORE_${code}: ${message}`);
}

/** A secret store backed by `orceld` requests on one configured workspace. */
export class KernelSecretStore implements SecretStore {
  constructor(
    private readonly call: KernelCall,
    private readonly workspaceId: string
  ) {}

  async get(name: SecretName): Promise<string | null> {
    const response = await this.call({
      workspaceId: this.workspaceId,
      capability: "secret",
      operation: "get",
      target: name,
      arguments: {},
      timeoutMs: 60_000
    });
    if (!response.ok) {
      throw failure(response);
    }
    const value = (response.result as { value?: unknown } | undefined)?.value;
    if (value === null || value === undefined) {
      return null;
    }
    if (typeof value !== "string" || value.length === 0) {
      throw new Error("SECRET_STORE_PROVIDER_UNAVAILABLE: malformed secret store reply");
    }
    return value;
  }

  async put(name: SecretName, value: string): Promise<void> {
    if (value.length === 0) {
      throw new Error("SECRET_STORE_INVALID_REQUEST: empty secret");
    }
    const response = await this.call({
      workspaceId: this.workspaceId,
      capability: "secret",
      operation: "put",
      target: name,
      arguments: { value },
      timeoutMs: 60_000
    });
    if (!response.ok) {
      throw failure(response, value);
    }
  }
}

/**
 * Run `use` with a store on a fresh local `orceld` (ORCEL_DAEMON), then stop
 * that `orceld`. Requests carry no remote context.
 */
export async function withKernelSecretStore<T>(
  workspaceId: string,
  use: (store: SecretStore) => Promise<T>
): Promise<T> {
  const client = new KernelClient();
  try {
    return await use(new KernelSecretStore((input) => client.call(input), workspaceId));
  } finally {
    client.close();
  }
}
