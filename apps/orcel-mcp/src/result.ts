import type { KernelResponse } from "./kernel.js";

/** The largest screenshot orceld returns, base64 included (2 MiB of PNG). */
const MAX_SCREENSHOT_BASE64 = Math.ceil((2 * 1024 * 1024) / 3) * 4;
const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/**
 * Project a kernel response into an MCP tool result.
 *
 * This is the single authoritative result projection for the local MCP edge.
 * Transport adapters must reuse this function and must not define an
 * independent projection that could add authority or leak internal metadata.
 *
 * The shape is byte-compatible with the Orcel v0.1 public MCP surface:
 * failures return `isError: true` with a JSON error envelope, successes
 * return the kernel result plus bounded evidence. No transport identity,
 * device identity, token material, or approval secrets are added here.
 */
export function projectKernelResult(response: KernelResponse) {
  if (!response.ok) {
    return {
      isError: true,
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(
            {
              error: response.error ?? {
                code: "INTERNAL_ERROR",
                message: "orceld returned an unspecified failure"
              }
            },
            null,
            2
          )
        }
      ]
    };
  }

  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify(
          {
            result: response.result,
            evidence: response.evidence
          },
          null,
          2
        )
      }
    ]
  };
}

/**
 * SG-000135 OB-03: project a `browser_screenshot` result. The PNG crosses as
 * MCP image content (the only content besides the JSON text, and never
 * inside it); the JSON keeps every other field of the result, including
 * the image's SHA-256. A result whose image is missing, not strict base64,
 * past the bound or not a PNG is an error, never passed on.
 */
export function projectScreenshotResult(response: KernelResponse) {
  if (!response.ok) return projectKernelResult(response);
  const result = (response.result ?? {}) as Record<string, unknown>;
  const { png_base64: data, ...rest } = result;
  const valid =
    typeof data === "string" &&
    data.length > 0 &&
    data.length <= MAX_SCREENSHOT_BASE64 &&
    data.length % 4 === 0 &&
    /^[A-Za-z0-9+/]+={0,2}$/.test(data) &&
    Buffer.from(data.slice(0, 12), "base64").subarray(0, 8).equals(PNG_SIGNATURE);
  if (!valid) {
    return projectKernelResult({
      ...response,
      ok: false,
      error: { code: "INTERNAL_ERROR", message: "orceld returned a malformed screenshot" }
    });
  }
  return {
    content: [
      {
        type: "text" as const,
        text: JSON.stringify({ result: rest, evidence: response.evidence }, null, 2)
      },
      { type: "image" as const, data, mimeType: "image/png" }
    ]
  };
}
