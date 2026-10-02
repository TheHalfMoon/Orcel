import type { OrcelEvalTargetHandle } from "orcel/evals";

export async function postChannel<T>(
  target: OrcelEvalTargetHandle,
  path: string,
  body: unknown,
): Promise<T> {
  const response = await target.fetch(path, {
    body: JSON.stringify(body),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`POST ${path} failed (${response.status}): ${text}`);
  }
  return JSON.parse(text) as T;
}
