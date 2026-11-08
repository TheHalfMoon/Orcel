// BR-03: set an approved file input to one host-staged file.
//
// Adapted from microsoft/playwright at commit
// 1b025d7e20a026371cd5f98ba0cdce48892737c8,
// `packages/playwright-core/src/tools/backend/files.ts` (blob
// 44e1f5ee6badd8794dee76c5ac3af21d32b92df4; browser_file_upload: `setFiles`).
// Apache License 2.0, Copyright (c) Microsoft Corporation; notice in
// docs/orcel/notices/playwright-Apache-2.0.txt. Modifications for
// Orcel: no file chooser is opened or answered; the approved element (BR-01
// ref, or its exact role and name) must itself be an <input type=file>, and
// it is given exactly the one path the host staged, never a path the page or
// the model names. Setting the file sends nothing; a later submission is a
// separate approval.

import { NavigationError } from "../worker.js";
import type { ApprovedTarget } from "../protocol.js";
import { isOcclusion, approvedElement, type TargetPage } from "./targets.js";
import type { Page } from "playwright-core";

export type UploadPage = TargetPage & Pick<Page, "locator">;

export const UPLOAD_TIMEOUT_MS = 5_000;

/// Sets the approved file input to `path`. Rejects with NavigationError:
/// "stale", "denied" (not a file input), "occluded", "timeout" or "failed".
export async function uploadFile(page: UploadPage, ref: string, path: string, target?: ApprovedTarget): Promise<void> {
  const element = await approvedElement(page, ref, target);
  const input = element.and(page.locator('input[type="file" i]'));
  if ((await input.count().catch(() => 0)) !== 1) throw new NavigationError("denied");
  try {
    await input.setInputFiles(path, { timeout: UPLOAD_TIMEOUT_MS });
  } catch (error) {
    if (isOcclusion(error)) throw new NavigationError("occluded");
    const message = error instanceof Error ? error.message : "";
    throw new NavigationError(/timeout/i.test(message) ? "timeout" : "failed");
  }
}
