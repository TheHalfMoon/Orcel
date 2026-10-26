// BR-05 (first slice): JavaScript dialogs (alert, confirm, prompt,
// beforeunload) are dismissed at once, without any approval, and recorded,
// so the host can tell the user that a page asked something and the answer
// was "no". Accepting a dialog needs its own approval and is not offered.
//
// Adapted from microsoft/playwright at commit
// 1b025d7e20a026371cd5f98ba0cdce48892737c8,
// `packages/playwright-core/src/tools/backend/dialogs.ts` (blob
// 6d3d0f251d1e4f24af1a66e899006d0e2c0f52d8; browser_handle_dialog:
// `dialog.dismiss`). Apache License 2.0, Copyright (c) Microsoft
// Corporation; notice in docs/orcel/notices/playwright-Apache-2.0.txt.
// Modifications for Orcel: no dialog is ever held open or accepted; every
// dialog is dismissed as it opens (the donor waits for the model's
// decision); the kind and a bounded, single-line copy of the message are
// kept for the host, which treats them as untrusted page text.

import type { Dialog, Page } from "playwright-core";

/// Dialogs remembered between two reads.
export const MAX_DIALOGS = 8;
/// Longest message kept, in UTF-8 bytes.
export const MAX_DIALOG_MESSAGE_BYTES = 1024;

export type DialogKind = "alert" | "confirm" | "prompt" | "beforeunload";

export interface DismissedDialog {
  kind: DialogKind;
  message: string;
}

const KINDS: readonly string[] = ["alert", "confirm", "prompt", "beforeunload"];

/// One line, no control characters, at most `MAX_DIALOG_MESSAGE_BYTES`.
function bounded(text: string): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
  if (Buffer.byteLength(clean, "utf8") <= MAX_DIALOG_MESSAGE_BYTES) return clean;
  let out = "";
  for (const ch of clean) {
    if (Buffer.byteLength(out + ch, "utf8") > MAX_DIALOG_MESSAGE_BYTES) break;
    out += ch;
  }
  return out;
}

/// The dialogs dismissed since the last `take`.
export class DialogLog {
  private entries: DismissedDialog[] = [];
  private dropped = false;
  private readonly attached = new WeakSet<Page>();

  /// Dismiss every dialog `page` opens, and record it.
  attach(page: Pick<Page, "on">): void {
    if (this.attached.has(page as Page)) return;
    this.attached.add(page as Page);
    page.on("dialog", (dialog: Dialog) => this.dismiss(dialog));
  }

  dismiss(dialog: Pick<Dialog, "type" | "message" | "dismiss">): void {
    void dialog.dismiss().catch(() => {});
    const kind = dialog.type();
    if (this.entries.length >= MAX_DIALOGS) {
      this.dropped = true;
      return;
    }
    this.entries.push({ kind: (KINDS.includes(kind) ? kind : "alert") as DialogKind, message: bounded(dialog.message()) });
  }

  /// The recorded dialogs (and whether some were dropped), clearing the log.
  take(): { dialogs: DismissedDialog[]; truncated: boolean } {
    const out = { dialogs: this.entries, truncated: this.dropped };
    this.entries = [];
    this.dropped = false;
    return out;
  }
}
