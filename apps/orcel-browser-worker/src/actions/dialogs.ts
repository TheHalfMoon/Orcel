// BR-05: JavaScript dialogs are answered at once and recorded, so the host
// can tell the user that a page asked something and what the answer was.
// alert, confirm and prompt are dismissed ("no"), without any approval;
// beforeunload is accepted, as Playwright does by default, because leaving
// the page is what the host-approved step that caused it already allows (a
// dismissed beforeunload would cancel an approved navigation). The one
// other exception is armed by an approved action: during that action only,
// a confirm the target page itself opens, whose message (as the host saw it:
// cleaned, whole) is exactly the approved one, is accepted, once.
//
// Adapted from microsoft/playwright at commit
// 1b025d7e20a026371cd5f98ba0cdce48892737c8,
// `packages/playwright-core/src/tools/backend/dialogs.ts` (blob
// 6d3d0f251d1e4f24af1a66e899006d0e2c0f52d8; browser_handle_dialog:
// `dialog.accept` and `dialog.dismiss`). Apache License 2.0, Copyright (c)
// Microsoft Corporation; notice in docs/orcel/notices/playwright-Apache-2.0.txt.
// Modifications for Orcel: no dialog is ever held open (the donor waits for
// the model's decision); dialogs are answered as they open, from one
// listener on the whole context; the kind, the opening page's URL and a
// bounded, single-line, cleaned copy of the message are kept for the host,
// which treats them as untrusted page text; an approved confirm is
// accepted only when its message matches exactly.

import type { BrowserContext, Dialog } from "playwright-core";
import { safeText } from "../extract/clean.js";

/// Dialogs remembered between two reads.
export const MAX_DIALOGS = 8;
/// Longest message kept, in UTF-8 bytes.
export const MAX_DIALOG_MESSAGE_BYTES = 1024;
/// Longest page URL kept, in UTF-8 bytes.
export const MAX_DIALOG_URL_BYTES = 2048;

export type DialogKind = "alert" | "confirm" | "prompt" | "beforeunload";

export interface DismissedDialog {
  kind: DialogKind;
  /// The URL of the page that opened it ("" when unknown).
  url: string;
  message: string;
  /// Accepted: a beforeunload, or the confirm an approved action named.
  accepted: boolean;
}

const KINDS: readonly string[] = ["alert", "confirm", "prompt", "beforeunload"];

/// Cleaned (no lone surrogates, controls or invisible characters), on one
/// line.
function cleaned(text: string): string {
  return safeText(text).replace(/[\u0000-\u001f\u007f-\u009f]/g, " ");
}

/// `cleaned`, at most `maxBytes`.
function bounded(text: string, maxBytes: number): string {
  const clean = cleaned(text);
  if (Buffer.byteLength(clean, "utf8") <= maxBytes) return clean;
  let out = "";
  for (const ch of clean) {
    if (Buffer.byteLength(out + ch, "utf8") > maxBytes) break;
    out += ch;
  }
  return out;
}

type DialogPage = { url(): string };
type AnsweredDialog = Pick<Dialog, "type" | "message" | "dismiss" | "accept"> & { page?: () => DialogPage | null };

/// The dialogs answered since the last `take`.
export class DialogLog {
  private entries: DismissedDialog[] = [];
  private dropped = false;
  /// The confirm message an approved action may accept while it runs, and
  /// the page that action targets (only its own dialogs qualify).
  private armed: { message: string; page: DialogPage } | null = null;

  /// Answer every dialog any page of `context` opens, and record it.
  listen(context: Pick<BrowserContext, "on">): void {
    context.on("dialog", (dialog: Dialog) => this.answer(dialog));
  }

  /// Accept, once and during the current action only, a confirm that
  /// `page` opens whose cleaned, whole message is exactly `message`.
  arm(message: string, page: DialogPage): void {
    this.armed = { message, page };
  }

  disarm(): void {
    this.armed = null;
  }

  answer(dialog: AnsweredDialog): void {
    const kind = dialog.type();
    const message = dialog.message();
    let source: DialogPage | null = null;
    try {
      source = dialog.page?.() ?? null;
    } catch {
      source = null;
    }
    const whole = cleaned(message);
    const approved =
      this.armed !== null &&
      kind === "confirm" &&
      source === this.armed.page &&
      Buffer.byteLength(whole, "utf8") <= MAX_DIALOG_MESSAGE_BYTES &&
      whole === this.armed.message;
    const accepted = kind === "beforeunload" || approved;
    if (kind === "confirm" && accepted) this.armed = null;
    void (accepted ? dialog.accept() : dialog.dismiss()).catch(() => {});
    // A kind Orcel does not know is answered "no" and only counted.
    if (!KINDS.includes(kind) || this.entries.length >= MAX_DIALOGS) {
      this.dropped = true;
      return;
    }
    let url = "";
    try {
      url = source?.url() ?? "";
    } catch {
      url = "";
    }
    this.entries.push({
      kind: kind as DialogKind,
      url: bounded(url, MAX_DIALOG_URL_BYTES),
      message: bounded(message, MAX_DIALOG_MESSAGE_BYTES),
      accepted
    });
  }

  /// The recorded dialogs (and whether some were dropped), clearing the log.
  take(): { dialogs: DismissedDialog[]; truncated: boolean } {
    const out = { dialogs: this.entries, truncated: this.dropped };
    this.entries = [];
    this.dropped = false;
    return out;
  }
}
