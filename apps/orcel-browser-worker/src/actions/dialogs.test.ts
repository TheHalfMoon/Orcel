import assert from "node:assert/strict";
import { test } from "node:test";
import { DialogLog, MAX_DIALOGS, MAX_DIALOG_MESSAGE_BYTES } from "./dialogs.js";

function dialog(type: string, message: string, url = "https://fixture.test/items") {
  const calls: string[] = [];
  return {
    calls,
    dialog: {
      type: () => type,
      message: () => message,
      page: () => ({ url: () => url }),
      dismiss: async () => {
        calls.push("dismiss");
      },
      accept: async () => {
        calls.push("accept");
      }
    }
  };
}

test("BR-05 dialogs are answered and logged once: no, except beforeunload (leaving was approved)", () => {
  const log = new DialogLog();
  const confirm = dialog("confirm", "Delete\nthis item?");
  log.answer(confirm.dialog);
  const prompt = dialog("prompt", "Name?");
  log.answer(prompt.dialog);
  const unload = dialog("beforeunload", "");
  log.answer(unload.dialog);
  assert.deepEqual([confirm.calls, prompt.calls, unload.calls], [["dismiss"], ["dismiss"], ["accept"]]);
  const first = log.take();
  assert.equal(first.truncated, false);
  assert.deepEqual(first.dialogs[0], { kind: "confirm", url: "https://fixture.test/items", message: "Delete this item?", accepted: false });
  assert.deepEqual(first.dialogs[2], { kind: "beforeunload", url: "https://fixture.test/items", message: "", accepted: true });
  assert.deepEqual(log.take(), { dialogs: [], truncated: false }, "taken once");
});

test("BR-05 messages are bounded, single-line and cleaned of what could break or hide text", () => {
  const log = new DialogLog();
  log.answer(dialog("alert", "x".repeat(MAX_DIALOG_MESSAGE_BYTES + 50)).dialog);
  log.answer(dialog("alert", "a\ud800b‮c​d\u0085e").dialog);
  const [long, odd] = log.take().dialogs;
  assert.equal(Buffer.byteLength(long!.message, "utf8"), MAX_DIALOG_MESSAGE_BYTES);
  assert.equal(odd!.message, "a�bcde");
  // A lone surrogate never reaches the wire: it encodes as valid UTF-8 JSON.
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(odd)));
});

test("BR-05 unknown kinds are answered no and only counted; the log is bounded", () => {
  const log = new DialogLog();
  const strange = dialog("permission", "Allow?");
  log.answer(strange.dialog);
  assert.deepEqual(strange.calls, ["dismiss"]);
  assert.deepEqual(log.take(), { dialogs: [], truncated: true });
  for (let i = 0; i < MAX_DIALOGS + 3; i++) log.answer(dialog("alert", `n${i}`).dialog);
  const many = log.take();
  assert.equal(many.dialogs.length, MAX_DIALOGS);
  assert.equal(many.truncated, true);
});

test("BR-05 an armed action accepts exactly its approved confirm, once; everything else is dismissed", () => {
  const log = new DialogLog();
  const target = { url: () => "https://fixture.test/items" };
  const dialog = (type: string, message: string, page: { url(): string } = target) => {
    const calls: string[] = [];
    return {
      calls,
      dialog: {
        type: () => type,
        message: () => message,
        page: () => page,
        dismiss: async () => {
          calls.push("dismiss");
        },
        accept: async () => {
          calls.push("accept");
        }
      }
    };
  };
  log.arm("Delete this item?", target);
  const other = dialog("confirm", "Delete everything?");
  log.answer(other.dialog);
  const alert = dialog("alert", "Delete this item?");
  log.answer(alert.dialog);
  const match = dialog("confirm", "Delete this item?");
  log.answer(match.dialog);
  const again = dialog("confirm", "Delete this item?");
  log.answer(again.dialog);
  assert.deepEqual([other.calls, alert.calls, match.calls, again.calls], [["dismiss"], ["dismiss"], ["accept"], ["dismiss"]]);
  assert.deepEqual(
    log.take().dialogs.map((d) => d.accepted),
    [false, false, true, false]
  );
  log.arm("Delete this item?", target);
  log.disarm();
  const later = dialog("confirm", "Delete this item?");
  log.answer(later.dialog);
  assert.deepEqual(later.calls, ["dismiss"], "disarmed after the action");
});

test("BR-05 one listener on the whole context", () => {
  const log = new DialogLog();
  const events: string[] = [];
  log.listen({ on: (event: string) => events.push(event) } as never);
  assert.deepEqual(events, ["dialog"]);
});

test("BR-05 an approved confirm counts only from the target page, matched as the host saw it", () => {
  const log = new DialogLog();
  const target = { url: () => "https://fixture.test/items" };
  const other = { url: () => "https://fixture.test/popup" };
  const make = (message: string, page: { url(): string }) => {
    const calls: string[] = [];
    return { calls, dialog: { type: () => "confirm", message: () => message, page: () => page, dismiss: async () => void calls.push("dismiss"), accept: async () => void calls.push("accept") } };
  };
  // A multi-line confirm is approved as the host reported it (one line).
  log.arm("Are you sure? This cannot be undone.", target);
  const popup = make("Are you sure?\nThis cannot be undone.", other);
  log.answer(popup.dialog);
  const own = make("Are you sure?\nThis cannot be undone.", target);
  log.answer(own.dialog);
  assert.deepEqual([popup.calls, own.calls], [["dismiss"], ["accept"]]);
});
