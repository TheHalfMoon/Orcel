import assert from "node:assert/strict";
import { test } from "node:test";
import { DialogLog, MAX_DIALOGS, MAX_DIALOG_MESSAGE_BYTES } from "./dialogs.js";

function dialog(type: string, message: string) {
  const calls: string[] = [];
  return {
    calls,
    dialog: {
      type: () => type,
      message: () => message,
      dismiss: async () => {
        calls.push("dismiss");
      }
    }
  };
}

test("BR-05 every dialog is dismissed and logged once, bounded and on one line", () => {
  const log = new DialogLog();
  const confirm = dialog("confirm", "Delete\nthis item?");
  log.dismiss(confirm.dialog);
  assert.deepEqual(confirm.calls, ["dismiss"]);
  const long = dialog("prompt", "x".repeat(MAX_DIALOG_MESSAGE_BYTES + 50));
  log.dismiss(long.dialog);
  const first = log.take();
  assert.equal(first.truncated, false);
  assert.deepEqual(first.dialogs[0], { kind: "confirm", message: "Delete this item?" });
  assert.equal(Buffer.byteLength(first.dialogs[1]!.message, "utf8"), MAX_DIALOG_MESSAGE_BYTES);
  assert.deepEqual(log.take(), { dialogs: [], truncated: false }, "taken once");
  for (let i = 0; i < MAX_DIALOGS + 3; i++) log.dismiss(dialog("alert", `n${i}`).dialog);
  const many = log.take();
  assert.equal(many.dialogs.length, MAX_DIALOGS);
  assert.equal(many.truncated, true);
});

test("BR-05 a page is attached once", () => {
  const log = new DialogLog();
  const handlers: string[] = [];
  const page = { on: (event: string) => handlers.push(event) };
  log.attach(page as never);
  log.attach(page as never);
  assert.deepEqual(handlers, ["dialog"]);
});
