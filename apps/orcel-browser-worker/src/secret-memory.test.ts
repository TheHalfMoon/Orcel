// SG-000135 OB-07b: a password field stays secret after a "show password"
// toggle, for the detector, the secret-field check and the screenshot mask.
// Fixture markup only; no value of any field is ever read.

import assert from "node:assert/strict";
import { test } from "node:test";
import type { Locator } from "playwright-core";
import { classifyChallenge } from "./challenge.js";
import { snapshotOf } from "./challenge-html.fixture.js";
import { maskSelector, SECRET_FIELD_SELECTOR } from "./screenshot.js";
import { existingSecretMemory, MAX_REMEMBERED, rememberSecretField, secretMemory, wasSecretField, wasSecretName } from "./secret-memory.js";
import { isSecretField } from "./verify.js";

const form = (field: string) =>
  `<!doctype html><html><head><title>Sign in</title></head><body><form action="/login" method="post"><input type="email" name="email">${field}<button type="button">Show</button><button>Sign in</button></form></body></html>`;

test("OB-07b a password autocomplete token marks a sign-in field whatever its type", () => {
  for (const field of ['<input type="text" name="secret-field" autocomplete="current-password">', '<input autocomplete="new-password" name="pw2">']) {
    const report = classifyChallenge(snapshotOf(form(field)), 200);
    assert.equal(report.kind, "sign_in", field);
    assert.deepEqual(report.signals, ["password_field"], field);
  }
});

test("OB-07b a password field shown in clear by a toggle still holds the page", () => {
  const page = {};
  const memory = secretMemory(page);
  const before = classifyChallenge(snapshotOf(form('<input type="password" name="pw" data-backend="77">')), 200, memory);
  assert.equal(before.kind, "sign_in");
  assert.ok(wasSecretField(memory, 77));
  // The page's toggle turned the same element into a text field.
  const after = classifyChallenge(snapshotOf(form('<input type="text" name="pw" data-backend="77">')), 200, memory);
  assert.equal(after.kind, "sign_in");
  assert.deepEqual(after.signals, ["password_field"]);
  // Without the memory (a fresh page), the same markup is an ordinary field.
  assert.equal(classifyChallenge(snapshotOf(form('<input type="text" name="pw" data-backend="77">')), 200).kind, "none");
  // Another element is not affected.
  assert.equal(classifyChallenge(snapshotOf(form('<input type="text" name="nickname" data-backend="78">')), 200, memory).kind, "none");
});

test("OB-07b the memory is per page and bounded", () => {
  const one = {};
  const two = {};
  rememberSecretField(secretMemory(one), 1, "pw", "password-field");
  assert.ok(wasSecretName(secretMemory(one), "PW", ""));
  assert.ok(wasSecretName(secretMemory(one), "", "Password-Field"));
  assert.equal(existingSecretMemory(two), undefined);
  assert.ok(!wasSecretName(secretMemory(two), "pw", ""));
  assert.ok(!wasSecretName(secretMemory(one), "", ""), "an empty name or id never matches");
  const memory = secretMemory({});
  for (let id = 1; id <= MAX_REMEMBERED + 10; id++) rememberSecretField(memory, id, `n${id}`, undefined);
  assert.equal(memory.backends.size, MAX_REMEMBERED);
  assert.equal(memory.names.size, MAX_REMEMBERED);
  assert.ok(!wasSecretField(memory, 1), "the oldest went first");
  assert.ok(wasSecretField(memory, MAX_REMEMBERED + 10));
});

/// A Locator stand-in: attribute reads and the page it belongs to.
function control(attrs: Record<string, string>, page?: object): Locator {
  return {
    getAttribute: async (name: string) => attrs[name] ?? null,
    ...(page ? { page: () => page } : {})
  } as unknown as Locator;
}

test("OB-07b isSecretField: accessible label, placeholder and a remembered password field", async () => {
  assert.equal(await isSecretField(control({ type: "text", "aria-label": "Password" })), true);
  assert.equal(await isSecretField(control({ type: "text", placeholder: "One-time code" })), true);
  assert.equal(await isSecretField(control({ type: "text", placeholder: "Your PIN" })), true);
  assert.equal(await isSecretField(control({ type: "text", name: "city", "aria-label": "City" })), false);
  assert.equal(await isSecretField(control({ type: "text", name: "spinner-size" })), false);
  const page = {};
  // "pw2" names no secret by itself; once the page showed it as a password
  // field, it stays secret in clear text.
  assert.equal(await isSecretField(control({ type: "text", name: "pw2" }, page)), false);
  rememberSecretField(secretMemory(page), undefined, "pw2", undefined);
  assert.equal(await isSecretField(control({ type: "text", name: "pw2" }, page)), true);
  assert.equal(await isSecretField(control({ type: "text", name: "pw2" }, {})), false, "another page");
});

test("OB-07b the screenshot mask covers remembered password fields and labels", () => {
  assert.equal(maskSelector(undefined), SECRET_FIELD_SELECTOR);
  assert.ok(SECRET_FIELD_SELECTOR.includes('input[aria-label*="password" i]'));
  assert.ok(SECRET_FIELD_SELECTOR.includes('input[placeholder*="password" i]'));
  const memory = secretMemory({});
  rememberSecretField(memory, 5, 'odd"name\\x', "pw-field");
  const selector = maskSelector(memory);
  assert.ok(selector.startsWith(SECRET_FIELD_SELECTOR));
  assert.ok(selector.includes('input[name="odd\\"name\\\\x" i]'), selector.slice(-80));
  assert.ok(selector.includes('input[id="pw-field" i]'));
});
