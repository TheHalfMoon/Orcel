import assert from "node:assert/strict";
import test from "node:test";
import { isUnaffected, parseVersion } from "./check-lopdf-advisories.mjs";

const v = (text) => parseVersion(text);

test("a version at or past the patched release is unaffected", () => {
  const toml = '[versions]\npatched = [">= 0.42.0"]\n';
  assert.equal(isUnaffected(v("0.45.0"), toml), true);
  assert.equal(isUnaffected(v("0.42.0"), toml), true);
  assert.equal(isUnaffected(v("0.41.9"), toml), false);
});

test("unaffected ranges and comma-joined sets are honoured", () => {
  const toml = '[versions]\npatched = []\nunaffected = ["< 0.30.0", ">= 0.40.0, < 0.43.0"]\n';
  assert.equal(isUnaffected(v("0.29.9"), toml), true);
  assert.equal(isUnaffected(v("0.41.0"), toml), true);
  assert.equal(isUnaffected(v("0.45.0"), toml), false);
  assert.equal(isUnaffected(v("0.35.0"), toml), false);
});

test("no patched release and no unaffected range means affected", () => {
  assert.equal(isUnaffected(v("0.45.0"), "[versions]\npatched = []\n"), false);
});

test("an unsupported requirement fails loudly", () => {
  assert.throws(() => isUnaffected(v("0.45.0"), '[versions]\npatched = ["~> 1"]\n'));
});
