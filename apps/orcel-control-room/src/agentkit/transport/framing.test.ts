import assert from "node:assert/strict";
import { test } from "node:test";

import { AppApiProtocolError } from "../protocol/errors.js";
import { MAX_FRAME_BYTES } from "../protocol/version.js";
import { LineDecoder } from "./framing.js";

const tooLarge = (error: unknown) =>
  error instanceof AppApiProtocolError && error.code === "FRAME_TOO_LARGE";

test("lines split across chunks, CRLF and blank lines", () => {
  const decoder = new LineDecoder();
  assert.deepEqual(decoder.push(Buffer.from('{"a":1}\r\n{"b"')), ['{"a":1}']);
  assert.equal(decoder.buffered, 4);
  assert.deepEqual(decoder.push(Buffer.from(':2}\n\n  \n{"c":3}\n')), ['{"b":2}', '{"c":3}']);
  assert.equal(decoder.buffered, 0);
});

test("a frame of exactly 64 KiB, newline included, is accepted", () => {
  const decoder = new LineDecoder();
  const body = "x".repeat(MAX_FRAME_BYTES - 1);
  assert.deepEqual(decoder.push(Buffer.from(`${body}\n`)), [body]);
});

test("an oversize incoming frame is refused once it passes the limit", () => {
  const decoder = new LineDecoder();
  assert.throws(() => decoder.push(Buffer.from(`${"x".repeat(MAX_FRAME_BYTES)}\n`)), tooLarge);
  // The decoder stays failed: the connection must be dropped.
  assert.throws(() => decoder.push(Buffer.from("{}\n")), tooLarge);
});

test("an oversize frame is refused before its newline arrives", () => {
  const decoder = new LineDecoder();
  const half = Buffer.from("y".repeat(MAX_FRAME_BYTES / 2));
  assert.deepEqual(decoder.push(half), []);
  assert.deepEqual(decoder.push(half), []);
  assert.equal(decoder.buffered, MAX_FRAME_BYTES);
  // One more byte cannot be a complete frame within the limit.
  assert.throws(() => decoder.push(Buffer.from("y")), tooLarge);
});

test("multi-byte characters split across chunks decode intact", () => {
  const decoder = new LineDecoder();
  const bytes = Buffer.from('"é\u{1F600}"\n');
  assert.deepEqual(decoder.push(bytes.subarray(0, 3)), []);
  assert.deepEqual(decoder.push(bytes.subarray(3)), ['"é\u{1F600}"']);
});
