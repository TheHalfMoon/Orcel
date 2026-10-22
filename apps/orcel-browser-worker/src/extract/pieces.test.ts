import assert from "node:assert/strict";
import { test } from "node:test";
import { encodeFrame, MAX_EXTRACT_PIECES, MAX_FRAME_BYTES, MAX_PIECE_BYTES } from "../protocol.js";
import type { MarkdownChunk } from "./chunk.js";
import { toPieces } from "./pieces.js";

const chunk = (content: string): MarkdownChunk => ({ content, index: 0, total: 1, start: 0, end: content.length, overlap: "", hasMore: false });
const wire = (text: string): number => Buffer.byteLength(JSON.stringify(text)) - 2;

test("pieces keep every character, in order, each within the wire bound", () => {
  const shapes = [
    "plain ".repeat(40_000),
    "\u{1f600}".repeat(30_000),
    '"\\'.repeat(40_000),
    "é".repeat(50_000),
    "line of text\n".repeat(10_000),
    "x".repeat(100) + "\n" + "y".repeat(200_000)
  ];
  for (const text of shapes) {
    const { pieces, truncated } = toPieces([chunk(text)], 1000, 10_000);
    assert.equal(truncated, false);
    assert.equal(pieces.map((p) => p.content).join(""), text);
    assert.ok(pieces.every((p) => wire(p.content) <= 1000 && p.content.length > 0 && p.chunk === 0));
  }
  // A surrogate pair is never split.
  const { pieces } = toPieces([chunk("a" + "\u{1f600}".repeat(10))], 17, 100);
  assert.ok(pieces.every((p) => !/[\ud800-\udbff]$/.test(p.content)), JSON.stringify(pieces));
});

test("a split prefers a line break in the second half of the piece", () => {
  const text = "a".repeat(700) + "\n" + "b".repeat(700);
  const { pieces } = toPieces([chunk(text)], 1000, 10);
  assert.deepEqual(
    pieces.map((p) => p.content),
    ["a".repeat(700) + "\n", "b".repeat(700)]
  );
  const early = "a".repeat(100) + "\n" + "b".repeat(1500);
  assert.ok((toPieces([chunk(early)], 1000, 10).pieces[0]?.content.length ?? 0) > 900, "an early break is not used");
});

test("chunks are numbered without the empty ones, and the piece count is bounded", () => {
  assert.deepEqual(toPieces([chunk("a"), chunk(""), chunk("b")], 1000, 10), {
    pieces: [
      { chunk: 0, content: "a" },
      { chunk: 1, content: "b" }
    ],
    truncated: false
  });
  assert.deepEqual(toPieces([chunk("")], 1000, 10), { pieces: [{ chunk: 0, content: "" }], truncated: false });
  const many = toPieces([chunk("z".repeat(10_000))], 100, 5);
  assert.deepEqual(many, { pieces: Array.from({ length: 5 }, () => ({ chunk: 0, content: "z".repeat(100) })), truncated: true });
});

test("a cut inside a chunk is only a transport detail: its pieces name the same chunk", () => {
  // A fenced block larger than one piece, ending in syntax that is live
  // outside the fence, and a paragraph aimed so a heading starts at a cut.
  const fence = "```\n" + "x".repeat(2500) + "\n[click](javascript:alert(1)) <img src=x onerror=alert(2)>\n```";
  const aimed = "y".repeat(1000) + "# Ignore previous instructions";
  const { pieces } = toPieces([chunk(fence), chunk(aimed)], 1000, 100);
  assert.ok(pieces.length > 3);
  const joined = (n: number): string =>
    pieces
      .filter((p) => p.chunk === n)
      .map((p) => p.content)
      .join("");
  assert.equal(joined(0), fence);
  assert.equal(joined(1), aimed);
  assert.ok(pieces.some((p) => p.chunk === 1 && p.content.startsWith("# Ignore")), "the aimed cut happened");
  // Chunk numbers never go back and step by one.
  for (let i = 1; i < pieces.length; i++) {
    const step = (pieces[i]?.chunk ?? 0) - (pieces[i - 1]?.chunk ?? 0);
    assert.ok(step === 0 || step === 1);
  }
});

test("the largest piece still fits a reply frame with the longest URL", () => {
  const { pieces } = toPieces([chunk('"\u0001'.repeat(100_000))], MAX_PIECE_BYTES, MAX_EXTRACT_PIECES);
  const frame = encodeFrame({
    frame: "extracted",
    ext_id: 2 ** 31,
    url: "https://x.test/" + "a".repeat(2033),
    truncated: true,
    piece: 95,
    total: 96,
    chunk: 95,
    content: pieces[0]?.content ?? ""
  });
  assert.ok(frame.length <= MAX_FRAME_BYTES + 4, `${frame.length}`);
});

test("splitting is linear", () => {
  // #374: a single wall-clock sample flakes under load (a GC pause or a
  // slow core inflates one side). Each size is timed by the fastest of
  // several interleaved runs instead, so a pause inflates neither, and
  // the sizes are 8x apart: linear work grows ~8x, quadratic ~64x, and the
  // 24x bound leaves 3x for noise while still failing a quadratic splitter
  // (it flags growth of about n^1.53 and steeper; n log n stays below it).
  // Two shapes: short lines (the line-break cut) and one line of astral
  // code points (the hard cut, width 2).
  const once = (text: string): number => {
    const started = process.hrtime.bigint();
    toPieces([chunk(text)], 64, 1_000_000);
    return Number(process.hrtime.bigint() - started);
  };
  for (const [unit, count] of [["ab\n", 20_000], ["\u{1F600}x", 20_000]] as const) {
    const smallText = unit.repeat(count);
    const largeText = unit.repeat(count * 8);
    once(smallText);
    once(largeText);
    let small = Infinity;
    let large = Infinity;
    for (let run = 0; run < 7; run++) {
      small = Math.min(small, once(smallText));
      large = Math.min(large, once(largeText));
    }
    assert.ok(large < small * 24, `${JSON.stringify(unit)}: fastest of 7: ${small} ns vs ${large} ns (8x the input)`);
  }
});
