// SG-000135 OB-03: the secret-field mask, checked on the installed Edge.
//
// The page is the test's own (set with setContent, no network); the capture
// is the worker's own `capturePng`. The PNG is decoded here and the pixels
// read: every secret field is the mask colour, the ordinary field next to
// it is still its own colour (the positive control: the decoding and the
// layout are what the test thinks). On Windows a missing engine fails the
// suite; elsewhere it is skipped, as the confinement probes are.

import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { inflateSync } from "node:zlib";
import { chromium } from "playwright-core";
import { capturePng, pngSize } from "./screenshot.js";

const EDGE_CANDIDATES = [
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
];
const isWindows = process.platform === "win32";
const engine = EDGE_CANDIDATES.find((path) => existsSync(path));
const skip = isWindows ? false : "native probes are Windows-only evidence";

/// Decode an 8-bit, non-interlaced RGB or RGBA PNG into RGBA rows.
export function decodePng(png: Buffer): { width: number; height: number; pixel: (x: number, y: number) => [number, number, number] } {
  const size = pngSize(png);
  assert.ok(size, "a PNG");
  const { width, height } = size;
  const bitDepth = png[24];
  const colourType = png[25];
  const interlace = png[28];
  assert.equal(bitDepth, 8);
  assert.equal(interlace, 0);
  assert.ok(colourType === 2 || colourType === 6, `colour type ${colourType}`);
  const channels = colourType === 6 ? 4 : 3;
  const data: Buffer[] = [];
  for (let offset = 8; offset < png.length; ) {
    const length = png.readUInt32BE(offset);
    const type = png.toString("latin1", offset + 4, offset + 8);
    if (type === "IDAT") data.push(png.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
  }
  const raw = inflateSync(Buffer.concat(data));
  const stride = width * channels;
  const out = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y++) {
    const filter = raw[y * (stride + 1)];
    for (let x = 0; x < stride; x++) {
      const value = raw[y * (stride + 1) + 1 + x] ?? 0;
      const left = x >= channels ? (out[y * stride + x - channels] ?? 0) : 0;
      const up = y > 0 ? (out[(y - 1) * stride + x] ?? 0) : 0;
      const upLeft = y > 0 && x >= channels ? (out[(y - 1) * stride + x - channels] ?? 0) : 0;
      let predicted = 0;
      if (filter === 1) predicted = left;
      else if (filter === 2) predicted = up;
      else if (filter === 3) predicted = (left + up) >> 1;
      else if (filter === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upLeft);
        predicted = pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
      }
      out[y * stride + x] = (value + predicted) & 0xff;
    }
  }
  return {
    width,
    height,
    pixel: (x, y) => {
      const at = y * stride + x * channels;
      return [out[at] ?? 0, out[at + 1] ?? 0, out[at + 2] ?? 0];
    }
  };
}

const field = (top: number, attributes: string) =>
  `<input ${attributes} value="hunter2-secret-value" style="position:absolute;left:40px;top:${top}px;width:320px;height:48px;border:0;margin:0;padding:0;outline:0;background:#00ff00;color:#00ff00;font-size:20px">`;

const PAGE = `<!doctype html><meta charset="utf-8"><body style="margin:0;background:#ffffff">
${field(20, 'type="text" name="nickname"')}
${field(100, 'type="password" name="pw"')}
${field(180, 'type="text" autocomplete="one-time-code" name="code"')}
${field(260, 'type="text" autocomplete="cc-number" name="number"')}
${field(340, 'type="text" name="user_password_confirm"')}
<div style="position:absolute;left:40px;top:2600px;width:320px;height:48px;background:#0000ff"></div>
</body>`;

test("OB-03: secret fields are masked in the PNG, ordinary ones are not", { skip }, async () => {
  assert.ok(engine, "Edge is installed");
  const browser = await chromium.launch({ executablePath: engine, headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();
    await page.setContent(PAGE);
    const shot = await capturePng(page);
    assert.deepEqual([shot.width, shot.height], [1280, 720]);
    const decoded = decodePng(shot.png);
    const at = (top: number) => decoded.pixel(200, top + 24);
    assert.deepEqual(at(20), [0, 255, 0], "the ordinary field keeps its colour (positive control)");
    for (const top of [100, 180, 260, 340]) assert.deepEqual(at(top), [0, 0, 0], `the secret field at ${top} is masked`);
    // A full-page clip reaches below the viewport.
    const tall = await capturePng(page, { x: 0, y: 0, width: 1280, height: 2640 });
    assert.equal(tall.height, 2640);
    const full = decodePng(tall.png);
    assert.deepEqual(full.pixel(200, 2624), [0, 0, 255]);
    assert.deepEqual(full.pixel(200, 124), [0, 0, 0]);
  } finally {
    await browser.close();
  }
});

const SHADOW_AND_FRAME = `<!doctype html><meta charset="utf-8"><body style="margin:0;background:#ffffff">
<div id="host" style="position:absolute;left:0;top:0;width:400px;height:100px"></div>
<iframe id="frame" style="position:absolute;left:0;top:120px;width:420px;height:100px;border:0" srcdoc='<body style="margin:0;background:#fff"><input type="password" value="hunter2" style="position:absolute;left:40px;top:20px;width:320px;height:48px;border:0;margin:0;padding:0;outline:0;background:#00ff00;color:#00ff00"></body>'></iframe>
${field(240, 'type="text" name="nickname"')}
<script>
const root = document.getElementById("host").attachShadow({ mode: "open" });
root.innerHTML = '<input type="password" value="hunter2" style="position:absolute;left:40px;top:20px;width:320px;height:48px;border:0;margin:0;padding:0;outline:0;background:#00ff00;color:#00ff00">';
</script>
</body>`;

test("OB-03: fields in an open shadow root, in an iframe and added before the capture are masked", { skip }, async () => {
  assert.ok(engine, "Edge is installed");
  const browser = await chromium.launch({ executablePath: engine, headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 } });
    const page = await context.newPage();
    await page.setContent(SHADOW_AND_FRAME);
    await page.frameLocator("#frame").locator("input").waitFor();
    // The page adds a field of its own just before the capture.
    await page.evaluate(() => {
      const added = document.createElement("input");
      added.type = "password";
      added.value = "added-late";
      added.setAttribute("style", "position:absolute;left:40px;top:340px;width:320px;height:48px;border:0;margin:0;padding:0;outline:0;background:#00ff00;color:#00ff00");
      document.body.append(added);
    });
    const shot = await capturePng(page);
    const decoded = decodePng(shot.png);
    assert.deepEqual(decoded.pixel(200, 264), [0, 255, 0], "the ordinary field keeps its colour (positive control)");
    assert.deepEqual(decoded.pixel(200, 44), [0, 0, 0], "the open shadow root's field is masked");
    assert.deepEqual(decoded.pixel(200, 164), [0, 0, 0], "the iframe's field is masked");
    assert.deepEqual(decoded.pixel(200, 364), [0, 0, 0], "the field added before the capture is masked");
  } finally {
    await browser.close();
  }
});
