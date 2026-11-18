#!/usr/bin/env node
// Build-time renderer for the `generated` entries of an Orcel design handoff package
// (docs/orcel/design-handoff/CONTRACT.md sections 2.2 and 2.7). Raster icons (PNG, ICO, ICNS) and
// reference screens are never committed; this script renders them from the package's SVG sources
// into a gitignored build folder. Ported from the Design session's export_icons.mjs: the same
// recipes, without Microsoft Edge (sharp renders SVG text with locally installed fonts).
//
// Uses the exact-locked sharp that apps/web already installs (like scripts/render-brand.mjs);
// no new dependency, no network. ICO and ICNS containers are assembled here.
//
//   node scripts/render-design-handoff.mjs design/handoff/1.0.0 [out-dir]
//   default out-dir: build/design-handoff/<version>
import { createRequire } from "node:module";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const GENERATOR = "scripts/render-design-handoff.mjs";
export const GENERATOR_VERSION = "1.0.0";
const here = dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = resolve(here, "..");
export const DEFAULT_BUILD_ROOT = join(REPO_ROOT, "build", "design-handoff");

// How one image of an entry is drawn from its single SVG source. `params` are required manifest
// fields of `generated`. All recipes output 8-bit RGBA PNG images (also inside ICO and ICNS).
export const RECIPES = {
  // The source scaled to fit the target, transparent outside the artwork.
  render: { params: [] },
  // Same artwork with its rounded tile plate replaced by a square plate of `plate`, for platforms
  // that apply their own mask (Apple touch icon, MSIX tiles).
  "full-bleed": { params: ["plate"] },
  // The source scaled to `contentHeight` pixels high and centred on a `plate`-coloured canvas
  // (the MSIX wide tile).
  "centered-on-plate": { params: ["plate", "contentHeight"] }
};
// ICNS element types that carry PNG data, by pixel size.
export const ICNS_TYPE_BY_SIZE = { 16: "icp4", 32: "icp5", 64: "icp6", 128: "ic07", 256: "ic08", 512: "ic09", 1024: "ic10" };
const SAFE_REL = /^(?!\/)(?!.*(^|\/)\.\.?(\/|$))(?!.*\/\/)[A-Za-z0-9._@/-]+$/;

export function loadSharp() {
  const req = createRequire(join(REPO_ROOT, "apps", "web", "package.json"));
  return req("sharp");
}

function viewBoxOf(svg) {
  const m = /<svg[^>]*\sviewBox="\s*[-0-9.]+[\s,]+[-0-9.]+[\s,]+([0-9.]+)[\s,]+([0-9.]+)\s*"/.exec(svg);
  return m ? [Number(m[1]), Number(m[2])] : [256, 256];
}

// Supersample: rasterise at twice the target scale, then resize down.
function densityFor(svg, w, h) {
  const [w0, h0] = viewBoxOf(svg);
  return Math.min(2400, Math.max(72, Math.ceil(72 * Math.max(w / w0, h / h0) * 2)));
}

async function pngOf(sharp, svg, w, h) {
  return sharp(Buffer.from(svg), { density: densityFor(svg, w, h) })
    .resize(w, h, { fit: "contain", background: { r: 0, g: 0, b: 0, alpha: 0 } })
    .ensureAlpha().png({ compressionLevel: 9, palette: false }).toBuffer();
}

// The first <rect> with an rx attribute is the tile plate; it becomes a square plate that covers
// the plate's full extent (its inset doubled), artwork unchanged.
export function fullBleedSvg(svg, plate) {
  let done = false;
  const out = svg.replace(/<rect\b[^>]*\srx="[^"]*"[^>]*\/>/, (tag) => {
    const num = (a) => Number((new RegExp("\\s" + a + "=\"([-0-9.]+)\"").exec(tag) ?? [])[1] ?? 0);
    const x = num("x"), y = num("y"), w = num("width"), h = num("height");
    if (!(w > 0 && h > 0)) return tag;
    done = true;
    return '<rect x="0" y="0" width="' + (w + 2 * x) + '" height="' + (h + 2 * y) + '" fill="' + plate + '"/>';
  });
  if (!done) throw new Error("full-bleed: the source has no rounded tile plate (<rect rx=...>)");
  return out;
}

async function drawImage(sharp, svg, g, w, h) {
  if (g.recipe === "render") return pngOf(sharp, svg, w, h);
  if (g.recipe === "full-bleed") return pngOf(sharp, fullBleedSvg(svg, g.plate), w, h);
  if (g.recipe === "centered-on-plate") {
    const [w0, h0] = viewBoxOf(svg);
    const ch = g.contentHeight, cw = Math.max(1, Math.round(ch * w0 / h0));
    if (cw > w || ch > h) throw new Error("centered-on-plate: content " + cw + "x" + ch + " does not fit " + w + "x" + h);
    const inner = await pngOf(sharp, svg, cw, ch);
    return sharp({ create: { width: w, height: h, channels: 4, background: g.plate } })
      .composite([{ input: inner, gravity: "center" }]).png({ compressionLevel: 9, palette: false }).toBuffer();
  }
  throw new Error("unknown recipe " + g.recipe);
}

export function assembleIco(images) {
  const head = Buffer.alloc(6 + images.length * 16);
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(images.length, 4);
  let off = head.length;
  images.forEach(({ size, png }, i) => {
    const e = 6 + i * 16;
    head[e] = size >= 256 ? 0 : size; head[e + 1] = size >= 256 ? 0 : size;
    head.writeUInt16LE(1, e + 4); head.writeUInt16LE(32, e + 6);
    head.writeUInt32LE(png.length, e + 8); head.writeUInt32LE(off, e + 12);
    off += png.length;
  });
  return Buffer.concat([head, ...images.map((i) => i.png)]);
}

export function assembleIcns(images) {
  const parts = images.map(({ size, png }) => {
    const type = ICNS_TYPE_BY_SIZE[size];
    if (!type) throw new Error("ICNS has no PNG element type for " + size + " px");
    const h = Buffer.alloc(8); h.write(type, 0, "latin1"); h.writeUInt32BE(png.length + 8, 4);
    return Buffer.concat([h, png]);
  });
  const body = Buffer.concat(parts);
  const h = Buffer.alloc(8); h.write("icns", 0, "latin1"); h.writeUInt32BE(body.length + 8, 4);
  return Buffer.concat([h, body]);
}

// Every generated entry of a manifest, as { kind, label, entry }.
export function generatedEntries(manifest) {
  const list = [];
  for (const [platform, icons] of Object.entries(manifest.icons ?? {})) {
    for (const icon of icons) if (icon.generated) list.push({ kind: "icon", platform, label: platform + " " + icon.role, entry: icon });
  }
  for (const s of manifest.screens ?? []) {
    if (s.generated) list.push({ kind: "screen", label: "screen " + s.name, entry: { ...s, format: "png" } });
  }
  return list;
}

// Renders every generated entry of the package at `pkgDir` into `outDir`. The caller validates the
// package first (check-design-handoff.mjs does); paths are re-checked here so nothing is written
// outside `outDir`. Returns [{ path, bytes }].
export async function renderPackage(pkgDir, outDir, { sharp = loadSharp() } = {}) {
  const root = resolve(pkgDir), out = resolve(outDir);
  const manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8"));
  const written = [];
  for (const { label, entry } of generatedEntries(manifest)) {
    const g = entry.generated;
    if (!SAFE_REL.test(entry.path) || g.sources.some((s) => !SAFE_REL.test(s))) throw new Error(label + ": unsafe path");
    const svg = readFileSync(join(root, ...g.sources[0].split("/")), "utf8");
    let buf;
    if (entry.format === "png") buf = await drawImage(sharp, svg, g, entry.width, entry.height);
    else if (entry.format === "ico" || entry.format === "icns") {
      const images = [];
      for (const size of g.sizes) images.push({ size, png: await drawImage(sharp, svg, g, size, size) });
      buf = entry.format === "ico" ? assembleIco(images) : assembleIcns(images);
    } else throw new Error(label + ": format " + entry.format + " is not generated");
    const target = join(out, ...entry.path.split("/"));
    if (!target.startsWith(out + sep)) throw new Error(label + ": output escapes the build folder");
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, buf);
    written.push({ path: entry.path, bytes: buf.length });
  }
  return written;
}

export function defaultOutDir(version) { return join(DEFAULT_BUILD_ROOT, version); }

async function main(argv) {
  const [pkg, outArg] = argv.filter((a) => !a.startsWith("--"));
  if (!pkg) { console.error("usage: render-design-handoff.mjs <design/handoff/VERSION> [out-dir]"); return 2; }
  const { checkPackage } = await import("./check-design-handoff.mjs");
  const { errors } = checkPackage(pkg);
  if (errors.length) {
    for (const e of errors) console.error(e.code + " " + e.path + ": " + e.message);
    console.error("the package does not pass check-design-handoff.mjs; nothing rendered");
    return 1;
  }
  const version = JSON.parse(readFileSync(join(resolve(pkg), "manifest.json"), "utf8")).version;
  const out = outArg ? resolve(outArg) : defaultOutDir(version);
  if (!outArg) rmSync(out, { recursive: true, force: true });
  const written = await renderPackage(pkg, out);
  for (const w of written) console.log(w.path + " " + w.bytes + " bytes");
  console.log("Rendered " + written.length + " generated file(s) into " + out + " (not committed).");
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Not top-level await: main imports check-design-handoff.mjs, which imports this module, and that
  // import must find this module fully evaluated.
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(e); process.exitCode = 1; });
}
