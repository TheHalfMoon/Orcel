#!/usr/bin/env node
// Builds the synthetic design handoff package used by scripts/check-design-handoff.test.mjs from the
// text files in source/. Like a real package it is text only: raster icons and the screen are
// generated entries. writeSyntheticOutputs() writes grey PNG, ICO and ICNS stand-ins for them so the
// build-output checks can be tested without sharp (binaries are never committed).
// Everything here is a neutral grey test fixture: no Orcel artwork, colours or type.
//   node scripts/fixtures/design-handoff/make-fixture-package.mjs <output-parent-folder>
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { crc32, deflateSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const sha = (b) => createHash("sha256").update(b).digest("hex");

function chunk(type, data) {
  const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "latin1"), data]);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
export function png(w, h, grey = 0x80) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  const row = Buffer.alloc(1 + w * 4, grey); row[0] = 0;
  for (let x = 0; x < w; x++) row[1 + x * 4 + 3] = 0xff;
  const raw = Buffer.concat(Array.from({ length: h }, () => row));
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })), chunk("IEND", Buffer.alloc(0))]);
}
export function ico(sizes) {
  const images = sizes.map((s) => png(s, s));
  const head = Buffer.alloc(6); head.writeUInt16LE(1, 2); head.writeUInt16LE(sizes.length, 4);
  let offset = 6 + 16 * sizes.length;
  const dir = sizes.map((s, i) => {
    const e = Buffer.alloc(16);
    e[0] = s >= 256 ? 0 : s; e[1] = s >= 256 ? 0 : s;
    e.writeUInt16LE(1, 4); e.writeUInt16LE(32, 6);
    e.writeUInt32LE(images[i].length, 8); e.writeUInt32LE(offset, 12);
    offset += images[i].length;
    return e;
  });
  return Buffer.concat([head, ...dir, ...images]);
}
export function icns(entries) {
  const parts = entries.map(([type, s]) => {
    const data = png(s, s);
    const h = Buffer.alloc(8); h.write(type, 0, "latin1"); h.writeUInt32BE(8 + data.length, 4);
    return Buffer.concat([h, data]);
  });
  const body = Buffer.concat(parts);
  const h = Buffer.alloc(8); h.write("icns", 0, "latin1"); h.writeUInt32BE(8 + body.length, 4);
  return Buffer.concat([h, body]);
}

const ICNS_TYPE = { 16: "icp4", 32: "icp5", 64: "icp6", 128: "ic07", 256: "ic08", 512: "ic09", 1024: "ic10" };
const ICNS_FULL = [16, 32, 64, 128, 256, 512, 1024];
const ICO_APP = [16, 24, 32, 48, 64, 256];

// The package itself is text only. Raster icons and the screen are generated entries.
const source = (name) => readFileSync(join(here, "source", name));
const files = () => new Map([
  ["assets/fixture-mark.svg", source("fixture-mark.svg")],
  ["icons/web/favicon.svg", source("favicon.svg")],
  ["tokens/tokens.json", source("tokens.json")],
  ["components/fixture-button.md", source("fixture-button.md")],
  ["notices/NOTICE.txt", source("NOTICE.txt")]
]);

const gen = (recipe, extra = {}, src = "assets/fixture-mark.svg") =>
  ({ sources: [src], generator: "scripts/render-design-handoff.mjs", generatorVersion: "1.0.0", recipe, ...extra });
const pngIcon = (role, path, w, h = w, g = gen("render")) => ({ role, path, format: "png", width: w, height: h, generated: g });
const setIcon = (role, path, format, sizes) => ({ role, path, format, generated: gen("render", { sizes }) });
const bleed = () => gen("full-bleed", { plate: "#C0C0C0" }, "icons/web/favicon.svg");

// Writes the complete synthetic package into <parent>/1.0.0 and returns that folder.
export function writePackage(parent) {
  const out = join(parent, "1.0.0");
  const all = files();
  rmSync(out, { recursive: true, force: true });
  for (const [path, data] of all) {
    mkdirSync(dirname(join(out, path)), { recursive: true });
    writeFileSync(join(out, path), data);
  }
  const h = (p) => sha(all.get(p));
  const manifest = {
    schemaVersion: "orcel-design-handoff/1",
    version: "1.0.0",
    status: "approved",
    approval: { approvedBy: "design-session", approvedOn: "2026-01-01", record: "synthetic fixture, no real approval" },
    supersedes: null,
    identity: { name: "Synthetic fixture", edition: "test", notes: "Not an Orcel identity." },
    source: { session: "check-design-handoff tests", createdOn: "2026-01-01" },
    assets: [{ path: "assets/fixture-mark.svg", kind: "mark", sha256: h("assets/fixture-mark.svg"), background: "any" }],
    icons: {
      web: [
        { role: "favicon-svg", path: "icons/web/favicon.svg", format: "svg", sha256: h("icons/web/favicon.svg") },
        setIcon("favicon-ico", "icons/web/favicon.ico", "ico", [16, 32, 48]),
        pngIcon("apple-touch-icon", "icons/web/apple-touch-icon.png", 180, 180, bleed()),
        pngIcon("icon-192", "icons/web/icon-192.png", 192),
        pngIcon("icon-512", "icons/web/icon-512.png", 512),
        pngIcon("social-card", "icons/web/social-card.png", 1200, 630)
      ],
      windows: [
        setIcon("app-ico", "icons/windows/app.ico", "ico", ICO_APP),
        pngIcon("msix-square44", "icons/windows/Square44x44Logo.png", 44, 44, bleed()),
        pngIcon("msix-square44-scale200", "icons/windows/Square44x44Logo.scale-200.png", 88, 88, bleed()),
        pngIcon("msix-square150", "icons/windows/Square150x150Logo.png", 150, 150, bleed()),
        pngIcon("msix-square150-scale200", "icons/windows/Square150x150Logo.scale-200.png", 300, 300, bleed()),
        pngIcon("msix-wide310", "icons/windows/Wide310x150Logo.png", 310, 150, gen("centered-on-plate", { plate: "#C0C0C0", contentHeight: 90 })),
        pngIcon("msix-store", "icons/windows/StoreLogo.png", 50, 50, bleed()),
        pngIcon("msix-store-scale200", "icons/windows/StoreLogo.scale-200.png", 100, 100, bleed())
      ],
      macos: [setIcon("app-icns", "icons/macos/app.icns", "icns", ICNS_FULL)],
      tauri: [
        pngIcon("tauri-32", "icons/tauri/32x32.png", 32), pngIcon("tauri-128", "icons/tauri/128x128.png", 128),
        pngIcon("tauri-128-2x", "icons/tauri/128x128@2x.png", 256), pngIcon("tauri-icon", "icons/tauri/icon.png", 512),
        setIcon("tauri-ico", "icons/tauri/icon.ico", "ico", ICO_APP), setIcon("tauri-icns", "icons/tauri/icon.icns", "icns", ICNS_FULL)
      ]
    },
    tokens: { path: "tokens/tokens.json", format: "dtcg", sha256: h("tokens/tokens.json") },
    contrastPairs: [{ foreground: "color.text-muted", background: "color.surface-raised", minimum: 4.5, use: "secondary text on raised panels" }],
    components: [{ name: "fixture-button", spec: "components/fixture-button.md", sha256: h("components/fixture-button.md"),
      states: ["default", "hover", "focus", "active", "disabled", "loading"], surfaces: ["shared"] }],
    screens: [{ surface: "website", name: "home", theme: "dark", width: 320, height: 200, path: "screens/website-home-dark.png", generated: gen("render") }],
    notices: [{ path: "notices/NOTICE.txt", covers: "the whole synthetic fixture" }]
  };
  writeFileSync(join(out, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
  return out;
}

// Writes grey stand-ins for every generated output of `manifest` into `outDir`, at the declared
// sizes, so the build-output checks can be tested without sharp.
export function writeSyntheticOutputs(manifest, outDir) {
  const entries = [...Object.values(manifest.icons).flat().filter((i) => i.generated),
    ...manifest.screens.filter((s) => s.generated).map((s) => ({ ...s, format: "png" }))];
  for (const e of entries) {
    const data = e.format === "png" ? png(e.width, e.height)
      : e.format === "ico" ? ico(e.generated.sizes) : icns(e.generated.sizes.map((s) => [ICNS_TYPE[s], s]));
    mkdirSync(dirname(join(outDir, e.path)), { recursive: true });
    writeFileSync(join(outDir, e.path), data);
  }
  return outDir;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv[2]) { console.error("usage: make-fixture-package.mjs <output-parent-folder>"); process.exit(2); }
  console.log("wrote the synthetic package to " + writePackage(resolve(process.argv[2])));
}
