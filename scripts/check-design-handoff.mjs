#!/usr/bin/env node
// Validates an Orcel design handoff package (docs/orcel/design-handoff/CONTRACT.md) against
// docs/orcel/design-handoff/manifest.schema.json and the SVG, icon and token rules.
// Deterministic and offline: reads only the package folder (and, with --repo, Rust sources).
// A package holds text files only; raster icons and reference screens are `generated` entries that
// scripts/render-design-handoff.mjs renders at build time into a gitignored folder.
//
//   node scripts/check-design-handoff.mjs design/handoff/1.0.0
//   node scripts/check-design-handoff.mjs design/handoff/1.0.0 --integrate   (approved packages only)
//   node scripts/check-design-handoff.mjs design/handoff/1.0.0 --build [--out <dir>]
//        also renders the generated entries (sharp from apps/web) and decodes the outputs
//   node scripts/check-design-handoff.mjs --repo .                           (presentation isolation only)
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { basename, dirname, extname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { GENERATOR, GENERATOR_VERSION, ICNS_TYPE_BY_SIZE, RECIPES, defaultOutDir, generatedEntries } from "./render-design-handoff.mjs";

const here = dirname(fileURLToPath(import.meta.url));
export const SCHEMA_PATH = join(here, "..", "docs", "orcel", "design-handoff", "manifest.schema.json");

// ---------------------------------------------------------------------------------------------
// Minimal JSON Schema (2020-12) validator for the keywords manifest.schema.json uses. Unknown
// keywords are a programming error, so the schema cannot silently grow past what is enforced.
const KNOWN = new Set(["$schema", "$id", "$ref", "$defs", "title", "description", "type", "const", "enum",
  "pattern", "minLength", "maxLength", "minimum", "maximum", "minItems", "uniqueItems", "required",
  "properties", "additionalProperties", "items", "allOf", "if", "then"]);

// A package carries text only. Anything else (PNG, ICO, ICNS, JPG, WOFF, TTF, ...) is refused, even
// when listed: raster outputs are generated at build, fonts are obtained at build.
export const TEXT_EXTENSIONS = new Set([".json", ".svg", ".md", ".txt"]);
export function isTextFile(name, buf) {
  if (!TEXT_EXTENSIONS.has(extname(name).toLowerCase())) return false;
  if (buf.includes(0)) return false;
  try { new TextDecoder("utf-8", { fatal: true }).decode(buf); return true; } catch { return false; }
}

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  return typeof v;
}

export function validateSchema(schema, value, root = schema, at = "$", out = []) {
  for (const key of Object.keys(schema)) {
    if (!KNOWN.has(key)) throw new Error("manifest schema uses an unsupported keyword: " + key);
  }
  if (schema.$ref) {
    const m = /^#\/\$defs\/([A-Za-z0-9_]+)$/.exec(schema.$ref);
    if (!m || !root.$defs?.[m[1]]) throw new Error("unresolvable $ref " + schema.$ref);
    validateSchema(root.$defs[m[1]], value, root, at, out);
  }
  const t = typeOf(value);
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    const ok = types.some((x) => x === t || (x === "number" && t === "integer"));
    if (!ok) { out.push(at + ": expected " + types.join(" or ") + ", got " + t); return out; }
  }
  if ("const" in schema && JSON.stringify(schema.const) !== JSON.stringify(value)) out.push(at + ": must be " + JSON.stringify(schema.const));
  if (schema.enum && !schema.enum.some((e) => JSON.stringify(e) === JSON.stringify(value))) out.push(at + ": must be one of " + schema.enum.join(", "));
  if (t === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) out.push(at + ": shorter than " + schema.minLength);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) out.push(at + ": longer than " + schema.maxLength);
    if (schema.pattern !== undefined && !new RegExp(schema.pattern).test(value)) out.push(at + ": does not match " + schema.pattern);
  }
  if (t === "number" || t === "integer") {
    if (schema.minimum !== undefined && value < schema.minimum) out.push(at + ": below " + schema.minimum);
    if (schema.maximum !== undefined && value > schema.maximum) out.push(at + ": above " + schema.maximum);
  }
  if (t === "array") {
    if (schema.minItems !== undefined && value.length < schema.minItems) out.push(at + ": fewer than " + schema.minItems + " items");
    if (schema.uniqueItems && new Set(value.map((v) => JSON.stringify(v))).size !== value.length) out.push(at + ": items are not unique");
    if (schema.items) value.forEach((v, i) => validateSchema(schema.items, v, root, at + "[" + i + "]", out));
  }
  if (t === "object") {
    for (const r of schema.required ?? []) if (!(r in value)) out.push(at + ": missing " + r);
    for (const [k, v] of Object.entries(value)) {
      if (schema.properties?.[k]) validateSchema(schema.properties[k], v, root, at + "." + k, out);
      else if (schema.additionalProperties === false) out.push(at + ": unexpected property " + k);
    }
  }
  for (const sub of schema.allOf ?? []) validateSchema(sub, value, root, at, out);
  if (schema.if && validateSchema(schema.if, value, root, at, []).length === 0 && schema.then) {
    validateSchema(schema.then, value, root, at, out);
  }
  return out;
}

// ---------------------------------------------------------------------------------------------
// Icon requirements per platform. width x height in pixels; contains = sizes an ICO/ICNS must hold.
export const REQUIRED_ICONS = {
  web: [
    { role: "favicon-svg", format: "svg" },
    { role: "favicon-ico", format: "ico", contains: [16, 32, 48] },
    { role: "apple-touch-icon", format: "png", size: [180, 180] },
    { role: "icon-192", format: "png", size: [192, 192] },
    { role: "icon-512", format: "png", size: [512, 512] },
    { role: "social-card", format: "png", size: [1200, 630] }
  ],
  windows: [
    { role: "app-ico", format: "ico", contains: [16, 24, 32, 48, 64, 256] },
    { role: "msix-square44", format: "png", size: [44, 44] },
    { role: "msix-square44-scale200", format: "png", size: [88, 88] },
    { role: "msix-square150", format: "png", size: [150, 150] },
    { role: "msix-square150-scale200", format: "png", size: [300, 300] },
    { role: "msix-wide310", format: "png", size: [310, 150] },
    { role: "msix-store", format: "png", size: [50, 50] },
    { role: "msix-store-scale200", format: "png", size: [100, 100] }
  ],
  macos: [
    { role: "app-icns", format: "icns", contains: [16, 32, 64, 128, 256, 512, 1024] }
  ],
  // The default bundle.icon list of a Tauri 2 app, plus the 512 px source PNG. Tauri needs RGBA PNGs.
  tauri: [
    { role: "tauri-32", format: "png", size: [32, 32], rgba: true },
    { role: "tauri-128", format: "png", size: [128, 128], rgba: true },
    { role: "tauri-128-2x", format: "png", size: [256, 256], rgba: true },
    { role: "tauri-icon", format: "png", size: [512, 512], rgba: true },
    { role: "tauri-ico", format: "ico", contains: [16, 24, 32, 48, 64, 256] },
    { role: "tauri-icns", format: "icns", contains: [16, 32, 64, 128, 256, 512, 1024] }
  ]
};

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
export function readPng(buf) {
  if (buf.length < 33 || !buf.subarray(0, 8).equals(PNG_SIG) || buf.toString("latin1", 12, 16) !== "IHDR") return null;
  const iend = buf.length >= 12 && buf.toString("latin1", buf.length - 8, buf.length - 4) === "IEND";
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20), bitDepth: buf[24], colorType: buf[25], complete: iend };
}

export function readIco(buf) {
  if (buf.length < 6 || buf.readUInt16LE(0) !== 0 || buf.readUInt16LE(2) !== 1) return null;
  const count = buf.readUInt16LE(4);
  if (count === 0 || buf.length < 6 + count * 16) return null;
  const sizes = [];
  for (let i = 0; i < count; i++) {
    const e = 6 + i * 16;
    const w = buf[e] || 256, h = buf[e + 1] || 256;
    const len = buf.readUInt32LE(e + 8), off = buf.readUInt32LE(e + 12);
    if (off + len > buf.length || len === 0) return null;
    const png = readPng(buf.subarray(off, off + len));
    if (png && (png.width !== w || png.height !== h)) return null;
    sizes.push(w === h ? w : -1);
  }
  return { sizes };
}

// ICNS element types that carry PNG data, mapped to pixel size.
const ICNS_TYPES = { icp4: 16, icp5: 32, icp6: 64, ic07: 128, ic08: 256, ic09: 512, ic10: 1024, ic11: 32, ic12: 64, ic13: 256, ic14: 512 };
export function readIcns(buf) {
  if (buf.length < 8 || buf.toString("latin1", 0, 4) !== "icns" || buf.readUInt32BE(4) !== buf.length) return null;
  const sizes = new Set();
  let off = 8;
  while (off < buf.length) {
    if (off + 8 > buf.length) return null;
    const type = buf.toString("latin1", off, off + 4), len = buf.readUInt32BE(off + 4);
    if (len < 8 || off + len > buf.length) return null;
    if (type in ICNS_TYPES) {
      const png = readPng(buf.subarray(off + 8, off + len));
      if (!png || png.width !== ICNS_TYPES[type] || png.height !== ICNS_TYPES[type]) return null;
      sizes.add(ICNS_TYPES[type]);
    }
    off += len;
  }
  return { sizes: [...sizes].sort((a, b) => a - b) };
}

// ---------------------------------------------------------------------------------------------
// SVG rules: static, self-contained vector art.
const SVG_MAX_BYTES = 512 * 1024;
const OUTLINED_KINDS = new Set(["mark", "wordmark", "lockup", "app-tile"]);
export function svgProblems(text, kind) {
  const p = [];
  const body = text.replace(/^﻿/, "");
  if (!/^(<\?xml[^>]*\?>\s*)?<svg[\s>]/.test(body)) p.push(["SVG_ROOT", "must start with <svg> (an XML declaration is allowed)"]);
  if (!/<svg[^>]*\sxmlns="http:\/\/www\.w3\.org\/2000\/svg"/.test(body)) p.push(["SVG_ROOT", "missing the SVG namespace on <svg>"]);
  if (!/<svg[^>]*\sviewBox="[-0-9.\s,]+"/.test(body)) p.push(["SVG_VIEWBOX", "missing a numeric viewBox"]);
  if (/<!DOCTYPE|<!ENTITY/i.test(body)) p.push(["SVG_DOCTYPE", "DOCTYPE and entity declarations are not allowed"]);
  if (/<script\b/i.test(body)) p.push(["SVG_SCRIPT", "contains <script>"]);
  if (/\son[a-z]+\s*=/i.test(body)) p.push(["SVG_SCRIPT", "contains an event-handler attribute"]);
  if (/javascript:/i.test(body)) p.push(["SVG_SCRIPT", "contains a javascript: URL"]);
  if (/<foreignObject\b/i.test(body)) p.push(["SVG_FOREIGN", "contains <foreignObject>"]);
  if (/\s(xlink:)?href\s*=\s*["'](?!#)/i.test(body)) {
    p.push(["SVG_EXTERNAL", "an href points outside the document (only #fragment references are allowed)"]);
  }
  for (const m of body.matchAll(/url\(\s*["']?([^)"']*)/gi)) {
    if (!m[1].startsWith("#")) { p.push(["SVG_EXTERNAL", "url(" + m[1].slice(0, 40) + ") is not a #fragment reference"]); break; }
  }
  if (/@import/i.test(body)) p.push(["SVG_EXTERNAL", "contains @import"]);
  if (/<image\b/i.test(body)) p.push(["SVG_RASTER", "embeds a raster <image>"]);
  if (OUTLINED_KINDS.has(kind) && /<text\b/i.test(body)) p.push(["SVG_TEXT", "brand artwork must be outlined, not live <text>"]);
  if (!/<svg[^>]*\s(aria-label|aria-labelledby)="[^"]+"/.test(body) && !/<title>[^<]+<\/title>/.test(body)) {
    p.push(["SVG_A11Y", "needs an accessible name (aria-label on <svg> or a <title>)"]);
  }
  return p;
}

// ---------------------------------------------------------------------------------------------
// DTCG tokens.
export const REQUIRED_THEME_COLORS = ["background", "surface", "surface-raised", "border", "border-strong", "text",
  "text-muted", "accent", "on-accent", "danger", "focus", "success", "warning"];
export const REQUIRED_TOKENS = {
  "font.family.display": "fontFamily",
  "font.family.text": "fontFamily",
  "font.family.mono": "fontFamily",
  "size.radius.base": "dimension",
  "size.content-max": "dimension",
  "breakpoint.compact": "dimension",
  "breakpoint.medium": "dimension",
  "motion.duration.fast": "duration",
  "motion.duration.base": "duration",
  "motion.duration.slow": "duration",
  "motion.duration.reduced": "duration",
  "motion.easing.standard": "cubicBezier"
};
// [foreground, background, minimum ratio] evaluated in every theme. 4.5 = WCAG 2.2 AA text,
// 3 = non-text contrast (1.4.11) and focus indicators (2.4.13 guidance, 2.4.11 visibility).
export const REQUIRED_CONTRAST = [
  ["color.text", "color.background", 4.5],
  ["color.text", "color.surface", 4.5],
  ["color.text", "color.surface-raised", 4.5],
  ["color.text-muted", "color.background", 4.5],
  ["color.text-muted", "color.surface", 4.5],
  ["color.on-accent", "color.accent", 4.5],
  ["color.danger", "color.background", 4.5],
  ["color.success", "color.background", 4.5],
  ["color.warning", "color.background", 4.5],
  ["color.accent", "color.background", 3],
  ["color.focus", "color.background", 3],
  ["color.focus", "color.surface", 3]
];
const TOKEN_TYPES = new Set(["color", "dimension", "fontFamily", "fontWeight", "duration", "cubicBezier", "number"]);

function flattenTokens(node, path, inherited, out, errs) {
  if (typeof node !== "object" || node === null || Array.isArray(node)) { errs.push(["TOKEN_SHAPE", (path || "$") + " is not a group or token"]); return; }
  const type = node.$type ?? inherited;
  if ("$value" in node) {
    if (!TOKEN_TYPES.has(type)) errs.push(["TOKEN_TYPE", path + " has missing or unsupported $type " + type]);
    out.set(path, { type, value: node.$value });
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    if (k.startsWith("$")) continue;
    if (!/^[a-z0-9][a-z0-9-]*$/.test(k)) errs.push(["TOKEN_NAME", (path ? path + "." : "") + k + " is not a lowercase kebab-case name"]);
    flattenTokens(v, path ? path + "." + k : k, type, out, errs);
  }
}

function resolveToken(tokens, path, seen = []) {
  const t = tokens.get(path);
  if (!t) return { error: "unknown token " + path };
  if (typeof t.value === "string") {
    const m = /^\{([a-z0-9.-]+)\}$/.exec(t.value);
    if (m) {
      if (seen.includes(m[1])) return { error: "alias cycle " + [...seen, path, m[1]].join(" -> ") };
      return resolveToken(tokens, m[1], [...seen, path]);
    }
  }
  return { type: t.type, value: t.value };
}

export function parseColor(v) {
  if (typeof v === "string") {
    const m = /^#([0-9a-fA-F]{6})([0-9a-fA-F]{2})?$/.exec(v);
    if (!m) return null;
    const n = parseInt(m[1], 16);
    return { r: (n >> 16) / 255, g: ((n >> 8) & 255) / 255, b: (n & 255) / 255, a: m[2] ? parseInt(m[2], 16) / 255 : 1 };
  }
  if (v && typeof v === "object" && v.colorSpace === "srgb" && Array.isArray(v.components) && v.components.length === 3 &&
      v.components.every((c) => typeof c === "number" && c >= 0 && c <= 1)) {
    const a = v.alpha ?? 1;
    if (typeof a !== "number" || a < 0 || a > 1) return null;
    return { r: v.components[0], g: v.components[1], b: v.components[2], a };
  }
  return null;
}

function over(fg, bg) {
  const a = fg.a;
  return { r: fg.r * a + bg.r * (1 - a), g: fg.g * a + bg.g * (1 - a), b: fg.b * a + bg.b * (1 - a), a: 1 };
}
function luminance(c) {
  const lin = (x) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4);
  return 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
}
export function contrastRatio(fg, bg) {
  const [hi, lo] = [luminance(fg), luminance(bg)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

function checkValue(type, value) {
  switch (type) {
    case "color": return parseColor(value) ? null : "is not an sRGB colour (#RRGGBB, #RRGGBBAA or a DTCG srgb object)";
    case "dimension":
      if (typeof value === "string") return /^-?[0-9]+(\.[0-9]+)?(px|rem)$/.test(value) ? null : "is not a px or rem dimension";
      return value && typeof value.value === "number" && ["px", "rem"].includes(value.unit) ? null : "is not a px or rem dimension";
    case "duration":
      if (typeof value === "string") return /^[0-9]+(\.[0-9]+)?(ms|s)$/.test(value) ? null : "is not a duration in ms or s";
      return value && typeof value.value === "number" && value.value >= 0 && ["ms", "s"].includes(value.unit) ? null : "is not a duration in ms or s";
    case "cubicBezier":
      return Array.isArray(value) && value.length === 4 && value.every((n) => typeof n === "number") &&
        value[0] >= 0 && value[0] <= 1 && value[2] >= 0 && value[2] <= 1 ? null : "is not a cubicBezier [x1, y1, x2, y2] with x in 0..1";
    case "fontFamily":
      if (typeof value === "string") return value.length ? null : "is empty";
      return Array.isArray(value) && value.length && value.every((s) => typeof s === "string" && s.length) ? null : "is not a font family list";
    case "fontWeight": return (typeof value === "number" && value >= 1 && value <= 1000) || typeof value === "string" ? null : "is not a font weight";
    case "number": return typeof value === "number" ? null : "is not a number";
    default: return "has an unsupported type";
  }
}

function durationMs(value) {
  if (typeof value === "string") { const n = parseFloat(value); return value.endsWith("ms") ? n : n * 1000; }
  return value.unit === "ms" ? value.value : value.value * 1000;
}

export function tokenProblems(doc, extraPairs = []) {
  const errs = [];
  const tokens = new Map();
  flattenTokens(doc, "", undefined, tokens, errs);
  const resolved = new Map();
  for (const path of tokens.keys()) {
    const r = resolveToken(tokens, path);
    if (r.error) { errs.push(["TOKEN_ALIAS", path + ": " + r.error]); continue; }
    if (r.type !== tokens.get(path).type) { errs.push(["TOKEN_ALIAS", path + " aliases a token of another type"]); continue; }
    const bad = checkValue(r.type, r.value);
    if (bad) errs.push(["TOKEN_VALUE", path + " " + bad]);
    else resolved.set(path, r);
  }
  for (const [path, type] of Object.entries(REQUIRED_TOKENS)) {
    if (!tokens.has(path)) errs.push(["TOKEN_MISSING", path + " (" + type + ") is required"]);
    else if (tokens.get(path).type !== type) errs.push(["TOKEN_TYPE", path + " must be " + type]);
  }
  const reduced = resolved.get("motion.duration.reduced");
  if (reduced && durationMs(reduced.value) !== 0) errs.push(["TOKEN_MOTION", "motion.duration.reduced must be 0ms"]);
  for (const [path, r] of resolved) {
    if (r.type === "duration" && durationMs(r.value) > 1000 && path.startsWith("motion.duration.")) {
      errs.push(["TOKEN_MOTION", path + " is longer than 1000ms; interface motion must stay short"]);
    }
  }
  const themes = doc.theme && typeof doc.theme === "object" ? Object.keys(doc.theme).filter((k) => !k.startsWith("$")).sort() : [];
  if (JSON.stringify(themes) !== JSON.stringify(["dark", "light"])) errs.push(["TOKEN_THEME", "theme must contain exactly dark and light"]);
  const keysOf = (theme) => [...tokens.keys()].filter((k) => k.startsWith("theme." + theme + ".")).map((k) => k.slice(("theme." + theme + ".").length)).sort();
  if (themes.length === 2 && JSON.stringify(keysOf("dark")) !== JSON.stringify(keysOf("light"))) {
    errs.push(["TOKEN_THEME", "theme.dark and theme.light must define the same token names"]);
  }
  const contrast = [];
  for (const theme of themes) {
    for (const name of REQUIRED_THEME_COLORS) {
      if (!tokens.has("theme." + theme + ".color." + name)) errs.push(["TOKEN_MISSING", "theme." + theme + ".color." + name + " is required"]);
    }
    const bgBase = resolved.get("theme." + theme + ".color.background");
    for (const [fgPath, bgPath, min] of [...REQUIRED_CONTRAST, ...extraPairs.map((p) => [p.foreground, p.background, p.minimum])]) {
      const fg = resolved.get("theme." + theme + "." + fgPath), bg = resolved.get("theme." + theme + "." + bgPath);
      if (!fg || !bg || fg.type !== "color" || bg.type !== "color") continue;
      let bgc = parseColor(bg.value);
      if (bgc.a < 1) {
        if (!bgBase) continue;
        bgc = over(bgc, parseColor(bgBase.value));
      }
      const ratio = contrastRatio(over(parseColor(fg.value), bgc), bgc);
      contrast.push({ theme, foreground: fgPath, background: bgPath, ratio: Math.round(ratio * 100) / 100, minimum: min });
      if (ratio < min) errs.push(["TOKEN_CONTRAST", theme + ": " + fgPath + " on " + bgPath + " is " + ratio.toFixed(2) + ":1, needs " + min + ":1"]);
    }
  }
  return { errors: errs, contrast };
}

// ---------------------------------------------------------------------------------------------
function sha256(buf) { return createHash("sha256").update(buf).digest("hex"); }

function listFiles(dir, base = dir, out = []) {
  for (const name of readdirSync(dir).sort()) {
    const full = join(dir, name);
    const st = lstatSync(full);
    if (st.isSymbolicLink()) out.push({ rel: relative(base, full).split(sep).join("/"), link: true });
    else if (st.isDirectory()) listFiles(full, base, out);
    else out.push({ rel: relative(base, full).split(sep).join("/"), link: false });
  }
  return out;
}

export function checkPackage(dir, { integrate = false, schemaPath = SCHEMA_PATH } = {}) {
  const errors = [], notes = [];
  const err = (code, path, message) => errors.push({ code, path, message });
  const root = resolve(dir);
  let manifest;
  try { manifest = JSON.parse(readFileSync(join(root, "manifest.json"), "utf8")); } catch (e) {
    err("MANIFEST_READ", "manifest.json", e.code === "ENOENT" ? "missing" : "is not valid JSON");
    return { errors, notes, contrast: [] };
  }
  const schema = JSON.parse(readFileSync(schemaPath, "utf8"));
  for (const m of validateSchema(schema, manifest)) err("MANIFEST_SCHEMA", "manifest.json", m);
  if (errors.length) return { errors, notes, contrast: [] };

  if (basename(root) !== manifest.version) err("MANIFEST_VERSION", "manifest.json", "version " + manifest.version + " does not match folder " + basename(root));
  if (manifest.supersedes && manifest.supersedes === manifest.version) err("MANIFEST_VERSION", "manifest.json", "a package cannot supersede itself");
  if (manifest.status !== "approved") {
    if (integrate) err("NOT_APPROVED", "manifest.json", "status is " + manifest.status + "; only an approved package is integrated");
    else notes.push("status is " + manifest.status + ": checked, but not eligible for integration");
  }

  // Every referenced file exists inside the package, is not a link, and matches its hash.
  const files = listFiles(root);
  const realRoot = realpathSync(root);
  const referenced = new Map();
  const ref = (path, hash, what) => {
    if (referenced.has(path)) { err("MANIFEST_DUPLICATE", path, "listed more than once"); return null; }
    referenced.set(path, what);
    const entry = files.find((f) => f.rel === path);
    if (!entry) { err("FILE_MISSING", path, what + " is listed but not in the package"); return null; }
    if (entry.link) { err("FILE_LINK", path, "symbolic links are not allowed"); return null; }
    const full = join(root, ...path.split("/"));
    if (!realpathSync(full).startsWith(realRoot + sep)) { err("FILE_ESCAPE", path, "resolves outside the package"); return null; }
    const buf = readFileSync(full);
    if (sha256(buf) !== hash) { err("FILE_HASH", path, "sha256 does not match the manifest"); return null; }
    return buf;
  };

  for (const a of manifest.assets) {
    const buf = ref(a.path, a.sha256, "asset");
    if (!buf) continue;
    if (buf.length > SVG_MAX_BYTES) err("SVG_SIZE", a.path, "larger than " + SVG_MAX_BYTES + " bytes");
    for (const [code, message] of svgProblems(buf.toString("utf8"), a.kind)) err(code, a.path, message);
  }

  // No binary file may be committed in a package, listed or not.
  for (const f of files) {
    if (f.link) continue;
    if (!isTextFile(f.rel, readFileSync(join(root, ...f.rel.split("/"))))) {
      err("FILE_BINARY", f.rel, "is not a UTF-8 text file (.json, .svg, .md, .txt); raster icons and screens are generated at build and fonts are obtained at build, never committed");
    }
  }

  // Generated entries: build outputs declared with their SVG source, generator and recipe.
  const fileSet = new Set(files.map((f) => f.rel));
  const svgSources = new Set([...manifest.assets.map((a) => a.path),
    ...Object.values(manifest.icons).flat().filter((i) => i.sha256 && !i.generated && i.format === "svg").map((i) => i.path)]);
  const outputs = new Set();
  const liveText = [];
  const checkGenerated = (entry, label, need) => {
    const g = entry.generated;
    if (outputs.has(entry.path)) err("GENERATED_DUPLICATE", entry.path, "more than one generated entry writes this path");
    outputs.add(entry.path);
    if (fileSet.has(entry.path)) err("GENERATED_COMMITTED", entry.path, label + " is a build output and must not be committed");
    if (g.generator !== GENERATOR || g.generatorVersion !== GENERATOR_VERSION) {
      err("GENERATED_GENERATOR", entry.path, label + " names " + g.generator + " " + g.generatorVersion + "; this repository has " + GENERATOR + " " + GENERATOR_VERSION);
    }
    const recipe = RECIPES[g.recipe];
    for (const p of ["plate", "contentHeight"]) {
      if (recipe.params.includes(p) && g[p] === undefined) err("GENERATED_RECIPE", entry.path, label + ": recipe " + g.recipe + " needs " + p);
      if (!recipe.params.includes(p) && g[p] !== undefined) err("GENERATED_RECIPE", entry.path, label + ": recipe " + g.recipe + " does not take " + p);
    }
    if (g.sources.length !== 1) err("GENERATED_SOURCE", entry.path, label + ": every recipe renders from exactly one SVG source");
    for (const s of g.sources) {
      if (!svgSources.has(s)) { err("GENERATED_SOURCE", entry.path, label + ": source " + s + " is not an SVG asset or committed SVG icon of this package"); continue; }
      let text = "";
      try { text = readFileSync(join(root, ...s.split("/")), "utf8"); } catch { /* reported as FILE_MISSING */ }
      if (/<text\b/i.test(text)) liveText.push([entry.path, label, s]);
    }
    if (entry.format === "png") {
      if (g.sizes !== undefined) err("GENERATED_SIZE", entry.path, label + ": sizes apply to ICO and ICNS outputs only");
      if (entry.width === undefined || entry.height === undefined) err("GENERATED_SIZE", entry.path, label + " needs width and height");
      else if (need?.size && (entry.width !== need.size[0] || entry.height !== need.size[1])) {
        err("ICON_SIZE", entry.path, label + " is declared " + entry.width + "x" + entry.height + ", needs " + need.size.join("x"));
      }
    } else if (entry.format === "ico" || entry.format === "icns") {
      if (!g.sizes) { err("GENERATED_SIZE", entry.path, label + " needs generated.sizes"); return; }
      for (const s of need?.contains ?? []) if (!g.sizes.includes(s)) err("ICON_SIZE", entry.path, label + " lacks the " + s + "x" + s + " image");
      if (entry.format === "ico" && g.sizes.some((s) => s > 256)) err("GENERATED_SIZE", entry.path, label + ": ICO images are at most 256 px");
      if (entry.format === "icns" && g.sizes.some((s) => !ICNS_TYPE_BY_SIZE[s])) {
        err("GENERATED_SIZE", entry.path, label + ": ICNS PNG images are " + Object.keys(ICNS_TYPE_BY_SIZE).join(", ") + " px");
      }
    } else err("GENERATED_FORMAT", entry.path, label + ": " + entry.format + " is committed as a file, not generated");
  };

  for (const platform of Object.keys(REQUIRED_ICONS)) {
    const given = manifest.icons[platform];
    const roles = new Set();
    for (const icon of given) {
      if (roles.has(icon.role)) err("ICON_DUPLICATE", icon.path, platform + " role " + icon.role + " listed twice");
      roles.add(icon.role);
      const need = REQUIRED_ICONS[platform].find((r) => r.role === icon.role);
      if (need && need.format !== icon.format) err("ICON_FORMAT", icon.path, icon.role + " must be " + need.format);
      if (!icon.path.toLowerCase().endsWith("." + icon.format)) err("ICON_FORMAT", icon.path, "extension does not match format " + icon.format);
      if (icon.generated && icon.sha256) { err("ICON_SOURCE", icon.path, "has both sha256 and generated; a committed SVG has sha256, a build output has generated"); continue; }
      if (icon.generated) { checkGenerated(icon, platform + " " + icon.role, need); continue; }
      if (!icon.sha256) { err("ICON_SOURCE", icon.path, "needs sha256 (a committed SVG) or generated (a build output)"); continue; }
      if (icon.format !== "svg") err("ICON_BINARY", icon.path, icon.role + ": " + icon.format.toUpperCase() + " icons are generated at build, never committed");
      const buf = ref(icon.path, icon.sha256, platform + " icon");
      if (buf && icon.format === "svg") {
        for (const [code, message] of svgProblems(buf.toString("utf8"), "app-tile")) err(code, icon.path, message);
      }
    }
    for (const r of REQUIRED_ICONS[platform]) if (!roles.has(r.role)) err("ICON_MISSING", "manifest.json", platform + " needs " + r.role);
  }

  const tokenBuf = ref(manifest.tokens.path, manifest.tokens.sha256, "tokens");
  let contrast = [];
  if (tokenBuf) {
    let doc;
    try { doc = JSON.parse(tokenBuf.toString("utf8")); } catch { err("TOKEN_SHAPE", manifest.tokens.path, "is not valid JSON"); }
    if (doc) {
      const result = tokenProblems(doc, manifest.contrastPairs ?? []);
      for (const [code, message] of result.errors) err(code, manifest.tokens.path, message);
      contrast = result.contrast;
    }
  }

  for (const c of manifest.components) {
    const buf = ref(c.spec, c.sha256, "component spec");
    if (!c.states.includes("default") || !c.states.includes("focus")) err("COMPONENT_STATES", c.spec, c.name + " must specify at least default and focus");
    if (buf && /\.md$/.test(c.spec)) {
      const text = buf.toString("utf8");
      for (const section of ["States", "Keyboard", "Accessibility", "Motion"]) {
        if (!new RegExp("^#+\\s+" + section + "\\b", "m").test(text)) err("COMPONENT_SPEC", c.spec, "missing a " + section + " section");
      }
    }
  }
  const boardOnly = [];
  for (const s of manifest.screens) {
    const label = "screen " + s.name;
    if (s.generated) {
      if (!s.path || s.height === undefined) { err("GENERATED_SIZE", s.path ?? "manifest.json", label + " needs path and height"); continue; }
      checkGenerated({ ...s, format: "png" }, label, null);
    } else if (s.board) {
      if (s.path || s.height !== undefined) err("SCREEN_SOURCE", "manifest.json", label + ": a board reference has no path or height; only a generated screen is rendered");
      boardOnly.push(s.name);
    } else err("SCREEN_SOURCE", "manifest.json", label + " needs generated (an SVG source rendered at build) or a board reference");
  }
  if (boardOnly.length) {
    const what = boardOnly.length + " screen(s) are board references only (" + boardOnly.join(", ") + ")";
    if (integrate) err("SCREEN_NOT_RENDERABLE", "manifest.json", what + "; an approved package renders every screen from an SVG source in the package");
    else notes.push(what + ": provenance, not rendered; refused at integration");
  }
  // A generated raster must look the same on every build machine, so its SVG source is outlined.
  for (const [path, label, src] of liveText) {
    if (integrate) err("GENERATED_LIVE_TEXT", path, label + ": source " + src + " has live <text>; outline it so the render does not depend on installed fonts");
    else notes.push(label + ": source " + src + " has live <text>, rendered with whatever fonts the build machine has; outline it before approval");
  }
  for (const n of manifest.notices) {
    const entry = files.find((f) => f.rel === n.path);
    if (!entry) err("FILE_MISSING", n.path, "notice is listed but not in the package");
    referenced.set(n.path, "notice");
  }

  for (const f of files) {
    if (f.rel === "manifest.json") continue;
    if (!referenced.has(f.rel)) err("FILE_UNLISTED", f.rel, "is in the package but not in the manifest");
  }
  errors.sort((a, b) => (a.path + a.code + a.message).localeCompare(b.path + b.code + b.message));
  return { errors, notes, contrast };
}

// Decodes the rendered outputs of every generated entry in `outDir` (the --build check): each file
// exists, PNGs are complete 8-bit images of the declared size (RGBA where the role needs it), and
// ICO/ICNS containers are well formed and hold exactly the declared sizes.
export function checkBuildOutputs(manifest, outDir) {
  const errors = [];
  const err = (code, path, message) => errors.push({ code, path, message });
  const out = resolve(outDir);
  for (const { kind, platform, label, entry } of generatedEntries(manifest)) {
    const full = join(out, ...entry.path.split("/"));
    if (!existsSync(full)) { err("BUILD_MISSING", entry.path, label + " was not rendered"); continue; }
    const buf = readFileSync(full);
    const need = kind === "icon" ? REQUIRED_ICONS[platform]?.find((r) => r.role === entry.role) : undefined;
    if (entry.format === "png") {
      const png = readPng(buf);
      if (!png || !png.complete || png.bitDepth !== 8) { err("ICON_DECODE", entry.path, label + ": not a complete 8-bit PNG"); continue; }
      if (png.width !== entry.width || png.height !== entry.height) {
        err("ICON_SIZE", entry.path, label + " rendered " + png.width + "x" + png.height + ", declared " + entry.width + "x" + entry.height);
      }
      if (need?.rgba && png.colorType !== 6) err("ICON_RGBA", entry.path, label + " must be RGBA (PNG colour type 6)");
    } else {
      const parsed = entry.format === "ico" ? readIco(buf) : readIcns(buf);
      if (!parsed) { err("ICON_DECODE", entry.path, label + ": not a well-formed " + entry.format.toUpperCase()); continue; }
      const want = [...entry.generated.sizes].sort((a, b) => a - b), got = [...parsed.sizes].sort((a, b) => a - b);
      if (JSON.stringify(want) !== JSON.stringify(got)) err("ICON_SIZE", entry.path, label + " holds " + got.join(", ") + "; declared " + want.join(", "));
    }
  }
  errors.sort((a, b) => (a.path + a.code + a.message).localeCompare(b.path + b.code + b.message));
  return errors;
}

// ---------------------------------------------------------------------------------------------
// Presentation isolation: privileged Rust code never embeds or reads presentation files.
const PRESENTATION_EXT = /\.(svg|css|html?|png|ico|icns|woff2?|ttf|otf)\b/i;
export function presentationIsolationProblems(repoRoot) {
  const problems = [];
  const roots = [join(repoRoot, "crates")];
  try {
    for (const app of readdirSync(join(repoRoot, "apps")).sort()) roots.push(join(repoRoot, "apps", app, "src-tauri", "src"));
  } catch { /* no apps folder */ }
  const walk = (dir) => {
    let names;
    try { names = readdirSync(dir).sort(); } catch { return; }
    for (const name of names) {
      if (name === "target" || name === "node_modules") continue;
      const full = join(dir, name);
      const st = lstatSync(full);
      if (st.isDirectory()) walk(full);
      else if (name.endsWith(".rs")) {
        const text = readFileSync(full, "utf8");
        const rel = relative(repoRoot, full).split(sep).join("/");
        if (/design[\\/]handoff|design-handoff/.test(text)) problems.push(rel + ": references the design handoff package");
        for (const m of text.matchAll(/include_(?:str|bytes)!\s*\(\s*"([^"]+)"/g)) {
          if (PRESENTATION_EXT.test(m[1]) || /tokens?\.json$/i.test(m[1])) problems.push(rel + ": embeds presentation file " + m[1]);
        }
      }
    }
  };
  for (const r of roots) walk(r);
  return problems;
}

// ---------------------------------------------------------------------------------------------
async function main(argv) {
  const repoIdx = argv.indexOf("--repo");
  if (repoIdx !== -1) {
    const problems = presentationIsolationProblems(resolve(argv[repoIdx + 1] ?? "."));
    if (problems.length) { console.error("Presentation isolation failed:\n" + problems.join("\n")); return 1; }
    console.log("Presentation isolation: no Rust source embeds or references presentation files.");
    return 0;
  }
  const outIdx = argv.indexOf("--out");
  const outArg = outIdx !== -1 ? argv[outIdx + 1] : undefined;
  const dir = argv.find((a, i) => !a.startsWith("--") && !(outIdx !== -1 && i === outIdx + 1));
  if (!dir || (outIdx !== -1 && !outArg)) {
    console.error("usage: check-design-handoff.mjs <design/handoff/VERSION> [--integrate] [--build [--out <dir>]] | --repo <root>");
    return 2;
  }
  const { errors, notes, contrast } = checkPackage(dir, { integrate: argv.includes("--integrate") });
  for (const n of notes) console.log("note: " + n);
  for (const c of contrast) console.log("contrast " + c.theme + " " + c.foreground + " on " + c.background + ": " + c.ratio + ":1 (min " + c.minimum + ")");
  if (errors.length) {
    for (const e of errors) console.error(e.code + " " + e.path + ": " + e.message);
    console.error(errors.length + " problem(s); the package is not accepted.");
    return 1;
  }
  if (argv.includes("--build")) {
    const manifest = JSON.parse(readFileSync(join(resolve(dir), "manifest.json"), "utf8"));
    const out = outArg ? resolve(outArg) : defaultOutDir(manifest.version);
    if (!outArg) rmSync(out, { recursive: true, force: true });
    const { renderPackage } = await import("./render-design-handoff.mjs");
    const written = await renderPackage(dir, out);
    const buildErrors = checkBuildOutputs(manifest, out);
    if (buildErrors.length) {
      for (const e of buildErrors) console.error(e.code + " " + e.path + ": " + e.message);
      console.error(buildErrors.length + " problem(s) in the generated outputs in " + out + "; the package is not accepted.");
      return 1;
    }
    console.log("Generated outputs rendered and decoded: " + written.length + " file(s) in " + out + " (not committed).");
  }
  console.log("Design handoff package accepted by the checks: " + dir);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (e) => { console.error(e); process.exitCode = 1; });
}
