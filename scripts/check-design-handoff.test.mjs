import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";
import {
  checkPackage, contrastRatio, parseColor, presentationIsolationProblems, readIcns, readIco, readPng, validateSchema
} from "./check-design-handoff.mjs";
import { ico, png, writePackage } from "./fixtures/design-handoff/make-fixture-package.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const SOURCE = join(here, "fixtures", "design-handoff", "source");
// The synthetic package is built once per run from the committed text fixtures plus generated grey
// PNG, ICO and ICNS files, so no binary is kept in Git.
const BUILD = mkdtempSync(join(tmpdir(), "orcel-handoff-fixture-"));
const VALID = writePackage(BUILD);
after(() => rmSync(BUILD, { recursive: true, force: true }));
const sha = (b) => createHash("sha256").update(b).digest("hex");

// Copy the synthetic package to a temp folder, let the test change it, and refresh the manifest
// hashes (unless asked not to) so each test isolates one rule.
function variant(change, { rehash = true, folder = "1.0.0" } = {}) {
  const base = mkdtempSync(join(tmpdir(), "orcel-handoff-"));
  const dir = join(base, folder);
  cpSync(VALID, dir, { recursive: true });
  const m = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
  const write = (rel, data) => { mkdirSync(dirname(join(dir, rel)), { recursive: true }); writeFileSync(join(dir, rel), data); };
  const read = (rel) => readFileSync(join(dir, rel));
  change({ m, write, read, dir });
  if (rehash) {
    const fix = (o, key) => { try { o.sha256 = sha(read(o[key])); } catch { /* missing on purpose */ } };
    m.assets.forEach((a) => fix(a, "path"));
    Object.values(m.icons).flat().forEach((i) => fix(i, "path"));
    fix(m.tokens, "path");
    m.components.forEach((c) => fix(c, "spec"));
    m.screens.forEach((s) => fix(s, "path"));
  }
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(m, null, 2));
  return { dir, cleanup: () => rmSync(base, { recursive: true, force: true }) };
}
function codes(change, opts = {}, checkOpts = { integrate: true }) {
  const { dir, cleanup } = variant(change, opts);
  try { return checkPackage(dir, checkOpts).errors.map((e) => e.code).sort(); } finally { cleanup(); }
}
const tokensOf = (read, m) => JSON.parse(read(m.tokens.path).toString("utf8"));
const writeTokens = (write, m, t) => write(m.tokens.path, JSON.stringify(t, null, 2));

test("the committed synthetic package passes integration checks", () => {
  const r = checkPackage(VALID, { integrate: true });
  assert.deepEqual(r.errors, []);
  assert.ok(r.contrast.length >= 24, "contrast evaluated for both themes");
});

test("the fixture is clearly synthetic, not brand material", () => {
  const m = JSON.parse(readFileSync(join(VALID, "manifest.json"), "utf8"));
  assert.match(m.identity.notes, /Not an Orcel identity/);
  for (const name of ["fixture-mark.svg", "favicon.svg"]) {
    assert.match(readFileSync(join(SOURCE, name), "utf8"), /not an Orcel asset/);
  }
  assert.match(readFileSync(join(SOURCE, "tokens.json"), "utf8"), /Synthetic test fixture/);
  assert.doesNotMatch(readFileSync(join(SOURCE, "tokens.json"), "utf8"), /#090C12|#A6ACE6|#5A61B8|#1838B1|#F6EDE0/i);
});

test("only an approved manifest is integrated; draft packages are checked but refused", () => {
  const draft = (c) => { c.m.status = "draft"; delete c.m.approval; };
  assert.deepEqual(codes(draft, {}, { integrate: false }), []);
  assert.deepEqual(codes(draft), ["NOT_APPROVED"]);
  assert.deepEqual(codes(({ m }) => { delete m.approval; }), ["MANIFEST_SCHEMA"]);
  assert.deepEqual(codes(({ m }) => { m.approval.approvedBy = "anyone"; }), ["MANIFEST_SCHEMA"]);
});

test("version must match the folder and the schema refuses unknown fields and unsafe paths", () => {
  assert.deepEqual(codes(() => {}, { folder: "1.0.1" }), ["MANIFEST_VERSION"]);
  assert.deepEqual(codes(({ m }) => { m.extra = true; }), ["MANIFEST_SCHEMA"]);
  for (const bad of ["../escape.svg", "/abs.svg", "C:/x.svg", "a/./b.svg", "https://example.invalid/x.svg"]) {
    assert.ok(codes(({ m }) => { m.assets[0].path = bad; }, { rehash: false }).includes("MANIFEST_SCHEMA"), bad);
  }
});

test("files must match their hashes and nothing unlisted may ride along", () => {
  assert.deepEqual(codes(({ write }) => { write("assets/fixture-mark.svg", "<svg/>"); }, { rehash: false }), ["FILE_HASH"]);
  assert.deepEqual(codes(({ write }) => { write("assets/extra.svg", "<svg/>"); }), ["FILE_UNLISTED"]);
  assert.deepEqual(codes(({ dir }) => { renameSync(join(dir, "screens/website-home-dark.png"), join(dir, "screens/gone.png")); }),
    ["FILE_MISSING", "FILE_UNLISTED"]);
});

test("SVG rules: no scripts, handlers, external references, raster images or live text in brand art", () => {
  const svg = (inner, attrs = ' role="img" aria-label="synthetic"') =>
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"' + attrs + '>' + inner + "</svg>";
  const one = (body, kind = "mark") => codes(({ m, write }) => { m.assets[0].kind = kind; write("assets/fixture-mark.svg", body); });
  assert.deepEqual(one(svg("<script>1</script>")), ["SVG_SCRIPT"]);
  assert.deepEqual(one(svg('<rect onload="x()"/>')), ["SVG_SCRIPT"]);
  assert.deepEqual(one(svg('<use href="https://example.invalid/a.svg#x"/>')), ["SVG_EXTERNAL"]);
  assert.deepEqual(one(svg('<rect fill="url(https://example.invalid/p)"/>')), ["SVG_EXTERNAL"]);
  assert.deepEqual(one(svg('<image href="data:image/png;base64,AA"/>')), ["SVG_EXTERNAL", "SVG_RASTER"]);
  assert.deepEqual(one(svg("<foreignObject/>")), ["SVG_FOREIGN"]);
  assert.deepEqual(one(svg("<text>orcel</text>"), "wordmark"), ["SVG_TEXT"]);
  assert.deepEqual(one(svg("<text>caption</text>"), "social"), []);
  assert.deepEqual(one(svg('<rect fill="url(#g)"/><use href="#g"/>')), []);
  assert.deepEqual(one(svg("<rect/>", "")), ["SVG_A11Y"]);
  assert.deepEqual(one('<!DOCTYPE svg [<!ENTITY x "y">]>' + svg("<rect/>")), ["SVG_DOCTYPE", "SVG_ROOT"]);
});

test("icons: every platform role, every size, the right container and RGBA for Tauri", () => {
  assert.deepEqual(codes(({ m }) => { m.icons.macos[0].role = "other"; }),
    ["ICON_MISSING"]);
  assert.deepEqual(codes(({ write }) => { write("icons/windows/app.ico", ico([16, 24, 32, 48, 64])); }), ["ICON_SIZE"]);
  assert.deepEqual(codes(({ write }) => { write("icons/web/apple-touch-icon.png", png(176, 176)); }), ["ICON_SIZE"]);
  assert.deepEqual(codes(({ write }) => {
    const b = png(32, 32); b[25] = 2; // relabel as RGB: synthetic corruption for the test
    write("icons/tauri/32x32.png", b);
  }), ["ICON_RGBA"]);
  assert.deepEqual(codes(({ write }) => { write("icons/macos/app.icns", Buffer.from("icns\0\0\0\x10garbage!", "latin1")); }), ["ICON_DECODE"]);
  assert.deepEqual(codes(({ m }) => { m.icons.web.find((i) => i.role === "favicon-ico").format = "png"; }), ["ICON_DECODE", "ICON_FORMAT", "ICON_FORMAT"]);
});

test("binary readers parse the synthetic containers", () => {
  assert.deepEqual(readIco(readFileSync(join(VALID, "icons/tauri/icon.ico"))).sizes, [16, 24, 32, 48, 64, 256]);
  assert.deepEqual(readIcns(readFileSync(join(VALID, "icons/macos/app.icns"))).sizes, [16, 32, 64, 128, 256, 512, 1024]);
  const p = readPng(readFileSync(join(VALID, "icons/web/social-card.png")));
  assert.equal(p.width, 1200); assert.equal(p.height, 630); assert.equal(p.colorType, 6);
  assert.equal(readPng(Buffer.from("not a png")), null);
});

test("tokens: required names, both themes, aliases, motion and WCAG 2.2 AA contrast", () => {
  assert.deepEqual(codes(({ m, read, write }) => {
    const t = tokensOf(read, m); t.theme.dark.color["text-muted"].$value = "#3a3a3a"; writeTokens(write, m, t);
  }), ["TOKEN_CONTRAST", "TOKEN_CONTRAST", "TOKEN_CONTRAST"]);
  const cycle = codes(({ m, read, write }) => {
    const t = tokensOf(read, m); t.palette["grey-900"].$value = "{theme.dark.color.background}"; writeTokens(write, m, t);
  });
  assert.ok(cycle.length > 0 && cycle.every((c) => c === "TOKEN_ALIAS"), cycle.join(","));
  assert.deepEqual(codes(({ m, read, write }) => {
    const t = tokensOf(read, m); delete t.theme.light.color.focus; writeTokens(write, m, t);
  }), ["TOKEN_MISSING", "TOKEN_THEME"]);
  assert.deepEqual(codes(({ m, read, write }) => {
    const t = tokensOf(read, m); t.motion.duration.reduced.$value = { value: 80, unit: "ms" }; writeTokens(write, m, t);
  }), ["TOKEN_MOTION"]);
  assert.deepEqual(codes(({ m, read, write }) => {
    const t = tokensOf(read, m); t.motion.duration.slow.$value = "2s"; writeTokens(write, m, t);
  }), ["TOKEN_MOTION"]);
  assert.deepEqual(codes(({ m, read, write }) => {
    const t = tokensOf(read, m); t.theme.dark.color.accent.$value = "rgb(1,2,3)"; writeTokens(write, m, t);
  }), ["TOKEN_VALUE"]);
  assert.deepEqual(codes(({ m, read, write }) => {
    const t = tokensOf(read, m); t.breakpoint.medium.$value = "60em"; writeTokens(write, m, t);
  }), ["TOKEN_VALUE"]);
});

test("component specs carry states, keyboard, accessibility and motion", () => {
  assert.deepEqual(codes(({ m, read, write }) => {
    write(m.components[0].spec, read(m.components[0].spec).toString("utf8").replace("## Keyboard", "## Keys"));
  }), ["COMPONENT_SPEC"]);
  assert.deepEqual(codes(({ m }) => { m.components[0].states = ["default", "hover"]; }), ["COMPONENT_STATES"]);
});

test("contrast and colour helpers follow the WCAG formula", () => {
  assert.equal(Math.round(contrastRatio(parseColor("#000000"), parseColor("#ffffff")) * 100) / 100, 21);
  assert.equal(Math.round(contrastRatio(parseColor("#777777"), parseColor("#ffffff")) * 100) / 100, 4.48);
  assert.deepEqual(parseColor({ colorSpace: "srgb", components: [1, 1, 1] }), { r: 1, g: 1, b: 1, a: 1 });
  assert.equal(parseColor("#fff"), null);
});

test("the schema validator refuses keywords it does not enforce", () => {
  assert.throws(() => validateSchema({ oneOf: [] }, 1), /unsupported keyword/);
  assert.deepEqual(validateSchema({ type: "string", pattern: "^a" }, "b").length, 1);
});

test("privileged Rust code never embeds presentation files", () => {
  assert.deepEqual(presentationIsolationProblems(repo), []);
  const base = mkdtempSync(join(tmpdir(), "orcel-isolation-"));
  try {
    mkdirSync(join(base, "crates", "x", "src"), { recursive: true });
    writeFileSync(join(base, "crates", "x", "src", "lib.rs"), 'const C: &str = include_str!("../../ui/style.css");\n');
    mkdirSync(join(base, "apps", "y", "src-tauri", "src"), { recursive: true });
    writeFileSync(join(base, "apps", "y", "src-tauri", "src", "main.rs"), '// loads design/handoff/1.0.0/tokens/tokens.json\n');
    const p = presentationIsolationProblems(base);
    assert.equal(p.length, 2);
    assert.match(p.join("\n"), /embeds presentation file \.\.\/\.\.\/ui\/style\.css/);
  } finally { rmSync(base, { recursive: true, force: true }); }
});

test("the CLI exits 0 for an accepted package and 1 otherwise, without network", () => {
  const script = join(here, "check-design-handoff.mjs");
  assert.match(execFileSync(process.execPath, [script, VALID, "--integrate"], { encoding: "utf8" }), /accepted by the checks/);
  const { dir, cleanup } = variant(({ m }) => { m.status = "review"; delete m.approval; });
  try {
    const r = spawnSync(process.execPath, [script, dir, "--integrate"], { encoding: "utf8" });
    assert.equal(r.status, 1);
    assert.match(r.stderr, /NOT_APPROVED/);
  } finally { cleanup(); }
  assert.doesNotMatch(readFileSync(script, "utf8"), /from "node:(http|https|net|dns|tls)"|fetch\(/);
});
