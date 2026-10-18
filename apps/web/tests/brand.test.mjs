import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import test from "node:test";
const root=join(dirname(fileURLToPath(import.meta.url)),"..","..","..");
const file=(path)=>readFileSync(join(root,path));
const str=(path)=>file(path).toString("utf8");
const hash=(path)=>createHash("sha256").update(file(path)).digest("hex");

test("Founder-approved Orcel Signal o slit and curved icon are canonical",()=>{
 const mark=str("assets/brand/orcel-o-white.svg");
 const logo=str("assets/brand/orcel-wordmark-white.svg");
 assert.match(mark,/Orcel Signal white mark/);
 assert.match(mark,/fill="#FF813E"/);
 assert.equal(str("apps/web/public/brand/orcel-o-white.svg"),mark);
 assert.match(str("assets/brand/orcel-o-black.svg"),/fill="#080808"/);
 for(const path of ["M67.1 161.6 A71 71 0 1 1 80.5 177.8","M557 52 L531 88","x=\"793\" y=\"5\" width=\"47\" height=\"218\""])
   assert.ok(logo.includes(path),path);
 assert.equal((logo.match(/fill-rule="evenodd"/g)||[]).length,1);
 assert.match(logo,/stroke-width="48" stroke-linecap="butt"/);
 assert.match(mark,/M148 105 C161 65 193 41/);
 assert.match(mark,/M187 119 C184 132/);
 assert.match(logo,/fill="#FF813E"/);
 assert.doesNotMatch(logo,/<text\\b|<image\\b|<circle|linearGradient/i);
});

test("OpenAI/Codex app icons and Next favicon are byte-identical",()=>{
 const master=file("assets/brand/orcel-app-icon.svg");
 for(const path of [
  "apps/web/public/brand/orcel-app-icon.svg",
  "apps/web/app/icon.svg",
  "distribution/openai/assets/logo.svg",
  "distribution/codex/orcel/assets/logo.svg"
 ]) assert.deepEqual(file(path),master,path);
 const openai=JSON.parse(str("distribution/openai/plugin.config.json"));
 const codex=JSON.parse(str("distribution/codex/orcel/plugin.json"));
 assert.equal(openai.brandColor,"#080808");
 assert.equal(codex.extensions["com.openai"].interface.brandColor,"#080808");
});

test("Identity delivers full mono and editorial system without distributing fonts",()=>{
 const names=[
 "orcel-o-white.svg","orcel-o-black.svg",
 "orcel-app-icon.svg","orcel-app-icon-light.svg","orcel-accent-icon.svg",
 "orcel-wordmark-white.svg","orcel-wordmark-black.svg","orcel-readme-lockup.svg",
 "orcel-lockup-white.svg","orcel-lockup-black.svg",
 "orcel-lockup-stacked-white.svg","orcel-lockup-stacked-black.svg",
 "orcel-social-dark.svg","orcel-social-light.svg","orcel-monogram-pattern.svg"
 ];
 for (const name of names) {
  assert.ok(statSync(join(root,"assets/brand",name)).size>175,name);
 }
 for (const name of ["orcel-wordmark-white.svg","orcel-wordmark-black.svg","orcel-lockup-white.svg"]) {
  const svg=str("assets/brand/"+name);
  assert.doesNotMatch(svg,/<text\b|<image\b|@font-face/i,"no font or image dependencies");
 }
 assert.match(str("assets/brand/orcel-wordmark-white.svg"),/fill="#FF813E"/);
 assert.equal(str("apps/web/public/brand/orcel-wordmark-white.svg"),str("assets/brand/orcel-wordmark-white.svg"));
 assert.equal(str("apps/web/public/brand/orcel-wordmark-black.svg"),str("assets/brand/orcel-wordmark-black.svg"));
 const readme=str("README.md");
 assert.match(readme,/orcel-readme-lockup\.svg/);
 const hero=str("assets/brand/orcel-readme-lockup.svg");
 assert.match(hero,/fill="#080808"/);
 assert.match(hero,/fill="#FF813E"/);
 const page=str("apps/web/app/brand/page.tsx");
 assert.match(page,/A clear signal/);
 assert.match(page,/Deliberate o opening and continuous c/);
 assert.match(page,/orcel-lockup-white\.svg/);
 assert.match(page,/Download kit/);
 const css=str("apps/web/app/globals.css");
 assert.match(css,/--accent-a:\s*#FF813E/);
 assert.match(css,/--accent-b:\s*#FF9D67/);
 assert.doesNotMatch(css,/#78c8ff|#8278ff|#d4a6ff|rgba\(\s*96,\s*104,\s*255/i);
 assert.match(str("apps/web/app/page.tsx"),/\/brand\.html/);
 assert.ok(statSync(join(root,"apps/web/app/brand/brand.css")).size>2000);
});

test("Every raster export is validated and delivered via deterministic ZIP",()=>{
 const manifest=JSON.parse(str("assets/brand/ASSET_MANIFEST.json"));
 assert.equal(manifest.name,"Orcel");
 assert.equal(manifest.brand_version,"2.0");
 assert.equal(manifest.source,"Orcel Signal Identity 2026");
 assert.ok(manifest.assets.length>=50);
 for (const item of manifest.assets) {
  assert.equal(hash(item.path),item.sha256,item.path);
  assert.equal(file(item.path).byteLength,item.bytes,item.path);
 }
 for (const n of [16,32,64,256,1024]) {
  const png=file("assets/brand/exports/orcel-app-dark-"+n+".png");
  assert.equal(png.subarray(0,8).toString("hex"),"89504e470d0a1a0a");
  assert.equal(png.readUInt32BE(16),n);
  assert.equal(png.readUInt32BE(20),n);
 }
 const zip=file("assets/brand/downloads/Orcel-Identity-Kit-v2.zip");
 assert.equal(zip.subarray(0,4).toString("hex"),"504b0304");
 assert.ok(zip.length>25000&&zip.length<3000000);
});

test("Historic brand release artifact is preserved without change",()=>{
 assert.equal(hash("apps/web/public/brand/orcel-mark-mask.svg"),
  "56bd8af1c84680e45ff579a130e16949a472e81c6846e475adf6f06f16e92daf");
});
