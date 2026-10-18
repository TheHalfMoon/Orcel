#!/usr/bin/env node
// Orcel Signal Identity. One deterministic vector construction, shared across
// site, OpenAI/Codex packages, favicon, marketing, and downloadable assets.
// Based on the founder-approved October 17, 2026 Signal typography design. Not third-party art.
// No font files, runtime dependencies, or mutable external resources.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo=join(dirname(fileURLToPath(import.meta.url)),"..");
const svgStart='<svg xmlns="http://www.w3.org/2000/svg"';
function doc(view,body,label) {
 return svgStart+' viewBox="'+view+'" role="img" aria-label="'+label+'">\n'+body+'\n</svg>\n';
}
// Orcel Signal. Founder-approved typographic identity, 17 October 2026.
// Original fill geometry derived from the approved Signal visual reference.
// Final visual reference: o has a precise lower-left opening; c is continuous; l orange tip and curved icon.
export const SIGNAL={
  orange:"#FF813E",
  wordWidth:860,
  glyphHeight:256,
  iconWidth:256
};
function lettering(ink,tip=SIGNAL.orange) {
 const o='M67.1 161.6 A71 71 0 1 1 80.5 177.8';
 const r='M248 219 V106 C248 62 279 35 321 35 H354 L331 78 H319 C299 78 290 91 290 112 V219 Z';
 const c='M557 52 L531 88 C513 76 496 70 471 70 C431 70 406 96 406 130 C406 166 433 190 471 190 C495 190 511 183 531 170 L556 201 C533 222 503 231 469 231 C404 231 361 191 361 130 C361 69 405 30 469 30 C506 30 535 38 557 52 Z';
 const e='M748 139 H603 C609 172 634 190 663 190 C688 190 713 180 730 165 L755 196 C734 217 702 229 661 229 C598 229 554 192 554 130 C554 71 594 31 655 31 C711 31 751 68 751 127 V139 H748 Z M605 112 H706 C701 88 681 72 655 72 C632 72 612 88 605 112 Z';
 const glyph=(d,evenodd=false)=>'<path d="'+d+'" fill="'+ink+'"'+(evenodd?' fill-rule="evenodd"':'')+'/>';
 return '<g class="orcel-signal-wordmark">'+
   '<path d="'+o+'" fill="none" stroke="'+ink+'" stroke-width="48" stroke-linecap="butt"/>'+glyph(r)+glyph(c)+
   '<g transform="translate(20 0)">'+glyph(e,true)+'</g>'+
   '<rect x="793" y="5" width="47" height="218" rx="10" fill="'+ink+'"/>'+
   '<path d="M803 5 H830 Q840 5 840 15 V118 C820 122 802 113 793 91 V15 Q793 5 803 5 Z" fill="'+tip+'"/>'+
   '</g>';
}
function signalMark(ink,tip=SIGNAL.orange) {
 // Cropped from the same architectural vocabulary as the wordmark: a
 // Continuous C with upper-right orange curved signal arc and white teardrop.
 const c='M190 58 L160 91 C145 78 131 70 111 70 C80 70 60 95 60 128 C60 161 81 186 112 186 C131 186 146 176 160 163 L190 194 C170 215 144 226 110 226 C58 226 21 182 21 128 C21 73 59 30 110 30 C143 30 171 41 190 58 Z';
 return '<g class="orcel-signal-mark"><path d="'+c+'" fill="'+ink+'"/>'+
  '<path d="M148 105 C161 65 193 41 231 41 V83 C209 82 191 92 179 119 L147 114 Z" fill="'+tip+'"/>'+
  '<path d="M187 119 C184 132 190 140 202 140 C212 140 217 130 214 122 C227 131 227 146 217 157 C207 168 188 164 179 155 C171 146 175 130 187 119 Z" fill="'+ink+'"/></g>';
}
const pure=doc("0 0 256 256","  "+signalMark("#FFFFFF"),"Orcel Signal white mark with orange terminal");
const inverse=doc("0 0 256 256","  "+signalMark("#080808"),"Orcel Signal black mark with orange terminal");
const tile=doc("0 0 256 256",'  <rect width="256" height="256" rx="54" fill="#080808"/>\n  '+signalMark("#FFFFFF"),"Orcel Signal dark application icon");
const tileLight=doc("0 0 256 256",'  <rect width="256" height="256" rx="54" fill="#F5F6F7"/>\n  '+signalMark("#080808"),"Orcel Signal light application icon");
const wordWhite=doc("0 0 860 256","  "+lettering("#FFFFFF"),"Orcel Signal original lowercase white and orange wordmark");
const wordBlack=doc("0 0 860 256","  "+lettering("#080808"),"Orcel Signal original lowercase black and orange wordmark");
// Dedicated dark-background lockup for GitHub README in either theme.
const readmeLogo=doc("0 0 1000 300",
  '  <rect width="1000" height="300" rx="20" fill="#080808"/>\n  <g transform="translate(40 26) scale(1.06)">\n    '+lettering("#FFFFFF")+'\n  </g>',
  "Orcel Signal primary white wordmark with orange l terminal for GitHub");
function horizontal(ink) {
 return doc("0 0 900 256",'  <g transform="translate(20 0)">'+lettering(ink)+'</g>',
  "Orcel Signal typographic horizontal logo with orange terminal");
}
const lockWhite=horizontal("#FFFFFF"),lockBlack=horizontal("#080808");
function stacked(ink) {
 return doc("0 0 520 450",
  '  <g transform="translate(132 10)">'+signalMark(ink)+'</g>\n'+
  '  <g transform="translate(6 291) scale(.59)">'+lettering(ink)+'</g>',
  "Orcel Signal stacked icon and original lowercase wordmark");
}
const stackWhite=stacked("#FFFFFF"),stackBlack=stacked("#080808");
function social(dark) {
 const ink=dark?"#FFFFFF":"#080808",bg=dark?"#080808":"#F5F6F7",muted=dark?"#B8BCC1":"#565D66";
 return doc("0 0 1200 630",
   '<rect width="1200" height="630" fill="'+bg+'"/>\n'+
   '<g transform="translate(85 128) scale(1.19)">'+lettering(ink)+'</g>\n'+
   '<path d="M95 503 H1105" stroke="'+muted+'" stroke-width="1" opacity=".4"/>\n'+
   '<text x="97" y="561" font-family="Arial,sans-serif" font-size="25" fill="'+muted+'">Your computer, your terms.</text>'+
   '<text x="1100" y="561" text-anchor="end" font-family="Arial,sans-serif" font-size="16" letter-spacing="2" fill="'+muted+'">OPEN SOURCE / LOCAL-FIRST</text>',
   "Orcel Signal social wordmark banner");
}
function motif() {
 const parts=['<rect width="1200" height="420" fill="#080808"/>'];
 for(let i=0;i<5;i++){
  const x=30+i*230;
  parts.push('<g transform="translate('+x+' 66) scale(.85)" opacity="'+(.14+i*.09).toFixed(2)+'">'+signalMark("#FFFFFF")+'</g>');
 }
 return doc("0 0 1200 420",parts.join("\n"),"Orcel Signal supporting editorial graphic");
}
const pattern=motif();
const accent=doc("0 0 256 256",
  '  <rect width="256" height="256" rx="54" fill="#17191B"/>\n'+signalMark("#FFFFFF"),
  "Orcel Signal editorial icon with orange approval terminal");
const outputs=new Map([
 ["assets/brand/orcel-o-white.svg",pure],
 ["assets/brand/orcel-o-black.svg",inverse],
 ["assets/brand/orcel-app-icon.svg",tile],
 ["assets/brand/orcel-app-icon-light.svg",tileLight],
 ["assets/brand/orcel-wordmark-white.svg",wordWhite],
 ["assets/brand/orcel-wordmark-black.svg",wordBlack],
 ["assets/brand/orcel-readme-lockup.svg",readmeLogo],
 ["assets/brand/orcel-lockup-white.svg",lockWhite],
 ["assets/brand/orcel-lockup-black.svg",lockBlack],
 ["assets/brand/orcel-lockup-stacked-white.svg",stackWhite],
 ["assets/brand/orcel-lockup-stacked-black.svg",stackBlack],
 ["assets/brand/orcel-social-dark.svg",social(true)],
 ["assets/brand/orcel-social-light.svg",social(false)],
 ["assets/brand/orcel-monogram-pattern.svg",pattern],
 ["assets/brand/orcel-orbit-pattern.svg",pattern],
 ["assets/brand/orcel-accent-icon.svg",accent],
 ["apps/web/public/brand/orcel-o-white.svg",pure],
 ["apps/web/public/brand/orcel-o-black.svg",inverse],
 ["apps/web/public/brand/orcel-wordmark-white.svg",wordWhite],
 ["apps/web/public/brand/orcel-wordmark-black.svg",wordBlack],
 ["apps/web/public/brand/orcel-app-icon.svg",tile],
 ["apps/web/public/brand/orcel-app-icon-light.svg",tileLight],
 ["apps/web/public/brand/orcel-lockup-white.svg",lockWhite],
 ["apps/web/public/brand/orcel-lockup-black.svg",lockBlack],
 ["apps/web/public/brand/orcel-lockup-stacked-white.svg",stackWhite],
 ["apps/web/public/brand/orcel-lockup-stacked-black.svg",stackBlack],
 ["apps/web/public/brand/orcel-social-dark.svg",social(true)],
 ["apps/web/public/brand/orcel-social-light.svg",social(false)],
 ["apps/web/public/brand/orcel-monogram-pattern.svg",pattern],
 ["apps/web/public/brand/orcel-orbit-pattern.svg",pattern],
 ["apps/web/public/brand/orcel-accent-icon.svg",accent],
 ["apps/web/app/icon.svg",tile],
 ["distribution/openai/assets/logo.svg",tile],
 ["distribution/codex/orcel/assets/logo.svg",tile]
]);
const check=process.argv.includes("--check"),errors=[];
for (const [name,contents] of outputs) {
 const path=join(repo,...name.split("/"));
 if(check) {
  let actual;
  try { actual=readFileSync(path,"utf8"); } catch { actual=undefined; }
  if(actual!==contents)errors.push(name);
 } else {
  mkdirSync(dirname(path),{recursive:true});writeFileSync(path,contents,"utf8");
 }
}
if(errors.length) {console.error("Brand asset drift:\n"+errors.join("\n"));process.exit(1);}
console.log("Orcel Signal identity "+(check?"verified":"generated")+": "+outputs.size+" SVG destinations");
for (const [name,data] of [["symbol",pure],["app tile",tile],["lockup",lockWhite]]) {
 console.log(name+": "+createHash("sha256").update(data).digest("hex"));
}
