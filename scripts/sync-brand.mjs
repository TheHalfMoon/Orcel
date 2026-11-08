#!/usr/bin/env node
// Orcel Orca Eye Identity. One deterministic vector construction, shared across
// site, OpenAI/Codex packages, favicon, marketing, and downloadable assets.
// Founder-selected November 8, 2026 Orca Eye mark with an Unbounded SemiBold wordmark.
// The wordmark is stored as outlines: no font files, runtime dependencies, or mutable external resources.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo=join(dirname(fileURLToPath(import.meta.url)),"..");
const svgStart='<svg xmlns="http://www.w3.org/2000/svg"';
function doc(view,body,label) {
 return svgStart+' viewBox="'+view+'" role="img" aria-label="'+label+'">\n'+body+'\n</svg>\n';
}
// Orca Eye: one circle with the orca eye patch cut out of it. Mono by design;
// Signal Lime is reserved for actions and the accent tile, never the mark itself.
export const ORCA={
  ink:"#080808",
  paper:"#F5F6F7",
  lime:"#D4FF3F",
  charcoal:"#17191B",
  wordWidth:780,
  glyphHeight:256,
  iconWidth:256
};
const MARK='M128 24 A104 104 0 1 1 127.9 24 Z M60 136 C80 92 150 70 206 82 C178 114 120 140 60 136 Z';
// "orcel" in Unbounded SemiBold (wght 600, SIL Open Font License), tracking -40/1000,
// converted to outlines in font units with the baseline at y=0.
const WORD='M392 16Q284 16 203 -22Q122 -60 77 -128Q32 -196 32 -285Q32 -375 77 -443Q122 -510 203 -548Q285 -586 392 -586Q500 -586 581 -548Q663 -510 708 -443Q753 -375 753 -285Q753 -195 708 -128Q663 -60 581 -22Q500 16 392 16ZM392 -124Q447 -124 485 -143Q524 -163 544 -199Q565 -235 565 -285Q565 -335 544 -371Q524 -407 485 -427Q447 -446 392 -446Q339 -446 300 -427Q261 -407 240 -371Q219 -335 219 -285Q219 -235 240 -199Q261 -163 300 -143Q339 -124 392 -124ZM778 -570H966L1000 -365V0H814V-380ZM1272 -578V-418Q1245 -424 1218 -427Q1192 -430 1170 -430Q1122 -430 1084 -410Q1045 -391 1023 -349Q1000 -307 1000 -240L963 -286Q970 -347 986 -401Q1002 -455 1030 -497Q1058 -538 1100 -562Q1141 -586 1200 -586Q1217 -586 1236 -584Q1255 -582 1272 -578ZM1973 -237Q1965 -162 1918 -105Q1870 -48 1796 -16Q1721 16 1628 16Q1525 16 1446 -22Q1367 -60 1323 -128Q1279 -196 1279 -285Q1279 -374 1323 -442Q1367 -510 1446 -548Q1525 -586 1628 -586Q1721 -586 1796 -554Q1870 -522 1918 -466Q1965 -409 1973 -333H1788Q1777 -388 1733 -417Q1690 -446 1628 -446Q1579 -446 1543 -427Q1506 -408 1486 -372Q1466 -336 1466 -285Q1466 -234 1486 -198Q1506 -162 1543 -143Q1579 -124 1628 -124Q1691 -124 1734 -154Q1777 -185 1788 -237ZM2346 16Q2244 16 2163 -22Q2083 -60 2037 -128Q1991 -196 1991 -287Q1991 -376 2035 -443Q2079 -510 2156 -548Q2234 -586 2332 -586Q2432 -586 2504 -542Q2576 -498 2615 -418Q2654 -338 2654 -230H2140V-347H2552L2485 -305Q2482 -352 2462 -385Q2443 -417 2411 -435Q2379 -452 2335 -452Q2287 -452 2252 -433Q2217 -414 2198 -380Q2178 -346 2178 -301Q2178 -244 2204 -204Q2229 -164 2278 -143Q2326 -122 2396 -122Q2460 -122 2524 -140Q2588 -157 2639 -189V-68Q2581 -28 2507 -6Q2432 16 2346 16ZM2707 -770H2892V0H2707Z';
function lettering(ink) {
 // 780x256 canvas: ink spans x 32-747 and y 30-226 (ascender to baseline overshoot).
 return '<path class="orcel-wordmark" transform="translate(24 222) scale(.25)" d="'+WORD+'" fill="'+ink+'"/>';
}
function orcaMark(ink) {
 return '<path class="orcel-orca-eye" fill-rule="evenodd" d="'+MARK+'" fill="'+ink+'"/>';
}
function tileOf(bg,ink) {
 return '  <rect width="256" height="256" rx="58" fill="'+bg+'"/>\n  <g transform="translate(48 48) scale(.625)">'+orcaMark(ink)+'</g>';
}
const pure=doc("0 0 256 256","  "+orcaMark("#FFFFFF"),"Orcel Orca Eye white mark");
const inverse=doc("0 0 256 256","  "+orcaMark(ORCA.ink),"Orcel Orca Eye black mark");
const tile=doc("0 0 256 256",tileOf(ORCA.ink,"#FFFFFF"),"Orcel Orca Eye dark application icon");
const tileLight=doc("0 0 256 256",tileOf(ORCA.paper,ORCA.ink),"Orcel Orca Eye light application icon");
const wordWhite=doc("0 0 780 256","  "+lettering("#FFFFFF"),"Orcel white wordmark");
const wordBlack=doc("0 0 780 256","  "+lettering(ORCA.ink),"Orcel black wordmark");
function lockupBody(ink) {
 return '<g transform="translate(20 0)">'+orcaMark(ink)+'</g><g transform="translate(316 0)">'+lettering(ink)+'</g>';
}
// Dedicated dark-background lockup for GitHub README in either theme.
const readmeLogo=doc("0 0 1000 300",
  '  <rect width="1000" height="300" rx="20" fill="'+ORCA.ink+'"/>\n  <g transform="translate(66 46) scale(.8)">\n    '+lockupBody("#FFFFFF")+'\n  </g>',
  "Orcel Orca Eye mark and white wordmark for GitHub");
function horizontal(ink) {
 return doc("0 0 1100 256","  "+lockupBody(ink),"Orcel Orca Eye horizontal logo");
}
const lockWhite=horizontal("#FFFFFF"),lockBlack=horizontal(ORCA.ink);
function stacked(ink) {
 return doc("0 0 520 450",
  '  <g transform="translate(132 10)">'+orcaMark(ink)+'</g>\n'+
  '  <g transform="translate(18 290) scale(.62)">'+lettering(ink)+'</g>',
  "Orcel Orca Eye stacked mark and wordmark");
}
const stackWhite=stacked("#FFFFFF"),stackBlack=stacked(ORCA.ink);
function social(dark) {
 const ink=dark?"#FFFFFF":ORCA.ink,bg=dark?ORCA.ink:ORCA.paper,muted=dark?"#B8BCC1":"#565D66";
 return doc("0 0 1200 630",
   '<rect width="1200" height="630" fill="'+bg+'"/>\n'+
   '<g transform="translate(95 150) scale(.92)">'+lockupBody(ink)+'</g>\n'+
   '<path d="M95 503 H1105" stroke="'+muted+'" stroke-width="1" opacity=".4"/>\n'+
   '<text x="97" y="561" font-family="Arial,sans-serif" font-size="25" fill="'+muted+'">Your computer, your terms.</text>'+
   '<text x="1100" y="561" text-anchor="end" font-family="Arial,sans-serif" font-size="16" letter-spacing="2" fill="'+muted+'">OPEN SOURCE / LOCAL-FIRST</text>',
   "Orcel Orca Eye social banner");
}
function motif() {
 // The eye patch on its own, repeated; one in twelve carries Signal Lime.
 const patch='M60 136 C80 92 150 70 206 82 C178 114 120 140 60 136 Z';
 const parts=['<rect width="1200" height="420" fill="'+ORCA.ink+'"/>'];
 for(let row=0;row<4;row++){
  for(let col=0;col<12;col++){
   const x=-20+col*100+(row%2?50:0),y=40+row*95;
   const fill=(col*5+row*3)%12===7?ORCA.lime:"#1F1F24";
   parts.push('<path transform="translate('+x+' '+y+') scale(.5)" d="'+patch+'" fill="'+fill+'"/>');
  }
 }
 return doc("0 0 1200 420",parts.join("\n"),"Orcel Orca Eye supporting pattern");
}
const pattern=motif();
const accent=doc("0 0 256 256",tileOf(ORCA.lime,ORCA.ink),"Orcel Orca Eye accent icon on Signal Lime");
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
console.log("Orcel Orca Eye identity "+(check?"verified":"generated")+": "+outputs.size+" SVG destinations");
for (const [name,data] of [["symbol",pure],["app tile",tile],["lockup",lockWhite]]) {
 console.log(name+": "+createHash("sha256").update(data).digest("hex"));
}
