#!/usr/bin/env node
// Orcel identity v4, a Halfmoon product. One deterministic vector construction, shared across
// site, OpenAI/Codex packages, favicon, marketing, and downloadable assets.
// Founder-selected November 17, 2026: the Night Window mark (a desktop window holding a half moon,
// from Halfmoon's shape grammar), Halfmoon's palette, and a Bricolage Grotesque wordmark.
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
// Halfmoon core palette (Halfmoon design tokens, 16 November 2026).
export const ORCEL={
  midnight:"#090C12",
  white:"#FFFFFF",
  lunar:"#F5F4F0",
  lavender:"#A6ACE6",
  lavenderDeep:"#5A61B8",
  red:"#B31B1B",
  wordWidth:620,
  glyphHeight:256,
  iconWidth:256
};
// "orcel" in Bricolage Grotesque SemiBold (Halfmoon 600 instance, SIL Open Font License),
// tracking -22/1000 as in the Halfmoon wordmark, outlined in font units with the baseline at y=0.
const WORD='M281 14Q208 14 150 -16Q93 -47 60 -108Q27 -169 27 -261Q27 -354 60 -415Q94 -476 152 -506Q209 -536 281 -536Q356 -536 413 -506Q470 -475 502 -414Q535 -352 535 -260Q535 -166 502 -106Q468 -45 410 -16Q353 14 281 14ZM284 -84Q323 -84 350 -104Q377 -123 392 -162Q407 -200 407 -253Q407 -310 392 -350Q376 -390 347 -412Q318 -434 278 -434Q240 -434 212 -414Q185 -393 170 -354Q155 -316 155 -262Q155 -178 189 -131Q223 -84 284 -84ZM581 0V-266V-522H693L686 -297H694Q700 -383 718 -435Q737 -487 766 -510Q795 -534 831 -534Q848 -534 866 -530Q883 -525 900 -516L893 -378Q874 -388 856 -393Q838 -398 821 -398Q785 -398 760 -374Q734 -350 720 -304Q707 -257 707 -191V0ZM1174 14Q1108 14 1060 -6Q1011 -27 980 -64Q948 -101 932 -150Q917 -200 917 -257Q917 -314 932 -364Q948 -415 979 -454Q1010 -493 1058 -514Q1105 -536 1170 -536Q1248 -536 1297 -506Q1346 -477 1368 -430Q1389 -383 1383 -328L1272 -318Q1273 -356 1260 -382Q1247 -408 1224 -421Q1200 -434 1169 -434Q1143 -434 1120 -424Q1098 -415 1081 -394Q1064 -374 1054 -342Q1045 -310 1045 -263Q1045 -203 1062 -163Q1078 -123 1108 -104Q1137 -84 1176 -84Q1218 -84 1242 -103Q1266 -122 1276 -152Q1285 -182 1282 -214L1400 -207Q1404 -162 1392 -122Q1380 -82 1352 -52Q1323 -21 1279 -4Q1235 14 1174 14ZM1680 14Q1612 14 1564 -6Q1515 -27 1484 -64Q1453 -100 1438 -148Q1424 -196 1424 -253Q1424 -310 1438 -361Q1453 -412 1484 -452Q1514 -491 1560 -514Q1607 -536 1671 -536Q1732 -536 1778 -515Q1823 -494 1852 -456Q1880 -417 1890 -364Q1901 -312 1893 -249L1503 -243V-318L1798 -323L1777 -280Q1781 -328 1770 -362Q1760 -396 1736 -414Q1711 -433 1671 -433Q1628 -433 1600 -411Q1573 -389 1560 -350Q1547 -311 1547 -258Q1547 -171 1581 -128Q1615 -84 1682 -84Q1714 -84 1735 -93Q1756 -102 1768 -118Q1781 -134 1786 -154Q1790 -173 1789 -193L1906 -186Q1908 -148 1896 -112Q1884 -77 1857 -48Q1830 -20 1786 -3Q1742 14 1680 14ZM1945 0V-690H2072V0Z';
function rrect(x,y,w,h,r) {
 return 'M'+(x+r)+' '+y+'H'+(x+w-r)+'A'+r+' '+r+' 0 0 1 '+(x+w)+' '+(y+r)+'V'+(y+h-r)+
  'A'+r+' '+r+' 0 0 1 '+(x+w-r)+' '+(y+h)+'H'+(x+r)+'A'+r+' '+r+' 0 0 1 '+x+' '+(y+h-r)+
  'V'+(y+r)+'A'+r+' '+r+' 0 0 1 '+(x+r)+' '+y+'Z';
}
// Night Window, on a 256 grid: an 8:7 window frame (stroke 22, corner 52), a title rule one stroke
// in from the frame, and the grammar's half moon (r 50) with its flat edge on the centre axis.
function nightWindow(ink,moon) {
 return '<g class="orcel-night-window">'+
  '<rect x="28" y="40" width="200" height="176" rx="52" fill="none" stroke="'+ink+'" stroke-width="22"/>'+
  '<path d="M66 82H102" stroke="'+ink+'" stroke-width="16" stroke-linecap="round"/>'+
  '<path d="M128 96A50 50 0 0 1 128 196Z" fill="'+moon+'"/></g>';
}
// Moon Tile: the same window filled solid, title slot and half moon cut out (even-odd).
function moonTile(ink,inner) {
 const d=rrect(24,30,208,196,56)+rrect(62,74,44,16,8)+'M136 96A50 50 0 0 1 136 196Z';
 return '<g class="orcel-moon-tile"><path fill-rule="evenodd" d="'+d+'" fill="'+ink+'"/>'+
  (inner?'<path d="M144 112A34 34 0 0 1 144 180Z" fill="'+inner+'"/>':'')+'</g>';
}
function lettering(ink) {
 // 620x256 canvas: ink spans x 24-597 and y 30-227 (ascender to baseline overshoot).
 return '<path class="orcel-wordmark" transform="translate(16 223) scale(.28)" d="'+WORD+'" fill="'+ink+'"/>';
}
function tileOf(bg,ink,inner) {
 return '  <rect width="256" height="256" rx="58" fill="'+bg+'"/>\n  <g transform="translate(40 40) scale(.6875)">'+moonTile(ink,inner)+'</g>';
}
const pure=doc("0 0 256 256","  "+nightWindow(ORCEL.white,ORCEL.lavender),"Orcel Night Window mark, white with lavender moon");
const inverse=doc("0 0 256 256","  "+nightWindow(ORCEL.midnight,ORCEL.lavenderDeep),"Orcel Night Window mark, midnight with deep lavender moon");
const tile=doc("0 0 256 256",tileOf(ORCEL.midnight,ORCEL.white,ORCEL.lavender),"Orcel Moon Tile dark application icon");
const tileLight=doc("0 0 256 256",tileOf(ORCEL.lunar,ORCEL.midnight,null),"Orcel Moon Tile light application icon");
const wordWhite=doc("0 0 620 256","  "+lettering(ORCEL.white),"Orcel white wordmark");
const wordBlack=doc("0 0 620 256","  "+lettering(ORCEL.midnight),"Orcel midnight wordmark");
function lockupBody(ink,moon) {
 return '<g>'+nightWindow(ink,moon)+'</g><g transform="translate(300 0)">'+lettering(ink)+'</g>';
}
// Dedicated dark-background lockup for GitHub README in either theme.
const readmeLogo=doc("0 0 1000 300",
  '  <rect width="1000" height="300" rx="20" fill="'+ORCEL.midnight+'"/>\n  <g transform="translate(40 22)">\n    '+lockupBody(ORCEL.white,ORCEL.lavender)+'\n  </g>',
  "Orcel Night Window mark and white wordmark for GitHub");
function horizontal(ink,moon) {
 return doc("0 0 940 256","  "+lockupBody(ink,moon),"Orcel horizontal logo");
}
const lockWhite=horizontal(ORCEL.white,ORCEL.lavender),lockBlack=horizontal(ORCEL.midnight,ORCEL.lavenderDeep);
function stacked(ink,moon) {
 return doc("0 0 520 460",
  '  <g transform="translate(132 0)">'+nightWindow(ink,moon)+'</g>\n'+
  '  <g transform="translate(27 262) scale(.75)">'+lettering(ink)+'</g>',
  "Orcel stacked mark and wordmark");
}
const stackWhite=stacked(ORCEL.white,ORCEL.lavender),stackBlack=stacked(ORCEL.midnight,ORCEL.lavenderDeep);
function social(dark) {
 const ink=dark?ORCEL.white:ORCEL.midnight,bg=dark?ORCEL.midnight:ORCEL.lunar;
 const moon=dark?ORCEL.lavender:ORCEL.lavenderDeep,muted=dark?"#9499A6":"#4A4F5A";
 return doc("0 0 1200 630",
   '<rect width="1200" height="630" fill="'+bg+'"/>\n'+
   '<g transform="translate(95 150) scale(.9)">'+lockupBody(ink,moon)+'</g>\n'+
   '<path d="M95 503 H1105" stroke="'+muted+'" stroke-width="1" opacity=".4"/>\n'+
   '<text x="97" y="561" font-family="Geist,Arial,sans-serif" font-size="25" fill="'+muted+'">Your computer, your terms.</text>'+
   '<text x="1100" y="561" text-anchor="end" font-family="Geist,Arial,sans-serif" font-size="16" letter-spacing="3" fill="'+muted+'">A HALFMOON PRODUCT</text>',
   "Orcel social banner");
}
function motif() {
 // Halfmoon's half moon repeated as a phase field; one in twelve carries lavender.
 const parts=['<rect width="1200" height="420" fill="'+ORCEL.midnight+'"/>'];
 for(let row=0;row<4;row++){
  for(let col=0;col<12;col++){
   const x=50+col*100+(row%2?50:0),y=60+row*100;
   const fill=(col*5+row*3)%12===7?ORCEL.lavender:"#1B2030";
   parts.push('<path d="M'+x+' '+(y-34)+'A34 34 0 0 1 '+x+' '+(y+34)+'Z" fill="'+fill+'"/>');
  }
 }
 return doc("0 0 1200 420",parts.join("\n"),"Orcel phase-field supporting pattern");
}
const pattern=motif();
const accent=doc("0 0 256 256",
  '  <rect width="256" height="256" rx="58" fill="'+ORCEL.lavender+'"/>\n  <g transform="translate(36 36) scale(.71875)">'+nightWindow(ORCEL.midnight,ORCEL.midnight)+'</g>',
  "Orcel accent icon on lavender");
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
console.log("Orcel identity v4 "+(check?"verified":"generated")+": "+outputs.size+" SVG destinations");
for (const [name,data] of [["symbol",pure],["app tile",tile],["lockup",lockWhite]]) {
 console.log(name+": "+createHash("sha256").update(data).digest("hex"));
}
