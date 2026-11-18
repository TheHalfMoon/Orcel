#!/usr/bin/env node
// Orcel identity v5, "People first". One deterministic vector construction, shared across
// site, OpenAI/Codex packages, favicon, marketing, and downloadable assets.
// Founder-approved November 18, 2026: the vermilion figure, the lowercase wordmark in Inter Display
// (SIL Open Font License) in ink, the product icon family, and the ivory/ink/navy/cobalt/orange/sky palette.
// All artwork is outlined vector paths: no font files, runtime dependencies, or external resources.
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo=join(dirname(fileURLToPath(import.meta.url)),"..");
const svgStart='<svg xmlns="http://www.w3.org/2000/svg"';
function doc(view,body,label) {
 return svgStart+' viewBox="'+view+'" role="img" aria-label="'+label+'">\n'+body+'\n</svg>\n';
}
// People First palette (founder-approved, 18 November 2026).
export const ORCEL={
  vermilion:"#DB2532",
  ink:"#141414",
  navy:"#182437",
  cobalt:"#2354D4",
  orange:"#F5724D",
  sky:"#BFD8F7",
  ivory:"#F7F3EB",
  white:"#FFFFFF",
  clusterRed:"#C8102E"
};
// The figure (master R13): squircle head, shoulders rounding into flat feet on the baseline,
// stroke 11.5% of its height. Outlined on a 100 grid: ink spans x 8-92, y 0-100 (baseline y=100).
const FIGURE='M 50 0 C 42.816036 0 36.214179 2.8252877 32.009766 8.0664062 C 27.805352 13.307525 26 20.35513 26 28.5 C 26 36.64487 27.805352 43.692475 32.009766 48.933594 C 32.806131 49.926323 33.688477 50.831835 34.644531 51.648438 C 27.499134 52.616671 21.304216 55.35594 16.705078 59.955078 C 10.839513 65.820643 8 74.281875 8 84 L 8 100 L 19.5 100 L 19.5 84 C 19.5 76.438125 21.521503 71.400373 24.835938 68.085938 C 28.150372 64.771503 33.188125 62.75 40.75 62.75 L 59.25 62.75 C 66.811875 62.75 71.849628 64.771503 75.164062 68.085938 C 78.478498 71.400373 80.5 76.438125 80.5 84 L 80.5 100 L 92 100 L 92 84 C 92 74.281875 89.160487 65.820643 83.294922 59.955078 C 78.695784 55.35594 72.500866 52.616671 65.355469 51.648438 C 66.311523 50.831835 67.193869 49.926323 67.990234 48.933594 C 72.194648 43.692475 74 36.64487 74 28.5 C 74 20.35513 72.194648 13.307525 67.990234 8.0664062 C 63.785821 2.8252877 57.183964 0 50 0 z M 50 11.5 C 54.496036 11.5 57.018945 12.76979 59.019531 15.263672 C 61.020118 17.757553 62.5 22.08487 62.5 28.5 C 62.5 34.91513 61.020118 39.242447 59.019531 41.736328 C 57.018945 44.23021 54.496036 45.5 50 45.5 C 45.503964 45.5 42.981055 44.23021 40.980469 41.736328 C 38.979882 39.242447 37.5 34.91513 37.5 28.5 C 37.5 22.08487 38.979882 17.757553 40.980469 15.263672 C 42.981055 12.76979 45.503964 11.5 50 11.5 z ';
// "orcel" in Inter Display (opsz 32) weight 600, tracking -3%, outlined in font units (2048/em)
// with the baseline at y=0. The l ascender reaches y=-1490; the advance is 4374.24.
const WORD='M583.59912109375 24.0Q428.5994873046875 24.0 311.07977294921875 -45.4200439453125Q193.56005859375 -114.840087890625 128.1002197265625 -238.840087890625Q62.640380859375 -362.840087890625 62.640380859375 -526.719970703125Q62.640380859375 -691.2398681640625 128.1002197265625 -815.6998901367188Q193.56005859375 -940.159912109375 311.07977294921875 -1010.0799560546875Q428.5994873046875 -1080.0 583.59912109375 -1080.0Q739.5987548828125 -1080.0 856.6184692382812 -1010.0799560546875Q973.63818359375 -940.159912109375 1039.0980224609375 -815.6998901367188Q1104.557861328125 -691.2398681640625 1104.557861328125 -526.719970703125Q1104.557861328125 -362.840087890625 1039.0980224609375 -238.840087890625Q973.63818359375 -114.840087890625 856.6184692382812 -45.4200439453125Q739.5987548828125 24.0 583.59912109375 24.0ZM583.59912109375 -186.877685546875Q664.8798828125 -186.877685546875 724.3603515625 -227.9580078125Q783.8408203125 -269.038330078125 816.4410400390625 -345.578857421875Q849.041259765625 -422.119384765625 849.041259765625 -526.719970703125Q849.041259765625 -632.9605712890625 816.4410400390625 -709.3211059570312Q783.8408203125 -785.681640625 724.3603515625 -827.4019775390625Q664.8798828125 -869.122314453125 583.59912109375 -869.122314453125Q503.318359375 -869.122314453125 443.337890625 -827.7219848632812Q383.357421875 -786.3216552734375 350.7572021484375 -709.64111328125Q318.156982421875 -632.9605712890625 318.156982421875 -526.719970703125Q318.156982421875 -421.4793701171875 350.7572021484375 -345.25885009765625Q383.357421875 -269.038330078125 443.01788330078125 -227.9580078125Q502.6783447265625 -186.877685546875 583.59912109375 -186.877685546875ZM1217.1605859375 0.0V-1056.0H1460.517275390625V-880.640380859375H1463.7973046875Q1492.7973046875 -971.6400146484375 1555.077333984375 -1018.9401245117188Q1617.35736328125 -1066.240234375 1719.957216796875 -1066.240234375Q1745.11712890625 -1066.240234375 1766.0570703125 -1064.960205078125Q1786.99701171875 -1063.68017578125 1802.036806640625 -1062.400146484375V-838.40234375Q1788.0769677734374 -840.3223876953125 1754.1771875 -843.2024536132812Q1720.2774072265624 -846.08251953125 1682.917421875 -846.08251953125Q1623.47748046875 -846.08251953125 1574.917421875 -818.7225341796875Q1526.35736328125 -791.362548828125 1498.1572900390624 -736.3424682617188Q1469.957216796875 -681.3223876953125 1469.957216796875 -598.162109375V0.0ZM2352.399296875 24.0Q2198.1196337890624 24.0 2081.679875488281 -45.96002197265625Q1965.2401171875 -115.9200439453125 1900.5002490234374 -240.10003662109375Q1835.760380859375 -364.280029296875 1835.760380859375 -526.719970703125Q1835.760380859375 -689.7999267578125 1900.5002490234374 -814.6199340820312Q1965.2401171875 -939.43994140625 2081.679875488281 -1009.719970703125Q2198.1196337890624 -1080.0 2352.399296875 -1080.0Q2451.758916015625 -1080.0 2535.8186083984374 -1050.340087890625Q2619.87830078125 -1020.68017578125 2683.0581103515624 -966.8603515625Q2746.237919921875 -913.04052734375 2784.677861328125 -839.7407836914062Q2823.117802734375 -766.4410400390625 2831.5979052734374 -678.161376953125H2584.0009814453124Q2577.1608935546874 -720.841552734375 2558.9407397460936 -755.8817138671875Q2540.7205859375 -790.921875 2511.6203662109374 -816.3619995117188Q2482.520146484375 -841.8021240234375 2443.5398608398436 -855.8222045898438Q2404.5595751953124 -869.84228515625 2355.2791796875 -869.84228515625Q2272.838505859375 -869.84228515625 2213.5780078125 -827.7219848632812Q2154.317509765625 -785.6016845703125 2122.79724609375 -708.5611572265625Q2091.276982421875 -631.5206298828125 2091.276982421875 -526.719970703125Q2091.276982421875 -422.9193115234375 2122.79724609375 -346.33880615234375Q2154.317509765625 -269.75830078125 2213.4379931640624 -227.9580078125Q2272.5584765625 -186.15771484375 2355.2791796875 -186.15771484375Q2404.5595751953124 -186.15771484375 2442.899846191406 -199.7177734375Q2481.2401171875 -213.27783203125 2509.0603076171874 -238.71795654296875Q2536.880498046875 -264.1580810546875 2555.1006518554686 -299.87823486328125Q2573.3208056640624 -335.598388671875 2582.0809375 -379.278564453125H2831.5979052734374Q2824.557744140625 -292.2789306640625 2786.6577807617186 -218.7991943359375Q2748.7578173828124 -145.3194580078125 2685.0780078125 -90.81964111328125Q2621.3981982421874 -36.31982421875 2536.798527832031 -6.159912109375Q2452.198857421875 24.0 2352.399296875 24.0ZM3404.8793408203123 24.0Q3246.63947265625 24.0 3130.839729003906 -46.82000732421875Q3015.0399853515623 -117.6400146484375 2952.1801831054686 -242.32000732421875Q2889.320380859375 -367.0 2889.320380859375 -526.719970703125Q2889.320380859375 -688.0799560546875 2953.920234375 -812.8999633789062Q3018.520087890625 -937.719970703125 3132.459846191406 -1008.8599853515625Q3246.3996044921873 -1080.0 3394.3192822265623 -1080.0Q3508.6391064453123 -1080.0 3601.6389233398436 -1040.1799926757812Q3694.638740234375 -1000.3599853515625 3761.5985791015623 -926.8999633789062Q3828.55841796875 -853.43994140625 3864.5783154296873 -752.8399047851562Q3900.598212890625 -652.2398681640625 3900.598212890625 -530.6798095703125V-462.0806884765625H2989.399970703125V-636.1595458984375H3774.2794873046873L3661.32111328125 -589.4793701171875Q3661.32111328125 -678.7601318359375 3629.1208569335936 -743.8607177734375Q3596.9206005859373 -808.9613037109375 3538.080146484375 -844.3616333007812Q3479.2396923828123 -879.761962890625 3398.27912109375 -879.761962890625Q3318.3185498046873 -879.761962890625 3259.6181103515623 -844.3616333007812Q3200.9176708984373 -808.9613037109375 3168.717414550781 -743.8607177734375Q3136.517158203125 -678.7601318359375 3136.517158203125 -589.4793701171875V-479.680908203125Q3136.517158203125 -389.0401611328125 3168.6173779296873 -320.1595458984375Q3200.71759765625 -251.2789306640625 3262.098029785156 -212.95855712890625Q3323.4784619140623 -174.63818359375 3410.6391064453123 -174.63818359375Q3474.1195751953123 -174.63818359375 3523.019904785156 -193.63836669921875Q3571.920234375 -212.6385498046875 3604.560432128906 -246.89886474609375Q3637.2006298828123 -281.1591796875 3651.400703125 -326.4395751953125H3887.6380078125Q3867.9979931640623 -222.919677734375 3800.31818359375 -144.07977294921875Q3732.6383740234373 -65.2398681640625 3630.578681640625 -20.61993408203125Q3528.5189892578123 24.0 3404.8793408203123 24.0ZM4262.637216796875 -1490.0V0.0H4009.8405859375V-1490.0Z';
const WORD_ADV=4374.24,WORD_L=1490;
// Product icon family on a 1024 grid, as approved: Orcel (figure on ivory), Browser (figure on an
// orange disc in an ink ring), Agent (one person, many agents), MCP (hub on navy), Cluster
// (connected dots on sky).
const ICONS={
 orcel:'<rect x="2" y="2" width="1020" height="1020" rx="230" fill="#F7F3EB" stroke="#E6DFD3" stroke-width="4"/><g fill="#DB2532"><path transform="translate(512 512) scale(7.2) translate(-48.5 -56)" d="M 47 15 C 34.327189 15 24 25.327189 24 38 L 24 46 C 24 54.20618 28.33078 61.428077 34.824219 65.5 C 23.372339 65.595882 14 75.026989 14 86.5 L 14 93 A 4 4 0 0 0 18 97 A 4 4 0 0 0 22 93 L 22 86.5 C 22 79.331818 27.831818 73.5 35 73.5 L 62 73.5 C 69.168182 73.5 75 79.331818 75 86.5 L 75 93 A 4 4 0 0 0 79 97 A 4 4 0 0 0 83 93 L 83 86.5 C 83 74.968182 73.531818 65.5 62 65.5 L 61.177734 65.5 C 67.670519 61.427942 72 54.205684 72 46 L 72 38 C 72 25.327189 61.672811 15 49 15 L 47 15 z M 47 23 L 49 23 C 57.379189 23 64 29.620811 64 38 L 64 46 C 64 54.379189 57.379189 61 49 61 L 47 61 C 38.620811 61 32 54.379189 32 46 L 32 38 C 32 29.620811 38.620811 23 47 23 z "/></g>',
 browser:'<circle cx="512" cy="512" r="480" fill="#F5724D" stroke="#141414" stroke-width="56"/><g fill="#141414"><path transform="translate(512 512) scale(6.0) translate(-48.5 -56)" d="M 47 15 C 34.327189 15 24 25.327189 24 38 L 24 46 C 24 54.20618 28.33078 61.428077 34.824219 65.5 C 23.372339 65.595882 14 75.026989 14 86.5 L 14 93 A 4 4 0 0 0 18 97 A 4 4 0 0 0 22 93 L 22 86.5 C 22 79.331818 27.831818 73.5 35 73.5 L 62 73.5 C 69.168182 73.5 75 79.331818 75 86.5 L 75 93 A 4 4 0 0 0 79 97 A 4 4 0 0 0 83 93 L 83 86.5 C 83 74.968182 73.531818 65.5 62 65.5 L 61.177734 65.5 C 67.670519 61.427942 72 54.205684 72 46 L 72 38 C 72 25.327189 61.672811 15 49 15 L 47 15 z M 47 23 L 49 23 C 57.379189 23 64 29.620811 64 38 L 64 46 C 64 54.379189 57.379189 61 49 61 L 47 61 C 38.620811 61 32 54.379189 32 46 L 32 38 C 32 29.620811 38.620811 23 47 23 z "/></g>',
 agent:'<rect x="2" y="2" width="1020" height="1020" rx="230" fill="#F7F3EB" stroke="#E6DFD3" stroke-width="4"/><g fill="#DB2532" transform="translate(512 512) scale(8.6) translate(-50 -50)"><path d="M49.4 6c-5.07 0-9.2 4.13-9.2 9.2v3.2a9.2 9.2 0 0 0 4.33 7.8c-4.581.038-8.33 3.81-8.33 8.4v2.6a1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6v-2.6c0-2.867 2.333-5.2 5.2-5.2h10.8c2.867 0 5.2 2.333 5.2 5.2v2.6a1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6v-2.6c0-4.613-3.787-8.4-8.4-8.4h-.329a9.2 9.2 0 0 0 4.329-7.8v-3.2c0-5.07-4.13-9.2-9.2-9.2zm0 3.2h.8c3.352 0 6 2.648 6 6v3.2c0 3.352-2.648 6-6 6h-.8c-3.352 0-6-2.648-6-6v-3.2c0-3.352 2.648-6 6-6M21.4 62c-5.07 0-9.2 4.13-9.2 9.2v3.2a9.2 9.2 0 0 0 4.33 7.8c-4.581.038-8.33 3.81-8.33 8.4v2.6a1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6v-2.6c0-2.867 2.333-5.2 5.2-5.2h10.8c2.867 0 5.2 2.333 5.2 5.2v2.6a1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6v-2.6c0-4.613-3.787-8.4-8.4-8.4h-.329a9.2 9.2 0 0 0 4.329-7.8v-3.2c0-5.07-4.13-9.2-9.2-9.2zm0 3.2h.8c3.352 0 6 2.648 6 6v3.2c0 3.352-2.648 6-6 6h-.8c-3.352 0-6-2.648-6-6v-3.2c0-3.352 2.648-6 6-6M77.4 62c-5.07 0-9.2 4.13-9.2 9.2v3.2a9.2 9.2 0 0 0 4.33 7.8c-4.581.038-8.33 3.81-8.33 8.4v2.6a1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6v-2.6c0-2.867 2.333-5.2 5.2-5.2h10.8c2.867 0 5.2 2.333 5.2 5.2v2.6a1.6 1.6 0 0 0 1.6 1.6 1.6 1.6 0 0 0 1.6-1.6v-2.6c0-4.613-3.787-8.4-8.4-8.4h-.329a9.2 9.2 0 0 0 4.329-7.8v-3.2c0-5.07-4.13-9.2-9.2-9.2zm0 3.2h.8c3.352 0 6 2.648 6 6v3.2c0 3.352-2.648 6-6 6h-.8c-3.352 0-6-2.648-6-6v-3.2c0-3.352 2.648-6 6-6M48.4 46v10a1.6 1.6 0 0 0 3.2 0V46a1.6 1.6 0 0 0-3.2 0"/><path d="m48.976 54.771-12 10a1.6 1.6 0 0 0 2.048 2.458l12-10a1.6 1.6 0 0 0-2.048-2.458"/><path d="m48.976 57.229 12 10a1.6 1.6 0 0 0 2.048-2.458l-12-10a1.6 1.6 0 0 0-2.048 2.458"/></g>',
 mcp:'<rect x="2" y="2" width="1020" height="1020" rx="230" fill="#182437"/><g fill="#F7F3EB"><g transform="translate(512 512)"><g stroke="#F7F3EB" stroke-width="44" stroke-linecap="round" fill="none"><path d="M0 0L-170 150M0 0L170 150M0 0V-200"/></g><circle r="80"/><circle cx="-190" cy="168" r="64"/><circle cx="190" cy="168" r="64"/><circle cy="-230" r="64"/></g></g>',
 cluster:'<rect x="2" y="2" width="1020" height="1020" rx="230" fill="#BFD8F7"/><g transform="translate(512 512)"><path d="M-160 -160H160V160H-160Z" fill="none" stroke="#141414" stroke-width="44" stroke-linejoin="round"/><g fill="#C8102E"><circle cx="-160" cy="-160" r="96"/><circle cx="160" cy="-160" r="96"/><circle cx="-160" cy="160" r="96"/><circle cx="160" cy="160" r="96"/></g></g>'
};
function figure(fill,x,y,h) {
 const s=h/100;
 return '<path class="orcel-figure" transform="translate('+(x-8*s).toFixed(2)+' '+y.toFixed(2)+') scale('+s.toFixed(4)+')" fill="'+fill+'" d="'+FIGURE+'"/>';
}
function word(fill,x,base,h) {
 const s=h/WORD_L;
 return '<path class="orcel-wordmark" transform="translate('+x.toFixed(2)+' '+base.toFixed(2)+') scale('+s.toFixed(5)+')" fill="'+fill+'" d="'+WORD+'"/>';
}
function wordWidth(h){return WORD_ADV*h/WORD_L;}
function icon(name,size) {
 return '<g transform="scale('+(size/1024).toFixed(5)+')">'+ICONS[name]+'</g>';
}
const mark=(fill,label)=>doc("0 0 256 256","  "+figure(fill,44,28,200),label);
const markWhite=mark(ORCEL.white,"Orcel figure, white");
const markInk=mark(ORCEL.ink,"Orcel figure, ink");
const markRed=mark(ORCEL.vermilion,"Orcel figure, vermilion");
const appIcon=doc("0 0 256 256","  "+icon("orcel",256),"Orcel application icon: vermilion figure on ivory");
const appIconRed=doc("0 0 256 256",
  '  <rect width="256" height="256" rx="58" fill="'+ORCEL.vermilion+'"/>\n  '+figure(ORCEL.white,70,58,140),
  "Orcel reversed application icon: white figure on vermilion");
const productIcon=(name,label)=>doc("0 0 256 256","  "+icon(name,256),label);
// Wordmark canvas 1032 x 307 (the raster export size): the l stands 200 high, centred.
function wordDoc(fill,label) {
 const h=200,w=wordWidth(h);
 return doc("0 0 1032 307","  "+word(fill,(1032-w)/2,253,h),label);
}
const wordInk=wordDoc(ORCEL.ink,"orcel wordmark, ink");
const wordWhite=wordDoc(ORCEL.white,"orcel wordmark, white");
// Horizontal lockup 1350 x 384: the figure is exactly as tall as the l; gap 0.26 of that height.
function lockupBody(wordFill,figFill,x,base,h) {
 const fw=0.84*h,gap=0.26*h;
 return figure(figFill,x,base-h,h)+word(wordFill,x+fw+gap,base,h);
}
function lockupDoc(wordFill,figFill,label) {
 const h=230,total=0.84*h+0.26*h+wordWidth(h);
 return doc("0 0 1350 384","  "+lockupBody(wordFill,figFill,(1350-total)/2,307,h),label);
}
const lockInk=lockupDoc(ORCEL.ink,ORCEL.vermilion,"orcel horizontal logo: vermilion figure, ink wordmark");
const lockWhite=lockupDoc(ORCEL.white,ORCEL.vermilion,"orcel horizontal logo: vermilion figure, white wordmark");
function stacked(wordFill,figFill,label) {
 const w=wordWidth(110);
 return doc("0 0 520 460","  "+figure(figFill,260-0.42*230,20,230)+"\n  "+word(wordFill,(520-w)/2,410,110),label);
}
const stackInk=stacked(ORCEL.ink,ORCEL.vermilion,"orcel stacked logo, ink");
const stackWhite=stacked(ORCEL.white,ORCEL.vermilion,"orcel stacked logo, white");
// README lockup on ivory, readable in GitHub light and dark themes.
const readmeLogo=doc("0 0 1000 300",
  '  <rect width="1000" height="300" rx="20" fill="'+ORCEL.ivory+'"/>\n  '+lockupBody(ORCEL.ink,ORCEL.vermilion,(1000-(0.84+0.26)*150-wordWidth(150))/2,225,150),
  "orcel logo on ivory for GitHub");
function social(dark) {
 const bg=dark?ORCEL.navy:ORCEL.ivory,wordFill=dark?ORCEL.white:ORCEL.ink,muted=dark?"#B9C0D6":"#5B6070";
 return doc("0 0 1200 630",
   '<rect width="1200" height="630" fill="'+bg+'"/>\n'+lockupBody(wordFill,ORCEL.vermilion,95,330,170)+'\n'+
   '<path d="M95 470 H1105" stroke="'+muted+'" stroke-width="1" opacity=".4"/>\n'+
   '<text x="97" y="540" font-family="Inter,Arial,sans-serif" font-size="30" fill="'+muted+'">People first. One person, many agents.</text>'+
   '<text x="1100" y="540" text-anchor="end" font-family="Inter,Arial,sans-serif" font-size="16" letter-spacing="3" fill="'+muted+'">YOUR COMPUTER. YOUR TERMS.</text>',
   "Orcel social banner");
}
function motif() {
 // A field of figures on ivory; one in twelve is vermilion: one person among many agents.
 const parts=['<rect width="1200" height="420" fill="'+ORCEL.ivory+'"/>'];
 for(let row=0;row<4;row++){
  for(let col=0;col<12;col++){
   const x=34+col*100+(row%2?50:0),y=22+row*100;
   const fill=(col*5+row*3)%12===7?ORCEL.vermilion:"#D9D1C3";
   parts.push(figure(fill,x,y,64));
  }
 }
 return doc("0 0 1200 420",parts.join("\n"),"Orcel supporting pattern: one person among many");
}
const pattern=motif();
const outputs=new Map([
 ["assets/brand/orcel-o-white.svg",markWhite],
 ["assets/brand/orcel-o-black.svg",markInk],
 ["assets/brand/orcel-mark-red.svg",markRed],
 ["assets/brand/orcel-app-icon.svg",appIcon],
 ["assets/brand/orcel-app-icon-light.svg",appIconRed],
 ["assets/brand/orcel-icon-browser.svg",productIcon("browser","Orcel Browser icon")],
 ["assets/brand/orcel-icon-agent.svg",productIcon("agent","Orcel Agent icon")],
 ["assets/brand/orcel-icon-mcp.svg",productIcon("mcp","Orcel MCP icon")],
 ["assets/brand/orcel-icon-cluster.svg",productIcon("cluster","Orcel Cluster icon")],
 ["assets/brand/orcel-wordmark-white.svg",wordWhite],
 ["assets/brand/orcel-wordmark-black.svg",wordInk],
 ["assets/brand/orcel-readme-lockup.svg",readmeLogo],
 ["assets/brand/orcel-lockup-white.svg",lockWhite],
 ["assets/brand/orcel-lockup-black.svg",lockInk],
 ["assets/brand/orcel-lockup-stacked-white.svg",stackWhite],
 ["assets/brand/orcel-lockup-stacked-black.svg",stackInk],
 ["assets/brand/orcel-social-dark.svg",social(true)],
 ["assets/brand/orcel-social-light.svg",social(false)],
 ["assets/brand/orcel-monogram-pattern.svg",pattern],
 ["assets/brand/orcel-orbit-pattern.svg",pattern],
 ["assets/brand/orcel-accent-icon.svg",productIcon("browser","Orcel accent icon: Orcel Browser")]
]);
for (const [name,data] of [...outputs]) {
 if(name.startsWith("assets/brand/")&&name!=="assets/brand/orcel-readme-lockup.svg")outputs.set(name.replace("assets/brand/","apps/web/public/brand/"),data);
}
outputs.set("apps/web/app/icon.svg",appIcon);
outputs.set("distribution/openai/assets/logo.svg",appIcon);
outputs.set("distribution/codex/orcel/assets/logo.svg",appIcon);
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
console.log("Orcel identity v5 "+(check?"verified":"generated")+": "+outputs.size+" SVG destinations");
for (const [name,data] of [["figure",markRed],["app icon",appIcon],["lockup",lockInk]]) {
 console.log(name+": "+createHash("sha256").update(data).digest("hex"));
}
