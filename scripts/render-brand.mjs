#!/usr/bin/env node
// Build-time only. Uses the already exact-pinned sharp dependency of apps/web.
// No bundled font files, online API, or graphics runtime in Orcel's product.
import { createRequire } from "node:module";
import { mkdirSync,readFileSync,copyFileSync } from "node:fs";
import { resolve,dirname,join } from "node:path";
import { fileURLToPath } from "node:url";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const require=createRequire(join(root,"apps/web/package.json"));
const sharp=require("sharp");
const out=join(root,"assets/brand/exports");
mkdirSync(out,{recursive:true});
const batch=[];
const add=(src,w,h,name)=>batch.push({src,w,h,name});
for(const n of [16,24,32,48,64,128,256,512,1024]){
 add("orcel-app-icon.svg",n,n,"orcel-app-dark-"+n+".png");
 add("orcel-o-white.svg",n,n,"orcel-mark-white-"+n+".png");
}
for(const n of [32,64,128,256,512,1024]){
 add("orcel-app-icon-light.svg",n,n,"orcel-app-light-"+n+".png");
 add("orcel-o-black.svg",n,n,"orcel-mark-black-"+n+".png");
}
for(const color of ["white","black"]){
 add("orcel-wordmark-"+color+".svg",1032,307,"orcel-wordmark-"+color+".png");
 add("orcel-lockup-"+color+".svg",1350,384,"orcel-lockup-"+color+".png");
}
for(const kind of ["dark","light"])add("orcel-social-"+kind+".svg",1200,630,"orcel-social-"+kind+".png");
const fails=[];
for(const {src,w,h,name} of batch){
 try {
   const path=join(root,"assets/brand",src);
   const raw=readFileSync(path);
   const vb=raw.toString("utf8").match(/viewBox="0 0 ([0-9]+) ([0-9]+)"/);
   const w0=Number(vb?.[1]||256),h0=Number(vb?.[2]||256);
   const density=Math.min(800,Math.max(72,Math.ceil(72*Math.max(w/w0,h/h0))));
   await sharp(raw,{density}).resize(w,h,{fit:"fill"}).png({compressionLevel:9}).toFile(join(out,name));
 }catch(e){fails.push(name+": "+e.message)}
}
if(fails.length){console.error(fails.join("\n"));process.exit(1)}
// The overview composites the same canonical icon assets used by the product.
const previewSvg=Buffer.from(
 '<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="1050" viewBox="0 0 1600 1050">'+
 '<rect width="1600" height="1050" fill="#080808"/>'+
 '<text x="68" y="98" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="48" font-weight="700" letter-spacing="5">ORCEL</text>'+
 '<text x="70" y="137" fill="#B8BCC1" font-family="Arial,sans-serif" font-size="20" letter-spacing="3">BRAND SYSTEM   /   SIGNAL IDENTITY   /   2026</text>'+
 '<line x1="70" y1="177" x2="1530" y2="177" stroke="#3E4144"/>'+
 '<rect x="70" y="210" width="710" height="600" rx="28" fill="#17191B"/>'+
 '<rect x="800" y="210" width="730" height="600" rx="28" fill="#F5F6F7"/>'+
 '<text x="108" y="760" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="22" letter-spacing="2">DARK  /  PRIMARY APP ICON</text>'+
 '<text x="840" y="760" fill="#080808" font-family="Arial,sans-serif" font-size="22" letter-spacing="2">LIGHT  /  INVERSE ICON</text>'+
 '<text x="80" y="875" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="29" font-weight="600">One distinctive wordmark. One consistent signal.</text>'+
 '<text x="80" y="927" fill="#B8BCC1" font-family="Arial,sans-serif" font-size="25">Your computer, your terms.</text>'+
 '<text x="815" y="870" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="21">16px</text>'+
 '<text x="930" y="870" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="21">32px</text>'+
 '<text x="1080" y="870" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="21">64px</text>'+
 '<text x="1300" y="870" fill="#FFFFFF" font-family="Arial,sans-serif" font-size="21">128px</text>'+
 '</svg>');
const overlay=[];
for(const {file,left,top,size} of [
 {file:"orcel-app-dark-512.png",left:225,top:275,size:405},
 {file:"orcel-app-light-512.png",left:955,top:275,size:405},
 {file:"orcel-app-dark-16.png",left:827,top:910,size:16},
 {file:"orcel-app-dark-32.png",left:944,top:904,size:32},
 {file:"orcel-app-dark-64.png",left:1090,top:892,size:64},
 {file:"orcel-app-dark-128.png",left:1310,top:878,size:128}
]){
 const input=await sharp(join(out,file)).resize(size,size).png().toBuffer();
 overlay.push({input,left,top});
}
await sharp(previewSvg).composite(overlay).png().toFile(join(out,"orcel-identity-overview.png"));
copyFileSync(join(out,"orcel-social-dark.png"),join(root,"apps/web/public/brand/orcel-social-dark.png"));
console.log("Rendered "+(batch.length+1)+" PNG files from the canonical Orcel SVG assets using local sharp.");
