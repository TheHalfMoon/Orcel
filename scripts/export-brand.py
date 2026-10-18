#!/usr/bin/env python3
"""Reproducible Orcel brand packaging. Python standard library only.
First run: node scripts/sync-brand.mjs && node scripts/render-brand.mjs
SVG sources and verification are in Git; binary exports are Pages artifacts.
"""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
from zipfile import ZipFile, ZipInfo, ZIP_DEFLATED
from shutil import copyfile
import json
import struct

ROOT=Path(__file__).resolve().parent.parent
BRAND=ROOT/"assets"/"brand"
OUT=BRAND/"exports"
PUBLIC=ROOT/"apps"/"web"/"public"/"brand"
DOWNLOADS=BRAND/"downloads"
DOWNLOADS.mkdir(parents=True,exist_ok=True)
PUBLIC.mkdir(parents=True,exist_ok=True)
ZIPPATH=DOWNLOADS/"Orcel-Identity-Kit-v2.zip"

def png_info(path:Path)->tuple[int,int]:
    raw=path.read_bytes()
    if not raw.startswith(b"\x89PNG\r\n\x1a\n") or len(raw)<24:
        raise ValueError(f"Not PNG: {path}")
    return struct.unpack(">II",raw[16:24])

# Exact expected app sizes, generated from reviewed SVG via local sharp.
for n in (16,24,32,48,64,128,256,512,1024):
    for name in (f"orcel-app-dark-{n}.png",f"orcel-mark-white-{n}.png"):
        if png_info(OUT/name)!=(n,n):raise ValueError(f"Incorrect dimensions: {name}")
for n in (32,64,128,256,512,1024):
    for name in (f"orcel-app-light-{n}.png",f"orcel-mark-black-{n}.png"):
        if png_info(OUT/name)!=(n,n):raise ValueError(f"Incorrect dimensions: {name}")
if png_info(OUT/"orcel-social-dark.png")!=(1200,630):raise ValueError("Invalid social image")
if png_info(OUT/"orcel-identity-overview.png")!=(1600,1050):raise ValueError("Invalid preview")

# A standard ICO containing embedded 16,32,256px PNGs; no third-party PIL.
sizes=[16,32,256]
images=[(n,(OUT/f"orcel-app-dark-{n}.png").read_bytes()) for n in sizes]
start=6+16*len(images);offset=start
ico=[struct.pack("<HHH",0,1,len(images))]
for n,raw in images:
    ico.append(struct.pack("<BBBBHHII",n if n<256 else 0,n if n<256 else 0,
                           0,0,1,32,len(raw),offset))
    offset+=len(raw)
ico.extend(raw for _,raw in images)
(OUT/"orcel-favicon.ico").write_bytes(b"".join(ico))

sources=sorted(BRAND.glob("*.svg"))
exports=sorted(OUT.glob("*"))
docs=[BRAND/"IDENTITY.md",ROOT/"docs"/"brand"/"README.md"]
entries=sorted([*sources,*exports,*docs],key=lambda p:p.relative_to(ROOT).as_posix())
manifest={"name":"Orcel","brand_version":"2.0","source":"Orcel Signal Identity 2026","assets":[]}
for path in entries:
    body=path.read_bytes()
    manifest["assets"].append({
        "path":path.relative_to(ROOT).as_posix(),
        "sha256":sha256(body).hexdigest(),
        "bytes":len(body)
    })
manifest_path=BRAND/"ASSET_MANIFEST.json"
manifest_path.write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n",encoding="utf8")
entries.append(manifest_path)
with ZipFile(ZIPPATH,"w",ZIP_DEFLATED,compresslevel=9) as z:
    for path in sorted(entries,key=lambda p:p.relative_to(ROOT).as_posix()):
        name="Orcel-Identity-Kit-v2/"+path.relative_to(ROOT).as_posix()
        info=ZipInfo(name,date_time=(2026,10,16,0,0,0))
        info.compress_type=ZIP_DEFLATED
        info.external_attr=0o644<<16
        z.writestr(info,path.read_bytes(),compress_type=ZIP_DEFLATED,compresslevel=9)
copyfile(ZIPPATH,PUBLIC/ZIPPATH.name)
copyfile(manifest_path,PUBLIC/"orcel-asset-manifest.json")
print("Orcel SVG masters:",len(sources))
print("Orcel raster/ICO exports:",len(exports))
print("Manifest entries:",len(manifest["assets"]))
print("Pages brand kit ZIP:",ZIPPATH.name,"bytes:",ZIPPATH.stat().st_size)
