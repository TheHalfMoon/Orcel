#!/usr/bin/env python3
# Copyright 2026 TheHalfMoon contributors
# SPDX-License-Identifier: Apache-2.0
"""XP-12 raw input oracle for Linux (Tk on X11).

Usage: tk_input_probe.py NONCE STATE_FILE COVER_FLAG

Tk, not GTK: Cua refuses background pointer and key delivery to a GTK
application unless a real (uinput) pointer backend exists, and the CI session
(Xvfb) has none. A Tk application accepts the targeted events Cua sends, so
the probe measures what the host delivers rather than what this session lacks.

Opens, and runs until killed (at most two minutes):
- "Orcel XP12 Input NONCE": a fixed 400x300 window whose one widget fills it
  and journals every pointer, scroll and key event it receives, with the
  window-relative coordinates Tk delivered. STATE_FILE is rewritten
  atomically after every event:
    {"pid": ..., "origin": [x, y], "size": [w, h], "cover": bool,
     "events": [{"kind": "down|up|motion|scroll|key", ...}, ...]}
  The host is never asked what happened; the test reads what the application
  itself received.
- "Orcel Approval Probe NONCE": titled as a protected Orcel surface, which
  the host must never deliver input to.
- "Orcel XP12 Cover NONCE": a larger window that is shown while the file
  COVER_FLAG exists, placed over the input window, and hidden when it is
  removed. It is how the test covers the target.
"""

import json
import os
import sys
import tkinter as tk

NONCE, STATE_FILE, COVER_FLAG = sys.argv[1], sys.argv[2], sys.argv[3]
WIDTH, HEIGHT = 400, 300
events = []

root = tk.Tk()
root.title("Orcel XP12 Input " + NONCE)
root.geometry(f"{WIDTH}x{HEIGHT}+100+100")
root.resizable(False, False)
canvas = tk.Canvas(
    root, width=WIDTH, height=HEIGHT, highlightthickness=0, borderwidth=0, bg="white"
)
canvas.pack(fill="both", expand=True)

approval = tk.Toplevel(root)
approval.title("Orcel Approval Probe " + NONCE)
approval.geometry("200x100+600+100")
tk.Label(approval, text="protected surface").pack()

cover = tk.Toplevel(root)
cover.title("Orcel XP12 Cover " + NONCE)
tk.Label(cover, text="cover").pack()
cover.withdraw()


def write_state():
    state = {
        "pid": os.getpid(),
        "origin": [root.winfo_rootx(), root.winfo_rooty()],
        "size": [WIDTH, HEIGHT],
        "cover": cover.state() == "normal",
        "events": events,
    }
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(state, handle)
    os.replace(tmp, STATE_FILE)


def record(**event):
    events.append(event)
    write_state()


def pointer(kind, clicks=None):
    def handler(event):
        entry = dict(kind=kind, x=event.x, y=event.y, button=event.num)
        if clicks is not None:
            entry["clicks"] = clicks
        record(**entry)

    return handler


def wheel(direction):
    def handler(event):
        record(kind="scroll", x=event.x, y=event.y, direction=direction)

    return handler


def key(event):
    record(kind="key", name=event.keysym, string=event.char)


for number in (1, 3):
    canvas.bind(f"<Button-{number}>", pointer("down", 1))
    canvas.bind(f"<Double-Button-{number}>", pointer("down", 2))
    canvas.bind(f"<Triple-Button-{number}>", pointer("down", 3))
    canvas.bind(f"<ButtonRelease-{number}>", pointer("up"))
canvas.bind(
    "<B1-Motion>",
    lambda event: record(kind="motion", x=event.x, y=event.y),
)
for number, direction in ((4, "up"), (5, "down"), (6, "left"), (7, "right")):
    canvas.bind(f"<Button-{number}>", wheel(direction))
root.bind("<KeyPress>", key)


def sync_cover():
    wanted = os.path.exists(COVER_FLAG)
    shown = cover.state() == "normal"
    if wanted and not shown:
        x, y = root.winfo_rootx(), root.winfo_rooty()
        cover.geometry(f"{WIDTH + 200}x{HEIGHT + 200}+{max(0, x - 100)}+{max(0, y - 100)}")
        cover.deiconify()
        cover.lift()
        write_state()
    elif not wanted and shown:
        cover.withdraw()
        write_state()
    root.after(200, sync_cover)


def start():
    root.focus_force()
    write_state()
    sync_cover()


root.after(500, start)
root.after(120000, root.destroy)
root.mainloop()
