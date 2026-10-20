#!/usr/bin/env python3
# Copyright 2026 TheHalfMoon contributors
# SPDX-License-Identifier: Apache-2.0
"""XP-12 raw input oracle for Linux (GTK3 on X11).

Usage: gtk3_input_probe.py NONCE STATE_FILE COVER_FLAG

Opens, and runs until killed (at most two minutes):
- "Orcel XP12 Input NONCE": a fixed 400x300 window whose one widget fills it
  and journals every pointer, scroll and key event it receives, with the
  window-relative coordinates GTK delivered. STATE_FILE is rewritten
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

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gdk, GLib, Gtk  # noqa: E402

NONCE, STATE_FILE, COVER_FLAG = sys.argv[1], sys.argv[2], sys.argv[3]
WIDTH, HEIGHT = 400, 300
events = []
window_ref = {}


def write_state():
    win = window_ref["input"]
    x, y = win.get_position()
    state = {
        "pid": os.getpid(),
        "origin": [x, y],
        "size": [WIDTH, HEIGHT],
        "cover": window_ref["cover"].get_visible(),
        "events": events,
    }
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as handle:
        json.dump(state, handle)
    os.replace(tmp, STATE_FILE)


def record(**event):
    events.append(event)
    write_state()


def on_press(_widget, event):
    kind = {
        Gdk.EventType.BUTTON_PRESS: 1,
        Gdk.EventType._2BUTTON_PRESS: 2,
        Gdk.EventType._3BUTTON_PRESS: 3,
    }.get(event.type)
    if kind is None:
        return True
    record(kind="down", x=event.x, y=event.y, button=event.button, clicks=kind)
    return True


def on_release(_widget, event):
    record(kind="up", x=event.x, y=event.y, button=event.button)
    return True


def on_motion(_widget, event):
    # Only a held button: a drag, not a hover.
    if event.state & (
        Gdk.ModifierType.BUTTON1_MASK
        | Gdk.ModifierType.BUTTON2_MASK
        | Gdk.ModifierType.BUTTON3_MASK
    ):
        record(kind="motion", x=event.x, y=event.y)
    return True


def on_scroll(_widget, event):
    if event.direction == Gdk.ScrollDirection.SMOOTH:
        _ok, dx, dy = event.get_scroll_deltas()
        record(kind="scroll", x=event.x, y=event.y, dx=dx, dy=dy)
    else:
        name = event.direction.value_nick
        record(kind="scroll", x=event.x, y=event.y, direction=name)
    return True


def on_key(_widget, event):
    record(
        kind="key",
        name=Gdk.keyval_name(event.keyval),
        string=event.string,
        state=int(event.state & Gtk.accelerator_get_default_mod_mask()),
    )
    return True


def make_window(title, width, height, resizable=False):
    win = Gtk.Window(title=title)
    win.set_default_size(width, height)
    win.set_resizable(resizable)
    win.connect("destroy", Gtk.main_quit)
    return win


def build_input_window():
    win = make_window("Orcel XP12 Input " + NONCE, WIDTH, HEIGHT)
    area = Gtk.DrawingArea()
    area.set_size_request(WIDTH, HEIGHT)
    area.add_events(
        Gdk.EventMask.BUTTON_PRESS_MASK
        | Gdk.EventMask.BUTTON_RELEASE_MASK
        | Gdk.EventMask.POINTER_MOTION_MASK
        | Gdk.EventMask.BUTTON_MOTION_MASK
        | Gdk.EventMask.SCROLL_MASK
        | Gdk.EventMask.SMOOTH_SCROLL_MASK
    )
    area.connect("button-press-event", on_press)
    area.connect("button-release-event", on_release)
    area.connect("motion-notify-event", on_motion)
    area.connect("scroll-event", on_scroll)
    win.connect("key-press-event", on_key)
    win.add(area)
    win.show_all()
    return win


def build_cover_window():
    win = make_window("Orcel XP12 Cover " + NONCE, WIDTH + 200, HEIGHT + 200)
    win.add(Gtk.Label(label="cover"))
    return win


def sync_cover():
    cover = window_ref["cover"]
    wanted = os.path.exists(COVER_FLAG)
    if wanted and not cover.get_visible():
        x, y = window_ref["input"].get_position()
        cover.move(max(0, x - 100), max(0, y - 100))
        cover.show_all()
        cover.move(max(0, x - 100), max(0, y - 100))
        write_state()
    elif not wanted and cover.get_visible():
        cover.hide()
        write_state()
    return True


window_ref["input"] = build_input_window()
approval = make_window("Orcel Approval Probe " + NONCE, 200, 100)
approval.add(Gtk.Label(label="protected surface"))
approval.show_all()
window_ref["cover"] = build_cover_window()
GLib.timeout_add(200, sync_cover)
GLib.timeout_add(500, lambda: (write_state(), False)[1])
GLib.timeout_add_seconds(120, Gtk.main_quit)
Gtk.main()
