#!/usr/bin/env python3
# Copyright 2026 TheHalfMoon contributors
# SPDX-License-Identifier: Apache-2.0
"""XP-07 live capture probe for Linux X11 (GTK3).

Usage: gtk3_capture_probe.py NONCE

Opens three windows and runs until killed (at most three minutes):
- "Orcel XP07 Capture NONCE": a 320x200 area painted the marker colour
  RGB(224, 17, 157), the window the test captures.
- "Orcel Approval Probe NONCE": titled as a protected Orcel surface, which
  the host must refuse to capture.
- "Orcel XP07 Cover NONCE": a 200x120 green RGB(16, 200, 32) window, kept
  away from the target until told otherwise.

Commands, one per line on stdin:
- "cover": move the cover window over the middle of the target.
- "uncover": move the cover window back to the far corner.
- "minimize": minimize (iconify) the target. Nothing restores it.
"""

import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

NONCE = sys.argv[1]
MARKER = (224, 17, 157)
COVER = (16, 200, 32)


def painted(title, width, height, rgb, x, y):
    # The colour is a CSS background, so no cairo binding is needed.
    win = Gtk.Window(title=title)
    win.set_resizable(False)
    name = "probe%d%d%d" % rgb
    win.set_name(name)
    css = Gtk.CssProvider()
    css.load_from_data(
        ("#%s { background-color: rgb(%d, %d, %d); background-image: none; }"
         % ((name,) + rgb)).encode()
    )
    win.get_style_context().add_provider(css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
    area = Gtk.Box()
    area.set_size_request(width, height)
    win.add(area)
    win.move(x, y)
    win.show_all()
    return win


target = painted("Orcel XP07 Capture " + NONCE, 320, 200, MARKER, 40, 40)
protected = painted("Orcel Approval Probe " + NONCE, 200, 120, (40, 40, 40), 40, 400)
cover = painted("Orcel XP07 Cover " + NONCE, 200, 120, COVER, 900, 560)
target.connect("destroy", Gtk.main_quit)


def command(source, _condition):
    line = source.readline()
    if not line:
        return False
    word = line.strip()
    if word == "cover":
        x, y = target.get_position()
        cover.move(x + 60, y + 60)
        cover.present()
    elif word == "uncover":
        cover.move(900, 560)
    elif word == "minimize":
        target.iconify()
    return True


GLib.io_add_watch(sys.stdin, GLib.IO_IN | GLib.IO_HUP, command)
GLib.timeout_add_seconds(180, Gtk.main_quit)
Gtk.main()
