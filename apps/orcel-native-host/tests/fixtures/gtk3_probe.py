#!/usr/bin/env python3
# Copyright 2026 TheHalfMoon contributors
# SPDX-License-Identifier: Apache-2.0
"""XP-06 live observation probe for Linux (GTK3 over AT-SPI).

Usage: gtk3_probe.py NONCE SECRET

Opens two windows and runs until killed (at most two minutes):
- "Orcel XP06 Probe NONCE": a plain entry holding "visible-NONCE", a
  password entry (visibility off, AT-SPI role "password text") holding
  SECRET and named "Sign in" (no password marker in its name, so redaction
  must come from the role), and a button.
- "Orcel Approval Probe NONCE": titled as a protected Orcel surface, which
  the kernel registry must omit.
"""

import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk  # noqa: E402

NONCE, SECRET = sys.argv[1], sys.argv[2]


def window(title, build):
    win = Gtk.Window(title=title)
    win.set_default_size(420, 200)
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    build(box)
    win.add(box)
    win.connect("destroy", Gtk.main_quit)
    win.show_all()
    return win


def probe(box):
    plain = Gtk.Entry()
    plain.set_text("visible-" + NONCE)
    plain.get_accessible().set_name("Plain field")
    box.add(plain)
    hidden = Gtk.Entry()
    hidden.set_visibility(False)
    hidden.set_text(SECRET)
    hidden.get_accessible().set_name("Sign in")
    box.add(hidden)
    box.add(Gtk.Button(label="Submit"))


def protected(box):
    box.add(Gtk.Label(label="protected surface"))


window("Orcel XP06 Probe " + NONCE, probe)
window("Orcel Approval Probe " + NONCE, protected)
GLib.timeout_add_seconds(120, Gtk.main_quit)
Gtk.main()
