// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// XP-07 live capture probe for macOS (AppKit), run with
//   osascript -l JavaScript appkit_capture_probe.js NONCE [MINIMIZE_AFTER]
// Opens:
// - "Orcel XP07 Capture NONCE": 320x200 points filled with the marker colour
//   sRGB(224, 17, 157), the window the test captures;
// - "Orcel Approval Probe NONCE": a protected Orcel surface;
// - "Orcel XP07 Cover NONCE": a green window placed over the middle of the
//   target and ordered above it. ScreenCaptureKit's window filter reads the
//   target's own buffer, so the cover must never appear in its frame.
// Then serves its run loop for three minutes. With MINIMIZE_AFTER (seconds),
// it minimizes the capture window to the Dock at that point; nothing
// restores it.
ObjC.import("Cocoa");

function run(argv) {
  const nonce = argv[0];
  const minimizeAfter = Number(argv[1] || 0);
  const app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyRegular);

  function makeWindow(title, x, y, width, height, red, green, blue) {
    const style = $.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable;
    const window = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer(
      $.NSMakeRect(x, y, width, height),
      style,
      $.NSBackingStoreBuffered,
      false
    );
    window.title = title;
    window.releasedWhenClosed = false;
    window.backgroundColor = $.NSColor.colorWithSRGBRedGreenBlueAlpha(
      red / 255,
      green / 255,
      blue / 255,
      1
    );
    window.makeKeyAndOrderFront(null);
    return window;
  }

  const target = makeWindow("Orcel XP07 Capture " + nonce, 200, 420, 320, 200, 224, 17, 157);
  makeWindow("Orcel Approval Probe " + nonce, 600, 420, 200, 120, 40, 40, 40);
  const cover = makeWindow("Orcel XP07 Cover " + nonce, 260, 460, 200, 120, 16, 200, 32);
  cover.orderFrontRegardless;
  app.activateIgnoringOtherApps(true);
  const loop = $.NSRunLoop.currentRunLoop;
  if (minimizeAfter > 0) {
    loop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(minimizeAfter));
    target.miniaturize(null);
  }
  loop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(180));
}
