// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// XP-06 live observation probe for macOS (AppKit over AX), run with
//   osascript -l JavaScript appkit_probe.js NONCE SECRET
// Opens "Orcel XP06 Probe NONCE" (a text field holding "visible-NONCE", an
// NSSecureTextField holding SECRET labelled "Sign in", and a button) and
// "Orcel Approval Probe NONCE" (a protected Orcel surface), then serves its
// run loop for two minutes so AX requests are answered.
ObjC.import("Cocoa");

function run(argv) {
  const nonce = argv[0];
  const secret = argv[1];
  const app = $.NSApplication.sharedApplication;
  app.setActivationPolicy($.NSApplicationActivationPolicyRegular);

  function makeWindow(title, top) {
    const style = $.NSWindowStyleMaskTitled | $.NSWindowStyleMaskClosable;
    const window = $.NSWindow.alloc.initWithContentRectStyleMaskBackingDefer(
      $.NSMakeRect(200, top, 420, 200),
      style,
      $.NSBackingStoreBuffered,
      false
    );
    window.title = title;
    window.releasedWhenClosed = false;
    window.makeKeyAndOrderFront(null);
    return window;
  }

  const probe = makeWindow("Orcel XP06 Probe " + nonce, 420);
  const plain = $.NSTextField.alloc.initWithFrame($.NSMakeRect(20, 130, 380, 24));
  plain.stringValue = "visible-" + nonce;
  probe.contentView.addSubview(plain);
  const hidden = $.NSSecureTextField.alloc.initWithFrame($.NSMakeRect(20, 90, 380, 24));
  hidden.stringValue = secret;
  hidden.setAccessibilityLabel("Sign in");
  probe.contentView.addSubview(hidden);
  const button = $.NSButton.alloc.initWithFrame($.NSMakeRect(20, 30, 120, 32));
  button.title = "Submit";
  probe.contentView.addSubview(button);

  makeWindow("Orcel Approval Probe " + nonce, 120);
  app.activateIgnoringOtherApps(true);
  $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(120));
}
