// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// XP-12 raw input oracle for macOS (AppKit).
//
//   swiftc -O appkit_input_probe.swift -o appkit_input_probe
//   appkit_input_probe NONCE STATE_FILE COVER_FLAG
//
// Opens, and runs for two minutes:
// - "Orcel XP12 Input NONCE": a fixed 400x300 content window whose one view
//   fills it and journals every pointer, scroll and key event it receives.
//   Coordinates are window-relative points from the top-left of the window
//   frame (the title bar included), which is the frame `list_windows` bounds
//   describe. STATE_FILE is rewritten atomically after every event:
//     {"pid": ..., "origin": [x, y], "size": [w, h], "cover": bool,
//      "events": [{"kind": "down|up|motion|scroll|key", ...}, ...]}
//   The host is never asked what happened; the test reads what the
//   application itself received.
// - "Orcel Approval Probe NONCE": titled as a protected Orcel surface, which
//   the host must never deliver input to.
// - "Orcel XP12 Cover NONCE": a larger window shown while the file COVER_FLAG
//   exists, placed over the input window, hidden when it is removed.

import AppKit

let arguments = CommandLine.arguments
guard arguments.count == 4 else {
    FileHandle.standardError.write(Data("usage: appkit_input_probe NONCE STATE_FILE COVER_FLAG\n".utf8))
    exit(2)
}
let nonce = arguments[1]
let stateFile = URL(fileURLWithPath: arguments[2])
let coverFlag = arguments[3]

var events: [[String: Any]] = []
var inputWindow: NSWindow!
var coverWindow: NSWindow!

/// The window's top-left corner in screen coordinates with a top-left origin,
/// the convention of the window list.
func topLeft(of window: NSWindow) -> [Double] {
    let screenHeight = NSScreen.screens.first?.frame.height ?? 0
    return [Double(window.frame.minX), Double(screenHeight - window.frame.maxY)]
}

func writeState() {
    let state: [String: Any] = [
        "pid": Int(ProcessInfo.processInfo.processIdentifier),
        "origin": topLeft(of: inputWindow),
        "size": [Double(inputWindow.frame.width), Double(inputWindow.frame.height)],
        "cover": coverWindow.isVisible,
        "events": events,
    ]
    guard let data = try? JSONSerialization.data(withJSONObject: state) else { return }
    let temporary = stateFile.appendingPathExtension("tmp")
    do {
        try data.write(to: temporary)
        _ = try FileManager.default.replaceItemAt(stateFile, withItemAt: temporary)
    } catch {
        FileHandle.standardError.write(Data("state write failed: \(error)\n".utf8))
    }
}

func record(_ event: [String: Any]) {
    events.append(event)
    writeState()
}

final class EventView: NSView {
    override var acceptsFirstResponder: Bool { true }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }

    private func point(_ event: NSEvent) -> (Double, Double) {
        guard let window else { return (-1, -1) }
        return (Double(event.locationInWindow.x), Double(window.frame.height - event.locationInWindow.y))
    }

    private func pointer(_ kind: String, _ event: NSEvent, button: Int) {
        let (x, y) = point(event)
        record(["kind": kind, "x": x, "y": y, "button": button, "clicks": event.clickCount])
    }

    override func mouseDown(with event: NSEvent) { pointer("down", event, button: 1) }
    override func mouseUp(with event: NSEvent) { pointer("up", event, button: 1) }
    override func rightMouseDown(with event: NSEvent) { pointer("down", event, button: 3) }
    override func rightMouseUp(with event: NSEvent) { pointer("up", event, button: 3) }
    override func mouseDragged(with event: NSEvent) {
        let (x, y) = point(event)
        record(["kind": "motion", "x": x, "y": y])
    }

    override func scrollWheel(with event: NSEvent) {
        let (x, y) = point(event)
        record(["kind": "scroll", "x": x, "y": y, "dx": Double(event.scrollingDeltaX), "dy": Double(event.scrollingDeltaY)])
    }

    override func keyDown(with event: NSEvent) {
        record([
            "kind": "key",
            "code": Int(event.keyCode),
            "string": event.characters ?? "",
            "state": Int(event.modifierFlags.intersection(.deviceIndependentFlagsMask).rawValue),
        ])
    }
}

func makeWindow(_ title: String, width: CGFloat, height: CGFloat, top: CGFloat) -> NSWindow {
    let window = NSWindow(
        contentRect: NSRect(x: 200, y: top, width: width, height: height),
        styleMask: [.titled, .closable],
        backing: .buffered,
        defer: false
    )
    window.title = title
    window.isReleasedWhenClosed = false
    return window
}

let application = NSApplication.shared
application.setActivationPolicy(.regular)

inputWindow = makeWindow("Orcel XP12 Input " + nonce, width: 400, height: 300, top: 300)
inputWindow.contentView = EventView(frame: NSRect(x: 0, y: 0, width: 400, height: 300))
inputWindow.makeKeyAndOrderFront(nil)
inputWindow.makeFirstResponder(inputWindow.contentView)

let approval = makeWindow("Orcel Approval Probe " + nonce, width: 200, height: 100, top: 80)
approval.makeKeyAndOrderFront(nil)

coverWindow = makeWindow("Orcel XP12 Cover " + nonce, width: 600, height: 500, top: 200)

// The window server may place the frame a little off; the cover is placed
// from the input window's actual frame.
Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { _ in
    let wanted = FileManager.default.fileExists(atPath: coverFlag)
    if wanted && !coverWindow.isVisible {
        let frame = inputWindow.frame.insetBy(dx: -100, dy: -100)
        coverWindow.setFrame(frame, display: true)
        coverWindow.orderFrontRegardless()
        writeState()
    } else if !wanted && coverWindow.isVisible {
        coverWindow.orderOut(nil)
        writeState()
    }
}
Timer.scheduledTimer(withTimeInterval: 0.5, repeats: false) { _ in writeState() }
Timer.scheduledTimer(withTimeInterval: 120, repeats: false) { _ in NSApplication.shared.terminate(nil) }
application.activate(ignoringOtherApps: true)
application.run()
