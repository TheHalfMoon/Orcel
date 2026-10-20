#!/usr/bin/env bash
# Copyright 2026 TheHalfMoon contributors
# SPDX-License-Identifier: Apache-2.0
#
# XP-08: builds the harness apps the native conformance suite drives, from the
# upstream sources in this directory, into OUT. Nothing is written into the
# checkout. Upstream's build/ scripts stage into Cua's own repository layout
# (libs/cua-driver/rust/test-apps), so Orcel stages here with the same build
# commands: swiftc flags and Info.plist from build/macos.sh, the GTK3 launch
# from build/linux.sh, and Electron from the pinned package-lock.json.
#
# Usage: orcel-stage.sh OUT [electron|gtk3|appkit|wkwebview ...]
# With no harness named, stages the ones this OS runs: gtk3 and electron on
# Linux; appkit, wkwebview and electron on macOS. The Tauri host is not built
# (ORCEL.md says why).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -lt 1 ]]; then
    echo "usage: $0 OUT [electron|gtk3|appkit|wkwebview ...]" >&2
    exit 2
fi
mkdir -p "$1"
out="$(cd "$1" && pwd)"
shift
case "$out/" in
    "$here"/*) echo "OUT must be outside $here" >&2; exit 2 ;;
esac

if [[ $# -gt 0 ]]; then
    targets=("$@")
else
    case "$(uname -s)" in
        Darwin) targets=(appkit wkwebview electron) ;;
        Linux) targets=(gtk3 electron) ;;
        *) echo "no harness for $(uname -s)" >&2; exit 2 ;;
    esac
fi

stage_electron() {
    local source="$here/apps/cross-platform/electron" dir="$out/electron"
    rm -rf "$dir"
    mkdir -p "$dir/web"
    cp "$source/main.js" "$source/preload.js" "$source/package.json" "$source/package-lock.json" "$dir/"
    cp "$here/shared/web/index.html" "$dir/web/index.html"
    # Lifecycle scripts stay off; only Electron's own installer runs. It
    # fetches the release the lockfile pins and checks it against the
    # checksums that ship inside the electron package.
    (cd "$dir" && npm ci --ignore-scripts --no-audit --no-fund --loglevel=error && node node_modules/electron/install.js)
    local binary
    if [[ "$(uname -s)" == Darwin ]]; then
        binary="$dir/node_modules/electron/dist/Electron.app/Contents/MacOS/Electron"
    else
        binary="$dir/node_modules/electron/dist/electron"
    fi
    test -x "$binary" || { echo "Electron runtime missing at $binary" >&2; exit 1; }
    printf '%s\n' "$binary" > "$dir/orcel-binary"
    echo "==> electron $(cat "$dir/node_modules/electron/dist/version") -> $binary"
}

stage_gtk3() {
    local dir="$out/gtk3"
    rm -rf "$dir"
    mkdir -p "$dir"
    cp "$here/apps/linux/gtk3/main.py" "$dir/main.py"
    python3 -c "import gi; gi.require_version('Gtk', '3.0'); from gi.repository import Gtk" \
        || { echo "PyGObject with GTK 3 is required for the gtk3 harness" >&2; exit 1; }
    echo "==> gtk3 -> $dir/main.py"
}

# Same compiler invocation and Info.plist as build/macos.sh build_app.
stage_swift() {
    local name="$1" source="$2" frameworks="$3" stage="$4"
    local bundle="$out/$stage/$name.app"
    rm -rf "$out/$stage"
    mkdir -p "$bundle/Contents/MacOS"
    # shellcheck disable=SC2086  # $frameworks is a word list on purpose
    xcrun swiftc -O -target "$(uname -m)-apple-macos13.0" $frameworks -parse-as-library \
        -o "$bundle/Contents/MacOS/$name" "$source"/*.swift
    cat > "$bundle/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>$name</string>
    <key>CFBundleIdentifier</key><string>com.trycua.harness.${stage#harness-}</string>
    <key>CFBundleName</key><string>$name</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>CFBundleShortVersionString</key><string>1.0.0</string>
    <key>CFBundleVersion</key><string>1</string>
    <key>LSMinimumSystemVersion</key><string>13.0</string>
    <key>NSHighResolutionCapable</key><true/>
    <key>NSPrincipalClass</key><string>NSApplication</string>
</dict>
</plist>
EOF
    echo "==> $name -> $bundle"
}

for target in "${targets[@]}"; do
    case "$target" in
        electron) stage_electron ;;
        gtk3) stage_gtk3 ;;
        appkit) stage_swift CuaTestHarness.AppKit "$here/apps/macos/appkit" "" harness-appkit ;;
        wkwebview)
            stage_swift CuaTestHarness.WKWebView "$here/apps/macos/wkwebview" "-framework WebKit" harness-wkwebview
            mkdir -p "$out/harness-wkwebview/CuaTestHarness.WKWebView.app/Contents/Resources/web"
            cp "$here/shared/web/index.html" "$out/harness-wkwebview/CuaTestHarness.WKWebView.app/Contents/Resources/web/index.html"
            ;;
        *) echo "unknown harness: $target" >&2; exit 2 ;;
    esac
done
