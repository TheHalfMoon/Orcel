//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT

package semantic

// On Windows the TreeSource is the Orcel computer host's Go UIA reader
// (native_uia_windows.go), qualified by the SG-000094 native tests and the
// W2-01 ref-tree test against a disposable window.
var currentPlatform = PlatformAdapter{
	Platform:     "windows",
	Backend:      "uia",
	Verification: Verified,
	Note:         "orcel-computer-host UIA reader",
}
