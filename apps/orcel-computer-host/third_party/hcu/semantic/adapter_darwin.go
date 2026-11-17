//go:build darwin

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT

package semantic

// UNVERIFIED: the package compiles and its unit tests run on macOS, but no
// macOS TreeSource is wired. Orcel's macOS reader is orcel-native-host (AX,
// Rust); the donor's Swift provider is not ported.
var currentPlatform = PlatformAdapter{
	Platform:     "macos",
	Backend:      "ax",
	Verification: Unverified,
	Note:         "UNVERIFIED: no macOS TreeSource; orcel-native-host serves AX observation",
}
