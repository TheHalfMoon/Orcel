//go:build !windows && !darwin

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT

package semantic

// UNVERIFIED: the package compiles and its unit tests run on Linux, but no
// Linux TreeSource is wired. Orcel's Linux reader is orcel-native-host
// (AT-SPI and X11, Rust); the donor's Python AT-SPI provider is not ported.
var currentPlatform = PlatformAdapter{
	Platform:     "linux",
	Backend:      "atspi",
	Verification: Unverified,
	Note:         "UNVERIFIED: no Linux TreeSource; orcel-native-host serves AT-SPI observation",
}
