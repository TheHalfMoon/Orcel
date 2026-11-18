// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// Cross-platform adapter boundary, after the donor's provider split in
// microsoft/Hybrid-Computer-Use computer-use/internal/core/provider_types.go
// and computer-use/internal/provider/runtime_backend_{windows,darwin,linux}.go
// at 00eaeebe8ac0d275e46f875bdb5347e5f326faa1 (MIT).
// Orcel changes: the donor runs a separate native provider per platform
// (.NET/FlaUI on Windows, Swift on macOS, Python AT-SPI on Linux) behind a
// sidecar protocol. Orcel keeps its own native readers (the Go UIA reader in
// this host on Windows; orcel-native-host on macOS and Linux) and ports only
// the interface: a TreeSource reads one bounded tree of one bound window and
// reports its layout. No donor sidecar, daemon or MCP server is ported.

package semantic

// Verification is the qualification state of a platform adapter.
type Verification string

const (
	// Verified: built and exercised against a real window in CI or on a
	// qualified host.
	Verified Verification = "verified"
	// Unverified: compiles, but has not been run against a real window.
	Unverified Verification = "UNVERIFIED"
)

// TreeSource is one platform's native reader.
type TreeSource interface {
	// ReadTree reads the bounded tree of the bound window.
	ReadTree(binding Binding, maxNodes, maxDepth int) ([]Node, error)
	// ReadLayout reads the bound window's current layout.
	ReadLayout(binding Binding) (Layout, error)
}

// PlatformAdapter describes the adapter compiled for this platform.
type PlatformAdapter struct {
	Platform     string
	Backend      string
	Verification Verification
	Note         string
}

// CurrentPlatform reports the adapter compiled for this platform.
func CurrentPlatform() PlatformAdapter { return currentPlatform }
