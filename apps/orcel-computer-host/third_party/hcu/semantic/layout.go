// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// PORT (C# to Go) from microsoft/Hybrid-Computer-Use at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1 (MIT):
//   computer-use/native/windows/ComputerUse.Windows.Runtime/
//     WindowsDesktopLayoutDiagnostics.cs,
//     blob e6e158f1dd6116f0964e5167a5515594381dad45 (the layout frame id: a
//     SHA-256 over the desktop bounds and window geometry, and the
//     requested/current difference);
//   computer-use/native/windows/ComputerUse.Windows.Runtime/DesktopProvider.cs,
//     blob c9d9f4cc97450cef8e6a46f5ccfe1b55309ed909 (coordinate input is
//     refused with stale_layout when the requested frame is not current).
// Orcel changes: the frame covers the bound target window only (its
// rectangle, client rectangle and DPI) and the virtual desktop bounds, not
// every top-level window or the foreground handle, because Orcel input is
// window-relative and the host itself brings the bound window forward
// before input. The point check keeps a window-relative point inside the
// window rectangle and the window inside the virtual desktop.

package semantic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Rect is a screen rectangle in physical pixels.
type Rect struct {
	Left   int `json:"left"`
	Top    int `json:"top"`
	Right  int `json:"right"`
	Bottom int `json:"bottom"`
}

func (r Rect) empty() bool { return r.Right <= r.Left || r.Bottom <= r.Top }

func (r Rect) intersects(other Rect) bool {
	return r.Left < other.Right && other.Left < r.Right && r.Top < other.Bottom && other.Top < r.Bottom
}

// Layout is the geometry GUI coordinates were planned against.
type Layout struct {
	Desktop Rect   `json:"desktop"`
	Window  Rect   `json:"window"`
	Client  Rect   `json:"client"`
	DPI     int    `json:"dpi"`
	Handle  uint64 `json:"handle"`
}

// ErrStaleLayout reports that the layout changed since the frame was issued.
var ErrStaleLayout = errors.New("target_stale: the window layout changed since the coordinate frame was observed (stale_layout); observe again")

// FrameID is the donor's layout frame id: a lower-case hex SHA-256 over the
// desktop bounds and the window geometry.
func (layout Layout) FrameID() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%d,%d,%d,%d;", layout.Desktop.Left, layout.Desktop.Top,
		layout.Desktop.Right-layout.Desktop.Left, layout.Desktop.Bottom-layout.Desktop.Top)
	fmt.Fprintf(&builder, "window:%d:%d,%d,%d,%d;", layout.Handle, layout.Window.Left, layout.Window.Top,
		layout.Window.Right-layout.Window.Left, layout.Window.Bottom-layout.Window.Top)
	fmt.Fprintf(&builder, "client:%d,%d,%d,%d;dpi:%d;", layout.Client.Left, layout.Client.Top,
		layout.Client.Right-layout.Client.Left, layout.Client.Bottom-layout.Client.Top, layout.DPI)
	sum := sha256.Sum256([]byte(builder.String()))
	return "l1:" + hex.EncodeToString(sum[:])
}

// Validate refuses a layout that cannot carry coordinates: an empty window,
// or a window wholly outside the virtual desktop.
func (layout Layout) Validate() error {
	if layout.Desktop.empty() {
		return errors.New("the virtual desktop bounds are empty")
	}
	if layout.Window.empty() {
		return errors.New("the window rectangle is empty (minimized or hidden)")
	}
	if !layout.Window.intersects(layout.Desktop) {
		return errors.New("the window lies outside the virtual desktop")
	}
	return nil
}

// CheckFrame compares a requested frame id with the current layout, as the
// donor does before coordinate input. An empty request is not checked (the
// caller did not plan against a frame).
func CheckFrame(requested string, current Layout) error {
	if strings.TrimSpace(requested) == "" {
		return nil
	}
	if err := current.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrStaleLayout, err)
	}
	if requested != current.FrameID() {
		return ErrStaleLayout
	}
	return nil
}

// CheckPoint keeps a window-relative point inside the window rectangle and
// the resulting screen point inside the virtual desktop.
func CheckPoint(layout Layout, x, y int) (int, int, error) {
	if err := layout.Validate(); err != nil {
		return 0, 0, err
	}
	width := layout.Window.Right - layout.Window.Left
	height := layout.Window.Bottom - layout.Window.Top
	if x < 0 || y < 0 || x >= width || y >= height {
		return 0, 0, errors.New("window-relative point is outside the bound window")
	}
	screenX, screenY := layout.Window.Left+x, layout.Window.Top+y
	if screenX < layout.Desktop.Left || screenX >= layout.Desktop.Right ||
		screenY < layout.Desktop.Top || screenY >= layout.Desktop.Bottom {
		return 0, 0, errors.New("window-relative point is outside the virtual desktop")
	}
	return screenX, screenY, nil
}

// LayoutDifference names what changed between two layouts, for diagnostics.
func LayoutDifference(requested, current Layout) []string {
	changes := []string{}
	if requested.Desktop != current.Desktop {
		changes = append(changes, "desktop_bounds")
	}
	if requested.Handle != current.Handle {
		changes = append(changes, "window")
	}
	if requested.Window != current.Window {
		changes = append(changes, "window_rect")
	}
	if requested.Client != current.Client {
		changes = append(changes, "client_rect")
	}
	if requested.DPI != current.DPI {
		changes = append(changes, "dpi")
	}
	return changes
}
