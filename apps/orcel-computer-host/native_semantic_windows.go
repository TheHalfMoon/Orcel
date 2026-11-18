//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// W2-01: the native reads behind the HCU-derived semantic checks. Both are
// read-only: the layout of the bound window, and the identity of the live
// target element compared with the observed one before a semantic action.

package main

import (
	"errors"
	"unsafe"

	"github.com/TheHalfMoon/Orcel/apps/orcel-computer-host/third_party/hcu/semantic"
	"golang.org/x/sys/windows"
)

var (
	procGetClientRect   = user32.NewProc("GetClientRect")
	procClientToScreen  = user32.NewProc("ClientToScreen")
	procGetDpiForWindow = user32.NewProc("GetDpiForWindow")
)

type nativePoint struct{ X, Y int32 }

// signedMetric reads a GetSystemMetrics value as the signed int it is: the
// virtual desktop origin is negative when a monitor sits left of or above
// the primary one.
func signedMetric(index int) int {
	value, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(int32(value))
}

// currentLayout reads the bound window's layout: its rectangle, its client
// rectangle in screen coordinates, its DPI and the virtual desktop bounds.
func currentLayout(hwnd windows.HWND) (semantic.Layout, error) {
	rect, ok := getWindowRect(hwnd)
	if !ok {
		return semantic.Layout{}, errors.New("window geometry is unreadable")
	}
	var client windowRect
	if okCall, _, _ := procGetClientRect.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&client))); okCall == 0 {
		return semantic.Layout{}, errors.New("client geometry is unreadable")
	}
	origin := nativePoint{X: client.Left, Y: client.Top}
	if okCall, _, _ := procClientToScreen.Call(uintptr(hwnd), uintptr(unsafe.Pointer(&origin))); okCall == 0 {
		return semantic.Layout{}, errors.New("client origin is unreadable")
	}
	dpi := 0
	if procGetDpiForWindow.Find() == nil {
		value, _, _ := procGetDpiForWindow.Call(uintptr(hwnd))
		dpi = int(value)
	}
	left, top := signedMetric(smXVirtualScreen), signedMetric(smYVirtualScreen)
	return semantic.Layout{
		Desktop: semantic.Rect{Left: left, Top: top, Right: left + signedMetric(smCXVirtualScreen), Bottom: top + signedMetric(smCYVirtualScreen)},
		Window:  semantic.Rect{Left: int(rect.Left), Top: int(rect.Top), Right: int(rect.Right), Bottom: int(rect.Bottom)},
		Client: semantic.Rect{
			Left: int(origin.X), Top: int(origin.Y),
			Right: int(origin.X) + int(client.Right-client.Left), Bottom: int(origin.Y) + int(client.Bottom-client.Top),
		},
		DPI:    dpi,
		Handle: uint64(hwnd),
	}, nil
}

// checkLayoutFrame refuses pointer input planned against another layout.
// It runs before the window is focused and before any input is sent.
func checkLayoutFrame(req hostRequest) error {
	if req.LayoutFrameID == "" {
		return nil
	}
	layout, err := currentLayout(windows.HWND(uintptr(req.HWND)))
	if err != nil {
		return semantic.ErrStaleLayout
	}
	return semantic.CheckFrame(req.LayoutFrameID, layout)
}

// checkLiveTarget compares the observed identity with the live element
// found by its exact runtime id, before any pattern is invoked. The name is
// bounded as observation bounds it.
func checkLiveTarget(req hostRequest, element uiaElement) error {
	if req.ExpectedElement == nil {
		return nil
	}
	limit := 1024
	return semantic.CheckLive(
		*req.ExpectedElement,
		shortControlType(element.controlTypeName()),
		element.automationId(),
		limitTextPS(element.name(), &limit),
	)
}
