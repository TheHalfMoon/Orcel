//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// PORT of the observation-only dispatch boundary from
// opensymph/open-computer-use/apps/OpenComputerUseWindows/native_backend.go
// blob 8af3b00559e5ec1f5b1e900743bda24ea75932b6 at commit
// 5b433b98019c18201a15d11e8c3cb0010879a3d8 (MIT).
// Launch, activation, action dispatch, and app-state auto-launch are absent.

package main

import (
	"encoding/base64"
	"strings"

	"golang.org/x/sys/windows"
)

func errorResponse(id uint64, err error) hostResponse {
	if err == nil {
		return failure(id, "provider_unavailable", "native host operation failed")
	}
	message := err.Error()
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "stale") || strings.Contains(lower, "gone"):
		return failure(id, "target_stale", message)
	case strings.Contains(lower, "excluded") ||
		strings.Contains(lower, "outside") ||
		strings.Contains(lower, "winsta0") ||
		strings.Contains(lower, "interactive"):
		return failure(id, "capability_denied", message)
	default:
		return failure(id, "provider_unavailable", message)
	}
}

func nativeListWindows(req hostRequest) hostResponse {
	windowsFound, err := enumerateWindows()
	if err != nil {
		return errorResponse(req.ID, err)
	}
	resp := success(req.ID)
	resp.Windows = windowsFound
	return resp
}

func nativeObserveWindow(req hostRequest) hostResponse {
	if _, _, err := validateBoundWindow(req); err != nil {
		return errorResponse(req.ID, err)
	}
	elements, err := observeWindowUIA(req.HWND, req.MaxNodes, req.MaxDepth, req.ElementRuntimeID)
	if err != nil {
		return errorResponse(req.ID, err)
	}
	resp := success(req.ID)
	resp.Elements = elements
	return resp
}

func nativeCaptureWindow(req hostRequest) hostResponse {
	hwnd := windows.HWND(uintptr(req.HWND))
	if _, _, err := validateBoundWindow(req); err != nil {
		return errorResponse(req.ID, err)
	}
	pixels, width, height, err := captureExactWindow(hwnd)
	if err != nil {
		return errorResponse(req.ID, err)
	}
	if len(pixels) > maxCaptureBytes {
		return failure(req.ID, "output_limit", "capture exceeds Orcel pixel bound")
	}
	resp := success(req.ID)
	resp.Capture = &captureFact{
		Width: uint32(width),
		Height: uint32(height),
		PixelFormat: "rgba8",
		PixelsB64: base64.StdEncoding.EncodeToString(pixels),
	}
	return resp
}
