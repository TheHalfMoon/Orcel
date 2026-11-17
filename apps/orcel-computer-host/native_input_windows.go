//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// COPY_ADAPT input subset from opensymph/open-computer-use at
// 5b433b98019c18201a15d11e8c3cb0010879a3d8 (MIT):
//   apps/OpenComputerUseWindows/native_win32.go
//     blob e94ce44c7e76ce45035dfe584c883cab16babdf0
//   apps/OpenComputerUseWindows/desktop_windows.go
//     blob 59466d669c1bfea13a15dfc371d9eceb471f21bd
//
// Deliberately excluded: whole-desktop capture, recording/ffmpeg, detached
// process lifecycle, PostMessage/background mutation, donor authority flags,
// public command/MCP surfaces, and launch/elevation helpers.

package main

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	inputMouse    = 0
	inputKeyboard = 1

	mouseeventfMove        = 0x0001
	mouseeventfLeftDown    = 0x0002
	mouseeventfLeftUp      = 0x0004
	mouseeventfRightDown   = 0x0008
	mouseeventfRightUp     = 0x0010
	mouseeventfMiddleDown  = 0x0020
	mouseeventfMiddleUp    = 0x0040
	mouseeventfWheel       = 0x0800
	mouseeventfHWheel      = 0x1000
	mouseeventfVirtualDesk = 0x4000
	mouseeventfAbsolute    = 0x8000
	keyeventfKeyUp         = 0x0002
	keyeventfUnicode       = 0x0004
	keyeventfScancode      = 0x0008
	mapvkVKToVSC           = 0

	smXVirtualScreen  = 76
	smYVirtualScreen  = 77
	smCXVirtualScreen = 78
	smCYVirtualScreen = 79
	wheelDeltaUnit    = 120
)

var (
	procSendInput           = user32.NewProc("SendInput")
	procMapVirtualKey       = user32.NewProc("MapVirtualKeyW")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procGetCursorPos        = user32.NewProc("GetCursorPos")
	procGetLastInputInfo    = user32.NewProc("GetLastInputInfo")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procGetForegroundWindow = user32.NewProc("GetForegroundWindow")
)

var bannedModifierNames = []string{"super", "win", "cmd", "meta", "command", "os", "windows"}

type tagINPUT struct {
	inputType uint32
	mi        mouseInput
}

type mouseInput struct {
	dx, dy      int32
	mouseData   uint32
	dwFlags     uint32
	time        uint32
	padding     uint32
	dwExtraInfo uintptr
}

type lastInputInfo struct {
	cbSize uint32
	dwTime uint32
}

func sendInputs(inputs []tagINPUT) error {
	if len(inputs) == 0 {
		return nil
	}
	injected, _, _ := procSendInput.Call(
		uintptr(len(inputs)),
		uintptr(unsafe.Pointer(&inputs[0])),
		unsafe.Sizeof(tagINPUT{}),
	)
	if injected != uintptr(len(inputs)) {
		return fmt.Errorf("SendInput injected %d of %d events", injected, len(inputs))
	}
	return nil
}

func mouseEvent(flags uint32, dx, dy int32, data uint32) tagINPUT {
	return tagINPUT{
		inputType: inputMouse,
		mi: mouseInput{
			dx:        dx,
			dy:        dy,
			mouseData: data,
			dwFlags:   flags,
		},
	}
}

// KEYBDINPUT overlays the INPUT union's first bytes. This matches the pinned
// donor layout and is covered by native Windows qualification.
func keyEvent(vk, scan uint16, flags uint32) tagINPUT {
	return tagINPUT{
		inputType: inputKeyboard,
		mi: mouseInput{
			dx: int32(vk) | int32(scan)<<16,
			dy: int32(flags),
		},
	}
}

func mapVirtualKey(vk uint16) uint16 {
	ret, _, _ := procMapVirtualKey.Call(uintptr(vk), mapvkVKToVSC)
	return uint16(ret)
}

func systemMetrics(index int) int {
	ret, _, _ := procGetSystemMetrics.Call(uintptr(index))
	return int(ret)
}

func normalizeVirtualScreen(value, origin, extent int) int32 {
	if extent <= 0 {
		return 0
	}
	return int32((float64(value-origin) * 65535.0) / float64(extent))
}

func virtualScreenNormalizedPoint(x, y int) (int32, int32) {
	return normalizeVirtualScreen(x, systemMetrics(smXVirtualScreen), systemMetrics(smCXVirtualScreen)),
		normalizeVirtualScreen(y, systemMetrics(smYVirtualScreen), systemMetrics(smCYVirtualScreen))
}

func currentLastInputTick() (uint32, error) {
	info := lastInputInfo{cbSize: uint32(unsafe.Sizeof(lastInputInfo{}))}
	ok, _, _ := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&info)))
	if ok == 0 {
		return 0, errors.New("GetLastInputInfo failed")
	}
	return info.dwTime, nil
}

func requireExpectedLastInput(req hostRequest) error {
	if req.ExpectedLastInputTick == nil {
		return errors.New("fresh human-input tick binding is required")
	}
	current, err := currentLastInputTick()
	if err != nil {
		return err
	}
	if current != *req.ExpectedLastInputTick {
		return errors.New("human input changed after approval; input dispatch cancelled")
	}
	return nil
}

func nativeCursorPosition(req hostRequest) hostResponse {
	if err := requireInteractiveStation(); err != nil {
		return failure(req.ID, "provider_unavailable", err.Error())
	}
	var point struct{ X, Y int32 }
	ok, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&point)))
	if ok == 0 {
		return failure(req.ID, "provider_unavailable", "GetCursorPos failed")
	}
	tick, err := currentLastInputTick()
	if err != nil {
		return failure(req.ID, "provider_unavailable", err.Error())
	}
	resp := success(req.ID)
	resp.Cursor = &cursorFact{
		X:            int(point.X),
		Y:            int(point.Y),
		ScreenWidth:  systemMetrics(smCXVirtualScreen),
		ScreenHeight: systemMetrics(smCYVirtualScreen),
		LastInputTick: tick,
	}
	return resp
}

func windowRelativePoint(rect windowRect, x, y int) (int, int, error) {
	width := int(rect.Right - rect.Left)
	height := int(rect.Bottom - rect.Top)
	if x < 0 || y < 0 || x >= width || y >= height {
		return 0, 0, errors.New("window-relative coordinate is outside the exact target window")
	}
	return int(rect.Left) + x, int(rect.Top) + y, nil
}

func focusBoundWindow(hwnd windows.HWND) error {
	current, _, _ := procGetForegroundWindow.Call()
	if windows.HWND(current) == hwnd {
		return nil
	}
	ok, _, _ := procSetForegroundWindow.Call(uintptr(hwnd))
	if ok == 0 {
		return errors.New("target window could not be brought to the foreground")
	}
	for attempt := 0; attempt < 10; attempt++ {
		sleepMs(20)
		current, _, _ = procGetForegroundWindow.Call()
		if windows.HWND(current) == hwnd {
			return nil
		}
	}
	return errors.New("foreground focus did not bind to the exact target window")
}

func realMouseMove(x, y int) error {
	nx, ny := virtualScreenNormalizedPoint(x, y)
	if err := sendInputs([]tagINPUT{
		mouseEvent(mouseeventfMove|mouseeventfAbsolute|mouseeventfVirtualDesk, nx, ny, 0),
	}); err != nil {
		return err
	}
	sleepMs(20)
	return nil
}

func mouseDownUpFlags(button string) (uint32, uint32, error) {
	switch button {
	case "left":
		return mouseeventfLeftDown, mouseeventfLeftUp, nil
	case "right":
		return mouseeventfRightDown, mouseeventfRightUp, nil
	case "middle":
		return mouseeventfMiddleDown, mouseeventfMiddleUp, nil
	default:
		return 0, 0, fmt.Errorf("unsupported mouse button: %s", button)
	}
}

func realMouseClick(button string, count int) error {
	down, up, err := mouseDownUpFlags(button)
	if err != nil {
		return err
	}
	if count != 1 && count != 2 {
		return errors.New("click count must be 1 or 2")
	}
	for i := 0; i < count; i++ {
		if err := sendInputs([]tagINPUT{mouseEvent(down, 0, 0, 0)}); err != nil {
			return err
		}
		sleepMs(35)
		if err := sendInputs([]tagINPUT{mouseEvent(up, 0, 0, 0)}); err != nil {
			return err
		}
		sleepMs(60)
	}
	return nil
}

func realMouseDragButton(fromX, fromY, toX, toY int, button string) error {
	if err := realMouseMove(fromX, fromY); err != nil {
		return err
	}
	down, up, err := mouseDownUpFlags(button)
	if err != nil {
		return err
	}
	if err := sendInputs([]tagINPUT{mouseEvent(down, 0, 0, 0)}); err != nil {
		return err
	}
	sleepMs(30)
	const steps = 12
	for i := 1; i <= steps; i++ {
		x := fromX + int(math.Round(float64(toX-fromX)*(float64(i)/float64(steps))))
		y := fromY + int(math.Round(float64(toY-fromY)*(float64(i)/float64(steps))))
		nx, ny := virtualScreenNormalizedPoint(x, y)
		if err := sendInputs([]tagINPUT{
			mouseEvent(mouseeventfMove|mouseeventfAbsolute|mouseeventfVirtualDesk, nx, ny, 0),
		}); err != nil {
			return err
		}
		sleepMs(20)
	}
	return sendInputs([]tagINPUT{mouseEvent(up, 0, 0, 0)})
}

func realWheel(dy, dx int) error {
	if dy != 0 {
		if err := sendInputs([]tagINPUT{
			mouseEvent(mouseeventfWheel, 0, 0, uint32(int32(dy))),
		}); err != nil {
			return err
		}
	}
	if dx != 0 {
		if err := sendInputs([]tagINPUT{
			mouseEvent(mouseeventfHWheel, 0, 0, uint32(int32(dx))),
		}); err != nil {
			return err
		}
	}
	return nil
}

func utf16Units(text string) []uint16 {
	return utf16.Encode([]rune(text))
}

func realTypeText(text string) error {
	for _, unit := range utf16Units(text) {
		if err := sendInputs([]tagINPUT{keyEvent(0, unit, keyeventfUnicode)}); err != nil {
			return err
		}
		sleepMs(5)
		if err := sendInputs([]tagINPUT{keyEvent(0, unit, keyeventfUnicode|keyeventfKeyUp)}); err != nil {
			return err
		}
		sleepMs(5)
	}
	return nil
}

func splitChord(key string) []string {
	raw := strings.Split(key, "+")
	parts := make([]string, 0, len(raw))
	for _, part := range raw {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	return parts
}

func decimalDigits(value string) int {
	if value == "" {
		return -1
	}
	n := 0
	for _, char := range value {
		if char < '0' || char > '9' {
			return -1
		}
		n = n*10 + int(char-'0')
	}
	return n
}

func splitKeypadName(name string) (string, int, bool) {
	for _, prefix := range []string{"kp_", "numpad_"} {
		if strings.HasPrefix(name, prefix) {
			rest := name[len(prefix):]
			n := decimalDigits(rest)
			return prefix, n, n >= 0
		}
	}
	return "", 0, false
}

func virtualKeyForName(key string) (uint16, error) {
	normalized := strings.ToLower(strings.TrimSpace(key))
	table := map[string]uint16{
		"return": 0x0D, "enter": 0x0D, "tab": 0x09, "escape": 0x1B, "esc": 0x1B,
		"backspace": 0x08, "back_space": 0x08, "delete": 0x2E, "space": 0x20,
		"left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
		"home": 0x24, "end": 0x23, "page_up": 0x21, "prior": 0x21,
		"page_down": 0x22, "next": 0x22,
		"period": 0xBE, "greater": 0xBE, "less": 0xBC, "comma": 0xBC,
		"slash": 0xBF, "question": 0xBF, "semicolon": 0xBA, "apostrophe": 0xDE,
		"bracketleft": 0xDB, "bracketright": 0xDD, "backslash": 0xDC, "grave": 0xC0,
		"minus": 0xBD, "equal": 0xBB,
		"numpad_enter": 0x0D, "numpad_add": 0x6B, "numpad_subtract": 0x6D,
		"numpad_multiply": 0x6A, "numpad_divide": 0x6F, "numpad_decimal": 0x6E,
	}
	if vk, ok := table[normalized]; ok {
		return vk, nil
	}
	if len(normalized) >= 2 && normalized[0] == 'f' {
		if n := decimalDigits(normalized[1:]); n >= 1 && n <= 12 {
			return uint16(0x70 + n - 1), nil
		}
	}
	if _, digit, ok := splitKeypadName(normalized); ok && digit <= 9 {
		return uint16(0x60 + digit), nil
	}
	if len(normalized) == 1 {
		code := strings.ToUpper(normalized)[0]
		if (code >= '0' && code <= '9') || (code >= 'A' && code <= 'Z') {
			return uint16(code), nil
		}
	}
	return 0, fmt.Errorf("unsupported key: %s", key)
}

func modifierVirtualKeyForName(name string) (uint16, error) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for _, banned := range bannedModifierNames {
		if normalized == banned {
			return 0, fmt.Errorf("Windows/Meta modifier %q is denied by Orcel Full User policy", name)
		}
	}
	switch normalized {
	case "ctrl", "control", "control_l", "control_r", "ctrl_l", "ctrl_r":
		return 0x11, nil
	case "shift", "shift_l", "shift_r":
		return 0x10, nil
	case "alt", "alt_l", "alt_r":
		return 0x12, nil
	default:
		return 0, fmt.Errorf("unsupported modifier: %s", name)
	}
}

func realKeyForName(key string) ([]uint16, uint16, error) {
	parts := splitChord(key)
	if len(parts) == 0 {
		return nil, 0, errors.New("key is required")
	}
	main := parts[len(parts)-1]
	modifiers := make([]uint16, 0, len(parts)-1)
	for i := 0; i < len(parts)-1; i++ {
		vk, err := modifierVirtualKeyForName(parts[i])
		if err != nil {
			return nil, 0, err
		}
		modifiers = append(modifiers, vk)
	}
	vk, err := virtualKeyForName(main)
	if err != nil {
		return nil, 0, err
	}
	return modifiers, vk, nil
}

func realKeyChord(modifierVks []uint16, vk uint16) error {
	chord := make([]struct{ vk, scan uint16 }, 0, len(modifierVks)+1)
	downs := make([]tagINPUT, 0, len(modifierVks)+1)
	for _, modifier := range modifierVks {
		scan := mapVirtualKey(modifier)
		chord = append(chord, struct{ vk, scan uint16 }{modifier, scan})
		downs = append(downs, keyEvent(modifier, scan, keyeventfScancode))
	}
	scan := mapVirtualKey(vk)
	chord = append(chord, struct{ vk, scan uint16 }{vk, scan})
	downs = append(downs, keyEvent(vk, scan, keyeventfScancode))
	if err := sendInputs(downs); err != nil {
		return err
	}
	sleepMs(40)
	for i := len(chord) - 1; i >= 0; i-- {
		if err := sendInputs([]tagINPUT{
			keyEvent(chord[i].vk, chord[i].scan, keyeventfScancode|keyeventfKeyUp),
		}); err != nil {
			return err
		}
	}
	return nil
}

func completedAction(req hostRequest) hostResponse {
	resp := success(req.ID)
	resp.Action = &actionFact{State: "completed", Action: req.Op}
	return resp
}

func nativeRawInput(req hostRequest) hostResponse {
	_, rect, err := validateBoundWindow(req)
	if err != nil {
		return failure(req.ID, "target_stale", err.Error())
	}
	// W2-01: pointer input planned against another window layout is refused
	// before the window is focused and before any input is sent.
	if err := checkLayoutFrame(req); err != nil {
		return failure(req.ID, "target_stale", err.Error())
	}
	if err := requireExpectedLastInput(req); err != nil {
		return failure(req.ID, "cancelled", err.Error())
	}
	hwnd := windows.HWND(uintptr(req.HWND))

	point := func(x, y *int) (int, int, error) {
		if x == nil || y == nil {
			return 0, 0, errors.New("window-relative coordinate is missing")
		}
		return windowRelativePoint(rect, *x, *y)
	}

	switch req.Op {
	case "input_move":
		x, y, err := point(req.X, req.Y)
		if err != nil {
			return failure(req.ID, "invalid_request", err.Error())
		}
		if err := realMouseMove(x, y); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
	case "input_click":
		x, y, err := point(req.X, req.Y)
		if err != nil {
			return failure(req.ID, "invalid_request", err.Error())
		}
		if err := focusBoundWindow(hwnd); err != nil {
			return failure(req.ID, "cancelled", err.Error())
		}
		if err := realMouseMove(x, y); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
		if err := realMouseClick(req.Button, req.ClickCount); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
	case "input_drag":
		x, y, err := point(req.X, req.Y)
		if err != nil {
			return failure(req.ID, "invalid_request", err.Error())
		}
		toX, toY, err := point(req.ToX, req.ToY)
		if err != nil {
			return failure(req.ID, "invalid_request", err.Error())
		}
		if err := focusBoundWindow(hwnd); err != nil {
			return failure(req.ID, "cancelled", err.Error())
		}
		if err := realMouseDragButton(x, y, toX, toY, "left"); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
	case "input_scroll":
		x, y, err := point(req.X, req.Y)
		if err != nil {
			return failure(req.ID, "invalid_request", err.Error())
		}
		if err := focusBoundWindow(hwnd); err != nil {
			return failure(req.ID, "cancelled", err.Error())
		}
		if err := realMouseMove(x, y); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
		if err := realWheel(req.ScrollY*wheelDeltaUnit, req.ScrollX*wheelDeltaUnit); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
	case "input_type_text":
		if err := focusBoundWindow(hwnd); err != nil {
			return failure(req.ID, "cancelled", err.Error())
		}
		if err := realTypeText(req.Text); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
	case "input_key", "input_hotkey":
		if err := focusBoundWindow(hwnd); err != nil {
			return failure(req.ID, "cancelled", err.Error())
		}
		modifiers, vk, err := realKeyForName(req.Key)
		if err != nil {
			return failure(req.ID, "invalid_request", err.Error())
		}
		if req.Op == "input_key" && len(modifiers) != 0 {
			return failure(req.ID, "invalid_request", "input_key accepts one key; use input_hotkey for chords")
		}
		if req.Op == "input_hotkey" && len(modifiers) == 0 {
			return failure(req.ID, "invalid_request", "input_hotkey requires at least one modifier")
		}
		if err := realKeyChord(modifiers, vk); err != nil {
			return failure(req.ID, "outcome_unknown", err.Error())
		}
	default:
		return failure(req.ID, "capability_denied", "raw input operation is not mapped")
	}
	return completedAction(req)
}
