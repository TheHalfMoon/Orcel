//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// COPY_ADAPT semantic-action subset from opensymph/open-computer-use
// apps/OpenComputerUseWindows/native_actions.go at
// 5b433b98019c18201a15d11e8c3cb0010879a3d8,
// blob 25c2482d9d0e6b82c890ecf07956643b88bbf97f (MIT).
//
// Orcel keeps only typed UIA pattern execution on an exact SG-000094 window
// binding. There is no donor authority flag, app-name fallback, coordinate
// fallback, PostMessage fallback, foreground fallback, or public tool surface.

package main

import (
	"errors"
	"fmt"
	"math"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	invokeSlotInvoke    = 3
	valueSlotSetValue   = 3
	selectSlotSelect    = 3
	toggleSlotToggle    = 3
	scrollSlotScroll    = 3
)

// Semantic lookup must bound both recursion and raw sibling enumeration.
// Unlike the read-only tree helper, it cannot precollect unbounded children
// before applying the node ceiling to an adversarial accessibility provider.
// SG-000128: callers search to maxRootSearchDepth with maxRootSearchNodes, so
// an element orceld issued from a scoped read (below a web Document, past the
// tree's depth cap) is found; nothing found here widens what is returned.
func findElementByRuntimeID(root uiaElement, walker unsafe.Pointer, key string, depth int, remaining *int) (uiaElement, bool) {
	if depth > maxRootSearchDepth || *remaining <= 0 || !root.valid() {
		return uiaElement{}, false
	}
	*remaining = *remaining - 1
	if root.runtimeIdKey() == key {
		_, _, _ = vtableCall(root.ptr, 1) // AddRef for the returned owner.
		return root, true
	}
	if depth == maxRootSearchDepth || *remaining == 0 {
		return uiaElement{}, false
	}

	var current unsafe.Pointer
	if hr, _, _ := vtableCall(walker, walkerSlotGetFirstChildElement,
		uintptr(root.ptr), uintptr(unsafe.Pointer(&current))); int32(hr) < 0 {
		if current != nil {
			oleRelease(current)
		}
		return uiaElement{}, false
	}
	for current != nil && *remaining > 0 {
		var next unsafe.Pointer
		hr, _, _ := vtableCall(walker, walkerSlotGetNextSiblingElement,
			uintptr(current), uintptr(unsafe.Pointer(&next)))
		var isContent int32
		contentHR, _, _ := vtableCall(current, elemSlotCurrentIsContentElement,
			uintptr(unsafe.Pointer(&isContent)))
		var found uiaElement
		var ok bool
		if int32(contentHR) >= 0 && isContent != 0 {
			found, ok = findElementByRuntimeID(uiaElement{current}, walker, key, depth+1, remaining)
		} else {
			// Hidden/provider-only siblings must consume traversal budget too.
			*remaining = *remaining - 1
		}
		oleRelease(current)
		if ok || int32(hr) < 0 || *remaining == 0 {
			if next != nil {
				oleRelease(next)
			}
			return found, ok
		}
		current = next
	}
	if current != nil {
		oleRelease(current)
	}
	return uiaElement{}, false
}

func semanticScroll(element uiaElement, xTicks, yTicks int) error {
	pattern := element.currentPattern(uiaPatternScroll)
	if pattern == nil {
		return errors.New("element does not support ScrollPattern")
	}
	defer oleRelease(pattern)

	abs := func(value int) int {
		if value < 0 {
			return -value
		}
		return value
	}
	repeat := int(math.Max(float64(abs(xTicks)), float64(abs(yTicks))))
	if repeat == 0 {
		return errors.New("semantic scroll requires a non-zero bounded direction")
	}

	for index := 0; index < repeat; index++ {
		horizontal, vertical := int32(0), int32(0) // NoAmount.
		if index < abs(xTicks) {
			if xTicks < 0 {
				horizontal = 1 // LargeDecrement.
			} else {
				horizontal = 2 // LargeIncrement.
			}
		}
		if index < abs(yTicks) {
			if yTicks < 0 {
				vertical = 1
			} else {
				vertical = 2
			}
		}
		hr, _, _ := vtableCall(
			pattern,
			scrollSlotScroll,
			uintptr(horizontal),
			uintptr(vertical),
		)
		if int32(hr) < 0 {
			return fmt.Errorf("ScrollPattern.Scroll failed: 0x%08x", uint32(hr))
		}
		if index+1 < repeat {
			sleepMs(40)
		}
	}
	return nil
}

func dispatchSemanticAction(req hostRequest, element uiaElement) error {
	if !boolProperty(element, uiaPropIsEnabled, false) {
		return errors.New("target element is disabled")
	}
	switch req.SemanticAction {
	case "invoke":
		pattern := element.currentPattern(uiaPatternInvoke)
		if pattern == nil {
			return errors.New("element does not support InvokePattern")
		}
		defer oleRelease(pattern)
		hr, _, _ := vtableCall(pattern, invokeSlotInvoke)
		if int32(hr) < 0 {
			return fmt.Errorf("InvokePattern.Invoke failed: 0x%08x", uint32(hr))
		}
		return nil
	case "set_value":
		if boolProperty(element, uiaPropIsPassword, true) {
			return errors.New("password/security value targets are not writable")
		}
		pattern := element.currentPattern(uiaPatternValue)
		if pattern == nil {
			return errors.New("element does not support ValuePattern")
		}
		defer oleRelease(pattern)
		value, err := windows.UTF16PtrFromString(req.Value)
		if err != nil {
			return errors.New("value contains an invalid NUL")
		}
		hr, _, _ := vtableCall(pattern, valueSlotSetValue, uintptr(unsafe.Pointer(value)))
		if int32(hr) < 0 {
			return fmt.Errorf("ValuePattern.SetValue failed: 0x%08x", uint32(hr))
		}
		return nil
	case "select":
		pattern := element.currentPattern(uiaPatternSelect)
		if pattern == nil {
			return errors.New("element does not support SelectionItemPattern")
		}
		defer oleRelease(pattern)
		hr, _, _ := vtableCall(pattern, selectSlotSelect)
		if int32(hr) < 0 {
			return fmt.Errorf("SelectionItemPattern.Select failed: 0x%08x", uint32(hr))
		}
		return nil
	case "toggle":
		pattern := element.currentPattern(uiaPatternToggle)
		if pattern == nil {
			return errors.New("element does not support TogglePattern")
		}
		defer oleRelease(pattern)
		hr, _, _ := vtableCall(pattern, toggleSlotToggle)
		if int32(hr) < 0 {
			return fmt.Errorf("TogglePattern.Toggle failed: 0x%08x", uint32(hr))
		}
		return nil
	case "scroll":
		return semanticScroll(element, req.ScrollX, req.ScrollY)
	default:
		return errors.New("semantic action is not mapped")
	}
}

func nativeSemanticAction(req hostRequest) hostResponse {
	if _, _, err := validateBoundWindow(req); err != nil {
		return failure(req.ID, "target_stale", err.Error())
	}

	var operationErr error
	err := uiaOnThread(func() {
		root, bindErr := uiaElementFromHandle(int64(req.HWND))
		if bindErr != nil {
			operationErr = bindErr
			return
		}
		defer root.release()

		walker, walkerErr := uiaRawViewWalker()
		if walkerErr != nil {
			operationErr = walkerErr
			return
		}
		defer oleRelease(walker)

		remaining := maxRootSearchNodes
		element, found := findElementByRuntimeID(root, walker, req.ElementRuntimeID, 0, &remaining)
		if !found {
			operationErr = errors.New("exact UIA runtime id is stale or no longer present")
			return
		}
		defer element.release()
		operationErr = dispatchSemanticAction(req, element)
	})
	if err != nil {
		return failure(req.ID, "provider_unavailable", err.Error())
	}
	if operationErr != nil {
		return failure(req.ID, "target_stale", operationErr.Error())
	}
	resp := success(req.ID)
	resp.Action = &actionFact{State: "completed", Action: "semantic_" + req.SemanticAction}
	return resp
}
