//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// COPY_ADAPT from opensymph/open-computer-use
// apps/OpenComputerUseWindows/native_uia.go blob
// 74c0e98b04f612484580eb9dfd2dbfd840659ca7 at commit
// 5b433b98019c18201a15d11e8c3cb0010879a3d8 (MIT).
// Orcel keeps COM apartment, element/property, raw-view traversal, pattern
// discovery, and value observation only. Every UIA mutation path is absent.

package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// CLSID_CUIAutomation8. Headers say ...7395c6, but this system's registry
	// (and Windows 11 generally) registers the client central class as
	// ...7395c9; both hand out IID_IUIAutomation.
	uiaCLSID = "{E22AD333-B25F-460C-83D0-0581107395C9}"
	uiaIID   = "{30CBE57D-D9D0-452A-AB13-7AC5AC4825EE}" // IID_IUIAutomation

	// IUIAutomation slots.
	uiaSlotGetRootElement          = 5
	uiaSlotGetRawViewWalker        = 16
	uiaSlotElementFromHandle       = 6
	uiaSlotGetFocusedElement       = 8
	uiaSlotCreateTrueCondition     = 21
	uiaSlotCreatePropertyCondition = 23

	// IUIAutomationElement read-only slots.
	elemSlotGetRuntimeId            = 4
	elemSlotFindAll                 = 6
	elemSlotGetCurrentPattern       = 16
	elemSlotGetCurrentPropertyValue = 10
	elemSlotCurrentProcessId        = 20
	elemSlotCurrentControlType      = 21
	elemSlotCurrentLocalizedType    = 22
	elemSlotCurrentName             = 23
	elemSlotCurrentAutomationId     = 29
	elemSlotCurrentClassName        = 30
	elemSlotCurrentIsContentElement = 34
	elemSlotCurrentNativeWindow     = 36
	elemSlotCurrentBoundingRect     = 43

	// IUIAutomationTreeWalker slots (shared by the raw/control/content walkers).
	walkerSlotGetFirstChildElement  = 4
	walkerSlotGetNextSiblingElement = 6

	// Array pattern (ElementArray / TextRangeArray share the layout).
	arrSlotLength     = 3
	arrSlotGetElement = 4

	// Pattern slots.
	textSlotGetSelection     = 5
	textRangeSlotGetText     = 12
	valueSlotGetCurrentValue = 4
	expandCollapseSlotState  = 5

	// Property / pattern ids.
	uiaPropControlType               = 30003
	uiaPropIsExpandCollapseAvailable = 30028
	uiaPropIsInvokeAvailable         = 30031
	uiaPropIsScrollAvailable         = 30034
	uiaPropIsScrollItemAvailable     = 30035
	uiaPropIsSelectionItemAvailable  = 30036
	uiaPropIsToggleAvailable         = 30041
	uiaPropIsValueAvailable          = 30043
	uiaPropProcessId                 = 30002
	uiaPatternInvoke                 = 10000
	uiaPatternValue                  = 10002
	uiaPatternScroll                 = 10004
	uiaPatternExpand                 = 10005
	uiaPatternSelect                 = 10010
	uiaPatternText                   = 10014
	uiaPatternToggle                 = 10015
	uiaPatternScrollItem             = 10017

	treeScopeChildren = 2

	defaultTextLimit      = 500
	accessibilityMaxNodes = 1200
	accessibilityMaxDepth = 64
)

// uiaControlTypeNames maps CONTROLTYPEID to the ProgrammaticName form
// ("ControlType.Button") used by Get-ElementControlTypeName.
var uiaControlTypeNames = map[int32]string{
	50000: "ControlType.Button", 50001: "ControlType.Calendar",
	50002: "ControlType.CheckBox", 50003: "ControlType.ComboBox",
	50004: "ControlType.Edit", 50005: "ControlType.Hyperlink",
	50006: "ControlType.Image", 50007: "ControlType.ListItem",
	50008: "ControlType.List", 50009: "ControlType.Menu",
	50010: "ControlType.MenuBar", 50011: "ControlType.MenuItem",
	50012: "ControlType.ProgressBar", 50013: "ControlType.RadioButton",
	50014: "ControlType.ScrollBar", 50015: "ControlType.Slider",
	50016: "ControlType.Spinner", 50017: "ControlType.StatusBar",
	50018: "ControlType.Tab", 50019: "ControlType.TabItem",
	50020: "ControlType.Text", 50021: "ControlType.ToolBar",
	50022: "ControlType.ToolTip", 50023: "ControlType.Tree",
	50024: "ControlType.TreeItem", 50025: "ControlType.Custom",
	50026: "ControlType.Group", 50027: "ControlType.Thumb",
	50028: "ControlType.DataGrid", 50029: "ControlType.DataItem",
	50030: "ControlType.Document", 50031: "ControlType.SplitButton",
	50032: "ControlType.Window", 50033: "ControlType.Pane",
	50034: "ControlType.Header", 50035: "ControlType.HeaderItem",
	50036: "ControlType.Table", 50037: "ControlType.TitleBar",
	50038: "ControlType.Separator", 50039: "ControlType.SemanticZoom",
}

// --- UIA apartment/thread plumbing ------------------------------------------

// All UIA COM calls run on one goroutine pinned to one OS thread with COM
// initialized, so apartment semantics stay deterministic regardless of which
// goroutine services a request.
var (
	uiaThreadOnce sync.Once
	uiaClientPtr  unsafe.Pointer
	uiaClientErr  error
	uiaJobs       chan func()
	uiaThreadID   uint32
)

// runUIAJob executes fn on the UIA thread, converting a panic inside the job
// (e.g. a malformed provider tripping a nil dereference) into an error so a
// single bad element cannot take down the whole server process.
func runUIAJob(fn func()) error {
	var jobErr error
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				jobErr = fmt.Errorf("UIA operation panicked: %v", recovered)
			}
		}()
		fn()
	}()
	return jobErr
}

func uiaOnThread(fn func()) error {
	uiaThreadOnce.Do(func() {
		uiaJobs = make(chan func())
		ready := make(chan struct{})
		go func() {
			runtime.LockOSThread()
			coInitializeEx(0 /* COINIT_MULTITHREADED */)
			uiaThreadID = windows.GetCurrentThreadId()
			close(ready)
			for job := range uiaJobs {
				_ = runUIAJob(job)
			}
		}()
		<-ready
		uiaClientPtr, uiaClientErr = oleCreateInstance(uiaCLSID, uiaIID)
	})
	if uiaClientErr != nil {
		return uiaClientErr
	}
	if windows.GetCurrentThreadId() == uiaThreadID {
		return runUIAJob(fn) // already on the UIA thread; avoid self-deadlock
	}
	// Flat node-API calls (UiaNavigate & co.) require COM to be initialized
	// on the calling thread; dispatch every job to the dedicated UIA thread.
	done := make(chan error, 1)
	uiaJobs <- func() { done <- runUIAJob(fn) }
	return <-done
}

// uiaPtr converts a raw address to unsafe.Pointer through a pointer round
// trip so `go vet`'s unsafeptr check accepts it (same trick as storing COM
// out-params in unsafe.Pointer variables).
func uiaPtr(base uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&base))
}

// --- oleaut32 helpers -------------------------------------------------------

var (
	procSysFreeString    = windows.NewLazySystemDLL("oleaut32.dll").NewProc("SysFreeString")
	procVariantClear     = windows.NewLazySystemDLL("oleaut32.dll").NewProc("VariantClear")
	procSafeArrayDestroy = windows.NewLazySystemDLL("oleaut32.dll").NewProc("SafeArrayDestroy")
)

// bstrToString reads a BSTR out parameter; hr must be checked by the caller
// before invoking this. Freeing is skipped for empty strings.
func bstrToString(p uintptr) string {
	if p == 0 {
		return ""
	}
	s := bstrToStringKeep(p)
	procSysFreeString.Call(p)
	return s
}

// bstrToStringKeep copies a BSTR without freeing it — for BSTRs owned by a
// VARIANT, whose VariantClear call performs the single release.
func bstrToStringKeep(p uintptr) string {
	if p == 0 {
		return ""
	}
	n := *(*uint32)(uiaPtr(p - 4))
	return windows.UTF16ToString(unsafe.Slice((*uint16)(uiaPtr(p)), n/2))
}

// safeArrayCount returns cElements of the first (only) bound dimension.
func safeArrayCount(sa uintptr) int {
	if sa == 0 {
		return 0
	}
	return int(*(*uint32)(uiaPtr(sa + 24))) // rgsabound[0].cElements
}

// safeArrayInts reads a SAFEARRAY of I4 (GetRuntimeId) and destroys it.
func safeArrayInts(sa uintptr) []int {
	count := safeArrayCount(sa)
	if count == 0 {
		if sa != 0 {
			procSafeArrayDestroy.Call(sa)
		}
		return []int{}
	}
	data := *(*uintptr)(uiaPtr(sa + 16)) // pvData
	values := unsafe.Slice((*int32)(uiaPtr(data)), count)
	out := make([]int, count)
	for i, v := range values {
		out[i] = int(v)
	}
	procSafeArrayDestroy.Call(sa)
	return out
}

// --- element wrapper ---------------------------------------------------------

type uiaElement struct{ ptr unsafe.Pointer }

func (e uiaElement) valid() bool { return e.ptr != nil }

func (e uiaElement) release() {
	if e.ptr != nil {
		vtableCall(e.ptr, 2)
	}
}

func (e uiaElement) processId() int32 {
	var out int32
	if hr, _, _ := vtableCall(e.ptr, elemSlotCurrentProcessId, uintptr(unsafe.Pointer(&out))); int32(hr) < 0 {
		return 0
	}
	return out
}

func (e uiaElement) controlTypeId() int32 {
	var out int32
	if hr, _, _ := vtableCall(e.ptr, elemSlotCurrentControlType, uintptr(unsafe.Pointer(&out))); int32(hr) < 0 {
		return 0
	}
	return out
}

func (e uiaElement) controlTypeName() string {
	return uiaControlTypeNames[e.controlTypeId()]
}

func (e uiaElement) bstrProp(slot int) string {
	var p uintptr
	if hr, _, _ := vtableCall(e.ptr, slot, uintptr(unsafe.Pointer(&p))); int32(hr) < 0 {
		return ""
	}
	return bstrToString(p)
}

func (e uiaElement) localizedControlType() string { return e.bstrProp(elemSlotCurrentLocalizedType) }

// uiaLocalizedControlTypeEN maps CONTROLTYPEID to the English localized
// name. the retired PS-era runtime's managed UIA client returns these on this machine
// (dominant behavior; the first property access can occasionally race to
// the zh-CN core resources instead). Dual-run diffs normalize the two.
var uiaLocalizedControlTypeEN = map[int32]string{
	50000: "button", 50001: "calendar", 50002: "check box",
	50003: "combo box", 50004: "edit", 50005: "hyperlink",
	50006: "image", 50007: "list item", 50008: "list",
	50009: "menu", 50010: "menu bar", 50011: "menu item",
	50012: "progress bar", 50013: "radio button", 50014: "scroll bar",
	50015: "slider", 50016: "spinner", 50017: "status bar",
	50018: "tab", 50019: "tab item", 50020: "text", 50021: "tool bar",
	50022: "tooltip", 50023: "tree", 50024: "tree item", 50025: "custom",
	50026: "group", 50027: "thumb", 50028: "data grid",
	50029: "data item", 50030: "document", 50031: "split button",
	50032: "window", 50033: "pane", 50034: "header",
	50035: "header item", 50036: "table", 50037: "title bar",
	50038: "separator", 50039: "semantic zoom",
}

// localizedControlTypeName mirrors the PS daemon's observable behavior: for
// Win32-framework elements the managed client's MSAA proxies report the
// English localized control type (e.g. "pane") even on a localized system,
// while non-Win32 providers (Chrome "区域", XAML) supply their own localized
// value that must be passed through untouched.
func (e uiaElement) localizedControlTypeName() string {
	if e.frameworkId() == "Win32" {
		if name, ok := uiaLocalizedControlTypeEN[e.controlTypeId()]; ok {
			return name
		}
	}
	return e.localizedControlType()
}

// frameworkId reads UIA_FrameworkIdPropertyId (30024). The BSTR is owned by
// the VARIANT: copy it, then let VariantClear perform the single free (a
// manual SysFreeString here double-frees and corrupts the heap).
func (e uiaElement) frameworkId() string {
	v := oleVariant{}
	if hr, _, _ := vtableCall(e.ptr, elemSlotGetCurrentPropertyValue,
		uintptr(30024), uintptr(unsafe.Pointer(&v))); int32(hr) < 0 || v.vt != 8 {
		procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
		return ""
	}
	p := *(*uintptr)(unsafe.Pointer(&v.value[0]))
	s := bstrToStringKeep(p)
	procVariantClear.Call(uintptr(unsafe.Pointer(&v)))
	return s
}

func (e uiaElement) name() string         { return e.bstrProp(elemSlotCurrentName) }
func (e uiaElement) automationId() string { return e.bstrProp(elemSlotCurrentAutomationId) }
func (e uiaElement) className() string    { return e.bstrProp(elemSlotCurrentClassName) }

func (e uiaElement) nativeWindowHandle() int64 {
	var out uintptr
	if hr, _, _ := vtableCall(e.ptr, elemSlotCurrentNativeWindow, uintptr(unsafe.Pointer(&out))); int32(hr) < 0 {
		return 0
	}
	return int64(out)
}

func (e uiaElement) runtimeId() []int {
	var sa uintptr
	if hr, _, _ := vtableCall(e.ptr, elemSlotGetRuntimeId, uintptr(unsafe.Pointer(&sa))); int32(hr) < 0 {
		return nil
	}
	return safeArrayInts(sa)
}

func (e uiaElement) runtimeIdKey() string {
	ids := e.runtimeId()
	if ids == nil {
		return "" // caller falls back to a random key (PS uses a GUID)
	}
	return strings.Join(intsToStrings(ids), ".")
}

// boundingRect mirrors get_CurrentBoundingRectangle (RECT of LONGs).
func (e uiaElement) boundingRect() (x, y, w, h float64, ok bool) {
	var rect [4]int32
	if hr, _, _ := vtableCall(e.ptr, elemSlotCurrentBoundingRect, uintptr(unsafe.Pointer(&rect[0]))); int32(hr) < 0 {
		return 0, 0, 0, 0, false
	}
	left, top, right, bottom := rect[0], rect[1], rect[2], rect[3]
	w = float64(right - left)
	h = float64(bottom - top)
	if left == 0 && top == 0 && right == 0 && bottom == 0 {
		return 0, 0, 0, 0, false // Rect.IsEmpty equivalent
	}
	if w <= 0 || h <= 0 {
		return 0, 0, 0, 0, false
	}
	return float64(left), float64(top), w, h, true
}

// currentPattern mirrors GetCurrentPattern: nil when unsupported.
func (e uiaElement) currentPattern(patternId int32) unsafe.Pointer {
	var out unsafe.Pointer
	if hr, _, _ := vtableCall(e.ptr, elemSlotGetCurrentPattern,
		uintptr(patternId), uintptr(unsafe.Pointer(&out))); int32(hr) < 0 {
		return nil
	}
	return out
}

// patternAvailable mirrors the managed IsXxxPatternAvailable properties
// (what GetSupportedPatterns reports); GetCurrentPattern alone can return
// patterns the provider does not declare (e.g. the WinUI Notepad document
// answers Scroll without reporting it).
func (e uiaElement) patternAvailable(propertyId int32) bool {
	variant := oleVariant{}
	if hr, _, _ := vtableCall(e.ptr, elemSlotGetCurrentPropertyValue,
		uintptr(propertyId), uintptr(unsafe.Pointer(&variant))); int32(hr) < 0 {
		return false
	}
	result := variant.vt == 11 /*VT_BOOL*/ && *(*int16)(unsafe.Pointer(&variant.value[0])) != 0
	procVariantClear.Call(uintptr(unsafe.Pointer(&variant)))
	return result
}

// findAllChildren mirrors FindAll(TreeScope.Children, TrueCondition).
func (e uiaElement) findAllChildren(condition unsafe.Pointer) []uiaElement {
	var arrayPtr unsafe.Pointer
	if hr, _, _ := vtableCall(e.ptr, elemSlotFindAll,
		uintptr(treeScopeChildren), uintptr(condition), uintptr(unsafe.Pointer(&arrayPtr))); int32(hr) < 0 {
		return nil
	}
	if arrayPtr == nil {
		return nil
	}
	defer oleRelease(arrayPtr)
	var length int32
	if hr, _, _ := vtableCall(arrayPtr, arrSlotLength, uintptr(unsafe.Pointer(&length))); int32(hr) < 0 {
		return nil
	}
	children := make([]uiaElement, 0, length)
	for i := int32(0); i < length; i++ {
		var elemPtr unsafe.Pointer
		if hr, _, _ := vtableCall(arrayPtr, arrSlotGetElement,
			uintptr(i), uintptr(unsafe.Pointer(&elemPtr))); int32(hr) < 0 || elemPtr == nil {
			continue
		}
		children = append(children, uiaElement{elemPtr})
	}
	return children
}

func intsToStrings(values []int) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = fmt.Sprintf("%d", v)
	}
	return out
}

// --- client-level helpers -----------------------------------------------------

func uiaElementFromHandle(hwnd int64) (uiaElement, error) {
	var out unsafe.Pointer
	hr, _, _ := vtableCall(uiaClientPtr, uiaSlotElementFromHandle,
		uintptr(hwnd), uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == nil {
		return uiaElement{}, fmt.Errorf("ElementFromHandle failed: 0x%08x", int32(hr))
	}
	return uiaElement{out}, nil
}

func uiaGetRootElement() (uiaElement, error) {
	var out unsafe.Pointer
	hr, _, _ := vtableCall(uiaClientPtr, uiaSlotGetRootElement, uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == nil {
		return uiaElement{}, fmt.Errorf("GetRootElement failed: 0x%08x", int32(hr))
	}
	return uiaElement{out}, nil
}

func uiaGetFocusedElement() (uiaElement, error) {
	var out unsafe.Pointer
	hr, _, _ := vtableCall(uiaClientPtr, uiaSlotGetFocusedElement, uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == nil {
		return uiaElement{}, fmt.Errorf("GetFocusedElement failed: 0x%08x", int32(hr))
	}
	return uiaElement{out}, nil
}

func uiaTrueCondition() (unsafe.Pointer, error) {
	var out unsafe.Pointer
	hr, _, _ := vtableCall(uiaClientPtr, uiaSlotCreateTrueCondition, uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == nil {
		return nil, fmt.Errorf("CreateTrueCondition failed: 0x%08x", int32(hr))
	}
	return out, nil
}

// oleVariant is the x64 VARIANT layout (24 bytes): vt + 3 reserved WORDs,
// then the 16-byte payload union (largest member is the {pvRecord, pRecInfo}
// pointer pair), which places scalar/pointer values at offset 8. COM callees
// and VariantClear copy sizeof(VARIANT) bytes, so a shorter struct would be
// written past its end.
type oleVariant struct {
	vt    uint16
	r1    uint16
	r2    uint16
	r3    uint16
	value [16]byte
}

func uiaPropertyConditionInt(propertyId int32, value int32) (unsafe.Pointer, error) {
	variant := oleVariant{vt: 3 /* VT_I4 */}
	*(*int32)(unsafe.Pointer(&variant.value[0])) = value
	var out unsafe.Pointer
	hr, _, _ := vtableCall(uiaClientPtr, uiaSlotCreatePropertyCondition,
		uintptr(propertyId), uintptr(unsafe.Pointer(&variant)), uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == nil {
		return nil, fmt.Errorf("CreatePropertyCondition failed: 0x%08x", int32(hr))
	}
	return out, nil
}

// uiaRawViewWalker mirrors [Windows.Automation.TreeWalker]::RawViewWalker.
func uiaRawViewWalker() (unsafe.Pointer, error) {
	var out unsafe.Pointer
	hr, _, _ := vtableCall(uiaClientPtr, uiaSlotGetRawViewWalker, uintptr(unsafe.Pointer(&out)))
	if int32(hr) < 0 || out == nil {
		return nil, fmt.Errorf("get_RawViewWalker failed: 0x%08x", int32(hr))
	}
	return out, nil
}

// walkerChildren enumerates the raw-view children of an element, skipping
// IsContentElement=0 nodes. The managed FindAll(TreeScope.Children,
// TrueCondition) that Render-Tree uses hides the proxy-generated title bar
// and menu bar subtrees (both content=0); this filter reproduces its exact
// output (verified against Notepad, Explorer, Everything, and Edge).
func walkerChildren(walker unsafe.Pointer, e uiaElement) []uiaElement {
	var first unsafe.Pointer
	if hr, _, _ := vtableCall(walker, walkerSlotGetFirstChildElement,
		uintptr(e.ptr), uintptr(unsafe.Pointer(&first))); int32(hr) < 0 {
		return nil
	}
	children := make([]uiaElement, 0, 8)
	for current := first; current != nil; {
		var next unsafe.Pointer
		hr, _, _ := vtableCall(walker, walkerSlotGetNextSiblingElement,
			uintptr(current), uintptr(unsafe.Pointer(&next)))
		var isContent int32
		if hrC, _, _ := vtableCall(current, elemSlotCurrentIsContentElement,
			uintptr(unsafe.Pointer(&isContent))); int32(hrC) >= 0 && isContent != 0 {
			children = append(children, uiaElement{current})
		} else {
			oleRelease(current)
		}
		if int32(hr) < 0 {
			break
		}
		current = next
	}
	return children
}

// --- Get-PatternNames / Get-ElementValue ports --------------------------------

// Note on pattern semantics: the retired PS-era runtime's managed client
// registered .NET Framework client-side proxies (UiaCoreApi's static ctor
// calls UiaRegisterProviderCallback), which changed pattern availability and
// LocalizedControlType answers for Win32-hosted content versus a plain COM
// client (e.g. the WinUI Notepad document answers Scroll to GetCurrentPattern
// while the managed client reported it unsupported). That proxy layer cannot
// be reproduced in-process from Go; per the 2026-08-22 decision the raw COM
// answers below ARE the behavior baseline for the tree tools (the same view
// the official Swift runtime gets).

// uiaPatternActions probes candidate patterns in ascending pattern-id order,
// which is the order GetSupportedPatterns returns them in (verified against
// Notepad: Document=Value,Text; MenuItem=Invoke,ExpandCollapse,ScrollItem;
// Text=Text,ScrollItem — all ascending by id).
func uiaPatternActions(e uiaElement) []string {
	var names []string
	add := func(n string) { names = append(names, n) }
	for _, candidate := range []struct {
		id   int32
		prop int32
		name string
	}{
		{uiaPatternInvoke, uiaPropIsInvokeAvailable, "Invoke"},
		{uiaPatternValue, uiaPropIsValueAvailable, "SetValue"},
		{uiaPatternScroll, uiaPropIsScrollAvailable, "Scroll"},
		{uiaPatternExpand, uiaPropIsExpandCollapseAvailable, ""},
		{uiaPatternSelect, uiaPropIsSelectionItemAvailable, "Select"},
		{uiaPatternToggle, uiaPropIsToggleAvailable, "Toggle"},
		{uiaPatternScrollItem, uiaPropIsScrollItemAvailable, "ScrollIntoView"},
	} {
		if !e.patternAvailable(candidate.prop) {
			continue
		}
		pattern := e.currentPattern(candidate.id)
		if pattern == nil {
			// GetCurrentPattern can return a NULL out-param (with a success
			// HRESULT) even when the availability property says supported;
			// vtableCall would dereference it and crash the process.
			continue
		}
		if candidate.id == uiaPatternExpand {
			var state int32
			hr, _, _ := vtableCall(pattern, expandCollapseSlotState, uintptr(unsafe.Pointer(&state)))
			switch {
			case int32(hr) < 0:
				add("Expand")
				add("Collapse")
			case state == 0: // Collapsed
				add("Expand")
			case state == 1: // Expanded
				add("Collapse")
			}
			oleRelease(pattern)
			continue
		}
		add(candidate.name)
		oleRelease(pattern)
	}
	return names
}

// uiaElementValue mirrors Get-ElementValue (ValuePattern.Current.Value).
func uiaElementValue(e uiaElement, textLimit *int) string {
	pattern := e.currentPattern(uiaPatternValue)
	if pattern == nil {
		return ""
	}
	defer oleRelease(pattern)
	var p uintptr
	if hr, _, _ := vtableCall(pattern, valueSlotGetCurrentValue, uintptr(unsafe.Pointer(&p))); int32(hr) < 0 {
		return ""
	}
	return limitTextPS(bstrToString(p), textLimit)
}



func limitTextPS(text string, textLimit *int) string {
	if textLimit == nil {
		return text
	}
	runes := []rune(text)
	if len(runes) > *textLimit {
		return string(runes[:*textLimit]) + "..."
	}
	return text
}

const (
	uiaPropIsEnabled = 30010
	uiaPropIsPassword = 30019
	selectionSlotCurrentIsSelected = 6
	toggleSlotCurrentState = 4
	scrollSlotHorizontalPercent = 5
	scrollSlotVerticalPercent = 7
)

func boolProperty(e uiaElement, propertyID int32, failClosed bool) bool {
	variant := oleVariant{}
	hr, _, _ := vtableCall(
		e.ptr,
		elemSlotGetCurrentPropertyValue,
		uintptr(propertyID),
		uintptr(unsafe.Pointer(&variant)),
	)
	if int32(hr) < 0 || variant.vt != 11 { // VT_BOOL
		return failClosed
	}
	value := *(*int16)(unsafe.Pointer(&variant.value[0]))
	return value != 0
}

func selectionState(e uiaElement) bool {
	if !e.patternAvailable(uiaPropIsSelectionItemAvailable) {
		return false
	}
	pattern := e.currentPattern(uiaPatternSelect)
	if pattern == nil { return false }
	defer oleRelease(pattern)
	var selected int32
	hr, _, _ := vtableCall(pattern, selectionSlotCurrentIsSelected, uintptr(unsafe.Pointer(&selected)))
	return int32(hr) >= 0 && selected != 0
}

func toggleState(e uiaElement) bool {
	if !e.patternAvailable(uiaPropIsToggleAvailable) {
		return false
	}
	pattern := e.currentPattern(uiaPatternToggle)
	if pattern == nil { return false }
	defer oleRelease(pattern)
	var state int32
	hr, _, _ := vtableCall(pattern, toggleSlotCurrentState, uintptr(unsafe.Pointer(&state)))
	return int32(hr) >= 0 && state != 0
}

func percentFromPattern(pattern unsafe.Pointer, slot int) uint8 {
	if pattern == nil { return 0 }
	var value float64
	hr, _, _ := vtableCall(pattern, slot, uintptr(unsafe.Pointer(&value)))
	if int32(hr) < 0 || value <= 0 { return 0 }
	if value > 100 { value = 100 }
	return uint8(value + 0.5)
}

func scrollState(e uiaElement) (uint8, uint8) {
	if !e.patternAvailable(uiaPropIsScrollAvailable) {
		return 0, 0
	}
	pattern := e.currentPattern(uiaPatternScroll)
	if pattern == nil { return 0, 0 }
	defer oleRelease(pattern)
	return percentFromPattern(pattern, scrollSlotHorizontalPercent),
		percentFromPattern(pattern, scrollSlotVerticalPercent)
}

func canonicalPatterns(e uiaElement) []string {
	raw := uiaPatternActions(e)
	out := make([]string, 0, len(raw))
	seen := map[string]bool{}
	for _, name := range raw {
		var canonical string
		switch name {
		case "Invoke":
			canonical = "Invoke"
		case "SetValue":
			canonical = "Value"
		case "Select":
			canonical = "SelectionItem"
		case "Toggle":
			canonical = "Toggle"
		case "Scroll":
			canonical = "Scroll"
		default:
			continue
		}
		if !seen[canonical] {
			seen[canonical] = true
			out = append(out, canonical)
		}
	}
	return out
}

func shortControlType(value string) string {
	return strings.TrimPrefix(value, "ControlType.")
}

func observeUIAElement(
	e uiaElement,
	walker unsafe.Pointer,
	depth int,
	maxDepth int,
	remaining *int,
) elementFact {
	if *remaining <= 0 {
		return elementFact{}
	}
	*remaining--
	password := boolProperty(e, uiaPropIsPassword, true)
	enabled := boolProperty(e, uiaPropIsEnabled, false)
	var value *string
	if !password {
		limit := 1024
		text := uiaElementValue(e, &limit)
		if text != "" {
			value = &text
		}
	}
	horizontal, vertical := scrollState(e)
	node := elementFact{
		RuntimeID: e.runtimeIdKey(),
		ControlType: shortControlType(e.controlTypeName()),
		AutomationID: e.automationId(),
		Name: limitTextPS(e.name(), func() *int { v := 1024; return &v }()),
		Enabled: enabled,
		Selected: selectionState(e),
		Toggled: toggleState(e),
		ScrollHorizontalPercent: horizontal,
		ScrollVerticalPercent: vertical,
		Patterns: canonicalPatterns(e),
		Value: value,
		ValueIsPassword: password,
		Children: []elementFact{},
	}
	if node.RuntimeID == "" {
		node.RuntimeID = fmt.Sprintf("unidentified.%d.%d", windows.GetCurrentProcessId(), *remaining)
	}
	if depth >= maxDepth || *remaining <= 0 {
		return node
	}
	for _, child := range walkerChildren(walker, e) {
		if *remaining <= 0 {
			child.release()
			break
		}
		node.Children = append(node.Children, observeUIAElement(child, walker, depth+1, maxDepth, remaining))
		child.release()
	}
	return node
}

// observeWindowUIA reads the bound window's tree, or (SG-000128) the
// subtree below rootRuntimeID inside that same window. The root is found by
// the bounded runtime-id search; the returned tree keeps the node and depth
// caps, counted from its root. A root that does not resolve fails closed.
func observeWindowUIA(hwnd uint64, maxNodes, maxDepth int, rootRuntimeID string) ([]elementFact, error) {
	if maxNodes <= 0 || maxNodes > maxTreeNodes { maxNodes = maxTreeNodes }
	if maxDepth <= 0 || maxDepth > maxTreeDepth { maxDepth = maxTreeDepth }
	var result []elementFact
	var operationErr error
	err := uiaOnThread(func() {
		root, bindErr := uiaElementFromHandle(int64(hwnd))
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
		start := root
		if rootRuntimeID != "" {
			searched := maxRootSearchNodes
			found, ok := findElementByRuntimeID(root, walker, rootRuntimeID, 0, &searched)
			if !ok {
				operationErr = errors.New("subtree root is stale or gone: not found inside the window within the search bounds")
				return
			}
			defer found.release()
			start = found
		}
		remaining := maxNodes
		result = []elementFact{observeUIAElement(start, walker, 0, maxDepth, &remaining)}
	})
	if err != nil { return nil, err }
	if operationErr != nil { return nil, operationErr }
	if result == nil { result = []elementFact{} }
	return result, nil
}
