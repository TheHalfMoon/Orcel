//go:build windows

// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// W2-01 native qualification of the HCU-derived semantic layer against a
// disposable Windows Forms window this test launches. It runs only when
// ORCEL_W201_NATIVE_TESTS=1 (set in CI) and then only reads: UIA
// observation of the test window, its layout, and a test-only move of the
// test window itself. No input is sent. The live
// identity check of a semantic action calls a UIA pattern on the test
// window and runs only when ORCEL_W201_SEMANTIC_ACTIONS=1 (set in CI, on a
// disposable runner).

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/TheHalfMoon/Orcel/apps/orcel-computer-host/third_party/hcu/semantic"
	"golang.org/x/sys/windows"
)

func readOnlyNativeDispatch(t *testing.T) func(hostRequest) hostResponse {
	return func(req hostRequest) hostResponse {
		if req.Op != "observe_window" {
			t.Fatalf("a read-only W2-01 test reached native %q", req.Op)
		}
		return nativeObserveWindow(req)
	}
}

func refTreeFrame(id int, fact windowFact) string {
	return fmt.Sprintf(`{"id":%d,"protocol":"orcel-computer-host/2","op":"observe_window","ref_tree":true,"max_nodes":64,"max_depth":6,"window":{"kind":"hwnd","id":%d,"expected_pid":%d,"expected_start_generation":%d,"expected_window_nonce":%d}}`,
		id, fact.HWND, fact.Process.PID, fact.Process.StartGeneration, fact.WindowNonce)
}

func runtimeIDFor(t *testing.T, elements []elementFact, name string) string {
	t.Helper()
	return elementNamed(t, elements, name).RuntimeID
}

func elementNamed(t *testing.T, elements []elementFact, name string) elementFact {
	t.Helper()
	var walk func([]elementFact) *elementFact
	walk = func(nodes []elementFact) *elementFact {
		for index := range nodes {
			if nodes[index].Name == name {
				return &nodes[index]
			}
			if found := walk(nodes[index].Children); found != nil {
				return found
			}
		}
		return nil
	}
	if found := walk(elements); found != nil && found.RuntimeID != "" {
		return *found
	}
	t.Fatalf("no element named %q", name)
	return elementFact{}
}

func TestW201RefTreeAgainstDisposableWindow(t *testing.T) {
	if os.Getenv("ORCEL_W201_NATIVE_TESTS") != "1" {
		t.Skip("set ORCEL_W201_NATIVE_TESTS=1 to run the W2-01 native qualification against a disposable window (set in CI)")
	}
	if err := requireInteractiveStation(); err != nil {
		t.Fatalf("native qualification requires the interactive WinSta0 session: %v", err)
	}
	helper := launchNativeTestWindow(t)
	fact := findNativeTestWindow(t, helper.title)
	s := newSupervisor()
	dispatch := readOnlyNativeDispatch(t)

	first, _ := s.handleFrame([]byte(refTreeFrame(1, fact)), dispatch)
	if !first.OK || first.RefTree == nil {
		t.Fatalf("ref tree observation failed: %+v", first.Error)
	}
	tree := first.RefTree
	t.Logf("ref tree of the disposable window:\n%s", tree.Text)
	for _, want := range []string{`button "SG94 Button" [ref=r`, `"SG94 Value"`, `[ref=r1]`} {
		if !strings.Contains(tree.Text, want) {
			t.Fatalf("ref tree lacks %q:\n%s", want, tree.Text)
		}
	}
	if first.Layout != nil {
		t.Fatal("the worker layout was forwarded to orceld")
	}
	layout, err := currentLayout(helper.hwnd)
	if err != nil || tree.LayoutFrameID != layout.FrameID() {
		t.Fatalf("layout frame %q does not match the live layout %+v (%v)", tree.LayoutFrameID, layout, err)
	}
	if !strings.Contains(tree.Adapter, "windows/uia verified") {
		t.Fatalf("adapter = %q", tree.Adapter)
	}

	// The ref tree is stable across observations of an unchanged window.
	second, _ := s.handleFrame([]byte(refTreeFrame(2, fact)), dispatch)
	if !second.OK || second.RefTree.Text != tree.Text || second.RefTree.SnapshotID == tree.SnapshotID {
		t.Fatalf("ref tree not stable:\n%s\n---\n%+v", tree.Text, second.RefTree)
	}
	if second.RefTree.Diff == nil || len(second.RefTree.Diff.Changes) != 0 {
		t.Fatalf("unchanged window diffed: %+v", second.RefTree.Diff)
	}

	// A stale target is refused before dispatch: the first snapshot is no
	// longer current. readOnlyNativeDispatch fails the test if the action
	// reaches native code.
	button := runtimeIDFor(t, first.Elements, "SG94 Button")
	stale := fmt.Sprintf(`{"id":3,"protocol":"orcel-computer-host/1","op":"semantic_action","semantic_action":"invoke","element_runtime_id":%q,"snapshot_id":%q,"hwnd":%d,"expected_pid":%d,"expected_start_generation":%d,"expected_window_nonce":%d}`,
		button, tree.SnapshotID, fact.HWND, fact.Process.PID, fact.Process.StartGeneration, fact.WindowNonce)
	refused, _ := s.handleFrame([]byte(stale), dispatch)
	if refused.OK || refused.Error == nil || refused.Error.Code != "target_stale" {
		t.Fatalf("stale snapshot action was not refused: %+v", refused)
	}

	// Window layout validation for GUI coordinates: moving the test window
	// makes the issued frame stale. Checked without sending input.
	planned := boundHostRequest(4, "input_click", fact)
	planned.LayoutFrameID = tree.LayoutFrameID
	if err := checkLayoutFrame(planned); err != nil {
		t.Fatalf("the current frame was refused: %v", err)
	}
	setWindowPos := user32.NewProc("SetWindowPos")
	if ok, _, callErr := setWindowPos.Call(uintptr(helper.hwnd), 0, 200, 170, 460, 300, 0x0004|0x0010); ok == 0 {
		t.Fatalf("test-only SetWindowPos failed: %v", callErr)
	}
	time.Sleep(300 * time.Millisecond)
	if err := checkLayoutFrame(planned); !errors.Is(err, semantic.ErrStaleLayout) {
		t.Fatalf("a moved window kept its frame: %v", err)
	}
	moved, _ := s.handleFrame([]byte(refTreeFrame(5, fact)), dispatch)
	if !moved.OK || moved.RefTree.LayoutFrameID == tree.LayoutFrameID {
		t.Fatalf("the frame did not follow the move: %+v", moved.RefTree)
	}

	if os.Getenv("ORCEL_W201_SEMANTIC_ACTIONS") != "1" {
		t.Log("live identity check of a semantic action skipped (set ORCEL_W201_SEMANTIC_ACTIONS=1 on a disposable host)")
		return
	}
	action := boundHostRequest(6, "semantic_action", fact)
	action.SemanticAction = "invoke"
	action.ElementRuntimeID = button
	action.ExpectedElement = &semantic.Expectation{ControlType: "Button", Name: "Not The Button"}
	if resp := nativeSemanticAction(action); resp.OK || resp.Error == nil || resp.Error.Code != "target_stale" {
		t.Fatalf("a mismatched live target was not refused: %+v", resp)
	}
	// The WinForms button reports a non-empty UIA AutomationId (its control
	// id). A different expected id is refused before the pattern is invoked.
	observedButton := elementNamed(t, first.Elements, "SG94 Button")
	action.ExpectedElement = &semantic.Expectation{ControlType: "Button", AutomationID: observedButton.AutomationID + "-changed", Name: "SG94 Button"}
	if resp := nativeSemanticAction(action); resp.OK || resp.Error == nil || resp.Error.Code != "target_stale" {
		t.Fatalf("a live target with another automation id was not refused: %+v", resp)
	}
	// An expectation without an automation id names the same element.
	action.ExpectedElement = &semantic.Expectation{ControlType: "Button", Name: "SG94 Button"}
	if resp := nativeSemanticAction(action); !resp.OK {
		t.Fatalf("the matching live target was refused: %+v", resp.Error)
	}
	// The full observed identity, as orceld sends it, matches too.
	action.ExpectedElement = &semantic.Expectation{ControlType: observedButton.ControlType, AutomationID: observedButton.AutomationID, Name: observedButton.Name}
	if resp := nativeSemanticAction(action); !resp.OK {
		t.Fatalf("the observed identity of the live target was refused: %+v", resp.Error)
	}
}

type processMemoryCounters struct {
	Cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func processMemory(handle windows.Handle) processMemoryCounters {
	var counters processMemoryCounters
	counters.Cb = uint32(unsafe.Sizeof(counters))
	proc := kernel32.NewProc("K32GetProcessMemoryInfo")
	_, _, _ = proc.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.Cb))
	return counters
}

func percentile(values []time.Duration, p float64) float64 {
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := int(p * float64(len(sorted)-1))
	return float64(sorted[index].Microseconds()) / 1000
}

// TestW201RefTreeBaseline prints the latency and memory baseline of a ref
// tree snapshot of the disposable window. It only reads. It runs when
// ORCEL_W201_BASELINE=1; with ORCEL_COMPUTER_HOST_BIN it also measures the
// end-to-end path through the built host (supervisor plus one sacrificial
// worker per observation).
func TestW201RefTreeBaseline(t *testing.T) {
	if os.Getenv("ORCEL_W201_BASELINE") != "1" {
		t.Skip("set ORCEL_W201_BASELINE=1 to measure the W2-01 baseline")
	}
	helper := launchNativeTestWindow(t)
	fact := findNativeTestWindow(t, helper.title)
	const rounds = 30
	s := newSupervisor()
	var read, build []time.Duration
	var elementBytes, textBytes int
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for round := 0; round < rounds; round++ {
		req := boundHostRequest(uint64(round+1), "observe_window", fact)
		req.MaxNodes, req.MaxDepth, req.RefTree = maxTreeNodes, maxTreeDepth, true
		start := time.Now()
		resp := nativeObserveWindow(req)
		read = append(read, time.Since(start))
		if !resp.OK {
			t.Fatalf("observation failed: %+v", resp.Error)
		}
		binding, _ := bindingOf(req)
		start = time.Now()
		built, err := s.buildRefTree(binding, resp.Elements, resp.Layout)
		build = append(build, time.Since(start))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(resp.Elements)
		elementBytes, textBytes = len(raw), len(built.Text)
	}
	runtime.ReadMemStats(&after)
	memory := processMemory(windows.CurrentProcess())
	report := map[string]any{
		"rounds":                   rounds,
		"uia_read_ms_p50":          percentile(read, 0.5),
		"uia_read_ms_p95":          percentile(read, 0.95),
		"ref_tree_build_ms_p50":    percentile(build, 0.5),
		"ref_tree_build_ms_p95":    percentile(build, 0.95),
		"element_json_bytes":       elementBytes,
		"ref_tree_text_bytes":      textBytes,
		"heap_alloc_bytes_per_obs": (after.TotalAlloc - before.TotalAlloc) / rounds,
		"in_process_peak_ws_bytes": memory.PeakWorkingSetSize,
		"in_process_ws_bytes":      memory.WorkingSetSize,
		"go_version":               runtime.Version(),
	}
	if bin := os.Getenv("ORCEL_COMPUTER_HOST_BIN"); bin != "" {
		cmd := exec.Command(bin)
		stdin, _ := cmd.StdinPipe()
		stdout, _ := cmd.StdoutPipe()
		if err := cmd.Start(); err != nil {
			t.Fatalf("start host: %v", err)
		}
		defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
		reader := bufio.NewReaderSize(stdout, 1<<20)
		var endToEnd []time.Duration
		for round := 0; round < rounds; round++ {
			start := time.Now()
			if _, err := stdin.Write([]byte(refTreeFrame(round+1, fact) + "\n")); err != nil {
				t.Fatal(err)
			}
			line, err := reader.ReadBytes('\n')
			if err != nil {
				t.Fatal(err)
			}
			endToEnd = append(endToEnd, time.Since(start))
			var resp hostResponse
			if json.Unmarshal(line, &resp) != nil || !resp.OK || resp.RefTree == nil {
				t.Fatalf("host ref tree failed: %s", line)
			}
			report["host_response_bytes"] = len(line)
		}
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(cmd.Process.Pid))
		if err == nil {
			hostMemory := processMemory(handle)
			report["host_supervisor_peak_ws_bytes"] = hostMemory.PeakWorkingSetSize
			_ = windows.CloseHandle(handle)
		}
		report["host_end_to_end_ms_p50"] = percentile(endToEnd, 0.5)
		report["host_end_to_end_ms_p95"] = percentile(endToEnd, 0.95)
	}
	encoded, _ := json.Marshal(report)
	t.Logf("W201-BASELINE %s", encoded)
	fmt.Printf("W201-BASELINE %s\n", encoded)
}
