// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// Tests marked PORT adapt microsoft/Hybrid-Computer-Use at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1 (MIT):
// computer-use/internal/core/ax_renderer_test.go (blob
// 772253bde17d846262787cba0d551e3c979f41fa),
// ax_semantic_diff_test.go (blob f62294b75bec5e5bdbf972bef489e15511e4113a)
// and ax_batch_plan_test.go (blob 20d1f57c0c3250014c5c47cd1697777864a4df26).

package semantic

import (
	"errors"
	"strings"
	"testing"
)

func TestRenderedTreeUsesTheDonorLineShape(t *testing.T) {
	snapshot, _ := NewRegistry().Observe(testBinding, testTree())
	text, truncated := Render(snapshot, 0)
	if truncated {
		t.Fatal("small tree was truncated")
	}
	want := strings.Join([]string{
		`- window "Orcel Test" [ref=r1]:`,
		` - button "OK" [ref=r2]`,
		` - textbox "Value" = "hello" [ref=r3]`,
		` - checkbox "Remember" [checked=true] [ref=r5]`,
		``,
	}, "\n")
	if text != want {
		t.Fatalf("rendered tree:\n%s\nwant:\n%s", text, want)
	}
}

// PORT of TestAllModelRenderersHideProviderDiagnostics, for the Orcel
// secret rule: a password value is never rendered, and runtime ids (the
// provider identity) are not in the model-facing text.
func TestRendererHidesPasswordValuesAndProviderIdentity(t *testing.T) {
	tree := []Node{{RuntimeID: "9.1", ProviderRole: "Window", Name: "Login", Enabled: true, Children: []Node{
		{RuntimeID: "9.2", ProviderRole: "Edit", Name: "Password", Enabled: true, Value: str("hunter2"), ValueHidden: true},
	}}}
	snapshot, _ := NewRegistry().Observe(testBinding, tree)
	text, _ := Render(snapshot, 0)
	if strings.Contains(text, "hunter2") || !strings.Contains(text, "[value=hidden]") {
		t.Fatalf("password value leaked or unmarked:\n%s", text)
	}
	if strings.Contains(text, "9.2") {
		t.Fatalf("runtime id leaked into the rendered tree:\n%s", text)
	}
}

func TestRenderBudgetEndsWithAnOmissionNote(t *testing.T) {
	children := make([]Node, 0, 400)
	for index := 0; index < 400; index++ {
		children = append(children, Node{RuntimeID: "c." + strings.Repeat("x", index%7) + string(rune('A'+index%26)) + strings.Repeat("y", index/26),
			ProviderRole: "Button", Name: strings.Repeat("n", 40), Enabled: true})
	}
	snapshot, _ := NewRegistry().Observe(testBinding, []Node{{RuntimeID: "root", ProviderRole: "Window", Enabled: true, Children: children}})
	text, truncated := Render(snapshot, 4096)
	if !truncated || len(text) > 4096 || !strings.HasSuffix(text, "more nodes omitted by the output budget\n") {
		t.Fatalf("budget not applied: truncated=%v len=%d tail=%q", truncated, len(text), text[len(text)-80:])
	}
}

// PORT of TestWeakDuplicateCohortDoesNotInventObjectContinuity: nodes
// without a ref are never reported as changed, only counted.
func TestDiffReportsOnlyRefKeyedChanges(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	changed := testTree()
	changed[0].Children[0].Enabled = false                  // r2 state
	changed[0].Children[1].Value = str("world")             // r3 property
	changed[0].Children[2].Children = nil                   // r5 removed
	changed[0].Children = append(changed[0].Children, Node{ // new ref
		RuntimeID: "42.9", ProviderRole: "Button", Name: "Apply", Enabled: true})
	changed[0].Children = append(changed[0].Children, Node{ProviderRole: "Text", Name: "unkeyed", Enabled: true})
	second, _ := registry.Observe(testBinding, changed)
	diff := Compare(first, second)
	got := map[DiffKind][]string{}
	for _, change := range diff.Changes {
		got[change.Kind] = append(got[change.Kind], change.Ref)
	}
	if strings.Join(got[DiffStateChanged], ",") != "r2" || strings.Join(got[DiffChanged], ",") != "r3" ||
		strings.Join(got[DiffRemoved], ",") != "r5" || len(got[DiffAdded]) != 1 {
		t.Fatalf("diff = %+v", diff.Changes)
	}
	if diff.Unkeyed != 1 {
		t.Fatalf("unkeyed = %d, want 1", diff.Unkeyed)
	}
	text := diff.Text()
	if !strings.Contains(text, `~ button "OK" [ref=r2] -> button "OK" [disabled=true] [ref=r2]`) ||
		!strings.Contains(text, `- checkbox "Remember" [checked=true] [ref=r5]`) {
		t.Fatalf("diff text:\n%s", text)
	}
}

func TestDiffRefusesDifferentWindows(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	other := testBinding
	other.Window++
	second, _ := registry.Observe(other, testTree())
	if Compare(first, second) != nil {
		t.Fatal("snapshots of different windows were compared")
	}
}

// PORT of TestAXBatchPlanGroupsOnlyUntargetedKeypresses.
func TestBatchPlanGroupsOnlyUntargetedKeypresses(t *testing.T) {
	plan, err := CompileBatchPlan(testBinding, []BatchAction{
		{Type: "keypress", Key: "DOWN"}, {Type: "keypress", Key: "ENTER"}, {Type: "keypress", Key: "A"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.RequiresMutationLease {
		t.Fatal("a batch plan must require a mutation lease")
	}
	for index, step := range plan.Steps {
		if step.Class != OrderedInput || step.PreConsistency != WindowIdentity || step.OrderedInputRun != 1 {
			t.Fatalf("step %d not in one ordered run: %+v", index, step)
		}
	}
	if plan.Steps[0].Boundary != NoBoundary || plan.Steps[1].Boundary != NoBoundary ||
		plan.Steps[2].Boundary != TransactionBoundary || plan.Steps[2].PostConsistency != CanonicalWindow {
		t.Fatalf("ordered run boundaries: %+v", plan.Steps)
	}
}

// PORT of TestAXBatchPlanSeparatesRunsAtCanonicalActions.
func TestBatchPlanSeparatesRunsAtCanonicalActions(t *testing.T) {
	plan, err := CompileBatchPlan(testBinding, []BatchAction{
		{Type: "invoke", Ref: "r1"}, {Type: "keypress", Key: "DOWN"}, {Type: "keypress", Key: "ENTER"},
		{Type: "set_value", Ref: "r2", Value: "6"}, {Type: "keypress", Key: "TAB"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []ExecutionClass{SingleAction, OrderedInput, OrderedInput, SingleAction, OrderedInput}
	for index, class := range want {
		if plan.Steps[index].Class != class {
			t.Fatalf("step %d class %q, want %q", index, plan.Steps[index].Class, class)
		}
	}
	if plan.Steps[0].Boundary != TargetedBoundary || plan.Steps[2].Boundary != NextActionBoundary ||
		plan.Steps[3].Boundary != TargetedBoundary || plan.Steps[4].Boundary != TransactionBoundary ||
		plan.Steps[1].OrderedInputRun == plan.Steps[4].OrderedInputRun {
		t.Fatalf("boundaries: %+v", plan.Steps)
	}
}

func TestBatchPlanBoundsAndDispatchIsDeniedByDefault(t *testing.T) {
	if BatchDispatchEnabled {
		t.Fatal("batched actions must stay denied until a grain amendment enables them")
	}
	bad := [][]BatchAction{
		nil,
		{{Type: "invoke"}},
		{{Type: "invoke", Ref: "w1"}},
		{{Type: "invoke", Ref: "e1"}},
		{{Type: "wait", WaitMS: MaxWaitMS + 1}},
		{{Type: "wait", WaitMS: 5000}, {Type: "wait", WaitMS: 5000}, {Type: "wait", WaitMS: 1}},
		{{Type: "launch", Ref: "r1"}},
		{{Type: "close", Ref: "r1"}},
	}
	for index, actions := range bad {
		if _, err := CompileBatchPlan(testBinding, actions); err == nil {
			t.Errorf("case %d compiled: %+v", index, actions)
		}
	}
	long := make([]BatchAction, MaxBatchSteps+1)
	for index := range long {
		long[index] = BatchAction{Type: "keypress", Key: "A"}
	}
	if _, err := CompileBatchPlan(testBinding, long); err == nil {
		t.Error("an over-long plan compiled")
	}
	if _, err := CompileBatchPlan(Binding{}, []BatchAction{{Type: "keypress", Key: "A"}}); err == nil {
		t.Error("an unbound plan compiled")
	}
}

func TestLayoutFrameDetectsGeometryChanges(t *testing.T) {
	layout := Layout{
		Desktop: Rect{0, 0, 1920, 1080}, Window: Rect{80, 80, 500, 340},
		Client: Rect{88, 111, 492, 332}, DPI: 96, Handle: 0x1001,
	}
	frame := layout.FrameID()
	if !strings.HasPrefix(frame, "l1:") || len(frame) != 3+64 || frame != layout.FrameID() {
		t.Fatalf("frame id %q is not stable l1:<64 hex>", frame)
	}
	if err := CheckFrame(frame, layout); err != nil {
		t.Fatalf("current frame refused: %v", err)
	}
	if err := CheckFrame("", layout); err != nil {
		t.Fatalf("unplanned input refused: %v", err)
	}
	moved := layout
	moved.Window = Rect{81, 80, 501, 340}
	scaled := layout
	scaled.DPI = 144
	for _, changed := range []Layout{moved, scaled} {
		if err := CheckFrame(frame, changed); !errors.Is(err, ErrStaleLayout) {
			t.Fatalf("changed layout admitted: %v", err)
		}
	}
	if diff := LayoutDifference(layout, moved); len(diff) != 1 || diff[0] != "window_rect" {
		t.Fatalf("difference = %v", diff)
	}
	minimized := layout
	minimized.Window = Rect{-32000, -32000, -32000, -32000}
	if err := CheckFrame(minimized.FrameID(), minimized); !errors.Is(err, ErrStaleLayout) {
		t.Fatalf("a minimized window carried a frame: %v", err)
	}
}

func TestLayoutPointStaysInsideWindowAndDesktop(t *testing.T) {
	layout := Layout{Desktop: Rect{0, 0, 1920, 1080}, Window: Rect{1800, 80, 2200, 340}, Handle: 1}
	if x, y, err := CheckPoint(layout, 10, 10); err != nil || x != 1810 || y != 90 {
		t.Fatalf("inside point = %d,%d,%v", x, y, err)
	}
	for _, point := range [][2]int{{-1, 0}, {0, -1}, {400, 0}, {0, 260}, {200, 10}} {
		if _, _, err := CheckPoint(layout, point[0], point[1]); err == nil {
			t.Errorf("point %v admitted", point)
		}
	}
}

func TestEveryPlatformReportsItsAdapter(t *testing.T) {
	adapter := CurrentPlatform()
	if adapter.Platform == "" || adapter.Backend == "" {
		t.Fatalf("adapter = %+v", adapter)
	}
	if adapter.Platform != "windows" && adapter.Verification != Unverified {
		t.Fatalf("non-Windows adapter must be marked UNVERIFIED: %+v", adapter)
	}
}
