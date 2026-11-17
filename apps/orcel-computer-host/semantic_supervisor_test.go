// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/TheHalfMoon/Orcel/apps/orcel-computer-host/third_party/hcu/semantic"
)

const boundObserve = `"hwnd":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14`

func strPtr(value string) *string { return &value }

// fakeTree is what a worker returns for the bound window.
func fakeTree(buttonName string) []elementFact {
	return []elementFact{{
		RuntimeID: "42.1", ControlType: "Window", Name: "Orcel W2-01", Enabled: true, Children: []elementFact{
			{RuntimeID: "42.2", ControlType: "Button", AutomationID: "ok", Name: buttonName, Enabled: true, Patterns: []string{"Invoke"}, Children: []elementFact{}},
			{RuntimeID: "42.3", ControlType: "Edit", AutomationID: "field", Name: "Value", Enabled: true, Value: strPtr("draft"), Patterns: []string{"Value"}, Children: []elementFact{}},
			{RuntimeID: "42.4", ControlType: "Edit", Name: "Password", Enabled: true, ValueIsPassword: true, Children: []elementFact{}},
		},
	}}
}

// recordingDispatch answers like a worker and records every request. A
// semantic_action is answered as completed, but only the supervisor tests
// below decide whether one may reach it.
type recordingDispatch struct {
	t      *testing.T
	tree   []elementFact
	seen   []hostRequest
	layout *semantic.Layout
}

func (d *recordingDispatch) dispatch(req hostRequest) hostResponse {
	d.seen = append(d.seen, req)
	switch req.Op {
	case "observe_window":
		resp := success(req.ID)
		resp.Elements = d.tree
		if req.RefTree {
			resp.Layout = d.layout
		}
		return resp
	case "semantic_action":
		resp := success(req.ID)
		resp.Action = &actionFact{State: "completed", Action: "semantic_" + req.SemanticAction}
		return resp
	default:
		d.t.Fatalf("unexpected native op %q", req.Op)
		return hostResponse{}
	}
}

func (d *recordingDispatch) ops() []string {
	out := []string{}
	for _, req := range d.seen {
		out = append(out, req.Op)
	}
	return out
}

func observeRefTree(t *testing.T, s *supervisor, d *recordingDispatch, id int) hostResponse {
	t.Helper()
	line := fmt.Sprintf(`{"id":%d,"protocol":"orcel-computer-host/2","op":"observe_window","ref_tree":true,%s}`, id, boundObserve)
	resp, _ := s.handleFrame([]byte(line), d.dispatch)
	if !resp.OK || resp.RefTree == nil {
		t.Fatalf("ref tree observation failed: %+v", resp)
	}
	return resp
}

func refOf(t *testing.T, tree *refTreeFact, runtimeID string) string {
	t.Helper()
	for _, entry := range tree.Refs {
		if entry.RuntimeID == runtimeID {
			return entry.Ref
		}
	}
	t.Fatalf("no ref for %s in %+v", runtimeID, tree.Refs)
	return ""
}

func TestSemanticBatchIsDeniedByDefault(t *testing.T) {
	s := newSupervisor()
	hello, _ := s.handleFrame([]byte(`{"id":1,"protocol":"orcel-computer-host/2","op":"hello"}`), refuseDispatch(t))
	if fact := hello.Capabilities["semantic_batch"]; fact.Support != "refused" || fact.Reason != "grain_amendment_required" {
		t.Fatalf("semantic_batch capability = %+v", fact)
	}
	for _, line := range []string{
		`{"id":2,"protocol":"orcel-computer-host/1","op":"semantic_batch"}`,
		`{"id":2,"protocol":"orcel-computer-host/2","op":"semantic_batch",` + boundObserve + `}`,
	} {
		resp, _ := s.handleFrame([]byte(line), refuseDispatch(t))
		if resp.OK || resp.Error == nil || resp.Error.Code != "capability_denied" {
			t.Fatalf("semantic_batch was not denied: %+v", resp)
		}
	}
	if semantic.BatchDispatchEnabled {
		t.Fatal("batch dispatch must stay disabled until a grain amendment")
	}
}

func TestRefTreeObservationReturnsCompactTreeAndFoldsLayout(t *testing.T) {
	s := newSupervisor()
	layout := semantic.Layout{Desktop: semantic.Rect{Right: 1920, Bottom: 1080}, Window: semantic.Rect{Left: 10, Top: 10, Right: 410, Bottom: 310}, Handle: 11}
	d := &recordingDispatch{t: t, tree: fakeTree("OK"), layout: &layout}
	resp := observeRefTree(t, s, d, 3)
	if resp.Layout != nil {
		t.Fatal("the worker's raw layout was forwarded")
	}
	tree := resp.RefTree
	if tree.LayoutFrameID != layout.FrameID() || !strings.HasPrefix(tree.SnapshotID, "s") || tree.Generation != 1 {
		t.Fatalf("ref tree header = %+v", tree)
	}
	for _, want := range []string{`- window "Orcel W2-01" [ref=r1]:`, ` - button "OK" [ref=r2]`, ` - textbox "Value" = "draft" [ref=r3]`, `[value=hidden] [ref=r4]`} {
		if !strings.Contains(tree.Text, want) {
			t.Fatalf("ref tree text lacks %q:\n%s", want, tree.Text)
		}
	}
	if len(resp.Elements) == 0 {
		t.Fatal("the element tree orceld registers was dropped")
	}
	if got := d.ops(); len(got) != 1 || got[0] != "observe_window" || !d.seen[0].RefTree {
		t.Fatalf("native requests = %v", got)
	}
	raw, _ := json.Marshal(resp)
	for _, marker := range []string{"token", "secret", "credential", "approval", "lease", "admin"} {
		if strings.Contains(strings.ToLower(string(raw)), marker) {
			t.Fatalf("ref tree response contains %q", marker)
		}
	}
	plain, _ := s.handleFrame([]byte(`{"id":4,"protocol":"orcel-computer-host/2","op":"observe_window",`+boundObserve+`}`), d.dispatch)
	if plain.RefTree != nil || d.seen[1].RefTree {
		t.Fatal("a plain observation produced a ref tree")
	}
}

// Orcel regression: the ref tree is stable across identical observations,
// and a changed element shows in the semantic diff under its ref.
func TestRefTreeIsStableAndDiffsUnderRefs(t *testing.T) {
	s := newSupervisor()
	d := &recordingDispatch{t: t, tree: fakeTree("OK")}
	first := observeRefTree(t, s, d, 5).RefTree
	second := observeRefTree(t, s, d, 6).RefTree
	if first.Text != second.Text || first.SnapshotID == second.SnapshotID {
		t.Fatalf("ref tree not stable:\n%s\n---\n%s", first.Text, second.Text)
	}
	if second.Diff == nil || len(second.Diff.Changes) != 0 || second.Diff.FromSnapshot != first.SnapshotID {
		t.Fatalf("identical observation diff = %+v", second.Diff)
	}
	d.tree = fakeTree("Apply")
	third := observeRefTree(t, s, d, 7).RefTree
	if refOf(t, third, "42.2") != refOf(t, first, "42.2") {
		t.Fatal("a renamed element lost its ref")
	}
	if !strings.Contains(third.DiffText, `~ button "OK" [ref=r2] -> button "Apply" [ref=r2]`) {
		t.Fatalf("diff text:\n%s", third.DiffText)
	}
}

func semanticActionLine(id int, snapshotID, runtimeID string) string {
	return fmt.Sprintf(`{"id":%d,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"invoke","element_runtime_id":%q,"snapshot_id":%q,%s}`,
		id, runtimeID, snapshotID, boundObserve)
}

// Orcel regression: a stale target is refused by the supervisor before any
// native dispatch.
func TestStaleSnapshotTargetIsRefusedBeforeDispatch(t *testing.T) {
	s := newSupervisor()
	d := &recordingDispatch{t: t, tree: fakeTree("OK")}
	first := observeRefTree(t, s, d, 8).RefTree
	observeRefTree(t, s, d, 9)
	before := len(d.seen)
	cases := []string{
		semanticActionLine(10, first.SnapshotID, "42.2"),                          // an older snapshot
		semanticActionLine(11, "s00000000.1", "42.2"),                             // another host process
		semanticActionLine(12, strings.Repeat("s", maxSnapshotIDBytes+1), "42.2"), // over the bound
	}
	for index, line := range cases {
		resp, _ := s.handleFrame([]byte(line), d.dispatch)
		if resp.OK || resp.Error == nil || (resp.Error.Code != "target_stale" && resp.Error.Code != "invalid_request") {
			t.Fatalf("case %d: stale action not refused: %+v", index, resp)
		}
	}
	if len(d.seen) != before {
		t.Fatalf("a refused action reached native dispatch: %v", d.ops()[before:])
	}
	// A runtime id that is not in the current snapshot is refused too.
	current := observeRefTree(t, s, d, 13).RefTree
	resp, _ := s.handleFrame([]byte(semanticActionLine(14, current.SnapshotID, "42.99")), d.dispatch)
	if resp.OK || resp.Error.Code != "target_stale" {
		t.Fatalf("unknown runtime id admitted: %+v", resp)
	}
}

// The current snapshot narrows the action to the observed element: the
// worker receives the observed identity to compare with the live element,
// and after the action the snapshot can no longer address anything.
func TestCurrentSnapshotSendsTheObservedIdentityThenExpires(t *testing.T) {
	s := newSupervisor()
	d := &recordingDispatch{t: t, tree: fakeTree("OK")}
	tree := observeRefTree(t, s, d, 15).RefTree
	resp, _ := s.handleFrame([]byte(semanticActionLine(16, tree.SnapshotID, "42.2")), d.dispatch)
	if !resp.OK {
		t.Fatalf("current-snapshot action refused: %+v", resp)
	}
	sent := d.seen[len(d.seen)-1]
	if sent.Op != "semantic_action" || sent.ExpectedElement == nil ||
		*sent.ExpectedElement != (semantic.Expectation{ControlType: "Button", AutomationID: "ok", Name: "OK"}) {
		t.Fatalf("worker did not receive the observed identity: %+v", sent)
	}
	again, _ := s.handleFrame([]byte(semanticActionLine(17, tree.SnapshotID, "42.3")), d.dispatch)
	if again.OK || again.Error.Code != "target_stale" {
		t.Fatalf("snapshot still addressed elements after an action: %+v", again)
	}
	mismatch := strings.Replace(semanticActionLine(18, observeRefTree(t, s, d, 19).RefTree.SnapshotID, "42.2"),
		`"snapshot_id"`, `"expected_element":{"control_type":"Button","automation_id":"ok","name":"Cancel"},"snapshot_id"`, 1)
	count := len(d.seen)
	refused, _ := s.handleFrame([]byte(mismatch), d.dispatch)
	if refused.OK || refused.Error.Code != "target_stale" || len(d.seen) != count {
		t.Fatalf("an expectation contradicting the snapshot was dispatched: %+v", refused)
	}
}

// Without a snapshot the host behaves as before: the request orceld sent
// (after its approval) is dispatched unchanged, with any expected_element
// orceld attached. A ref is never an action address at the host: only an
// exact runtime id orceld approved is.
func TestActionsAreAddressedOnlyByApprovedRuntimeIDs(t *testing.T) {
	s := newSupervisor()
	d := &recordingDispatch{t: t, tree: fakeTree("OK")}
	line := `{"id":20,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"invoke","element_runtime_id":"42.2","expected_element":{"control_type":"Button","automation_id":"ok","name":"OK"},` + boundObserve + `}`
	resp, _ := s.handleFrame([]byte(line), d.dispatch)
	if !resp.OK || len(d.seen) != 1 || d.seen[0].ExpectedElement == nil || d.seen[0].ExpectedElement.Name != "OK" {
		t.Fatalf("plain action with expectation = %+v, sent %+v", resp, d.seen)
	}
	for _, refOnly := range []string{
		`{"id":21,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"invoke","element_ref":"r2",` + boundObserve + `}`,
		`{"id":22,"protocol":"orcel-computer-host/2","op":"semantic_action","semantic_action":"invoke","snapshot_id":"s1.1",` + boundObserve + `}`,
	} {
		refused, _ := s.handleFrame([]byte(refOnly), d.dispatch)
		if refused.OK || refused.Error.Code != "invalid_request" {
			t.Fatalf("an action without an approved runtime id was admitted: %+v", refused)
		}
	}
	if len(d.seen) != 1 {
		t.Fatalf("refused actions reached dispatch: %v", d.ops())
	}
}

func TestSemanticFieldsAreConfinedAndBounded(t *testing.T) {
	pid, start, nonce, tick := uint32(12), uint64(13), uint64(14), uint32(1)
	x := 1
	bound := func(op string) hostRequest {
		return hostRequest{Protocol: protocolGeneration, Op: op, HWND: 11, ExpectedPID: &pid, ExpectedStartGeneration: &start, ExpectedWindowNonce: &nonce}
	}
	refused := []hostRequest{}
	r := bound("capture_window")
	r.RefTree = true
	refused = append(refused, r)
	r = bound("observe_window")
	r.RefTree, r.ElementRuntimeID = true, "42.1"
	refused = append(refused, r)
	r = bound("observe_window")
	r.SnapshotID = "s1.1"
	refused = append(refused, r)
	r = bound("observe_window")
	r.ExpectedElement = &semantic.Expectation{ControlType: "Button"}
	refused = append(refused, r)
	r = bound("semantic_action")
	r.SemanticAction, r.ElementRuntimeID = "invoke", "1"
	r.ExpectedElement = &semantic.Expectation{Name: strings.Repeat("n", maxExpectedTextBytes+1)}
	refused = append(refused, r)
	r = bound("input_type_text")
	r.Text, r.ExpectedLastInputTick, r.LayoutFrameID = "a", &tick, "l1:abc"
	refused = append(refused, r)
	r = bound("input_click")
	r.X, r.Y, r.Button, r.ClickCount, r.ExpectedLastInputTick, r.LayoutFrameID = &x, &x, "left", 1, &tick, "frame"
	refused = append(refused, r)
	for index, req := range refused {
		if problem := validateRequest(req); problem == nil || problem.Code != "invalid_request" {
			t.Errorf("case %d (%s) accepted: %+v", index, req.Op, problem)
		}
	}
	ok := bound("input_click")
	ok.X, ok.Y, ok.Button, ok.ClickCount, ok.ExpectedLastInputTick, ok.LayoutFrameID = &x, &x, "left", 1, &tick, "l1:"+strings.Repeat("a", 64)
	if problem := validateRequest(ok); problem != nil {
		t.Fatalf("a well-formed layout frame was refused: %+v", problem)
	}
}

// /1 frames stay byte-identical: the new fields are omitted when unset, so
// a /1 request reaches the worker exactly as before.
func TestSemanticFieldsAreOmittedFromUnchangedRequests(t *testing.T) {
	raw, err := json.Marshal(hostRequest{ID: 1, Protocol: protocolGeneration, Op: "ping"})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"id":1,"protocol":"orcel-computer-host/1","op":"ping"}` {
		t.Fatalf("unset W2-01 fields were serialized: %s", raw)
	}
}
