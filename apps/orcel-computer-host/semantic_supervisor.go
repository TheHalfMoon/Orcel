// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0
//
// W2-01: the supervisor side of the HCU-derived semantic layer
// (third_party/hcu/semantic). The long-lived supervisor still performs no
// native work: it keeps the ref registry, turns a worker's bounded tree read
// into the compact ref tree, and narrows semantic actions to the window's
// current snapshot. It never admits a request the host would otherwise
// refuse, never dispatches without a request from orceld, and adds no
// authority: orceld still approves every action before it reaches the host.

package main

import (
	"errors"
	"strings"

	"github.com/TheHalfMoon/Orcel/apps/orcel-computer-host/third_party/hcu/semantic"
)

// refEntryFact maps one short ref to the provider identity orceld already
// holds for the element. The runtime id is for orceld, never for a model.
type refEntryFact struct {
	Ref         string `json:"ref"`
	RuntimeID   string `json:"runtime_id"`
	Role        string `json:"role"`
	Fingerprint string `json:"fingerprint"`
}

// refTreeFact is the compact ref tree of one observation.
type refTreeFact struct {
	SnapshotID    string         `json:"snapshot_id"`
	Generation    uint64         `json:"generation"`
	Text          string         `json:"text"`
	Truncated     bool           `json:"truncated"`
	Refs          []refEntryFact `json:"refs"`
	Diff          *semantic.Diff `json:"diff,omitempty"`
	DiffText      string         `json:"diff_text,omitempty"`
	LayoutFrameID string         `json:"layout_frame_id,omitempty"`
	Adapter       string         `json:"adapter"`
}

type supervisor struct {
	refs *semantic.Registry
}

func newSupervisor() *supervisor {
	return &supervisor{refs: semantic.NewRegistry()}
}

func bindingOf(req hostRequest) (semantic.Binding, bool) {
	if req.HWND == 0 || req.ExpectedPID == nil || req.ExpectedStartGeneration == nil || req.ExpectedWindowNonce == nil {
		return semantic.Binding{}, false
	}
	return semantic.Binding{
		Window:          req.HWND,
		PID:             *req.ExpectedPID,
		StartGeneration: *req.ExpectedStartGeneration,
		WindowNonce:     *req.ExpectedWindowNonce,
	}, true
}

func isPointerInput(op string) bool {
	switch op {
	case "input_move", "input_click", "input_drag", "input_scroll":
		return true
	default:
		return false
	}
}

// validateSemanticFields keeps every W2-01 field on the one operation that
// reads it, bounded.
func validateSemanticFields(req hostRequest) *hostError {
	if req.RefTree && (req.Op != "observe_window" || req.ElementRuntimeID != "") {
		return &hostError{Code: "invalid_request", Message: "ref_tree is accepted only by a whole-window observe_window"}
	}
	if req.SnapshotID != "" {
		if req.Op != "semantic_action" {
			return &hostError{Code: "invalid_request", Message: "snapshot_id is accepted only by semantic_action"}
		}
		if len(req.SnapshotID) > maxSnapshotIDBytes {
			return &hostError{Code: "invalid_request", Message: "snapshot_id exceeds the bounded limit"}
		}
	}
	if req.ExpectedElement != nil {
		if req.Op != "semantic_action" {
			return &hostError{Code: "invalid_request", Message: "expected_element is accepted only by semantic_action"}
		}
		expected := req.ExpectedElement
		if len(expected.ControlType) > maxKeyBytes || len(expected.AutomationID) > maxExpectedTextBytes || len(expected.Name) > maxExpectedTextBytes {
			return &hostError{Code: "invalid_request", Message: "expected_element exceeds the bounded limit"}
		}
	}
	if req.LayoutFrameID != "" {
		if !isPointerInput(req.Op) {
			return &hostError{Code: "invalid_request", Message: "layout_frame_id is accepted only by pointer input"}
		}
		if len(req.LayoutFrameID) > maxLayoutFrameBytes || !strings.HasPrefix(req.LayoutFrameID, "l1:") {
			return &hostError{Code: "invalid_request", Message: "layout_frame_id is malformed"}
		}
	}
	return nil
}

// dispatch runs one native request with the semantic narrowing around it.
func (s *supervisor) dispatch(req hostRequest, native func(hostRequest) hostResponse) hostResponse {
	binding, bound := bindingOf(req)
	if req.Op == "semantic_action" && req.SnapshotID != "" {
		entry, err := s.refs.CheckTarget(binding, req.SnapshotID, req.ElementRuntimeID)
		if err != nil {
			return failure(req.ID, "target_stale", err.Error())
		}
		observed := entry.Expectation()
		if req.ExpectedElement == nil {
			req.ExpectedElement = &observed
		} else if semantic.CheckLive(observed, req.ExpectedElement.ControlType, req.ExpectedElement.AutomationID, req.ExpectedElement.Name) != nil {
			return failure(req.ID, "target_stale", "expected_element does not match the snapshot's element; observe again")
		}
	}
	resp := native(req)
	if isMutationOperation(req.Op) && bound {
		// An action may have changed the window (the donor invalidates its
		// accessibility snapshots after GUI input): refs planned before it
		// must be observed again, whatever the outcome.
		s.refs.Invalidate(binding)
	}
	layout := resp.Layout
	resp.Layout = nil
	if req.Op != "observe_window" || !req.RefTree || !resp.OK || !bound {
		return resp
	}
	fact, err := s.buildRefTree(binding, resp.Elements, layout)
	if err != nil {
		return failure(req.ID, "provider_unavailable", err.Error())
	}
	resp.RefTree = fact
	return resp
}

func toSemanticNodes(elements []elementFact) []semantic.Node {
	nodes := make([]semantic.Node, 0, len(elements))
	for _, element := range elements {
		nodes = append(nodes, semantic.Node{
			RuntimeID:    element.RuntimeID,
			ProviderRole: element.ControlType,
			AutomationID: element.AutomationID,
			Name:         element.Name,
			Value:        element.Value,
			ValueHidden:  element.ValueIsPassword,
			Enabled:      element.Enabled,
			Selected:     element.Selected,
			Toggled:      element.Toggled,
			Patterns:     element.Patterns,
			Children:     toSemanticNodes(element.Children),
		})
	}
	return nodes
}

func (s *supervisor) buildRefTree(binding semantic.Binding, elements []elementFact, layout *semantic.Layout) (*refTreeFact, error) {
	if len(elements) == 0 {
		return nil, errors.New("ref tree requested but the worker returned no tree")
	}
	snapshot, previous := s.refs.Observe(binding, toSemanticNodes(elements))
	text, truncated := semantic.Render(snapshot, semantic.DefaultRenderBudget)
	adapter := semantic.CurrentPlatform()
	fact := &refTreeFact{
		SnapshotID: snapshot.ID,
		Generation: snapshot.Generation,
		Text:       text,
		Truncated:  truncated,
		Refs:       make([]refEntryFact, 0, len(snapshot.Refs)),
		Adapter:    adapter.Platform + "/" + adapter.Backend + " " + string(adapter.Verification),
	}
	for _, entry := range snapshot.Refs {
		fact.Refs = append(fact.Refs, refEntryFact{
			Ref: entry.Ref, RuntimeID: entry.RuntimeID, Role: string(entry.Role), Fingerprint: entry.Fingerprint,
		})
	}
	if diff := semantic.Compare(previous, snapshot); diff != nil {
		fact.Diff = diff
		fact.DiffText = diff.Text()
	}
	if layout != nil && layout.Validate() == nil {
		fact.LayoutFrameID = layout.FrameID()
	}
	return fact, nil
}
