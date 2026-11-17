// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// Tests marked PORT adapt microsoft/Hybrid-Computer-Use
// computer-use/internal/core/ax_ref_registry_test.go at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1,
// blob 306c28b621d5ec56ade69b4a3137d56b387cbae0 (MIT), to the Orcel
// registry. The others are Orcel regression tests.

package semantic

import (
	"errors"
	"strings"
	"testing"
)

var testBinding = Binding{Window: 0x1001, PID: 42, StartGeneration: 7, WindowNonce: 99}

func str(value string) *string { return &value }

func testTree() []Node {
	return []Node{{
		RuntimeID: "42.1", ProviderRole: "Window", Name: "Orcel Test", Enabled: true,
		Children: []Node{
			{RuntimeID: "42.2", ProviderRole: "Button", AutomationID: "ok", Name: "OK", Enabled: true, Patterns: []string{"Invoke"}},
			{RuntimeID: "42.3", ProviderRole: "Edit", AutomationID: "field", Name: "Value", Enabled: true, Value: str("hello"), Patterns: []string{"Value"}},
			{RuntimeID: "42.4", ProviderRole: "Pane", Enabled: true, Children: []Node{
				{RuntimeID: "42.5", ProviderRole: "CheckBox", Name: "Remember", Enabled: true, Toggled: true, Patterns: []string{"Toggle"}},
			}},
		},
	}}
}

func refFor(t *testing.T, snapshot *Snapshot, runtimeID string) string {
	t.Helper()
	for _, entry := range snapshot.Refs {
		if entry.RuntimeID == runtimeID {
			return entry.Ref
		}
	}
	t.Fatalf("no ref for runtime id %s", runtimeID)
	return ""
}

// PORT of TestShortAXRefExpandsToWindowScopedSemanticRef: a short ref
// resolves to the element it was issued for, in its own window only.
func TestShortRefResolvesInsideItsWindowOnly(t *testing.T) {
	registry := NewRegistry()
	snapshot, previous := registry.Observe(testBinding, testTree())
	if previous != nil {
		t.Fatal("first observation must have no previous snapshot")
	}
	ref := refFor(t, snapshot, "42.2")
	entry, err := registry.Resolve(testBinding, snapshot.ID, ref)
	if err != nil || entry.RuntimeID != "42.2" || entry.Role != "button" {
		t.Fatalf("resolve = %+v, %v", entry, err)
	}
	other := testBinding
	other.WindowNonce++
	if _, err := registry.Resolve(other, snapshot.ID, ref); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("a ref resolved through another window binding: %v", err)
	}
}

// Orcel regression: the ref tree is stable. Observing the same tree again
// keeps every ref and renders the same text.
func TestRefTreeIsStableAcrossIdenticalObservations(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	second, previous := registry.Observe(testBinding, testTree())
	if previous == nil || previous.ID != first.ID || second.ID == first.ID {
		t.Fatalf("snapshot ids: first=%s previous=%v second=%s", first.ID, previous, second.ID)
	}
	if len(first.Refs) != len(second.Refs) {
		t.Fatalf("ref count changed: %d -> %d", len(first.Refs), len(second.Refs))
	}
	for index := range first.Refs {
		if first.Refs[index].Ref != second.Refs[index].Ref || first.Refs[index].RuntimeID != second.Refs[index].RuntimeID {
			t.Fatalf("ref %d changed: %+v -> %+v", index, first.Refs[index], second.Refs[index])
		}
	}
	firstText, _ := Render(first, 0)
	secondText, _ := Render(second, 0)
	if firstText != secondText {
		t.Fatalf("rendered tree changed:\n%s\n---\n%s", firstText, secondText)
	}
	if diff := Compare(first, second); diff == nil || len(diff.Changes) != 0 {
		t.Fatalf("identical observations must not diff: %+v", diff)
	}
}

// Orcel regression: a stale target is refused. A newer observation makes
// the older snapshot id stale, so a ref or runtime id planned against it
// cannot act.
func TestNewerObservationMakesOlderSnapshotStale(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	ref := refFor(t, first, "42.2")
	second, _ := registry.Observe(testBinding, testTree())
	if _, err := registry.Resolve(testBinding, first.ID, ref); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("old snapshot resolved: %v", err)
	}
	if _, err := registry.CheckTarget(testBinding, first.ID, "42.2"); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("old snapshot admitted a runtime id: %v", err)
	}
	if _, err := registry.CheckTarget(testBinding, second.ID, "42.2"); err != nil {
		t.Fatalf("current snapshot refused a live runtime id: %v", err)
	}
	if _, err := registry.CheckTarget(testBinding, second.ID, "42.99"); !errors.Is(err, ErrUnknownRef) {
		t.Fatalf("unknown runtime id admitted: %v", err)
	}
	registry.Invalidate(testBinding)
	if _, err := registry.CheckTarget(testBinding, second.ID, "42.2"); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("invalidated window admitted a target: %v", err)
	}
}

// PORT of TestProviderBoundIdentitySemanticMutationSupersedesOldRef: the
// same provider object exposing a different semantic object gets a new ref
// and the old one never resolves again.
func TestRoleChangeUnderSameRuntimeIDSupersedesRef(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	oldRef := refFor(t, first, "42.2")
	mutated := testTree()
	mutated[0].Children[0].ProviderRole = "Edit"
	second, _ := registry.Observe(testBinding, mutated)
	newRef := refFor(t, second, "42.2")
	if newRef == oldRef {
		t.Fatalf("role change kept ref %s", oldRef)
	}
	if _, err := registry.Resolve(testBinding, second.ID, oldRef); !errors.Is(err, ErrRefStale) {
		t.Fatalf("superseded ref resolved: %v", err)
	}
	diff := Compare(first, second)
	kinds := map[DiffKind]int{}
	for _, change := range diff.Changes {
		kinds[change.Kind]++
	}
	if kinds[DiffAdded] != 1 || kinds[DiffRemoved] != 1 {
		t.Fatalf("supersession must show as removed+added: %+v", diff.Changes)
	}
}

// PORT of TestStaleRefErrorDoesNotExposeInternalReason.
func TestStaleRefErrorDoesNotExposeInternalReason(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	ref := refFor(t, first, "42.5")
	without := testTree()
	without[0].Children = without[0].Children[:2]
	second, _ := registry.Observe(testBinding, without)
	_, err := registry.Resolve(testBinding, second.ID, ref)
	if !errors.Is(err, ErrRefStale) {
		t.Fatalf("absent element's ref resolved: %v", err)
	}
	if strings.Contains(err.Error(), "42.5") || strings.Contains(err.Error(), "not present") {
		t.Fatalf("stale error exposes internal detail: %v", err)
	}
}

// PORT of TestCompleteInventoryKeepsPresentTemporarilyHiddenRef: an element
// that disappears and comes back keeps its ref.
func TestTemporarilyAbsentElementKeepsItsRef(t *testing.T) {
	registry := NewRegistry()
	first, _ := registry.Observe(testBinding, testTree())
	ref := refFor(t, first, "42.5")
	without := testTree()
	without[0].Children = without[0].Children[:2]
	registry.Observe(testBinding, without)
	third, _ := registry.Observe(testBinding, testTree())
	if got := refFor(t, third, "42.5"); got != ref {
		t.Fatalf("returning element got %s, want %s", got, ref)
	}
	if _, err := registry.Resolve(testBinding, third.ID, ref); err != nil {
		t.Fatalf("revived ref refused: %v", err)
	}
}

// PORT of TestDaemonRestartNeverReusesRefNumbers, inside one registry: an
// evicted or superseded ref number is never issued again for that window.
func TestRefNumbersAreNeverReused(t *testing.T) {
	registry := NewRegistry()
	registry.maxEntries = 4
	issued := map[string]string{}
	for round := 0; round < 6; round++ {
		tree := []Node{{RuntimeID: "1", ProviderRole: "Window", Enabled: true, Children: []Node{
			{RuntimeID: "child." + string(rune('a'+round)), ProviderRole: "Button", Name: "B", Enabled: true},
		}}}
		snapshot, _ := registry.Observe(testBinding, tree)
		for _, entry := range snapshot.Refs {
			if owner, seen := issued[entry.Ref]; seen && owner != entry.RuntimeID {
				t.Fatalf("ref %s reissued from %s to %s", entry.Ref, owner, entry.RuntimeID)
			}
			issued[entry.Ref] = entry.RuntimeID
		}
	}
	if len(registry.windows[testBinding.key()].entries) > 4 {
		t.Fatalf("eviction did not bound the window's entries")
	}
}

// Orcel regression: a runtime id seen twice in one read is ambiguous, and
// nodes without a provider identity get no ref.
func TestAmbiguousAndUnidentifiedNodesGetNoRef(t *testing.T) {
	registry := NewRegistry()
	tree := []Node{{RuntimeID: "1", ProviderRole: "Window", Enabled: true, Children: []Node{
		{RuntimeID: "dup", ProviderRole: "Button", Name: "A", Enabled: true},
		{RuntimeID: "dup", ProviderRole: "Button", Name: "B", Enabled: true},
		{RuntimeID: "unidentified.5.3", ProviderRole: "Button", Name: "C", Enabled: true},
	}}}
	snapshot, _ := registry.Observe(testBinding, tree)
	if len(snapshot.Refs) != 2 {
		t.Fatalf("refs = %+v, want the window and the first duplicate", snapshot.Refs)
	}
	text, _ := Render(snapshot, 0)
	if strings.Count(text, "[addressable=false]") != 2 {
		t.Fatalf("unaddressable controls are not marked:\n%s", text)
	}
}

func TestRegistryBoundsWindows(t *testing.T) {
	registry := NewRegistry()
	registry.maxWindows = 3
	for window := uint64(1); window <= 5; window++ {
		binding := testBinding
		binding.Window = window
		registry.Observe(binding, testTree())
	}
	if registry.WindowCount() != 3 {
		t.Fatalf("window count = %d, want 3", registry.WindowCount())
	}
}

func TestSnapshotIDsDifferAcrossRegistries(t *testing.T) {
	first, _ := NewRegistry().Observe(testBinding, testTree())
	second := NewRegistry()
	second.Observe(testBinding, testTree())
	if _, err := second.Resolve(testBinding, first.ID, "r1"); !errors.Is(err, ErrSnapshotStale) {
		t.Fatalf("a snapshot id from another host process resolved: %v", err)
	}
}

func TestCheckLiveRefusesAnyIdentityChange(t *testing.T) {
	expected := Expectation{ControlType: "Button", AutomationID: "ok", Name: "OK  now"}
	if err := CheckLive(expected, "Button", "ok", " OK now "); err != nil {
		t.Fatalf("whitespace-only difference refused: %v", err)
	}
	for _, live := range [][3]string{
		{"Edit", "ok", "OK now"},
		{"Button", "cancel", "OK now"},
		{"Button", "ok", "Cancel"},
	} {
		if err := CheckLive(expected, live[0], live[1], live[2]); !errors.Is(err, ErrTargetChanged) {
			t.Fatalf("changed live element %v admitted: %v", live, err)
		}
	}
}

// A WinForms or Win32 control reports a non-empty UIA AutomationId (its
// control id) even when the caller's expectation names only the control
// type and name. Such an expectation matches the same live element; a
// non-empty expected id must still equal the live one, including an
// observed id that the live element lost.
func TestCheckLiveComparesOnlyANonEmptyExpectedAutomationID(t *testing.T) {
	partial := Expectation{ControlType: "Button", Name: "SG94 Button"}
	for _, liveID := range []string{"1050418", "", "  "} {
		if err := CheckLive(partial, "Button", liveID, "SG94 Button"); err != nil {
			t.Fatalf("matching live element with automation id %q refused: %v", liveID, err)
		}
	}
	for _, live := range [][3]string{
		{"Edit", "1050418", "SG94 Button"},
		{"Button", "1050418", "Not The Button"},
	} {
		if err := CheckLive(partial, live[0], live[1], live[2]); !errors.Is(err, ErrTargetChanged) {
			t.Fatalf("changed live element %v admitted: %v", live, err)
		}
	}
	observed := Expectation{ControlType: "Button", AutomationID: " 1050418 ", Name: "SG94 Button"}
	if err := CheckLive(observed, "Button", "1050418", "SG94 Button"); err != nil {
		t.Fatalf("matching live element refused: %v", err)
	}
	for _, liveID := range []string{"", "1050419", "1050418x"} {
		if err := CheckLive(observed, "Button", liveID, "SG94 Button"); !errors.Is(err, ErrTargetChanged) {
			t.Fatalf("live automation id %q admitted against an observed one: %v", liveID, err)
		}
	}
}

func TestFingerprintIsDonorShaped(t *testing.T) {
	value := Fingerprint("w", "button", "ok", "OK")
	if !strings.HasPrefix(value, "f1:") || len(value) != 3+24 {
		t.Fatalf("fingerprint %q is not f1:<24 hex>", value)
	}
	if value != Fingerprint("w", "button", "ok", " OK ") || value == Fingerprint("w", "button", "ok", "Cancel") {
		t.Fatal("fingerprint does not fold whitespace or does not cover the name")
	}
}

func TestCanonicalRolesCoverUIAControlTypes(t *testing.T) {
	cases := map[string]Role{
		"Button": "button", "Edit": "textbox", "CheckBox": "checkbox", "Hyperlink": "link",
		"TabItem": "tab", "Tab": "tablist", "Pane": "group", "Window": "window",
		"ListItem": "listitem", "Custom": RoleGeneric, "Text": RoleText, "Unheard": RoleGeneric,
	}
	for provider, want := range cases {
		if got, _ := CanonicalRole(provider, ""); got != want {
			t.Errorf("CanonicalRole(%q) = %q, want %q", provider, got, want)
		}
	}
	if got, _ := CanonicalRole("DataItem", "grid"); got != "gridcell" {
		t.Errorf("a data item under a grid is %q, want gridcell", got)
	}
}
