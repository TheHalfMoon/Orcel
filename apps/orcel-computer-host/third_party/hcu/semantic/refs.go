// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1 (MIT):
//   computer-use/internal/core/ax_ref_registry.go,
//     blob 36182c2f3a151fb272643ec50a4113750fefb245 (lifecycle, eviction,
//     resolve errors);
//   computer-use/internal/core/ax_ref_minting.go,
//     blob 51f642f6b2d96beba4f30914f7fe60a3671b454e (rN minting, identity
//     reuse, supersession on a changed identity).
// Orcel changes: refs are scoped to one exact Orcel window binding (HWND,
// PID, start generation and window nonce) and to one host process; only the
// provider-bound locator is kept (the UIA runtime id is the provider
// identity); semantic, table-owner and process-instance scopes, app and
// window refs, persistence and the daemon counters are not ported. Every
// observation is one snapshot with an id, and a ref resolves only through
// the window's current snapshot, so any newer observation makes older
// snapshot ids stale.

package semantic

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
)

const (
	// DefaultMaxWindows bounds how many window bindings keep refs.
	DefaultMaxWindows = 64
	// DefaultMaxEntriesPerWindow bounds the refs (live and retired) one
	// window keeps; the donor's registry limit is 4096 for all windows.
	DefaultMaxEntriesPerWindow = 1024
)

// Binding is the exact Orcel window binding refs are scoped to.
type Binding struct {
	Window          uint64
	PID             uint32
	StartGeneration uint64
	WindowNonce     uint64
}

func (b Binding) key() string {
	return fmt.Sprintf("%d|%d|%d|%d", b.Window, b.PID, b.StartGeneration, b.WindowNonce)
}

// Lifecycle is a ref's state, as in the donor.
type Lifecycle string

const (
	RefActive     Lifecycle = "active"
	RefStale      Lifecycle = "stale"
	RefSuperseded Lifecycle = "superseded"
)

// Typed staleness errors. The host maps each to the target_stale code.
var (
	ErrSnapshotStale = errors.New("target_stale: the snapshot is not the window's current observation; observe again")
	ErrUnknownRef    = errors.New("target_stale: the ref was not issued for this window; observe again")
	ErrRefStale      = errors.New("target_stale: the ref no longer names a live element; observe again")
)

// RefEntry is one issued ref.
type RefEntry struct {
	Ref          string
	RuntimeID    string
	Role         Role
	ProviderRole string
	AutomationID string
	Name         string
	Fingerprint  string
	Lifecycle    Lifecycle
	lastSeen     uint64
}

// Expectation is the identity the host compares with the live element.
func (entry RefEntry) Expectation() Expectation {
	return Expectation{ControlType: entry.ProviderRole, AutomationID: entry.AutomationID, Name: entry.Name}
}

// TreeNode is one projected node of a snapshot.
type TreeNode struct {
	Ref         string
	RuntimeID   string
	Role        Role
	Class       string
	Name        string
	Value       string
	HasValue    bool
	ValueHidden bool
	// Actionable is true when the element reports an action pattern.
	Actionable bool
	States     []string
	Children   []*TreeNode
}

// Snapshot is one observation of one window.
type Snapshot struct {
	ID         string
	Generation uint64
	Binding    Binding
	Roots      []*TreeNode
	Refs       []RefEntry
	NodeCount  int
}

type windowRefs struct {
	binding    Binding
	next       uint64
	generation uint64
	current    *Snapshot
	byIdentity map[string]string
	entries    map[string]*RefEntry
	lastUsed   uint64
}

// Registry holds the refs of every observed window. It is safe for
// concurrent use; the host supervisor serializes frames anyway.
type Registry struct {
	mu         sync.Mutex
	instance   string
	tick       uint64
	maxWindows int
	maxEntries int
	windows    map[string]*windowRefs
}

// NewRegistry returns an empty registry. Its instance tag makes snapshot ids
// from another host process (or a restarted one) never match.
func NewRegistry() *Registry {
	var tag [4]byte
	if _, err := rand.Read(tag[:]); err != nil {
		// rand.Read does not fail on supported platforms; a fixed tag would
		// still be correct, only less distinct across restarts.
		tag = [4]byte{0, 0, 0, 1}
	}
	return &Registry{
		instance:   hex.EncodeToString(tag[:]),
		maxWindows: DefaultMaxWindows,
		maxEntries: DefaultMaxEntriesPerWindow,
		windows:    map[string]*windowRefs{},
	}
}

// Observe projects one bounded tree read into a new snapshot of the window,
// reusing the ref of every element whose provider identity is continuous and
// retiring the rest. It returns the new snapshot and the window's previous
// one (nil on the first observation).
func (registry *Registry) Observe(binding Binding, roots []Node) (*Snapshot, *Snapshot) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.tick++
	window := registry.window(binding, true)
	window.generation++
	window.lastUsed = registry.tick
	snapshot := &Snapshot{
		ID:         "s" + registry.instance + "." + strconv.FormatUint(window.generation, 10),
		Generation: window.generation,
		Binding:    binding,
	}
	seen := map[string]bool{}
	for index := range roots {
		snapshot.Roots = append(snapshot.Roots, registry.project(window, snapshot, &roots[index], "", seen))
	}
	for ref, entry := range window.entries {
		if entry.Lifecycle == RefActive && !seen[ref] {
			retire(window, entry, RefStale)
		}
	}
	window.evict(registry.maxEntries)
	previous := window.current
	window.current = snapshot
	return snapshot, previous
}

func (registry *Registry) project(window *windowRefs, snapshot *Snapshot, node *Node, parent Role, seen map[string]bool) *TreeNode {
	snapshot.NodeCount++
	role, class := CanonicalRole(node.ProviderRole, parent)
	projected := &TreeNode{
		RuntimeID:   node.RuntimeID,
		Role:        role,
		Class:       class,
		Name:        node.Name,
		ValueHidden: node.ValueHidden,
		Actionable:  len(node.Patterns) > 0,
		States:      nodeStates(node),
	}
	if node.Value != nil && !node.ValueHidden {
		projected.Value, projected.HasValue = *node.Value, true
	}
	if hasStableIdentity(node.RuntimeID) {
		projected.Ref = registry.acquire(window, node, role, seen)
		if projected.Ref != "" {
			entry := window.entries[projected.Ref]
			snapshot.Refs = append(snapshot.Refs, *entry)
		}
	}
	for index := range node.Children {
		projected.Children = append(projected.Children, registry.project(window, snapshot, &node.Children[index], role, seen))
	}
	return projected
}

// acquire returns the ref for one node, as the donor's AcquireTyped does for
// a provider-bound locator: reuse while the identity is continuous, retire
// and mint when the role or automation id changed under the same runtime
// id. A runtime id seen twice in one snapshot is ambiguous and the second
// occurrence gets no ref.
func (registry *Registry) acquire(window *windowRefs, node *Node, role Role, seen map[string]bool) string {
	key := strings.TrimSpace(node.RuntimeID)
	fingerprint := Fingerprint(window.binding.key(), role, node.AutomationID, node.Name)
	if ref := window.byIdentity[key]; ref != "" {
		entry := window.entries[ref]
		switch {
		case entry == nil || entry.Lifecycle != RefActive && entry.Lifecycle != RefStale:
			delete(window.byIdentity, key)
		case seen[ref]:
			return ""
		case entry.Role != role || entry.ProviderRole != node.ProviderRole ||
			strings.TrimSpace(entry.AutomationID) != strings.TrimSpace(node.AutomationID):
			retire(window, entry, RefSuperseded)
		default:
			// A stale ref whose element is present again is revived, as
			// the donor keeps a temporarily hidden element's ref.
			entry.Lifecycle = RefActive
			entry.Name = node.Name
			entry.Fingerprint = fingerprint
			entry.lastSeen = window.generation
			seen[ref] = true
			return ref
		}
	}
	window.next++
	ref := "r" + strconv.FormatUint(window.next, 10)
	window.entries[ref] = &RefEntry{
		Ref:          ref,
		RuntimeID:    key,
		Role:         role,
		ProviderRole: node.ProviderRole,
		AutomationID: node.AutomationID,
		Name:         node.Name,
		Fingerprint:  fingerprint,
		Lifecycle:    RefActive,
		lastSeen:     window.generation,
	}
	window.byIdentity[key] = ref
	seen[ref] = true
	return ref
}

func retire(window *windowRefs, entry *RefEntry, lifecycle Lifecycle) {
	entry.Lifecycle = lifecycle
	if lifecycle == RefSuperseded && window.byIdentity[entry.RuntimeID] == entry.Ref {
		delete(window.byIdentity, entry.RuntimeID)
	}
}

// evict drops the oldest retired entries over the bound, as the donor's
// registry evicts least recently used refs; an evicted ref resolves as
// unknown, never as another element.
func (window *windowRefs) evict(limit int) {
	for len(window.entries) > limit {
		var oldest *RefEntry
		for _, entry := range window.entries {
			if entry.Lifecycle == RefActive {
				continue
			}
			if oldest == nil || entry.lastSeen < oldest.lastSeen ||
				entry.lastSeen == oldest.lastSeen && entry.Ref < oldest.Ref {
				oldest = entry
			}
		}
		if oldest == nil {
			return
		}
		if window.byIdentity[oldest.RuntimeID] == oldest.Ref {
			delete(window.byIdentity, oldest.RuntimeID)
		}
		delete(window.entries, oldest.Ref)
	}
}

func (registry *Registry) window(binding Binding, create bool) *windowRefs {
	key := binding.key()
	if window := registry.windows[key]; window != nil || !create {
		return window
	}
	if len(registry.windows) >= registry.maxWindows {
		var oldestKey string
		var oldest *windowRefs
		for candidateKey, candidate := range registry.windows {
			if oldest == nil || candidate.lastUsed < oldest.lastUsed {
				oldestKey, oldest = candidateKey, candidate
			}
		}
		delete(registry.windows, oldestKey)
	}
	window := &windowRefs{binding: binding, byIdentity: map[string]string{}, entries: map[string]*RefEntry{}}
	registry.windows[key] = window
	return window
}

func (registry *Registry) currentEntries(binding Binding, snapshotID string) (*windowRefs, error) {
	window := registry.window(binding, false)
	if window == nil || window.current == nil || strings.TrimSpace(snapshotID) == "" ||
		window.current.ID != snapshotID {
		return nil, ErrSnapshotStale
	}
	registry.tick++
	window.lastUsed = registry.tick
	return window, nil
}

// Resolve returns the live entry a ref names in the window's current
// snapshot. Like the donor, the error never exposes the internal reason.
func (registry *Registry) Resolve(binding Binding, snapshotID, ref string) (RefEntry, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	window, err := registry.currentEntries(binding, snapshotID)
	if err != nil {
		return RefEntry{}, err
	}
	entry := window.entries[strings.TrimSpace(ref)]
	if entry == nil {
		return RefEntry{}, ErrUnknownRef
	}
	if entry.Lifecycle != RefActive {
		return RefEntry{}, ErrRefStale
	}
	return *entry, nil
}

// CheckTarget validates an action addressed by runtime id against the
// window's current snapshot: the snapshot must be current and the runtime
// id must name a live ref in it.
func (registry *Registry) CheckTarget(binding Binding, snapshotID, runtimeID string) (RefEntry, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	window, err := registry.currentEntries(binding, snapshotID)
	if err != nil {
		return RefEntry{}, err
	}
	ref := window.byIdentity[strings.TrimSpace(runtimeID)]
	entry := window.entries[ref]
	if ref == "" || entry == nil {
		return RefEntry{}, ErrUnknownRef
	}
	if entry.Lifecycle != RefActive {
		return RefEntry{}, ErrRefStale
	}
	return *entry, nil
}

// Invalidate retires every ref of a window, for example after an action
// that may have changed it. The next observation issues a new snapshot.
func (registry *Registry) Invalidate(binding Binding) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	window := registry.window(binding, false)
	if window == nil {
		return
	}
	window.current = nil
	for _, entry := range window.entries {
		if entry.Lifecycle == RefActive {
			entry.Lifecycle = RefStale
		}
	}
}

// WindowCount reports how many window bindings keep refs.
func (registry *Registry) WindowCount() int {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	return len(registry.windows)
}

func nodeStates(node *Node) []string {
	states := []string{}
	if !node.Enabled {
		states = append(states, "disabled=true")
	}
	for _, pattern := range node.Patterns {
		if pattern == "Toggle" {
			states = append(states, "checked="+strconv.FormatBool(node.Toggled))
			break
		}
	}
	if node.Selected {
		states = append(states, "selected=true")
	}
	// The donor renders state tokens sorted.
	sort.Strings(states)
	return states
}
