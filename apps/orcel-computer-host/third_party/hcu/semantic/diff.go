// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use
// computer-use/internal/core/ax_semantic_diff.go at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1,
// blob cc30f95d0f3781eb8d1085615bf3e283aa1fec2d (MIT): the diff kinds, the
// ref-keyed matching (axNodeDiffKey) and the state and property signatures.
// Orcel changes: nodes are matched only by ref (a node without a ref has no
// proven continuity, so it is never reported as changed, only counted); the
// weak-duplicate LCS matching and order changes are not ported; the output
// is a bounded list of changes and a compact text form.

package semantic

import (
	"sort"
	"strconv"
	"strings"
)

// DiffKind is one kind of change between two snapshots.
type DiffKind string

const (
	DiffAdded        DiffKind = "added"
	DiffRemoved      DiffKind = "removed"
	DiffStateChanged DiffKind = "state_changed"
	DiffChanged      DiffKind = "property_changed"
)

// MaxDiffChanges bounds the changes one diff reports.
const MaxDiffChanges = 128

// DiffChange is one change of one ref.
type DiffChange struct {
	Kind   DiffKind `json:"kind"`
	Ref    string   `json:"ref"`
	Before string   `json:"before,omitempty"`
	After  string   `json:"after,omitempty"`
}

// Diff is the semantic difference between two snapshots of one window.
type Diff struct {
	FromSnapshot string       `json:"from_snapshot"`
	ToSnapshot   string       `json:"to_snapshot"`
	Changes      []DiffChange `json:"changes"`
	Omitted      int          `json:"omitted"`
	// Unkeyed counts nodes without a ref in the newer snapshot; their
	// changes cannot be attributed and are not reported.
	Unkeyed int `json:"unkeyed"`
}

type keyedNode struct {
	label      string
	properties string
	states     string
}

func indexByRef(snapshot *Snapshot) (map[string]keyedNode, []string, int) {
	index := map[string]keyedNode{}
	order := []string{}
	unkeyed := 0
	var walk func(nodes []*TreeNode)
	walk = func(nodes []*TreeNode) {
		for _, node := range nodes {
			if node.Ref == "" {
				unkeyed++
			} else if _, dup := index[node.Ref]; !dup {
				value := ""
				if node.HasValue {
					value = node.Value
				}
				index[node.Ref] = keyedNode{
					label:      Label(node),
					properties: strings.Join([]string{string(node.Role), comparableText(node.Name), value}, "\x00"),
					states:     strings.Join(node.States, ","),
				}
				order = append(order, node.Ref)
			}
			walk(node.Children)
		}
	}
	walk(snapshot.Roots)
	return index, order, unkeyed
}

// Compare returns the changes from before to after. Both must be snapshots
// of the same window binding; a nil before yields no changes.
func Compare(before, after *Snapshot) *Diff {
	if before == nil || after == nil || before.Binding != after.Binding {
		return nil
	}
	old, oldOrder, _ := indexByRef(before)
	current, currentOrder, unkeyed := indexByRef(after)
	diff := &Diff{FromSnapshot: before.ID, ToSnapshot: after.ID, Unkeyed: unkeyed, Changes: []DiffChange{}}
	add := func(change DiffChange) {
		if len(diff.Changes) >= MaxDiffChanges {
			diff.Omitted++
			return
		}
		diff.Changes = append(diff.Changes, change)
	}
	for _, ref := range currentOrder {
		now := current[ref]
		was, existed := old[ref]
		switch {
		case !existed:
			add(DiffChange{Kind: DiffAdded, Ref: ref, After: now.label})
		case was.properties != now.properties:
			add(DiffChange{Kind: DiffChanged, Ref: ref, Before: was.label, After: now.label})
		case was.states != now.states:
			add(DiffChange{Kind: DiffStateChanged, Ref: ref, Before: was.label, After: now.label})
		}
	}
	removed := []string{}
	for _, ref := range oldOrder {
		if _, still := current[ref]; !still {
			removed = append(removed, ref)
		}
	}
	sort.SliceStable(removed, func(i, j int) bool { return refNumber(removed[i]) < refNumber(removed[j]) })
	for _, ref := range removed {
		add(DiffChange{Kind: DiffRemoved, Ref: ref, Before: old[ref].label})
	}
	return diff
}

func refNumber(ref string) uint64 {
	value, _ := strconv.ParseUint(strings.TrimPrefix(ref, "r"), 10, 64)
	return value
}

// MaxDiffTextBytes bounds Text: the Rust adapter rejects a whole
// observation whose diff text exceeds 64 KiB (MAX_REF_TREE_TEXT_BYTES).
const MaxDiffTextBytes = 64 * 1024

// diffTextNoteReserve keeps room for the truncation and omission notes.
const diffTextNoteReserve = 128

// Text renders a diff compactly: "+ label" for added, "- label" for
// removed and "~ before -> after" for a changed ref. The output never
// exceeds MaxDiffTextBytes: it is cut on a change boundary and ends with a
// truncation note instead.
func (diff *Diff) Text() string {
	if diff == nil {
		return ""
	}
	var builder strings.Builder
	truncated := 0
	for index, change := range diff.Changes {
		var line string
		switch change.Kind {
		case DiffAdded:
			line = "+ " + change.After + "\n"
		case DiffRemoved:
			line = "- " + change.Before + "\n"
		default:
			line = "~ " + change.Before + " -> " + change.After + "\n"
		}
		if builder.Len()+len(line) > MaxDiffTextBytes-diffTextNoteReserve {
			truncated = len(diff.Changes) - index
			break
		}
		builder.WriteString(line)
	}
	if truncated > 0 {
		builder.WriteString("~ note: " + strconv.Itoa(truncated) + " changes truncated by the output budget\n")
	}
	if diff.Omitted > 0 {
		builder.WriteString("~ note: " + strconv.Itoa(diff.Omitted) + " more changes omitted\n")
	}
	return builder.String()
}
