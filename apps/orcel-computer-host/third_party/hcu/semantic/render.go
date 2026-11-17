// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use
// computer-use/internal/core/ax_renderer.go at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1,
// blob fc202bfb3081b8539d1ad86bf91c2164bdae92a2 (MIT): the node label
// (role, quoted name, inline value, sorted state tokens, [ref=rN] or the
// addressability marker) and the indented "- label:" tree line.
// Orcel changes: a hidden (password) value renders as [value=hidden] and is
// never printed; layout wrappers (unnamed generic or group nodes without a
// ref) are flattened into their parent, as the donor's diff does; the output
// has a byte budget and ends with an omission note instead of being cut mid
// line; visibility evidence, relations and audit fields are not rendered.

package semantic

import (
	"strconv"
	"strings"
)

// DefaultRenderBudget is the byte budget of a rendered tree.
const DefaultRenderBudget = 64 * 1024

// maxRenderedText bounds one rendered name or value.
const maxRenderedText = 200

func clipText(value string) string {
	value = strings.ToValidUTF8(value, "\uFFFD")
	value = comparableText(value)
	if len(value) <= maxRenderedText {
		return value
	}
	cut := maxRenderedText
	for cut > 0 && !utf8Start(value[cut]) {
		cut--
	}
	return value[:cut] + "..."
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// Label renders one node's label as the donor does.
func Label(node *TreeNode) string {
	if node == nil {
		return string(RoleGeneric)
	}
	label := string(node.Role)
	if label == "" {
		label = string(RoleGeneric)
	}
	if name := clipText(node.Name); name != "" {
		label += " " + strconv.Quote(name)
	}
	if node.HasValue {
		if value := clipText(node.Value); value != "" && value != clipText(node.Name) {
			label += " = " + strconv.Quote(value)
		}
	}
	states := append([]string(nil), node.States...)
	if node.ValueHidden {
		states = append(states, "value=hidden")
	}
	if len(states) > 0 {
		label += " [" + strings.Join(states, " ") + "]"
	}
	switch {
	case node.Ref != "":
		label += " [ref=" + node.Ref + "]"
	case isInteractiveClass(node.Class):
		label += " [addressable=false]"
	}
	return label
}

// layoutWrapper reports an unnamed, stateless generic or group node with no
// action pattern. Its children are rendered in its place; its ref (if any)
// stays resolvable but is not printed.
func layoutWrapper(node *TreeNode) bool {
	return !node.Actionable && strings.TrimSpace(node.Name) == "" && !node.HasValue &&
		len(node.States) == 0 && (node.Role == RoleGeneric || node.Role == "group")
}

// Render returns the compact text tree of a snapshot within budget bytes
// (DefaultRenderBudget when budget <= 0) and whether nodes were omitted.
func Render(snapshot *Snapshot, budget int) (string, bool) {
	if snapshot == nil {
		return "", false
	}
	if budget <= 0 {
		budget = DefaultRenderBudget
	}
	var builder strings.Builder
	omitted := 0
	var walk func(nodes []*TreeNode, depth int)
	walk = func(nodes []*TreeNode, depth int) {
		for _, node := range nodes {
			if layoutWrapper(node) && depth > 0 {
				walk(node.Children, depth)
				continue
			}
			line := strings.Repeat(" ", depth) + "- " + Label(node)
			if len(node.Children) > 0 {
				line += ":"
			}
			line += "\n"
			if omitted > 0 || builder.Len()+len(line) > budget-64 {
				omitted += 1 + countNodes(node.Children)
				continue
			}
			builder.WriteString(line)
			walk(node.Children, depth+1)
		}
	}
	walk(snapshot.Roots, 0)
	if omitted > 0 {
		builder.WriteString("- note: " + strconv.Itoa(omitted) + " more nodes omitted by the output budget\n")
	}
	return builder.String(), omitted > 0
}

func countNodes(nodes []*TreeNode) int {
	total := 0
	for _, node := range nodes {
		total += 1 + countNodes(node.Children)
	}
	return total
}
