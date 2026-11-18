// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use
// computer-use/internal/core/ax_role_ontology.go at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1,
// blob f5ed94abea98c2d8e1ca4496a48465a41b047e6f (MIT).
// Orcel changes: the provider role is the UIA control type name the Orcel
// host reports (for example "Button", "Edit"), so the Windows UIA
// ControlType names are added as provider aliases; the AT-SPI aliases are
// kept for the macOS and Linux adapters (UNVERIFIED there).

package semantic

import "strings"

// Role is a canonical, platform-neutral role.
type Role string

const (
	RoleGeneric Role = "generic"
	RoleText    Role = "text"
)

type roleDescriptor struct {
	role    Role
	aliases []string
	class   string
}

// The donor ontology, plus the UIA ControlType names (lower case) that the
// Windows host reports. Each alias appears once.
var roleOntology = []roleDescriptor{
	{"alert", []string{"alert"}, "boundary"},
	{"application", []string{"application", "appbar"}, "boundary"},
	{"article", []string{"article"}, "boundary"},
	{"button", []string{"push button", "toggle button", "button", "splitbutton"}, "control"},
	{"checkbox", []string{"check box", "checkbox"}, "control"},
	{"combobox", []string{"combo box", "combobox"}, "control"},
	{"dialog", []string{"dialog"}, "boundary"},
	{"document", []string{"document web", "document text", "document frame", "document"}, "boundary"},
	{"grid", []string{"document spreadsheet", "datagrid"}, "collection"},
	{"table", []string{"table"}, "collection"},
	{"cell", []string{"table cell", "dataitem"}, "item"},
	{"columnheader", []string{"header", "headeritem"}, "item"},
	{"heading", []string{"heading"}, "content"},
	{"img", []string{"image", "icon"}, "content"},
	{"link", []string{"link", "hyperlink"}, "control"},
	{"list", []string{"list", "list box"}, "collection"},
	{"listitem", []string{"list item", "listitem"}, "item"},
	{"menu", []string{"menu"}, "boundary"},
	{"menubar", []string{"menu bar", "menubar"}, "boundary"},
	{"menuitem", []string{"menu item", "menuitem"}, "control"},
	{"menuitemcheckbox", []string{"check menu item"}, "control"},
	{"menuitemradio", []string{"radio menu item"}, "control"},
	{"option", []string{"option"}, "item"},
	{"paragraph", []string{"paragraph"}, "content"},
	{"progressbar", []string{"progress bar", "busy indicator", "progressbar"}, "status"},
	{"radio", []string{"radio button", "radiobutton"}, "control"},
	{"scrollbar", []string{"scroll bar", "scrollbar"}, "control"},
	{"separator", []string{"separator"}, "structure"},
	{"slider", []string{"slider"}, "control"},
	{"spinbutton", []string{"spin button", "spinner"}, "control"},
	{"status", []string{"status bar", "notification", "statusbar"}, "status"},
	{"tab", []string{"page tab", "tabitem"}, "control"},
	{"tablist", []string{"page tab list"}, "collection"},
	{"textbox", []string{"entry", "text area", "password text", "edit"}, "control"},
	{RoleText, []string{"static", "text", "label", "caption"}, "text"},
	{"toolbar", []string{"tool bar", "toolbar"}, "boundary"},
	{"tooltip", []string{"tooltip"}, "content"},
	{"tree", []string{"tree"}, "collection"},
	{"treegrid", []string{"tree table"}, "collection"},
	{"treeitem", []string{"tree item", "treeitem"}, "item"},
	{"window", []string{"frame", "window", "titlebar"}, "boundary"},
	{"group", []string{"panel", "root pane", "filler", "section", "group", "viewport", "scroll pane", "layered pane", "split pane", "pane", "thumb"}, "structure"},
}

var roleByProvider = func() map[string]roleDescriptor {
	out := map[string]roleDescriptor{}
	for _, descriptor := range roleOntology {
		out[strings.ToLower(strings.TrimSpace(string(descriptor.role)))] = descriptor
		for _, alias := range descriptor.aliases {
			out[strings.ToLower(strings.TrimSpace(alias))] = descriptor
		}
	}
	return out
}()

// UIA reports "Tab" for a tab list and "TabItem" for a tab: the canonical
// "tab" name would map a UIA "Tab" to the wrong role, so UIA names win here.
var uiaOverrides = map[string]roleDescriptor{
	"tab":    {role: "tablist", class: "collection"},
	"custom": {role: RoleGeneric, class: "unknown"},
}

// CanonicalRole maps a provider role (a UIA ControlType name on Windows, an
// AT-SPI or AX role elsewhere) to a canonical role and its semantic class.
// A table cell under a grid is a gridcell, as in the donor.
func CanonicalRole(providerRole string, parent Role) (Role, string) {
	provider := strings.ToLower(strings.TrimSpace(providerRole))
	if (provider == "table cell" || provider == "dataitem") &&
		(parent == "grid" || parent == "treegrid") {
		return "gridcell", "item"
	}
	if descriptor, ok := uiaOverrides[provider]; ok {
		return descriptor.role, descriptor.class
	}
	if descriptor, ok := roleByProvider[provider]; ok {
		return descriptor.role, descriptor.class
	}
	return RoleGeneric, "unknown"
}

// isInteractiveClass reports whether a node of this class is something an
// agent may target, so the renderer marks it when it has no ref.
func isInteractiveClass(class string) bool {
	return class == "control" || class == "item"
}
