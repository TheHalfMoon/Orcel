// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use
// computer-use/internal/core/ax_snapshot_identity.go at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1,
// blob fa1efac8dc6683f2460493d2cddf9056e740219d (MIT):
// semanticFingerprint and validateExactProviderAlias.
// Orcel changes: the fingerprint covers the control identity the Orcel host
// reports (role, automation id, name); relations are not reported, so they
// are not hashed. The live-target check compares the observed element with
// the live element before an action and refuses on any difference.

package semantic

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Node is one accessibility element as a native adapter reports it, with
// its children already nested. RuntimeID is the provider's object identity
// (the UIA runtime id on Windows); an empty id or one starting with
// "unidentified." has no stable identity and never receives a ref.
type Node struct {
	RuntimeID    string
	ProviderRole string
	AutomationID string
	Name         string
	Value        *string
	ValueHidden  bool
	Enabled      bool
	Selected     bool
	Toggled      bool
	Patterns     []string
	Children     []Node
}

// Expectation is the identity of an element as observed, sent with an
// action so the host can refuse when the live element differs.
type Expectation struct {
	ControlType  string `json:"control_type"`
	AutomationID string `json:"automation_id"`
	Name         string `json:"name"`
}

// ErrTargetChanged reports that the live element is not the one observed.
var ErrTargetChanged = errors.New("target_stale: the live element no longer matches the observed element; observe again")

// comparableText folds whitespace runs to one space and trims, as the
// donor's comparableTreeText does for identity comparison.
func comparableText(value string) string {
	var builder strings.Builder
	space := false
	for _, char := range strings.TrimSpace(value) {
		if unicode.IsSpace(char) || unicode.IsControl(char) {
			space = true
			continue
		}
		if space && builder.Len() > 0 {
			builder.WriteByte(' ')
		}
		space = false
		builder.WriteRune(char)
	}
	return builder.String()
}

// Fingerprint is the donor's "f1:" semantic fingerprint: the first 12 bytes
// of a SHA-256 over the identity parts, hex encoded.
func Fingerprint(window string, role Role, automationID, name string) string {
	parts := []string{
		strings.TrimSpace(window),
		string(role),
		strings.TrimSpace(automationID),
		comparableText(name),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "f1:" + hex.EncodeToString(sum[:12])
}

// CheckLive compares the observed identity with the live element's. The
// control type must be equal, an expected automation id that is not empty
// must equal the live one, and the names must be equal after whitespace
// folding; anything else is ErrTargetChanged. An empty expected automation
// id carries no identifier to compare (the expectation does not distinguish
// "none observed" from "not sent"), so it is not compared with the live id,
// as the donor's alias check compares control identifiers only when they are
// not empty; the exact runtime id, the control type and the name still bind
// the target. A conflict is never resolved in favour of acting.
func CheckLive(expected Expectation, liveControlType, liveAutomationID, liveName string) error {
	if strings.TrimSpace(expected.ControlType) != strings.TrimSpace(liveControlType) {
		return fmt.Errorf("%w (control type)", ErrTargetChanged)
	}
	if want := strings.TrimSpace(expected.AutomationID); want != "" && want != strings.TrimSpace(liveAutomationID) {
		return fmt.Errorf("%w (automation id)", ErrTargetChanged)
	}
	if comparableText(expected.Name) != comparableText(liveName) {
		return fmt.Errorf("%w (name)", ErrTargetChanged)
	}
	return nil
}

// hasStableIdentity reports whether a node can carry a ref: the donor mints
// a provider-bound ref only for a complete provider identity.
func hasStableIdentity(runtimeID string) bool {
	runtimeID = strings.TrimSpace(runtimeID)
	return runtimeID != "" && !strings.HasPrefix(runtimeID, "unidentified.")
}
