// Copyright (c) 2026 Hybrid Computer Use authors
// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: MIT
//
// COPY_ADAPT from microsoft/Hybrid-Computer-Use
// computer-use/internal/core/ax_batch_plan.go at
// 00eaeebe8ac0d275e46f875bdb5347e5f326faa1,
// blob 41b2560db454441f2a021c95e8d94ec4f427bd27 (MIT): execution classes,
// consistency boundaries and ordered keypress runs.
// Orcel changes: the action vocabulary is the Orcel semantic and window
// actions plus "keypress" and "wait"; a plan has a step and wait budget; a
// window ref ("wN") target is refused (Orcel binds one window per request).
// The compiled plan is not executed: BatchDispatchEnabled is false, and the
// host refuses the semantic_batch capability, until a grain amendment
// (SG-000132, or an SG-000095 amendment) admits batched actions under
// orceld's per-step approval.

package semantic

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// BatchDispatchEnabled is false: batched actions are a new action kind and
// stay denied by default until a grain amendment enables them.
const BatchDispatchEnabled = false

// Plan bounds.
const (
	MaxBatchSteps  = 16
	MaxWaitMS      = 5000
	MaxTotalWaitMS = 10000
)

var shortRefPattern = regexp.MustCompile(`^r[1-9][0-9]{0,8}$`)
var windowRefPattern = regexp.MustCompile(`^w[1-9][0-9]{0,8}$`)

// IsShortRef reports whether value is an rN element ref.
func IsShortRef(value string) bool { return shortRefPattern.MatchString(value) }

// BatchAction is one requested step.
type BatchAction struct {
	Type   string `json:"type"`
	Ref    string `json:"ref,omitempty"`
	Value  string `json:"value,omitempty"`
	Key    string `json:"key,omitempty"`
	WaitMS int    `json:"wait_ms,omitempty"`
}

// ExecutionClass, Consistency and Boundary are the donor's plan vocabulary.
type ExecutionClass string
type Consistency string
type Boundary string

const (
	SingleAction ExecutionClass = "single_action"
	OrderedInput ExecutionClass = "ordered_window_input"

	WindowIdentity  Consistency = "window_identity"
	CanonicalWindow Consistency = "canonical_window"

	NoBoundary          Boundary = "none"
	CanonicalBoundary   Boundary = "canonical_action"
	TargetedBoundary    Boundary = "targeted_action"
	WaitBoundary        Boundary = "wait"
	WindowBoundary      Boundary = "window_transition"
	NextActionBoundary  Boundary = "next_action_requires_canonical"
	TransactionBoundary Boundary = "transaction_end"
)

// PlannedStep is one compiled step.
type PlannedStep struct {
	Index           int
	Type            string
	Class           ExecutionClass
	Targeted        bool
	PreConsistency  Consistency
	PostConsistency Consistency
	Boundary        Boundary
	OrderedInputRun int
}

// BatchPlan is a compiled plan for one bound window.
type BatchPlan struct {
	Binding               Binding
	RequiresMutationLease bool
	Steps                 []PlannedStep
	TotalWaitMS           int
}

var targetedActions = map[string]bool{"invoke": true, "set_value": true, "select": true, "toggle": true, "scroll": true}
var windowActions = map[string]bool{"focus": true, "minimize": true, "maximize": true, "restore": true, "close": true}

// CompileBatchPlan validates and compiles a plan, as the donor does after
// normalization: every element action names a current rN ref, waits and
// steps are bounded, and runs of untargeted keypresses share one ordered
// input run whose last step needs a canonical observation.
func CompileBatchPlan(binding Binding, actions []BatchAction) (BatchPlan, error) {
	if binding.Window == 0 {
		return BatchPlan{}, errors.New("batch plans require one bound window")
	}
	if len(actions) == 0 {
		return BatchPlan{}, errors.New("batch plans require at least one action")
	}
	if len(actions) > MaxBatchSteps {
		return BatchPlan{}, fmt.Errorf("batch plans allow at most %d actions", MaxBatchSteps)
	}
	plan := BatchPlan{Binding: binding, RequiresMutationLease: true, Steps: make([]PlannedStep, 0, len(actions))}
	nextRun, activeRun := 0, 0
	for index, action := range actions {
		ref := strings.TrimSpace(action.Ref)
		if windowRefPattern.MatchString(ref) {
			return BatchPlan{}, fmt.Errorf("actions[%d]: window refs are not accepted; the request binds one window", index)
		}
		if ref != "" && !IsShortRef(ref) {
			return BatchPlan{}, fmt.Errorf("actions[%d]: target %q is not a current rN ref", index, ref)
		}
		step := PlannedStep{
			Index:           index,
			Type:            action.Type,
			Class:           SingleAction,
			Targeted:        ref != "",
			PreConsistency:  CanonicalWindow,
			PostConsistency: CanonicalWindow,
		}
		switch {
		case targetedActions[action.Type]:
			if ref == "" {
				return BatchPlan{}, fmt.Errorf("actions[%d]: %s requires an rN ref", index, action.Type)
			}
			step.Boundary = TargetedBoundary
		case windowActions[action.Type]:
			if ref != "" {
				return BatchPlan{}, fmt.Errorf("actions[%d]: window actions take no element ref", index)
			}
			step.Boundary = WindowBoundary
		case action.Type == "wait":
			if ref != "" || action.WaitMS <= 0 || action.WaitMS > MaxWaitMS {
				return BatchPlan{}, fmt.Errorf("actions[%d]: wait needs wait_ms between 1 and %d and no ref", index, MaxWaitMS)
			}
			plan.TotalWaitMS += action.WaitMS
			if plan.TotalWaitMS > MaxTotalWaitMS {
				return BatchPlan{}, fmt.Errorf("batch waits exceed %d ms in total", MaxTotalWaitMS)
			}
			step.Boundary = WaitBoundary
		case action.Type == "keypress":
			if strings.TrimSpace(action.Key) == "" {
				return BatchPlan{}, fmt.Errorf("actions[%d]: keypress requires a key", index)
			}
			step.Boundary = CanonicalBoundary
			if ref == "" {
				if activeRun == 0 {
					nextRun++
					activeRun = nextRun
				}
				step.Class = OrderedInput
				step.PreConsistency = WindowIdentity
				step.PostConsistency = WindowIdentity
				step.Boundary = NoBoundary
				step.OrderedInputRun = activeRun
			}
		default:
			return BatchPlan{}, fmt.Errorf("actions[%d]: action type %q is not mapped", index, action.Type)
		}
		if step.Class != OrderedInput {
			activeRun = 0
		}
		plan.Steps = append(plan.Steps, step)
	}
	for index := range plan.Steps {
		step := &plan.Steps[index]
		if step.Class != OrderedInput {
			continue
		}
		last := index == len(plan.Steps)-1
		if !last && plan.Steps[index+1].OrderedInputRun == step.OrderedInputRun {
			continue
		}
		step.PostConsistency = CanonicalWindow
		if last {
			step.Boundary = TransactionBoundary
		} else {
			step.Boundary = NextActionBoundary
		}
	}
	return plan, nil
}
