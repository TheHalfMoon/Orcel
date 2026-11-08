// Copyright 2026 TheHalfMoon contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
)

const (
	protocolGeneration = "orcel-computer-host/1"
	// protocolGenerationV2 is the strict superset described in
	// docs/orcel/implementation-readiness/protocol/ORCEL_COMPUTER_HOST_2.md.
	protocolGenerationV2 = "orcel-computer-host/2"
	hostPlatform = "windows"
	hostBackend = "uia"
	hostIdentity = "orcel-windows-computer-host"
	maxRequestBytes = 64 * 1024
	maxResponseBytes = 16 * 1024 * 1024
	maxWindows = 64
	maxTreeNodes = 256
	maxTreeDepth = 8
	// SG-000128: the bounded search that finds one exact runtime id inside a
	// bound window (a subtree root, or a semantic action's target). It only
	// locates; what is returned or acted on keeps the caps above.
	maxRootSearchNodes = 4096
	maxRootSearchDepth = 64
	maxRuntimeIDBytes  = 512
	maxCaptureBytes = 8 * 1024 * 1024
	maxCaptureWidth = 7680
	maxCaptureHeight = 4320
	maxInputTextBytes = 16 * 1024
	maxKeyBytes = 64
	maxScrollTicks = 20
	workerTimeoutMS = 8000
	workerAttempts = 2
)

var allowedOperations = map[string]struct{}{
	"hello": {},
	"ping": {},
	"list_windows": {},
	"observe_window": {},
	"capture_window": {},
	"cursor_position": {},
	"semantic_action": {},
	"window_action": {},
	"input_move": {},
	"input_click": {},
	"input_drag": {},
	"input_scroll": {},
	"input_type_text": {},
	"input_key": {},
	"input_hotkey": {},
	"shutdown": {},
}

// windowRef is the /2 platform-tagged window reference. This host serves
// only kind "hwnd"; the reference is normalized into the /1 binding fields
// before any native work happens.
type windowRef struct {
	Kind string `json:"kind"`
	ID uint64 `json:"id"`
	ExpectedPID *uint32 `json:"expected_pid"`
	ExpectedStartGeneration *uint64 `json:"expected_start_generation"`
	ExpectedWindowNonce *uint64 `json:"expected_window_nonce"`
}

type hostRequest struct {
	ID uint64 `json:"id"`
	Protocol string `json:"protocol"`
	Op string `json:"op"`
	HWND uint64 `json:"hwnd,omitempty"`
	ExpectedPID *uint32 `json:"expected_pid,omitempty"`
	ExpectedStartGeneration *uint64 `json:"expected_start_generation,omitempty"`
	ExpectedWindowNonce *uint64 `json:"expected_window_nonce,omitempty"`
	MaxNodes int `json:"max_nodes,omitempty"`
	MaxDepth int `json:"max_depth,omitempty"`
	ElementRuntimeID string `json:"element_runtime_id,omitempty"`
	SemanticAction string `json:"semantic_action,omitempty"`
	WindowAction string `json:"window_action,omitempty"`
	Value string `json:"value,omitempty"`
	X *int `json:"x,omitempty"`
	Y *int `json:"y,omitempty"`
	ToX *int `json:"to_x,omitempty"`
	ToY *int `json:"to_y,omitempty"`
	Button string `json:"button,omitempty"`
	ClickCount int `json:"click_count,omitempty"`
	ScrollX int `json:"scroll_x,omitempty"`
	ScrollY int `json:"scroll_y,omitempty"`
	Text string `json:"text,omitempty"`
	Key string `json:"key,omitempty"`
	ExpectedLastInputTick *uint32 `json:"expected_last_input_tick,omitempty"`
}

// v2Frame is the strict /2 request shape. The window reference lives only
// here, so /1 decoding of hostRequest stays exactly as it was.
type v2Frame struct {
	hostRequest
	Window *windowRef `json:"window,omitempty"`
}

type hostError struct {
	Code string `json:"code"`
	Message string `json:"message"`
}

type processFact struct {
	PID uint32 `json:"pid"`
	ExeName string `json:"exe_name"`
	ExeID string `json:"exe_id"`
	SessionID uint32 `json:"session_id"`
	SessionVerified bool `json:"session_verified"`
	StartGeneration uint64 `json:"start_generation"`
	GenerationSource string `json:"generation_source"`
}

type windowFact struct {
	Process processFact `json:"process"`
	HWND uint64 `json:"hwnd"`
	Title string `json:"title"`
	Class string `json:"class"`
	Visible bool `json:"visible"`
	WindowNonce uint64 `json:"window_nonce"`
}

type elementFact struct {
	RuntimeID string `json:"runtime_id"`
	ControlType string `json:"control_type"`
	AutomationID string `json:"automation_id"`
	Name string `json:"name"`
	Enabled bool `json:"enabled"`
	Selected bool `json:"selected"`
	Toggled bool `json:"toggled"`
	ScrollHorizontalPercent uint8 `json:"scroll_horizontal_percent"`
	ScrollVerticalPercent uint8 `json:"scroll_vertical_percent"`
	Patterns []string `json:"patterns"`
	Value *string `json:"value,omitempty"`
	ValueIsPassword bool `json:"value_is_password"`
	Children []elementFact `json:"children"`
}

type captureFact struct {
	Width uint32 `json:"width"`
	Height uint32 `json:"height"`
	PixelFormat string `json:"pixel_format"`
	PixelsB64 string `json:"pixels_b64"`
}

type cursorFact struct {
	X int `json:"x"`
	Y int `json:"y"`
	ScreenWidth int `json:"screen_width"`
	ScreenHeight int `json:"screen_height"`
	LastInputTick uint32 `json:"last_input_tick"`
}

type actionFact struct {
	State string `json:"state"`
	Action string `json:"action"`
}

// capabilityFact is one /2 capability table entry. It is advisory: the
// kernel registry still enforces every binding and approval.
type capabilityFact struct {
	Support string `json:"support"`
	Delivery string `json:"delivery,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type hostResponse struct {
	ID uint64 `json:"id"`
	OK bool `json:"ok"`
	Protocol string `json:"protocol"`
	Host string `json:"host"`
	Pong bool `json:"pong,omitempty"`
	Windows []windowFact `json:"windows,omitempty"`
	Elements []elementFact `json:"elements,omitempty"`
	Capture *captureFact `json:"capture,omitempty"`
	Cursor *cursorFact `json:"cursor,omitempty"`
	Action *actionFact `json:"action,omitempty"`
	Error *hostError `json:"error,omitempty"`
	Platform string `json:"platform,omitempty"`
	Backend string `json:"backend,omitempty"`
	Capabilities map[string]capabilityFact `json:"capabilities,omitempty"`
}

func success(id uint64) hostResponse {
	return hostResponse{ID: id, OK: true, Protocol: protocolGeneration, Host: hostIdentity}
}

func failure(id uint64, code, message string) hostResponse {
	return hostResponse{ID: id, OK: false, Protocol: protocolGeneration, Host: hostIdentity, Error: &hostError{Code: code, Message: message}}
}

// windowsCapabilities is the /2 capability table: exactly one entry per
// operation in allowedOperations. Raw input foregrounds the exact target
// before SendInput, so it is foreground_only; UIA patterns and PrintWindow
// do not need the foreground.
var windowsCapabilities = map[string]capabilityFact{
	"hello": {Support: "delivered"},
	"ping": {Support: "delivered"},
	"shutdown": {Support: "delivered"},
	"list_windows": {Support: "delivered"},
	"observe_window": {Support: "delivered"},
	"capture_window": {Support: "delivered", Delivery: "background"},
	"cursor_position": {Support: "delivered"},
	"semantic_action": {Support: "delivered", Delivery: "background"},
	"window_action": {Support: "delivered", Delivery: "foreground"},
	"input_move": {Support: "foreground_only", Delivery: "foreground"},
	"input_click": {Support: "foreground_only", Delivery: "foreground"},
	"input_drag": {Support: "foreground_only", Delivery: "foreground"},
	"input_scroll": {Support: "foreground_only", Delivery: "foreground"},
	"input_type_text": {Support: "foreground_only", Delivery: "foreground"},
	"input_key": {Support: "foreground_only", Delivery: "foreground"},
	"input_hotkey": {Support: "foreground_only", Delivery: "foreground"},
}

// helloV2 answers a /2 hello with the platform, backend and capability table.
func helloV2(id uint64) hostResponse {
	resp := success(id)
	resp.Protocol = protocolGenerationV2
	resp.Platform = hostPlatform
	resp.Backend = hostBackend
	resp.Capabilities = make(map[string]capabilityFact, len(windowsCapabilities))
	for op, fact := range windowsCapabilities {
		resp.Capabilities[op] = fact
	}
	return resp
}

// decodeRequest parses one request frame. /1 frames keep their historical
// lenient decoding unchanged (unknown fields, including any "window" value of
// any type, are ignored).
// /2 frames refuse unknown fields and normalize the window reference.
func decodeRequest(line []byte) (hostRequest, *hostError) {
	var req hostRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return hostRequest{}, &hostError{Code: "invalid_request", Message: "request is not valid JSON"}
	}
	if req.Protocol != protocolGenerationV2 {
		return req, nil
	}
	strict := json.NewDecoder(bytes.NewReader(line))
	strict.DisallowUnknownFields()
	var frame v2Frame
	if err := strict.Decode(&frame); err != nil {
		return req, &hostError{Code: "invalid_request", Message: "request contains an unknown or malformed field"}
	}
	v2 := frame.hostRequest
	if frame.Window != nil {
		if v2.HWND != 0 || v2.ExpectedPID != nil || v2.ExpectedStartGeneration != nil || v2.ExpectedWindowNonce != nil {
			return v2, &hostError{Code: "invalid_request", Message: "window reference and legacy window fields are mutually exclusive"}
		}
		if frame.Window.Kind != "hwnd" {
			return v2, &hostError{Code: "invalid_request", Message: "window reference kind is not served by this host"}
		}
		v2.HWND = frame.Window.ID
		v2.ExpectedPID = frame.Window.ExpectedPID
		v2.ExpectedStartGeneration = frame.Window.ExpectedStartGeneration
		v2.ExpectedWindowNonce = frame.Window.ExpectedWindowNonce
	}
	return v2, nil
}

// respondFailure builds a typed refusal in the generation the caller spoke.
func respondFailure(req hostRequest, code, message string) hostResponse {
	resp := failure(req.ID, code, message)
	if req.Protocol == protocolGenerationV2 {
		resp.Protocol = protocolGenerationV2
	}
	return resp
}

// handleFrame answers one request line. dispatch runs native operations;
// it always receives a normalized /1 request so the sacrificial worker and
// its response binding stay unchanged. stop reports a completed shutdown.
func handleFrame(line []byte, dispatch func(hostRequest) hostResponse) (resp hostResponse, stop bool) {
	req, problem := decodeRequest(line)
	if problem == nil {
		problem = validateRequest(req)
	}
	if problem != nil {
		return respondFailure(req, problem.Code, problem.Message), false
	}
	switch req.Op {
	case "hello":
		if req.Protocol == protocolGenerationV2 {
			return helloV2(req.ID), false
		}
		resp = success(req.ID)
	case "ping":
		resp = success(req.ID)
		resp.Pong = true
	case "shutdown":
		resp = success(req.ID)
		stop = true
	default:
		native := req
		native.Protocol = protocolGeneration
		resp = dispatch(native)
	}
	if encodedSize(resp) > maxResponseBytes {
		resp = failure(req.ID, "output_limit", "host response exceeds the bounded private IPC size")
	}
	if req.Protocol == protocolGenerationV2 {
		resp.Protocol = protocolGenerationV2
	}
	return resp, stop
}

func isMutationOperation(op string) bool {
	switch op {
	case "semantic_action", "window_action", "input_move", "input_click", "input_drag", "input_scroll",
		"input_type_text", "input_key", "input_hotkey":
		return true
	default:
		return false
	}
}

func requiresWindowBinding(op string) bool {
	return op == "observe_window" || op == "capture_window" || op == "semantic_action" ||
		isMutationOperation(op)
}

func validateRequest(req hostRequest) *hostError {
	if req.Protocol != protocolGeneration && req.Protocol != protocolGenerationV2 {
		return &hostError{Code: "invalid_request", Message: "protocol generation mismatch"}
	}
	if _, ok := allowedOperations[req.Op]; !ok {
		return &hostError{Code: "capability_denied", Message: "operation is not exposed by the private host"}
	}
	if requiresWindowBinding(req.Op) {
		if req.HWND == 0 {
			return &hostError{Code: "invalid_request", Message: "window handle is required"}
		}
		if req.ExpectedPID == nil || req.ExpectedStartGeneration == nil || req.ExpectedWindowNonce == nil {
			return &hostError{Code: "invalid_request", Message: "exact window binding is required"}
		}
	}
	if req.MaxNodes < 0 || req.MaxDepth < 0 {
		return &hostError{Code: "invalid_request", Message: "tree bounds must be non-negative"}
	}
	if len(req.Text) > maxInputTextBytes || len(req.Value) > maxInputTextBytes {
		return &hostError{Code: "invalid_request", Message: "text input exceeds the bounded limit"}
	}
	if len(req.Key) > maxKeyBytes {
		return &hostError{Code: "invalid_request", Message: "key input exceeds the bounded limit"}
	}
	if len(req.ElementRuntimeID) > maxRuntimeIDBytes {
		return &hostError{Code: "invalid_request", Message: "element runtime id exceeds the bounded limit"}
	}
	// SG-000128: an element runtime id names a semantic action's target or
	// an observe_window subtree root, and nothing else.
	if req.ElementRuntimeID != "" && req.Op != "semantic_action" && req.Op != "observe_window" {
		return &hostError{Code: "invalid_request", Message: "element runtime id is accepted only by semantic_action and observe_window"}
	}
	if isMutationOperation(req.Op) && req.Op != "semantic_action" && req.ExpectedLastInputTick == nil {
		return &hostError{Code: "invalid_request", Message: "raw input requires a fresh human-input tick binding"}
	}
	switch req.Op {
	case "window_action":
		switch req.WindowAction {
		case "focus", "minimize", "maximize", "restore", "close":
		default:
			return &hostError{Code: "invalid_request", Message: "unknown window action"}
		}
	case "semantic_action":
		switch req.SemanticAction {
		case "invoke", "set_value", "select", "toggle", "scroll":
		default:
			return &hostError{Code: "invalid_request", Message: "unknown semantic action"}
		}
		if req.ElementRuntimeID == "" {
			return &hostError{Code: "invalid_request", Message: "exact element runtime id is required"}
		}
		if req.SemanticAction == "scroll" && (req.ScrollX < -maxScrollTicks || req.ScrollX > maxScrollTicks || req.ScrollY < -maxScrollTicks || req.ScrollY > maxScrollTicks) {
			return &hostError{Code: "invalid_request", Message: "semantic scroll exceeds the bounded limit"}
		}
	case "input_move":
		if req.X == nil || req.Y == nil {
			return &hostError{Code: "invalid_request", Message: "window-relative x and y are required"}
		}
	case "input_drag":
		if req.X == nil || req.Y == nil || req.ToX == nil || req.ToY == nil {
			return &hostError{Code: "invalid_request", Message: "drag requires window-relative start and end coordinates"}
		}
	case "input_click":
		if req.X == nil || req.Y == nil {
			return &hostError{Code: "invalid_request", Message: "window-relative x and y are required"}
		}
		if req.Button != "left" && req.Button != "right" && req.Button != "middle" {
			return &hostError{Code: "invalid_request", Message: "mouse button must be left, right, or middle"}
		}
		if req.ClickCount != 1 && req.ClickCount != 2 {
			return &hostError{Code: "invalid_request", Message: "click_count must be 1 or 2"}
		}
	case "input_scroll":
		if req.X == nil || req.Y == nil {
			return &hostError{Code: "invalid_request", Message: "scroll requires window-relative x and y"}
		}
		if req.ScrollX < -maxScrollTicks || req.ScrollX > maxScrollTicks || req.ScrollY < -maxScrollTicks || req.ScrollY > maxScrollTicks || (req.ScrollX == 0 && req.ScrollY == 0) {
			return &hostError{Code: "invalid_request", Message: "scroll ticks are missing or out of bounds"}
		}
	case "input_type_text":
		if req.Text == "" {
			return &hostError{Code: "invalid_request", Message: "text is required"}
		}
	case "input_key", "input_hotkey":
		if req.Key == "" {
			return &hostError{Code: "invalid_request", Message: "key or hotkey is required"}
		}
	}
	return nil
}

func encodedSize(value any) int {
	raw, err := json.Marshal(value)
	if err != nil {
		return maxResponseBytes + 1
	}
	return len(raw)
}
