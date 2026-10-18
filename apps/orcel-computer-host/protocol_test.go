package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestProtocolOperationSurfaceIsExact(t *testing.T) {
	want := []string{"capture_window", "cursor_position", "hello", "input_click", "input_drag", "input_hotkey", "input_key", "input_move", "input_scroll", "input_type_text", "list_windows", "observe_window", "ping", "semantic_action", "shutdown", "window_action"}
	if len(allowedOperations) != len(want) {
		t.Fatalf("operation count=%d want=%d", len(allowedOperations), len(want))
	}
	for _, op := range want {
		if _, ok := allowedOperations[op]; !ok {
			t.Fatalf("missing operation %q", op)
		}
	}
	for _, forbidden := range []string{"click", "type", "key", "drag", "scroll", "focus", "launch", "activate_window", "set_value", "mouse", "keyboard", "shell", "process"} {
		if _, ok := allowedOperations[forbidden]; ok {
			t.Fatalf("forbidden operation %q exposed", forbidden)
		}
	}
}

func TestProtocolRejectsUnknownAndMalformedRequests(t *testing.T) {
	if err := validateRequest(hostRequest{Protocol: protocolGeneration, Op: "click"}); err == nil {
		t.Fatal("unknown mutation operation accepted")
	}
	if err := validateRequest(hostRequest{Protocol: "other", Op: "ping"}); err == nil {
		t.Fatal("wrong protocol accepted")
	}
	if err := validateRequest(hostRequest{Protocol: protocolGeneration, Op: "capture_window"}); err == nil {
		t.Fatal("capture without HWND accepted")
	}
	if err := validateRequest(hostRequest{Protocol: protocolGeneration, Op: "observe_window", HWND: 1}); err == nil {
		t.Fatal("observation without exact target binding accepted")
	}
	pid := uint32(10)
	start := uint64(20)
	nonce := uint64(30)
	if err := validateRequest(hostRequest{
		Protocol: protocolGeneration,
		Op: "observe_window",
		HWND: 1,
		ExpectedPID: &pid,
		ExpectedStartGeneration: &start,
		ExpectedWindowNonce: &nonce,
	}); err != nil {
		t.Fatalf("complete exact target binding rejected: %+v", err)
	}
}

func TestResponseSchemaContainsNoSecretOrAuthorityFields(t *testing.T) {
	raw, err := json.Marshal(success(1))
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, marker := range []string{"token", "secret", "credential", "approval", "lease", "admin"} {
		if strings.Contains(text, marker) {
			t.Fatalf("response unexpectedly contains %q", marker)
		}
	}
}

func encodeFrame(t *testing.T, resp hostResponse) string {
	t.Helper()
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(resp); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func refuseDispatch(t *testing.T) func(hostRequest) hostResponse {
	return func(req hostRequest) hostResponse {
		t.Fatalf("supervisor-only frame reached native dispatch: %+v", req)
		return hostResponse{}
	}
}

// The /1 vectors below are the exact bytes the supervisor wrote before /2
// existed. They must never change.
func TestProtocolV1VectorsAreByteIdentical(t *testing.T) {
	vectors := []struct {
		name string
		line string
		want string
		stop bool
	}{
		{"hello", `{"id":1,"protocol":"orcel-computer-host/1","op":"hello"}`,
			`{"id":1,"ok":true,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host"}` + "\n", false},
		{"ping", `{"id":2,"protocol":"orcel-computer-host/1","op":"ping"}`,
			`{"id":2,"ok":true,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","pong":true}` + "\n", false},
		{"unknown op", `{"id":3,"protocol":"orcel-computer-host/1","op":"click"}`,
			`{"id":3,"ok":false,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","error":{"code":"capability_denied","message":"operation is not exposed by the private host"}}` + "\n", false},
		{"bad json", `{"id":4,`,
			`{"id":0,"ok":false,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","error":{"code":"invalid_request","message":"request is not valid JSON"}}` + "\n", false},
		{"unknown generation", `{"id":5,"protocol":"orcel-computer-host/3","op":"hello"}`,
			`{"id":5,"ok":false,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","error":{"code":"invalid_request","message":"protocol generation mismatch"}}` + "\n", false},
		{"unknown field stays lenient", `{"id":6,"protocol":"orcel-computer-host/1","op":"ping","extra":true,"window":{"kind":"hwnd","id":9}}`,
			`{"id":6,"ok":true,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","pong":true}` + "\n", false},
		{"unbound observe", `{"id":7,"protocol":"orcel-computer-host/1","op":"observe_window","hwnd":1}`,
			`{"id":7,"ok":false,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host","error":{"code":"invalid_request","message":"exact window binding is required"}}` + "\n", false},
		{"shutdown", `{"id":8,"protocol":"orcel-computer-host/1","op":"shutdown"}`,
			`{"id":8,"ok":true,"protocol":"orcel-computer-host/1","host":"orcel-windows-computer-host"}` + "\n", true},
	}
	for _, vector := range vectors {
		resp, stop := handleFrame([]byte(vector.line), refuseDispatch(t))
		if got := encodeFrame(t, resp); got != vector.want {
			t.Fatalf("%s: got %s want %s", vector.name, got, vector.want)
		}
		if stop != vector.stop {
			t.Fatalf("%s: stop=%v want %v", vector.name, stop, vector.stop)
		}
	}
}

func TestProtocolV1BoundRequestReachesWorkerUnchanged(t *testing.T) {
	line := `{"id":9,"protocol":"orcel-computer-host/1","op":"observe_window","hwnd":11,"expected_pid":12,"expected_start_generation":13,"expected_window_nonce":14,"window":{"kind":"hwnd","id":99}}`
	var forwarded hostRequest
	resp, _ := handleFrame([]byte(line), func(req hostRequest) hostResponse {
		forwarded = req
		return success(req.ID)
	})
	if !resp.OK || resp.Protocol != protocolGeneration {
		t.Fatalf("bound /1 request failed: %+v", resp)
	}
	if forwarded.Protocol != protocolGeneration || forwarded.HWND != 11 || forwarded.Window != nil || *forwarded.ExpectedWindowNonce != 14 {
		t.Fatalf("/1 request was rewritten before dispatch: %+v", forwarded)
	}
}

func TestProtocolV2HelloReportsPlatformBackendAndCapabilities(t *testing.T) {
	resp, stop := handleFrame([]byte(`{"id":1,"protocol":"orcel-computer-host/2","op":"hello"}`), refuseDispatch(t))
	if stop || !resp.OK || resp.Protocol != protocolGenerationV2 || resp.Host != hostIdentity {
		t.Fatalf("/2 hello failed: %+v", resp)
	}
	if resp.Platform != "windows" || resp.Backend != "uia" {
		t.Fatalf("platform=%q backend=%q", resp.Platform, resp.Backend)
	}
	if len(resp.Capabilities) != len(allowedOperations) {
		t.Fatalf("capability count=%d operations=%d", len(resp.Capabilities), len(allowedOperations))
	}
	for op := range allowedOperations {
		fact, ok := resp.Capabilities[op]
		if !ok {
			t.Fatalf("operation %q has no capability entry", op)
		}
		switch fact.Support {
		case "delivered", "foreground_only", "refused", "unavailable":
		default:
			t.Fatalf("operation %q has open support value %q", op, fact.Support)
		}
	}
	for op := range resp.Capabilities {
		if _, ok := allowedOperations[op]; !ok {
			t.Fatalf("capability %q names no operation", op)
		}
	}
	if resp.Capabilities["input_click"].Support != "foreground_only" {
		t.Fatalf("raw input must not claim background delivery: %+v", resp.Capabilities["input_click"])
	}
	raw := encodeFrame(t, resp)
	if !strings.HasPrefix(raw, `{"id":1,"ok":true,"protocol":"orcel-computer-host/2","host":"orcel-windows-computer-host","platform":"windows","backend":"uia","capabilities":{`) {
		t.Fatalf("unexpected /2 hello frame %s", raw)
	}
}

func TestProtocolV2RefusesUnknownFieldsAndForeignWindowKinds(t *testing.T) {
	for _, line := range []string{
		`{"id":2,"protocol":"orcel-computer-host/2","op":"ping","extra":true}`,
		`{"id":2,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"hwnd","id":1,"expected_pid":1,"expected_start_generation":1,"expected_window_nonce":1,"extra":1}}`,
		`{"id":2,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"cgwindow","id":1,"expected_pid":1,"expected_start_generation":1,"expected_window_nonce":1}}`,
		`{"id":2,"protocol":"orcel-computer-host/2","op":"observe_window","hwnd":1,"window":{"kind":"hwnd","id":1,"expected_pid":1,"expected_start_generation":1,"expected_window_nonce":1}}`,
		`{"id":2,"protocol":"orcel-computer-host/2","op":"observe_window","window":{"kind":"hwnd","id":1}}`,
	} {
		resp, _ := handleFrame([]byte(line), refuseDispatch(t))
		if resp.OK || resp.Error == nil || resp.Error.Code != "invalid_request" || resp.Protocol != protocolGenerationV2 || resp.ID != 2 {
			t.Fatalf("/2 frame %s was not refused as invalid_request: %+v", line, resp)
		}
	}
	resp, _ := handleFrame([]byte(`{"id":3,"protocol":"orcel-computer-host/2","op":"click"}`), refuseDispatch(t))
	if resp.OK || resp.Error == nil || resp.Error.Code != "capability_denied" || resp.Protocol != protocolGenerationV2 {
		t.Fatalf("/2 unknown operation not denied: %+v", resp)
	}
}

func TestProtocolV2WindowReferenceIsNormalizedForTheWorker(t *testing.T) {
	line := `{"id":4,"protocol":"orcel-computer-host/2","op":"observe_window","max_nodes":5,"window":{"kind":"hwnd","id":21,"expected_pid":22,"expected_start_generation":23,"expected_window_nonce":24}}`
	var forwarded hostRequest
	resp, _ := handleFrame([]byte(line), func(req hostRequest) hostResponse {
		forwarded = req
		return failure(req.ID, "target_stale", "window changed")
	})
	if resp.OK || resp.Protocol != protocolGenerationV2 || resp.Error == nil || resp.Error.Code != "target_stale" {
		t.Fatalf("worker refusal not projected into /2: %+v", resp)
	}
	if forwarded.Protocol != protocolGeneration || forwarded.Window != nil || forwarded.HWND != 21 ||
		*forwarded.ExpectedPID != 22 || *forwarded.ExpectedStartGeneration != 23 || *forwarded.ExpectedWindowNonce != 24 || forwarded.MaxNodes != 5 {
		t.Fatalf("worker did not receive the normalized /1 request: %+v", forwarded)
	}
	legacy := `{"id":5,"protocol":"orcel-computer-host/2","op":"observe_window","hwnd":31,"expected_pid":32,"expected_start_generation":33,"expected_window_nonce":34}`
	resp, _ = handleFrame([]byte(legacy), func(req hostRequest) hostResponse {
		forwarded = req
		return success(req.ID)
	})
	if !resp.OK || resp.Protocol != protocolGenerationV2 || forwarded.HWND != 31 {
		t.Fatalf("/2 legacy window fields rejected: %+v", resp)
	}
}
