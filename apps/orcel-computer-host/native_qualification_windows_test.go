//go:build windows

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type nativeTestWindow struct {
	cmd   *exec.Cmd
	hwnd  windows.HWND
	title string
}

func launchNativeTestWindow(t *testing.T) nativeTestWindow {
	t.Helper()
	title := fmt.Sprintf("Orcel SG94 Native Qualification %d", os.Getpid())
	escapedTitle := strings.ReplaceAll(title, "'", "''")
	script := fmt.Sprintf(`
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = '%s'
$form.StartPosition = 'Manual'
$form.Location = New-Object System.Drawing.Point(80, 80)
$form.Size = New-Object System.Drawing.Size(420, 260)
$button = New-Object System.Windows.Forms.Button
$button.Text = 'SG94 Button'
$button.Location = New-Object System.Drawing.Point(20, 20)
$button.Size = New-Object System.Drawing.Size(140, 35)
$text = New-Object System.Windows.Forms.TextBox
$text.Text = 'SG94 Value'
$text.Location = New-Object System.Drawing.Point(20, 80)
$text.Size = New-Object System.Drawing.Size(220, 30)
$form.Controls.Add($button)
$form.Controls.Add($text)
$form.Add_Shown({
  [Console]::Out.WriteLine(('READY:{0}' -f $form.Handle.ToInt64()))
  [Console]::Out.Flush()
})
[System.Windows.Forms.Application]::Run($form)
`, escapedTitle)

	cmd := exec.Command(
		"powershell.exe",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-STA",
		"-Command", script,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("open helper stdout: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start native helper window: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})

	lineCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		if scanner.Scan() {
			lineCh <- scanner.Text()
			return
		}
		if err := scanner.Err(); err != nil {
			errCh <- err
			return
		}
		errCh <- fmt.Errorf("helper exited before reporting a window handle")
	}()

	var line string
	select {
	case line = <-lineCh:
	case err := <-errCh:
		t.Fatalf("native helper startup failed: %v; stderr=%s", err, stderr.String())
	case <-time.After(45 * time.Second):
		// Windows Forms first-load compilation on a shared CI runner can take
		// longer than 15s under parallel Rust/Node jobs. This remains a finite
		// fail-closed readiness deadline; only a real READY handle can pass.
		t.Fatalf("native helper startup timed out after 45s; stderr=%s", stderr.String())
	}
	if !strings.HasPrefix(line, "READY:") {
		t.Fatalf("unexpected helper readiness line %q", line)
	}
	raw, err := strconv.ParseUint(strings.TrimPrefix(line, "READY:"), 10, 64)
	if err != nil || raw == 0 {
		t.Fatalf("invalid helper window handle %q: %v", line, err)
	}
	return nativeTestWindow{cmd: cmd, hwnd: windows.HWND(uintptr(raw)), title: title}
}

func findNativeTestWindow(t *testing.T, title string) windowFact {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		facts, err := enumerateWindows()
		if err != nil {
			t.Fatalf("enumerate native windows: %v", err)
		}
		for _, fact := range facts {
			if fact.Title == title {
				return fact
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("native helper window %q was not discovered", title)
	return windowFact{}
}

func boundHostRequest(id uint64, op string, fact windowFact) hostRequest {
	pid := fact.Process.PID
	start := fact.Process.StartGeneration
	nonce := fact.WindowNonce
	return hostRequest{
		ID:                      id,
		Protocol:                protocolGeneration,
		Op:                      op,
		HWND:                    fact.HWND,
		ExpectedPID:             &pid,
		ExpectedStartGeneration: &start,
		ExpectedWindowNonce:     &nonce,
	}
}

func elementTreeStats(nodes []elementFact, depth int) (count int, maxDepthSeen int) {
	maxDepthSeen = depth - 1
	for _, node := range nodes {
		count++
		if depth > maxDepthSeen {
			maxDepthSeen = depth
		}
		childCount, childDepth := elementTreeStats(node.Children, depth+1)
		count += childCount
		if childDepth > maxDepthSeen {
			maxDepthSeen = childDepth
		}
	}
	return count, maxDepthSeen
}

func decodedCaptureBytes(t *testing.T, capture *captureFact) []byte {
	t.Helper()
	if capture == nil {
		t.Fatal("capture payload is missing")
	}
	if capture.Width == 0 || capture.Height == 0 {
		t.Fatalf("capture geometry is empty: %dx%d", capture.Width, capture.Height)
	}
	if capture.Width > maxCaptureWidth || capture.Height > maxCaptureHeight {
		t.Fatalf("capture geometry exceeds bounds: %dx%d", capture.Width, capture.Height)
	}
	raw, err := base64.StdEncoding.DecodeString(capture.PixelsB64)
	if err != nil {
		t.Fatalf("capture base64 is invalid: %v", err)
	}
	want := int(capture.Width) * int(capture.Height) * 4
	if len(raw) != want {
		t.Fatalf("capture bytes=%d want=%d", len(raw), want)
	}
	if len(raw) > maxCaptureBytes {
		t.Fatalf("capture bytes=%d exceed bound=%d", len(raw), maxCaptureBytes)
	}
	return raw
}

func TestSG000094NativeObservationCaptureQualification(t *testing.T) {
	if err := requireInteractiveStation(); err != nil {
		t.Fatalf("native qualification requires the interactive WinSta0 session: %v", err)
	}
	helper := launchNativeTestWindow(t)
	fact := findNativeTestWindow(t, helper.title)

	if fact.HWND != uint64(helper.hwnd) {
		t.Fatalf("discovered HWND=%d helper HWND=%d", fact.HWND, helper.hwnd)
	}
	if !fact.Process.SessionVerified || fact.Process.GenerationSource != "win32-creation-time" {
		t.Fatalf("process identity is not verified: %+v", fact.Process)
	}
	if fact.Process.StartGeneration == 0 || fact.WindowNonce == 0 {
		t.Fatalf("process/window generation is empty: %+v", fact)
	}

	observe := boundHostRequest(1, "observe_window", fact)
	observe.MaxNodes = 64
	observe.MaxDepth = 4
	observed := nativeObserveWindow(observe)
	if !observed.OK {
		t.Fatalf("UIA observation failed: %+v", observed.Error)
	}
	if len(observed.Elements) == 0 {
		t.Fatal("UIA observation returned no root element")
	}
	count, depth := elementTreeStats(observed.Elements, 0)
	if count == 0 || count > observe.MaxNodes {
		t.Fatalf("UIA node count=%d bound=%d", count, observe.MaxNodes)
	}
	if depth > observe.MaxDepth {
		t.Fatalf("UIA depth=%d bound=%d", depth, observe.MaxDepth)
	}

	// SG-000128: a subtree read below an element of the same window starts
	// at exactly that element, keeps the caps, and a root that does not
	// resolve inside the window fails closed and observes nothing.
	scopedRead := func(runtimeID string) hostResponse {
		scoped := boundHostRequest(5, "observe_window", fact)
		scoped.MaxNodes = 64
		scoped.MaxDepth = 4
		scoped.ElementRuntimeID = runtimeID
		return nativeObserveWindow(scoped)
	}
	rootID := observed.Elements[0].RuntimeID
	if rootID == "" {
		t.Fatal("the helper window's root element has no runtime id")
	}
	whole := scopedRead(rootID)
	if !whole.OK || len(whole.Elements) != 1 || whole.Elements[0].RuntimeID != rootID {
		t.Fatalf("a subtree read at the window's root did not start there: %+v", whole.Error)
	}
	for _, child := range observed.Elements[0].Children {
		if child.RuntimeID == "" {
			continue
		}
		subtree := scopedRead(child.RuntimeID)
		if subtree.OK {
			if len(subtree.Elements) != 1 || subtree.Elements[0].RuntimeID != child.RuntimeID {
				t.Fatalf("a subtree read did not start at the requested element %q", child.RuntimeID)
			}
			count, depth := elementTreeStats(subtree.Elements, 0)
			if count > 64 || depth > 4 {
				t.Fatalf("a subtree exceeded its caps: nodes=%d depth=%d", count, depth)
			}
		} else if subtree.Error == nil || subtree.Error.Code != "target_stale" || len(subtree.Elements) != 0 {
			t.Fatalf("a non-content child did not fail closed: %+v", subtree)
		}
	}
	missing := boundHostRequest(6, "observe_window", fact)
	missing.ElementRuntimeID = "999999.1.2.3"
	notFound := nativeObserveWindow(missing)
	if notFound.OK || notFound.Error == nil || notFound.Error.Code != "target_stale" || len(notFound.Elements) != 0 {
		t.Fatalf("an unresolved subtree root did not fail closed: %+v", notFound)
	}

	captureReq := boundHostRequest(2, "capture_window", fact)
	first := nativeCaptureWindow(captureReq)
	if !first.OK {
		t.Fatalf("initial exact-window capture failed: %+v", first.Error)
	}
	_ = decodedCaptureBytes(t, first.Capture)
	firstWidth, firstHeight := first.Capture.Width, first.Capture.Height

	setWindowPos := user32.NewProc("SetWindowPos")
	ok, _, callErr := setWindowPos.Call(
		uintptr(helper.hwnd),
		0,
		180,
		160,
		620,
		360,
		0x0004|0x0010, // SWP_NOZORDER | SWP_NOACTIVATE
	)
	if ok == 0 {
		t.Fatalf("test-only SetWindowPos failed: %v", callErr)
	}
	time.Sleep(500 * time.Millisecond)
	rect, valid := getWindowRect(helper.hwnd)
	if !valid || rect.Left < 150 || rect.Top < 130 {
		t.Fatalf("window move was not observed: %+v", rect)
	}

	second := nativeCaptureWindow(captureReq)
	if !second.OK {
		t.Fatalf("post-move/resize capture failed: %+v", second.Error)
	}
	_ = decodedCaptureBytes(t, second.Capture)
	if second.Capture.Width == firstWidth && second.Capture.Height == firstHeight {
		t.Fatalf(
			"capture geometry did not refresh after resize: before=%dx%d after=%dx%d",
			firstWidth, firstHeight, second.Capture.Width, second.Capture.Height,
		)
	}

	staleGeneration := boundHostRequest(3, "capture_window", fact)
	(*staleGeneration.ExpectedStartGeneration)++
	stale := nativeCaptureWindow(staleGeneration)
	if stale.OK || stale.Error == nil || stale.Error.Code != "target_stale" {
		t.Fatalf("stale process generation did not fail closed: %+v", stale)
	}

	staleNonce := boundHostRequest(4, "observe_window", fact)
	(*staleNonce.ExpectedWindowNonce)++
	staleTree := nativeObserveWindow(staleNonce)
	if staleTree.OK || staleTree.Error == nil || staleTree.Error.Code != "target_stale" {
		t.Fatalf("stale window nonce did not fail closed: %+v", staleTree)
	}

	if err := helper.cmd.Process.Kill(); err != nil {
		t.Fatalf("kill helper process: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for windows.IsWindow(helper.hwnd) && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if windows.IsWindow(helper.hwnd) {
		t.Fatal("helper HWND remained live after process exit")
	}
	gone := nativeCaptureWindow(captureReq)
	if gone.OK || gone.Error == nil || gone.Error.Code != "target_stale" {
		t.Fatalf("destroyed HWND did not fail closed: %+v", gone)
	}
}

func TestSG000094SecuritySurfaceAndSessionPredicates(t *testing.T) {
	for _, name := range []string{
		"orcel.exe",
		"orceld.exe",
		"orcel.exe",
		"orcel-computer-host.exe",
		"CredentialUIBroker.exe",
		"consent.exe",
		"LogonUI.exe",
	} {
		if !isProtectedExecutable(name) {
			t.Fatalf("protected executable %q was not excluded", name)
		}
	}
	if isProtectedExecutable("notepad.exe") {
		t.Fatal("ordinary application was classified as protected")
	}
	if err := validateInteractiveStationName("WinSta0"); err != nil {
		t.Fatalf("WinSta0 was rejected: %v", err)
	}
	if err := validateInteractiveStationName("Service-0x0-3e7$\\Default"); err == nil {
		t.Fatal("non-interactive service station was accepted")
	}
}

func TestSG000094WorkerFailuresRemainFailClosed(t *testing.T) {
	req := hostRequest{ID: 91, Protocol: protocolGeneration, Op: "list_windows"}
	valid, err := jsonMarshalResponse(success(req.ID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeWorkerResponse(req, valid); err != nil {
		t.Fatalf("valid worker response was rejected: %v", err)
	}
	for name, raw := range map[string][]byte{
		"empty":   {},
		"nul":     []byte("{\"id\":91}\x00"),
		"corrupt": []byte("{not-json}"),
		"mismatch": []byte(
			"{\"id\":92,\"ok\":true,\"protocol\":\"orcel-computer-host/1\",\"host\":\"orcel-windows-computer-host\"}",
		),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeWorkerResponse(req, raw); err == nil {
				t.Fatalf("%s worker response was accepted", name)
			}
		})
	}

	resp := runSacrificialWorker(req)
	if resp.OK || resp.Error == nil || resp.Error.Code != "provider_unavailable" {
		t.Fatalf("repeated worker startup failure did not fail closed: %+v", resp)
	}
}

func jsonMarshalResponse(response hostResponse) ([]byte, error) {
	return json.Marshal(response)
}
