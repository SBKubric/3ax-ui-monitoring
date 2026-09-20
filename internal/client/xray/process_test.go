package xray

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeBin is the compiled testdata/fakexray, the stand-in for the real xray
// binary (docs/agents/testing.md: no real xray in unit tests). Empty when the
// Go toolchain is unavailable, in which case the process tests skip.
var fakeBin string

func TestMain(m *testing.M) {
	if path, err := buildFake(); err != nil {
		fmt.Fprintf(os.Stderr, "fakexray unavailable: %v\n", err)
	} else {
		fakeBin = path
		defer os.RemoveAll(filepath.Dir(path))
	}
	os.Exit(m.Run())
}

func buildFake() (string, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "fakexray")
	if err != nil {
		return "", err
	}
	bin := filepath.Join(dir, "fakexray")
	cmd := exec.Command("go", "build", "-o", bin, "./testdata/fakexray")
	out, err := cmd.CombinedOutput()
	if err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("go build: %v: %s", err, out)
	}
	return bin, nil
}

func newTestProcess(t *testing.T) *Process {
	t.Helper()
	if fakeBin == "" {
		t.Skip("fakexray was not built (no Go toolchain)")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(fakeBin, logger)
}

// fakeCfg is the "fake" section of a config understood by testdata/fakexray.
type fakeCfg struct {
	TestFail      string   `json:"testFail,omitempty"`
	ExitNow       bool     `json:"exitNow,omitempty"`
	ExitMsg       string   `json:"exitMsg,omitempty"`
	DelayMs       int      `json:"delayMs,omitempty"`
	Stderr        []string `json:"stderr,omitempty"`
	Stderr2       []string `json:"stderr2,omitempty"`
	IgnoreSIGTERM bool     `json:"ignoreSigterm,omitempty"`
}

// writeCfg writes a config in the shape internal/client/config generates:
// one socks inbound per port, plus the fake's script.
func writeCfg(t *testing.T, name string, ports []int, fake fakeCfg) string {
	t.Helper()
	type inbound struct {
		Tag      string `json:"tag"`
		Listen   string `json:"listen"`
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	doc := struct {
		Inbounds []inbound `json:"inbounds"`
		Fake     fakeCfg   `json:"fake"`
	}{Fake: fake}
	for i, p := range ports {
		doc.Inbounds = append(doc.Inbounds, inbound{
			Tag: fmt.Sprintf("in-xray-%d-proxy", i), Listen: "127.0.0.1", Port: p, Protocol: "socks",
		})
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// freePort returns a loopback port nothing is listening on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func dialable(port int) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func ctxT(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// TestProcessTest covers the gate of spec §4 step 3: a good config passes,
// a bad one comes back as an error whose text is the first line xray printed
// (exit 23, research §2.2) — that text becomes configError in the heartbeat.
func TestProcessTest(t *testing.T) {
	p := newTestProcess(t)

	good := writeCfg(t, "good.json", []int{freePort(t)}, fakeCfg{})
	if err := p.Test(ctxT(t, 10*time.Second), good); err != nil {
		t.Fatalf("Test(good) = %v, want nil", err)
	}

	// The real wording of ghcr.io/xtls/xray-core:latest for a vless outbound
	// without an encryption field, banner and Info lines included.
	const msg = `Failed to start: main: failed to load config files: [bad.json] > infra/conf: failed to build outbound config with tag out-xray-12-proxy > infra/conf: VLESS users: please add/set "encryption":"none" for every user`
	bad := writeCfg(t, "bad.json", nil, fakeCfg{TestFail: msg})
	err := p.Test(ctxT(t, 10*time.Second), bad)
	if err == nil {
		t.Fatalf("Test(bad) = nil, want an error")
	}
	if err.Error() != msg {
		t.Errorf("Test(bad) = %q, want the first printed line %q", err.Error(), msg)
	}

	if err := p.Test(ctxT(t, 10*time.Second), filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Errorf("Test(missing) = nil, want an error")
	}
}

// TestProcessTestDoesNotKillRunningChild is the invariant of spec §4 step 3:
// a config that fails validation leaves mon-client probing on the previous
// revision, so the running child must survive a failed Test untouched.
func TestProcessTestDoesNotKillRunningChild(t *testing.T) {
	p := newTestProcess(t)
	port := freePort(t)
	running := writeCfg(t, "running.json", []int{port}, fakeCfg{})
	if err := p.Start(ctxT(t, 10*time.Second), running, []int{port}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(ctxT(t, 5*time.Second)) })

	bad := writeCfg(t, "bad.json", nil, fakeCfg{TestFail: "boom"})
	if err := p.Test(ctxT(t, 10*time.Second), bad); err == nil {
		t.Fatalf("Test(bad) = nil, want an error")
	}
	if !p.Running() {
		t.Errorf("Running() = false after a failed Test, want the old child alive")
	}
	if !dialable(port) {
		t.Errorf("socks port %d stopped accepting after a failed Test", port)
	}
}

// TestProcessStartWaitsForPorts proves Start returns only once the socks
// inbounds accept (spec §4 step 3: "дождаться готовности socks-портов"): the
// fake binds them 400 ms after it starts.
func TestProcessStartWaitsForPorts(t *testing.T) {
	p := newTestProcess(t)
	ports := []int{freePort(t), freePort(t)}
	cfg := writeCfg(t, "xray.json", ports, fakeCfg{DelayMs: 400})

	start := time.Now()
	if err := p.Start(ctxT(t, 15*time.Second), cfg, ports); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(ctxT(t, 5*time.Second)) })

	if elapsed := time.Since(start); elapsed < 400*time.Millisecond {
		t.Errorf("Start returned after %v, before the ports could be bound", elapsed)
	}
	for _, port := range ports {
		if !dialable(port) {
			t.Errorf("port %d does not accept after Start", port)
		}
	}
	if !p.Running() {
		t.Errorf("Running() = false right after Start")
	}
}

// TestProcessStartFailsFastOnEarlyExit: a child that dies before its ports
// come up must not hold Start until the context expires, and the error must
// carry the first line it printed so it can become configError.
func TestProcessStartFailsFastOnEarlyExit(t *testing.T) {
	p := newTestProcess(t)
	port := freePort(t)
	const msg = "Failed to start: main: failed to load config files: [xray.json]"
	cfg := writeCfg(t, "xray.json", []int{port}, fakeCfg{ExitNow: true, ExitMsg: msg})

	start := time.Now()
	err := p.Start(ctxT(t, 30*time.Second), cfg, []int{port})
	if err == nil {
		t.Fatalf("Start = nil, want an error")
	}
	if err.Error() != msg {
		t.Errorf("Start error = %q, want %q", err.Error(), msg)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("Start took %v, want a fast failure", elapsed)
	}
	if p.Running() {
		t.Errorf("Running() = true after the child exited")
	}
}

// TestProcessStartTimesOutWhenPortsNeverCome: readiness is bounded by the
// caller's context, and a Start that gives up leaves no child behind.
func TestProcessStartTimesOutWhenPortsNeverCome(t *testing.T) {
	p := newTestProcess(t)
	bound := freePort(t)
	never := freePort(t)
	cfg := writeCfg(t, "xray.json", []int{bound}, fakeCfg{})

	err := p.Start(ctxT(t, 600*time.Millisecond), cfg, []int{bound, never})
	if err == nil {
		t.Fatalf("Start = nil, want a readiness timeout")
	}
	if p.Running() {
		t.Errorf("Running() = true after a failed Start")
	}
	if dialable(bound) {
		t.Errorf("port %d still accepts: the abandoned child was not stopped", bound)
	}
}

// TestProcessRestartWaitsForNewPorts is the apply path of spec §4 step 3:
// between cycles the child is SIGTERMed and restarted on the new config, and
// Restart returns only when the new socks ports are ready.
func TestProcessRestartWaitsForNewPorts(t *testing.T) {
	p := newTestProcess(t)
	oldPort := freePort(t)
	oldCfg := writeCfg(t, "old.json", []int{oldPort}, fakeCfg{})
	if err := p.Start(ctxT(t, 15*time.Second), oldCfg, []int{oldPort}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(ctxT(t, 5*time.Second)) })

	newPorts := []int{freePort(t), freePort(t)}
	newCfg := writeCfg(t, "new.json", newPorts, fakeCfg{DelayMs: 300})
	if err := p.Restart(ctxT(t, 15*time.Second), newCfg, newPorts); err != nil {
		t.Fatalf("Restart: %v", err)
	}
	for _, port := range newPorts {
		if !dialable(port) {
			t.Errorf("port %d does not accept after Restart", port)
		}
	}
	if dialable(oldPort) {
		t.Errorf("old port %d still accepts after Restart", oldPort)
	}
	if !p.Running() {
		t.Errorf("Running() = false after Restart")
	}
}

// TestProcessStopIsIdempotent: Stop on a Process that was never started, and
// a second Stop on a stopped one, are both no-ops — the apply path and the
// shutdown path call it without bookkeeping.
func TestProcessStopIsIdempotent(t *testing.T) {
	p := newTestProcess(t)
	if err := p.Stop(ctxT(t, time.Second)); err != nil {
		t.Fatalf("Stop before Start = %v, want nil", err)
	}
	if p.Running() {
		t.Fatalf("Running() = true before Start")
	}

	port := freePort(t)
	cfg := writeCfg(t, "xray.json", []int{port}, fakeCfg{})
	if err := p.Start(ctxT(t, 15*time.Second), cfg, []int{port}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	for range 2 {
		if err := p.Stop(ctxT(t, 5*time.Second)); err != nil {
			t.Fatalf("Stop = %v, want nil", err)
		}
		if p.Running() {
			t.Fatalf("Running() = true after Stop")
		}
	}
	if dialable(port) {
		t.Errorf("port %d still accepts after Stop", port)
	}
}

// TestProcessStopKillsOnDeadline: a child that ignores SIGTERM is killed
// once the caller's context ends (spec §4 step 3).
func TestProcessStopKillsOnDeadline(t *testing.T) {
	p := newTestProcess(t)
	port := freePort(t)
	cfg := writeCfg(t, "xray.json", []int{port}, fakeCfg{IgnoreSIGTERM: true})
	if err := p.Start(ctxT(t, 15*time.Second), cfg, []int{port}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.Stop(ctxT(t, 300*time.Millisecond)); err != nil {
		t.Fatalf("Stop = %v, want nil", err)
	}
	if p.Running() {
		t.Errorf("Running() = true after SIGKILL")
	}
}

// TestProcessStderrRingAndDiagnose is the end-to-end of spec §5: the child's
// stderr lands in the ring with mon-client's own timestamps, and the probe's
// adapter finds the target's failure in it.
func TestProcessStderrRingAndDiagnose(t *testing.T) {
	p := newTestProcess(t)
	port := freePort(t)
	cfg := writeCfg(t, "xray.json", []int{port}, fakeCfg{
		Stderr:  []string{sampleDial, sampleReality},
		Stderr2: []string{sampleFailed, otherDial, otherFailed},
	})

	since := time.Now().Add(-time.Second)
	if err := p.Start(ctxT(t, 15*time.Second), cfg, []int{port}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(ctxT(t, 5*time.Second)) })

	deadline := time.Now().Add(5 * time.Second)
	var snap []Line
	for time.Now().Before(deadline) {
		snap = p.Log().Snapshot()
		if countContaining(snap, "all retry attempts failed") == 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if countContaining(snap, "dialing TCP") != 2 {
		t.Fatalf("ring does not hold both dial lines: %+v", snap)
	}

	m, ok := p.Diagnose("www.cloudflare.com", 443, since, time.Now())
	if !ok {
		t.Fatalf("Diagnose found nothing in %+v", snap)
	}
	if m.Reason != ReasonRealityRealCert {
		t.Errorf("reason = %q, want %q", m.Reason, ReasonRealityRealCert)
	}
	if !strings.Contains(m.Detail, "failed to process outbound traffic") {
		t.Errorf("detail = %q", m.Detail)
	}
}

func countContaining(lines []Line, sub string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l.Text, sub) {
			n++
		}
	}
	return n
}

// TestProcessVersion: the heartbeat carries client.xrayVersion (protocol
// §5.3), taken from `xray version` (research §2.2 wording).
func TestProcessVersion(t *testing.T) {
	p := newTestProcess(t)
	got, err := p.Version(ctxT(t, 10*time.Second))
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if got != "26.3.27" {
		t.Errorf("Version = %q, want %q", got, "26.3.27")
	}
}

// TestProcessStartTwice: the second Start is refused rather than leaking a
// second child onto the same socks ports.
func TestProcessStartTwice(t *testing.T) {
	p := newTestProcess(t)
	port := freePort(t)
	cfg := writeCfg(t, "xray.json", []int{port}, fakeCfg{})
	if err := p.Start(ctxT(t, 15*time.Second), cfg, []int{port}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = p.Stop(ctxT(t, 5*time.Second)) })
	if err := p.Start(ctxT(t, 2*time.Second), cfg, []int{port}); err == nil {
		t.Errorf("second Start = nil, want an error")
	}
}
