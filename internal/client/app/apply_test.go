package app

import (
	"context"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/config"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/xray/xraytest"
)

// TestMain removes the fake xray binary xraytest built for this package's
// tests: Build has to leave it in place for the whole run (every test
// shares one build), so the only moment left to clean up is here, and
// os.Exit runs no deferred function.
func TestMain(m *testing.M) {
	code := m.Run()
	xraytest.Cleanup()
	os.Exit(code)
}

// Sample material in the shapes the panel generates (the same links
// internal/client/config's own tests use): documentation addresses and
// throwaway keys only.
const (
	vlessRealityLink = "vless://8c1ef5c2-2c09-4f3a-93f2-3b5c1a4d6e70@198.51.100.10:443" +
		"?type=tcp&encryption=none&flow=xtls-rprx-vision&security=reality" +
		"&sni=www.microsoft.com&pbk=jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0" +
		"&sid=6ba85179e30d4fc2&fp=chrome&spx=%2FKmSmLBwPvOvfmd#ams-1-proxy"

	trojanGRPCLink = "trojan://s3cr3t-p4ssw0rd@198.51.100.20:443" +
		"?type=grpc&security=tls&sni=trojan.example.org&serviceName=probesvc&mode=multi#ams-2"

	awgConf = `[Interface]
PrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=
Address = 10.66.66.2/32
MTU = 1420
Jc = 4

[Peer]
PublicKey = KCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkc=
AllowedIPs = 0.0.0.0/0
Endpoint = 198.51.100.50:51820
`
)

func xrayTarget(path, link string) proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "xray", InboundID: 12, Path: path},
		Protocol:  "vless",
		Link:      link,
	}
}

func awgTarget() proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "awg", InboundID: 0, Path: "proxy"},
		Protocol:  "awg",
		Conf:      awgConf,
	}
}

// revisionDoc is a config document of one revision carrying targets.
func revisionDoc(revision string, targets ...proto.Target) *proto.ConfigDoc {
	return &proto.ConfigDoc{
		ConfigRevision: revision,
		MonClientID:    "ams-1",
		ProbeURL:       "https://mon.example/v1/probe",
		Probe: proto.ProbeParams{
			IntervalMs: 60_000, BudgetMs: 500, ConnectMs: 200, TlsMs: 200,
			HeadersMs: 200, StartJitterMs: 0, HeartbeatTimeoutMs: 1_000,
		},
		Targets: targets,
	}
}

// applierHarness is a RevisionApplier over a fresh state directory and the
// fake xray binary (internal/client/xray/xraytest), which is as close to
// the real apply path as a unit test gets: a real child process is started,
// tested and restarted.
type applierHarness struct {
	applier *RevisionApplier
	dir     *state.Dir
	file    *state.File
	child   *xray.Process
	logs    *lockedBuffer
}

func newApplierHarness(t *testing.T, withXray bool) *applierHarness {
	t.Helper()

	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	file := &state.File{MonClientID: "ams-1", Token: "tok"}
	if err := dir.Save(file); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(logs, nil))

	var child *xray.Process
	if withXray {
		child = xray.New(xraytest.Build(t), logger)
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = child.Stop(ctx)
		})
	}

	return &applierHarness{
		applier: NewRevisionApplier(ApplierDeps{Xray: child, Dir: dir, File: file, Log: logger}),
		dir:     dir,
		file:    file,
		child:   child,
		logs:    logs,
	}
}

func (h *applierHarness) xrayJSON(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.dir.Path("xray.json"))
	if err != nil {
		t.Fatalf("read xray.json: %v", err)
	}
	return string(raw)
}

func dialable(t *testing.T, port int) bool {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// TestApply_WritesXrayJSONAndStartsTheChild is spec §4 step 3's happy
// path: the generated config lands in the state directory, passes -test,
// the child runs on it with its socks ports up, and appliedRevision is
// recorded.
func TestApply_WritesXrayJSONAndStartsTheChild(t *testing.T) {
	h := newApplierHarness(t, true)

	if err := h.applier.Apply(context.Background(), revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := h.xrayJSON(t); !strings.Contains(got, `"port": `+strconv.Itoa(config.FirstSocksPort)) {
		t.Errorf("xray.json does not carry the first socks inbound:\n%s", got)
	}
	if !h.child.Running() {
		t.Error("the xray child is not running after a successful apply")
	}
	if !dialable(t, config.FirstSocksPort) {
		t.Errorf("socks port %d does not accept connections", config.FirstSocksPort)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1", h.file.AppliedRevision)
	}
	saved, err := h.dir.Load()
	if err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	if saved.AppliedRevision != "rev1" {
		t.Errorf("state.json appliedRevision = %q, want rev1", saved.AppliedRevision)
	}

	doc, probes, cfgErr := h.applier.Applied()
	if cfgErr != nil {
		t.Errorf("configError = %v, want none", cfgErr)
	}
	if doc == nil || doc.ConfigRevision != "rev1" {
		t.Errorf("Applied doc = %+v, want rev1", doc)
	}
	if len(probes) != 1 {
		t.Errorf("%d probes, want one per target", len(probes))
	}
	if !strings.Contains(h.logs.String(), "applied revision rev1: 1 xray targets, 0 awg targets") {
		t.Errorf("logs = %q, want the spec §7 revision line", h.logs.String())
	}
}

// TestApply_TestFailureKeepsTheOldRevision is spec §4 step 3's "`-test`
// упал → остаться на старой ревизии": the previous document, the previous
// xray.json and the running child all stay, and the error becomes the
// configError. A later good revision clears it.
func TestApply_TestFailureKeepsTheOldRevision(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	before := h.xrayJSON(t)

	xraytest.Scripted(t, xraytest.Script{TestFail: "Failed to start: main: failed to load config files: bad outbound"})
	err := h.applier.Apply(ctx, revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), xrayTarget("direct", trojanGRPCLink)))
	if err == nil {
		t.Fatal("Apply = nil, want the -test failure")
	}
	if !strings.Contains(err.Error(), "bad outbound") {
		t.Errorf("error = %q, want xray's own first line", err)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1 kept", h.file.AppliedRevision)
	}
	if got := h.xrayJSON(t); got != before {
		t.Error("xray.json was replaced by a config that failed -test")
	}
	if !h.child.Running() {
		t.Error("the child was stopped by a failed -test; probes must continue on the old config")
	}
	doc, probes, cfgErr := h.applier.Applied()
	if doc.ConfigRevision != "rev1" || len(probes) != 1 {
		t.Errorf("Applied = %+v / %d probes, want the rev1 document", doc, len(probes))
	}
	if cfgErr == nil || !strings.Contains(cfgErr.Error(), "bad outbound") {
		t.Errorf("configError = %v, want the -test failure", cfgErr)
	}

	// A later revision that does pass clears the configError (spec §4
	// step 3: it is carried "until the next successful apply").
	t.Setenv(xraytest.ScriptEnv, "")
	if err := h.applier.Apply(ctx, revisionDoc("rev3", xrayTarget("proxy", vlessRealityLink), xrayTarget("direct", trojanGRPCLink))); err != nil {
		t.Fatalf("Apply rev3: %v", err)
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 2 {
		t.Errorf("after a good apply: configError = %v, %d probes; want none and two", cfgErr, len(probes))
	}
	if h.file.AppliedRevision != "rev3" {
		t.Errorf("AppliedRevision = %q, want rev3", h.file.AppliedRevision)
	}
	if !dialable(t, config.FirstSocksPort+1) {
		t.Errorf("socks port %d of the second target is not up", config.FirstSocksPort+1)
	}
}

// TestApply_ParseErrorNamesTheTarget is the other half of spec §4 step 3's
// error branch ("ссылка не разобралась"): nothing is written, nothing is
// restarted, and the configError says which target is broken.
func TestApply_ParseErrorNamesTheTarget(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	before := h.xrayJSON(t)

	bad := xrayTarget("direct", "vless://id@198.51.100.10:443?security=reality&pbk=k") // no fp
	err := h.applier.Apply(ctx, revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), bad))
	if err == nil {
		t.Fatal("Apply = nil, want the link parse error")
	}
	if !strings.Contains(err.Error(), "xray:12:direct") {
		t.Errorf("error = %q, want the offending target key", err)
	}
	if len(err.Error()) > maxConfigError {
		t.Errorf("error is %d characters, over the configError limit", len(err.Error()))
	}
	if h.file.AppliedRevision != "rev1" || h.xrayJSON(t) != before {
		t.Error("a document that would not parse changed the applied revision")
	}
}

// TestApply_AWGOnlyDocumentWithoutXray is the AWG-only box of spec §1: no
// xray binary at all, and a document of AWG-targets still applies.
func TestApply_AWGOnlyDocumentWithoutXray(t *testing.T) {
	h := newApplierHarness(t, false)

	if err := h.applier.Apply(context.Background(), revisionDoc("rev1", awgTarget())); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("AppliedRevision = %q, want rev1", h.file.AppliedRevision)
	}
	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 1 {
		t.Errorf("Applied = %d probes, err %v; want one AWG probe and no error", len(probes), cfgErr)
	}
	if _, err := os.Stat(h.dir.Path("xray.json")); !os.IsNotExist(err) {
		t.Error("xray.json was written by a box with no xray binary")
	}
}

// TestApply_XrayTargetWithoutBinaryIsAConfigError: the same box handed a
// document with xray-targets cannot probe them, and says so rather than
// pretending they are down (spec §4 step 3's configError).
func TestApply_XrayTargetWithoutBinaryIsAConfigError(t *testing.T) {
	h := newApplierHarness(t, false)

	err := h.applier.Apply(context.Background(), revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink)))
	if err == nil || !strings.Contains(err.Error(), "xray") {
		t.Fatalf("Apply = %v, want an error naming the missing xray binary", err)
	}
	if h.file.AppliedRevision != "" {
		t.Errorf("AppliedRevision = %q, want nothing applied", h.file.AppliedRevision)
	}
}

// TestApply_EmptyDocumentRunsAnEmptyCycle is spec §4 step 4: a box with no
// targets applies the document, keeps no child running and probes nothing.
func TestApply_EmptyDocumentRunsAnEmptyCycle(t *testing.T) {
	h := newApplierHarness(t, true)
	ctx := context.Background()

	if err := h.applier.Apply(ctx, revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink))); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}
	if err := h.applier.Apply(ctx, revisionDoc("rev2")); err != nil {
		t.Fatalf("Apply rev2 (empty): %v", err)
	}

	if _, probes, cfgErr := h.applier.Applied(); cfgErr != nil || len(probes) != 0 {
		t.Errorf("Applied = %d probes, err %v; want an empty cycle", len(probes), cfgErr)
	}
	if h.child.Running() {
		t.Error("the child is still running with no xray-targets left to probe")
	}
	if strings.Contains(h.xrayJSON(t), "198.51.100.10") {
		t.Error("xray.json still carries the dropped target")
	}
	if h.file.AppliedRevision != "rev2" {
		t.Errorf("AppliedRevision = %q, want rev2", h.file.AppliedRevision)
	}
}

// TestApply_WaitsForProbesInFlight is spec §4 step 3's "дождаться проб в
// полёте": the applier's cycle guard is what the loop holds for the
// duration of a cycle, and Apply must not swap anything while it is held.
func TestApply_WaitsForProbesInFlight(t *testing.T) {
	h := newApplierHarness(t, false)
	ctx := context.Background()
	if err := h.applier.Apply(ctx, revisionDoc("rev1", awgTarget())); err != nil {
		t.Fatalf("Apply rev1: %v", err)
	}

	var guard CycleGuard = h.applier
	guard.BeginCycle()

	applied := make(chan struct{})
	go func() {
		defer close(applied)
		if err := h.applier.Apply(ctx, revisionDoc("rev2", awgTarget())); err != nil {
			t.Errorf("Apply rev2: %v", err)
		}
	}()

	// While the cycle is in flight the old revision is still in force, no
	// matter how long the apply has been waiting.
	select {
	case <-applied:
		t.Fatal("Apply finished while a cycle was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	if doc, _, _ := h.applier.Applied(); doc.ConfigRevision != "rev1" {
		t.Fatalf("Applied revision = %q during a cycle, want rev1", doc.ConfigRevision)
	}

	guard.EndCycle()
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("Apply did not finish after the cycle ended")
	}
	if doc, _, _ := h.applier.Applied(); doc.ConfigRevision != "rev2" {
		t.Fatalf("Applied revision = %q after the cycle, want rev2", doc.ConfigRevision)
	}
}

// TestLoop_ConfigErrorFromARealApplyReachesTheHeartbeat drives the whole
// step through the loop and a protocol stub: a revision that xray rejects
// leaves the heartbeat reporting the old revision plus the configError
// (spec §4 step 3, protocol §5.3), and the next revision that applies
// clears it.
func TestLoop_ConfigErrorFromARealApplyReachesTheHeartbeat(t *testing.T) {
	h := newHarness(t, nil)
	ha := newApplierHarness(t, true)
	// The loop and the applier must share one state file, exactly as
	// cmd/mon-client wires them.
	applier := NewRevisionApplier(ApplierDeps{
		XrayProber: &probe.Prober{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))},
		Xray:       ha.child,
		Dir:        h.dir,
		File:       h.file,
		Log:        slog.New(slog.NewTextHandler(h.logs, nil)),
	})
	loop := h.withApplier(t, applier)
	ctx := context.Background()

	h.stub.SetConfig(revisionDoc("rev1", xrayTarget("proxy", vlessRealityLink)))
	h.stub.SetRevision("rev2") // mon-server already has a newer one
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	if hbs := h.stub.Heartbeats(); len(hbs) != 1 || hbs[0].ConfigRevision != "rev1" || hbs[0].Client.ConfigError != nil {
		t.Fatalf("first heartbeat = %+v, want rev1 with no configError", hbs)
	}

	xraytest.Scripted(t, xraytest.Script{TestFail: "Failed to start: main: bad outbound in rev2"})
	h.stub.SetConfig(revisionDoc("rev2", xrayTarget("proxy", vlessRealityLink), xrayTarget("direct", trojanGRPCLink)))
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs := h.stub.Heartbeats()
	if len(hbs) != 2 {
		t.Fatalf("%d heartbeats, want 2", len(hbs))
	}
	if hbs[1].ConfigRevision != "rev1" {
		t.Errorf("configRevision = %q, want the old revision kept", hbs[1].ConfigRevision)
	}
	if hbs[1].Client.ConfigError == nil || !strings.Contains(*hbs[1].Client.ConfigError, "bad outbound in rev2") {
		t.Fatalf("client.configError = %v, want xray's -test line", hbs[1].Client.ConfigError)
	}

	t.Setenv(xraytest.ScriptEnv, "")
	if err := loop.Once(ctx); err != nil {
		t.Fatalf("Once: %v", err)
	}
	hbs = h.stub.Heartbeats()
	if len(hbs) != 3 {
		t.Fatalf("%d heartbeats, want 3", len(hbs))
	}
	if hbs[2].ConfigRevision != "rev2" || hbs[2].Client.ConfigError != nil {
		t.Fatalf("third heartbeat = %+v, want rev2 with the configError cleared", hbs[2])
	}
	// Two targets now, so two results — and both probes went through the
	// child's socks ports, which is the whole point of the restart.
	if got := hbs[2].Cycles[0].Results; len(got) != 2 {
		t.Fatalf("%d results, want one per applied target", len(got))
	}
}

// TestApply_StateSaveFailureKeepsOldRevision pins the order apply() works
// in: appliedRevision reaches state.json before the probe set is swapped,
// so a state directory that cannot be written (here read-only, the shape a
// full disk takes) leaves the old revision *fully* in force rather than
// probing the new targets while reporting the old revision to mon-server
// (protocol §5.3).
func TestApply_StateSaveFailureKeepsOldRevision(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	h := newApplierHarness(t, false)
	ctx := context.Background()

	// An AWG-only document: no xray child is involved, so the only write
	// this apply does is state.json's.
	first := revisionDoc("rev1", awgTarget())
	if err := h.applier.Apply(ctx, first); err != nil {
		t.Fatalf("apply rev1: %v", err)
	}

	if err := os.Chmod(h.dir.Path(""), 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(h.dir.Path(""), 0o700) })

	second := revisionDoc("rev2", awgTarget(), awgTarget2())
	err := h.applier.Apply(ctx, second)
	if err == nil {
		t.Fatal("apply reported success although appliedRevision could not be saved")
	}

	doc, probes, configErr := h.applier.Applied()
	if doc != first {
		t.Errorf("applied doc = %v, want rev1 — the old revision stays in force", doc)
	}
	if len(probes) != 1 {
		t.Errorf("applied probes = %d, want rev1's single target", len(probes))
	}
	if configErr == nil || !strings.Contains(configErr.Error(), "save applied revision") {
		t.Errorf("configError = %v, want the save failure", configErr)
	}
	if h.file.AppliedRevision != "rev1" {
		t.Errorf("appliedRevision = %q, want rev1", h.file.AppliedRevision)
	}
}

// awgTarget2 is a second AWG-target, so a revision can differ from another
// in more than its name.
func awgTarget2() proto.Target {
	return proto.Target{
		TargetKey: proto.TargetKey{InboundKind: "awg", InboundID: 1, Path: "direct"},
		Protocol:  "awg",
		Conf:      awgConf,
	}
}
