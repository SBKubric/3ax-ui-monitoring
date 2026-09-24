package app

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	mrand "math/rand/v2"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/client/api"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/heartbeat"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/probe"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/proto"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/servertest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/client/state"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
)

// supHarness is one supervisor wired to a protocol stub: a real Loop over
// a fake applier whose single probe is an actual GET /v1/probe against the
// stub, so "probes must not run" (spec §6's 401 and 403 branches) is
// asserted the only way that means anything — by mon-server not seeing
// any.
type supHarness struct {
	t    *testing.T
	stub *servertest.Stub
	dir  *state.Dir
	clk  *clock.Fake
	logs *lockedBuffer
	log  *slog.Logger

	// applyErr, when set before run(), is the error every loop's applier
	// fails Apply with — the box whose config will not apply (spec §4.3),
	// which must keep reporting that error as configError even while it is
	// disabled.
	applyErr error

	mu     sync.Mutex
	sleeps []time.Duration
	stops  int
}

// harnessXrayVersion is what every loop this harness builds reports as
// client.xrayVersion (protocol §5.3), so a heartbeat that drops it is
// visible as an empty string rather than as an indistinguishable default.
const harnessXrayVersion = "Xray 1.8.24"

func newSupHarness(t *testing.T) *supHarness {
	t.Helper()
	dir, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	logs := &lockedBuffer{}
	stub := servertest.NewStub(t)
	stub.SetConfig(doc("rev1"))
	stub.SetRevision("rev1")
	return &supHarness{
		t:    t,
		stub: stub,
		dir:  dir,
		clk:  clock.NewFake(time.Date(2025, 9, 13, 12, 0, 0, 0, time.UTC)),
		logs: logs,
		log:  slog.New(slog.NewTextHandler(logs, nil)),
	}
}

// registered pre-seeds state.json and makes token valid on the stub — a
// box that is already a mon-client, which is what the 403 branch needs to
// start from.
func (h *supHarness) registered(monClientID, token string) {
	h.t.Helper()
	if err := h.dir.Save(&state.File{MonClientID: monClientID, Token: token, ServerURL: h.stub.URL()}); err != nil {
		h.t.Fatalf("state.Save: %v", err)
	}
	h.stub.Approve("req-0", monClientID, token)
}

func (h *supHarness) deps() SupervisorDeps {
	return SupervisorDeps{
		ServerURL: h.stub.URL(),
		HTTP:      h.stub.HTTPClient(),
		Dir:       h.dir,
		Clock:     h.clk,
		Sleep:     h.sleep,
		Log:       h.log,
		Version:   "0.1.0",
		Hostname:  "box-1",
		NewLoop:   h.newLoop,
	}
}

// sleep is the one seam that keeps this test file off the wall clock: it
// records the wait the supervisor (or the loop) asked for, advances the
// fake clock by it, and returns after a millisecond of real time — enough
// for the goroutine to make progress, little enough that a five-minute
// disabled cadence runs in milliseconds.
func (h *supHarness) sleep(ctx context.Context, d time.Duration) error {
	h.mu.Lock()
	h.sleeps = append(h.sleeps, d)
	h.mu.Unlock()
	h.clk.Advance(d)

	t := time.NewTimer(2 * time.Millisecond)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (h *supHarness) slept(d time.Duration) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, s := range h.sleeps {
		if s == d {
			n++
		}
	}
	return n
}

// sleepCount is every wait the supervisor and its loops have asked for,
// the only clock a supervisor test has: a negative assertion ("no probes
// happen while X") waits for the machinery to take a known number of steps
// through this seam rather than for a wall-clock duration that is a race
// on a loaded machine.
func (h *supHarness) sleepCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.sleeps)
}

func (h *supHarness) stopped() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stops
}

// newLoop is the harness' LoopFactory: a real Loop, a fake applier, and
// one probe that really goes to the stub.
func (h *supHarness) newLoop(f *state.File, c *api.Client) (*Loop, func(context.Context) error, error) {
	buf, err := heartbeat.OpenBuffer(h.dir.Path("cycles.json"))
	if err != nil {
		return nil, nil, err
	}
	applier := &fakeApplier{
		file:     f,
		probes:   map[proto.TargetKey]probe.Fn{targetKey(): h.stubProbe(f.Token)},
		applyErr: h.applyErr,
	}
	loop := NewLoop(Deps{
		API:         c,
		State:       h.dir,
		File:        f,
		Buffer:      buf,
		Runner:      probe.NewRunner(h.log),
		Applier:     applier,
		Clock:       h.clk,
		Sleep:       h.sleep,
		Rand:        mrand.New(mrand.NewPCG(1, 2)),
		Log:         h.log,
		Version:     "0.1.0",
		XrayVersion: func() string { return harnessXrayVersion },
		StartedAt:   h.clk.Now(),
	})
	return loop, func(context.Context) error {
		h.mu.Lock()
		h.stops++
		h.mu.Unlock()
		return nil
	}, nil
}

// stubProbe is a probe.Fn that performs the real tunnel probe request
// (protocol §5.2) straight at the stub — no tunnel, since what is under
// test is whether a probe happens at all, not what it measures.
func (h *supHarness) stubProbe(token string) probe.Fn {
	hc := h.stub.HTTPClient()
	base := h.stub.URL() + "/v1/probe"
	return func(ctx context.Context, k proto.TargetKey) proto.Result {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"?target="+k.String()+"&n=nonce", nil)
		if err != nil {
			return proto.Result{TargetKey: k}
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := hc.Do(req)
		if err != nil {
			return proto.Result{TargetKey: k}
		}
		defer func() { _ = resp.Body.Close() }()
		return proto.Result{TargetKey: k, Ok: resp.StatusCode == http.StatusOK}
	}
}

// counts of what mon-server has seen, by route.
func (h *supHarness) count(method, prefix string) int {
	n := 0
	for _, r := range h.stub.Requests() {
		if r.Method == method && strings.HasPrefix(r.Path, prefix) {
			n++
		}
	}
	return n
}

func (h *supHarness) probes() int     { return h.count(http.MethodGet, "/v1/probe") }
func (h *supHarness) configs() int    { return h.count(http.MethodGet, "/v1/config") }
func (h *supHarness) heartbeats() int { return h.count(http.MethodPost, "/v1/heartbeat") }

// pairingCodes is every code mon-client has submitted, in order (protocol
// §2.1) — spec §6's 401 branch must file its new request with a new one.
func (h *supHarness) pairingCodes() []string {
	var codes []string
	for _, r := range h.stub.Requests() {
		if r.Method != http.MethodPost || r.Path != "/v1/register" {
			continue
		}
		var req proto.RegisterRequest
		if err := json.Unmarshal(r.Body, &req); err != nil {
			continue
		}
		codes = append(codes, req.PairingCode)
	}
	return codes
}

// pollIDs is every registration request id mon-client has polled, in
// order: the harness' way of learning the requestId to Approve.
func (h *supHarness) pollIDs() []string {
	seen := map[string]bool{}
	var ids []string
	for _, r := range h.stub.Requests() {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.Path, "/v1/register/") {
			continue
		}
		id := strings.TrimPrefix(r.Path, "/v1/register/")
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	return ids
}

// waitFor blocks until cond holds, failing the test with what after five
// seconds. Everything a supervisor test waits for happens in milliseconds
// (the harness' sleep sees to that); the deadline only exists so a broken
// branch fails instead of hanging.
func (h *supHarness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	h.t.Fatalf("timed out waiting for %s\nlogs:\n%s", what, h.logs.String())
}

// stateExists reports whether state.json is on disk.
func (h *supHarness) stateExists() bool {
	_, err := os.Stat(h.dir.Path("state.json"))
	return err == nil
}

// run starts the supervisor on its own goroutine and returns a stop
// function that cancels it and asserts it came back cleanly (a cancelled
// ctx is an ordinary shutdown, reported as nil).
func (h *supHarness) run() func() {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- RunSupervisor(ctx, h.deps()) }()
	return func() {
		h.t.Helper()
		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				h.t.Fatalf("RunSupervisor = %v, want nil on a cancelled context", err)
			}
		case <-time.After(5 * time.Second):
			h.t.Fatalf("RunSupervisor did not return after cancel\nlogs:\n%s", h.logs.String())
		}
	}
}

// TestSupervisor_TokenRevokedClearsStateAndRegistersAgain is spec §6's
// "401 token_revoked → остановить пробы, стереть state-файл, §3": the box
// loses its state file, files a *new* registration request with a *new*
// pairing code, runs no probes while it waits, and comes back as a
// different mon-client on the token that approval hands it.
func TestSupervisor_TokenRevokedClearsStateAndRegistersAgain(t *testing.T) {
	h := newSupHarness(t)
	stop := h.run()
	defer stop()

	h.waitFor("the first registration poll", func() bool { return len(h.pollIDs()) > 0 })
	firstCode := h.pairingCodes()[0]
	h.stub.Approve(h.pollIDs()[0], "ams-1", "tok1")

	h.waitFor("the loop to probe and heartbeat", func() bool { return h.probes() > 0 && h.heartbeats() > 0 })

	// Revoke: every authenticated route answers 401 from here on.
	h.stub.SetTokenStatus(http.StatusUnauthorized)

	h.waitFor("state.json to be cleared", func() bool { return !h.stateExists() })
	h.waitFor("a second registration request", func() bool { return len(h.pairingCodes()) > 1 })

	if codes := h.pairingCodes(); codes[1] == firstCode {
		t.Fatalf("re-registration reused pairing code %q; spec §3 wants a new one", codes[1])
	}
	if h.stopped() == 0 {
		t.Fatal("the loop's stop function was never called; spec §6 wants probing stopped on a 401")
	}

	// Spec §6: no probes while the box has no identity. Nothing can resume
	// until the new request is approved, so the count must hold — and
	// "hold" is measured in the waits registration's polling takes through
	// the harness' sleeper, not in wall-clock time, so the assertion is
	// the same on an idle machine and a loaded one.
	probesAtRevoke := h.probes()
	waitsAtRevoke := h.sleepCount()
	h.waitFor("several registration polls", func() bool { return h.sleepCount() >= waitsAtRevoke+5 })
	if got := h.probes(); got != probesAtRevoke {
		t.Fatalf("%d probes during re-registration, want none (was %d)", got-probesAtRevoke, probesAtRevoke)
	}

	h.waitFor("the second request to be polled", func() bool { return len(h.pollIDs()) > 1 })
	h.stub.SetTokenStatus(0)
	h.stub.Approve(h.pollIDs()[1], "ams-2", "tok2")

	h.waitFor("a heartbeat from the new identity", func() bool {
		for _, hb := range h.stub.Heartbeats() {
			if hb.MonClientID == "ams-2" {
				return true
			}
		}
		return false
	})
	h.waitFor("probes to resume", func() bool { return h.probes() > probesAtRevoke })

	if !strings.Contains(h.logs.String(), "token revoked, re-registering") {
		t.Fatalf("logs do not mention the revocation:\n%s", h.logs.String())
	}
}

// TestSupervisor_DisabledHeartbeatsEveryFiveMinutesThenResumes is spec
// §6's "403 disabled → остановить пробы, heartbeat раз в 5 мин до 200":
// bare heartbeats on a five-minute cadence, no probes at all, and the
// ordinary cycle back once mon-server answers 200.
func TestSupervisor_DisabledHeartbeatsEveryFiveMinutesThenResumes(t *testing.T) {
	h := newSupHarness(t)
	h.registered("ams-1", "tok")
	stop := h.run()
	defer stop()

	h.waitFor("the loop to probe and heartbeat", func() bool { return h.probes() > 0 && h.heartbeats() > 0 })

	// The five-minute waits are counted from before the 403 is even
	// served: the supervisor logs "disabled" and then goes straight into
	// its first wait, so a snapshot taken after the log line may or may
	// not already include that wait, while the heartbeat that follows it
	// is counted below as a disabled one either way.
	fiveMinFrom := h.slept(disabledHeartbeatInterval)
	h.stub.SetTokenStatus(http.StatusForbidden)
	h.waitFor("the disabled branch", func() bool {
		return strings.Contains(h.logs.String(), "mon-client disabled, probing stopped")
	})

	probesAtDisable := h.probes()
	disabledFrom := h.heartbeats()

	// Three heartbeats later, still no probes and three more five-minute
	// waits — the whole of disabled mode.
	h.waitFor("three disabled heartbeats", func() bool { return h.heartbeats() >= disabledFrom+3 })
	if got := h.probes(); got != probesAtDisable {
		t.Fatalf("%d probes while disabled, want none", got-probesAtDisable)
	}
	if got := h.slept(disabledHeartbeatInterval) - fiveMinFrom; got < 3 {
		t.Fatalf("%d five-minute waits while disabled, want at least 3", got)
	}
	if h.stopped() == 0 {
		t.Fatal("the loop's stop function was never called; spec §6 wants probing stopped on a 403")
	}

	// Re-enabled: the next bare heartbeat is answered 200 and the cycle
	// resumes on the same identity.
	acceptedBefore := len(h.stub.Heartbeats())
	configsWhileDisabled := h.configs()
	h.stub.SetTokenStatus(0)

	h.waitFor("the bare heartbeat that finds the box enabled", func() bool {
		return len(h.stub.Heartbeats()) > acceptedBefore
	})
	bare := h.stub.Heartbeats()[acceptedBefore]
	if len(bare.Cycles) != 0 {
		t.Fatalf("the disabled heartbeat carried %d cycles, want none", len(bare.Cycles))
	}
	if bare.MonClientID != "ams-1" || bare.Client.Version != "0.1.0" {
		t.Fatalf("bare heartbeat = %+v, want the client block of ams-1", bare)
	}
	// Protocol §5.3: bare or not, the client block is the whole client
	// block — a disabled box still says which xray it has.
	if bare.Client.XrayVersion != harnessXrayVersion {
		t.Fatalf("bare heartbeat xrayVersion = %q, want %q", bare.Client.XrayVersion, harnessXrayVersion)
	}
	if bare.Client.UptimeMs <= 0 {
		t.Fatalf("bare heartbeat uptimeMs = %d, want the process' age", bare.Client.UptimeMs)
	}

	h.waitFor("probes to resume", func() bool { return h.probes() > probesAtDisable })
	// Spec §6: a re-enabled box gets a freshly built loop, and a fresh
	// loop fetches GET /v1/config before its first cycle (spec §4.1) —
	// the disable may have lasted across any number of revisions.
	h.waitFor("the config to be fetched again", func() bool { return h.configs() > configsWhileDisabled })
	h.waitFor("a cycle to be delivered again", func() bool {
		for _, hb := range h.stub.Heartbeats()[acceptedBefore:] {
			if len(hb.Cycles) > 0 {
				return true
			}
		}
		return false
	})
	if !strings.Contains(h.logs.String(), "enabled again, resuming") {
		t.Fatalf("logs do not mention resuming:\n%s", h.logs.String())
	}
	if h.stateExists() != true {
		t.Fatal("state.json was cleared on a 403; spec §6 keeps it")
	}
}

// TestSupervisor_DisabledHeartbeatCarriesConfigError pins the other half
// of protocol §5.3's client block on a disabled box: a mon-client whose
// applied config is broken is very often a mon-client an operator has just
// disabled *because* it is broken, and the five-minute bare heartbeats are
// then the only thing still telling them why. So configError rides along
// with them, exactly as it rides along with an ordinary heartbeat (spec
// §4.3: "до следующего успешного применения").
func TestSupervisor_DisabledHeartbeatCarriesConfigError(t *testing.T) {
	h := newSupHarness(t)
	h.applyErr = errors.New("xray config rejected: no such outbound\nsecond line")
	h.registered("ams-1", "tok")
	stop := h.run()
	defer stop()

	h.waitFor("the loop to heartbeat", func() bool { return h.heartbeats() > 0 })
	h.stub.SetTokenStatus(http.StatusForbidden)
	h.waitFor("the disabled branch", func() bool {
		return strings.Contains(h.logs.String(), "mon-client disabled, probing stopped")
	})

	acceptedBefore := len(h.stub.Heartbeats())
	h.stub.SetTokenStatus(0)
	h.waitFor("the bare heartbeat that finds the box enabled", func() bool {
		return len(h.stub.Heartbeats()) > acceptedBefore
	})

	bare := h.stub.Heartbeats()[acceptedBefore]
	if len(bare.Cycles) != 0 {
		t.Fatalf("the disabled heartbeat carried %d cycles, want none", len(bare.Cycles))
	}
	if bare.Client.ConfigError == nil {
		t.Fatalf("bare heartbeat carried no configError; client = %+v", bare.Client)
	}
	// Spec §4.3: the first line only.
	if got, want := *bare.Client.ConfigError, "xray config rejected: no such outbound"; got != want {
		t.Fatalf("bare heartbeat configError = %q, want %q", got, want)
	}
	if bare.Client.XrayVersion != harnessXrayVersion {
		t.Fatalf("bare heartbeat xrayVersion = %q, want %q", bare.Client.XrayVersion, harnessXrayVersion)
	}
}

// TestSupervisor_RevokedWhileDisabledRegistersAgain checks the transition
// between spec §6's two branches: an operator who revokes a mon-client
// that is currently disabled must get a re-registration, not a mon-client
// heartbeating a dead token every five minutes forever.
func TestSupervisor_RevokedWhileDisabledRegistersAgain(t *testing.T) {
	h := newSupHarness(t)
	h.registered("ams-1", "tok")
	stop := h.run()
	defer stop()

	h.waitFor("the loop to heartbeat", func() bool { return h.heartbeats() > 0 })
	h.stub.SetTokenStatus(http.StatusForbidden)
	h.waitFor("the disabled branch", func() bool {
		return strings.Contains(h.logs.String(), "mon-client disabled, probing stopped")
	})
	disabledFrom := h.heartbeats()
	h.waitFor("a disabled heartbeat", func() bool { return h.heartbeats() > disabledFrom })

	h.stub.SetTokenStatus(http.StatusUnauthorized)
	h.waitFor("state.json to be cleared", func() bool { return !h.stateExists() })
	h.waitFor("a new registration request", func() bool { return len(h.pairingCodes()) > 0 })
}

// TestSupervisor_TokenRevokedClearsCycles pins the other half of spec §6's
// 401 branch: the cycles buffered under the revoked identity must not be
// delivered under the new one. mon-server tracks ackSeq per mon-client
// (protocol §5.3), so the first heartbeat of the new identity has to start
// at seq 1 and carry nothing older.
func TestSupervisor_TokenRevokedClearsCycles(t *testing.T) {
	h := newSupHarness(t)
	stop := h.run()
	defer stop()

	h.waitFor("the first registration poll", func() bool { return len(h.pollIDs()) > 0 })
	h.stub.Approve(h.pollIDs()[0], "ams-1", "tok1")

	// Let the first identity buffer cycles that are never acknowledged, so
	// there is something on disk for the 401 to throw away.
	h.stub.DropNextHeartbeats(3)
	h.waitFor("unacknowledged cycles", func() bool { return h.heartbeats() >= 3 })
	if _, err := os.Stat(h.dir.Path("cycles.json")); err != nil {
		t.Fatalf("cycles.json was never written: %v", err)
	}

	h.stub.SetTokenStatus(http.StatusUnauthorized)
	// clearState removes cycles.json before state.json, so once the
	// identity is gone the buffer is already gone with it.
	h.waitFor("state.json to be cleared", func() bool { return !h.stateExists() })
	if _, err := os.Stat(h.dir.Path("cycles.json")); !os.IsNotExist(err) {
		t.Fatalf("cycles.json survived the 401: %v", err)
	}

	// The new identity: approve it and read its first heartbeat.
	h.waitFor("a second registration poll", func() bool { return len(h.pollIDs()) > 1 })
	h.stub.SetTokenStatus(0)
	h.stub.Approve(h.pollIDs()[1], "ams-2", "tok2")

	h.waitFor("a heartbeat from the new identity", func() bool {
		for _, hb := range h.stub.Heartbeats() {
			if hb.MonClientID == "ams-2" {
				return true
			}
		}
		return false
	})
	for _, hb := range h.stub.Heartbeats() {
		if hb.MonClientID != "ams-2" {
			continue
		}
		if len(hb.Cycles) == 0 {
			t.Fatal("the new identity's heartbeat carried no cycles at all")
		}
		if got := hb.Cycles[0].Seq; got != 1 {
			t.Fatalf("the new identity's first cycle has seq %d, want 1", got)
		}
		break
	}
}

// TestSupervisor_TokenRevokedKeepsIdentityUntilCyclesCleared pins the order
// of clearState: cycles.json is removed before state.json. Removing the
// identity first left a window in which the box had no state file but
// still held the revoked identity's cycles — a crash there, or a failed
// second remove, and the next identity would deliver them as its own
// (issue #76). Here the buffer cannot be removed (it is a non-empty
// directory), and the identity must survive so the next pass meets the
// same 401 and tries again.
func TestSupervisor_TokenRevokedKeepsIdentityUntilCyclesCleared(t *testing.T) {
	h := newSupHarness(t)
	h.registered("ams-1", "tok")
	if err := os.MkdirAll(h.dir.Path("cycles.json")+"/stuck", 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	s := &supervisor{d: h.deps().withDefaults()}
	if err := s.clearState(); err == nil {
		t.Fatal("clearState = nil with an unremovable cycles.json, want an error")
	}
	if !h.stateExists() {
		t.Fatal("state.json was removed although cycles.json was not; the next identity would inherit the old cycles")
	}
}
