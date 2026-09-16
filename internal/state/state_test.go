package state

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// testTime is where the fake clock of every test starts.
var testTime = time.Date(2025, 9, 13, 10, 0, 0, 0, time.UTC)

// testClientID is the mon-client every harness registers.
const testClientID = "ams-1"

// xrayProxy and awgDirect are the two targets the tests probe.
var (
	xrayProxy  = TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy}
	xrayDirect = TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathDirect}
	awgDirect  = TargetKey{InboundKind: store.InboundKindAWG, InboundID: 0, Path: store.PathDirect}
)

// eventRecord is one row of events_outbox flattened to what a test asserts on.
type eventRecord struct {
	Kind        string
	MonClientID string
	// Target is the "kind:inboundId:path" key, empty for a mon_client event.
	Target   string
	From     string
	To       string
	Reason   string
	Notified bool
	TS       int64
}

// statsCall is one call the state machine made to the statistics sink.
type statsCall struct {
	monClientID string
	cycleTS     int64
	results     []Result
	unverified  bool
}

// statsRecorder is the StatsSink step 7 will replace, recording what it is
// handed so the tests can assert on the cycle selection.
type statsRecorder struct {
	mu    sync.Mutex
	calls []statsCall
}

// Record implements StatsSink.
func (r *statsRecorder) Record(_ context.Context, monClientID string, cycleTS int64, results []Result, unverified bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, statsCall{monClientID: monClientID, cycleTS: cycleTS, results: append([]Result(nil), results...), unverified: unverified})
	return nil
}

// took returns the calls recorded so far.
func (r *statsRecorder) took() []statsCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]statsCall(nil), r.calls...)
}

// alertRecorder captures the Telegram messages mon-server sends itself.
type alertRecorder struct {
	mu    sync.Mutex
	texts []string
}

func (a *alertRecorder) fn() alert.Func {
	return func(_ context.Context, text string) {
		a.mu.Lock()
		defer a.mu.Unlock()
		a.texts = append(a.texts, text)
	}
}

func (a *alertRecorder) sent() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.texts...)
}

// harness is a Machine on a real SQLite store in a temporary directory, driven
// by a fake clock.
type harness struct {
	t      *testing.T
	st     *store.Store
	clk    *clock.Fake
	m      *Machine
	mon    *Monitor
	alerts *alertRecorder
	stats  *statsRecorder

	seq       int64
	seen      int
	seenStats int
	seenAlert int
}

// newHarness opens the store, registers one mon-client and returns the
// machine under test.
func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := clock.NewFake(testTime)
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), slog.New(slog.DiscardHandler), store.WithClock(fake))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close store: %v", err)
		}
	})
	alerts := &alertRecorder{}
	stats := &statsRecorder{}
	m := New(st, fake, alerts.fn(), slog.New(slog.DiscardHandler), WithStatsSink(stats))
	h := &harness{t: t, st: st, clk: fake, m: m, mon: NewMonitor(m), alerts: alerts, stats: stats}
	h.addMonClient(testClientID, store.ClientStateNever)
	return h
}

// addMonClient inserts a registered mon-client in the given state.
func (h *harness) addMonClient(id, state string) {
	h.t.Helper()
	paths, err := store.EncodePaths(store.DefaultPaths())
	if err != nil {
		h.t.Fatalf("encode paths: %v", err)
	}
	mc := store.MonClient{
		ID: id, Name: "Amsterdam #1", Region: "NL", Paths: paths,
		TokenHash: store.HashToken("token-" + id), Enabled: true,
		State: state, ApprovedAt: h.now(),
	}
	if state == store.ClientStateOnline {
		mc.LastHeartbeat = h.now()
	}
	if err := h.st.DB().Create(&mc).Error; err != nil {
		h.t.Fatalf("create mon-client: %v", err)
	}
}

// now is the fake clock in the storage form.
func (h *harness) now() int64 { return clock.MS(h.clk.Now()) }

// advance moves the fake clock forward.
func (h *harness) advance(d time.Duration) { h.clk.Advance(d) }

// sync gives the mon-client exactly these targets, the way the panel poll
// does after rebuilding its configuration.
func (h *harness) sync(keys ...TargetKey) {
	h.t.Helper()
	if err := h.m.SyncTargets(context.Background(), testClientID, keys); err != nil {
		h.t.Fatalf("SyncTargets: %v", err)
	}
}

// setConfigRevision pretends step 5 has built a configuration document.
func (h *harness) setConfigRevision(revision string) {
	h.t.Helper()
	cfg := store.ClientConfig{MonClientID: testClientID, Revision: revision, Document: "{}", BuiltAt: h.now()}
	if err := h.st.DB().Save(&cfg).Error; err != nil {
		h.t.Fatalf("save client config: %v", err)
	}
}

// heartbeat applies one heartbeat and fails the test if it is rejected.
func (h *harness) heartbeat(hb Heartbeat) HeartbeatAck {
	h.t.Helper()
	ack, err := h.m.Heartbeat(context.Background(), testClientID, hb)
	if err != nil {
		h.t.Fatalf("Heartbeat: %v", err)
	}
	return ack
}

// cycle builds one live cycle numbered by the harness, stamped with the fake
// clock.
func (h *harness) cycle(results ...Result) Cycle {
	h.seq++
	return Cycle{Seq: h.seq, TS: h.now(), Results: results}
}

// probe sends one heartbeat carrying a single live cycle with one result, the
// shape of a normal minute of monitoring.
func (h *harness) probe(key TargetKey, ok bool, reason string) {
	h.t.Helper()
	h.heartbeat(Heartbeat{Cycles: []Cycle{h.cycle(result(key, ok, reason))}})
}

// probeN sends n such heartbeats a minute apart.
func (h *harness) probeN(key TargetKey, ok bool, reason string, n int) {
	h.t.Helper()
	for i := 0; i < n; i++ {
		h.probe(key, ok, reason)
		h.advance(time.Minute)
	}
}

// result builds one probe result.
func result(key TargetKey, ok bool, reason string) Result {
	r := Result{InboundKind: key.InboundKind, InboundID: key.InboundID, Path: key.Path, OK: ok}
	if ok {
		r.TLSMS = ptr(int64(47))
		r.EgressIP = "203.0.113.10"
		return r
	}
	r.Reason = reason
	return r
}

// ptr is the pointer form the nullable millisecond fields use.
func ptr[T any](v T) *T { return &v }

// target reads one target row.
func (h *harness) target(key TargetKey) store.Target {
	h.t.Helper()
	row, err := h.m.loadTarget(context.Background(), testClientID, key)
	if err != nil {
		h.t.Fatalf("load target: %v", err)
	}
	if row == nil {
		h.t.Fatalf("target %s does not exist", key)
	}
	return *row
}

// state is the stored state of one target.
func (h *harness) state(key TargetKey) string { return h.target(key).State }

// monClient reads the mon-client row.
func (h *harness) monClient() store.MonClient {
	h.t.Helper()
	var mc store.MonClient
	if err := h.st.DB().Where("id = ?", testClientID).Take(&mc).Error; err != nil {
		h.t.Fatalf("read mon-client: %v", err)
	}
	return mc
}

// allEvents returns every event filed so far, oldest first.
func (h *harness) allEvents() []eventRecord {
	h.t.Helper()
	var rows []store.EventOutbox
	if err := h.st.DB().Order("id").Find(&rows).Error; err != nil {
		h.t.Fatalf("read events_outbox: %v", err)
	}
	out := make([]eventRecord, 0, len(rows))
	for _, row := range rows {
		ev, err := events.UnmarshalEvent(row.Payload)
		if err != nil {
			h.t.Fatalf("unmarshal event: %v", err)
		}
		rec := eventRecord{
			Kind: ev.Kind, MonClientID: ev.MonClientID, From: ev.From, To: ev.To,
			Reason: ev.Reason, Notified: row.Notified, TS: row.TS,
		}
		if ev.Kind == panel.EventKindTarget {
			var id int64
			if ev.InboundID != nil {
				id = *ev.InboundID
			}
			rec.Target = events.TargetKey(ev.InboundKind, id, ev.Path)
		}
		out = append(out, rec)
	}
	return out
}

// newEvents returns the events filed since the previous call, which is how the
// table-driven steps assert one transition at a time.
func (h *harness) newEvents() []eventRecord {
	h.t.Helper()
	all := h.allEvents()
	fresh := all[h.seen:]
	h.seen = len(all)
	return fresh
}

// newStats returns the statistics calls made since the previous call.
func (h *harness) newStats() []statsCall {
	all := h.stats.took()
	fresh := all[h.seenStats:]
	h.seenStats = len(all)
	return fresh
}

// newAlerts returns the Telegram messages mon-server sent itself since the
// previous call.
func (h *harness) newAlerts() []string {
	all := h.alerts.sent()
	fresh := all[h.seenAlert:]
	h.seenAlert = len(all)
	return fresh
}

// targetEvents keeps the target events of one key out of a list.
func targetEvents(list []eventRecord, key TargetKey) []eventRecord {
	out := make([]eventRecord, 0, len(list))
	for _, rec := range list {
		if rec.Kind == panel.EventKindTarget && rec.Target == key.String() {
			out = append(out, rec)
		}
	}
	return out
}
