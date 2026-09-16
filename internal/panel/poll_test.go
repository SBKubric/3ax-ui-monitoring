package panel_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// pollNow is where the fake clock every poll test starts from.
var pollNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// alertLog collects the Telegram messages mon-server sent itself, in order.
type alertLog struct {
	mu    sync.Mutex
	texts []string
}

func (a *alertLog) fn(_ context.Context, text string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.texts = append(a.texts, text)
}

func (a *alertLog) all() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.texts...)
}

// reconcileCall records one call of the target reconciliation seam.
type reconcileCall struct {
	inbounds []panel.Inbound
	cfgs     map[string]panel.ProbeConfigs
}

// pollHarness is the client harness plus a real store, a real outbox and spies
// standing in for the four packages the poll loop does not import.
type pollHarness struct {
	*harness
	st     *store.Store
	fake   *clock.Fake
	outbox *events.Outbox
	alerts *alertLog
	poller *panel.Poller

	mu          sync.Mutex
	snapshot    []panel.MonClientSnapshot
	snapshotErr error
	rebuilds    []map[string]panel.ProbeConfigs
	reconciles  []reconcileCall
	dispatched  int
	dispatchN   int
	dispatchErr error
	onDispatch  func()
}

func newPollHarness(t *testing.T, mutate ...func(*panel.PollOptions)) *pollHarness {
	t.Helper()
	return newPollHarnessWith(t, nil, mutate...)
}

// newPollHarnessWith is newPollHarness with a say over the panel client, for
// the tests that need a short request timeout.
func newPollHarnessWith(t *testing.T, client func(*panel.Options), mutate ...func(*panel.PollOptions)) *pollHarness {
	t.Helper()
	var clientOpts []func(*panel.Options)
	if client != nil {
		clientOpts = append(clientOpts, client)
	}
	h := &pollHarness{
		harness: newHarness(t, clientOpts...),
		fake:    clock.NewFake(pollNow),
		alerts:  &alertLog{},
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(h.fake))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	h.st = st

	settings, err := st.Settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	settings.RealHost = "real.example.net"
	settings.PanelURL = h.stub.URL()
	settings.MonToken = paneltest.DefaultToken
	if err := st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	h.outbox = events.New(st, h.alerts.fn)
	opts := panel.PollOptions{
		Client:    h.client,
		Store:     st,
		Outbox:    h.outbox,
		Alert:     h.alerts.fn,
		Clock:     h.fake,
		Log:       slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Snapshot:  h.seamSnapshot,
		Rebuild:   h.seamRebuild,
		Reconcile: h.seamReconcile,
		Dispatch:  h.seamDispatch,
	}
	for _, m := range mutate {
		m(&opts)
	}
	poller, err := panel.NewPoller(opts)
	if err != nil {
		t.Fatalf("NewPoller: %v", err)
	}
	h.poller = poller
	return h
}

func (h *pollHarness) seamSnapshot(context.Context) ([]panel.MonClientSnapshot, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.snapshot, h.snapshotErr
}

func (h *pollHarness) seamRebuild(_ context.Context, cfgs map[string]panel.ProbeConfigs) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.rebuilds = append(h.rebuilds, cfgs)
	return nil
}

func (h *pollHarness) seamReconcile(_ context.Context, inbounds []panel.Inbound, cfgs map[string]panel.ProbeConfigs) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.reconciles = append(h.reconciles, reconcileCall{inbounds: inbounds, cfgs: cfgs})
	return nil
}

func (h *pollHarness) seamDispatch(context.Context) (int, error) {
	h.mu.Lock()
	h.dispatchN++
	sent, err := h.dispatched, h.dispatchErr
	hook := h.onDispatch
	h.mu.Unlock()
	if hook != nil {
		hook()
	}
	return sent, err
}

func (h *pollHarness) calls() (rebuilds int, reconciles int, dispatches int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.rebuilds), len(h.reconciles), h.dispatchN
}

func (h *pollHarness) lastRebuild(t *testing.T) map[string]panel.ProbeConfigs {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.rebuilds) == 0 {
		t.Fatal("the configuration rebuild was never called")
	}
	return h.rebuilds[len(h.rebuilds)-1]
}

func (h *pollHarness) panelState(t *testing.T) store.PanelState {
	t.Helper()
	ps, err := h.st.PanelState()
	if err != nil {
		t.Fatalf("panel state: %v", err)
	}
	return ps
}

// outboxEvents reads the queued events back in the order the panel would get
// them.
func (h *pollHarness) outboxEvents(t *testing.T) []panel.Event {
	t.Helper()
	var rows []store.EventOutbox
	if err := h.st.DB().Order("ts asc, id asc").Find(&rows).Error; err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	out := make([]panel.Event, 0, len(rows))
	for _, row := range rows {
		ev, err := events.UnmarshalEvent(row.Payload)
		if err != nil {
			t.Fatalf("decode event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

func (h *pollHarness) panelInbounds(t *testing.T) []store.PanelInbound {
	t.Helper()
	var rows []store.PanelInbound
	if err := h.st.DB().Order("inbound_kind asc, inbound_id asc").Find(&rows).Error; err != nil {
		t.Fatalf("read panel inbounds: %v", err)
	}
	return rows
}

func TestNewPollerValidatesOptions(t *testing.T) {
	if _, err := panel.NewPoller(panel.PollOptions{}); !errors.Is(err, panel.ErrInvalidOptions) {
		t.Errorf("err = %v, want ErrInvalidOptions without a client", err)
	}
	client, err := panel.New(panel.Options{BaseURL: "https://panel.example.net/", Token: "t"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := panel.NewPoller(panel.PollOptions{Client: client}); !errors.Is(err, panel.ErrInvalidOptions) {
		t.Errorf("err = %v, want ErrInvalidOptions without a store", err)
	}
}

func TestPollOnceHappyPath(t *testing.T) {
	h := newPollHarness(t)
	h.snapshot = []panel.MonClientSnapshot{
		{ID: "ams-1", Name: "Amsterdam #1", Region: "NL", State: panel.MonClientOnline, LastHeartbeat: 1757721590000},
	}

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}

	ps := h.panelState(t)
	if ps.Status != store.PanelStatusUp {
		t.Errorf("status = %q, want %q", ps.Status, store.PanelStatusUp)
	}
	if ps.LastRevision != paneltest.DefaultRevision {
		t.Errorf("lastRevision = %q, want %q", ps.LastRevision, paneltest.DefaultRevision)
	}
	if ps.ProbeSubID == "" {
		t.Error("probeSubId is empty, want the id the ensure created")
	}
	if ps.LastCheckedAt != clock.MS(pollNow) {
		t.Errorf("lastCheckedAt = %d, want %d", ps.LastCheckedAt, clock.MS(pollNow))
	}
	if ps.LastError != "" {
		t.Errorf("lastError = %q, want empty on a clean cycle", ps.LastError)
	}

	inbounds := h.panelInbounds(t)
	if len(inbounds) != 2 {
		t.Fatalf("stored %d inbounds, want 2", len(inbounds))
	}
	if inbounds[0].InboundKind != panel.InboundKindAWG || inbounds[0].Port != 51820 {
		t.Errorf("awg row = %+v", inbounds[0])
	}
	if inbounds[1].InboundKind != panel.InboundKindXray || inbounds[1].SeenRevision != paneltest.DefaultRevision {
		t.Errorf("xray row = %+v", inbounds[1])
	}

	snapshots := h.stub.EnsureSnapshots()
	if len(snapshots) != 1 || len(snapshots[0]) != 1 || snapshots[0][0].ID != "ams-1" {
		t.Errorf("ensure snapshots = %+v, want the registry", snapshots)
	}

	rebuilds, reconciles, dispatches := h.calls()
	if rebuilds != 1 || reconciles != 1 || dispatches != 1 {
		t.Errorf("rebuilds = %d, reconciles = %d, dispatches = %d, want 1 each", rebuilds, reconciles, dispatches)
	}
	if cfgs := h.lastRebuild(t); len(cfgs) != 1 || cfgs[panel.PathDirect].Path != panel.PathDirect {
		t.Errorf("configs = %+v, want only the direct path while the override is off", cfgs)
	}
	if len(h.alerts.all()) != 0 {
		t.Errorf("alerts = %v, want silence on a clean cycle", h.alerts.all())
	}
	if len(h.outboxEvents(t)) != 0 {
		t.Errorf("outbox = %+v, want no events on a clean cycle", h.outboxEvents(t))
	}
}

func TestPollOnceSnapshotCarriesDisabledAndNeverSeenMonClients(t *testing.T) {
	h := newPollHarness(t)
	h.snapshot = []panel.MonClientSnapshot{
		{ID: "ams-1", Name: "Amsterdam #1", Region: "NL", State: panel.MonClientOnline, LastHeartbeat: 1757721590000},
		{ID: "msk-1", Name: "Moscow #1", Region: "RU", State: panel.MonClientOffline, LastHeartbeat: 1757720000000},
		{ID: "new-1", Name: "Fresh #1", Region: "DE", State: panel.MonClientNever},
	}

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}

	got := h.stub.EnsureSnapshots()
	if len(got) != 1 || len(got[0]) != 3 {
		t.Fatalf("snapshots = %+v, want all three mon-clients", got)
	}
	states := map[string]string{}
	for _, mc := range got[0] {
		states[mc.ID] = mc.State
	}
	want := map[string]string{"ams-1": panel.MonClientOnline, "msk-1": panel.MonClientOffline, "new-1": panel.MonClientNever}
	for id, state := range want {
		if states[id] != state {
			t.Errorf("%s state = %q, want %q", id, states[id], state)
		}
	}
}

func TestPollOnceRereadsConfigsOnlyWhenTheRevisionMoves(t *testing.T) {
	h := newPollHarness(t)

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("first PollOnce: %v", err)
	}
	if n := h.stub.Count(paneltest.ProbeConfigs); n != 1 {
		t.Fatalf("read the probe material %d times, want 1", n)
	}

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("second PollOnce: %v", err)
	}
	if n := h.stub.Count(paneltest.ProbeConfigs); n != 1 {
		t.Errorf("read the probe material %d times, want it left alone while the revision holds", n)
	}
	if rebuilds, _, _ := h.calls(); rebuilds != 1 {
		t.Errorf("rebuilt %d times, want 1", rebuilds)
	}

	h.stub.SetRevision("a-new-revision")
	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("third PollOnce: %v", err)
	}
	if n := h.stub.Count(paneltest.ProbeConfigs); n != 2 {
		t.Errorf("read the probe material %d times, want a reread after the revision moved", n)
	}
	if rebuilds, reconciles, _ := h.calls(); rebuilds != 2 || reconciles != 2 {
		t.Errorf("rebuilt %d times, reconciled %d, want 2 each", rebuilds, reconciles)
	}
	if ps := h.panelState(t); ps.LastRevision != "a-new-revision" {
		t.Errorf("lastRevision = %q, want the new one", ps.LastRevision)
	}
}

func TestPollOnceReadsBothPathsWithTheOverrideOn(t *testing.T) {
	cases := []struct {
		name      string
		override  bool
		wantPaths []string
	}{
		{name: "override off", wantPaths: []string{panel.PathDirect}},
		{name: "override on", override: true, wantPaths: []string{panel.PathDirect, panel.PathProxy}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newPollHarness(t)
			if tc.override {
				h.stub.SetOverride(true, "front.example.net")
			}

			if err := h.poller.PollOnce(t.Context()); err != nil {
				t.Fatalf("PollOnce: %v", err)
			}

			cfgs := h.lastRebuild(t)
			if len(cfgs) != len(tc.wantPaths) {
				t.Fatalf("configs = %+v, want %v", cfgs, tc.wantPaths)
			}
			for _, path := range tc.wantPaths {
				cfg, ok := cfgs[path]
				if !ok {
					t.Fatalf("configs are missing %q: %+v", path, cfgs)
				}
				if cfg.Path != path {
					t.Errorf("configs[%q].Path = %q", path, cfg.Path)
				}
			}
			ps := h.panelState(t)
			if ps.OverrideEnabled != tc.override {
				t.Errorf("overrideEnabled = %v, want %v", ps.OverrideEnabled, tc.override)
			}
			if tc.override && ps.OverrideHost != "front.example.net" {
				t.Errorf("overrideHost = %q", ps.OverrideHost)
			}
		})
	}
}

func TestPollOnceDiscardsStaleProbeMaterial(t *testing.T) {
	h := newPollHarness(t)
	h.stub.SetConfigs(panel.PathDirect, panel.ProbeConfigs{
		Revision: "an-older-revision",
		Path:     panel.PathDirect,
		Items:    []panel.ConfigItem{},
	})

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if rebuilds, reconciles, _ := h.calls(); rebuilds != 0 || reconciles != 0 {
		t.Errorf("rebuilt %d times, reconciled %d, want neither on stale material", rebuilds, reconciles)
	}
	if ps := h.panelState(t); ps.LastRevision != "" {
		t.Errorf("lastRevision = %q, want it unchanged so the next cycle retries", ps.LastRevision)
	}
	if !strings.Contains(h.logs.String(), "stale probe material") {
		t.Errorf("logs = %q, want the discard logged", h.logs.String())
	}

	// The next cycle asks again and this time the answer is current.
	h.stub.SetConfigs(panel.PathDirect, panel.ProbeConfigs{
		Revision: paneltest.DefaultRevision,
		Path:     panel.PathDirect,
		Items:    []panel.ConfigItem{{Kind: panel.InboundKindXray, InboundID: 12, Link: "vless://probe"}},
	})
	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("second PollOnce: %v", err)
	}
	if rebuilds, _, _ := h.calls(); rebuilds != 1 {
		t.Errorf("rebuilt %d times, want 1 once the material caught up", rebuilds)
	}
	if ps := h.panelState(t); ps.LastRevision != paneltest.DefaultRevision {
		t.Errorf("lastRevision = %q, want it recorded", ps.LastRevision)
	}
}

func TestPollOnceWithoutARealHostHasNoDirectMaterial(t *testing.T) {
	h := newPollHarness(t)
	settings, err := h.st.Settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	settings.RealHost = ""
	if err := h.st.SaveSettings(settings); err != nil {
		t.Fatalf("save settings: %v", err)
	}

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if n := h.stub.Count(paneltest.ProbeConfigs); n != 0 {
		t.Errorf("read the probe material %d times, want none without a real host", n)
	}
	if rebuilds, _, _ := h.calls(); rebuilds != 0 {
		t.Errorf("rebuilt %d times, want none", rebuilds)
	}
	if ps := h.panelState(t); ps.LastRevision != "" {
		t.Errorf("lastRevision = %q, want it unset until the material is read", ps.LastRevision)
	}
	if !strings.Contains(h.logs.String(), "no real host configured") {
		t.Errorf("logs = %q, want the missing host logged", h.logs.String())
	}
}

func TestPollOnceXrayUnavailableIsNotAnOutage(t *testing.T) {
	h := newPollHarness(t)
	h.stub.Fail(paneltest.ProbeEnsure, paneltest.XrayUnavailable())

	err := h.poller.PollOnce(t.Context())
	if !errors.Is(err, panel.ErrXrayUnavailable) {
		t.Fatalf("err = %v, want it reported", err)
	}
	ps := h.panelState(t)
	if ps.Status != store.PanelStatusUp {
		t.Errorf("status = %q, want the panel still up: it answered", ps.Status)
	}
	if ps.LastError == "" {
		t.Error("lastError is empty, want the incomplete probe set on the status line")
	}
	if len(h.alerts.all()) != 0 {
		t.Errorf("alerts = %v, want none: the next cycle finishes the probe set", h.alerts.all())
	}
	if len(h.outboxEvents(t)) != 0 {
		t.Error("an event was filed for an incomplete probe set")
	}
	// The cycle carried on: it still asked for the material — the probe set
	// is not there yet, so the panel says so — and still drained the queues.
	if n := h.stub.Count(paneltest.ProbeConfigs); n != 1 {
		t.Errorf("asked for the material %d times, want the cycle to have continued", n)
	}
	if !errors.Is(err, panel.ErrProbeNotEnsured) {
		t.Errorf("err = %v, want the missing probe set reported too", err)
	}
	if _, _, dispatches := h.calls(); dispatches != 1 {
		t.Errorf("dispatched %d times, want the queues drained anyway", dispatches)
	}
}

func TestPollOnceBare404AlertsOnceAndKeepsThePanelState(t *testing.T) {
	h := newPollHarness(t)
	h.stub.SetToken("the-token-was-rotated")

	for i := range 3 {
		h.fake.Advance(time.Minute)
		err := h.poller.PollOnce(t.Context())
		if !errors.Is(err, panel.ErrNotFound) {
			t.Fatalf("cycle %d: err = %v, want ErrNotFound", i, err)
		}
	}

	if got := h.alerts.all(); len(got) != 1 || got[0] != "mon-server: panel rejects monitoring token or monitoring is disabled" {
		t.Errorf("alerts = %v, want exactly one wrong-token message", got)
	}
	ps := h.panelState(t)
	if ps.Status == store.PanelStatusDown {
		t.Error("status is PANEL_DOWN, but the panel answered: a 404 is not an outage")
	}
	if ps.LastError == "" {
		t.Error("lastError is empty, want the rejection on the status line")
	}
	if ps.LastCheckedAt != clock.MS(pollNow.Add(3*time.Minute)) {
		t.Errorf("lastCheckedAt = %d, want the last cycle's time", ps.LastCheckedAt)
	}
	if evs := h.outboxEvents(t); len(evs) != 0 {
		t.Errorf("outbox = %+v, want no panel event for a 404", evs)
	}

	// The condition is standing, not an event: it is repeated at most hourly.
	h.fake.Advance(panel.TokenAlertInterval)
	_ = h.poller.PollOnce(t.Context())
	if got := h.alerts.all(); len(got) != 2 {
		t.Errorf("alerts = %v, want a second message after the quiet hour", got)
	}
}

func TestPollDeclaresPanelDownAfterThreeFailures(t *testing.T) {
	h := newPollHarness(t)
	h.stub.Fail(paneltest.Any, paneltest.ServerError())

	for i := range 2 {
		if err := h.poller.PollOnce(t.Context()); !errors.Is(err, panel.ErrUnavailable) {
			t.Fatalf("cycle %d: err = %v, want ErrUnavailable", i, err)
		}
		if ps := h.panelState(t); ps.Status == store.PanelStatusDown {
			t.Fatalf("cycle %d declared PANEL_DOWN early", i)
		}
	}

	if err := h.poller.PollOnce(t.Context()); !errors.Is(err, panel.ErrUnavailable) {
		t.Fatalf("third cycle: err = %v", err)
	}
	ps := h.panelState(t)
	if ps.Status != store.PanelStatusDown {
		t.Fatalf("status = %q, want PANEL_DOWN after three failures", ps.Status)
	}

	evs := h.outboxEvents(t)
	if len(evs) != 1 {
		t.Fatalf("outbox = %+v, want one panel event", evs)
	}
	ev := evs[0]
	if ev.Kind != panel.EventKindPanel || ev.From != panel.PanelUp || ev.To != panel.PanelDown {
		t.Errorf("event = %+v, want PANEL_UP to PANEL_DOWN", ev)
	}
	if ev.Reason != panel.ReasonHTTP5xx {
		t.Errorf("reason = %q, want %q", ev.Reason, panel.ReasonHTTP5xx)
	}
	if !ev.Notified {
		t.Error("the panel event is not notified, but mon-server sent it itself")
	}
	if ev.ID == "" || ev.TS != clock.MS(pollNow) {
		t.Errorf("event id = %q ts = %d, want an id and the poll time", ev.ID, ev.TS)
	}
	if got := h.alerts.all(); len(got) != 1 || got[0] != "mon-server: panel unreachable (http_5xx)" {
		t.Errorf("alerts = %v, want one unreachable message", got)
	}

	// A fourth failing cycle is the same outage, not a new one.
	if err := h.poller.PollOnce(t.Context()); !errors.Is(err, panel.ErrUnavailable) {
		t.Fatalf("fourth cycle: err = %v", err)
	}
	if got := h.alerts.all(); len(got) != 1 {
		t.Errorf("alerts = %v, want the outage announced once", got)
	}
	if evs := h.outboxEvents(t); len(evs) != 1 {
		t.Errorf("outbox = %+v, want one panel event for one outage", evs)
	}
}

func TestPollRecoversAndReportsWhatItResent(t *testing.T) {
	h := newPollHarness(t)
	h.stub.Fail(paneltest.Any, paneltest.ServerError())
	for range 3 {
		_ = h.poller.PollOnce(t.Context())
	}
	if ps := h.panelState(t); ps.Status != store.PanelStatusDown {
		t.Fatalf("status = %q, want PANEL_DOWN before the recovery", ps.Status)
	}

	h.stub.Clear(paneltest.Any)
	h.fake.Advance(time.Minute)
	h.dispatched = 7

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("recovery cycle: %v", err)
	}

	ps := h.panelState(t)
	if ps.Status != store.PanelStatusUp {
		t.Errorf("status = %q, want PANEL_UP", ps.Status)
	}
	if ps.LastError != "" {
		t.Errorf("lastError = %q, want it cleared", ps.LastError)
	}

	evs := h.outboxEvents(t)
	if len(evs) != 2 {
		t.Fatalf("outbox = %+v, want the down and the up event", evs)
	}
	if evs[1].From != panel.PanelDown || evs[1].To != panel.PanelUp || evs[1].Reason != panel.ReasonRecovered {
		t.Errorf("recovery event = %+v", evs[1])
	}
	if evs[0].TS > evs[1].TS {
		t.Errorf("events are out of order: %d then %d", evs[0].TS, evs[1].TS)
	}
	want := []string{
		"mon-server: panel unreachable (http_5xx)",
		"mon-server: panel back, 7 events resent",
	}
	got := h.alerts.all()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("alerts = %v, want %v", got, want)
	}
}

func TestPollHoldsTheRecoveryMessageUntilTheDrainWorks(t *testing.T) {
	h := newPollHarness(t)
	h.stub.Fail(paneltest.Any, paneltest.ServerError())
	for range 3 {
		_ = h.poller.PollOnce(t.Context())
	}
	h.stub.Clear(paneltest.Any)
	h.dispatchErr = errors.New("the outbox could not be drained")

	if err := h.poller.PollOnce(t.Context()); err == nil {
		t.Fatal("PollOnce: want the dispatch failure reported")
	}
	if got := h.alerts.all(); len(got) != 1 {
		t.Errorf("alerts = %v, want no count quoted before the drain worked", got)
	}

	h.dispatchErr = nil
	h.dispatched = 4
	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if got := h.alerts.all(); len(got) != 2 || got[1] != "mon-server: panel back, 4 events resent" {
		t.Errorf("alerts = %v, want the count once the drain worked", got)
	}
}

func TestPollDropsBufferedEventsOlderThanADay(t *testing.T) {
	h := newPollHarness(t)
	now := clock.MS(pollNow)
	stale := events.Target(now-25*int64(time.Hour/time.Millisecond),
		"ams-1", panel.InboundKindXray, 12, panel.PathProxy,
		panel.TargetUp, panel.TargetDown, panel.ReasonTLSTimeout)
	fresh := events.Target(now-int64(time.Hour/time.Millisecond),
		"ams-1", panel.InboundKindXray, 12, panel.PathDirect,
		panel.TargetUp, panel.TargetDown, panel.ReasonTCPRefused)
	for _, ev := range []panel.Event{stale, fresh} {
		if err := h.outbox.Enqueue(t.Context(), ev); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	h.stub.Fail(paneltest.Any, paneltest.ServerError())

	if err := h.poller.PollOnce(t.Context()); !errors.Is(err, panel.ErrUnavailable) {
		t.Fatalf("PollOnce: %v", err)
	}

	evs := h.outboxEvents(t)
	if len(evs) != 1 {
		t.Fatalf("outbox = %+v, want only the event inside the 24 hour cap", evs)
	}
	if evs[0].Path != panel.PathDirect {
		t.Errorf("kept %+v, want the fresh event", evs[0])
	}
	if !strings.Contains(h.logs.String(), "24 hour cap") {
		t.Errorf("logs = %q, want the drop logged", h.logs.String())
	}
}

func TestPollKeepsDeliveredEventsPastTheCap(t *testing.T) {
	h := newPollHarness(t)
	now := clock.MS(pollNow)
	old := events.Target(now-30*int64(time.Hour/time.Millisecond),
		"ams-1", panel.InboundKindXray, 12, panel.PathProxy,
		panel.TargetUp, panel.TargetDown, panel.ReasonTLSTimeout)
	if err := h.outbox.Enqueue(t.Context(), old); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	sent := now - 29*int64(time.Hour/time.Millisecond)
	if err := h.st.DB().Model(&store.EventOutbox{}).Where("1 = 1").Update("sent_at", sent).Error; err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	if evs := h.outboxEvents(t); len(evs) != 1 {
		t.Errorf("outbox = %+v, want delivered events left to the retention job", evs)
	}
}

func TestPollWritesThePanelCacheOnFailure(t *testing.T) {
	// A panel that never answers: the timeout is shortened so the four
	// attempts of one cycle cost milliseconds.
	h := newPollHarnessWith(t, func(o *panel.Options) {
		o.Timeout = 50 * time.Millisecond
		o.HTTPClient = &http.Client{}
	})
	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("first PollOnce: %v", err)
	}

	h.stub.Fail(paneltest.Any, paneltest.Hanging())
	h.fake.Advance(5 * time.Minute)
	if err := h.poller.PollOnce(t.Context()); !errors.Is(err, panel.ErrUnavailable) {
		t.Fatalf("PollOnce: err = %v, want ErrUnavailable", err)
	}

	ps := h.panelState(t)
	if ps.LastCheckedAt != clock.MS(pollNow.Add(5*time.Minute)) {
		t.Errorf("lastCheckedAt = %d, want the failed cycle's time: the status line must not go stale",
			ps.LastCheckedAt)
	}
	if !strings.Contains(ps.LastError, "state") {
		t.Errorf("lastError = %q, want the failing step named", ps.LastError)
	}
	if ps.LastRevision != paneltest.DefaultRevision {
		t.Errorf("lastRevision = %q, want the last good one kept", ps.LastRevision)
	}
}

func TestPollForgetsInboundsThePanelDropped(t *testing.T) {
	h := newPollHarness(t)
	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("first PollOnce: %v", err)
	}
	if rows := h.panelInbounds(t); len(rows) != 2 {
		t.Fatalf("stored %d inbounds, want 2", len(rows))
	}

	h.stub.SetInbounds(panel.Inbound{
		Kind: panel.InboundKindXray, InboundID: 12, Tag: "inbound-443",
		Protocol: "vless", Port: 443, Enable: false,
	})
	h.stub.SetRevision("without-the-awg-server")
	if err := h.poller.PollOnce(t.Context()); err != nil {
		t.Fatalf("second PollOnce: %v", err)
	}

	rows := h.panelInbounds(t)
	if len(rows) != 1 {
		t.Fatalf("stored %+v, want only the inbound the panel still has", rows)
	}
	if rows[0].InboundID != 12 || rows[0].Enable {
		t.Errorf("row = %+v, want the disabled xray inbound", rows[0])
	}
	if rows[0].SeenRevision != "without-the-awg-server" {
		t.Errorf("seenRevision = %q", rows[0].SeenRevision)
	}
	// A disabled inbound is in /state but not in the material, which is how
	// the reconciliation sees PAUSED.
	h.mu.Lock()
	last := h.reconciles[len(h.reconciles)-1]
	h.mu.Unlock()
	if len(last.inbounds) != 1 || last.inbounds[0].Enable {
		t.Errorf("reconcile inbounds = %+v, want the disabled one", last.inbounds)
	}
	if items := last.cfgs[panel.PathDirect].Items; len(items) != 0 {
		t.Errorf("material = %+v, want a disabled inbound left out", items)
	}
}

func TestPollSurvivesASnapshotFailure(t *testing.T) {
	h := newPollHarness(t)
	h.snapshotErr = errors.New("the registry is unreadable")

	err := h.poller.PollOnce(t.Context())
	if err == nil || !strings.Contains(err.Error(), "registry snapshot") {
		t.Fatalf("err = %v, want the snapshot failure reported", err)
	}
	if n := h.stub.Count(paneltest.ProbeEnsure); n != 0 {
		t.Errorf("ensured %d times, want none without a snapshot to post", n)
	}
	if ps := h.panelState(t); ps.Status != store.PanelStatusUp {
		t.Errorf("status = %q, want the panel still up", ps.Status)
	}
	if _, _, dispatches := h.calls(); dispatches != 1 {
		t.Errorf("dispatched %d times, want the queues drained anyway", dispatches)
	}
}

func TestRunPollsUntilTheContextEnds(t *testing.T) {
	h := newPollHarness(t, func(o *panel.PollOptions) { o.Interval = time.Millisecond })
	ctx, cancel := context.WithCancel(t.Context())
	// The dispatch seam closes the cycle, so it is the deterministic place to
	// count cycles and stop the loop.
	cycles := make(chan int, 8)
	h.onDispatch = func() {
		h.mu.Lock()
		n := h.dispatchN
		h.mu.Unlock()
		select {
		case cycles <- n:
		default:
		}
		if n >= 2 {
			cancel()
		}
	}

	done := make(chan struct{})
	go func() {
		h.poller.Run(ctx)
		close(done)
	}()

	<-done
	if n := <-cycles; n != 1 {
		t.Errorf("first cycle reported %d, want the loop to poll immediately", n)
	}
	if _, _, dispatches := h.calls(); dispatches < 2 {
		t.Errorf("ran %d cycles, want at least 2 before the context ended", dispatches)
	}
}
