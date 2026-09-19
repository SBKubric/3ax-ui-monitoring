package panel_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel/paneltest"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// fakeConfigs counts RebuildAll calls: the poller must rebuild exactly once
// per accepted material change and never on an unchanged revision (spec §4
// step 3), because every rebuild makes every mon-client re-fetch its config.
type fakeConfigs struct {
	mu sync.Mutex
	n  int
}

func (f *fakeConfigs) RebuildAll(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return nil
}

func (f *fakeConfigs) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// fakeSnapshot stands in for internal/registry (step 4).
type fakeSnapshot struct {
	mu    sync.Mutex
	items []panel.MonClientSnapshot
}

func (f *fakeSnapshot) Snapshot(context.Context) ([]panel.MonClientSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]panel.MonClientSnapshot(nil), f.items...), nil
}

// fakeInbounds stands in for internal/state's inbound sync (step 6).
type fakeInbounds struct {
	mu   sync.Mutex
	seen [][]panel.Inbound
}

func (f *fakeInbounds) SyncInbounds(_ context.Context, in []panel.Inbound) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, append([]panel.Inbound(nil), in...))
	return nil
}

func (f *fakeInbounds) calls() [][]panel.Inbound {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]panel.Inbound(nil), f.seen...)
}

// fakeStats stands in for internal/state's bucket flush (step 7).
type fakeStats struct {
	mu sync.Mutex
	n  int
}

func (f *fakeStats) Flush(context.Context, panel.Client) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return nil
}

func (f *fakeStats) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

// harness is one fully wired poller against one panel stub: a temp-file
// store, a Fake clock, a recording notifier and fakes for every collaborator
// later steps will supply.
type harness struct {
	stub     *paneltest.Stub
	store    *store.Store
	clk      *clock.Fake
	tg       *tg.Recorder
	poller   *panel.Poller
	configs  *fakeConfigs
	inbounds *fakeInbounds
	snapshot *fakeSnapshot
	stats    *fakeStats
}

// newHarness builds the harness with monitoring configured and one enabled
// xray inbound, the smallest panel that produces a non-trivial revision.
// Extra client options (a short timeout, say) are applied to the client the
// poller builds from settings.
func newHarness(t *testing.T, opts ...panel.Option) *harness {
	t.Helper()

	h := &harness{
		stub:     paneltest.NewStub(t),
		clk:      clock.NewFake(testTime),
		tg:       &tg.Recorder{},
		configs:  &fakeConfigs{},
		inbounds: &fakeInbounds{},
		snapshot: &fakeSnapshot{},
		stats:    &fakeStats{},
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	h.store = st

	set := store.DefaultSettings()
	set.PanelURL = h.stub.URL()
	set.MonToken = h.stub.Token()
	set.RealHost = "real.example.net"
	if err := st.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	h.stub.SetInbounds([]panel.Inbound{
		{Kind: "xray", InboundId: 12, Tag: "inbound-443", Remark: "Reality main", Protocol: "vless", Port: 443, Enable: true},
	})
	h.stub.SetItems("direct", []panel.ProbeItem{{Kind: "xray", InboundId: 12, Link: "vless://direct"}})
	h.stub.SetItems("proxy", []panel.ProbeItem{{Kind: "xray", InboundId: 12, Link: "vless://proxy"}})

	h.poller = panel.NewPoller(panel.PollerDeps{
		Store:    st,
		Clock:    h.clk,
		Notifier: h.tg,
		Snapshot: h.snapshot,
		Configs:  h.configs,
		Inbounds: h.inbounds,
		Stats:    h.stats,
		NewClient: func(baseURL, token string) panel.Client {
			all := append([]panel.Option{panel.WithSleeper(func(context.Context, time.Duration) error { return nil })}, opts...)
			return panel.NewHTTPClient(baseURL, token, h.clk, all...)
		},
	})
	return h
}

// configFetches counts the GET /probe/configs requests the stub saw, split
// by path: the direct path carries ?host=, the proxy path carries nothing.
func (h *harness) configFetches() (direct, proxy int) {
	for _, r := range h.stub.Requests() {
		if !strings.HasSuffix(r.Path, "/probe/configs") {
			continue
		}
		if r.Query.Get("host") != "" {
			direct++
		} else {
			proxy++
		}
	}
	return direct, proxy
}

// outbox reads every event row, sent or not, in ts order.
func (h *harness) outbox(t *testing.T) []store.EventOutbox {
	t.Helper()
	var rows []store.EventOutbox
	if err := h.store.DB.Order("ts, id").Find(&rows).Error; err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	return rows
}

// panelEvents returns the kind:"panel" events mon-server queued about itself.
func (h *harness) panelEvents(t *testing.T) []store.EventPayload {
	t.Helper()
	var out []store.EventPayload
	for _, row := range h.outbox(t) {
		var ev store.EventPayload
		if err := json.Unmarshal([]byte(row.Payload), &ev); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if ev.Kind == "panel" {
			out = append(out, ev)
		}
	}
	return out
}

// seedEvents inserts n target events straight into the outbox, oldest first
// at baseTs and one second apart, but in an insertion order that is not ts
// order — so a test asserting "sent in ts order" cannot pass by accident.
func (h *harness) seedEvents(t *testing.T, n int, baseTs int64) []string {
	t.Helper()
	rows := make([]store.EventOutbox, 0, n)
	ids := make([]string, 0, n)
	for i := n - 1; i >= 0; i-- {
		id := fmt.Sprintf("seed-%04d", i)
		inbound := 12
		ev := store.EventPayload{
			ID: id, Ts: baseTs + int64(i)*1000, Kind: "target",
			MonClientID: "ams-1", InboundKind: "xray", InboundID: &inbound, Path: "direct",
			From: "UP", To: "DOWN", Reason: "tcp_timeout",
		}
		payload, err := json.Marshal(ev)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rows = append(rows, store.EventOutbox{Id: id, Ts: ev.Ts, Payload: string(payload)})
		ids = append(ids, id)
	}
	if err := h.store.DB.CreateInBatches(&rows, 500).Error; err != nil {
		t.Fatalf("seed events: %v", err)
	}
	return ids
}

// failCycles drives n whole poll cycles whose every request fails the way
// inject arranges, which is how PANEL_DOWN is reached: one failed cycle is
// one failed request as far as the accounting is concerned, however many
// retries it took (spec §4.1).
func (h *harness) failCycles(t *testing.T, n int, inject func(*paneltest.Stub)) {
	t.Helper()
	for i := 0; i < n; i++ {
		inject(h.stub)
		if err := h.poller.Poll(context.Background()); err == nil {
			t.Fatalf("cycle %d: Poll returned no error against a failing panel", i+1)
		}
	}
}

// TestPoll_RevisionChangeRereadsConfigsOnBothPaths checks spec §4 step 3:
// with the override on, a new revision re-reads both paths, an unchanged
// revision re-reads neither, and the config rebuild happens exactly once per
// accepted material.
func TestPoll_RevisionChangeRereadsConfigsOnBothPaths(t *testing.T) {
	h := newHarness(t)
	h.stub.SetOverride(true, "front.example.net")

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	direct, proxy := h.configFetches()
	if direct != 1 || proxy != 1 {
		t.Fatalf("first cycle fetched direct=%d proxy=%d, want 1 and 1", direct, proxy)
	}
	mat, ok := h.poller.Material()
	if !ok {
		t.Fatal("no material after the first cycle")
	}
	if mat.Revision != h.stub.Revision() {
		t.Fatalf("material revision = %q, want %q", mat.Revision, h.stub.Revision())
	}
	if len(mat.Direct) != 1 || mat.Direct[0].Link != "vless://direct" {
		t.Fatalf("direct items = %+v", mat.Direct)
	}
	if len(mat.Proxy) != 1 || mat.Proxy[0].Link != "vless://proxy" {
		t.Fatalf("proxy items = %+v", mat.Proxy)
	}
	if mat.ProbeSubID == "" {
		t.Fatal("material carries no probe subId")
	}
	if h.configs.calls() != 1 {
		t.Fatalf("RebuildAll called %d times, want 1", h.configs.calls())
	}

	// Same revision: nothing to re-read, nothing to rebuild.
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	direct, proxy = h.configFetches()
	if direct != 1 || proxy != 1 {
		t.Fatalf("unchanged revision re-read configs: direct=%d proxy=%d", direct, proxy)
	}
	if h.configs.calls() != 1 {
		t.Fatalf("RebuildAll called %d times on an unchanged revision, want 1", h.configs.calls())
	}

	// A new inbound moves the revision (contract §4.2) and both paths are
	// read again.
	h.stub.SetInbounds([]panel.Inbound{
		{Kind: "xray", InboundId: 12, Protocol: "vless", Port: 443, Enable: true},
		{Kind: "awg", InboundId: 0, Protocol: "awg", Port: 51820, Enable: true},
	})
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("third Poll: %v", err)
	}
	direct, proxy = h.configFetches()
	if direct != 2 || proxy != 2 {
		t.Fatalf("revision change fetched direct=%d proxy=%d, want 2 and 2", direct, proxy)
	}
	if h.configs.calls() != 2 {
		t.Fatalf("RebuildAll called %d times, want 2", h.configs.calls())
	}
	if mat, _ := h.poller.Material(); mat.Revision != h.stub.Revision() {
		t.Fatalf("material revision = %q, want the new %q", mat.Revision, h.stub.Revision())
	}
}

// TestPoll_OverrideDisabledFetchesOnlyDirect checks contract §4.4: without
// the host override there is no proxy front, so mon-server must not ask for
// the proxy path at all (asking would be a 409).
func TestPoll_OverrideDisabledFetchesOnlyDirect(t *testing.T) {
	h := newHarness(t)

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	direct, proxy := h.configFetches()
	if direct != 1 || proxy != 0 {
		t.Fatalf("fetched direct=%d proxy=%d, want 1 and 0", direct, proxy)
	}
	mat, ok := h.poller.Material()
	if !ok {
		t.Fatal("no material")
	}
	if len(mat.Proxy) != 0 {
		t.Fatalf("proxy items = %+v, want none", mat.Proxy)
	}
	if mat.Override.Enabled {
		t.Fatal("material claims the override is on")
	}
}

// TestPoll_ForeignRevisionConfigsAreDiscarded checks spec §4 step 3's guard:
// an answer stamped with a revision other than the one /state just reported
// describes a configuration mon-server has already moved past, so it is
// dropped whole — no material, no rebuild — and retried next cycle.
func TestPoll_ForeignRevisionConfigsAreDiscarded(t *testing.T) {
	h := newHarness(t)
	h.stub.SetConfigsRevision("0123456789abcdef")

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if _, ok := h.poller.Material(); ok {
		t.Fatal("material was accepted from a foreign revision")
	}
	if h.configs.calls() != 0 {
		t.Fatalf("RebuildAll called %d times on a discarded answer", h.configs.calls())
	}

	// Next cycle, the panel answers for the revision it is actually on.
	h.stub.SetConfigsRevision("")
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("second Poll: %v", err)
	}
	mat, ok := h.poller.Material()
	if !ok {
		t.Fatal("material was not picked up on the retry")
	}
	if mat.Revision != h.stub.Revision() {
		t.Fatalf("material revision = %q, want %q", mat.Revision, h.stub.Revision())
	}
	if h.configs.calls() != 1 {
		t.Fatalf("RebuildAll called %d times, want 1", h.configs.calls())
	}
}

// TestPoll_BareNotFoundAlertsOnceAndStaysUp checks contract §2 and spec §8:
// the panel refusing our token is an operator problem, alerted once per
// spell, and explicitly not PANEL_DOWN — the panel is answering.
func TestPoll_BareNotFoundAlertsOnceAndStaysUp(t *testing.T) {
	h := newHarness(t)
	h.stub.SetMonEnabled(false)

	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("Poll returned no error against a panel that refuses the token")
	}
	if h.poller.PanelDown() {
		t.Fatal("a bare 404 must not declare PANEL_DOWN")
	}
	if got := h.tg.Sent; len(got) != 1 || got[0] != "panel rejects monitoring token or monitoring is disabled" {
		t.Fatalf("Telegram = %q, want exactly the spec §8 message", got)
	}
	if evs := h.panelEvents(t); len(evs) != 0 {
		t.Fatalf("panel events = %+v, want none", evs)
	}

	// A second identical cycle must not repeat the message.
	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("second Poll returned no error")
	}
	if got := h.tg.Sent; len(got) != 1 {
		t.Fatalf("Telegram = %q, want the message only once", got)
	}
}

// TestPoll_ThreeFailuresDeclarePanelDown checks spec §4.1: three consecutive
// failed requests trip PANEL_DOWN once, with the reason that matches how
// they failed, one queued event marked notified, and one Telegram message.
func TestPoll_ThreeFailuresDeclarePanelDown(t *testing.T) {
	// attemptsPerCycle is one attempt plus the three retries of spec §4:
	// the injector has to starve the whole cycle, not just one attempt.
	const attemptsPerCycle = 4

	cases := []struct {
		name       string
		opts       []panel.Option
		inject     func(*paneltest.Stub)
		wantReason string
	}{
		{
			name:       "connection dropped",
			inject:     func(s *paneltest.Stub) { s.DropNext(attemptsPerCycle) },
			wantReason: "conn_refused",
		},
		{
			name:       "panel 500",
			inject:     func(s *paneltest.Stub) { s.FailNext(attemptsPerCycle, http.StatusInternalServerError) },
			wantReason: "http_5xx",
		},
		{
			name:       "panel never answers",
			opts:       []panel.Option{panel.WithTimeout(20 * time.Millisecond)},
			inject:     func(s *paneltest.Stub) { s.SleepNext(attemptsPerCycle, 2*time.Second) },
			wantReason: "http_timeout",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, tc.opts...)

			h.failCycles(t, 2, tc.inject)
			if h.poller.PanelDown() {
				t.Fatal("PANEL_DOWN after two failures, want three (spec §4.1)")
			}
			if len(h.panelEvents(t)) != 0 || len(h.tg.Sent) != 0 {
				t.Fatal("two failures already produced an event or a message")
			}

			h.failCycles(t, 1, tc.inject)
			if !h.poller.PanelDown() {
				t.Fatal("no PANEL_DOWN after three consecutive failures")
			}

			evs := h.panelEvents(t)
			if len(evs) != 1 {
				t.Fatalf("panel events = %+v, want exactly one", evs)
			}
			ev := evs[0]
			if ev.From != "PANEL_UP" || ev.To != "PANEL_DOWN" {
				t.Fatalf("event = %s → %s, want PANEL_UP → PANEL_DOWN", ev.From, ev.To)
			}
			if ev.Reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", ev.Reason, tc.wantReason)
			}
			if !ev.Notified {
				t.Fatal("a panel event must be notified=true (contract §4.6)")
			}
			if ev.Ts != clock.Ms(testTime) {
				t.Fatalf("ts = %d, want the clock's %d", ev.Ts, clock.Ms(testTime))
			}
			if got := h.tg.Sent; len(got) != 1 || got[0] != "panel unreachable" {
				t.Fatalf("Telegram = %q, want one \"panel unreachable\"", got)
			}

			// A fourth failure must not repeat either.
			h.failCycles(t, 1, tc.inject)
			if len(h.panelEvents(t)) != 1 || len(h.tg.Sent) != 1 {
				t.Fatal("PANEL_DOWN was declared twice")
			}
		})
	}
}

// failingNotifier is a Notifier whose Send always errors, standing in for a
// broken bot token or an unreachable Telegram API.
type failingNotifier struct{}

func (failingNotifier) Send(context.Context, string) error {
	return errors.New("tg: send message: boom")
}

// TestPoll_TelegramSendFailureDoesNotBreakCycle checks Poller.notify's own
// contract (internal/panel/poller.go: "logging rather than propagating a
// delivery failure: a broken bot token must not stop the poll cycle") end
// to end: even when every Telegram send errors, PANEL_DOWN is still
// declared and the panel event is still enqueued and marked notified.
func TestPoll_TelegramSendFailureDoesNotBreakCycle(t *testing.T) {
	h := newHarness(t)
	h.poller = panel.NewPoller(panel.PollerDeps{
		Store:    h.store,
		Clock:    h.clk,
		Notifier: failingNotifier{},
		Snapshot: h.snapshot,
		Configs:  h.configs,
		Inbounds: h.inbounds,
		Stats:    h.stats,
		NewClient: func(baseURL, token string) panel.Client {
			return panel.NewHTTPClient(baseURL, token, h.clk, panel.WithSleeper(func(context.Context, time.Duration) error { return nil }))
		},
	})

	h.failCycles(t, 3, func(s *paneltest.Stub) { s.DropNext(4) })

	if !h.poller.PanelDown() {
		t.Fatal("PANEL_DOWN not declared even though every Telegram send failed")
	}
	evs := h.panelEvents(t)
	if len(evs) != 1 {
		t.Fatalf("panel events = %+v, want exactly one despite the Telegram failures", evs)
	}
	if !evs[0].Notified {
		t.Fatal("panel event must still be notified=true (mon-server attempted delivery; contract §4.6 does not care that it failed)")
	}
}

// TestPoll_RecoveryResendsOutboxInTsOrder checks the return half of spec
// §4.1: the first successful request ends PANEL_DOWN, everything buffered is
// resent with its original ts in ascending order and in batches of at most
// 1000, and the operator is told how much was resent.
func TestPoll_RecoveryResendsOutboxInTsOrder(t *testing.T) {
	h := newHarness(t)
	downAt := clock.Ms(testTime)

	h.failCycles(t, 3, func(s *paneltest.Stub) { s.FailNext(4, http.StatusInternalServerError) })
	if !h.poller.PanelDown() {
		t.Fatal("not PANEL_DOWN")
	}

	// 1500 transitions pile up while the panel is unreachable — two batches.
	const buffered = 1500
	h.seedEvents(t, buffered, downAt+1000)

	// Far enough ahead that the PANEL_UP event is the newest thing in the
	// outbox, so "ascending ts" and "PANEL_UP last" are the same assertion.
	h.clk.Advance(time.Hour)
	upAt := clock.Ms(h.clk.Now())

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("recovery Poll: %v", err)
	}
	if h.poller.PanelDown() {
		t.Fatal("still PANEL_DOWN after a successful cycle")
	}

	// PANEL_DOWN + 1500 buffered + PANEL_UP.
	want := buffered + 2
	got := h.stub.Events()
	if len(got) != want {
		t.Fatalf("panel received %d events, want %d", len(got), want)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Ts < got[i-1].Ts {
			t.Fatalf("events arrived out of ts order at %d: %d after %d", i, got[i].Ts, got[i-1].Ts)
		}
	}
	if got[0].Ts != downAt || got[0].To != "PANEL_DOWN" {
		t.Fatalf("first event = %+v, want the PANEL_DOWN event with its original ts", got[0])
	}
	last := got[len(got)-1]
	if last.To != "PANEL_UP" || last.Ts != upAt || !last.Notified {
		t.Fatalf("last event = %+v, want a notified PANEL_UP at %d", last, upAt)
	}

	// Batches of at most 1000 (spec §4 step 4).
	posts := 0
	for _, r := range h.stub.Requests() {
		if r.Method == http.MethodPost && strings.HasSuffix(r.Path, "/events") {
			posts++
		}
	}
	if posts != 2 {
		t.Fatalf("%d POST /events, want 2 for %d events", posts, want)
	}

	for _, row := range h.outbox(t) {
		if row.SentAt == nil {
			t.Fatalf("event %s still unsent after a successful flush", row.Id)
		}
		if *row.SentAt != upAt {
			t.Fatalf("event %s sent_at = %d, want the flush time %d", row.Id, *row.SentAt, upAt)
		}
	}

	wantMsg := fmt.Sprintf("panel back, %d events resent", want)
	if msgs := h.tg.Sent; len(msgs) != 2 || msgs[0] != "panel unreachable" || msgs[1] != wantMsg {
		t.Fatalf("Telegram = %q, want [panel unreachable, %q]", msgs, wantMsg)
	}
	if h.stats.calls() != 1 {
		t.Fatalf("stats flushed %d times, want 1", h.stats.calls())
	}
}

// TestPoll_DropsBufferedNotifiedEventsOlderThan24h checks spec §4.1's bound
// on the PANEL_DOWN buffer: a *notified* transition older than 24 h is
// dropped rather than resent — its "via mon-server" Telegram alert already
// went out, so replaying it into the panel's feed is a nice-to-have —  while
// anything younger survives the whole outage.
func TestPoll_DropsBufferedNotifiedEventsOlderThan24h(t *testing.T) {
	h := newHarness(t)
	now := clock.Ms(testTime)

	old := store.EventPayload{ID: "too-old", Ts: now - int64(25*time.Hour/time.Millisecond),
		Kind: "mon_client", MonClientID: "ams-1", From: "ONLINE", To: "OFFLINE", Reason: "heartbeat_missed",
		Notified: true}
	young := store.EventPayload{ID: "still-good", Ts: now - int64(23*time.Hour/time.Millisecond),
		Kind: "mon_client", MonClientID: "ams-1", From: "OFFLINE", To: "ONLINE", Reason: "recovered",
		Notified: true}
	for _, ev := range []store.EventPayload{old, young} {
		if err := h.store.EnqueueEvent(ev); err != nil {
			t.Fatalf("EnqueueEvent: %v", err)
		}
	}

	h.failCycles(t, 3, func(s *paneltest.Stub) { s.FailNext(4, http.StatusInternalServerError) })

	// The prune runs on every cycle that cannot reach the panel, so the
	// stale event is gone before there is anything to resend.
	var stale int64
	if err := h.store.DB.Model(&store.EventOutbox{}).Where("id = ?", "too-old").Count(&stale).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if stale != 0 {
		t.Fatal("a notified event older than 24 h survived the PANEL_DOWN buffer limit")
	}

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("recovery Poll: %v", err)
	}
	for _, ev := range h.stub.Events() {
		if ev.ID == "too-old" {
			t.Fatal("a notified event older than 24 h was resent to the panel")
		}
	}
	var sawYoung bool
	for _, ev := range h.stub.Events() {
		if ev.ID == "still-good" {
			sawYoung = true
		}
	}
	if !sawYoung {
		t.Fatal("an event younger than 24 h was not resent")
	}
}

// TestPoll_PruneNeverDropsUnnotifiedEventsRegardlessOfAge checks the
// PLAUSIBLE finding: an event queued in ordinary PANEL_UP operation
// (notified=false) has no Telegram alert behind it yet — the panel is the
// only place that alert will ever come from — so the 24 h buffer, which
// exists because a notified=true event's alert already went out "via
// mon-server", must never apply to it. Reachable in practice via POST
// /events failing with 5xx for a day while GET /state keeps succeeding and
// resetting the PANEL_DOWN failure run, so this drives Prune directly rather
// than through three failed cycles.
func TestPoll_PruneNeverDropsUnnotifiedEventsRegardlessOfAge(t *testing.T) {
	h := newHarness(t)
	now := clock.Ms(testTime)

	unnotified := store.EventPayload{ID: "old-unnotified", Ts: now - int64(48*time.Hour/time.Millisecond),
		Kind: "mon_client", MonClientID: "ams-1", From: "ONLINE", To: "OFFLINE", Reason: "heartbeat_missed",
		Notified: false}
	notified := store.EventPayload{ID: "old-notified", Ts: now - int64(48*time.Hour/time.Millisecond),
		Kind: "panel", From: "PANEL_UP", To: "PANEL_DOWN", Reason: "http_timeout", Notified: true}
	for _, ev := range []store.EventPayload{unnotified, notified} {
		if err := h.store.EnqueueEvent(ev); err != nil {
			t.Fatalf("EnqueueEvent: %v", err)
		}
	}

	if err := h.poller.Prune(context.Background()); err != nil {
		t.Fatalf("Prune: %v", err)
	}

	var remaining []string
	if err := h.store.DB.Model(&store.EventOutbox{}).
		Where("id IN ?", []string{"old-unnotified", "old-notified"}).
		Pluck("id", &remaining).Error; err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(remaining) != 1 || remaining[0] != "old-unnotified" {
		t.Fatalf("rows remaining after Prune = %v, want only the unnotified one", remaining)
	}

	// The survivor is not just present — it still gets delivered on the next
	// successful flush, exactly like any other queued event.
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	var posted bool
	for _, ev := range h.stub.Events() {
		if ev.ID == "old-unnotified" {
			posted = true
		}
	}
	if !posted {
		t.Fatal("the unnotified event that survived Prune was never posted to the panel")
	}
}

// TestPoll_EventBatchRejectedWithFourXXIsDropped checks the contract §3 /
// spec §4 rule for a 4xx on a batch: the panel will reject it identically
// forever, so it is dropped rather than retried — and the rest of the queue
// still goes out behind it.
func TestPoll_EventBatchRejectedWithFourXXIsDropped(t *testing.T) {
	h := newHarness(t)
	h.seedEvents(t, 1500, clock.Ms(testTime))

	h.stub.FailNextOn("/events", 1, http.StatusBadRequest)
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}

	if h.poller.PanelDown() {
		t.Fatal("a 4xx must not count toward PANEL_DOWN — the panel answered")
	}
	got := h.stub.Events()
	if len(got) != 500 {
		t.Fatalf("panel accepted %d events, want the 500 of the second batch", len(got))
	}
	for _, ev := range got {
		if ev.ID <= "seed-0999" {
			t.Fatalf("event %s from the rejected batch was delivered", ev.ID)
		}
	}
	for _, row := range h.outbox(t) {
		if row.SentAt == nil {
			t.Fatalf("event %s is still queued; a rejected batch must be dropped, not left to wedge the outbox", row.Id)
		}
	}
}

// TestPoll_UpsertsPanelInbounds checks spec §4 step 1: the inbound list is
// mirrored into panel_inbounds with the revision it was seen at, an existing
// row is updated in place rather than duplicated, and a row is never deleted
// here — retiring targets is the state machine's decision (step 6).
func TestPoll_UpsertsPanelInbounds(t *testing.T) {
	h := newHarness(t)

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("first Poll: %v", err)
	}
	firstRevision := h.stub.Revision()

	var rows []store.PanelInbound
	if err := h.store.DB.Order("inbound_kind, inbound_id").Find(&rows).Error; err != nil {
		t.Fatalf("read panel_inbounds: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("%d rows, want 1", len(rows))
	}
	if rows[0].InboundKind != "xray" || rows[0].InboundId != 12 || !rows[0].Enable {
		t.Fatalf("row = %+v", rows[0])
	}
	if rows[0].Protocol != "vless" || rows[0].Port != 443 || rows[0].Remark != "Reality main" {
		t.Fatalf("row = %+v, want the panel's fields", rows[0])
	}
	if rows[0].SeenRevision != firstRevision {
		t.Fatalf("seen_revision = %q, want %q", rows[0].SeenRevision, firstRevision)
	}

	// The inbound is disabled and a second one appears.
	h.stub.SetInbounds([]panel.Inbound{
		{Kind: "xray", InboundId: 12, Remark: "Reality main", Protocol: "vless", Port: 443, Enable: false},
		{Kind: "awg", InboundId: 0, Remark: "AmneziaWG", Protocol: "awg", Port: 51820, Enable: true},
	})
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("second Poll: %v", err)
	}

	rows = nil
	if err := h.store.DB.Order("inbound_kind, inbound_id").Find(&rows).Error; err != nil {
		t.Fatalf("read panel_inbounds: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("%d rows, want 2 (upsert, not insert)", len(rows))
	}
	if rows[0].InboundKind != "awg" || !rows[0].Enable {
		t.Fatalf("awg row = %+v", rows[0])
	}
	if rows[1].InboundKind != "xray" || rows[1].Enable {
		t.Fatalf("xray row = %+v, want enable=false after the update", rows[1])
	}
	if rows[1].SeenRevision == firstRevision {
		t.Fatal("seen_revision was not refreshed on the second cycle")
	}

	// The state machine is told the full list every cycle.
	calls := h.inbounds.calls()
	if len(calls) != 2 || len(calls[0]) != 1 || len(calls[1]) != 2 {
		t.Fatalf("SyncInbounds calls = %+v, want the full list each cycle", calls)
	}
}

// TestPoll_SendsRegistrySnapshot checks spec §4 step 2: ensure carries the
// whole registry, as a replacement for the panel's cache, every cycle.
func TestPoll_SendsRegistrySnapshot(t *testing.T) {
	h := newHarness(t)
	h.snapshot.items = []panel.MonClientSnapshot{
		{Id: "ams-1", Name: "Amsterdam #1", Region: "NL", State: "ONLINE", LastHeartbeat: clock.Ms(testTime)},
		{Id: "msk-1", Name: "Moscow #1", Region: "RU", State: "OFFLINE", LastHeartbeat: clock.Ms(testTime) - 60000},
	}

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	ensured := h.stub.Ensured()
	if len(ensured) != 1 {
		t.Fatalf("%d ensure calls, want 1", len(ensured))
	}
	if len(ensured[0]) != 2 || ensured[0][0].Id != "ams-1" || ensured[0][1].State != "OFFLINE" {
		t.Fatalf("snapshot = %+v", ensured[0])
	}
}

// TestPoll_XrayUnavailableIsNotAPanelFailure checks contract §4.3 against
// spec §4.1: a 503 xray_unavailable is the panel telling us xray is down,
// which is not the panel being unreachable — the next ensure finishes the
// job and PANEL_DOWN stays out of it.
func TestPoll_XrayUnavailableIsNotAPanelFailure(t *testing.T) {
	h := newHarness(t)
	// The probe set already exists, so a failing ensure costs nothing but
	// the ensure itself — which is the situation spec §4 step 2 describes.
	sub := "existing-sub"
	h.stub.SetProbeSubID(&sub)

	for i := 0; i < 3; i++ {
		h.stub.FailNextOn("/probe/ensure", 4, http.StatusServiceUnavailable)
		if err := h.poller.Poll(context.Background()); err != nil {
			t.Fatalf("Poll %d: %v", i+1, err)
		}
	}
	if h.poller.PanelDown() {
		t.Fatal("xray_unavailable declared PANEL_DOWN")
	}
	if len(h.tg.Sent) != 0 {
		t.Fatalf("Telegram = %q, want nothing", h.tg.Sent)
	}
	// The rest of the cycle still ran: material was read and configs built.
	if _, ok := h.poller.Material(); !ok {
		t.Fatal("no material — the cycle stopped at the failed ensure")
	}
}

// TestPoll_NotConfiguredIsANoop checks spec §4's precondition: a mon-server
// whose settings have no panel yet is not failing, it simply has nothing to
// poll, and must not touch the network or alert anyone.
func TestPoll_NotConfiguredIsANoop(t *testing.T) {
	h := newHarness(t)
	set := store.DefaultSettings()
	if err := h.store.SaveSettings(set); err != nil {
		t.Fatalf("SaveSettings: %v", err)
	}

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	if n := len(h.stub.Requests()); n != 0 {
		t.Fatalf("%d requests to the panel, want none", n)
	}
	if len(h.tg.Sent) != 0 {
		t.Fatalf("Telegram = %q, want nothing", h.tg.Sent)
	}
	if h.poller.PanelDown() {
		t.Fatal("an unconfigured panel must not be PANEL_DOWN")
	}
}

// TestRun_PollsImmediatelyAndStopsOnContext checks the loop internal/app
// runs: the first cycle happens at once rather than a minute in, and
// cancelling the context ends the goroutine.
func TestRun_PollsImmediatelyAndStopsOnContext(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.poller.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := h.poller.Material(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not complete a cycle immediately")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// TestRun_SecondConcurrentCallIsRejected checks the self-check finding on
// Poller.Run's lifecycle: a second call while one is already running must
// not start a second overlapping loop against the same store and client
// cache — it is rejected promptly instead.
func TestRun_SecondConcurrentCallIsRejected(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done1 := make(chan struct{})
	go func() {
		defer close(done1)
		h.poller.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := h.poller.Material(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first Run did not complete a cycle")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// A second Run, on a context that would otherwise run forever, must
	// return immediately rather than block — proof it was rejected, not
	// that it happened to finish a cycle.
	done2 := make(chan struct{})
	go func() {
		defer close(done2)
		h.poller.Run(context.Background())
	}()
	select {
	case <-done2:
	case <-time.After(time.Second):
		t.Fatal("a second concurrent Run call was not rejected promptly")
	}

	cancel()
	select {
	case <-done1:
	case <-time.After(5 * time.Second):
		t.Fatal("first Run did not return after its context was cancelled")
	}
}

// TestPoll_HonoursContextCancellationMidCycle checks the self-check finding
// behind pollCycleDeadline: a cycle blocked inside an HTTP call must return
// promptly once its context is cancelled, not run out the panel's full
// (much longer) response delay — the property that keeps a whole cycle from
// ever running unbounded.
func TestPoll_HonoursContextCancellationMidCycle(t *testing.T) {
	h := newHarness(t)
	h.stub.SleepNext(1, 2*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := h.poller.Poll(ctx)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Poll returned no error against a cancelled context")
	}
	if elapsed > time.Second {
		t.Fatalf("Poll took %v after its context was cancelled, want well under the panel's 2s delay", elapsed)
	}
}

// TestPoll_RecoveryCountAccumulatesAcrossCyclesAfterAMidDrainFailure checks
// the CONFIRMED finding: a retryable PostEvents failure partway through
// draining a big backlog returns before finishRecovery while pendingRecovery
// stays set, so the next cycle's flush must add to what was already sent
// rather than replace it — otherwise "panel back, N events resent" reports
// only the cycle that happened to finish the drain.
func TestPoll_RecoveryCountAccumulatesAcrossCyclesAfterAMidDrainFailure(t *testing.T) {
	h := newHarness(t)
	downAt := clock.Ms(testTime)

	h.failCycles(t, 3, func(s *paneltest.Stub) { s.FailNext(4, http.StatusInternalServerError) })
	if !h.poller.PanelDown() {
		t.Fatal("not PANEL_DOWN")
	}

	// 2500 buffered transitions plus the PANEL_DOWN and (once recovery
	// starts) PANEL_UP events split into three batches of 1000, 1000 and
	// 502: the third one is made to fail after exhausting its retries, once
	// the first two have already gone out within the same cycle.
	const buffered = 2500
	h.seedEvents(t, buffered, downAt+1000)
	h.clk.Advance(time.Hour)

	const attemptsPerCall = 4 // one attempt plus the three retries of spec §4
	h.stub.FailNextOnAfter("/events", 2, attemptsPerCall, http.StatusInternalServerError)

	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("cycle A: Poll returned no error against a batch that exhausts its retries")
	}
	if h.poller.PanelDown() {
		t.Fatal("cycle A: one failed batch after recovery must not re-declare PANEL_DOWN")
	}
	midway := len(h.stub.Events())
	if midway == 0 || midway >= buffered+2 {
		t.Fatalf("cycle A delivered %d events, want some but not all of the backlog", midway)
	}
	for _, msg := range h.tg.Sent {
		if strings.HasPrefix(msg, "panel back,") {
			t.Fatal("cycle A: \"panel back\" sent before the backlog finished draining")
		}
	}

	// Cycle B finishes the drain — the earlier failure's budget is spent, so
	// this retry (and everything after it) succeeds.
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("cycle B: %v", err)
	}
	total := len(h.stub.Events())
	if total <= midway {
		t.Fatalf("cycle B delivered no further events (total=%d, midway=%d)", total, midway)
	}

	wantMsg := fmt.Sprintf("panel back, %d events resent", total)
	var backMsgs []string
	for _, msg := range h.tg.Sent {
		if strings.HasPrefix(msg, "panel back,") {
			backMsgs = append(backMsgs, msg)
		}
	}
	if len(backMsgs) != 1 {
		t.Fatalf("\"panel back\" messages = %v, want exactly one", backMsgs)
	}
	if backMsgs[0] != wantMsg {
		t.Fatalf("message = %q, want %q — it must count the whole recovery (cycle A + cycle B), not just cycle B", backMsgs[0], wantMsg)
	}
}

// TestPoll_BadBodyOnStateIsNeutralAndNotifiesOncePerSpell checks the
// PLAUSIBLE finding: a 200 whose body is not contract JSON (a proxy or
// captive portal in front of panelUrl) must never count toward PANEL_DOWN —
// spec §4 retries and counts only network/5xx/timeout — while still alerting
// the operator, once per spell rather than every cycle, and again after a
// recovery clears the latch.
func TestPoll_BadBodyOnStateIsNeutralAndNotifiesOncePerSpell(t *testing.T) {
	h := newHarness(t)
	const wantMsg = "panel returned a non-contract response (wrong panelUrl or a proxy in front of it?)"

	h.stub.BadBodyNext(1)
	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("Poll returned no error against a bad body")
	}
	if h.poller.PanelDown() {
		t.Fatal("a bad body must not count toward PANEL_DOWN")
	}
	if got := h.tg.Sent; len(got) != 1 || got[0] != wantMsg {
		t.Fatalf("Telegram = %q, want exactly [%q]", got, wantMsg)
	}

	// A second cycle with the same failure must not repeat the message.
	h.stub.BadBodyNext(1)
	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("second Poll returned no error")
	}
	if got := h.tg.Sent; len(got) != 1 {
		t.Fatalf("Telegram = %q, want the message only once", got)
	}

	// A third bad body in a row still must not trip PANEL_DOWN — it never
	// counts toward the three-strikes rule at all.
	h.stub.BadBodyNext(1)
	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("third Poll returned no error")
	}
	if h.poller.PanelDown() {
		t.Fatal("PANEL_DOWN after three bad bodies — they must never count")
	}

	// Recovery to a good body clears the latch: the cycle succeeds, and a
	// later bad body notifies again.
	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("recovery Poll: %v", err)
	}
	h.stub.BadBodyNext(1)
	if err := h.poller.Poll(context.Background()); err == nil {
		t.Fatal("Poll returned no error against a bad body")
	}
	if got := h.tg.Sent; len(got) != 2 || got[1] != wantMsg {
		t.Fatalf("Telegram = %q, want a second bad-body message after recovery", got)
	}
}

// TestPoll_TruncatesMonClientSnapshotToContractLimit checks the PLAUSIBLE
// finding: a registry snapshot past the contract's 200-item cap (§3) must be
// truncated before POST /probe/ensure, not sent whole — sending more trips a
// permanent 413 on every future ensure, since the snapshot only grows, and
// on a fresh panel that means the probe subId is never allocated.
func TestPoll_TruncatesMonClientSnapshotToContractLimit(t *testing.T) {
	h := newHarness(t)
	items := make([]panel.MonClientSnapshot, 205)
	for i := range items {
		items[i] = panel.MonClientSnapshot{Id: fmt.Sprintf("mc-%03d", i), State: "ONLINE"}
	}
	h.snapshot.items = items

	if err := h.poller.Poll(context.Background()); err != nil {
		t.Fatalf("Poll: %v", err)
	}
	ensured := h.stub.Ensured()
	if len(ensured) != 1 {
		t.Fatalf("%d ensure calls, want 1", len(ensured))
	}
	if len(ensured[0]) != 200 {
		t.Fatalf("ensure sent %d mon-clients, want the contract's limit of 200", len(ensured[0]))
	}
}
