package events_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// recorder collects the alert texts the outbox produced, in order.
type recorder struct {
	mu    sync.Mutex
	texts []string
	// onAlert runs inside the alert, so a test can assert on what is already
	// durable at the moment the message is sent.
	onAlert func()
}

func (r *recorder) fn(_ context.Context, text string) {
	r.mu.Lock()
	r.texts = append(r.texts, text)
	r.mu.Unlock()
	if r.onAlert != nil {
		r.onAlert()
	}
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.texts...)
}

func newStore(t *testing.T) (*store.Store, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(testNow)
	st, err := store.Open(filepath.Join(t.TempDir(), "mon-server.db"), nil, store.WithClock(clk))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, clk
}

func setPanelStatus(t *testing.T, st *store.Store, status string) {
	t.Helper()
	ps, err := st.PanelState()
	if err != nil {
		t.Fatalf("panel state: %v", err)
	}
	ps.Status = status
	if err := st.SavePanelState(ps); err != nil {
		t.Fatalf("save panel state: %v", err)
	}
}

func addMonClient(t *testing.T, st *store.Store, id, name, region string) {
	t.Helper()
	mc := store.MonClient{ID: id, Name: name, Region: region, Enabled: true, State: store.ClientStateOnline}
	if err := st.DB().Create(&mc).Error; err != nil {
		t.Fatalf("create mon-client: %v", err)
	}
}

func rows(t *testing.T, st *store.Store) []store.EventOutbox {
	t.Helper()
	var got []store.EventOutbox
	if err := st.DB().Order("ts asc, id asc").Find(&got).Error; err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	return got
}

// TestEnqueueWhilePanelUpDoesNotAlert is the ordinary path: the panel is
// reachable, so it will announce the transition itself and mon-server must
// stay quiet and leave the event unnotified.
func TestEnqueueWhilePanelUpDoesNotAlert(t *testing.T) {
	st, _ := newStore(t)
	setPanelStatus(t, st, store.PanelStatusUp)
	rec := &recorder{}
	ob := events.New(st, rec.fn)

	ev := events.Target(st.NowMS(), "ams-1", panel.InboundKindXray, 12, panel.PathProxy,
		panel.TargetUp, panel.TargetDown, panel.ReasonTLSTimeout)
	if err := ob.Enqueue(context.Background(), ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	got := rows(t, st)
	if len(got) != 1 {
		t.Fatalf("outbox rows = %d, want 1", len(got))
	}
	if got[0].Notified {
		t.Error("event marked notified while the panel is up; the panel must announce it")
	}
	if got[0].SentAt != nil {
		t.Error("sent_at set before the panel accepted the event")
	}
	if texts := rec.all(); len(texts) != 0 {
		t.Errorf("alerts sent while the panel is up: %v", texts)
	}
}

// TestEnqueueWhilePanelDownAnnounces covers spec §4.1: mon-server sends the
// transition itself, marks it notified so the panel will not repeat it, and
// still queues it for delivery.
func TestEnqueueWhilePanelDownAnnounces(t *testing.T) {
	tests := []struct {
		name     string
		event    panel.Event
		monClien bool
		want     string
	}{
		{
			name: "target transition names the target and the reason",
			event: events.Target(0, "ams-1", panel.InboundKindXray, 12, panel.PathProxy,
				panel.TargetUp, panel.TargetDown, panel.ReasonTLSTimeout),
			want: "target xray:12:proxy on ams-1: UP → DOWN (tls_timeout) — via mon-server",
		},
		{
			name: "awg target keeps inbound id zero",
			event: events.Target(0, "ams-1", panel.InboundKindAWG, 0, panel.PathDirect,
				panel.TargetDown, panel.TargetUp, panel.ReasonRecovered),
			want: "target awg:0:direct on ams-1: DOWN → UP (recovered) — via mon-server",
		},
		{
			name: "mon-client transition is named the way the panel names it",
			event: events.MonClient(0, "ams-1", panel.MonClientOnline, panel.MonClientOffline,
				panel.ReasonHeartbeatMissed),
			monClien: true,
			want:     "mon-client Amsterdam #1 (NL) OFFLINE — via mon-server",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := newStore(t)
			setPanelStatus(t, st, store.PanelStatusDown)
			if tc.monClien {
				addMonClient(t, st, "ams-1", "Amsterdam #1", "NL")
			}
			rec := &recorder{}
			ob := events.New(st, rec.fn)

			if err := ob.Enqueue(context.Background(), tc.event); err != nil {
				t.Fatalf("enqueue: %v", err)
			}

			got := rows(t, st)
			if len(got) != 1 {
				t.Fatalf("outbox rows = %d, want 1", len(got))
			}
			if !got[0].Notified {
				t.Error("event not marked notified; the panel would announce it a second time")
			}
			texts := rec.all()
			if len(texts) != 1 {
				t.Fatalf("alerts = %v, want exactly one", texts)
			}
			if texts[0] != tc.want {
				t.Errorf("alert text\n got: %q\nwant: %q", texts[0], tc.want)
			}
		})
	}
}

// TestMonClientAlertFallsBackToID keeps an alert useful when the row is gone,
// which happens when a mon-client is deleted while the panel is down.
func TestMonClientAlertFallsBackToID(t *testing.T) {
	st, _ := newStore(t)
	setPanelStatus(t, st, store.PanelStatusDown)
	rec := &recorder{}
	ob := events.New(st, rec.fn)

	ev := events.MonClient(0, "gone-1", panel.MonClientOnline, panel.MonClientOffline, panel.ReasonHeartbeatMissed)
	if err := ob.Enqueue(context.Background(), ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	texts := rec.all()
	if len(texts) != 1 {
		t.Fatalf("alerts = %v, want one", texts)
	}
	if want := "mon-client gone-1 () OFFLINE — via mon-server"; texts[0] != want {
		t.Errorf("alert text\n got: %q\nwant: %q", texts[0], want)
	}
}

// TestPanelEventIsNeverAnnouncedHere: the panel client sends its own "panel
// unreachable" message, so the outbox must not add a second one, and a panel
// event is always notified.
func TestPanelEventIsNeverAnnouncedHere(t *testing.T) {
	st, _ := newStore(t)
	setPanelStatus(t, st, store.PanelStatusDown)
	rec := &recorder{}
	ob := events.New(st, rec.fn)

	ev := events.Panel(0, panel.PanelUp, panel.PanelDown, panel.ReasonHTTPTimeout)
	if err := ob.Enqueue(context.Background(), ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	if texts := rec.all(); len(texts) != 0 {
		t.Errorf("outbox announced a panel event itself: %v", texts)
	}
	got := rows(t, st)
	if len(got) != 1 || !got[0].Notified {
		t.Fatalf("panel event must be stored notified, got %+v", got)
	}
	decoded, err := events.UnmarshalEvent(got[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.MonClientID != "" || decoded.InboundID != nil || decoded.Path != "" {
		t.Errorf("panel event carries target fields: %+v", decoded)
	}
}

// TestPayloadKeepsTheWireShape guards the stored form: draining the outbox is a
// copy, so whatever is stored is exactly what the panel will receive.
func TestPayloadKeepsTheWireShape(t *testing.T) {
	st, _ := newStore(t)
	setPanelStatus(t, st, store.PanelStatusUp)
	ob := events.New(st, nil)

	ts := st.NowMS()
	in := events.Target(ts, "ams-1", panel.InboundKindAWG, 0, panel.PathDirect,
		panel.TargetUnknown, panel.TargetUp, panel.ReasonRecovered)
	if err := ob.Enqueue(context.Background(), in); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	got := rows(t, st)
	decoded, err := events.UnmarshalEvent(got[0].Payload)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.InboundID == nil || *decoded.InboundID != 0 {
		t.Errorf("inboundId lost for AWG: %+v", decoded.InboundID)
	}
	if decoded.Kind != panel.EventKindTarget || decoded.Path != panel.PathDirect || decoded.TS != ts {
		t.Errorf("event shape changed in storage: %+v", decoded)
	}
	if decoded.ID != got[0].ID || decoded.ID == "" {
		t.Errorf("payload id %q does not match row id %q", decoded.ID, got[0].ID)
	}
}

// TestGeneratedFields: an event filed without an id or timestamp gets both, and
// a caller-supplied one is respected.
func TestGeneratedFields(t *testing.T) {
	st, clk := newStore(t)
	setPanelStatus(t, st, store.PanelStatusUp)
	ob := events.New(st, nil)

	clk.Advance(90 * time.Second)
	bare := events.MonClient(0, "ams-1", panel.MonClientNever, panel.MonClientOnline, "")
	own := events.MonClient(1700000000000, "ams-1", panel.MonClientOnline, panel.MonClientOffline, panel.ReasonHeartbeatMissed)
	own.ID = "019254a0-7c3e-7d2a-9b4f-1f2e3d4c5b6a"

	if err := ob.EnqueueAll(context.Background(), []panel.Event{bare, own}); err != nil {
		t.Fatalf("enqueue all: %v", err)
	}

	got := rows(t, st)
	if len(got) != 2 {
		t.Fatalf("outbox rows = %d, want 2", len(got))
	}
	var generated, supplied store.EventOutbox
	for _, r := range got {
		if r.ID == own.ID {
			supplied = r
		} else {
			generated = r
		}
	}
	if generated.ID == "" {
		t.Error("no id generated for an event filed without one")
	}
	if want := clock.MS(clk.Now()); generated.TS != want {
		t.Errorf("generated ts = %d, want the clock's %d", generated.TS, want)
	}
	if supplied.TS != 1700000000000 {
		t.Errorf("supplied ts overwritten: %d", supplied.TS)
	}
}

// TestAlertHappensAfterTheEventIsDurable: a Telegram message about a transition
// mon-server then forgot would be worse than a late message, so the row must
// already be readable when the alert fires.
func TestAlertHappensAfterTheEventIsDurable(t *testing.T) {
	st, _ := newStore(t)
	setPanelStatus(t, st, store.PanelStatusDown)

	var seen int64
	rec := &recorder{onAlert: func() {
		if err := st.DB().Model(&store.EventOutbox{}).Count(&seen).Error; err != nil {
			t.Errorf("count during alert: %v", err)
		}
	}}
	ob := events.New(st, rec.fn)

	ev := events.Target(0, "ams-1", panel.InboundKindXray, 7, panel.PathDirect,
		panel.TargetUp, panel.TargetDown, panel.ReasonTCPRefused)
	if err := ob.Enqueue(context.Background(), ev); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if seen != 1 {
		t.Errorf("rows visible when the alert fired = %d, want 1", seen)
	}
}

// TestEnqueueAllIsAtomicAndBatched covers the case a mon-client going offline
// produces: many target events at once, all or nothing.
func TestEnqueueAllIsAtomicAndBatched(t *testing.T) {
	st, _ := newStore(t)
	setPanelStatus(t, st, store.PanelStatusUp)
	ob := events.New(st, nil)

	var batch []panel.Event
	for i := int64(1); i <= 25; i++ {
		batch = append(batch, events.Target(st.NowMS(), "ams-1", panel.InboundKindXray, i, panel.PathProxy,
			panel.TargetUp, panel.TargetUnknown, panel.ReasonMonClientOffline))
	}
	if err := ob.EnqueueAll(context.Background(), batch); err != nil {
		t.Fatalf("enqueue all: %v", err)
	}
	if got := rows(t, st); len(got) != 25 {
		t.Fatalf("outbox rows = %d, want 25", len(got))
	}

	if err := ob.EnqueueAll(context.Background(), nil); err != nil {
		t.Errorf("empty batch should be a no-op, got %v", err)
	}
	if got := rows(t, st); len(got) != 25 {
		t.Errorf("empty batch wrote rows: %d", len(got))
	}
}

// TestTargetKey pins the "kind:inboundId:path" form shared with the tunnel
// probe query parameter.
func TestTargetKey(t *testing.T) {
	if got := events.TargetKey(panel.InboundKindXray, 12, panel.PathProxy); got != "xray:12:proxy" {
		t.Errorf("TargetKey = %q", got)
	}
	if got := events.TargetKey(panel.InboundKindAWG, 0, panel.PathDirect); got != "awg:0:direct" {
		t.Errorf("TargetKey for awg = %q", got)
	}
}
