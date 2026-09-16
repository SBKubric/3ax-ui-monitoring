package state

import (
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// offlineAfter is the default deadline of spec §7.3:
// clientOfflineAfter (3) × intervalMs (60000) + heartbeatTimeoutMs (10000).
const offlineAfter = 3*60*time.Second + 10*time.Second

// TestMonitorDeclaresAMonClientOffline covers spec §7.3: silence past the
// deadline moves the mon-client to OFFLINE with heartbeat_missed and sweeps
// its targets to UNKNOWN with mon_client_offline, filed as events but left out
// of Telegram — the mon-client's own transition is the message.
func TestMonitorDeclaresAMonClientOffline(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy, awgDirect)
	h.probeN(xrayProxy, true, "", 1)
	h.probeN(awgDirect, false, panel.ReasonAWGNoHandshake, 3)
	if got := h.state(xrayProxy); got != store.TargetUp {
		t.Fatalf("xray target = %s, want UP", got)
	}
	if got := h.state(awgDirect); got != store.TargetDown {
		t.Fatalf("awg target = %s, want DOWN", got)
	}
	// The last heartbeat was a minute before the clock the harness left.
	lastHeartbeat := h.monClient().LastHeartbeat

	// One millisecond inside the deadline: nothing happens.
	h.clk.Set(clockAt(lastHeartbeat, offlineAfter))
	h.newEvents()
	if err := h.mon.CheckOnce(t.Context()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if got := h.monClient().State; got != store.ClientStateOnline {
		t.Fatalf("mon-client = %s at the deadline, want ONLINE", got)
	}
	if got := h.newEvents(); len(got) != 0 {
		t.Fatalf("filed %+v at the deadline", got)
	}

	// One millisecond past it.
	h.advance(time.Millisecond)
	offlineAt := h.now()
	if err := h.mon.CheckOnce(t.Context()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	mc := h.monClient()
	if mc.State != store.ClientStateOffline {
		t.Fatalf("mon-client = %s, want OFFLINE", mc.State)
	}
	if mc.MissedHeartbeats != 3 {
		t.Errorf("missed heartbeats = %d, want 3", mc.MissedHeartbeats)
	}
	for _, key := range []TargetKey{xrayProxy, awgDirect} {
		row := h.target(key)
		if row.State != store.TargetUnknown {
			t.Errorf("target %s = %s, want UNKNOWN", key, row.State)
		}
		if row.Reason != panel.ReasonMonClientOffline {
			t.Errorf("target %s reason = %q, want mon_client_offline", key, row.Reason)
		}
		if row.Since != offlineAt {
			t.Errorf("target %s since = %d, want %d", key, row.Since, offlineAt)
		}
		if row.ConsecutiveOK != 0 || row.ConsecutiveFail != 0 {
			t.Errorf("target %s kept its counters: %+v", key, row)
		}
	}

	filed := h.newEvents()
	if len(filed) != 3 {
		t.Fatalf("filed %d events, want the mon-client and both targets: %+v", len(filed), filed)
	}
	wantClient := eventRecord{
		Kind: panel.EventKindMonClient, MonClientID: testClientID,
		From: store.ClientStateOnline, To: store.ClientStateOffline,
		Reason: panel.ReasonHeartbeatMissed, TS: offlineAt,
	}
	if filed[0] != wantClient {
		t.Errorf("mon-client event = %+v, want %+v", filed[0], wantClient)
	}
	for _, rec := range filed[1:] {
		if rec.Kind != panel.EventKindTarget || rec.To != store.TargetUnknown || rec.Reason != panel.ReasonMonClientOffline {
			t.Errorf("target event = %+v, want a move to UNKNOWN with mon_client_offline", rec)
		}
		if !rec.Notified {
			t.Errorf("target event %+v was left announceable; only the mon-client transition is", rec)
		}
	}

	// A second pass finds nothing new to say.
	h.advance(time.Minute)
	if err := h.mon.CheckOnce(t.Context()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if got := h.newEvents(); len(got) != 0 {
		t.Fatalf("a second pass filed %+v", got)
	}

	// The mon-client comes back: ONLINE again, targets still UNKNOWN until a
	// result (spec §7.3).
	h.advance(time.Minute)
	backAt := h.now()
	h.heartbeat(Heartbeat{Cycles: []Cycle{{Seq: 100, TS: backAt}}})
	if got := h.monClient().State; got != store.ClientStateOnline {
		t.Errorf("mon-client = %s after a heartbeat, want ONLINE", got)
	}
	for _, key := range []TargetKey{xrayProxy, awgDirect} {
		if got := h.state(key); got != store.TargetUnknown {
			t.Errorf("target %s = %s, want UNKNOWN until a result", key, got)
		}
	}
	back := h.newEvents()
	if len(back) != 1 || back[0].Kind != panel.EventKindMonClient || back[0].To != store.ClientStateOnline {
		t.Fatalf("coming back filed %+v, want one mon_client ONLINE event", back)
	}
}

// TestMonitorLeavesNeverAndPausedAlone covers the two exceptions of spec §7.3
// and §7.2: a mon-client that has never reported is not an outage, and a
// target paused by the configuration is not swept to UNKNOWN.
func TestMonitorLeavesNeverAndPausedAlone(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy, awgDirect)

	// Nothing has ever reported: hours of silence change nothing.
	h.advance(4 * time.Hour)
	if err := h.mon.CheckOnce(t.Context()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if got := h.monClient().State; got != store.ClientStateNever {
		t.Fatalf("mon-client = %s, want NEVER", got)
	}
	if got := h.allEvents(); len(got) != 0 {
		t.Fatalf("a mon-client that never reported filed %+v", got)
	}

	// It reports once, one of its inbounds is disabled, then it goes quiet.
	h.probeN(xrayProxy, true, "", 1)
	h.sync(xrayProxy)
	if got := h.state(awgDirect); got != store.TargetPaused {
		t.Fatalf("awg target = %s, want PAUSED", got)
	}
	h.newEvents()
	h.advance(offlineAfter + time.Second)
	if err := h.mon.CheckOnce(t.Context()); err != nil {
		t.Fatalf("CheckOnce: %v", err)
	}
	if got := h.monClient().State; got != store.ClientStateOffline {
		t.Fatalf("mon-client = %s, want OFFLINE", got)
	}
	if got := h.state(awgDirect); got != store.TargetPaused {
		t.Errorf("paused target = %s, want it left PAUSED", got)
	}
	if got := h.state(xrayProxy); got != store.TargetUnknown {
		t.Errorf("target = %s, want UNKNOWN", got)
	}
	for _, rec := range h.newEvents() {
		if rec.Target == awgDirect.String() {
			t.Errorf("filed %+v for a paused target", rec)
		}
	}
}

// TestResetToUnknownIsQuiet covers the entry point the registry uses when an
// administrator disables a mon-client (spec §6): the targets move with
// mon_client_disabled and the move is filed, not announced.
func TestResetToUnknownIsQuiet(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SavePanelState(store.PanelState{Status: store.PanelStatusDown}); err != nil {
		t.Fatalf("save panel state: %v", err)
	}
	h.sync(xrayProxy)
	h.probeN(xrayProxy, true, "", 1)
	h.newEvents()
	h.newAlerts()

	moved, err := h.m.ResetToUnknown(t.Context(), testClientID, panel.ReasonMonClientDisabled)
	if err != nil {
		t.Fatalf("ResetToUnknown: %v", err)
	}
	if moved != 1 {
		t.Errorf("moved %d targets, want 1", moved)
	}
	assertEvents(t, "disabled", filedFor(h.newEvents(), xrayProxy), []wantEvent{
		{from: store.TargetUp, to: store.TargetUnknown, reason: panel.ReasonMonClientDisabled, quiet: true},
	})
	if got := h.newAlerts(); len(got) != 0 {
		t.Errorf("disabling a mon-client announced its targets: %v", got)
	}
}

// clockAt is the instant d after a stored millisecond timestamp.
func clockAt(ms int64, d time.Duration) time.Time {
	return time.UnixMilli(ms).UTC().Add(d)
}
