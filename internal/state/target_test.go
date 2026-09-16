package state

import (
	"context"
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// wantEvent is one expected transition: what a test asserts about an event,
// without the timestamp and the identity the surrounding case already fixes.
// quiet means the event was filed with notified=true, which is how spec §7.2
// keeps a transition out of Telegram on both sides — the panel does not
// announce it, and neither does mon-server while the panel is down.
type wantEvent struct {
	from, to, reason string
	quiet            bool
}

// filedFor reduces the target events of one key to the assertable form.
func filedFor(list []eventRecord, key TargetKey) []wantEvent {
	out := make([]wantEvent, 0, len(list))
	for _, rec := range targetEvents(list, key) {
		out = append(out, wantEvent{from: rec.From, to: rec.To, reason: rec.Reason, quiet: rec.Notified})
	}
	return out
}

// assertEvents compares the transitions a step filed with what it should have.
func assertEvents(t *testing.T, step string, got, want []wantEvent) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: filed %d events, want %d: got %+v, want %+v", step, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%s: event %d = %+v, want %+v", step, i, got[i], want[i])
		}
	}
}

// TestTargetStateMachine is the transition table of spec §7.2: every
// threshold, the flap window and the hold, driven a result at a time through
// real heartbeats and asserted on both the stored state and the events filed.
func TestTargetStateMachine(t *testing.T) {
	const (
		tcpTimeout = panel.ReasonTCPTimeout
		recovered  = panel.ReasonRecovered
		flapping   = panel.ReasonFlapping
	)
	// A step applies n results one minute apart, after waiting `wait`.
	type step struct {
		name   string
		wait   time.Duration
		ok     bool
		reason string
		n      int
		want   string
		events []wantEvent
	}
	cases := []struct {
		name  string
		steps []step
	}{
		{
			name: "the first result ever being a success starts UP",
			steps: []step{
				{name: "one success", ok: true, n: 1, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetUp, reason: recovered}}},
			},
		},
		{
			name: "a failure does not reach DOWN before downAfter",
			steps: []step{
				{name: "first failure", reason: tcpTimeout, n: 1, want: store.TargetUnknown},
				{name: "second failure", reason: tcpTimeout, n: 1, want: store.TargetUnknown},
				{name: "third failure", reason: tcpTimeout, n: 1, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetDown, reason: tcpTimeout}}},
			},
		},
		{
			name: "upAfter successes are needed to leave DOWN",
			steps: []step{
				{name: "three failures", reason: tcpTimeout, n: 3, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "one success", ok: true, n: 1, want: store.TargetDown},
				{name: "second success", ok: true, n: 1, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetUp, reason: recovered}}},
			},
		},
		{
			name: "a success resets the failure counter",
			steps: []step{
				{name: "two failures", reason: tcpTimeout, n: 2, want: store.TargetUnknown},
				{name: "one success", ok: true, n: 1, want: store.TargetUnknown},
				{name: "two more failures", reason: tcpTimeout, n: 2, want: store.TargetUnknown},
				{name: "the third failure in a row", reason: tcpTimeout, n: 1, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetDown, reason: tcpTimeout}}},
			},
		},
		{
			name: "a failure resets the success counter",
			steps: []step{
				{name: "three failures", reason: tcpTimeout, n: 3, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "one success", ok: true, n: 1, want: store.TargetDown},
				{name: "one failure", reason: tcpTimeout, n: 1, want: store.TargetDown},
				{name: "one success again", ok: true, n: 1, want: store.TargetDown},
				{name: "the second success in a row", ok: true, n: 1, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetUp, reason: recovered}}},
			},
		},
		{
			name: "flapN transitions within flapMin enter FLAPPING, and it holds and settles",
			steps: []step{
				{name: "start UP", ok: true, n: 1, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetUp, reason: recovered}}},
				{name: "transition 1 to DOWN", reason: tcpTimeout, n: 3, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUp, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "transition 2 to UP", ok: true, n: 2, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetUp, reason: recovered}}},
				{name: "transition 3 to DOWN", reason: tcpTimeout, n: 3, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUp, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "transition 4 enters FLAPPING", ok: true, n: 2, want: store.TargetFlapping,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetFlapping, reason: flapping}}},
				{name: "a transition inside FLAPPING is filed but quiet", reason: tcpTimeout, n: 3, want: store.TargetFlapping,
					events: []wantEvent{{from: store.TargetUp, to: store.TargetDown, reason: tcpTimeout, quiet: true}}},
				{name: "flapHoldMin of quiet settles it on the real state", wait: 15 * time.Minute, ok: true, n: 1, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetFlapping, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "and the window starts over", ok: true, n: 1, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetUp, reason: recovered}}},
			},
		},
		{
			name: "a transition outside flapMin does not trip FLAPPING",
			steps: []step{
				{name: "start UP", ok: true, n: 1, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetUnknown, to: store.TargetUp, reason: recovered}}},
				{name: "transition 1 to DOWN", reason: tcpTimeout, n: 3, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUp, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "transition 2 to UP", ok: true, n: 2, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetUp, reason: recovered}}},
				{name: "transition 3 to DOWN", reason: tcpTimeout, n: 3, want: store.TargetDown,
					events: []wantEvent{{from: store.TargetUp, to: store.TargetDown, reason: tcpTimeout}}},
				{name: "transition 4, with the first one now out of the window", wait: 24 * time.Minute, ok: true, n: 2, want: store.TargetUp,
					events: []wantEvent{{from: store.TargetDown, to: store.TargetUp, reason: recovered}}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.sync(xrayProxy)
			h.newEvents()
			for _, st := range tc.steps {
				if st.wait > 0 {
					h.advance(st.wait)
				}
				h.probeN(xrayProxy, st.ok, st.reason, st.n)
				if got := h.state(xrayProxy); got != st.want {
					t.Fatalf("%s: state = %s, want %s", st.name, got, st.want)
				}
				assertEvents(t, st.name, filedFor(h.newEvents(), xrayProxy), st.events)
			}
			if texts := h.alerts.sent(); len(texts) != 0 {
				t.Errorf("mon-server announced %v itself while the panel was up", texts)
			}
		})
	}
}

// TestTargetFlappingKeepsTelegramQuiet checks the rule that separates a filed
// event from an announced one (spec §7.2): entering and leaving FLAPPING are
// announced, the transitions inside are only filed. The panel is down here, so
// mon-server is the one announcing (§4.1) and every message it sends is
// visible to the test.
func TestTargetFlappingKeepsTelegramQuiet(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SavePanelState(store.PanelState{Status: store.PanelStatusDown}); err != nil {
		t.Fatalf("save panel state: %v", err)
	}
	h.sync(xrayProxy)

	// Four UP<->DOWN transitions inside flapMin.
	h.probeN(xrayProxy, true, "", 1)
	h.probeN(xrayProxy, false, panel.ReasonTCPTimeout, 3)
	h.probeN(xrayProxy, true, "", 2)
	h.probeN(xrayProxy, false, panel.ReasonTCPTimeout, 3)
	h.newAlerts()
	h.probeN(xrayProxy, true, "", 2)
	if got := h.state(xrayProxy); got != store.TargetFlapping {
		t.Fatalf("state = %s, want FLAPPING", got)
	}
	entering := h.newAlerts()
	if len(entering) != 1 {
		t.Fatalf("entering FLAPPING sent %d messages, want 1: %v", len(entering), entering)
	}

	// A transition inside FLAPPING: filed, notified, silent.
	h.newEvents()
	h.probeN(xrayProxy, false, panel.ReasonTCPTimeout, 3)
	inner := filedFor(h.newEvents(), xrayProxy)
	assertEvents(t, "inside FLAPPING", inner, []wantEvent{
		{from: store.TargetUp, to: store.TargetDown, reason: panel.ReasonTCPTimeout, quiet: true},
	})
	if got := h.newAlerts(); len(got) != 0 {
		t.Fatalf("a transition inside FLAPPING was announced: %v", got)
	}

	// Leaving is announced again.
	h.advance(15 * time.Minute)
	h.probeN(xrayProxy, false, panel.ReasonTCPTimeout, 1)
	if got := h.state(xrayProxy); got != store.TargetDown {
		t.Fatalf("state = %s, want DOWN after the hold", got)
	}
	if got := h.newAlerts(); len(got) != 1 {
		t.Fatalf("leaving FLAPPING sent %d messages, want 1: %v", len(got), got)
	}
}

// TestTrimWindowBoundary pins the edge of the flap window: a transition
// exactly flapMin old still counts, a millisecond older does not.
func TestTrimWindowBoundary(t *testing.T) {
	const now int64 = 1_000_000_000
	window := []transition{
		{TS: now - 30*minuteMS - 1, To: store.TargetDown},
		{TS: now - 30*minuteMS, To: store.TargetUp},
		{TS: now, To: store.TargetDown},
	}
	got := trimWindow(window, now-30*minuteMS)
	if len(got) != 2 {
		t.Fatalf("kept %d transitions, want 2: %+v", len(got), got)
	}
	if got[0].TS != now-30*minuteMS {
		t.Errorf("oldest kept transition = %d, want %d", got[0].TS, now-30*minuteMS)
	}
}

// TestSyncTargetsPausesAndRestores covers the configuration side of the state
// machine (spec §7.2, §4 step 3): a target that disappears from the
// configuration is PAUSED, and one that comes back waits in UNKNOWN for a
// result.
func TestSyncTargetsPausesAndRestores(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy, awgDirect)
	if got := h.allEvents(); len(got) != 0 {
		t.Fatalf("creating targets filed %d events, want none: %+v", len(got), got)
	}
	for _, key := range []TargetKey{xrayProxy, awgDirect} {
		if got := h.state(key); got != store.TargetUnknown {
			t.Fatalf("new target %s = %s, want UNKNOWN", key, got)
		}
	}

	h.probeN(xrayProxy, true, "", 1)
	if got := h.state(xrayProxy); got != store.TargetUp {
		t.Fatalf("state = %s, want UP", got)
	}
	h.newEvents()
	h.newStats()

	// The inbound is switched off in the panel: it is gone from the next
	// configuration.
	h.sync(awgDirect)
	if got := h.state(xrayProxy); got != store.TargetPaused {
		t.Fatalf("state = %s, want PAUSED", got)
	}
	assertEvents(t, "paused", filedFor(h.newEvents(), xrayProxy), []wantEvent{
		{from: store.TargetUp, to: store.TargetPaused, reason: panel.ReasonConfigDisabled, quiet: true},
	})

	// A lagging mon-client still probing the paused target changes nothing.
	h.probeN(xrayProxy, false, panel.ReasonTCPRefused, 3)
	if got := h.state(xrayProxy); got != store.TargetPaused {
		t.Fatalf("results moved a paused target to %s", got)
	}
	if got := h.newEvents(); len(got) != 0 {
		t.Fatalf("results for a paused target filed %+v", got)
	}
	if calls := h.newStats(); len(calls) != 0 {
		t.Fatalf("results for a paused target reached statistics: %+v", calls)
	}

	// The inbound is switched back on.
	h.sync(xrayProxy, awgDirect)
	if got := h.state(xrayProxy); got != store.TargetUnknown {
		t.Fatalf("state = %s, want UNKNOWN", got)
	}
	assertEvents(t, "resumed", filedFor(h.newEvents(), xrayProxy), []wantEvent{
		{from: store.TargetPaused, to: store.TargetUnknown, reason: panel.ReasonConfigEnabled, quiet: true},
	})

	// Starting over: the first result after a pause counts as a first result.
	h.probeN(xrayProxy, true, "", 1)
	if got := h.state(xrayProxy); got != store.TargetUp {
		t.Fatalf("state = %s, want UP on the first result after a pause", got)
	}
}

// TestPauseAndResumeOneTarget covers the single-target entry points the panel
// poll uses for an inbound that is present but disabled.
func TestPauseAndResumeOneTarget(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy)
	h.probeN(xrayProxy, true, "", 1)
	h.newEvents()

	ctx := context.Background()
	if err := h.m.Pause(ctx, testClientID, xrayProxy.InboundKind, xrayProxy.InboundID, xrayProxy.Path, ""); err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if got := h.state(xrayProxy); got != store.TargetPaused {
		t.Fatalf("state = %s, want PAUSED", got)
	}
	assertEvents(t, "pause", filedFor(h.newEvents(), xrayProxy), []wantEvent{
		{from: store.TargetUp, to: store.TargetPaused, reason: panel.ReasonConfigDisabled, quiet: true},
	})

	// Pausing twice says nothing twice.
	if err := h.m.Pause(ctx, testClientID, xrayProxy.InboundKind, xrayProxy.InboundID, xrayProxy.Path, ""); err != nil {
		t.Fatalf("Pause again: %v", err)
	}
	if got := h.newEvents(); len(got) != 0 {
		t.Fatalf("pausing a paused target filed %+v", got)
	}

	if err := h.m.Resume(ctx, testClientID, xrayProxy.InboundKind, xrayProxy.InboundID, xrayProxy.Path, ""); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if got := h.state(xrayProxy); got != store.TargetUnknown {
		t.Fatalf("state = %s, want UNKNOWN", got)
	}
	assertEvents(t, "resume", filedFor(h.newEvents(), xrayProxy), []wantEvent{
		{from: store.TargetPaused, to: store.TargetUnknown, reason: panel.ReasonConfigEnabled, quiet: true},
	})
}
