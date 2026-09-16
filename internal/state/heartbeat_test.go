package state

import (
	"testing"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// TestHeartbeatFirstOneBringsTheMonClientOnline covers spec §7.1 step 2 and
// the ONLINE row of §7.3: the first heartbeat makes a mon-client ONLINE, files
// the transition, and leaves every target UNKNOWN until a result arrives.
func TestHeartbeatFirstOneBringsTheMonClientOnline(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy, awgDirect)
	h.setConfigRevision("3a91c0de77b1f2e4")

	recv := h.now()
	ack := h.heartbeat(Heartbeat{
		MonClientID:    testClientID,
		ConfigRevision: "0000000000000000",
		Client:         ClientReport{Version: "0.1.0", XrayVersion: "26.3.27", UptimeMS: 86_400_000},
		Cycles:         []Cycle{{Seq: 1441, TS: recv}},
	})

	if ack.ConfigRevision != "3a91c0de77b1f2e4" {
		t.Errorf("ack.ConfigRevision = %q, want the revision mon-server built", ack.ConfigRevision)
	}
	if ack.ServerTS != recv {
		t.Errorf("ack.ServerTS = %d, want mon-server's receive time %d", ack.ServerTS, recv)
	}
	if ack.AckSeq != 1441 {
		t.Errorf("ack.AckSeq = %d, want 1441", ack.AckSeq)
	}

	mc := h.monClient()
	if mc.State != store.ClientStateOnline {
		t.Errorf("mon-client state = %s, want ONLINE", mc.State)
	}
	if mc.LastHeartbeat != recv {
		t.Errorf("last heartbeat = %d, want %d", mc.LastHeartbeat, recv)
	}
	if mc.Version != "0.1.0" || mc.XrayVersion != "26.3.27" {
		t.Errorf("versions = %q/%q, want 0.1.0/26.3.27", mc.Version, mc.XrayVersion)
	}
	if mc.AppliedRevision != "0000000000000000" {
		t.Errorf("applied revision = %q, want the one the mon-client reported", mc.AppliedRevision)
	}
	if mc.MissedHeartbeats != 0 {
		t.Errorf("missed heartbeats = %d, want 0", mc.MissedHeartbeats)
	}

	for _, key := range []TargetKey{xrayProxy, awgDirect} {
		if got := h.state(key); got != store.TargetUnknown {
			t.Errorf("target %s = %s, want UNKNOWN until a result", key, got)
		}
	}
	filed := h.allEvents()
	if len(filed) != 1 {
		t.Fatalf("filed %d events, want one: %+v", len(filed), filed)
	}
	want := eventRecord{
		Kind: panel.EventKindMonClient, MonClientID: testClientID,
		From: store.ClientStateNever, To: store.ClientStateOnline, Reason: panel.ReasonRecovered, TS: recv,
	}
	if filed[0] != want {
		t.Errorf("mon-client event = %+v, want %+v", filed[0], want)
	}
}

// TestHeartbeatCycleSelection is spec §7.1 step 3: only the live cycle drives
// the state machine, everything else is statistics.
func TestHeartbeatCycleSelection(t *testing.T) {
	t.Run("a resent cycle does not replay history", func(t *testing.T) {
		h := newHarness(t)
		h.sync(xrayProxy)
		recv := h.now()
		// Two new cycles arrive together: the buffered one and the live one.
		// Only the live one may reach the state machine, so exactly one
		// failure is counted.
		h.heartbeat(Heartbeat{Cycles: []Cycle{
			{Seq: 6, TS: recv - 60_000, Results: []Result{result(xrayProxy, false, panel.ReasonTCPTimeout)}},
			{Seq: 7, TS: recv, Results: []Result{result(xrayProxy, false, panel.ReasonTCPTimeout)}},
		}})
		if got := h.target(xrayProxy).ConsecutiveFail; got != 1 {
			t.Errorf("consecutive failures = %d, want 1: the resent cycle was replayed", got)
		}
		if calls := h.newStats(); len(calls) != 2 {
			t.Errorf("statistics saw %d cycles, want both", len(calls))
		}
		if got := h.allEvents(); len(got) != 1 || got[0].Kind != panel.EventKindMonClient {
			t.Errorf("filed %+v, want only the ONLINE event", got)
		}
	})

	t.Run("an unverified cycle counts for statistics only, and only its successes", func(t *testing.T) {
		h := newHarness(t)
		h.sync(xrayProxy, awgDirect)
		recv := h.now()
		h.heartbeat(Heartbeat{Cycles: []Cycle{{
			Seq: 3, TS: recv, Unverified: true,
			Results: []Result{
				result(xrayProxy, false, panel.ReasonAWGNoHandshake),
				result(awgDirect, true, ""),
			},
		}}})

		for _, key := range []TargetKey{xrayProxy, awgDirect} {
			if got := h.state(key); got != store.TargetUnknown {
				t.Errorf("target %s = %s, an unverified cycle drove the state machine", key, got)
			}
		}
		if got := h.target(xrayProxy).ConsecutiveFail; got != 0 {
			t.Errorf("consecutive failures = %d, want 0: an unverified failure was counted", got)
		}
		calls := h.newStats()
		if len(calls) != 1 {
			t.Fatalf("statistics saw %d cycles, want one: %+v", len(calls), calls)
		}
		if !calls[0].unverified {
			t.Error("the cycle reached statistics without its unverified flag")
		}
		if len(calls[0].results) != 1 || !calls[0].results[0].OK {
			t.Errorf("statistics got %+v, want the success alone", calls[0].results)
		}

		// However many unverified failures arrive, nothing goes DOWN.
		for seq := int64(4); seq <= 9; seq++ {
			h.advance(time.Minute)
			h.heartbeat(Heartbeat{Cycles: []Cycle{{
				Seq: seq, TS: h.now(), Unverified: true,
				Results: []Result{result(xrayProxy, false, panel.ReasonTCPTimeout)},
			}}})
		}
		if got := h.state(xrayProxy); got != store.TargetUnknown {
			t.Errorf("target = %s, want UNKNOWN: unverified failures moved it", got)
		}
	})

	t.Run("the live cycle is the last verified one", func(t *testing.T) {
		h := newHarness(t)
		h.sync(xrayProxy)
		recv := h.now()
		// The last cycle is unverified, so this heartbeat has no live cycle at
		// all and the success below must not start the target UP.
		h.heartbeat(Heartbeat{Cycles: []Cycle{
			{Seq: 1, TS: recv - 60_000, Results: []Result{result(xrayProxy, true, "")}},
			{Seq: 2, TS: recv, Unverified: true, Results: []Result{result(xrayProxy, true, "")}},
		}})
		if got := h.state(xrayProxy); got != store.TargetUnknown {
			t.Errorf("target = %s, want UNKNOWN: a cycle that is not live drove the state machine", got)
		}
		if got := h.newStats(); len(got) != 2 {
			t.Errorf("statistics saw %d cycles, want both", len(got))
		}
	})
}

// TestHeartbeatAcknowledgement covers the acknowledgement cursor of spec §7.1
// step 3: cycles at or below the previous ackSeq are ignored outright, so a
// heartbeat that is replayed after a lost answer changes nothing.
func TestHeartbeatAcknowledgement(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy)
	hb := Heartbeat{Cycles: []Cycle{{Seq: 11, TS: h.now(), Results: []Result{result(xrayProxy, false, panel.ReasonTCPRefused)}}}}

	if ack := h.heartbeat(hb); ack.AckSeq != 11 {
		t.Fatalf("ack = %d, want 11", ack.AckSeq)
	}
	before := h.target(xrayProxy)
	statsBefore := len(h.stats.took())
	eventsBefore := len(h.allEvents())

	// The mon-client never saw the answer and sends the very same heartbeat.
	h.advance(30 * time.Second)
	if ack := h.heartbeat(hb); ack.AckSeq != 11 {
		t.Fatalf("replayed ack = %d, want 11", ack.AckSeq)
	}
	after := h.target(xrayProxy)
	if after.ConsecutiveFail != before.ConsecutiveFail || after.LastResultAt != before.LastResultAt {
		t.Errorf("the replayed heartbeat moved the target: %+v -> %+v", before, after)
	}
	if got := len(h.stats.took()); got != statsBefore {
		t.Errorf("the replayed heartbeat recorded %d extra cycles", got-statsBefore)
	}
	if got := len(h.allEvents()); got != eventsBefore {
		t.Errorf("the replayed heartbeat filed %d extra events", got-eventsBefore)
	}

	// An older cycle resurfacing is ignored as well, and does not lower the
	// acknowledgement.
	h.advance(30 * time.Second)
	ack := h.heartbeat(Heartbeat{Cycles: []Cycle{{Seq: 4, TS: h.now(), Results: []Result{result(xrayProxy, false, panel.ReasonTCPRefused)}}}})
	if ack.AckSeq != 11 {
		t.Errorf("ack = %d, want 11", ack.AckSeq)
	}
	if got := h.target(xrayProxy).ConsecutiveFail; got != after.ConsecutiveFail {
		t.Errorf("an already acknowledged cycle was applied: failures = %d, want %d", got, after.ConsecutiveFail)
	}
	if got := len(h.stats.took()); got != statsBefore {
		t.Errorf("an already acknowledged cycle reached statistics")
	}
}

// TestHeartbeatClockClamp covers spec §7.1 step 1: the cycle's own timestamp
// buckets the results and nothing else, clamped to mon-server's receive time
// when it is more than five minutes adrift.
func TestHeartbeatClockClamp(t *testing.T) {
	const fiveMinutes = 5 * 60 * 1000
	cases := []struct {
		name string
		// offset is added to the receive time to build the cycle's ts; zero
		// offset with missing=true sends no timestamp at all.
		offset  int64
		missing bool
		clamped bool
	}{
		{name: "exactly five minutes behind", offset: -fiveMinutes},
		{name: "a millisecond further behind", offset: -fiveMinutes - 1, clamped: true},
		{name: "exactly five minutes ahead", offset: fiveMinutes},
		{name: "a millisecond further ahead", offset: fiveMinutes + 1, clamped: true},
		{name: "no timestamp at all", missing: true, clamped: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.sync(xrayProxy)
			recv := h.now()
			cycleTS := recv + tc.offset
			if tc.missing {
				cycleTS = 0
			}
			h.heartbeat(Heartbeat{Cycles: []Cycle{{Seq: 1, TS: cycleTS, Results: []Result{result(xrayProxy, true, "")}}}})

			want := cycleTS
			if tc.clamped {
				want = recv
			}
			calls := h.newStats()
			if len(calls) != 1 {
				t.Fatalf("statistics saw %d cycles, want one", len(calls))
			}
			if calls[0].cycleTS != want {
				t.Errorf("bucketing timestamp = %d, want %d", calls[0].cycleTS, want)
			}

			// Whatever the mon-client's clock says, the state is dated by
			// mon-server's receive time.
			row := h.target(xrayProxy)
			if row.State != store.TargetUp {
				t.Fatalf("target = %s, want UP", row.State)
			}
			if row.Since != recv || row.LastResultAt != recv {
				t.Errorf("target since/lastResult = %d/%d, want the receive time %d", row.Since, row.LastResultAt, recv)
			}
			filed := targetEvents(h.allEvents(), xrayProxy)
			if len(filed) != 1 {
				t.Fatalf("filed %d target events, want one", len(filed))
			}
			if filed[0].TS != recv {
				t.Errorf("event ts = %d, want the receive time %d", filed[0].TS, recv)
			}
		})
	}
}

// TestHeartbeatDiscardsUnconfiguredTargets covers the last rule of spec §7.1
// step 3: a result naming a target this mon-client is not configured to probe
// is dropped, and never invents a target row.
func TestHeartbeatDiscardsUnconfiguredTargets(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy)
	h.heartbeat(Heartbeat{Cycles: []Cycle{{Seq: 1, TS: h.now(), Results: []Result{
		result(xrayDirect, false, panel.ReasonTCPRefused),
		result(xrayProxy, true, ""),
	}}}})

	row, err := h.m.loadTarget(t.Context(), testClientID, xrayDirect)
	if err != nil {
		t.Fatalf("load target: %v", err)
	}
	if row != nil {
		t.Errorf("a result created target %s, which is not in the configuration: %+v", xrayDirect, row)
	}
	if got := h.state(xrayProxy); got != store.TargetUp {
		t.Errorf("configured target = %s, want UP", got)
	}
	calls := h.newStats()
	if len(calls) != 1 {
		t.Fatalf("statistics saw %d cycles, want one", len(calls))
	}
	if len(calls[0].results) != 1 || calls[0].results[0].Path != store.PathProxy {
		t.Errorf("statistics got %+v, want the configured target alone", calls[0].results)
	}
	if got := targetEvents(h.allEvents(), xrayDirect); len(got) != 0 {
		t.Errorf("filed %+v for a target outside the configuration", got)
	}
}

// TestHeartbeatConfigError covers the configError rule of spec §7.1 step 2: an
// error that appears is stored with its time and told to the owner once, an
// error that disappears is cleared.
func TestHeartbeatConfigError(t *testing.T) {
	h := newHarness(t)
	h.sync(xrayProxy)

	const detail = "xray -test failed: invalid link for inbound 12"
	appearedAt := h.now()
	h.heartbeat(Heartbeat{Client: ClientReport{ConfigError: detail}, Cycles: []Cycle{{Seq: 1, TS: h.now()}}})

	mc := h.monClient()
	if mc.ConfigError != detail {
		t.Errorf("stored config error = %q, want %q", mc.ConfigError, detail)
	}
	if mc.ConfigErrorAt != appearedAt {
		t.Errorf("config error time = %d, want %d", mc.ConfigErrorAt, appearedAt)
	}
	alerts := h.newAlerts()
	if len(alerts) != 1 {
		t.Fatalf("config error sent %d messages, want one: %v", len(alerts), alerts)
	}

	// The same error again is not news.
	h.advance(time.Minute)
	h.heartbeat(Heartbeat{Client: ClientReport{ConfigError: detail}, Cycles: []Cycle{{Seq: 2, TS: h.now()}}})
	if got := h.newAlerts(); len(got) != 0 {
		t.Errorf("the same config error was announced again: %v", got)
	}
	if got := h.monClient().ConfigErrorAt; got != appearedAt {
		t.Errorf("config error time moved to %d, want the time it appeared %d", got, appearedAt)
	}

	// It is cleared when the mon-client stops reporting it.
	h.advance(time.Minute)
	h.heartbeat(Heartbeat{Cycles: []Cycle{{Seq: 3, TS: h.now()}}})
	mc = h.monClient()
	if mc.ConfigError != "" || mc.ConfigErrorAt != 0 {
		t.Errorf("config error left as %q at %d, want it cleared", mc.ConfigError, mc.ConfigErrorAt)
	}
	if got := h.newAlerts(); len(got) != 0 {
		t.Errorf("clearing a config error announced %v", got)
	}
}
