package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/registry"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
	"github.com/SBKubric/3ax-ui-monitoring/internal/tg"
)

// stubConfigs answers what registry.ConfigBuilder would, from a literal.
type stubConfigs struct {
	keys     []registry.TargetKey
	revision string
	excl     registry.Exclusions
}

func (s *stubConfigs) Exclusions(context.Context, string) (registry.Exclusions, error) {
	return s.excl, nil
}

func (s *stubConfigs) TargetKeys(context.Context, string) ([]registry.TargetKey, error) {
	return s.keys, nil
}

func (s *stubConfigs) CurrentRevision(context.Context, string) (string, error) {
	return s.revision, nil
}

// recordingSink is step 7's StatsSink as far as step 6 can check it: it
// keeps what it was handed so the tests can assert the filtering contract,
// and can be told to fail so the heartbeat's transaction can be tested.
type recordingSink struct {
	cycles []Cycle
	err    error
	// tx records the handle the engine passed in, to pin the contract that
	// the sink joins the heartbeat's transaction rather than opening its own.
	tx *gorm.DB
}

func (r *recordingSink) Record(_ context.Context, tx *gorm.DB, _ string, cycles []Cycle) error {
	r.tx = tx
	if r.err != nil {
		return r.err
	}
	r.cycles = append(r.cycles, cycles...)
	return nil
}

// flakyNotifier wraps the recorder so a test can make Telegram fail without
// touching internal/tg, which step 9 owns.
type flakyNotifier struct {
	rec *tg.Recorder
	err error
}

func (n *flakyNotifier) Send(ctx context.Context, text string) error {
	if n.err != nil {
		return n.err
	}
	return n.rec.Send(ctx, text)
}

// fixture is one engine over a real temp-file store with a fake clock, the
// combination docs/agents/testing.md asks for.
type fixture struct {
	t    *testing.T
	e    *Engine
	st   *store.Store
	clk  *clock.Fake
	tgr  *tg.Recorder
	tgn  *flakyNotifier
	cfg  *stubConfigs
	sink *recordingSink
	mc   *store.MonClient

	panelDown bool
}

var (
	keyProxy  = registry.TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathProxy}
	keyDirect = registry.TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: store.PathDirect}
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	f := &fixture{
		t:    t,
		st:   st,
		clk:  clock.NewFake(baseTime),
		tgr:  &tg.Recorder{},
		cfg:  &stubConfigs{keys: []registry.TargetKey{keyProxy, keyDirect}, revision: "rev-current"},
		sink: &recordingSink{},
	}
	f.mc = &store.MonClient{
		Id: "ams-1", Name: "ams-1", Region: "NL", Enabled: true,
		State: store.MonClientNever, ApprovedAt: clock.Ms(baseTime),
	}
	f.mc.SetPaths([]string{store.PathProxy, store.PathDirect})
	if err := st.DB.Create(f.mc).Error; err != nil {
		t.Fatalf("create mon-client: %v", err)
	}
	f.tgn = &flakyNotifier{rec: f.tgr}
	f.e = New(Deps{
		Store: st, Clock: f.clk, Notifier: f.tgn,
		PanelDown: func() bool { return f.panelDown },
		Configs:   f.cfg, Stats: f.sink,
	})
	return f
}

// result builds one wire result for keyProxy unless told otherwise.
func result(key registry.TargetKey, ok bool, reason string) Result {
	r := Result{InboundKind: key.InboundKind, InboundID: key.InboundID, Path: key.Path, Ok: ok}
	if !ok && reason != "" {
		r.Reason = &reason
	}
	return r
}

// beat sends one heartbeat with the given cycles and fails the test if the
// engine errors.
func (f *fixture) beat(cycles ...Cycle) *HeartbeatResponse {
	f.t.Helper()
	resp, err := f.e.Heartbeat(context.Background(), f.mc, &HeartbeatRequest{
		MonClientID:    f.mc.Id,
		ConfigRevision: "rev-applied",
		Client:         ClientInfo{Version: "0.1.0", XrayVersion: "26.3.27"},
		Cycles:         cycles,
	})
	if err != nil {
		f.t.Fatalf("Heartbeat: %v", err)
	}
	return resp
}

// beatErr sends one heartbeat and hands back whatever the engine said,
// for the tests that are about a beat failing.
func (f *fixture) beatErr(cycles ...Cycle) error {
	f.t.Helper()
	_, err := f.e.Heartbeat(context.Background(), f.mc, &HeartbeatRequest{
		MonClientID:    f.mc.Id,
		ConfigRevision: "rev-applied",
		Client:         ClientInfo{Version: "0.1.0", XrayVersion: "26.3.27"},
		Cycles:         cycles,
	})
	return err
}

// cycle is a live cycle at the fake clock's current time.
func (f *fixture) cycle(seq int64, results ...Result) Cycle {
	return Cycle{Seq: seq, Ts: clock.Ms(f.clk.Now()), Results: results}
}

// targetState reads one target row back, failing if it is gone.
func (f *fixture) targetState(key registry.TargetKey) store.Target {
	f.t.Helper()
	var t store.Target
	if err := f.st.DB.First(&t, "mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ?",
		f.mc.Id, key.InboundKind, key.InboundID, key.Path).Error; err != nil {
		f.t.Fatalf("read target %+v: %v", key, err)
	}
	return t
}

// events decodes the outbox in insertion order.
func (f *fixture) events() []store.EventPayload {
	f.t.Helper()
	var rows []store.EventOutbox
	if err := f.st.DB.Order("ts, id").Find(&rows).Error; err != nil {
		f.t.Fatalf("read outbox: %v", err)
	}
	out := make([]store.EventPayload, 0, len(rows))
	for _, r := range rows {
		var ev store.EventPayload
		if err := json.Unmarshal([]byte(r.Payload), &ev); err != nil {
			f.t.Fatalf("decode event: %v", err)
		}
		out = append(out, ev)
	}
	return out
}

// reload re-reads the mon-client row from the database.
func (f *fixture) reload() store.MonClient {
	f.t.Helper()
	var mc store.MonClient
	if err := f.st.DB.First(&mc, "id = ?", f.mc.Id).Error; err != nil {
		f.t.Fatalf("reload mon-client: %v", err)
	}
	return mc
}

// fail3 drives the target to DOWN through three live heartbeats.
func (f *fixture) fail3(seq int64, key registry.TargetKey, reason string) int64 {
	f.t.Helper()
	for i := 0; i < 3; i++ {
		f.clk.Advance(time.Minute)
		f.beat(f.cycle(seq, result(key, false, reason)))
		seq++
	}
	return seq
}

// TestHeartbeat_FirstHeartbeatBringsTheClientOnline covers spec §7.1 step 2
// and §7.3's ONLINE rule, including that targets stay UNKNOWN until a
// result actually arrives.
func TestHeartbeat_FirstHeartbeatBringsTheClientOnline(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)

	resp := f.beat()

	mc := f.reload()
	if mc.State != store.MonClientOnline {
		t.Fatalf("state = %s, want ONLINE", mc.State)
	}
	if mc.LastHeartbeat == nil || *mc.LastHeartbeat != clock.Ms(f.clk.Now()) {
		t.Fatalf("last_heartbeat = %v, want mon-server's receive time", mc.LastHeartbeat)
	}
	if mc.Version != "0.1.0" || mc.XrayVersion != "26.3.27" || mc.AppliedRevision != "rev-applied" {
		t.Fatalf("mon-client row = %+v, want the heartbeat's versions and applied revision", mc)
	}
	if resp.ConfigRevision != "rev-current" || resp.ServerTs != clock.Ms(f.clk.Now()) {
		t.Fatalf("response = %+v, want the current revision and mon-server's time", resp)
	}

	evs := f.events()
	if len(evs) != 1 || evs[0].Kind != eventKindMonClient || evs[0].From != "" || evs[0].To != store.MonClientOnline {
		t.Fatalf("events = %+v, want one mon_client \"\" → ONLINE", evs)
	}
	if evs[0].Notified {
		t.Fatalf("event notified = true, want the panel to send it (the panel is up)")
	}
	var targets []store.Target
	if err := f.st.DB.Find(&targets).Error; err != nil {
		t.Fatalf("read targets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want none until a result arrives", targets)
	}
}

// TestHeartbeat_NoConfigRevisionEchoesTheClients covers the "nothing built
// yet" answer: a mon-client must not be told to converge on "".
func TestHeartbeat_NoConfigRevisionEchoesTheClients(t *testing.T) {
	f := newFixture(t)
	f.cfg.revision = ""
	if got := f.beat().ConfigRevision; got != "rev-applied" {
		t.Fatalf("configRevision = %q, want the client's own when nothing is built", got)
	}
}

// TestHeartbeat_LiveCycleDrivesTheMachine is the end-to-end of §7.1 step 3
// plus §7.2: results move the target and the transition lands in the
// outbox with mon-server's receive time.
func TestHeartbeat_LiveCycleDrivesTheMachine(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("state = %s, want UP after the first success", got.State)
	}
	evs := f.events()
	last := evs[len(evs)-1]
	if last.Kind != eventKindTarget || last.To != store.TargetUp || last.Reason != ReasonRecovered {
		t.Fatalf("last event = %+v, want a target UNKNOWN → UP", last)
	}
	if last.InboundID == nil || *last.InboundID != 12 || last.Path != store.PathProxy || last.Ts != clock.Ms(f.clk.Now()) {
		t.Fatalf("event = %+v, want it to name the target and carry received_at", last)
	}

	seq := f.fail3(2, keyProxy, "tls_timeout")
	if got := f.targetState(keyProxy); got.State != store.TargetDown || got.Reason != "tls_timeout" {
		t.Fatalf("state = %s/%s, want DOWN/tls_timeout", got.State, got.Reason)
	}
	_ = seq
}

// TestHeartbeat_UnverifiedFailureIsNotCounted is the protocol §5.3 rule
// the issue calls out: an unverified cycle's failures say nothing about
// the tunnel, so they must never move the state machine — but the cycle
// still reaches statistics.
func TestHeartbeat_UnverifiedFailureIsNotCounted(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	for i := int64(0); i < 5; i++ {
		f.clk.Advance(time.Minute)
		c := f.cycle(2+i, result(keyProxy, false, "tcp_timeout"))
		c.Unverified = true
		f.beat(c)
	}

	got := f.targetState(keyProxy)
	if got.State != store.TargetUp || got.ConsecutiveFail != 0 {
		t.Fatalf("state = %s (fails %d), want UP untouched by unverified failures", got.State, got.ConsecutiveFail)
	}
	if len(f.sink.cycles) != 6 {
		t.Fatalf("stats got %d cycles, want all six (unverified included)", len(f.sink.cycles))
	}
}

// TestHeartbeat_ResentCycleDoesNotReplayState covers "переходы задним
// числом не переигрываются": a resend carrying failures arrives after the
// live cycle already said the target is up, and must not take it down.
func TestHeartbeat_ResentCycleDoesNotReplayState(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(10, result(keyProxy, true, "")))

	f.clk.Advance(time.Minute)
	// seq 11 is live; 12, 13 and 14 are older-looking resends carrying
	// failures. Only the highest non-unverified cycle counts, and one
	// success cannot be outvoted by resent failures.
	resend := func(seq int64) Cycle {
		c := f.cycle(seq, result(keyProxy, false, "tcp_refused"))
		c.Unverified = true
		return c
	}
	f.beat(f.cycle(11, result(keyProxy, true, "")), resend(12), resend(13), resend(14))

	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("state = %s, want UP: resent/unverified cycles must not replay state", got.State)
	}
}

// TestHeartbeat_AckSeqAndReplay covers the ackSeq contract: the response
// acknowledges the highest seq seen, it is persisted, and a repeat of an
// acknowledged cycle changes nothing.
func TestHeartbeat_AckSeqAndReplay(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)

	resp := f.beat(f.cycle(7, result(keyProxy, true, "")), f.cycle(8, result(keyProxy, true, "")))
	if resp.AckSeq != 8 {
		t.Fatalf("ackSeq = %d, want 8 (the highest seq seen)", resp.AckSeq)
	}
	if got := f.reload().LastAckSeq; got != 8 {
		t.Fatalf("last_ack_seq = %d, want it persisted as 8", got)
	}
	before := len(f.events())
	sinkBefore := len(f.sink.cycles)

	// The same cycles again (the mon-client never saw the answer).
	f.clk.Advance(time.Minute)
	resp = f.beat(f.cycle(7, result(keyProxy, false, "tcp_refused")), f.cycle(8, result(keyProxy, false, "tcp_refused")))
	if resp.AckSeq != 8 {
		t.Fatalf("ackSeq on a replay = %d, want 8 again", resp.AckSeq)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUp || got.ConsecutiveFail != 0 {
		t.Fatalf("state = %s (fails %d), want UP: acknowledged cycles must be ignored", got.State, got.ConsecutiveFail)
	}
	if len(f.events()) != before {
		t.Fatalf("replayed cycles produced %d new events, want none", len(f.events())-before)
	}
	if len(f.sink.cycles) != sinkBefore {
		t.Fatalf("replayed cycles reached statistics, want them dropped")
	}
}

// TestHeartbeat_ClampsSkewedTimestamps covers spec §7.1 step 1: a cycle
// whose own ts is more than five minutes from mon-server's receive time is
// filed under the receive time, and one inside the window is kept as sent.
func TestHeartbeat_ClampsSkewedTimestamps(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Hour)
	nowMs := clock.Ms(f.clk.Now())

	skewed := f.cycle(1, result(keyProxy, true, ""))
	skewed.Ts = nowMs + int64(6*time.Minute/time.Millisecond)
	behind := f.cycle(2, result(keyProxy, true, ""))
	behind.Ts = nowMs - int64(2*time.Minute/time.Millisecond)
	f.beat(skewed, behind)

	if len(f.sink.cycles) != 2 {
		t.Fatalf("stats got %d cycles, want 2", len(f.sink.cycles))
	}
	if f.sink.cycles[0].Ts != nowMs {
		t.Fatalf("skewed ts = %d, want it clamped to %d", f.sink.cycles[0].Ts, nowMs)
	}
	if f.sink.cycles[1].Ts != behind.Ts {
		t.Fatalf("in-window ts = %d, want it kept as %d", f.sink.cycles[1].Ts, behind.Ts)
	}
}

// TestHeartbeat_DropsResultsForUnknownTargets covers §7.1 step 3's last
// sentence: a result for a target that is not in this mon-client's config
// creates no row, no state and no statistics.
func TestHeartbeat_DropsResultsForUnknownTargets(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	stranger := registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0, Path: store.PathProxy}

	f.beat(f.cycle(1, result(keyProxy, true, ""), result(stranger, false, "awg_no_handshake")))

	var targets []store.Target
	if err := f.st.DB.Find(&targets).Error; err != nil {
		t.Fatalf("read targets: %v", err)
	}
	if len(targets) != 1 || targets[0].Path != store.PathProxy || targets[0].InboundKind != store.InboundKindXray {
		t.Fatalf("targets = %+v, want only the configured one", targets)
	}
	if got := f.sink.cycles[0].Results; len(got) != 1 {
		t.Fatalf("stats results = %+v, want the stranger dropped before the sink", got)
	}
}

// TestHeartbeat_ConfigErrorNotifiesAndClears covers spec §7.1 step 2 and
// §8: a configError is one of the few things mon-server tells Telegram
// itself, whatever the panel is doing, and clearing it leaves no trace on
// the row.
func TestHeartbeat_ConfigErrorNotifiesAndClears(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	boom := "cannot parse link\nstack trace"
	if _, err := f.e.Heartbeat(context.Background(), f.mc, &HeartbeatRequest{
		MonClientID: f.mc.Id, Client: ClientInfo{ConfigError: &boom},
	}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}

	mc := f.reload()
	if mc.ConfigError != boom || mc.ConfigErrorAt == nil {
		t.Fatalf("row = %+v, want the configError recorded", mc)
	}
	if len(f.tgr.Sent) != 1 || f.tgr.Sent[0] != tg.MsgConfigError("ams-1", boom) {
		t.Fatalf("telegram = %v, want exactly the configError message", f.tgr.Sent)
	}

	// The same error again must not notify twice.
	f.clk.Advance(time.Minute)
	if _, err := f.e.Heartbeat(context.Background(), f.mc, &HeartbeatRequest{
		MonClientID: f.mc.Id, Client: ClientInfo{ConfigError: &boom},
	}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if len(f.tgr.Sent) != 1 {
		t.Fatalf("telegram = %v, want no repeat for an unchanged configError", f.tgr.Sent)
	}

	// Gone.
	f.clk.Advance(time.Minute)
	f.beat()
	mc = f.reload()
	if mc.ConfigError != "" || mc.ConfigErrorAt != nil {
		t.Fatalf("row = %+v, want the configError cleared", mc)
	}
}

// TestHeartbeat_NeverIsNotSentToThePanel pins decision #50 item 1: a
// mon-client's first transition goes to the panel with an empty from. NEVER
// is mon-server's internal registry state (spec §3); the panel's dictionary
// for kind mon_client is ONLINE/OFFLINE, and a NEVER there made it reject
// the event (and, before per-element answers, the whole batch around it).
// A later OFFLINE → ONLINE keeps its from — only NEVER is hidden.
func TestHeartbeat_NeverIsNotSentToThePanel(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat()

	var rows []store.EventOutbox
	if err := f.st.DB.Find(&rows).Error; err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	for _, row := range rows {
		if strings.Contains(row.Payload, store.MonClientNever) {
			t.Fatalf("outbox payload %s carries NEVER to the panel", row.Payload)
		}
	}
	evs := f.events()
	if len(evs) != 1 || evs[0].From != "" || evs[0].To != store.MonClientOnline {
		t.Fatalf("events = %+v, want one mon_client with an empty from", evs)
	}

	if err := f.st.DB.Model(&store.MonClient{}).Where("id = ?", f.mc.Id).
		Update("state", store.MonClientOffline).Error; err != nil {
		t.Fatalf("mark offline: %v", err)
	}
	f.mc.State = store.MonClientOffline
	f.clk.Advance(time.Minute)
	f.beat()
	evs = f.events()
	if last := evs[len(evs)-1]; last.From != store.MonClientOffline || last.To != store.MonClientOnline {
		t.Fatalf("event = %+v, want OFFLINE → ONLINE kept as is", last)
	}
}

// TestHeartbeat_PanelDownSendsTransitionsItself covers spec §4.1: while
// the panel is unreachable mon-server sends the transition to Telegram and
// marks the event notified so the panel does not repeat it later.
func TestHeartbeat_PanelDownSendsTransitionsItself(t *testing.T) {
	f := newFixture(t)
	f.panelDown = true
	f.clk.Advance(time.Minute)

	f.beat(f.cycle(1, result(keyProxy, true, "")))

	evs := f.events()
	last := evs[len(evs)-1]
	if !last.Notified {
		t.Fatalf("event = %+v, want notified=true while PANEL_DOWN", last)
	}
	want := tg.MsgTargetTransition("ams-1", "NL", store.InboundKindXray, 12, store.PathProxy,
		store.TargetUnknown, store.TargetUp, ReasonRecovered)
	if len(f.tgr.Sent) != 2 || f.tgr.Sent[1] != want {
		// [0] is the mon_client NEVER → ONLINE message.
		t.Fatalf("telegram = %v, want the target transition as %q", f.tgr.Sent, want)
	}
}

// TestHeartbeat_PanelDownStaysSilentForUnknownTransitions is the other
// half of spec §7.2: UNKNOWN and PAUSED transitions never reach Telegram,
// even from mon-server itself.
func TestHeartbeat_PanelDownStaysSilentForUnknownTransitions(t *testing.T) {
	f := newFixture(t)
	f.panelDown = true
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	sentBefore := len(f.tgr.Sent)

	if err := f.e.MonClientDisabled(context.Background(), f.mc.Id); err != nil {
		t.Fatalf("MonClientDisabled: %v", err)
	}

	if got := f.targetState(keyProxy); got.State != store.TargetUnknown || got.Reason != ReasonMonClientDisabled {
		t.Fatalf("target = %s/%s, want UNKNOWN/mon_client_disabled", got.State, got.Reason)
	}
	if len(f.tgr.Sent) != sentBefore {
		t.Fatalf("telegram = %v, want nothing for a transition into UNKNOWN", f.tgr.Sent[sentBefore:])
	}
	evs := f.events()
	last := evs[len(evs)-1]
	if last.To != store.TargetUnknown || last.Reason != ReasonMonClientDisabled || last.Notified {
		t.Fatalf("event = %+v, want an un-notified UNKNOWN event", last)
	}
}

// TestMarkOffline covers spec §7.3 end to end: silence past
// clientOfflineAfter intervals turns the mon-client OFFLINE with reason
// heartbeat_missed and drops its targets to UNKNOWN without alerting on
// each one. mon-server has been ready since baseTime, before the heartbeat,
// so this is plain silence with no restart in it: the count runs from
// last_heartbeat exactly as it did before decision #84.
func TestMarkOffline(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	set, err := f.st.LoadSettings()
	if err != nil {
		t.Fatalf("LoadSettings: %v", err)
	}
	silence := time.Duration(int64(set.ClientOfflineAfter)*set.IntervalMs+set.HeartbeatTimeoutMs) * time.Millisecond

	// One millisecond short of the threshold: nothing happens yet.
	f.clk.Advance(silence)
	if err := f.e.MarkOffline(context.Background(), baseTime); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	if got := f.reload().State; got != store.MonClientOnline {
		t.Fatalf("state = %s, want still ONLINE exactly at the threshold", got)
	}

	f.clk.Advance(time.Millisecond)
	if err := f.e.MarkOffline(context.Background(), baseTime); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	mc := f.reload()
	if mc.State != store.MonClientOffline {
		t.Fatalf("state = %s, want OFFLINE", mc.State)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUnknown || got.Reason != ReasonMonClientOffline {
		t.Fatalf("target = %s/%s, want UNKNOWN/mon_client_offline", got.State, got.Reason)
	}

	evs := f.events()
	var monClientEv, targetEv *store.EventPayload
	for i := range evs {
		switch {
		case evs[i].Kind == eventKindMonClient && evs[i].To == store.MonClientOffline:
			monClientEv = &evs[i]
		case evs[i].Kind == eventKindTarget && evs[i].Reason == ReasonMonClientOffline:
			targetEv = &evs[i]
		}
	}
	if monClientEv == nil || monClientEv.Reason != ReasonHeartbeatMissed {
		t.Fatalf("events = %+v, want a mon_client OFFLINE with reason heartbeat_missed", evs)
	}
	if targetEv == nil || targetEv.From != store.TargetUp || targetEv.Notified {
		t.Fatalf("events = %+v, want an un-notified target UP → UNKNOWN", evs)
	}

	// A second sweep must not repeat itself.
	before := len(evs)
	f.clk.Advance(time.Hour)
	if err := f.e.MarkOffline(context.Background(), baseTime); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	if len(f.events()) != before {
		t.Fatalf("a second sweep produced %d more events, want none", len(f.events())-before)
	}

	// And the next heartbeat brings it back.
	f.clk.Advance(time.Minute)
	f.beat()
	if got := f.reload().State; got != store.MonClientOnline {
		t.Fatalf("state = %s, want ONLINE again after a heartbeat", got)
	}
}

// TestMarkOffline_NeverSeenClientIsLeftAlone pins spec §3's NEVER state: a
// box that has not come up for the first time is not an outage.
func TestMarkOffline_NeverSeenClientIsLeftAlone(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(24 * time.Hour)

	if err := f.e.MarkOffline(context.Background(), baseTime); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	if got := f.reload().State; got != store.MonClientNever {
		t.Fatalf("state = %s, want NEVER", got)
	}
	if evs := f.events(); len(evs) != 0 {
		t.Fatalf("events = %+v, want none", evs)
	}
}

// TestMarkOffline_PanelDownAnnouncesItself covers the mon_client half of
// spec §4.1.
func TestMarkOffline_PanelDownAnnouncesItself(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat()
	f.panelDown = true
	f.clk.Advance(time.Hour)

	if err := f.e.MarkOffline(context.Background(), baseTime); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	want := tg.MsgMonClientTransition("ams-1", "NL", store.MonClientOnline, store.MonClientOffline)
	if len(f.tgr.Sent) != 1 || f.tgr.Sent[0] != want {
		t.Fatalf("telegram = %v, want %q", f.tgr.Sent, want)
	}
	evs := f.events()
	if !evs[len(evs)-1].Notified {
		t.Fatalf("event = %+v, want notified=true", evs[len(evs)-1])
	}
}

// offlineSilence is spec §7.3's threshold under the fixture's settings:
// clientOfflineAfter whole intervals plus the heartbeat timeout.
func (f *fixture) offlineSilence() time.Duration {
	f.t.Helper()
	set, err := f.st.LoadSettings()
	if err != nil {
		f.t.Fatalf("LoadSettings: %v", err)
	}
	return time.Duration(int64(set.ClientOfflineAfter)*set.IntervalMs+set.HeartbeatTimeoutMs) * time.Millisecond
}

// sweep runs one pass of the 20 s liveness job for a mon-server that became
// ready at readyAt, and advances the clock to the next tick.
func (f *fixture) sweep(readyAt time.Time) {
	f.t.Helper()
	if err := f.e.MarkOffline(context.Background(), readyAt); err != nil {
		f.t.Fatalf("MarkOffline: %v", err)
	}
	f.clk.Advance(20 * time.Second)
}

// TestMarkOffline_RestartAfterDowntimeIsNotAnOutage is issue #89 (decision
// #84): mon-server itself was down for longer than clientOfflineAfter
// intervals, and the first sweeps after it comes back must not count its
// own downtime as the mon-client's silence. Before the fix the first sweep
// saw the stale last_heartbeat and filed ONLINE → OFFLINE, and the
// mon-client's next heartbeat filed OFFLINE → ONLINE a moment later.
func TestMarkOffline_RestartAfterDowntimeIsNotAnOutage(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	before := f.events()

	f.clk.Advance(f.offlineSilence() + time.Minute) // mon-server is down
	readyAt := f.clk.Now()

	// The mon-client's next heartbeat lands within one interval of the
	// listener coming back; the sweeps on either side of it stay quiet.
	for range 3 {
		f.sweep(readyAt)
	}
	f.beat(f.cycle(2, result(keyProxy, true, "")))
	for range 3 {
		f.sweep(readyAt)
	}

	if got := f.events(); len(got) != len(before) {
		t.Fatalf("events after the restart = %+v, want none", got[len(before):])
	}
	if got := f.reload().State; got != store.MonClientOnline {
		t.Fatalf("state = %s, want ONLINE throughout", got)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("target = %s/%s, want still UP", got.State, got.Reason)
	}
	if len(f.tgr.Sent) != 0 {
		t.Fatalf("telegram = %v, want nothing", f.tgr.Sent)
	}
}

// TestMarkOffline_ClientDeadDuringDowntime is the other half of decision
// #84 §1: a mon-client that really died while mon-server was down still goes
// OFFLINE, clientOfflineAfter intervals after serverReadyAt — the silence
// the running server saw itself — and not a moment earlier.
func TestMarkOffline_ClientDeadDuringDowntime(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	f.clk.Advance(f.offlineSilence() + time.Minute) // mon-server is down
	readyAt := f.clk.Now()

	f.clk.Advance(f.offlineSilence())
	if err := f.e.MarkOffline(context.Background(), readyAt); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	if got := f.reload().State; got != store.MonClientOnline {
		t.Fatalf("state = %s, want still ONLINE exactly at the threshold after serverReadyAt", got)
	}

	f.clk.Advance(time.Millisecond)
	if err := f.e.MarkOffline(context.Background(), readyAt); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	if got := f.reload().State; got != store.MonClientOffline {
		t.Fatalf("state = %s, want OFFLINE once the server itself has seen the whole silence", got)
	}
	evs := f.events()
	if last := evs[len(evs)-1]; last.Kind != eventKindTarget || last.Reason != ReasonMonClientOffline {
		t.Fatalf("last event = %+v, want the target's move to UNKNOWN", last)
	}
	var offline int
	for _, ev := range evs {
		if ev.Kind == eventKindMonClient && ev.To == store.MonClientOffline && ev.Reason == ReasonHeartbeatMissed {
			offline++
		}
	}
	if offline != 1 {
		t.Fatalf("events = %+v, want exactly one mon_client OFFLINE heartbeat_missed", evs)
	}
}

// TestServerReady_LogsTheFreshestHeartbeat pins decision #84 §3: mon-server
// reports its own downtime only as one log line at start, measured from the
// most recent last_heartbeat of any mon-client, and says nothing when no
// mon-client has ever heartbeated.
func TestServerReady_LogsTheFreshestHeartbeat(t *testing.T) {
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	f := newFixture(t)
	if got := f.e.ServerReady(context.Background()); !got.Equal(f.clk.Now()) {
		t.Fatalf("ServerReady = %v, want the clock's now %v", got, f.clk.Now())
	}
	if strings.Contains(logs.String(), "last heartbeat seen") {
		t.Fatalf("logs = %q, want no heartbeat line before any mon-client heartbeated", logs.String())
	}

	older := clock.Ms(baseTime)
	other := &store.MonClient{
		Id: "msk-1", Name: "msk-1", Region: "RU", Enabled: true,
		State: store.MonClientOffline, ApprovedAt: older, LastHeartbeat: &older,
	}
	if err := f.st.DB.Create(other).Error; err != nil {
		t.Fatalf("create mon-client: %v", err)
	}
	f.clk.Advance(time.Minute)
	f.beat()
	f.clk.Advance(4*time.Minute + 2*time.Second)

	logs.Reset()
	f.e.ServerReady(context.Background())
	if want := "started; last heartbeat seen 4m2s ago"; !strings.Contains(logs.String(), want) {
		t.Fatalf("logs = %q, want %q", logs.String(), want)
	}
}

// saveInbound seeds panel_inbounds the way the poller's savePanelInbounds
// would.
func (f *fixture) saveInbound(kind string, id int, enable bool) {
	f.t.Helper()
	row := store.PanelInbound{InboundKind: kind, InboundId: id, Protocol: "vless", Enable: enable, SeenRevision: "r1"}
	if err := f.st.DB.Create(&row).Error; err != nil {
		f.t.Fatalf("create panel inbound: %v", err)
	}
}

// TestSyncInbounds_DisabledPausesAndEnabledResumes covers spec §4 step 3's
// first case: an inbound the panel disabled parks its targets in PAUSED,
// results for them are ignored, and enabling it again releases them to
// UNKNOWN.
func TestSyncInbounds_DisabledPausesAndEnabledResumes(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	f.saveInbound(store.InboundKindXray, 12, true)

	ctx := context.Background()
	disabled := []panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Enable: false}}
	if err := f.e.SyncInbounds(ctx, disabled); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	got := f.targetState(keyProxy)
	if got.State != store.TargetPaused || got.Reason != ReasonConfigDisabled {
		t.Fatalf("target = %s/%s, want PAUSED/config_disabled", got.State, got.Reason)
	}

	// A result for a paused target must change nothing.
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2, result(keyProxy, false, "tcp_refused")))
	if got := f.targetState(keyProxy); got.State != store.TargetPaused {
		t.Fatalf("target = %s, want it still PAUSED", got.State)
	}

	// Pausing twice must not re-file the event.
	before := len(f.events())
	if err := f.e.SyncInbounds(ctx, disabled); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	if len(f.events()) != before {
		t.Fatalf("a repeated sync produced %d more events, want none", len(f.events())-before)
	}

	if err := f.e.SyncInbounds(ctx, []panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Enable: true}}); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	got = f.targetState(keyProxy)
	if got.State != store.TargetUnknown || got.Reason != ReasonConfigEnabled {
		t.Fatalf("target = %s/%s, want UNKNOWN/config_enabled", got.State, got.Reason)
	}
}

// TestSyncInbounds_VanishedInboundRetiresOnTheNextHeartbeat covers the
// other case of spec §4 step 3: an inbound that stopped being offered
// pauses its targets and their rows are deleted once a heartbeat arrives
// for a config that no longer names them.
func TestSyncInbounds_VanishedInboundRetiresOnTheNextHeartbeat(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, ""), result(keyDirect, true, "")))
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)

	ctx := context.Background()
	if err := f.e.SyncInbounds(ctx, []panel.Inbound{{Kind: store.InboundKindAwg, InboundId: 0, Enable: true}}); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetPaused {
		t.Fatalf("target = %s, want PAUSED after its inbound vanished", got.State)
	}
	var inbounds []store.PanelInbound
	if err := f.st.DB.Find(&inbounds).Error; err != nil {
		t.Fatalf("read panel_inbounds: %v", err)
	}
	if len(inbounds) != 1 || inbounds[0].InboundKind != store.InboundKindAwg {
		t.Fatalf("panel_inbounds = %+v, want the vanished one forgotten", inbounds)
	}

	// The config no longer names those targets either; the next heartbeat
	// confirms the retirement.
	f.cfg.keys = nil
	f.clk.Advance(time.Minute)
	f.beat()

	var targets []store.Target
	if err := f.st.DB.Find(&targets).Error; err != nil {
		t.Fatalf("read targets: %v", err)
	}
	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want them retired", targets)
	}
}

// TestSyncInbounds_EmptyListIsIgnored pins the guard that keeps this in
// step with the poller's own savePanelInbounds: a contract response with
// no inbounds must not retire the whole install.
func TestSyncInbounds_EmptyListIsIgnored(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	f.saveInbound(store.InboundKindXray, 12, true)

	if err := f.e.SyncInbounds(context.Background(), nil); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("target = %s, want UP: an empty inbound list says nothing", got.State)
	}
}

// TestHeartbeat_FailedWriteRollsBackTheWholeBeat is the transaction
// guarantee: answering with ackSeq tells the mon-client it may drop those
// cycles forever, so nothing about a heartbeat may be half-applied. The
// stats sink is the last write in the beat; when it fails, the ack, the
// target the live cycle moved and the events it filed must all be gone, or
// the resend would be discarded as a duplicate and the transition lost with
// nothing left to replay it from.
func TestHeartbeat_FailedWriteRollsBackTheWholeBeat(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	ackBefore := f.reload().LastAckSeq
	eventsBefore := len(f.events())
	stateBefore := f.targetState(keyProxy)

	f.sink.err = errors.New("disk full")
	for i := int64(0); i < 3; i++ {
		f.clk.Advance(time.Minute)
		if err := f.beatErr(f.cycle(2+i, result(keyProxy, false, "tls_timeout"))); err == nil {
			t.Fatal("Heartbeat succeeded with a failing stats sink, want the beat rolled back")
		}
	}

	if got := f.reload().LastAckSeq; got != ackBefore {
		t.Fatalf("last_ack_seq = %d, want it unchanged at %d: a failed beat must not acknowledge", got, ackBefore)
	}
	got := f.targetState(keyProxy)
	if got.State != stateBefore.State || got.ConsecutiveFail != stateBefore.ConsecutiveFail {
		t.Fatalf("target = %s (fails %d), want it untouched at %s (fails %d)",
			got.State, got.ConsecutiveFail, stateBefore.State, stateBefore.ConsecutiveFail)
	}
	if n := len(f.events()); n != eventsBefore {
		t.Fatalf("outbox grew by %d events, want none from a rolled-back beat", n-eventsBefore)
	}

	// And with the sink healthy again, the mon-client's resend of exactly
	// those cycles is applied as if the failure had never happened.
	f.sink.err = nil
	for i := int64(0); i < 3; i++ {
		f.clk.Advance(time.Minute)
		f.beat(f.cycle(2+i, result(keyProxy, false, "tls_timeout")))
	}
	if got := f.targetState(keyProxy); got.State != store.TargetDown {
		t.Fatalf("target = %s after the resend, want DOWN: nothing may have been lost", got.State)
	}
	if got := f.reload().LastAckSeq; got != 4 {
		t.Fatalf("last_ack_seq = %d, want 4 once the resend committed", got)
	}
}

// TestHeartbeat_StatsSinkJoinsTheTransaction pins the StatsSink seam step 7
// implements: the sink is handed the beat's own transaction, not the
// store's handle, so its buckets commit with the ack that lets the
// mon-client forget the cycles they were built from.
func TestHeartbeat_StatsSinkJoinsTheTransaction(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	if f.sink.tx == nil {
		t.Fatal("stats sink got a nil handle, want the heartbeat's transaction")
	}
	if f.sink.tx == f.st.DB {
		t.Fatal("stats sink got Store.DB, want the heartbeat's transaction")
	}
}

// TestHeartbeat_PanelDownRecoveryCarriesTheDowntime covers spec §7.2's "UP"
// row: a DOWN → UP transition announced by mon-server itself must say how
// long the target was down, and only that transition uses the recovery
// wording.
func TestHeartbeat_PanelDownRecoveryCarriesTheDowntime(t *testing.T) {
	f := newFixture(t)
	f.panelDown = true
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	// Three failures, one minute apart, take it DOWN at minute 4.
	seq := f.fail3(2, keyProxy, "tls_timeout")
	downAt := f.clk.Now()
	if got := f.targetState(keyProxy); got.State != store.TargetDown {
		t.Fatalf("target = %s, want DOWN", got.State)
	}
	wantDown := tg.MsgTargetTransition("ams-1", "NL", store.InboundKindXray, 12, store.PathProxy,
		store.TargetUp, store.TargetDown, "tls_timeout")
	if last := f.tgr.Sent[len(f.tgr.Sent)-1]; last != wantDown {
		t.Fatalf("telegram = %q, want the DOWN message %q", last, wantDown)
	}

	// Two successes bring it back up; the second one is the transition.
	for i := 0; i < 2; i++ {
		f.clk.Advance(90 * time.Second)
		f.beat(f.cycle(seq, result(keyProxy, true, "")))
		seq++
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("target = %s, want UP again", got.State)
	}

	want := tg.MsgTargetRecovered("ams-1", "NL", store.InboundKindXray, 12, store.PathProxy,
		f.clk.Now().Sub(downAt))
	last := f.tgr.Sent[len(f.tgr.Sent)-1]
	if last != want {
		t.Fatalf("telegram = %q, want the recovery message %q", last, want)
	}
	if !strings.Contains(last, "DOWN → UP after 3m0s") {
		t.Fatalf("telegram = %q, want it to carry the three-minute downtime", last)
	}

	evs := f.events()
	up := evs[len(evs)-1]
	if up.From != store.TargetDown || up.To != store.TargetUp || !up.Notified {
		t.Fatalf("event = %+v, want a notified DOWN → UP", up)
	}
}

// TestHeartbeat_TelegramIsSentOnlyAfterTheCommit pins the ordering the
// transaction forces: a beat that rolls back must not have announced
// anything, however far into the state machine it got.
func TestHeartbeat_TelegramIsSentOnlyAfterTheCommit(t *testing.T) {
	f := newFixture(t)
	f.panelDown = true
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	sentBefore := len(f.tgr.Sent)

	f.sink.err = errors.New("disk full")
	for i := int64(0); i < 3; i++ {
		f.clk.Advance(time.Minute)
		if err := f.beatErr(f.cycle(2+i, result(keyProxy, false, "tls_timeout"))); err == nil {
			t.Fatal("Heartbeat succeeded with a failing stats sink, want the beat rolled back")
		}
	}

	if len(f.tgr.Sent) != sentBefore {
		t.Fatalf("telegram = %v, want nothing from rolled-back beats", f.tgr.Sent[sentBefore:])
	}
}

// TestHeartbeat_FailedTelegramLeavesTheEventForThePanel covers the other
// half of deferring the send: the outbox row is written notified=true
// before the message is attempted, so a send that fails has to put it back
// — otherwise the panel would stay silent about a transition nobody
// announced (contract §4.6).
func TestHeartbeat_FailedTelegramLeavesTheEventForThePanel(t *testing.T) {
	f := newFixture(t)
	f.panelDown = true
	f.tgn.err = errors.New("bot token revoked")
	f.clk.Advance(time.Minute)

	f.beat(f.cycle(1, result(keyProxy, true, "")))

	for _, ev := range f.events() {
		if ev.Notified {
			t.Fatalf("event = %+v, want notified=false after the send failed", ev)
		}
	}
	var rows []store.EventOutbox
	if err := f.st.DB.Find(&rows).Error; err != nil {
		t.Fatalf("read outbox: %v", err)
	}
	for _, r := range rows {
		if r.Notified {
			t.Fatalf("outbox row %s = notified, want the column cleared too", r.Id)
		}
	}
}

// revokeVia wires a real registry over the fixture's store with the engine
// as its Revoked hook — the production seam — and revokes the fixture's
// mon-client through it.
func (f *fixture) revokeVia() *registry.Registry {
	f.t.Helper()
	r := registry.New(f.st, f.clk)
	r.SetHooks(registry.Hooks{Revoked: f.e.MonClientRevoked})
	if err := r.Revoke(context.Background(), f.mc.Id); err != nil {
		f.t.Fatalf("Revoke: %v", err)
	}
	return r
}

// TestRevoke_GoesThroughTheStateMachine is decision #51 §2: a revoke is an
// OFFLINE like the timeout's — a mon_client event with reason
// token_revoked, the targets to UNKNOWN with mon_client_revoked, Telegram
// by the same PANEL_DOWN rule — not a silent flip of the registry row.
func TestRevoke_GoesThroughTheStateMachine(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	f.panelDown = true

	f.revokeVia()

	if got := f.reload().State; got != store.MonClientOffline {
		t.Fatalf("state = %s, want OFFLINE", got)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUnknown || got.Reason != ReasonMonClientRevoked {
		t.Fatalf("target = %s/%s, want UNKNOWN/mon_client_revoked", got.State, got.Reason)
	}
	var monClientEv, targetEv *store.EventPayload
	evs := f.events()
	for i := range evs {
		switch {
		case evs[i].Kind == eventKindMonClient && evs[i].To == store.MonClientOffline:
			monClientEv = &evs[i]
		case evs[i].Kind == eventKindTarget && evs[i].Reason == ReasonMonClientRevoked:
			targetEv = &evs[i]
		}
	}
	if monClientEv == nil || monClientEv.From != store.MonClientOnline || monClientEv.Reason != ReasonTokenRevoked || !monClientEv.Notified {
		t.Fatalf("events = %+v, want a notified mon_client ONLINE → OFFLINE with reason token_revoked", evs)
	}
	if targetEv == nil || targetEv.From != store.TargetUp || targetEv.To != store.TargetUnknown {
		t.Fatalf("events = %+v, want a target UP → UNKNOWN with reason mon_client_revoked", evs)
	}
	want := tg.MsgMonClientTransition("ams-1", "NL", store.MonClientOnline, store.MonClientOffline)
	if len(f.tgr.Sent) != 1 || f.tgr.Sent[0] != want {
		t.Fatalf("telegram = %v, want %q", f.tgr.Sent, want)
	}
}

// TestRevoke_NeverSeenGoesOutWithEmptyFrom: a mon-client revoked before its
// first heartbeat still changes state (NEVER → OFFLINE), and NEVER stays
// internal (decision #50 §1).
func TestRevoke_NeverSeenGoesOutWithEmptyFrom(t *testing.T) {
	f := newFixture(t)
	f.revokeVia()

	evs := f.events()
	if len(evs) != 1 || evs[0].Kind != eventKindMonClient || evs[0].From != "" ||
		evs[0].To != store.MonClientOffline || evs[0].Reason != ReasonTokenRevoked {
		t.Fatalf("events = %+v, want one mon_client \"\" → OFFLINE token_revoked", evs)
	}
}

// TestRevoke_AlreadyOfflineFilesNoTransition: the timeout already said
// OFFLINE and moved the targets; a revoke on top is not a second transition.
func TestRevoke_AlreadyOfflineFilesNoTransition(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	f.clk.Advance(time.Hour)
	if err := f.e.MarkOffline(context.Background(), baseTime); err != nil {
		t.Fatalf("MarkOffline: %v", err)
	}
	before := len(f.events())

	f.revokeVia()

	if got := len(f.events()); got != before {
		t.Fatalf("revoking an OFFLINE mon-client filed %d events, want none", got-before)
	}
}

// TestHeartbeat_ReplacementAfterRevokeAcceptsSeqOne is the bug of decision
// #51 §1: after Revoke and Approve as replacement the new box counts from
// seq 1, and mon-server must take that cycle rather than drop it as a
// duplicate of the old box's seqs.
func TestHeartbeat_ReplacementAfterRevokeAcceptsSeqOne(t *testing.T) {
	f := newFixture(t)
	for seq := int64(1); seq <= 5; seq++ {
		f.clk.Advance(time.Minute)
		f.beat(f.cycle(seq, result(keyProxy, true, "")))
	}
	if got := f.reload().LastAckSeq; got != 5 {
		t.Fatalf("last_ack_seq = %d, want 5", got)
	}

	r := f.revokeVia()
	f.clk.Advance(time.Hour)
	out, err := r.Register(context.Background(), registry.RegisterInput{PairingCode: "ABCDEF", Hostname: "ams-1", RemoteIP: "198.51.100.7"})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := r.ApproveAsReplacement(context.Background(), out.RequestID, f.mc.Id); err != nil {
		t.Fatalf("ApproveAsReplacement: %v", err)
	}

	f.clk.Advance(time.Minute)
	resp := f.beat(f.cycle(1, result(keyProxy, true, "")))
	if resp.AckSeq != 1 {
		t.Fatalf("ackSeq = %d, want 1", resp.AckSeq)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("target = %s, want UP: seq 1 of the new token must reach the state machine", got.State)
	}
}

// excluding describes a panel without a chain (it serves direct and
// proxy) where inbound xray:12 is enabled, with the given override and the
// paths the mon-client probes.
func excluding(override bool, paths ...string) registry.Exclusions {
	x := registry.Exclusions{
		Known:    true,
		Served:   map[string]bool{store.PathDirect: true, store.PathProxy: true},
		Paths:    map[string]bool{},
		Override: override,
		Inbounds: map[registry.TargetKey]bool{{InboundKind: store.InboundKindXray, InboundID: 12}: true},
	}
	for _, p := range paths {
		x.Paths[p] = true
	}
	return x
}

// TestHeartbeat_TargetOutsideConfigIsPausedWithReason is decision #51 §3:
// a target that falls out of the mon-client's config for a reason other
// than its inbound goes PAUSED with that reason (the row is kept), and
// coming back into the config releases it to UNKNOWN, after which the first
// result decides.
func TestHeartbeat_TargetOutsideConfigIsPausedWithReason(t *testing.T) {
	cases := []struct {
		name string
		excl registry.Exclusions
		want string
	}{
		{"override switched off", excluding(false, store.PathProxy, store.PathDirect), ReasonOverrideDisabled},
		{"path removed", excluding(true, store.PathDirect), ReasonPathRemoved},
		{"no probe link", excluding(true, store.PathProxy, store.PathDirect), ReasonNoProbeLink},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.saveInbound(store.InboundKindXray, 12, true)
			f.clk.Advance(time.Minute)
			f.beat(f.cycle(1, result(keyProxy, true, ""), result(keyDirect, true, "")))

			f.cfg.keys = []registry.TargetKey{keyDirect}
			f.cfg.excl = tc.excl
			f.clk.Advance(time.Minute)
			f.beat(f.cycle(2, result(keyProxy, true, ""), result(keyDirect, true, "")))

			got := f.targetState(keyProxy)
			if got.State != store.TargetPaused || got.Reason != tc.want {
				t.Fatalf("target = %s/%s, want PAUSED/%s", got.State, got.Reason, tc.want)
			}
			evs := f.events()
			last := evs[len(evs)-1]
			if last.Kind != eventKindTarget || last.Path != store.PathProxy || last.From != store.TargetUp ||
				last.To != store.TargetPaused || last.Reason != tc.want || last.Notified {
				t.Fatalf("last event = %+v, want an un-notified UP → PAUSED %s", last, tc.want)
			}
			if got := f.targetState(keyDirect); got.State != store.TargetUp {
				t.Fatalf("direct target = %s, want it untouched (UP)", got.State)
			}

			// Staying out of the config files nothing more.
			before := len(evs)
			f.clk.Advance(time.Minute)
			f.beat(f.cycle(3))
			if len(f.events()) != before {
				t.Fatalf("a second heartbeat filed %d more events, want none", len(f.events())-before)
			}

			// Back in the config: UNKNOWN, then the first result.
			f.cfg.keys = []registry.TargetKey{keyProxy, keyDirect}
			f.cfg.excl = excluding(true, store.PathProxy, store.PathDirect)
			f.clk.Advance(time.Minute)
			f.beat(f.cycle(4))
			if got := f.targetState(keyProxy); got.State != store.TargetUnknown || got.Reason != ReasonConfigEnabled {
				t.Fatalf("target = %s/%s, want UNKNOWN/config_enabled once back in the config", got.State, got.Reason)
			}
			f.clk.Advance(time.Minute)
			f.beat(f.cycle(5, result(keyProxy, true, "")))
			if got := f.targetState(keyProxy); got.State != store.TargetUp {
				t.Fatalf("target = %s, want UP after the first result", got.State)
			}
		})
	}
}

// TestHeartbeat_InboundExclusionIsLeftToSyncInbounds: a target whose
// inbound is disabled or gone is not a config pause — SyncInbounds pauses
// it with config_disabled — so the heartbeat leaves it alone.
func TestHeartbeat_InboundExclusionIsLeftToSyncInbounds(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))

	f.cfg.keys = []registry.TargetKey{keyDirect}
	f.cfg.excl = excluding(true, store.PathProxy, store.PathDirect)
	f.cfg.excl.Inbounds = map[registry.TargetKey]bool{{InboundKind: store.InboundKindXray, InboundID: 12}: false}
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2))

	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("target = %s/%s, want it left UP for SyncInbounds", got.State, got.Reason)
	}
}

// TestSyncInbounds_EnableDoesNotReleaseConfigPauses: an inbound coming back
// releases what *it* paused (config_disabled), not a target paused because
// its path was taken off the mon-client.
func TestSyncInbounds_EnableDoesNotReleaseConfigPauses(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, "")))
	f.saveInbound(store.InboundKindXray, 12, true)

	f.cfg.keys = []registry.TargetKey{keyDirect}
	f.cfg.excl = excluding(true, store.PathDirect)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2))

	ctx := context.Background()
	if err := f.e.SyncInbounds(ctx, []panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Enable: false}}); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	if err := f.e.SyncInbounds(ctx, []panel.Inbound{{Kind: store.InboundKindXray, InboundId: 12, Enable: true}}); err != nil {
		t.Fatalf("SyncInbounds: %v", err)
	}
	if got := f.targetState(keyProxy); got.State != store.TargetPaused || got.Reason != ReasonPathRemoved {
		t.Fatalf("target = %s/%s, want still PAUSED/path_removed", got.State, got.Reason)
	}
}

// beatRejecting sends one heartbeat whose client block reports rejected as
// client.rejectedTargets (protocol §5.3), target → error.
func (f *fixture) beatRejecting(rejected map[registry.TargetKey]string, cycles ...Cycle) {
	f.t.Helper()
	info := ClientInfo{Version: "0.1.0", XrayVersion: "26.3.27"}
	for k, e := range rejected {
		info.RejectedTargets = append(info.RejectedTargets, RejectedTarget{
			Target: fmt.Sprintf("%s:%d:%s", k.InboundKind, k.InboundID, k.Path), Error: e,
		})
	}
	if _, err := f.e.Heartbeat(context.Background(), f.mc, &HeartbeatRequest{
		MonClientID:    f.mc.Id,
		ConfigRevision: "rev-applied",
		Client:         info,
		Cycles:         cycles,
	}); err != nil {
		f.t.Fatalf("Heartbeat: %v", err)
	}
}

// TestHeartbeat_RejectedTargetIsPausedWithConfigError is decision #53 п. 3
// on mon-server's side: a target the mon-client reports in rejectedTargets
// goes PAUSED with reason config_error — a panel event, never Telegram, even
// while PANEL_DOWN — and the error is kept on the mon-client row for the
// admin UI. Dropping out of rejectedTargets releases it to UNKNOWN
// (config_enabled), and the next result decides.
func TestHeartbeat_RejectedTargetIsPausedWithConfigError(t *testing.T) {
	f := newFixture(t)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, ""), result(keyDirect, true, "")))

	f.panelDown = true
	sentBefore := len(f.tgr.Sent)
	f.clk.Advance(time.Minute)
	f.beatRejecting(map[registry.TargetKey]string{keyProxy: `unsupported transport "kcp"`},
		f.cycle(2, result(keyDirect, true, "")))

	if got := f.targetState(keyProxy); got.State != store.TargetPaused || got.Reason != ReasonConfigError {
		t.Fatalf("target = %s/%s, want PAUSED/config_error", got.State, got.Reason)
	}
	evs := f.events()
	last := evs[len(evs)-1]
	if last.Kind != eventKindTarget || last.Path != store.PathProxy || last.From != store.TargetUp ||
		last.To != store.TargetPaused || last.Reason != ReasonConfigError || last.Notified {
		t.Fatalf("last event = %+v, want an un-notified UP → PAUSED config_error", last)
	}
	if len(f.tgr.Sent) != sentBefore {
		t.Fatalf("Telegram got %q, want nothing for a config_error pause", f.tgr.Sent[sentBefore:])
	}
	if got := f.targetState(keyDirect); got.State != store.TargetUp {
		t.Fatalf("direct target = %s, want it untouched (UP)", got.State)
	}
	mc := f.reload()
	if r := mc.RejectedList(); len(r) != 1 || r[0].Target != "xray:12:proxy" || r[0].Error != `unsupported transport "kcp"` {
		t.Fatalf("mon-client rejected targets = %+v, want the reported one", r)
	}

	// Still rejected: nothing more is filed.
	before := len(f.events())
	f.clk.Advance(time.Minute)
	f.beatRejecting(map[registry.TargetKey]string{keyProxy: `unsupported transport "kcp"`}, f.cycle(3))
	if len(f.events()) != before {
		t.Fatalf("a second heartbeat filed %d more events, want none", len(f.events())-before)
	}

	// No longer rejected: UNKNOWN, then the first result.
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(4))
	if got := f.targetState(keyProxy); got.State != store.TargetUnknown || got.Reason != ReasonConfigEnabled {
		t.Fatalf("target = %s/%s, want UNKNOWN/config_enabled once no longer rejected", got.State, got.Reason)
	}
	if mc := f.reload(); len(mc.RejectedList()) != 0 {
		r := mc.RejectedList()
		t.Fatalf("mon-client rejected targets = %+v, want them cleared", r)
	}
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(5, result(keyProxy, true, "")))
	if got := f.targetState(keyProxy); got.State != store.TargetUp {
		t.Fatalf("target = %s, want UP after the first result", got.State)
	}
}

// TestHeartbeat_RejectedNewTargetGetsARow: a target rejected before it
// ever produced a result has no row yet; it gets one (UNKNOWN, the usual
// start of a new target) and goes PAUSED at once, so the panel learns about
// it. A rejected key that is not in the mon-client's config, or one that is
// not a target key at all, creates nothing.
func TestHeartbeat_RejectedNewTargetGetsARow(t *testing.T) {
	f := newFixture(t)
	stranger := registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 7, Path: store.PathProxy}
	f.clk.Advance(time.Minute)
	f.beatRejecting(map[registry.TargetKey]string{keyProxy: "bad", stranger: "bad", {InboundKind: "nonsense"}: "bad"})

	if got := f.targetState(keyProxy); got.State != store.TargetPaused || got.Reason != ReasonConfigError {
		t.Fatalf("target = %s/%s, want PAUSED/config_error", got.State, got.Reason)
	}
	var n int64
	if err := f.st.DB.Model(&store.Target{}).Where("mon_client_id = ?", f.mc.Id).Count(&n).Error; err != nil {
		t.Fatalf("count targets: %v", err)
	}
	if n != 1 {
		t.Fatalf("%d target rows, want only the rejected target of the config", n)
	}
	var paused []store.EventPayload
	for _, ev := range f.events() {
		if ev.Kind == eventKindTarget {
			paused = append(paused, ev)
		}
	}
	if len(paused) != 1 || paused[0].From != store.TargetUnknown || paused[0].To != store.TargetPaused {
		t.Fatalf("target events = %+v, want one UNKNOWN → PAUSED", paused)
	}
}

// awgExclusions is excluding with the AWG server (awg:0) enabled as well.
func awgExclusions(override bool, paths ...string) registry.Exclusions {
	x := excluding(override, paths...)
	x.Inbounds[registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0}] = true
	return x
}

// TestHeartbeat_MissingAwgProbePeerIsPausedNoProbeLink is decision #80
// п. 10: the panel gave this mon-client no AWG probe peer on a path (its
// address pool is exhausted, or ensure has not reached it yet), so the AWG
// target is missing from the config and has never produced a result. It
// still gets a row, PAUSED no_probe_link, so the operator sees it; once the
// item appears the target is released like any config pause.
func TestHeartbeat_MissingAwgProbePeerIsPausedNoProbeLink(t *testing.T) {
	awgProxy := registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0, Path: store.PathProxy}
	awgDirect := registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0, Path: store.PathDirect}

	f := newFixture(t)
	// panel_inbounds is where the real builder's Exclusions come from, and
	// what keeps a PAUSED row from being retired as "inbound gone".
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)
	f.cfg.keys = []registry.TargetKey{keyProxy, keyDirect, awgDirect}
	f.cfg.excl = awgExclusions(true, store.PathProxy, store.PathDirect)
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, ""), result(keyDirect, true, ""), result(awgDirect, true, "")))

	if got := f.targetState(awgProxy); got.State != store.TargetPaused || got.Reason != ReasonNoProbeLink {
		t.Fatalf("awg proxy target = %s/%s, want PAUSED/no_probe_link", got.State, got.Reason)
	}
	if got := f.targetState(awgDirect); got.State != store.TargetUp {
		t.Fatalf("awg direct target = %s, want UP: it has its own item", got.State)
	}
	var paused []store.EventPayload
	for _, ev := range f.events() {
		if ev.Kind == eventKindTarget && ev.To == store.TargetPaused {
			paused = append(paused, ev)
		}
	}
	if len(paused) != 1 || paused[0].InboundKind != store.InboundKindAwg || paused[0].Path != store.PathProxy ||
		paused[0].From != store.TargetUnknown || paused[0].Reason != ReasonNoProbeLink || paused[0].Notified {
		t.Fatalf("pause events = %+v, want one un-notified UNKNOWN → PAUSED no_probe_link for awg:0 proxy", paused)
	}

	// Still missing: nothing more is filed.
	before := len(f.events())
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2))
	if evs := f.events(); len(evs) != before {
		t.Fatalf("a second heartbeat filed %d more events, want none: %+v", len(evs)-before, evs[before:])
	}

	// The panel allocates the peer: the item appears, the target is
	// released, and its first result decides.
	f.cfg.keys = []registry.TargetKey{keyProxy, keyDirect, awgProxy, awgDirect}
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(3))
	if got := f.targetState(awgProxy); got.State != store.TargetUnknown || got.Reason != ReasonConfigEnabled {
		t.Fatalf("awg proxy target = %s/%s, want UNKNOWN/config_enabled once its item appears", got.State, got.Reason)
	}
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(4, result(awgProxy, true, "")))
	if got := f.targetState(awgProxy); got.State != store.TargetUp {
		t.Fatalf("awg proxy target = %s, want UP after the first result", got.State)
	}
}

// TestHeartbeat_MissingAwgRowOnlyWhereAPeerIsOwed: no row is invented for
// an AWG target the mon-client is not owed — the AWG server disabled (that
// is SyncInbounds' config_disabled), the proxy path while the override is
// off, a path the mon-client does not probe — nor before anything is known
// about the panel.
func TestHeartbeat_MissingAwgRowOnlyWhereAPeerIsOwed(t *testing.T) {
	disabled := awgExclusions(true, store.PathProxy, store.PathDirect)
	disabled.Inbounds[registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0}] = false

	cases := []struct {
		name string
		excl registry.Exclusions
	}{
		{"awg server disabled", disabled},
		{"override off, proxy only", awgExclusions(false, store.PathProxy)},
		{"nothing known yet", registry.Exclusions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.cfg.keys = []registry.TargetKey{keyProxy, keyDirect}
			f.cfg.excl = tc.excl
			f.clk.Advance(time.Minute)
			f.beat(f.cycle(1))

			var n int64
			if err := f.st.DB.Model(&store.Target{}).
				Where("mon_client_id = ? AND inbound_kind = ?", f.mc.Id, store.InboundKindAwg).
				Count(&n).Error; err != nil {
				t.Fatalf("count targets: %v", err)
			}
			if n != 0 {
				t.Fatalf("%d awg target rows, want none", n)
			}
		})
	}
}

// --- Paths by chain (spec §5.1, decision #61) ---

var (
	keyEdgeA = registry.TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: "edge:edge-a"}
	keyEdgeB = registry.TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: "edge:edge-b"}
	keyInner = registry.TargetKey{InboundKind: store.InboundKindXray, InboundID: 12, Path: "inner:core-1"}
)

// chained describes a chained panel serving direct and the given hop
// paths, where inbounds xray:12 and awg:0 are enabled and the mon-client
// probes probed (spec §5.1).
func chained(served []string, probed ...string) registry.Exclusions {
	x := awgExclusions(true, probed...)
	x.Served = map[string]bool{store.PathDirect: true}
	for _, p := range served {
		x.Served[p] = true
	}
	return x
}

// targetGone fails unless key has no row.
func (f *fixture) targetGone(key registry.TargetKey) {
	f.t.Helper()
	var n int64
	f.st.DB.Model(&store.Target{}).Where("mon_client_id = ? AND inbound_kind = ? AND inbound_id = ? AND path = ?",
		f.mc.Id, key.InboundKind, key.InboundID, key.Path).Count(&n)
	if n != 0 {
		f.t.Fatalf("target %+v still has a row, want it removed", key)
	}
}

// TestSyncPaths_RemovesTargetsSilently is decision #61 п. 6, 9: the
// targets of a path the panel no longer serves — a hop that was removed,
// renamed or left joined/legacy, or proxy once a hop is probed — are
// deleted for every mon-client, whatever their state, without an event;
// served paths are untouched.
func TestSyncPaths_RemovesTargetsSilently(t *testing.T) {
	f := newFixture(t)
	f.cfg.keys = []registry.TargetKey{keyProxy, keyDirect, keyEdgeA, keyEdgeB}
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, ""), result(keyDirect, true, ""), result(keyEdgeA, true, ""), result(keyEdgeB, false, "tcp_timeout")))
	other := store.Target{MonClientId: "fra-1", InboundKind: store.InboundKindXray, InboundId: 12, Path: "edge:edge-b", State: store.TargetPaused}
	if err := f.st.DB.Create(&other).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	before := len(f.events())

	if err := f.e.SyncPaths(context.Background(), []string{store.PathDirect, "edge:edge-a"}); err != nil {
		t.Fatalf("SyncPaths: %v", err)
	}
	f.targetGone(keyProxy)
	f.targetGone(keyEdgeB)
	var n int64
	f.st.DB.Model(&store.Target{}).Where("mon_client_id = ?", "fra-1").Count(&n)
	if n != 0 {
		t.Fatal("another mon-client's target of the retired hop survived")
	}
	if got := f.targetState(keyEdgeA); got.State != store.TargetUp {
		t.Fatalf("served hop target = %s, want UP untouched", got.State)
	}
	if got := f.targetState(keyDirect); got.State != store.TargetUp {
		t.Fatalf("direct target = %s, want UP untouched", got.State)
	}
	if evs := f.events(); len(evs) != before {
		t.Fatalf("SyncPaths filed events: %+v", evs[before:])
	}

	// An empty set is no answer, not "the panel serves nothing".
	if err := f.e.SyncPaths(context.Background(), nil); err != nil {
		t.Fatalf("SyncPaths(nil): %v", err)
	}
	f.targetState(keyDirect)
}

// TestHeartbeat_RetiredPathIsRemovedAndRejoinStartsUnknown covers the
// heartbeat side of spec §5.1: a row whose path the panel stopped serving
// (here a hop that went pending, and proxy after the chain appeared) is
// removed on the next heartbeat without an event — never PAUSED — and the
// hop coming back starts over from a fresh UNKNOWN row.
func TestHeartbeat_RetiredPathIsRemovedAndRejoinStartsUnknown(t *testing.T) {
	f := newFixture(t)
	f.saveInbound(store.InboundKindXray, 12, true)
	f.cfg.keys = []registry.TargetKey{keyProxy, keyDirect, keyEdgeA}
	f.cfg.excl = chained([]string{store.PathProxy, "edge:edge-a"}, store.PathProxy, store.PathDirect, "edge:edge-a")
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyProxy, true, ""), result(keyDirect, true, ""), result(keyEdgeA, true, "")))
	before := len(f.events())

	// edge-a goes pending, and the chain has a probed hop: proxy is gone.
	f.cfg.keys = []registry.TargetKey{keyDirect, keyInner}
	f.cfg.excl = chained([]string{"inner:core-1"}, store.PathDirect, "inner:core-1")
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2, result(keyDirect, true, ""), result(keyEdgeA, true, "")))
	f.targetGone(keyProxy)
	f.targetGone(keyEdgeA)
	for _, ev := range f.events()[before:] {
		if ev.Path == store.PathProxy || ev.Path == keyEdgeA.Path {
			t.Fatalf("an event was filed for a retired path: %+v", ev)
		}
	}

	// edge-a joins again: a new row, from UNKNOWN.
	f.cfg.keys = []registry.TargetKey{keyDirect, keyInner, keyEdgeA}
	f.cfg.excl = chained([]string{"inner:core-1", "edge:edge-a"}, store.PathDirect, "inner:core-1", "edge:edge-a")
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(3, result(keyEdgeA, false, "tcp_timeout")))
	if got := f.targetState(keyEdgeA); got.State != store.TargetUnknown || got.ConsecutiveFail != 1 {
		t.Fatalf("rejoined hop target = %s (fails %d), want a fresh UNKNOWN with one failure", got.State, got.ConsecutiveFail)
	}
}

// TestHeartbeat_HopPathsPauseLikeAnyPath checks that a served hop behaves
// as any other path for the config pauses of decision #51 §3: taken off the
// mon-client it is path_removed, and an AWG target on a hop the panel gave
// this mon-client no peer for (monProbePeerLimit, decision #61 п. 4) is
// PAUSED no_probe_link from the first heartbeat.
func TestHeartbeat_HopPathsPauseLikeAnyPath(t *testing.T) {
	awgInner := registry.TargetKey{InboundKind: store.InboundKindAwg, InboundID: 0, Path: "inner:core-1"}
	f := newFixture(t)
	f.saveInbound(store.InboundKindXray, 12, true)
	f.saveInbound(store.InboundKindAwg, 0, true)
	served := []string{"edge:edge-a", "inner:core-1"}
	f.cfg.keys = []registry.TargetKey{keyDirect, keyEdgeA, keyInner}
	f.cfg.excl = chained(served, store.PathDirect, "edge:edge-a", "inner:core-1")
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(1, result(keyDirect, true, ""), result(keyEdgeA, true, ""), result(keyInner, true, "")))

	if got := f.targetState(awgInner); got.State != store.TargetPaused || got.Reason != ReasonNoProbeLink {
		t.Fatalf("awg inner target = %s/%s, want PAUSED/no_probe_link (no peer, limit)", got.State, got.Reason)
	}

	// The administrator narrows the box to edge-a.
	f.cfg.keys = []registry.TargetKey{keyDirect, keyEdgeA}
	f.cfg.excl = chained(served, store.PathDirect, "edge:edge-a")
	f.clk.Advance(time.Minute)
	f.beat(f.cycle(2))
	if got := f.targetState(keyInner); got.State != store.TargetPaused || got.Reason != ReasonPathRemoved {
		t.Fatalf("inner target = %s/%s, want PAUSED/path_removed", got.State, got.Reason)
	}
}
