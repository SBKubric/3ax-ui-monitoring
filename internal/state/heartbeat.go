package state

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"

	"gorm.io/gorm"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Heartbeat is the body of POST /v1/heartbeat (mon-protocol.md §5.3): what one
// mon-client reports about itself and the cycles of probe results it has not
// had acknowledged yet.
type Heartbeat struct {
	MonClientID string `json:"monClientId"`
	// ConfigRevision is the revision the mon-client is actually running. It is
	// stored as applied_revision, so the admin UI can see a mon-client lagging
	// behind the revision mon-server built (spec §7.1).
	ConfigRevision string       `json:"configRevision"`
	Client         ClientReport `json:"client"`
	Cycles         []Cycle      `json:"cycles"`
}

// ClientReport is the mon-client's report about itself.
type ClientReport struct {
	Version     string `json:"version"`
	XrayVersion string `json:"xrayVersion"`
	UptimeMS    int64  `json:"uptimeMs"`
	// ConfigError is the error applying the last configuration, null or empty
	// when the mon-client is running its configuration cleanly
	// (mon-protocol.md §4.3).
	ConfigError string `json:"configError"`
}

// Cycle is one probe cycle: every target probed once, in parallel, and the
// results gathered (mon-protocol.md §5.1).
type Cycle struct {
	// Seq numbers the cycles of one mon-client. Everything up to the ackSeq of
	// the previous response has been accepted and is never reconsidered.
	Seq int64 `json:"seq"`
	// TS is the mon-client's own clock at the start of the cycle. It places
	// the results into five-minute buckets and decides nothing else; it is
	// clamped to mon-server's receive time when the two disagree by more than
	// five minutes (spec §7.1).
	TS int64 `json:"ts"`
	// Unverified marks a cycle whose heartbeat was never acknowledged. Its
	// failures are meaningless — the tunnel probe's destination is mon-server
	// itself, so mon-server being unreachable looks exactly like a broken
	// tunnel — and are dropped; only its successes count, and only for
	// statistics (mon-protocol.md §5.3).
	Unverified bool     `json:"unverified"`
	Results    []Result `json:"results"`
}

// Result is one probe of one target within a cycle.
type Result struct {
	InboundKind string `json:"inboundKind"`
	InboundID   int64  `json:"inboundId"`
	Path        string `json:"path"`
	OK          bool   `json:"ok"`
	ConnectMS   *int64 `json:"connectMs"`
	// TLSMS is the TLS phase of an xray probe, the latency the statistics
	// buckets summarise.
	TLSMS  *int64 `json:"tlsMs"`
	TTFBMS *int64 `json:"ttfbMs"`
	// HandshakeMS is AWG only.
	HandshakeMS *int64 `json:"handshakeMs"`
	EgressIP    string `json:"egressIp"`
	// Reason is the mon-client's diagnosis of a failure, from the dictionary
	// of contract §4.6; it becomes the reason of the DOWN event.
	Reason string `json:"reason"`
	// Detail is at most 256 characters of context. It never leaves mon-server.
	Detail string `json:"detail"`
}

// Key is the target the result is about.
func (r Result) Key() TargetKey {
	return TargetKey{InboundKind: r.InboundKind, InboundID: r.InboundID, Path: r.Path}
}

// HeartbeatAck is the answer to POST /v1/heartbeat: the revision mon-server
// wants the mon-client to be running, mon-server's own time, and the highest
// cycle sequence it has accepted (mon-protocol.md §5.3).
type HeartbeatAck struct {
	ConfigRevision string `json:"configRevision"`
	ServerTS       int64  `json:"serverTs"`
	AckSeq         int64  `json:"ackSeq"`
}

// StatsSink receives the probe results of every accepted cycle, the live one
// included, for the five-minute buckets of spec §7.4. Step 7
// (internal/stats) implements it; until it is wired in, DiscardStats drops
// everything and the state machine works regardless.
//
// cycleTS is the bucketing timestamp, already clamped to mon-server's receive
// time (spec §7.1), never the raw value the mon-client sent. results are the
// ones that survived the configuration filter, and for an unverified cycle
// they are its successes only: a failure of an unverified cycle is a gap, not
// an nFail. The flag is passed all the same, because a bucket that only ever
// saw unverified results is not the same as one that saw none.
//
// The sink is called while the state machine holds its lock; it must not call
// back into the Machine.
type StatsSink interface {
	Record(ctx context.Context, monClientID string, cycleTS int64, results []Result, unverified bool) error
}

// DiscardStats is the StatsSink of a mon-server whose statistics writer is not
// wired in yet: it drops every batch.
type DiscardStats struct{}

// Record implements StatsSink.
func (DiscardStats) Record(context.Context, string, int64, []Result, bool) error { return nil }

// maxClockSkewMS is how far a cycle's own timestamp may be from mon-server's
// receive time before it is clamped to it (spec §7.1).
const maxClockSkewMS int64 = 5 * 60 * 1000

// ackSeqKeyPrefix namespaces the per-mon-client cursor of the highest cycle
// sequence mon-server has acknowledged. The settings table holds it because
// mon_clients has no column for it in spec §3 and it is exactly the kind of
// small durable value that table already keeps for the panel poll; it is not a
// user setting and the admin UI never shows it.
const ackSeqKeyPrefix = "heartbeatAckSeq:"

// ackSeqKey is the settings key of one mon-client's acknowledgement cursor.
func ackSeqKey(monClientID string) string { return ackSeqKeyPrefix + monClientID }

// Heartbeat applies one heartbeat (spec §7.1) and returns the acknowledgement
// the mon-client gets back. monClientID is the authenticated caller, not the
// id in the body: the token decides whose results these are.
//
// The order is the spec's: the receive time is taken first and is the
// authority for everything that follows, the mon-client's own row is updated,
// the cycles are selected, the live one drives the state machine, and every
// accepted cycle goes to statistics.
func (m *Machine) Heartbeat(ctx context.Context, monClientID string, hb Heartbeat) (HeartbeatAck, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.nowMS()
	th, err := m.thresholds()
	if err != nil {
		return HeartbeatAck{}, err
	}
	mc, err := m.loadMonClient(ctx, monClientID)
	if err != nil {
		return HeartbeatAck{}, err
	}
	prevAck, err := m.ackSeq(monClientID)
	if err != nil {
		return HeartbeatAck{}, err
	}

	// 1. The mon-client itself: alive, running this version, on this revision.
	evs, alerts := m.applyClientReport(mc, hb, now)
	if err := m.saveMonClient(ctx, mc); err != nil {
		return HeartbeatAck{}, err
	}

	// 2. Cycle selection (spec §7.1 step 3).
	sel := selectCycles(hb.Cycles, prevAck)

	targets, err := m.loadTargets(ctx, monClientID)
	if err != nil {
		return HeartbeatAck{}, err
	}
	byKey := make(map[TargetKey]*store.Target, len(targets))
	for i := range targets {
		byKey[keyOf(&targets[i])] = &targets[i]
	}

	// 3. The live cycle, and only it, drives the state machine.
	if sel.live != nil {
		moved, err := m.applyLiveCycle(ctx, monClientID, *sel.live, byKey, now, th)
		if err != nil {
			return HeartbeatAck{}, err
		}
		evs = append(evs, moved...)
	}
	if err := m.file(ctx, evs); err != nil {
		return HeartbeatAck{}, err
	}
	// Telegram only once the rows are durable, the same order the outbox uses.
	for _, text := range alerts {
		m.alert(ctx, text)
	}

	// 4. Statistics: every accepted cycle, the live one included.
	m.recordStats(ctx, monClientID, sel.accepted, byKey, now)

	ack := prevAck
	if sel.maxSeq > ack {
		ack = sel.maxSeq
	}
	if ack != prevAck {
		if err := m.setAckSeq(monClientID, ack); err != nil {
			return HeartbeatAck{}, err
		}
	}
	revision, err := m.configRevision(ctx, monClientID)
	if err != nil {
		return HeartbeatAck{}, err
	}
	return HeartbeatAck{ConfigRevision: revision, ServerTS: now, AckSeq: ack}, nil
}

// applyClientReport updates the mon-client row from its own report (spec §7.1
// step 2) and returns the transitions to file and the Telegram messages
// mon-server sends itself.
func (m *Machine) applyClientReport(mc *store.MonClient, hb Heartbeat, now int64) ([]pendingEvent, []string) {
	var evs []pendingEvent
	var alerts []string

	from := mc.State
	mc.LastHeartbeat = now
	mc.MissedHeartbeats = 0
	mc.AppliedRevision = hb.ConfigRevision
	if hb.Client.Version != "" {
		mc.Version = hb.Client.Version
	}
	if hb.Client.XrayVersion != "" {
		mc.XrayVersion = hb.Client.XrayVersion
	}

	// A config error that appears — or changes — is stored with the time it
	// arrived and told to the owner by mon-server itself (spec §7.1, §8); one
	// that disappears is cleared. Repeating the same error says nothing new.
	detail := alert.FirstLine(hb.Client.ConfigError)
	switch {
	case detail == "":
		mc.ConfigError = ""
		mc.ConfigErrorAt = 0
	case detail != mc.ConfigError:
		mc.ConfigError = detail
		mc.ConfigErrorAt = now
		alerts = append(alerts, alert.MsgConfigError(mc.ID, detail))
	}

	if from != store.ClientStateOnline {
		mc.State = store.ClientStateOnline
		evs = append(evs, loudEvent(events.MonClient(now, mc.ID, from, store.ClientStateOnline, panel.ReasonRecovered)))
	}
	return evs, alerts
}

// cycleSelection is the outcome of spec §7.1 step 3.
type cycleSelection struct {
	// live is the cycle that drives the state machine: the last one, the one
	// that arrived with its own heartbeat, not marked unverified. It is nil
	// when the heartbeat carries no such cycle.
	live *Cycle
	// accepted is every cycle newer than the previous acknowledgement, in
	// sequence order, the live one included. Those go to statistics.
	accepted []Cycle
	// maxSeq is the highest sequence seen, which is what gets acknowledged.
	maxSeq int64
}

// selectCycles applies the cycle rules of spec §7.1 step 3 to the cycles of
// one heartbeat. Cycles at or below the previous acknowledgement are ignored
// outright: they have already been applied, and replaying them would move a
// target's state on evidence the panel has already been told about.
func selectCycles(cycles []Cycle, prevAck int64) cycleSelection {
	sel := cycleSelection{maxSeq: prevAck}
	for _, c := range cycles {
		if c.Seq > sel.maxSeq {
			sel.maxSeq = c.Seq
		}
		if c.Seq <= prevAck {
			continue
		}
		sel.accepted = append(sel.accepted, c)
	}
	sort.SliceStable(sel.accepted, func(i, j int) bool { return sel.accepted[i].Seq < sel.accepted[j].Seq })
	if n := len(sel.accepted); n > 0 {
		// The live cycle is the last one. A resent cycle carries a lower
		// sequence, so it is never last; an unverified last cycle means the
		// mon-client is only catching up and nothing drives the state machine
		// this time.
		if last := sel.accepted[n-1]; !last.Unverified {
			live := last
			sel.live = &live
		}
	}
	return sel
}

// applyLiveCycle runs the results of the live cycle through the state machine.
// Results naming a target this mon-client is not configured to probe are
// discarded (spec §7.1 step 3); so are results for a paused target, whose
// inbound the panel has switched off.
func (m *Machine) applyLiveCycle(ctx context.Context, monClientID string, cycle Cycle, byKey map[TargetKey]*store.Target, now int64, th thresholds) ([]pendingEvent, error) {
	var evs []pendingEvent
	for _, res := range cycle.Results {
		row, ok := byKey[res.Key()]
		if !ok || row.State == store.TargetPaused {
			m.log.Debug("heartbeat result for a target outside the configuration, discarded",
				"monClientId", monClientID, "target", res.Key().String())
			continue
		}
		moved := m.applyResult(row, resultOutcome{ok: res.OK, reason: res.Reason}, now, th)
		if err := m.saveTarget(ctx, row); err != nil {
			return evs, err
		}
		evs = append(evs, moved...)
	}
	return evs, nil
}

// recordStats hands every accepted cycle to the statistics sink with the
// bucketing timestamp of spec §7.1 step 1. A sink failure is logged and not
// returned: losing a bucket must not cost the acknowledgement, which would
// make the mon-client resend the whole cycle as unverified and lose its
// failures for good.
func (m *Machine) recordStats(ctx context.Context, monClientID string, cycles []Cycle, byKey map[TargetKey]*store.Target, now int64) {
	for _, cycle := range cycles {
		results := make([]Result, 0, len(cycle.Results))
		for _, res := range cycle.Results {
			row, ok := byKey[res.Key()]
			if !ok || row.State == store.TargetPaused {
				continue
			}
			if cycle.Unverified && !res.OK {
				continue
			}
			results = append(results, res)
		}
		if len(results) == 0 {
			continue
		}
		if err := m.stats.Record(ctx, monClientID, bucketTS(cycle.TS, now), results, cycle.Unverified); err != nil {
			m.log.Error("could not record cycle statistics",
				"monClientId", monClientID, "seq", cycle.Seq, "error", err)
		}
	}
}

// bucketTS is the timestamp the results of a cycle are bucketed under: the
// mon-client's own clock when it is close enough to mon-server's, and
// mon-server's receive time when it is not (spec §7.1 step 1).
func bucketTS(cycleTS, now int64) int64 {
	if cycleTS <= 0 {
		return now
	}
	skew := cycleTS - now
	if skew < 0 {
		skew = -skew
	}
	if skew > maxClockSkewMS {
		return now
	}
	return cycleTS
}

// loadMonClient reads the mon-client row the heartbeat belongs to.
func (m *Machine) loadMonClient(ctx context.Context, monClientID string) (*store.MonClient, error) {
	var mc store.MonClient
	err := m.st.DB().WithContext(ctx).Where("id = ?", monClientID).Take(&mc).Error
	switch {
	case err == nil:
		return &mc, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return nil, fmt.Errorf("state: unknown mon-client %q", monClientID)
	default:
		return nil, fmt.Errorf("state: read mon-client %q: %w", monClientID, err)
	}
}

// saveMonClient writes a mon-client row back.
func (m *Machine) saveMonClient(ctx context.Context, mc *store.MonClient) error {
	if err := m.st.DB().WithContext(ctx).Save(mc).Error; err != nil {
		return fmt.Errorf("state: save mon-client %q: %w", mc.ID, err)
	}
	return nil
}

// configRevision is the revision of the configuration mon-server has built for
// this mon-client, the value every heartbeat answer carries (spec §5). It is
// empty while no configuration has been assembled yet.
func (m *Machine) configRevision(ctx context.Context, monClientID string) (string, error) {
	var cfg store.ClientConfig
	err := m.st.DB().WithContext(ctx).Where("mon_client_id = ?", monClientID).Take(&cfg).Error
	switch {
	case err == nil:
		return cfg.Revision, nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return "", nil
	default:
		return "", fmt.Errorf("state: read client config of %q: %w", monClientID, err)
	}
}

// ackSeq reads the highest cycle sequence already acknowledged to one
// mon-client. An unreadable cursor starts over at zero rather than failing the
// heartbeat: the worst it costs is one cycle applied twice.
func (m *Machine) ackSeq(monClientID string) (int64, error) {
	raw, ok, err := m.st.LookupSetting(ackSeqKey(monClientID))
	if err != nil {
		return 0, fmt.Errorf("state: read ack cursor of %q: %w", monClientID, err)
	}
	if !ok || raw == "" {
		return 0, nil
	}
	seq, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		m.log.Warn("unreadable heartbeat acknowledgement cursor, starting over",
			"monClientId", monClientID, "value", raw, "error", err)
		return 0, nil
	}
	return seq, nil
}

// setAckSeq stores the acknowledgement cursor.
func (m *Machine) setAckSeq(monClientID string, seq int64) error {
	if err := m.st.SetSetting(ackSeqKey(monClientID), strconv.FormatInt(seq, 10)); err != nil {
		return fmt.Errorf("state: write ack cursor of %q: %w", monClientID, err)
	}
	return nil
}
