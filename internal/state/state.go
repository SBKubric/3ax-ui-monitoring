// Package state is the heart of mon-server: it turns the probe results a
// mon-client reports into target transitions (spec mon-server.md §7.1, §7.2)
// and notices when a mon-client itself stops reporting (§7.3).
//
// Two rules shape everything here.
//
// The first is that mon-server's own receive time is the authority. A
// heartbeat carries the mon-client's clock in every cycle's ts, and that ts is
// used for one thing only: placing results into five-minute statistics buckets
// (§7.4), clamped to the receive time when the two disagree by more than five
// minutes. Every state decision — thresholds, flap windows, event timestamps —
// uses the receive time from the injected clock.
//
// The second is that history is never replayed. A mon-client buffers the
// cycles whose heartbeat was not acknowledged and resends them later; those
// carry real statistics but must not move a target's state, because a
// transition filed now with a timestamp from ten minutes ago would rewrite a
// picture the panel has already drawn. Only the live cycle — the last one, the
// one that arrived with its own heartbeat, not marked unverified — drives the
// state machine.
//
// The package owns the targets table and the state column of mon_clients. It
// never writes events_outbox directly: every transition goes through
// internal/events, which applies the PANEL_DOWN rule of §4.1.
package state

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/events"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Machine applies heartbeats to the state machine of spec §7.2 and keeps the
// targets table. One instance serves every mon-client; its methods serialise
// on a mutex, so a heartbeat, the liveness job and the panel poll cannot
// interleave two read-modify-write cycles over the same target row.
type Machine struct {
	st    *store.Store
	clk   clock.Clock
	log   *slog.Logger
	alert alert.Func

	// loud files events that may be announced: while the panel is down the
	// outbox sends them to Telegram itself and marks them notified (§4.1).
	loud *events.Outbox
	// quiet files events that must never reach Telegram — the transitions
	// inside FLAPPING, a target paused by the configuration, a target reset
	// because its mon-client went offline. It is the same outbox with the
	// alert hook discarded, and the events it files carry notified=true so
	// that the panel does not announce them either (contract §4.6).
	quiet *events.Outbox

	stats StatsSink

	mu sync.Mutex
}

// Option customises New.
type Option func(*Machine)

// WithStatsSink replaces the no-op statistics sink with the real one. Step 7
// (internal/stats) implements StatsSink and is wired in here.
func WithStatsSink(sink StatsSink) Option {
	return func(m *Machine) {
		if sink != nil {
			m.stats = sink
		}
	}
}

// New returns a Machine.
//
// alertFn is the Telegram hook mon-server uses itself (spec §8): it carries a
// mon-client's configError (alert.MsgConfigError) and, while the panel is
// unreachable, the target and mon-client transitions the outbox announces on
// the panel's behalf. Pass alert.Discard to silence both.
func New(st *store.Store, clk clock.Clock, alertFn alert.Func, log *slog.Logger, opts ...Option) *Machine {
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if alertFn == nil {
		alertFn = alert.Discard
	}
	m := &Machine{
		st:    st,
		clk:   clk,
		log:   log,
		alert: alertFn,
		loud:  events.New(st, alertFn),
		quiet: events.New(st, alert.Discard),
		stats: DiscardStats{},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// nowMS is the receive time every decision in this package is made against.
func (m *Machine) nowMS() int64 { return clock.MS(m.clk.Now()) }

// thresholds is the settings slice the state machine reads (spec §7.2, §7.3),
// with the windows already converted to milliseconds.
type thresholds struct {
	downAfter    int
	upAfter      int
	flapN        int
	flapWindowMS int64
	flapHoldMS   int64
	// offlineAfterMS is clientOfflineAfter × intervalMs + heartbeatTimeoutMs,
	// the silence after which a mon-client is OFFLINE (§7.3).
	offlineAfterMS int64
	intervalMS     int64
}

// minuteMS is one minute in milliseconds: flapMin and flapHoldMin are stored
// in minutes.
const minuteMS int64 = 60_000

// thresholds reads the settings fresh, so a threshold changed in the admin UI
// applies to the next heartbeat. A value that is missing or nonsensical falls
// back to the default of spec §9.4 rather than disabling the state machine.
func (m *Machine) thresholds() (thresholds, error) {
	s, err := m.st.Settings()
	if err != nil {
		return thresholds{}, fmt.Errorf("state: settings: %w", err)
	}
	d := store.DefaultSettings()
	return thresholds{
		downAfter:      positive(s.DownAfter, d.DownAfter),
		upAfter:        positive(s.UpAfter, d.UpAfter),
		flapN:          positive(s.FlapN, d.FlapN),
		flapWindowMS:   int64(positive(s.FlapMin, d.FlapMin)) * minuteMS,
		flapHoldMS:     int64(positive(s.FlapHoldMin, d.FlapHoldMin)) * minuteMS,
		offlineAfterMS: int64(positive(s.ClientOfflineAfter, d.ClientOfflineAfter))*int64(positive(s.IntervalMs, d.IntervalMs)) + int64(positive(s.HeartbeatTimeoutMs, d.HeartbeatTimeoutMs)),
		intervalMS:     int64(positive(s.IntervalMs, d.IntervalMs)),
	}, nil
}

// positive returns v when it is usable as a threshold, otherwise fallback.
func positive(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// pendingEvent is one transition waiting to be filed, together with the single
// decision this package makes about it: whether mon-server may announce it to
// Telegram itself while the panel is down.
//
// Quiet events are the ones spec §7.2 and §7.3 mark "Telegram нет": the
// transitions inside FLAPPING, config_disabled and config_enabled, and the
// targets swept to UNKNOWN when their mon-client goes offline. They are filed
// like any other event, so the panel's picture is complete, and they carry
// notified=true so that neither the panel nor mon-server announces them.
type pendingEvent struct {
	ev    panel.Event
	quiet bool
}

// loudEvent wraps a transition the owner is allowed to hear about.
func loudEvent(ev panel.Event) pendingEvent { return pendingEvent{ev: ev} }

// quietEvent wraps a transition that must stay out of Telegram.
func quietEvent(ev panel.Event) pendingEvent {
	ev.Notified = true
	return pendingEvent{ev: ev, quiet: true}
}

// file writes a batch of transitions to the outbox: the announceable ones
// through the outbox holding the Telegram hook, the quiet ones through the
// outbox holding alert.Discard. Each group goes in one call, so a sweep that
// moves many targets at once is all-or-nothing.
func (m *Machine) file(ctx context.Context, evs []pendingEvent) error {
	if len(evs) == 0 {
		return nil
	}
	loud := make([]panel.Event, 0, len(evs))
	quiet := make([]panel.Event, 0, len(evs))
	for _, pe := range evs {
		if pe.quiet {
			quiet = append(quiet, pe.ev)
			continue
		}
		loud = append(loud, pe.ev)
	}
	if err := m.quiet.EnqueueAll(ctx, quiet); err != nil {
		return fmt.Errorf("state: file quiet events: %w", err)
	}
	if err := m.loud.EnqueueAll(ctx, loud); err != nil {
		return fmt.Errorf("state: file events: %w", err)
	}
	return nil
}
