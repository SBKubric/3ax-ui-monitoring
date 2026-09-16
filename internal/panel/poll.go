package panel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/SBKubric/3ax-ui-monitoring/internal/alert"
	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Poll loop constants (spec mon-server.md §4, §4.1).
const (
	// PollInterval is how often mon-server polls the panel. The same minute is
	// the budget for one cycle, retries included.
	PollInterval = time.Minute
	// OutboxMaxAge is how long an undelivered event is kept while the panel is
	// unreachable. This is the only place that cap lives; sent events are left
	// to the seven-day retention job.
	OutboxMaxAge = 24 * time.Hour
	// TokenAlertInterval is how long the bare-404 alert stays quiet before it
	// repeats. A wrong token is a standing condition, not an event, so it is
	// announced once on entry and then at most hourly until a request succeeds.
	TokenAlertInterval = time.Hour
	// maxPanelStateError bounds what a poll failure writes into the admin
	// status line.
	maxPanelStateError = 512
)

// Outbox is the events outbox as the poll loop uses it: somewhere to file a
// panel transition. *events.Outbox satisfies it. It is an interface rather
// than the concrete type because internal/events imports this package for the
// contract types, so this package cannot import it back.
type Outbox interface {
	Enqueue(ctx context.Context, ev Event) error
}

// PollOptions configures a Poller. Client and Store are required; every other
// field has a safe default, and the four function seams default to doing
// nothing so that the loop can run before the packages behind them exist.
type PollOptions struct {
	// Client talks to the panel.
	Client *Client
	// Store holds the panel cache, the inbound snapshot and the outbox.
	Store *store.Store
	// Outbox files the panel transitions of spec §4.1. Nil drops them, which
	// is only useful in a test that does not look at events.
	Outbox Outbox
	// Alert is the Telegram hook mon-server uses when it has to speak for
	// itself (spec §8). Nil discards.
	Alert alert.Func
	// Clock drives the poll interval, the 24-hour outbox cap and the alert
	// suppression window. Nil means clock.System.
	Clock clock.Clock
	// Log is the structured logger. Nil discards.
	Log *slog.Logger
	// Interval is the poll period and, unless it is shorter than one request
	// timeout, the budget of a single cycle. Zero means PollInterval.
	Interval time.Duration

	// Snapshot returns the registry snapshot posted with every
	// POST /probe/ensure: every mon-client, the disabled and never-seen ones
	// included, because the panel shows them as they are (spec §4 step 2).
	Snapshot func(ctx context.Context) ([]MonClientSnapshot, error)
	// Rebuild reassembles every mon-client's configuration document from the
	// probe material, keyed by path (spec §5).
	Rebuild func(ctx context.Context, cfgs map[string]ProbeConfigs) error
	// Reconcile brings the targets in line with the panel: an inbound that is
	// disabled or gone from the material is PAUSED, one that comes back goes
	// to UNKNOWN (spec §4 step 3, §7.2).
	Reconcile func(ctx context.Context, inbounds []Inbound, cfgs map[string]ProbeConfigs) error
	// Dispatch drains the queues — POST /events and POST /stats — and reports
	// how many events it managed to send, which is the number the "panel back"
	// message quotes (spec §4 step 4, §4.1).
	Dispatch func(ctx context.Context) (sentEvents int, err error)
}

// Poller runs the once-a-minute conversation with the panel of spec §4 and
// owns the PANEL_DOWN state machine of §4.1.
//
// It keeps the panel client, the store and four injected seams apart: nothing
// here knows how a mon-client configuration is built or how a target moves,
// only when those have to happen. One cycle is PollOnce; Run is PollOnce on a
// ticker.
type Poller struct {
	client   *Client
	st       *store.Store
	outbox   Outbox
	alertFn  alert.Func
	clock    clock.Clock
	log      *slog.Logger
	interval time.Duration

	snapshot  func(ctx context.Context) ([]MonClientSnapshot, error)
	rebuild   func(ctx context.Context, cfgs map[string]ProbeConfigs) error
	reconcile func(ctx context.Context, inbounds []Inbound, cfgs map[string]ProbeConfigs) error
	dispatch  func(ctx context.Context) (int, error)

	// mu serialises cycles: Run and a manual PollOnce never overlap.
	mu sync.Mutex
	// failures counts consecutive unreachable panel requests. It lives in
	// memory only: the status it produces is persisted, and a restart costs at
	// most one cycle of counting.
	failures int
	// tokenAlertedAt is when the bare-404 alert last went out, zero while the
	// panel is not rejecting the token.
	tokenAlertedAt time.Time
	// backAlertPending is set on recovery and cleared once the drain has
	// reported how many events went out.
	backAlertPending bool
}

// NewPoller builds a Poller.
func NewPoller(opts PollOptions) (*Poller, error) {
	if opts.Client == nil {
		return nil, fmt.Errorf("%w: client is nil", ErrInvalidOptions)
	}
	if opts.Store == nil {
		return nil, fmt.Errorf("%w: store is nil", ErrInvalidOptions)
	}
	p := &Poller{
		client:    opts.Client,
		st:        opts.Store,
		outbox:    opts.Outbox,
		alertFn:   opts.Alert,
		clock:     opts.Clock,
		log:       opts.Log,
		interval:  opts.Interval,
		snapshot:  opts.Snapshot,
		rebuild:   opts.Rebuild,
		reconcile: opts.Reconcile,
		dispatch:  opts.Dispatch,
	}
	if p.alertFn == nil {
		p.alertFn = alert.Discard
	}
	if p.clock == nil {
		p.clock = clock.System{}
	}
	if p.log == nil {
		p.log = slog.New(slog.DiscardHandler)
	}
	if p.interval <= 0 {
		p.interval = PollInterval
	}
	if p.snapshot == nil {
		p.snapshot = func(context.Context) ([]MonClientSnapshot, error) { return nil, nil }
	}
	if p.rebuild == nil {
		p.rebuild = func(context.Context, map[string]ProbeConfigs) error { return nil }
	}
	if p.reconcile == nil {
		p.reconcile = func(context.Context, []Inbound, map[string]ProbeConfigs) error { return nil }
	}
	if p.dispatch == nil {
		p.dispatch = func(context.Context) (int, error) { return 0, nil }
	}
	return p, nil
}

// Run polls immediately and then once per interval until ctx ends. A cycle
// that fails is logged and the loop carries on: the poll is also the detector
// that brings the panel back (spec §4.1).
func (p *Poller) Run(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if err := p.PollOnce(ctx); err != nil {
			p.log.Warn("panel poll cycle had failures", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// PollOnce runs one cycle of spec §4. It returns what went wrong, joined, and
// writes the panel cache whether the cycle succeeded or not, so the admin
// status line is never stale. A soft failure — the panel rejecting a request,
// xray being away, a configuration answer that has already gone stale — is
// reported but does not stop the cycle.
func (p *Poller) PollOnce(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, p.cycleBudget())
	defer cancel()

	ps, err := p.st.PanelState()
	if err != nil {
		return fmt.Errorf("panel poll: read panel state: %w", err)
	}
	settings, err := p.st.Settings()
	if err != nil {
		return fmt.Errorf("panel poll: read settings: %w", err)
	}

	problems := p.cycle(ctx, &ps, settings)

	// The 24-hour cap runs whatever the cycle did, because an unreachable
	// panel — the cycle that gives up earliest — is exactly when the buffer
	// grows (spec §4.1).
	if err := p.pruneOutbox(ctx); err != nil {
		problems = append(problems, err)
	}

	ps.LastCheckedAt = clock.MS(p.clock.Now())
	ps.LastError = truncate(errors.Join(problems...), maxPanelStateError)
	if err := p.st.SavePanelState(ps); err != nil {
		problems = append(problems, fmt.Errorf("panel poll: save panel state: %w", err))
	}
	return errors.Join(problems...)
}

// cycle is the conversation itself: the four steps of spec §4, stopping early
// only when the panel has stopped answering altogether.
func (p *Poller) cycle(ctx context.Context, ps *store.PanelState, settings store.Settings) []error {
	var problems []error

	// Step 1: the configuration snapshot and the revision.
	state, err := p.client.State(ctx)
	problems = append(problems, p.observe(ctx, ps, settings.PanelDownAfter, err))
	if err != nil {
		return append(problems, fmt.Errorf("panel poll: state: %w", err))
	}
	if err := p.savePanelInbounds(ctx, state); err != nil {
		problems = append(problems, err)
	}
	ps.OverrideEnabled = state.Override.Enabled
	ps.OverrideHost = state.Override.Host
	ps.ProbeSubID = state.Probe.SubIDValue()

	// Step 2: the probe set and the registry snapshot.
	if err := p.ensureProbeSet(ctx, ps, settings.PanelDownAfter); err != nil {
		problems = append(problems, err)
		if errors.Is(err, ErrUnavailable) {
			return problems
		}
	}

	// Step 3: a new revision means new probe material and a reconciliation.
	if state.Revision != ps.LastRevision {
		if err := p.applyRevision(ctx, ps, state, settings); err != nil {
			problems = append(problems, err)
			if errors.Is(err, ErrUnavailable) {
				return problems
			}
		}
	}

	// Step 4: drain the queues.
	return append(problems, p.drain(ctx))
}

// ensureProbeSet posts the registry snapshot and makes sure the probe accounts
// exist (spec §4 step 2).
func (p *Poller) ensureProbeSet(ctx context.Context, ps *store.PanelState, downAfter int) error {
	snapshot, err := p.snapshot(ctx)
	if err != nil {
		return fmt.Errorf("panel poll: registry snapshot: %w", err)
	}
	result, err := p.client.ProbeEnsure(ctx, snapshot)
	problem := p.observe(ctx, ps, downAfter, err)
	switch {
	case err == nil:
		if result.SubID != "" {
			ps.ProbeSubID = result.SubID
		}
		if len(result.Created) > 0 {
			p.log.Info("panel created probe accounts", "created", len(result.Created), "present", result.Present)
		}
	case errors.Is(err, ErrXrayUnavailable):
		// Not a panel failure: the set is partly there and the next cycle
		// finishes it.
		p.log.Warn("panel could not reach xray, the probe set stays incomplete", "error", err)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("panel poll: probe ensure: %w", err), problem)
	}
	return problem
}

// applyRevision fetches the probe material for both paths, rebuilds the
// mon-client configurations and reconciles the targets. The revision is only
// recorded as seen once all of that has worked, so a half-applied change is
// retried on the next cycle.
func (p *Poller) applyRevision(ctx context.Context, ps *store.PanelState, state State, settings store.Settings) error {
	cfgs, err := p.fetchConfigs(ctx, ps, state, settings)
	if err != nil {
		return err
	}
	if cfgs == nil {
		return nil
	}
	if err := p.rebuild(ctx, cfgs); err != nil {
		return fmt.Errorf("panel poll: rebuild mon-client configs: %w", err)
	}
	if err := p.reconcile(ctx, state.Inbounds, cfgs); err != nil {
		return fmt.Errorf("panel poll: reconcile targets: %w", err)
	}
	ps.LastRevision = state.Revision
	p.log.Info("panel revision applied", "revision", state.Revision, "paths", len(cfgs))
	return nil
}

// fetchConfigs reads GET /probe/configs for every path that has one: always
// direct, addressed at the real host, and proxy as well when the panel's host
// override is on. A nil map means this cycle has nothing to apply.
func (p *Poller) fetchConfigs(ctx context.Context, ps *store.PanelState, state State, settings store.Settings) (map[string]ProbeConfigs, error) {
	cfgs := map[string]ProbeConfigs{}
	var problems []error

	realHost := settings.RealHost
	if realHost == "" {
		p.log.Warn("no real host configured, the direct path has no probe material")
	} else {
		direct, err := p.client.ProbeConfigs(ctx, realHost)
		problems = append(problems, p.observe(ctx, ps, settings.PanelDownAfter, err))
		switch {
		case err != nil:
			problems = append(problems, fmt.Errorf("panel poll: probe configs for %s: %w", PathDirect, err))
		default:
			cfgs[PathDirect] = direct
		}
	}

	if state.Override.Enabled {
		proxy, err := p.client.ProbeConfigs(ctx, "")
		problems = append(problems, p.observe(ctx, ps, settings.PanelDownAfter, err))
		switch {
		case err != nil:
			problems = append(problems, fmt.Errorf("panel poll: probe configs for %s: %w", PathProxy, err))
		default:
			cfgs[PathProxy] = proxy
		}
	}

	if joined := errors.Join(problems...); joined != nil {
		return nil, joined
	}
	if len(cfgs) == 0 {
		return nil, nil
	}
	// An answer the panel rendered before the revision moved is no longer the
	// configuration mon-server just read, so the whole set is dropped and the
	// next cycle asks again (contract §4.4).
	for path, cfg := range cfgs {
		if cfg.Revision != state.Revision {
			p.log.Warn("discarding stale probe material",
				"path", path, "answer", cfg.Revision, "state", state.Revision)
			return nil, nil
		}
	}
	return cfgs, nil
}

// drain hands the queues to the dispatcher and announces the panel's return
// once it knows how much actually went out (spec §4 step 4, §4.1).
func (p *Poller) drain(ctx context.Context) error {
	sent, err := p.dispatch(ctx)
	if err != nil {
		// The queues did not move, so there is no honest number to quote yet:
		// the announcement waits for the next cycle.
		return fmt.Errorf("panel poll: dispatch: %w", err)
	}
	if p.backAlertPending {
		p.backAlertPending = false
		p.alertFn(ctx, alert.MsgPanelBack(sent))
	}
	return nil
}

// pruneOutbox drops undelivered events older than OutboxMaxAge. Sent events
// are left alone: the retention job keeps those for a week.
func (p *Poller) pruneOutbox(ctx context.Context) error {
	cutoff := clock.MS(p.clock.Now().Add(-OutboxMaxAge))
	res := p.st.DB().WithContext(ctx).
		Where("sent_at IS NULL AND ts < ?", cutoff).
		Delete(&store.EventOutbox{})
	if res.Error != nil {
		return fmt.Errorf("panel poll: prune outbox: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		p.log.Warn("dropped buffered events older than the 24 hour cap",
			"dropped", res.RowsAffected, "cutoff", cutoff)
	}
	return nil
}

// savePanelInbounds replaces the mirror of the panel's inbound list. Rows left
// behind by an older revision are inbounds the panel no longer has.
//
// The rows go in as maps rather than structs on purpose: PanelInbound.Enable
// carries a column default of true, and GORM substitutes a column default for
// any zero-valued field, so inserting the struct would quietly re-enable every
// inbound the panel has switched off.
func (p *Poller) savePanelInbounds(ctx context.Context, state State) error {
	rows := make([]map[string]any, 0, len(state.Inbounds))
	for _, in := range state.Inbounds {
		rows = append(rows, map[string]any{
			"inbound_kind":  in.Kind,
			"inbound_id":    in.InboundID,
			"protocol":      in.Protocol,
			"port":          in.Port,
			"remark":        in.Remark,
			"enable":        in.Enable,
			"seen_revision": state.Revision,
		})
	}
	err := p.st.DB().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if len(rows) > 0 {
			upsert := clause.OnConflict{
				Columns: []clause.Column{{Name: "inbound_kind"}, {Name: "inbound_id"}},
				DoUpdates: clause.AssignmentColumns([]string{
					"protocol", "port", "remark", "enable", "seen_revision",
				}),
			}
			if err := tx.Model(&store.PanelInbound{}).Clauses(upsert).Create(rows).Error; err != nil {
				return err
			}
		}
		gone := tx.Where("seen_revision <> ?", state.Revision).Delete(&store.PanelInbound{})
		if gone.Error != nil {
			return gone.Error
		}
		if gone.RowsAffected > 0 {
			p.log.Info("inbounds disappeared from the panel", "removed", gone.RowsAffected)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("panel poll: save panel inbounds: %w", err)
	}
	return nil
}

// observe folds one panel request outcome into the PANEL_DOWN state machine of
// spec §4.1.
//
// Only a request that never reached the panel counts as a failure. A request
// the panel answered — a bare 404, a 409, a 413 — proves it is reachable, so
// it clears the run of failures without declaring the panel up: the answer was
// not a successful one.
func (p *Poller) observe(ctx context.Context, ps *store.PanelState, downAfter int, err error) error {
	switch {
	case err == nil:
		p.failures = 0
		p.tokenAlertedAt = time.Time{}
		if ps.Status == store.PanelStatusDown {
			return p.declareUp(ctx, ps)
		}
		ps.Status = store.PanelStatusUp
		return nil

	case errors.Is(err, ErrNotFound):
		// Contract §2: a bare 404 is a wrong token, a wrong path, or
		// monitoring switched off. The panel answered, so the state is left
		// exactly as it was and mon-server tells the owner itself (spec §8).
		p.failures = 0
		p.alertTokenRejected(ctx)
		return nil

	case errors.Is(err, ErrUnavailable):
		p.failures++
		if downAfter < 1 {
			return nil
		}
		if p.failures >= downAfter && ps.Status != store.PanelStatusDown {
			return p.declareDown(ctx, ps, FailureReason(err))
		}
		p.log.Warn("panel request failed",
			"failures", p.failures, "downAfter", downAfter, "error", err)
		return nil

	default:
		p.failures = 0
		return nil
	}
}

// declareDown enters PANEL_DOWN: one event, one Telegram message, and the
// status written before either, because the outbox reads it to decide whether
// it has to announce transitions itself.
func (p *Poller) declareDown(ctx context.Context, ps *store.PanelState, reason string) error {
	if reason == "" {
		reason = ReasonConnRefused
	}
	ps.Status = store.PanelStatusDown
	ps.LastError = alert.MsgPanelUnreachable(reason)
	if err := p.st.SavePanelState(*ps); err != nil {
		return fmt.Errorf("panel poll: save PANEL_DOWN: %w", err)
	}
	p.backAlertPending = false
	p.log.Warn("panel is unreachable, entering PANEL_DOWN", "reason", reason, "failures", p.failures)
	err := p.file(ctx, Event{
		TS:     clock.MS(p.clock.Now()),
		Kind:   EventKindPanel,
		From:   PanelUp,
		To:     PanelDown,
		Reason: reason,
	})
	p.alertFn(ctx, alert.MsgPanelUnreachable(reason))
	return err
}

// declareUp leaves PANEL_DOWN. The "panel back" message waits for the drain,
// which is the only thing that knows how many buffered events actually went
// out.
func (p *Poller) declareUp(ctx context.Context, ps *store.PanelState) error {
	ps.Status = store.PanelStatusUp
	ps.LastError = ""
	if err := p.st.SavePanelState(*ps); err != nil {
		return fmt.Errorf("panel poll: save PANEL_UP: %w", err)
	}
	p.backAlertPending = true
	p.log.Info("panel answered again, leaving PANEL_DOWN")
	return p.file(ctx, Event{
		TS:     clock.MS(p.clock.Now()),
		Kind:   EventKindPanel,
		From:   PanelDown,
		To:     PanelUp,
		Reason: ReasonRecovered,
	})
}

// alertTokenRejected sends the wrong-token message, at most once per
// TokenAlertInterval while the condition lasts.
func (p *Poller) alertTokenRejected(ctx context.Context) {
	now := p.clock.Now()
	if !p.tokenAlertedAt.IsZero() && now.Sub(p.tokenAlertedAt) < TokenAlertInterval {
		p.log.Warn("panel still rejects the monitoring token")
		return
	}
	p.tokenAlertedAt = now
	p.log.Warn("panel rejects the monitoring token or monitoring is disabled")
	p.alertFn(ctx, alert.MsgPanelRejectsToken())
}

// file puts a panel event in the outbox. Panel events are always notified:
// mon-server has already told Telegram, the panel only files them.
func (p *Poller) file(ctx context.Context, ev Event) error {
	if p.outbox == nil {
		return nil
	}
	if err := p.outbox.Enqueue(ctx, ev.Normalized()); err != nil {
		return fmt.Errorf("panel poll: file %s event: %w", ev.To, err)
	}
	return nil
}

// cycleBudget is how long one cycle may take. It is the poll interval, never
// shorter than a single request timeout, so that a test running the loop fast
// does not starve the requests it is driving.
func (p *Poller) cycleBudget() time.Duration {
	if timeout := p.client.Timeout(); p.interval < timeout {
		return timeout
	}
	return p.interval
}

// truncate renders err for the admin status line, capped at n characters.
func truncate(err error, n int) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if len(msg) <= n {
		return msg
	}
	return msg[:n]
}
