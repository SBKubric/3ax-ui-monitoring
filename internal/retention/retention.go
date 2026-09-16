// Package retention is mon-server's housekeeping job: once an hour it drops
// the rows spec mon-server.md §3 says have served their purpose.
//
//	events_outbox          accepted by the panel, sent_at older than 7 days
//	stats_buckets          accepted by the panel, sent_at older than 7 days
//	probe_seen             seen_at older than 24 hours
//	registration_requests  not pending, created more than 7 days ago
//	admin_sessions         expires_at in the past
//
// Two rules shape everything here.
//
// **A row the panel has not accepted is never deleted.** An event or a bucket
// with a NULL sent_at is still owed to the panel, and while the panel is down
// (§4.1) the outbox is the only copy of what happened. The 24-hour cap on
// buffering during PANEL_DOWN is the panel poll's business, not this job's:
// dropping an event here would lose it silently.
//
// **One hour of accumulation must not hold the writer.** SQLite runs on a
// single connection shared with the poll loop and the HTTP handlers, so each
// table is swept in bounded batches of a few thousand rows, each its own
// statement, with the context checked between them. There is no VACUUM: the
// file keeps its size and reuses the freed pages, which is what a service that
// deletes a steady trickle every hour wants.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// Defaults of the job, the values of spec §3. Every one of them can be
// overridden with an Option, which is what the tests do instead of fabricating
// week-old rows.
const (
	// DefaultInterval is how often Run sweeps: the "job раз в час" of §3.
	DefaultInterval = time.Hour
	// DefaultBatchSize is how many rows one DELETE removes.
	DefaultBatchSize = 2000
	// DefaultEventTTL is how long a delivered event stays in events_outbox.
	DefaultEventTTL = 7 * 24 * time.Hour
	// DefaultStatsTTL is how long a delivered bucket stays in stats_buckets.
	DefaultStatsTTL = 7 * 24 * time.Hour
	// DefaultProbeSeenTTL is how long the tunnel probe diagnostics log is
	// kept.
	DefaultProbeSeenTTL = 24 * time.Hour
	// DefaultRequestTTL is how long a settled registration request is kept.
	DefaultRequestTTL = 7 * 24 * time.Hour
)

// maxBatchesPerTable bounds one table's sweep, so that an unexpected backlog
// — a restore from an old backup, a bug that filled a table — costs one
// bounded burst of writes per hour instead of locking the database until it is
// done. Whatever is left waits for the next run.
const maxBatchesPerTable = 64

// Result counts what one sweep removed, per table, so the caller logs one line
// instead of five.
type Result struct {
	// Events is rows removed from events_outbox.
	Events int64
	// Stats is rows removed from stats_buckets.
	Stats int64
	// ProbeSeen is rows removed from probe_seen.
	ProbeSeen int64
	// Requests is rows removed from registration_requests.
	Requests int64
	// Sessions is rows removed from admin_sessions.
	Sessions int64
}

// Total is how many rows the sweep removed altogether.
func (r Result) Total() int64 {
	return r.Events + r.Stats + r.ProbeSeen + r.Requests + r.Sessions
}

// IsZero reports whether the sweep removed nothing, the normal case on a quiet
// installation.
func (r Result) IsZero() bool { return r.Total() == 0 }

// LogValue renders the counts as one grouped log attribute.
func (r Result) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("events", r.Events),
		slog.Int64("stats", r.Stats),
		slog.Int64("probeSeen", r.ProbeSeen),
		slog.Int64("requests", r.Requests),
		slog.Int64("sessions", r.Sessions),
		slog.Int64("total", r.Total()),
	)
}

// Janitor is the retention job. It is safe for concurrent use; in the process
// there is one of them, started by the wiring in cmd/mon-server.
type Janitor struct {
	st  *store.Store
	log *slog.Logger
	clk clock.Clock

	interval time.Duration
	batch    int

	eventTTL     time.Duration
	statsTTL     time.Duration
	probeSeenTTL time.Duration
	requestTTL   time.Duration
}

// Option overrides a Janitor default. A value that is not positive is ignored,
// so a misconfigured setting keeps the spec's window rather than deleting
// everything.
type Option func(*Janitor)

// WithClock replaces the clock the cutoffs are measured from. By default the
// Janitor shares the store's clock, so a store opened with clock.Fake already
// gives a fake-driven job.
func WithClock(c clock.Clock) Option {
	return func(j *Janitor) {
		if c != nil {
			j.clk = c
		}
	}
}

// WithInterval sets how often Run sweeps.
func WithInterval(d time.Duration) Option {
	return func(j *Janitor) {
		if d > 0 {
			j.interval = d
		}
	}
}

// WithBatchSize sets how many rows one DELETE removes.
func WithBatchSize(n int) Option {
	return func(j *Janitor) {
		if n > 0 {
			j.batch = n
		}
	}
}

// WithEventTTL sets how long a delivered event stays in events_outbox. It does
// not apply to undelivered events: those are never removed.
func WithEventTTL(d time.Duration) Option {
	return func(j *Janitor) {
		if d > 0 {
			j.eventTTL = d
		}
	}
}

// WithStatsTTL sets how long a delivered bucket stays in stats_buckets. It does
// not apply to undelivered buckets: those are never removed.
func WithStatsTTL(d time.Duration) Option {
	return func(j *Janitor) {
		if d > 0 {
			j.statsTTL = d
		}
	}
}

// WithProbeSeenTTL sets how long the tunnel probe log is kept.
func WithProbeSeenTTL(d time.Duration) Option {
	return func(j *Janitor) {
		if d > 0 {
			j.probeSeenTTL = d
		}
	}
}

// WithRequestTTL sets how long a settled (approved, rejected or expired)
// registration request is kept. Pending requests are never removed here: they
// settle on their own five-minute expiry (§6).
func WithRequestTTL(d time.Duration) Option {
	return func(j *Janitor) {
		if d > 0 {
			j.requestTTL = d
		}
	}
}

// New returns the retention job for st. log may be nil, meaning discard.
func New(st *store.Store, log *slog.Logger, opts ...Option) *Janitor {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	j := &Janitor{
		st:           st,
		log:          log,
		clk:          clock.System{},
		interval:     DefaultInterval,
		batch:        DefaultBatchSize,
		eventTTL:     DefaultEventTTL,
		statsTTL:     DefaultStatsTTL,
		probeSeenTTL: DefaultProbeSeenTTL,
		requestTTL:   DefaultRequestTTL,
	}
	if st != nil {
		if c := st.Clock(); c != nil {
			j.clk = c
		}
	}
	for _, opt := range opts {
		opt(j)
	}
	return j
}

// Run sweeps immediately and then every interval, until ctx is done. It
// returns nil: a failed sweep is logged and retried on the next tick, because
// housekeeping falling over must not take the service with it.
func (j *Janitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		res, err := j.RunOnce(ctx)
		switch {
		case ctx.Err() != nil:
			// Shutting down mid-sweep: what was deleted is deleted, the rest
			// waits for the next process.
			j.log.Debug("retention interrupted by shutdown", "removed", res)
			return nil
		case err != nil:
			j.log.Error("retention sweep failed", "error", err, "removed", res)
		case !res.IsZero():
			j.log.Info("retention removed expired rows", "removed", res)
		default:
			j.log.Debug("retention found nothing to remove")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// RunOnce performs one sweep over every table and reports what it removed.
// A cancelled context stops it between batches; it then returns the rows it
// had already removed together with ctx.Err(), and nothing is half-deleted:
// every batch is its own statement.
func (j *Janitor) RunOnce(ctx context.Context) (Result, error) {
	var res Result
	now := clock.MS(j.clk.Now())
	for _, t := range j.tables(&res, now) {
		if err := j.sweep(ctx, t); err != nil {
			return res, err
		}
	}
	j.log.Debug("retention sweep done", "removed", res)
	return res, nil
}

// rule is one table's retention condition and the counter its deletions are
// added to.
type rule struct {
	// table and key are the SQL table and its primary key column. Both are
	// package constants taken from the models, never user input, which is why
	// they can be formatted into the statement.
	table string
	key   string
	// where is the condition the rows to delete satisfy, and args its
	// arguments.
	where string
	args  []any
	// count points at the Result field this table's deletions add up in.
	count *int64
}

// tables lists the five retention rules of §3, measured from now (ms UTC).
func (j *Janitor) tables(res *Result, now int64) []rule {
	return []rule{{
		// Delivered events only: sent_at IS NULL means the panel has not
		// taken it yet, and then age is irrelevant.
		table: (store.EventOutbox{}).TableName(),
		key:   "id",
		where: "sent_at IS NOT NULL AND sent_at < ?",
		args:  []any{now - j.eventTTL.Milliseconds()},
		count: &res.Events,
	}, {
		// Same for buckets: during PANEL_DOWN they accumulate unsent, and §4.1
		// puts no limit on that.
		table: (store.StatsBucket{}).TableName(),
		key:   "id",
		where: "sent_at IS NOT NULL AND sent_at < ?",
		args:  []any{now - j.statsTTL.Milliseconds()},
		count: &res.Stats,
	}, {
		table: (store.ProbeSeen{}).TableName(),
		key:   "id",
		where: "seen_at < ?",
		args:  []any{now - j.probeSeenTTL.Milliseconds()},
		count: &res.ProbeSeen,
	}, {
		// A pending request is live registration state and stays whatever its
		// age; only settled ones age out.
		table: (store.RegistrationRequest{}).TableName(),
		key:   "request_id",
		where: "status <> ? AND created_at < ?",
		args:  []any{store.RequestPending, now - j.requestTTL.Milliseconds()},
		count: &res.Requests,
	}, {
		// Sessions carry their own deadline; a session expiring exactly now is
		// still not in the past.
		table: (store.AdminSession{}).TableName(),
		key:   "id",
		where: "expires_at < ?",
		args:  []any{now},
		count: &res.Sessions,
	}}
}

// sweep deletes the rows r describes, a batch at a time, adding each batch to
// r.count as it goes so that an interrupted sweep still reports accurately.
//
// The batch is expressed as a subselect of primary keys rather than
// DELETE ... LIMIT, which SQLite only offers when compiled for it.
func (j *Janitor) sweep(ctx context.Context, r rule) error {
	stmt := fmt.Sprintf("DELETE FROM %s WHERE %s IN (SELECT %s FROM %s WHERE %s LIMIT ?)",
		r.table, r.key, r.key, r.table, r.where)
	args := make([]any, 0, len(r.args)+1)
	args = append(args, r.args...)
	args = append(args, j.batch)

	for range maxBatchesPerTable {
		if err := ctx.Err(); err != nil {
			return err
		}
		tx := j.st.DB().WithContext(ctx).Exec(stmt, args...)
		if tx.Error != nil {
			return fmt.Errorf("retention: sweep %s: %w", r.table, tx.Error)
		}
		*r.count += tx.RowsAffected
		if tx.RowsAffected < int64(j.batch) {
			return nil
		}
	}
	j.log.Warn("retention stopped at the batch cap, the rest waits for the next run",
		"table", r.table, "removed", *r.count)
	return nil
}
