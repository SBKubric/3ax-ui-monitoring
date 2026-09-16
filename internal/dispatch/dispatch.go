// Package dispatch drains mon-server's two queues to the panel: the events
// outbox and the closed statistics buckets (spec mon-server.md §4 step 4).
//
// It is the last step of the once-a-minute poll cycle, and the poller reaches
// it through one seam:
//
//	Dispatch func(ctx context.Context) (sentEvents int, err error)
//
// Everything here follows from one rule: sent_at is only ever written after a
// 200. A batch the panel refuses with a 4xx is logged with its error code and
// dropped for this call — retrying a batch the panel will never accept would
// block the queue behind it forever — while a panel that cannot be reached
// stops the drain and hands the failure back, so the poll loop can count it
// towards PANEL_DOWN (§4.1). Nothing is marked in either case.
//
// Events go out in ts order, carrying the timestamp they were filed with:
// internal/events stores the payload in the exact wire shape, so a transition
// buffered through a panel outage reaches the panel with its original wording
// and time. Aggregates go out per contract §4.7, which upserts on the bucket
// key, so a bucket a late cycle changed after delivery is simply sent again.
//
// Duplicates and ignored entries in the panel's answer are not failures: the
// panel deduplicates events by id and drops what belongs to an inbound it no
// longer has. They are logged and the batch counts as delivered.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/SBKubric/3ax-ui-monitoring/internal/clock"
	"github.com/SBKubric/3ax-ui-monitoring/internal/panel"
	"github.com/SBKubric/3ax-ui-monitoring/internal/store"
)

// DefaultMaxBatches is how many batches of each kind one call may send. It
// bounds the work of a single poll cycle: at the contract's limits that is
// 5000 events and 10000 aggregates, and whatever is left waits for the next
// minute rather than overrunning this one.
const DefaultMaxBatches = 5

// markChunk is how many ids one UPDATE stamps at a time, comfortably inside
// SQLite's limit on bound variables.
const markChunk = 500

// ErrInvalidOptions reports a Dispatcher that cannot be built.
var ErrInvalidOptions = errors.New("dispatch: invalid options")

// Panel is the part of the panel client this package uses. *panel.Client
// satisfies it; a test can stand in for it.
type Panel interface {
	SendEvents(ctx context.Context, events []panel.Event) (panel.EventsResult, error)
	SendStats(ctx context.Context, stats []panel.Stat) (panel.StatsResult, error)
}

// Stats is the statistics side of the queue: which buckets are ready and which
// the panel has taken. *stats.Recorder satisfies it. The two halves are
// separate on purpose, because only a 200 may mark anything.
type Stats interface {
	// ClosedFrom returns at most limit closed, undelivered buckets, oldest
	// first, passing over the oldest skip of them.
	ClosedFrom(ctx context.Context, skip, limit int) ([]panel.Stat, error)
	// MarkSent stamps the aggregates the panel accepted, at ms UTC.
	MarkSent(ctx context.Context, sent []panel.Stat, at int64) error
}

// Options configures a Dispatcher. Store and Panel are required.
type Options struct {
	// Store holds the events outbox.
	Store *store.Store
	// Panel is the contract client the batches go to.
	Panel Panel
	// Stats is the bucket queue. Nil sends no aggregates, which is only
	// useful before the recorder is wired in.
	Stats Stats
	// Clock stamps sent_at. Nil means clock.System.
	Clock clock.Clock
	// Log receives one line per batch that was refused, and one per answer
	// that reported duplicates or ignored entries. Nil discards.
	Log *slog.Logger
	// MaxBatches bounds the batches of each kind one Dispatch may send. Zero
	// means DefaultMaxBatches.
	MaxBatches int
}

// Dispatcher drains the queues. It holds no state between calls: what has been
// delivered is in the tables.
type Dispatcher struct {
	st         *store.Store
	panel      Panel
	stats      Stats
	clk        clock.Clock
	log        *slog.Logger
	maxBatches int
}

// New builds a Dispatcher.
func New(opts Options) (*Dispatcher, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("%w: store is nil", ErrInvalidOptions)
	}
	if opts.Panel == nil {
		return nil, fmt.Errorf("%w: panel client is nil", ErrInvalidOptions)
	}
	d := &Dispatcher{
		st:         opts.Store,
		panel:      opts.Panel,
		stats:      opts.Stats,
		clk:        opts.Clock,
		log:        opts.Log,
		maxBatches: opts.MaxBatches,
	}
	if d.clk == nil {
		d.clk = clock.System{}
	}
	if d.log == nil {
		d.log = slog.New(slog.DiscardHandler)
	}
	if d.maxBatches <= 0 {
		d.maxBatches = DefaultMaxBatches
	}
	return d, nil
}

// Dispatch drains both queues and reports how many events the panel accepted,
// which is the number the "panel back" message quotes after an outage
// (spec §4.1). It is the seam the poll loop calls once per cycle.
//
// An unreachable panel ends the call at once with the error, so the poller can
// count it; a 4xx is not an error here, because the batch is gone and the rest
// of the queue still has to move.
func (d *Dispatcher) Dispatch(ctx context.Context) (int, error) {
	sent, err := d.drainEvents(ctx)
	if err != nil {
		return sent, err
	}
	if err := d.drainStats(ctx); err != nil {
		return sent, err
	}
	return sent, nil
}

// drainEvents sends events_outbox in ts order, in batches of at most
// panel.MaxEvents, and returns how many the panel accepted.
func (d *Dispatcher) drainEvents(ctx context.Context) (int, error) {
	accepted := 0
	// left behind: rows this call has read but cannot mark — an unreadable
	// payload, or a batch the panel refused. They keep their place in the
	// queue, and the offset steps over them so the next read moves on.
	behind := 0

	for batch := 0; batch < d.maxBatches; batch++ {
		rows, err := d.pendingEvents(ctx, behind, panel.MaxEvents)
		if err != nil {
			return accepted, err
		}
		if len(rows) == 0 {
			return accepted, nil
		}

		evs, ids := decode(rows, d.log)
		behind += len(rows) - len(evs)
		if len(evs) == 0 {
			// Nothing in this batch can be sent; there is no point reading
			// past it in the same cycle.
			return accepted, nil
		}

		result, err := d.panel.SendEvents(ctx, evs)
		switch {
		case err == nil:
			accepted += result.Accepted
			d.logEventAnswer(result, len(evs))
			at := clock.MS(d.clk.Now())
			if err := d.markEventsSent(ctx, ids, at); err != nil {
				return accepted, err
			}
		case stopping(ctx, err):
			return accepted, fmt.Errorf("dispatch: send events: %w", err)
		default:
			d.log.Error("panel refused an events batch, dropping it",
				"events", len(evs), "code", codeOf(err), "status", statusOf(err), "error", err)
			behind += len(evs)
		}

		if len(rows) < panel.MaxEvents {
			// The queue held less than a full batch, so it is drained.
			return accepted, nil
		}
	}
	d.log.Info("events queue is still behind, the rest goes out next cycle",
		"batches", d.maxBatches, "accepted", accepted)
	return accepted, nil
}

// drainStats sends the closed buckets in batches of at most panel.MaxStats.
func (d *Dispatcher) drainStats(ctx context.Context) error {
	if d.stats == nil {
		return nil
	}
	behind := 0

	for batch := 0; batch < d.maxBatches; batch++ {
		ready, err := d.stats.ClosedFrom(ctx, behind, panel.MaxStats)
		if err != nil {
			return err
		}
		if len(ready) == 0 {
			return nil
		}

		result, err := d.panel.SendStats(ctx, ready)
		switch {
		case err == nil:
			if n := len(result.Ignored); n > 0 {
				d.log.Warn("panel ignored some aggregates",
					"ignored", n, "accepted", result.Accepted, "first", firstIgnoredStat(result.Ignored))
			}
			at := clock.MS(d.clk.Now())
			if err := d.stats.MarkSent(ctx, ready, at); err != nil {
				return err
			}
		case stopping(ctx, err):
			return fmt.Errorf("dispatch: send stats: %w", err)
		default:
			d.log.Error("panel refused a statistics batch, dropping it",
				"stats", len(ready), "code", codeOf(err), "status", statusOf(err), "error", err)
			behind += len(ready)
		}

		if len(ready) < panel.MaxStats {
			return nil
		}
	}
	d.log.Info("statistics queue is still behind, the rest goes out next cycle",
		"batches", d.maxBatches)
	return nil
}

// pendingEvents reads the undelivered events in ts order. The id breaks ties:
// it is a UUID v7, so it orders by creation time as well.
func (d *Dispatcher) pendingEvents(ctx context.Context, skip, limit int) ([]store.EventOutbox, error) {
	var rows []store.EventOutbox
	q := d.st.DB().WithContext(ctx).
		Where("sent_at IS NULL").
		Order("ts asc, id asc").
		Limit(limit)
	if skip > 0 {
		q = q.Offset(skip)
	}
	if err := q.Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("dispatch: read events outbox: %w", err)
	}
	return rows, nil
}

// markEventsSent stamps the rows the panel took.
func (d *Dispatcher) markEventsSent(ctx context.Context, ids []string, at int64) error {
	for start := 0; start < len(ids); start += markChunk {
		end := min(start+markChunk, len(ids))
		res := d.st.DB().WithContext(ctx).
			Model(&store.EventOutbox{}).
			Where("id IN ? AND sent_at IS NULL", ids[start:end]).
			Update("sent_at", at)
		if res.Error != nil {
			return fmt.Errorf("dispatch: mark events sent: %w", res.Error)
		}
	}
	return nil
}

// logEventAnswer reports what the panel did with a batch it accepted.
// Duplicates and ignored entries are expected: the panel deduplicates by id
// and drops events about inbounds it no longer has (contract §4.6).
func (d *Dispatcher) logEventAnswer(result panel.EventsResult, sent int) {
	if result.Duplicates > 0 {
		d.log.Info("panel already had some of the events",
			"duplicates", result.Duplicates, "sent", sent)
	}
	if n := len(result.Ignored); n > 0 {
		d.log.Warn("panel ignored some events",
			"ignored", n, "accepted", result.Accepted, "first", firstIgnoredEvent(result.Ignored))
	}
}
